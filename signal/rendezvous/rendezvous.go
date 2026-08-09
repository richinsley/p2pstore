// Package rendezvous implements a short-lived HTTPS signaling helper. The
// helper stores only capability-encrypted ICE envelopes.
package rendezvous

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"

	"github.com/richinsley/p2pstore"
)

const (
	// MaxMessageBytes is the largest encrypted signaling envelope accepted by
	// the client or helper.
	MaxMessageBytes = 64 * 1024
	// DefaultSessionTTL is the maximum lifetime of a rendezvous session.
	DefaultSessionTTL = 5 * time.Minute
	longPoll          = 20 * time.Second
)

// JoinCode is the out-of-band capability needed to join one provider session.
// Its String form is secret: anyone holding it can participate in that session
// and decrypt its signaling envelopes until the session expires.
type JoinCode struct {
	// URL is the HTTPS rendezvous helper base URL. Plain HTTP is accepted only
	// for an explicit loopback host.
	URL string `json:"url"`
	// SessionID is a random 128-bit, base64url session identifier.
	SessionID string `json:"session_id"`
	// ProviderID is the expected provider peer identifier.
	ProviderID string `json:"provider_id"`
	// Capability is a random 256-bit, base64url encryption capability.
	Capability string `json:"capability"`
}

// NewJoinCode generates a session ID and capability for baseURL and providerID.
func NewJoinCode(baseURL, providerID string) (JoinCode, error) {
	if providerID == "" {
		return JoinCode{}, errors.New("rendezvous: provider ID is empty")
	}
	if err := validateURL(baseURL); err != nil {
		return JoinCode{}, err
	}
	session := make([]byte, 16)
	capability := make([]byte, 32)
	if _, err := rand.Read(session); err != nil {
		return JoinCode{}, err
	}
	if _, err := rand.Read(capability); err != nil {
		return JoinCode{}, err
	}
	return JoinCode{
		URL: strings.TrimRight(baseURL, "/"), SessionID: base64.RawURLEncoding.EncodeToString(session),
		ProviderID: providerID, Capability: base64.RawURLEncoding.EncodeToString(capability),
	}, nil
}

// String encodes the complete join capability as unpadded base64url JSON.
func (c JoinCode) String() string {
	encoded, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(encoded)
}

// ParseJoinCode decodes and validates a String representation.
func ParseJoinCode(encoded string) (JoinCode, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil {
		return JoinCode{}, errors.New("rendezvous: invalid join code")
	}
	var code JoinCode
	if err = json.Unmarshal(raw, &code); err != nil || code.SessionID == "" || code.ProviderID == "" {
		return JoinCode{}, errors.New("rendezvous: invalid join code")
	}
	capability, decodeErr := base64.RawURLEncoding.DecodeString(code.Capability)
	if decodeErr != nil || len(capability) != 32 {
		return JoinCode{}, errors.New("rendezvous: invalid join capability")
	}
	if err = validateURL(code.URL); err != nil {
		return JoinCode{}, err
	}
	code.URL = strings.TrimRight(code.URL, "/")
	return code, nil
}

// Server is an in-memory HTTPS/long-poll rendezvous helper. It stores only
// opaque encrypted envelopes and capability hashes, never plaintext ICE
// metadata or object bytes.
type Server struct {
	mu       sync.Mutex
	sessions map[string]*serverSession
	// MaxSessionTTL optionally shortens session lifetime; zero and values above
	// DefaultSessionTTL are clamped to DefaultSessionTTL.
	MaxSessionTTL time.Duration
	// Now supplies wall-clock time for expiry decisions. NewServer uses time.Now.
	Now func() time.Time
}

// serverSession is helper-side opaque state. auth is the capability hash and
// messages contain encrypted envelopes the helper cannot open.
type serverSession struct {
	providerID string
	auth       string
	expires    time.Time
	timer      *time.Timer
	next       int64
	messages   map[string][]queuedEnvelope
	closed     map[string]bool
	notify     chan struct{}
}

// queuedEnvelope attaches a monotonic session sequence to one opaque body so a
// long-polling receiver can resume without replaying handled messages.
type queuedEnvelope struct {
	Sequence int64           `json:"sequence"`
	Body     json.RawMessage `json:"body"`
}

// NewServer returns an empty rendezvous handler with five-minute sessions.
func NewServer() *Server {
	return &Server{sessions: make(map[string]*serverSession), MaxSessionTTL: DefaultSessionTTL, Now: time.Now}
}

// ServeHTTP implements the internal v1 session and message endpoints used by
// ProviderListener and Dialer.
func (s *Server) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	parts := strings.Split(strings.Trim(request.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "v1" || parts[1] != "sessions" || parts[2] == "" {
		http.NotFound(w, request)
		return
	}
	sessionID := parts[2]
	if len(parts) == 3 && request.Method == http.MethodPut {
		s.create(w, request, sessionID)
		return
	}
	if len(parts) == 4 && parts[3] == "messages" {
		switch request.Method {
		case http.MethodPost:
			s.send(w, request, sessionID)
		case http.MethodGet:
			s.receive(w, request, sessionID)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	if len(parts) == 3 && request.Method == http.MethodDelete {
		s.closeRole(w, request, sessionID)
		return
	}
	http.NotFound(w, request)
}

// create registers a provider-created session after bounded JSON and capability
// hash validation.
func (s *Server) create(w http.ResponseWriter, request *http.Request, sessionID string) {
	var body struct {
		ProviderID string `json:"provider_id"`
	}
	if !readJSON(w, request, &body) {
		return
	}
	if body.ProviderID == "" || request.Header.Get("X-P2PStore-Auth") == "" {
		http.Error(w, "invalid session", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.expireLocked()
	if _, exists := s.sessions[sessionID]; exists {
		http.Error(w, "session exists", http.StatusConflict)
		return
	}
	ttl := s.MaxSessionTTL
	if ttl <= 0 || ttl > DefaultSessionTTL {
		ttl = DefaultSessionTTL
	}
	session := &serverSession{
		providerID: body.ProviderID, auth: request.Header.Get("X-P2PStore-Auth"), expires: s.Now().Add(ttl),
		messages: map[string][]queuedEnvelope{"provider": {}, "client": {}}, closed: make(map[string]bool), notify: make(chan struct{}),
	}
	s.sessions[sessionID] = session
	session.timer = time.AfterFunc(ttl, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.sessions[sessionID] == session {
			close(session.notify)
			delete(s.sessions, sessionID)
		}
	})
	w.WriteHeader(http.StatusCreated)
}

// send validates one encrypted JSON envelope and queues it for the opposite
// role, waking any active long poll.
func (s *Server) send(w http.ResponseWriter, request *http.Request, sessionID string) {
	from := request.URL.Query().Get("from")
	if from != "provider" && from != "client" {
		http.Error(w, "invalid role", http.StatusBadRequest)
		return
	}
	request.Body = http.MaxBytesReader(w, request.Body, MaxMessageBytes)
	body, err := io.ReadAll(request.Body)
	if err != nil || len(body) == 0 || len(body) > MaxMessageBytes || !json.Valid(body) {
		http.Error(w, "invalid envelope", http.StatusRequestEntityTooLarge)
		return
	}
	target := opposite(from)
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.authorizedLocked(request, sessionID)
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	session.next++
	session.messages[target] = append(session.messages[target], queuedEnvelope{Sequence: session.next, Body: append([]byte(nil), body...)})
	close(session.notify)
	session.notify = make(chan struct{})
	w.WriteHeader(http.StatusAccepted)
}

// receive returns the first envelope after the caller's sequence or waits up to
// longPoll for a message, closure, expiry, or request cancellation.
func (s *Server) receive(w http.ResponseWriter, request *http.Request, sessionID string) {
	to := request.URL.Query().Get("to")
	if to != "provider" && to != "client" {
		http.Error(w, "invalid role", http.StatusBadRequest)
		return
	}
	after := int64(0)
	_, _ = fmt.Sscan(request.URL.Query().Get("after"), &after)
	deadline := time.NewTimer(longPoll)
	defer deadline.Stop()
	for {
		s.mu.Lock()
		session, ok := s.authorizedLocked(request, sessionID)
		if !ok {
			s.mu.Unlock()
			w.WriteHeader(http.StatusForbidden)
			return
		}
		for _, envelope := range session.messages[to] {
			if envelope.Sequence > after {
				s.mu.Unlock()
				writeJSON(w, envelope)
				return
			}
		}
		notify := session.notify
		s.mu.Unlock()
		select {
		case <-notify:
		case <-deadline.C:
			w.WriteHeader(http.StatusNoContent)
			return
		case <-request.Context().Done():
			return
		}
	}
}

// closeRole records one peer's teardown and deletes the session after both
// peers close.
func (s *Server) closeRole(w http.ResponseWriter, request *http.Request, sessionID string) {
	role := request.URL.Query().Get("role")
	if role != "provider" && role != "client" {
		http.Error(w, "invalid role", http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.authorizedLocked(request, sessionID)
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	session.closed[role] = true
	if session.closed["provider"] && session.closed["client"] {
		if session.timer != nil {
			session.timer.Stop()
		}
		close(session.notify)
		delete(s.sessions, sessionID)
	}
	w.WriteHeader(http.StatusNoContent)
}

// authorizedLocked looks up a live session and compares its stored capability
// hash with the request header. The caller must hold s.mu.
func (s *Server) authorizedLocked(request *http.Request, sessionID string) (*serverSession, bool) {
	s.expireLocked()
	session := s.sessions[sessionID]
	return session, session != nil && request.Header.Get("X-P2PStore-Auth") == session.auth
}

// expireLocked removes sessions whose wall-clock TTL elapsed. The caller must
// hold s.mu.
func (s *Server) expireLocked() {
	now := s.Now()
	for id, session := range s.sessions {
		if !session.expires.After(now) {
			if session.timer != nil {
				session.timer.Stop()
			}
			close(session.notify)
			delete(s.sessions, id)
		}
	}
}

// ProviderListener creates and exposes exactly one provider-side rendezvous
// channel. The join capability can be accepted only once.
type ProviderListener struct {
	code    JoinCode
	channel *Channel
	used    bool
	mu      sync.Mutex
}

// NewProviderListener generates a join code and creates its short-lived session
// on the rendezvous helper. A nil client selects http.DefaultClient.
func NewProviderListener(ctx context.Context, baseURL, providerID string, client *http.Client) (*ProviderListener, error) {
	code, err := NewJoinCode(baseURL, providerID)
	if err != nil {
		return nil, err
	}
	channel, err := newChannel(code, "provider", client)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(struct {
		ProviderID string `json:"provider_id"`
	}{providerID})
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, channel.sessionURL(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	channel.authorize(request)
	request.Header.Set("Content-Type", "application/json")
	response, err := channel.client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("rendezvous create session: %s", response.Status)
	}
	return &ProviderListener{code: code, channel: channel}, nil
}

// JoinCode returns the secret out-of-band capability to give to one client.
func (l *ProviderListener) JoinCode() string { return l.code.String() }

// Accept returns the single provider channel. A second call fails rather than
// allowing the capability to create multiple storage sessions.
func (l *ProviderListener) Accept(context.Context) (p2pstore.SignalChannel, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.used {
		return nil, errors.New("rendezvous: join capability already used")
	}
	l.used = true
	return l.channel, nil
}

// Close marks the provider role closed at the helper.
func (l *ProviderListener) Close() error { return l.channel.Close() }

// Dialer opens the client side of the session encoded by a JoinCode.
type Dialer struct {
	// Code is the parsed join capability.
	Code JoinCode
	// Client performs helper requests; nil selects http.DefaultClient.
	Client *http.Client
}

// NewDialer validates encoded and returns a rendezvous signaling dialer.
func NewDialer(encoded string, client *http.Client) (*Dialer, error) {
	code, err := ParseJoinCode(encoded)
	if err != nil {
		return nil, err
	}
	return &Dialer{Code: code, Client: client}, nil
}

// Dial opens the client channel. A non-empty sessionID must match the join code.
func (d *Dialer) Dial(_ context.Context, sessionID string) (p2pstore.SignalChannel, error) {
	if sessionID != "" && sessionID != d.Code.SessionID {
		return nil, errors.New("rendezvous: join code session mismatch")
	}
	return newChannel(d.Code, "client", d.Client)
}

// Channel exchanges capability-encrypted Signal values through long polling.
// It is normally constructed through ProviderListener or Dialer.
type Channel struct {
	code   JoinCode
	role   string
	client *http.Client
	key    []byte
	auth   string
	mu     sync.Mutex
	after  int64
	close  sync.Once
}

// newChannel derives the role-independent encryption key and request
// authentication hash from the out-of-band capability.
func newChannel(code JoinCode, role string, client *http.Client) (*Channel, error) {
	if err := validateURL(code.URL); err != nil {
		return nil, err
	}
	capability, err := base64.RawURLEncoding.DecodeString(code.Capability)
	if err != nil || len(capability) != 32 {
		return nil, errors.New("rendezvous: invalid capability")
	}
	key := make([]byte, 32)
	if _, err = io.ReadFull(hkdf.New(sha256.New, capability, []byte(code.SessionID), []byte("p2pstore rendezvous v1")), key); err != nil {
		return nil, err
	}
	authHash := sha256.Sum256(capability)
	if client == nil {
		client = http.DefaultClient
	}
	return &Channel{code: code, role: role, client: client, key: key, auth: base64.RawURLEncoding.EncodeToString(authHash[:])}, nil
}

// Send encrypts and authenticates a Signal locally before posting the opaque
// envelope to the helper.
func (c *Channel) Send(ctx context.Context, signal p2pstore.Signal) error {
	plain, err := json.Marshal(signal)
	if err != nil {
		return err
	}
	envelope, err := c.seal(plain)
	if err != nil {
		return err
	}
	if len(envelope) > MaxMessageBytes {
		return &p2pstore.Error{Code: p2pstore.CodeInvalidArgument, Message: "rendezvous message exceeds 64 KiB"}
	}
	target := c.sessionURL() + "/messages?from=" + c.role
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(envelope))
	if err != nil {
		return err
	}
	c.authorize(request)
	request.Header.Set("Content-Type", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusForbidden {
		return &p2pstore.Error{Code: p2pstore.CodeUnauthenticated, Message: "rendezvous capability rejected"}
	}
	if response.StatusCode != http.StatusAccepted {
		return fmt.Errorf("rendezvous send: %s", response.Status)
	}
	return nil
}

// Receive long-polls for the next envelope, authenticates and decrypts it, and
// advances the per-channel sequence only after successful decoding.
func (c *Channel) Receive(ctx context.Context) (p2pstore.Signal, error) {
	for {
		c.mu.Lock()
		after := c.after
		c.mu.Unlock()
		target := fmt.Sprintf("%s/messages?to=%s&after=%d", c.sessionURL(), c.role, after)
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
		if err != nil {
			return p2pstore.Signal{}, err
		}
		c.authorize(request)
		response, err := c.client.Do(request)
		if err != nil {
			return p2pstore.Signal{}, err
		}
		if response.StatusCode == http.StatusNoContent {
			_ = response.Body.Close()
			continue
		}
		if response.StatusCode == http.StatusForbidden {
			_ = response.Body.Close()
			return p2pstore.Signal{}, &p2pstore.Error{Code: p2pstore.CodeUnauthenticated, Message: "rendezvous session expired or capability rejected"}
		}
		var queued queuedEnvelope
		decodeErr := json.NewDecoder(io.LimitReader(response.Body, MaxMessageBytes+1)).Decode(&queued)
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK || decodeErr != nil {
			return p2pstore.Signal{}, fmt.Errorf("rendezvous receive: %s: %v", response.Status, decodeErr)
		}
		plain, err := c.open(queued.Body)
		if err != nil {
			return p2pstore.Signal{}, &p2pstore.Error{Code: p2pstore.CodeUnauthenticated, Message: "rendezvous envelope authentication failed", Err: err}
		}
		var signal p2pstore.Signal
		if err = json.Unmarshal(plain, &signal); err != nil {
			return signal, err
		}
		c.mu.Lock()
		if queued.Sequence > c.after {
			c.after = queued.Sequence
		}
		c.mu.Unlock()
		return signal, nil
	}
}

// Close marks this role closed. The helper deletes the session after both roles
// close or when its TTL expires. Close is idempotent.
func (c *Channel) Close() error {
	var result error
	c.close.Do(func() {
		request, err := http.NewRequest(http.MethodDelete, c.sessionURL()+"?role="+c.role, nil)
		if err != nil {
			result = err
			return
		}
		c.authorize(request)
		response, err := c.client.Do(request)
		if err != nil {
			result = err
			return
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusNoContent && response.StatusCode != http.StatusForbidden {
			result = fmt.Errorf("rendezvous close: %s", response.Status)
		}
	})
	return result
}

// encryptedEnvelope is the only message content visible to the helper. Both
// values use unpadded base64url so the envelope remains ordinary JSON.
type encryptedEnvelope struct {
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// seal encrypts one local-role Signal with fresh AES-GCM nonce material.
func (c *Channel) seal(plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	aad := []byte(c.code.SessionID + ":" + c.role)
	ciphertext := aead.Seal(nil, nonce, plain, aad)
	return json.Marshal(encryptedEnvelope{
		Nonce: base64.RawURLEncoding.EncodeToString(nonce), Ciphertext: base64.RawURLEncoding.EncodeToString(ciphertext),
	})
}

// open authenticates an envelope as having been sent by the opposite role and
// returns its plaintext Signal JSON.
func (c *Channel) open(encoded []byte) ([]byte, error) {
	var envelope encryptedEnvelope
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		return nil, err
	}
	nonce, err := base64.RawURLEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, err
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aad := []byte(c.code.SessionID + ":" + opposite(c.role))
	return aead.Open(nil, nonce, ciphertext, aad)
}

// sessionURL constructs the only helper path scoped by this capability.
func (c *Channel) sessionURL() string {
	return c.code.URL + "/v1/sessions/" + url.PathEscape(c.code.SessionID)
}

// authorize attaches the capability hash used for helper-side bearer
// authorization; the encryption capability itself is never transmitted.
func (c *Channel) authorize(request *http.Request) { request.Header.Set("X-P2PStore-Auth", c.auth) }

// validateURL requires HTTPS except for an explicitly parsed loopback host.
func validateURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Hostname() == "" {
		return errors.New("rendezvous: invalid URL")
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme == "http" && isLoopback(parsed.Hostname()) {
		return nil
	}
	return errors.New("rendezvous: HTTPS is required except on loopback")
}

// isLoopback recognizes localhost and literal loopback IP addresses without
// performing DNS resolution.
func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// opposite maps each supported signaling role to its peer role.
func opposite(role string) string {
	if role == "provider" {
		return "client"
	}
	return "provider"
}

// readJSON decodes one helper request through the shared 64 KiB limit.
func readJSON(w http.ResponseWriter, request *http.Request, destination any) bool {
	request.Body = http.MaxBytesReader(w, request.Body, MaxMessageBytes)
	if err := json.NewDecoder(request.Body).Decode(destination); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return false
	}
	return true
}

// writeJSON emits one helper response as application/json.
func writeJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(value)
}

var _ p2pstore.SignalListener = (*ProviderListener)(nil)
var _ p2pstore.SignalDialer = (*Dialer)(nil)
var _ p2pstore.SignalChannel = (*Channel)(nil)
