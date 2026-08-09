// Package natssignal carries p2pstore ICE metadata over NATS. Object bodies are
// never accepted by this package.
package natssignal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/richinsley/p2pstore"
)

const maxSignalBytes = 64 * 1024

// Dialer opens client-side signaling channels on an existing NATS connection.
type Dialer struct {
	// NC carries signaling messages and must already be connected.
	NC *nats.Conn
	// PeerID identifies this client and must be safe for use as a NATS token.
	PeerID string
	// RemotePeerID is the provider node ID and must be token-safe.
	RemotePeerID string
}

// Dial opens the client side of sessionID. It subscribes before returning so
// the provider's first response cannot be missed.
func (d *Dialer) Dial(_ context.Context, sessionID string) (p2pstore.SignalChannel, error) {
	return newDirectChannel(d.NC, sessionID, d.PeerID, d.RemotePeerID)
}

// Listener accepts provider-side signaling channels addressed to one peer ID.
// One Channel is created per distinct session ID.
type Listener struct {
	nc       *nats.Conn
	peerID   string
	sub      *nats.Subscription
	mu       sync.Mutex
	channels map[string]*Channel
	accepted chan *Channel
	closed   chan struct{}
	once     sync.Once
}

// NewListener subscribes to signaling sessions addressed to peerID. IDs must
// not contain NATS wildcards, dots, spaces, or an empty value.
func NewListener(nc *nats.Conn, peerID string) (*Listener, error) {
	if nc == nil || !safeToken(peerID) {
		return nil, errors.New("natssignal: valid NATS connection and token-safe peer ID are required")
	}
	listener := &Listener{
		nc: nc, peerID: peerID, channels: make(map[string]*Channel),
		accepted: make(chan *Channel, 16), closed: make(chan struct{}),
	}
	var err error
	listener.sub, err = nc.Subscribe("p2pstore.signal.*."+peerID, listener.dispatch)
	if err != nil {
		return nil, err
	}
	if err = nc.Flush(); err != nil {
		_ = listener.sub.Unsubscribe()
		return nil, err
	}
	return listener, nil
}

// Accept waits for the first valid signal in a new session.
func (l *Listener) Accept(ctx context.Context) (p2pstore.SignalChannel, error) {
	select {
	case channel := <-l.accepted:
		return channel, nil
	case <-l.closed:
		return nil, nats.ErrConnectionClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Close unsubscribes the listener and closes all channels it accepted. It does
// not close the shared NATS connection.
func (l *Listener) Close() error {
	var result error
	l.once.Do(func() {
		close(l.closed)
		result = l.sub.Unsubscribe()
		l.mu.Lock()
		for _, channel := range l.channels {
			channel.closeLocal()
		}
		l.channels = nil
		l.mu.Unlock()
	})
	return result
}

// dispatch validates a provider-addressed signal, creates the session Channel
// on first contact, and queues it without blocking the NATS callback.
func (l *Listener) dispatch(message *nats.Msg) {
	if len(message.Data) > maxSignalBytes {
		return
	}
	parts := strings.Split(message.Subject, ".")
	if len(parts) != 4 {
		return
	}
	sessionID := parts[2]
	var signal p2pstore.Signal
	if json.Unmarshal(message.Data, &signal) != nil || signal.SessionID != sessionID || signal.PeerID == "" {
		return
	}
	l.mu.Lock()
	channel := l.channels[sessionID]
	if channel == nil {
		channel = &Channel{
			nc: l.nc, sessionID: sessionID, peerID: l.peerID, remotePeerID: signal.PeerID,
			incoming: make(chan p2pstore.Signal, 64), done: make(chan struct{}),
		}
		channel.onClose = func() {
			l.mu.Lock()
			delete(l.channels, sessionID)
			l.mu.Unlock()
		}
		l.channels[sessionID] = channel
		select {
		case l.accepted <- channel:
		case <-l.closed:
			l.mu.Unlock()
			return
		}
	}
	l.mu.Unlock()
	select {
	case channel.incoming <- signal:
	case <-channel.done:
	default:
	}
}

// Channel implements a bounded bidirectional SignalChannel over two NATS
// subjects. Incoming messages are capped at 64 KiB and a queue of 64 signals.
type Channel struct {
	nc                   *nats.Conn
	sessionID            string
	peerID, remotePeerID string
	sub                  *nats.Subscription
	incoming             chan p2pstore.Signal
	done                 chan struct{}
	onClose              func()
	once                 sync.Once
}

// newDirectChannel creates the client subscription before any hello is sent.
func newDirectChannel(nc *nats.Conn, sessionID, peerID, remotePeerID string) (*Channel, error) {
	if nc == nil || !safeToken(sessionID) || !safeToken(peerID) || !safeToken(remotePeerID) {
		return nil, errors.New("natssignal: connection, session, and token-safe peer IDs are required")
	}
	channel := &Channel{
		nc: nc, sessionID: sessionID, peerID: peerID, remotePeerID: remotePeerID,
		incoming: make(chan p2pstore.Signal, 64), done: make(chan struct{}),
	}
	var err error
	channel.sub, err = nc.Subscribe(channel.receiveSubject(), func(message *nats.Msg) {
		if len(message.Data) > maxSignalBytes {
			return
		}
		var signal p2pstore.Signal
		if json.Unmarshal(message.Data, &signal) != nil || signal.SessionID != sessionID || signal.PeerID != remotePeerID {
			return
		}
		select {
		case channel.incoming <- signal:
		case <-channel.done:
		default:
		}
	})
	if err != nil {
		return nil, err
	}
	if err = nc.Flush(); err != nil {
		_ = channel.sub.Unsubscribe()
		return nil, err
	}
	return channel, nil
}

// Send validates the local session identity and publishes one bounded signal.
func (c *Channel) Send(ctx context.Context, signal p2pstore.Signal) error {
	if signal.SessionID != c.sessionID || signal.PeerID != c.peerID {
		return &p2pstore.Error{Code: p2pstore.CodeInvalidArgument, Message: "signal identity does not match NATS channel"}
	}
	encoded, err := json.Marshal(signal)
	if err != nil {
		return err
	}
	if len(encoded) > maxSignalBytes {
		return &p2pstore.Error{Code: p2pstore.CodeInvalidArgument, Message: "NATS signal exceeds 64 KiB"}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	return c.nc.Publish(c.sendSubject(), encoded)
}

// Receive waits for the next queued remote signal or context cancellation.
func (c *Channel) Receive(ctx context.Context) (p2pstore.Signal, error) {
	select {
	case signal := <-c.incoming:
		return signal, nil
	case <-c.done:
		return p2pstore.Signal{}, nats.ErrConnectionClosed
	case <-ctx.Done():
		return p2pstore.Signal{}, ctx.Err()
	}
}

// Close unsubscribes this channel without closing the shared NATS connection.
func (c *Channel) Close() error {
	var result error
	c.once.Do(func() {
		close(c.done)
		if c.sub != nil {
			result = c.sub.Unsubscribe()
		}
		if c.onClose != nil {
			c.onClose()
		}
	})
	return result
}

// closeLocal closes a listener-owned channel without invoking its removal
// callback while the listener already holds lifecycle ownership.
func (c *Channel) closeLocal() {
	c.once.Do(func() {
		close(c.done)
		if c.sub != nil {
			_ = c.sub.Unsubscribe()
		}
	})
}

// sendSubject addresses signals to the configured remote peer.
func (c *Channel) sendSubject() string {
	return fmt.Sprintf("p2pstore.signal.%s.%s", c.sessionID, c.remotePeerID)
}

// receiveSubject addresses signals to this local peer.
func (c *Channel) receiveSubject() string {
	return fmt.Sprintf("p2pstore.signal.%s.%s", c.sessionID, c.peerID)
}

// providerQuery is the request/reply subject used only for provider discovery.
const providerQuery = "p2pstore.providers.query"

// ProviderAdvertisement is the short-lived response returned to provider
// discovery queries.
type ProviderAdvertisement struct {
	// NodeID is the provider's mesh node identifier.
	NodeID string `json:"node_id"`
	// ExpiresAt lets discovery ignore delayed or replayed advertisements.
	ExpiresAt time.Time `json:"expires_at"`
}

// AnnounceProvider registers a responder for provider discovery. The returned
// subscription is the announcement lifetime and must be unsubscribed when the
// node stops being a provider.
func AnnounceProvider(nc *nats.Conn, nodeID string) (*nats.Subscription, error) {
	if nc == nil || nodeID == "" {
		return nil, errors.New("natssignal: connection and provider node ID are required")
	}
	return nc.Subscribe(providerQuery, func(message *nats.Msg) {
		advertisement, _ := json.Marshal(ProviderAdvertisement{NodeID: nodeID, ExpiresAt: time.Now().Add(30 * time.Second).UTC()})
		_ = message.Respond(advertisement)
	})
}

// DiscoverProvider returns exactly one provider. An explicit provider wins but
// must still be advertised. Ambiguity is an error, never a random selection.
func DiscoverProvider(ctx context.Context, nc *nats.Conn, explicit string) (string, error) {
	if nc == nil {
		return "", errors.New("natssignal: nil NATS connection")
	}
	inbox := nats.NewInbox()
	sub, err := nc.SubscribeSync(inbox)
	if err != nil {
		return "", err
	}
	defer sub.Unsubscribe()
	if err = nc.PublishRequest(providerQuery, inbox, nil); err != nil {
		return "", err
	}
	if err = nc.Flush(); err != nil {
		return "", err
	}
	collectCtx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	providers := make(map[string]struct{})
	for {
		message, nextErr := sub.NextMsgWithContext(collectCtx)
		if nextErr != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			break
		}
		var advertisement ProviderAdvertisement
		if json.Unmarshal(message.Data, &advertisement) == nil && advertisement.ExpiresAt.After(time.Now()) {
			providers[advertisement.NodeID] = struct{}{}
		}
	}
	if explicit != "" {
		if _, ok := providers[explicit]; !ok {
			return "", &p2pstore.Error{Code: p2pstore.CodeUnavailable, Message: "configured provider is not advertised"}
		}
		return explicit, nil
	}
	if len(providers) == 0 {
		return "", &p2pstore.Error{Code: p2pstore.CodeUnavailable, Message: "no p2pstore provider discovered"}
	}
	if len(providers) != 1 {
		return "", &p2pstore.Error{Code: p2pstore.CodeUnavailable, Message: "ambiguous p2pstore provider discovery"}
	}
	for provider := range providers {
		return provider, nil
	}
	panic("unreachable")
}

// safeToken accepts an opaque value that occupies exactly one NATS subject
// token and cannot introduce a wildcard.
func safeToken(value string) bool { return value != "" && !strings.ContainsAny(value, ".*> ") }

var _ p2pstore.SignalDialer = (*Dialer)(nil)
var _ p2pstore.SignalListener = (*Listener)(nil)
var _ p2pstore.SignalChannel = (*Channel)(nil)
