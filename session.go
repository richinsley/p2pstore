package p2pstore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/stun/v3"
	quic "github.com/quic-go/quic-go"
)

// ICEConfig configures candidate gathering and one peer negotiation.
type ICEConfig struct {
	// SessionID identifies the signaling exchange and must match both peers.
	SessionID string
	// PeerID identifies this peer and must differ from the remote peer ID.
	PeerID string
	// STUNURLs lists STUN or STUNS servers used for server-reflexive candidates.
	// An empty list selects DefaultSTUNURL unless HostOnly is true.
	STUNURLs []string
	// Timeout bounds signaling and ICE connectivity checks. Non-positive values
	// select DefaultICETimeout.
	Timeout time.Duration
	// SignalTTL sets ExpiresAt on outgoing signals. Non-positive values select
	// five minutes.
	SignalTTL time.Duration
	// HostOnly disables STUN and is intended for CI and same-LAN sessions.
	HostOnly bool
}

// DefaultICEConfig returns an internet-oriented configuration using the
// default public STUN server and standard negotiation timeout.
func DefaultICEConfig(sessionID, peerID string) ICEConfig {
	return ICEConfig{
		SessionID: sessionID,
		PeerID:    peerID,
		STUNURLs:  []string{DefaultSTUNURL},
		Timeout:   DefaultICETimeout,
		SignalTTL: 5 * time.Minute,
	}
}

// PeerSession owns the resources for one selected ICE path and its single QUIC
// connection. A session is not reconnectable; establish a new signaling and
// peer session after it closes.
type PeerSession struct {
	// Conn is the established QUIC connection used by Client or RPCServer.
	Conn     *quic.Conn
	agent    *ice.Agent
	listener *quic.Listener
	signal   SignalChannel
	close    sync.Once
}

// Close closes the QUIC connection, listener, ICE agent, and signaling channel.
// It is idempotent and joins errors from all resources.
func (s *PeerSession) Close() error {
	var result error
	s.close.Do(func() {
		if s.Conn != nil {
			result = errors.Join(result, s.Conn.CloseWithError(0, "session closed"))
		}
		if s.listener != nil {
			result = errors.Join(result, s.listener.Close())
		}
		if s.agent != nil {
			result = errors.Join(result, s.agent.Close())
		}
		if s.signal != nil {
			result = errors.Join(result, s.signal.Close())
		}
	})
	return result
}

// AcceptPeer negotiates as the authoritative provider (ICE controlled, QUIC
// server). It generates a fresh ECDSA certificate, advertises its fingerprint
// through channel, and returns only after the QUIC handshake succeeds.
func AcceptPeer(ctx context.Context, channel SignalChannel, cfg ICEConfig) (*PeerSession, error) {
	return acceptPeerWithALPN(ctx, channel, cfg, ALPN)
}

func acceptPeerWithALPN(ctx context.Context, channel SignalChannel, cfg ICEConfig, alpn string) (*PeerSession, error) {
	certificate, err := NewSessionCertificate(10 * time.Minute)
	if err != nil {
		return nil, err
	}
	iceConn, agent, err := negotiateICE(ctx, channel, cfg, RoleProvider, certificate.Fingerprint)
	if err != nil {
		return nil, err
	}
	listener, err := listenICEWithALPN(iceConn, certificate, alpn)
	if err != nil {
		_ = agent.Close()
		_ = channel.Close()
		return nil, err
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, DefaultHandshakeTimeout)
	defer cancel()
	conn, err := listener.Accept(handshakeCtx)
	if err != nil {
		_ = listener.Close()
		_ = agent.Close()
		_ = channel.Close()
		return nil, unavailable(err)
	}
	return &PeerSession{Conn: conn, agent: agent, listener: listener, signal: channel}, nil
}

// DialPeer negotiates as a client or gateway (ICE controlling, QUIC client).
// The QUIC TLS handshake succeeds only when the provider certificate matches
// the fingerprint received through channel.
func DialPeer(ctx context.Context, channel SignalChannel, cfg ICEConfig) (*PeerSession, error) {
	return dialPeerWithALPN(ctx, channel, cfg, ALPN)
}

func dialPeerWithALPN(ctx context.Context, channel SignalChannel, cfg ICEConfig, alpn string) (*PeerSession, error) {
	iceConn, agent, fingerprint, err := negotiateClientICE(ctx, channel, cfg)
	if err != nil {
		return nil, err
	}
	handshakeCtx, cancel := context.WithTimeout(ctx, DefaultHandshakeTimeout)
	defer cancel()
	conn, err := dialICEWithALPN(handshakeCtx, iceConn, fingerprint, alpn)
	if err != nil {
		_ = agent.Close()
		_ = channel.Close()
		return nil, err
	}
	return &PeerSession{Conn: conn, agent: agent, signal: channel}, nil
}

// negotiateICE is the provider-shaped result wrapper around negotiate.
func negotiateICE(ctx context.Context, channel SignalChannel, cfg ICEConfig, role PeerRole, fingerprint string) (*ice.Conn, *ice.Agent, error) {
	result, err := negotiate(ctx, channel, cfg, role, fingerprint)
	if err != nil {
		return nil, nil, err
	}
	return result.conn, result.agent, nil
}

// negotiateClientICE additionally requires the remote provider fingerprint.
func negotiateClientICE(ctx context.Context, channel SignalChannel, cfg ICEConfig) (*ice.Conn, *ice.Agent, string, error) {
	result, err := negotiate(ctx, channel, cfg, RoleClient, "")
	if err != nil {
		return nil, nil, "", err
	}
	if result.remoteFingerprint == "" {
		_ = result.agent.Close()
		return nil, nil, "", errorf(CodeUnauthenticated, "provider signaling omitted TLS fingerprint")
	}
	return result.conn, result.agent, result.remoteFingerprint, nil
}

// negotiationResult keeps the selected connection with its owning agent and
// any fingerprint learned from the remote hello.
type negotiationResult struct {
	conn              *ice.Conn
	agent             *ice.Agent
	remoteFingerprint string
}

// negotiate validates and trickles signaling while Pion gathers candidates,
// then runs the controlling or controlled ICE connectivity checks.
func negotiate(parent context.Context, channel SignalChannel, cfg ICEConfig, role PeerRole, fingerprint string) (negotiationResult, error) {
	if channel == nil || cfg.SessionID == "" || cfg.PeerID == "" {
		return negotiationResult{}, errorf(CodeInvalidArgument, "signal channel, session ID, and peer ID are required")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = DefaultICETimeout
	}
	if cfg.SignalTTL <= 0 {
		cfg.SignalTTL = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(parent, cfg.Timeout)
	defer cancel()
	agent, err := newICEAgent(cfg)
	if err != nil {
		return negotiationResult{}, err
	}
	fail := func(err error) (negotiationResult, error) {
		_ = agent.Close()
		_ = channel.Close()
		if errors.Is(err, context.DeadlineExceeded) {
			return negotiationResult{}, &Error{Code: CodeUnavailable, Message: "ICE negotiation timed out; symmetric NAT may require TURN", Err: err}
		}
		return negotiationResult{}, err
	}

	ufrag, password, err := agent.GetLocalUserCredentials()
	if err != nil {
		return fail(err)
	}
	expires := time.Now().Add(cfg.SignalTTL).UTC()
	base := Signal{ProtocolVersion: ProtocolVersion, SessionID: cfg.SessionID, PeerID: cfg.PeerID, Role: role, ExpiresAt: expires}
	hello := base
	hello.Type = SignalHello
	hello.ICEUfrag = ufrag
	hello.ICEPassword = password
	hello.TLSFingerprint = fingerprint
	if err = channel.Send(ctx, hello); err != nil {
		return fail(unavailable(err))
	}

	// Candidate gathering is asynchronous. OnCandidate trickles each candidate
	// immediately and sends the nil-candidate completion marker last.
	signalErr := make(chan error, 1)
	if err = agent.OnCandidate(func(candidate ice.Candidate) {
		message := base
		if candidate == nil {
			message.Type = SignalGatheringComplete
		} else {
			message.Type = SignalCandidate
			message.Candidate = candidate.Marshal()
		}
		if sendErr := channel.Send(ctx, message); sendErr != nil {
			select {
			case signalErr <- sendErr:
			default:
			}
		}
	}); err != nil {
		return fail(err)
	}
	if err = agent.GatherCandidates(); err != nil {
		return fail(err)
	}

	type remoteHello struct {
		ufrag, password, fingerprint string
	}
	helloCh := make(chan remoteHello, 1)
	readerDone := make(chan error, 1)
	// Signaling validation happens before values are passed to Pion. This binds
	// every message to the intended protocol, session, peer, role, and TTL.
	go func() {
		helloSent := false
		for {
			message, receiveErr := channel.Receive(ctx)
			if receiveErr != nil {
				readerDone <- receiveErr
				return
			}
			if message.ProtocolVersion != ProtocolVersion || message.SessionID != cfg.SessionID || message.PeerID == "" || message.PeerID == cfg.PeerID {
				readerDone <- errorf(CodeUnauthenticated, "invalid signaling identity or protocol version")
				return
			}
			if !message.ExpiresAt.After(time.Now()) {
				readerDone <- errorf(CodeUnauthenticated, "expired signaling message")
				return
			}
			if role == RoleProvider && message.Role != RoleClient || role == RoleClient && message.Role != RoleProvider {
				readerDone <- errorf(CodeUnauthenticated, "invalid remote signaling role")
				return
			}
			switch message.Type {
			case SignalHello:
				if helloSent || message.ICEUfrag == "" || message.ICEPassword == "" {
					readerDone <- errorf(CodeInvalidArgument, "invalid duplicate or empty ICE hello")
					return
				}
				helloSent = true
				helloCh <- remoteHello{message.ICEUfrag, message.ICEPassword, message.TLSFingerprint}
			case SignalCandidate:
				candidate, parseErr := ice.UnmarshalCandidate(message.Candidate)
				if parseErr != nil {
					readerDone <- errorf(CodeInvalidArgument, "invalid ICE candidate: %v", parseErr)
					return
				}
				if candidate.Type() != ice.CandidateTypeHost && candidate.Type() != ice.CandidateTypeServerReflexive {
					readerDone <- errorf(CodeInvalidArgument, "unsupported ICE candidate type %s", candidate.Type())
					return
				}
				if addErr := agent.AddRemoteCandidate(candidate); addErr != nil {
					readerDone <- addErr
					return
				}
			case SignalGatheringComplete:
				if addErr := agent.AddRemoteCandidate(nil); addErr != nil {
					readerDone <- addErr
					return
				}
			default:
				readerDone <- errorf(CodeInvalidArgument, "unknown signaling message type %q", message.Type)
				return
			}
		}
	}()

	var remote remoteHello
	select {
	case remote = <-helloCh:
	case err = <-readerDone:
		return fail(unavailable(err))
	case err = <-signalErr:
		return fail(unavailable(err))
	case <-ctx.Done():
		return fail(ctx.Err())
	}

	type connectResult struct {
		conn *ice.Conn
		err  error
	}
	connected := make(chan connectResult, 1)
	go func() {
		var conn *ice.Conn
		var connectErr error
		if role == RoleClient {
			conn, connectErr = agent.Dial(ctx, remote.ufrag, remote.password)
		} else {
			conn, connectErr = agent.Accept(ctx, remote.ufrag, remote.password)
		}
		connected <- connectResult{conn, connectErr}
	}()
	select {
	case result := <-connected:
		if result.err != nil {
			return fail(result.err)
		}
		return negotiationResult{conn: result.conn, agent: agent, remoteFingerprint: remote.fingerprint}, nil
	case err = <-readerDone:
		return fail(unavailable(err))
	case err = <-signalErr:
		return fail(unavailable(err))
	case <-ctx.Done():
		return fail(ctx.Err())
	}
}

// newICEAgent maps the supported v1 candidate profile into Pion configuration.
func newICEAgent(cfg ICEConfig) (*ice.Agent, error) {
	var urls []*stun.URI
	if !cfg.HostOnly {
		configured := cfg.STUNURLs
		if len(configured) == 0 {
			configured = []string{DefaultSTUNURL}
		}
		for _, raw := range configured {
			parsed, err := stun.ParseURI(raw)
			if err != nil {
				return nil, errorf(CodeInvalidArgument, "invalid STUN URL %q: %v", raw, err)
			}
			if parsed.Scheme != stun.SchemeTypeSTUN && parsed.Scheme != stun.SchemeTypeSTUNS {
				return nil, errorf(CodeInvalidArgument, "TURN URLs are not supported")
			}
			urls = append(urls, parsed)
		}
	}
	// v1 deliberately gathers UDP host and server-reflexive candidates only.
	// TURN, TCP, mDNS candidates, and implicit relays are excluded.
	candidateTypes := []ice.CandidateType{ice.CandidateTypeHost}
	if !cfg.HostOnly {
		candidateTypes = append(candidateTypes, ice.CandidateTypeServerReflexive)
	}
	agent, err := ice.NewAgent(&ice.AgentConfig{
		Urls:             urls,
		NetworkTypes:     []ice.NetworkType{ice.NetworkTypeUDP4, ice.NetworkTypeUDP6},
		CandidateTypes:   candidateTypes,
		MulticastDNSMode: ice.MulticastDNSModeDisabled,
	})
	if err != nil {
		return nil, fmt.Errorf("create ICE agent: %w", err)
	}
	return agent, nil
}
