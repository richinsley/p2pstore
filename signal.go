package p2pstore

import (
	"context"
	"time"
)

// SignalType identifies one step in trickled ICE negotiation.
type SignalType string

const (
	// SignalHello carries a peer's ICE credentials and, for a provider, its
	// ephemeral TLS certificate fingerprint.
	SignalHello SignalType = "hello"
	// SignalCandidate carries one marshaled host or server-reflexive candidate.
	SignalCandidate SignalType = "candidate"
	// SignalGatheringComplete reports that a peer has no more ICE candidates.
	SignalGatheringComplete SignalType = "gathering_complete"
)

// PeerRole determines the ICE and QUIC roles used by a peer session.
type PeerRole string

const (
	// RoleProvider is ICE-controlled and accepts the QUIC connection.
	RoleProvider PeerRole = "provider"
	// RoleClient is ICE-controlling and dials the QUIC connection.
	RoleClient PeerRole = "client"
)

// Signal contains only connection setup metadata. Object bytes must never be
// placed in this type or carried by a SignalChannel.
type Signal struct {
	// ProtocolVersion must equal ProtocolVersion.
	ProtocolVersion int `json:"protocol_version"`
	// Type identifies the fields populated in this message.
	Type SignalType `json:"type"`
	// SessionID binds every message to one peer-session attempt.
	SessionID string `json:"session_id"`
	// PeerID identifies the sender and must differ from the receiving peer.
	PeerID string `json:"peer_id"`
	// Role is the sender's fixed role for this session.
	Role PeerRole `json:"role"`
	// ICEUfrag is present on SignalHello.
	ICEUfrag string `json:"ice_ufrag,omitempty"`
	// ICEPassword is present on SignalHello and must remain secret.
	ICEPassword string `json:"ice_password,omitempty"`
	// Candidate is a Pion-marshaled ICE candidate on SignalCandidate.
	Candidate string `json:"candidate,omitempty"`
	// ExpiresAt limits replay of signaling metadata.
	ExpiresAt time.Time `json:"expires_at"`
	// TLSFingerprint is the provider's ephemeral leaf-certificate SHA-256 pin.
	TLSFingerprint string `json:"tls_fingerprint,omitempty"`
}

// SignalChannel is an ordered, bidirectional exchange of signaling messages
// for one peer session. Implementations carry metadata only and must never put
// object bodies on the signaling transport.
type SignalChannel interface {
	// Send publishes one signal or returns when ctx is canceled.
	Send(context.Context, Signal) error
	// Receive waits for the next remote signal or ctx cancellation.
	Receive(context.Context) (Signal, error)
	// Close releases subscriptions, long polls, or session state.
	Close() error
}

// SignalDialer obtains the client side of a named signaling session.
type SignalDialer interface {
	// Dial opens sessionID and returns its bidirectional channel.
	Dial(context.Context, string) (SignalChannel, error)
}

// SignalListener accepts provider-side signaling sessions.
type SignalListener interface {
	// Accept waits for the next signaling session.
	Accept(context.Context) (SignalChannel, error)
	// Close stops acceptance and releases listener resources.
	Close() error
}
