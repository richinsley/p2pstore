package p2pstore

import (
	"context"
	"errors"
	"time"

	"github.com/pion/ice/v4"
	quic "github.com/quic-go/quic-go"

	"github.com/richinsley/p2pstore/internal/icequic"
)

const (
	// DefaultICETimeout bounds signaling and ICE negotiation.
	DefaultICETimeout = 30 * time.Second
	// DefaultHandshakeTimeout bounds the QUIC/TLS handshake.
	DefaultHandshakeTimeout = 10 * time.Second
	// DefaultIdleTimeout closes a QUIC connection with no network activity.
	DefaultIdleTimeout = 2 * time.Minute
	// DefaultSTUNURL is used when ICEConfig does not provide STUN servers.
	DefaultSTUNURL = "stun:stun.l.google.com:19302"
)

// QUICConfig returns a fresh v1 transport configuration. It allows at most 128
// peer-initiated bidirectional streams and disables unidirectional streams,
// 0-RTT, QUIC datagrams, and active path-MTU discovery. Connection migration is
// prevented by the ICE PacketConn accepting only the selected remote address.
func QUICConfig() *quic.Config {
	return &quic.Config{
		HandshakeIdleTimeout:    DefaultHandshakeTimeout,
		MaxIdleTimeout:          DefaultIdleTimeout,
		MaxIncomingStreams:      128,
		MaxIncomingUniStreams:   -1,
		Allow0RTT:               false,
		EnableDatagrams:         false,
		DisablePathMTUDiscovery: true,
	}
}

// ListenICE starts a single-session QUIC listener over an already connected
// ICE pair. Closing the listener closes the ICE connection.
func ListenICE(conn *ice.Conn, certificate SessionCertificate) (*quic.Listener, error) {
	return listenICEWithALPN(conn, certificate, ALPN)
}

func listenICEWithALPN(conn *ice.Conn, certificate SessionCertificate, alpn string) (*quic.Listener, error) {
	packetConn, err := icequic.New(conn)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := certificate.ServerTLSConfig()
	if err != nil {
		_ = packetConn.Close()
		return nil, err
	}
	tlsConfig.NextProtos = []string{alpn}
	listener, err := quic.Listen(packetConn, tlsConfig, QUICConfig())
	if err != nil {
		_ = packetConn.Close()
		return nil, err
	}
	return listener, nil
}

// DialICE establishes QUIC over an already connected ICE pair and requires a
// certificate fingerprint received through authenticated signaling.
func DialICE(ctx context.Context, conn *ice.Conn, fingerprint string) (*quic.Conn, error) {
	return dialICEWithALPN(ctx, conn, fingerprint, ALPN)
}

func dialICEWithALPN(ctx context.Context, conn *ice.Conn, fingerprint, alpn string) (*quic.Conn, error) {
	packetConn, err := icequic.New(conn)
	if err != nil {
		return nil, err
	}
	tlsConfig, err := PinnedClientTLSConfig(fingerprint)
	if err != nil {
		_ = packetConn.Close()
		return nil, err
	}
	tlsConfig.NextProtos = []string{alpn}
	remote := packetConn.RemoteAddr()
	quicConn, err := quic.Dial(ctx, packetConn, remote, tlsConfig, QUICConfig())
	if err != nil {
		_ = packetConn.Close()
		var typed *Error
		if errors.As(err, &typed) && typed.Code == CodeUnauthenticated {
			return nil, typed
		}
		return nil, unavailable(err)
	}
	return quicConn, nil
}
