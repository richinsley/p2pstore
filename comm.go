package p2pstore

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	quic "github.com/quic-go/quic-go"
)

// CommALPN separates application byte streams from the p2pstore object RPC.
// Both peers must explicitly select the comm API; an object client cannot
// connect to a comm listener or interpret its streams as object operations.
const CommALPN = "p2pstore-comm/1"

// Opening a QUIC stream does not notify its peer until the first stream byte
// is sent. Consume this byte before exposing the stream as net.Conn so a
// server-first protocol can accept a connection and send its greeting.
const commStreamOpenByte = 1

// CommSession owns one ICE-selected QUIC connection and its signaling channel.
// Each OpenConn or AcceptConn returns an independent bidirectional net.Conn.
// Close the session when its streams are no longer needed; closing one stream
// does not close the session or another stream.
type CommSession struct {
	peer *PeerSession
}

// AcceptComm negotiates the provider/ICE-controlled side of a comm session.
// The caller supplies any SignalChannel, including one obtained from an HTTP
// rendezvous listener. It must close the returned session.
func AcceptComm(ctx context.Context, channel SignalChannel, cfg ICEConfig) (*CommSession, error) {
	peer, err := acceptPeerWithALPN(ctx, channel, cfg, CommALPN)
	if err != nil {
		return nil, err
	}
	return &CommSession{peer: peer}, nil
}

// DialComm negotiates the client/ICE-controlling side of a comm session. The
// provider certificate remains pinned to the fingerprint in signaling.
func DialComm(ctx context.Context, channel SignalChannel, cfg ICEConfig) (*CommSession, error) {
	peer, err := dialPeerWithALPN(ctx, channel, cfg, CommALPN)
	if err != nil {
		return nil, err
	}
	return &CommSession{peer: peer}, nil
}

// OpenConn opens a new byte-stream connection to the remote peer.
func (s *CommSession) OpenConn(ctx context.Context) (net.Conn, error) {
	if s == nil || s.peer == nil || s.peer.Conn == nil {
		return nil, errorf(CodeInvalidArgument, "comm session is empty")
	}
	stream, err := s.peer.Conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, unavailable(err)
	}
	if _, err := stream.Write([]byte{commStreamOpenByte}); err != nil {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		return nil, unavailable(err)
	}
	return newCommConn(s.peer.Conn, stream), nil
}

// AcceptConn waits for the next byte-stream connection from the remote peer.
func (s *CommSession) AcceptConn(ctx context.Context) (net.Conn, error) {
	if s == nil || s.peer == nil || s.peer.Conn == nil {
		return nil, errorf(CodeInvalidArgument, "comm session is empty")
	}
	stream, err := s.peer.Conn.AcceptStream(ctx)
	if err != nil {
		return nil, unavailable(err)
	}
	stop := context.AfterFunc(ctx, func() { stream.CancelRead(0) })
	var opener [1]byte
	_, err = io.ReadFull(stream, opener[:])
	stop()
	if err != nil || opener[0] != commStreamOpenByte {
		stream.CancelRead(0)
		stream.CancelWrite(0)
		if err != nil {
			return nil, unavailable(err)
		}
		return nil, errorf(CodeInvalidArgument, "invalid comm stream opener")
	}
	return newCommConn(s.peer.Conn, stream), nil
}

// Close releases every stream, the QUIC connection, ICE agent, and signaling.
func (s *CommSession) Close() error {
	if s == nil || s.peer == nil {
		return nil
	}
	return s.peer.Close()
}

// CommConn adapts one QUIC bidirectional stream to net.Conn. Closing it sends
// a write FIN and cancels reads; the enclosing CommSession remains usable.
type CommConn struct {
	stream *quic.Stream
	local  net.Addr
	remote net.Addr
	close  sync.Once
}

func newCommConn(conn *quic.Conn, stream *quic.Stream) *CommConn {
	return &CommConn{stream: stream, local: conn.LocalAddr(), remote: conn.RemoteAddr()}
}

func (c *CommConn) Read(p []byte) (int, error)         { return c.stream.Read(p) }
func (c *CommConn) Write(p []byte) (int, error)        { return c.stream.Write(p) }
func (c *CommConn) LocalAddr() net.Addr                { return c.local }
func (c *CommConn) RemoteAddr() net.Addr               { return c.remote }
func (c *CommConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *CommConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *CommConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

func (c *CommConn) Close() error {
	c.close.Do(func() {
		// A peer may already have canceled its read side. quic-go then
		// reports a canceled-stream error from Close, but this local
		// net.Conn is still closed and no caller action is possible.
		_ = c.stream.Close()
		c.stream.CancelRead(0)
	})
	return nil
}

var _ net.Conn = (*CommConn)(nil)
