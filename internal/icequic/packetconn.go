// Package icequic adapts Pion ICE's connected datagram transport to the
// net.PacketConn contract expected by quic-go.
package icequic

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/pion/ice/v4"
)

// ErrUnexpectedRemote is returned when quic-go attempts to send a datagram to
// an address other than the candidate pair selected by ICE. Connection
// migration is intentionally unsupported by p2pstore v1.
var ErrUnexpectedRemote = errors.New("icequic: destination is not the selected ICE peer")

// connectedDatagram captures the Pion methods needed by the adapter and permits
// deterministic unit tests without constructing a live ICE agent.
type connectedDatagram interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// PacketConn preserves the message-oriented behavior of an ICE Conn while
// exposing the address-aware methods required by net.PacketConn.
type PacketConn struct {
	conn   connectedDatagram
	remote net.Addr
}

var _ net.PacketConn = (*PacketConn)(nil)

// New wraps a connected ICE connection. ICE must already have selected a
// candidate pair, so LocalAddr and RemoteAddr must both be available.
func New(conn *ice.Conn) (*PacketConn, error) {
	return newPacketConn(conn)
}

// newPacketConn validates that ICE has selected both sides of a candidate pair.
func newPacketConn(conn connectedDatagram) (*PacketConn, error) {
	if conn == nil {
		return nil, errors.New("icequic: nil ICE connection")
	}
	if conn.LocalAddr() == nil {
		return nil, errors.New("icequic: ICE has no selected local address")
	}
	remote := conn.RemoteAddr()
	if remote == nil {
		return nil, errors.New("icequic: ICE has no selected remote address")
	}
	return &PacketConn{conn: conn, remote: remote}, nil
}

// ReadFrom reads exactly one ICE datagram and reports the selected peer as its
// source address.
func (c *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, err := c.conn.Read(p)
	return n, c.remote, err
}

// WriteTo writes one ICE datagram if addr is the selected peer. Rejecting every
// other destination prevents quic-go from migrating outside the ICE path.
func (c *PacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if !sameAddr(addr, c.remote) {
		return 0, fmt.Errorf("%w: got %v, want %v", ErrUnexpectedRemote, addr, c.remote)
	}
	return c.conn.Write(p)
}

// Close closes the underlying selected ICE connection.
func (c *PacketConn) Close() error { return c.conn.Close() }

// LocalAddr returns the selected ICE pair's local address.
func (c *PacketConn) LocalAddr() net.Addr { return c.conn.LocalAddr() }

// RemoteAddr returns the selected ICE pair's remote address.
func (c *PacketConn) RemoteAddr() net.Addr { return c.remote }

// SetDeadline delegates the read and write deadline to the ICE connection.
func (c *PacketConn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

// SetReadDeadline delegates the read deadline to the ICE connection.
func (c *PacketConn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

// SetWriteDeadline delegates the write deadline to the ICE connection.
func (c *PacketConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }

// sameAddr compares the stable network and string forms exposed by the selected
// ICE pair rather than relying on concrete address types.
func sameAddr(a, b net.Addr) bool {
	if a == nil || b == nil || a.Network() != b.Network() {
		return false
	}
	return a.String() == b.String()
}
