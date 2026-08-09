package icequic

import (
	"errors"
	"net"
	"testing"
	"time"
)

type fakeConn struct {
	local, remote net.Addr
	wrote         []byte
}

func (f *fakeConn) Read([]byte) (int, error) { return 0, net.ErrClosed }
func (f *fakeConn) Write(p []byte) (int, error) {
	f.wrote = append([]byte(nil), p...)
	return len(p), nil
}
func (f *fakeConn) Close() error                     { return nil }
func (f *fakeConn) LocalAddr() net.Addr              { return f.local }
func (f *fakeConn) RemoteAddr() net.Addr             { return f.remote }
func (f *fakeConn) SetDeadline(time.Time) error      { return nil }
func (f *fakeConn) SetReadDeadline(time.Time) error  { return nil }
func (f *fakeConn) SetWriteDeadline(time.Time) error { return nil }

func TestPacketConnEnforcesSelectedRemote(t *testing.T) {
	local := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1000}
	remote := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2000}
	f := &fakeConn{local: local, remote: remote}
	pc, err := newPacketConn(f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pc.WriteTo([]byte("ok"), remote); err != nil {
		t.Fatal(err)
	}
	if string(f.wrote) != "ok" {
		t.Fatalf("wrote %q", f.wrote)
	}
	_, err = pc.WriteTo([]byte("no"), &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3000})
	if !errors.Is(err, ErrUnexpectedRemote) {
		t.Fatalf("expected ErrUnexpectedRemote, got %v", err)
	}
}

func TestPacketConnRequiresSelectedPair(t *testing.T) {
	_, err := newPacketConn(&fakeConn{})
	if err == nil {
		t.Fatal("expected an error")
	}
}
