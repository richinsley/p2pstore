package p2pstore

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestCommSessionHostICEStreams(t *testing.T) {
	providerSignal, clientSignal := memorySignalPair()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	providerConfig := DefaultICEConfig("comm-session", "provider")
	providerConfig.HostOnly = true
	clientConfig := DefaultICEConfig("comm-session", "client")
	clientConfig.HostOnly = true

	providerCh := make(chan *CommSession, 1)
	providerErr := make(chan error, 1)
	go func() {
		session, err := AcceptComm(ctx, providerSignal, providerConfig)
		if err != nil {
			providerErr <- err
			return
		}
		providerCh <- session
	}()
	client, err := DialComm(ctx, clientSignal, clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var provider *CommSession
	select {
	case provider = <-providerCh:
	case err = <-providerErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer provider.Close()
	for _, session := range []*CommSession{client, provider} {
		if got := session.peer.Conn.ConnectionState().TLS.NegotiatedProtocol; got != CommALPN {
			t.Fatalf("comm negotiated ALPN %q", got)
		}
	}

	// A closed stream must not close the shared QUIC/ICE session.
	for i := range 2 {
		outgoing, err := client.OpenConn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		incoming, err := provider.AcceptConn(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if outgoing.LocalAddr() == nil || outgoing.RemoteAddr() == nil || incoming.LocalAddr() == nil || incoming.RemoteAddr() == nil {
			t.Fatal("comm connection has no selected path addresses")
		}
		// The accepting side can greet first; opening a net.Conn must not
		// depend on the dialing application writing its own payload.
		if _, err := incoming.Write([]byte("!")); err != nil {
			t.Fatal(err)
		}
		got := make([]byte, 1)
		if _, err := io.ReadFull(outgoing, got); err != nil || got[0] != '!' {
			t.Fatalf("stream %d greeting: got %q, err %v", i, got, err)
		}
		want := []byte{byte('a' + i)}
		if _, err := outgoing.Write(want); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(incoming, got); err != nil || got[0] != want[0] {
			t.Fatalf("stream %d: got %q, err %v", i, got, err)
		}
		if err := outgoing.Close(); err != nil {
			t.Fatal(err)
		}
		if err := outgoing.Close(); err != nil {
			t.Fatalf("repeat close: %v", err)
		}
		if _, err := incoming.Read(got); err != io.EOF {
			t.Fatalf("stream %d close: got %v, want EOF", i, err)
		}
		if err := incoming.Close(); err != nil {
			t.Fatal(err)
		}
	}

	// net.Conn deadlines apply to the stream without terminating the session.
	conn, err := provider.OpenConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer, err := client.AcceptConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	if err := conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err = conn.Read(make([]byte, 1))
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("read deadline: got %v", err)
	}
}
