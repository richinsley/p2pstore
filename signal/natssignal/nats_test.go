package natssignal

import (
	"context"
	"testing"
	"time"

	server "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/richinsley/p2pstore"
)

func testNATS(t *testing.T) *nats.Conn {
	t.Helper()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS server did not start")
	}
	t.Cleanup(srv.Shutdown)
	nc, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	return nc
}

func TestNATSSignalRoundTrip(t *testing.T) {
	nc := testNATS(t)
	listener, err := NewListener(nc, "provider")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	dialer := &Dialer{NC: nc, PeerID: "client", RemotePeerID: "provider"}
	client, err := dialer.Dial(context.Background(), "session")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	want := p2pstore.Signal{ProtocolVersion: 1, Type: p2pstore.SignalHello, SessionID: "session", PeerID: "client", Role: p2pstore.RoleClient, ExpiresAt: time.Now().Add(time.Minute)}
	if err = client.Send(ctx, want); err != nil {
		t.Fatal(err)
	}
	if err = nc.Flush(); err != nil {
		t.Fatal(err)
	}
	provider, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got, err := provider.Receive(ctx)
	if err != nil || got.PeerID != "client" {
		t.Fatalf("provider receive: %+v err=%v", got, err)
	}
	reply := want
	reply.PeerID = "provider"
	reply.Role = p2pstore.RoleProvider
	if err = provider.Send(ctx, reply); err != nil {
		t.Fatal(err)
	}
	if err = nc.Flush(); err != nil {
		t.Fatal(err)
	}
	got, err = client.Receive(ctx)
	if err != nil || got.PeerID != "provider" {
		t.Fatalf("client receive: %+v err=%v", got, err)
	}
}

func TestProviderDiscoveryRejectsAmbiguity(t *testing.T) {
	nc := testNATS(t)
	first, err := AnnounceProvider(nc, "node-a")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Unsubscribe()
	if err = nc.Flush(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	provider, err := DiscoverProvider(ctx, nc, "")
	if err != nil || provider != "node-a" {
		t.Fatalf("discover one: provider=%q err=%v", provider, err)
	}
	second, err := AnnounceProvider(nc, "node-b")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Unsubscribe()
	if err = nc.Flush(); err != nil {
		t.Fatal(err)
	}
	_, err = DiscoverProvider(ctx, nc, "")
	if !p2pstore.IsCode(err, p2pstore.CodeUnavailable) {
		t.Fatalf("ambiguous discovery = %v", err)
	}
	provider, err = DiscoverProvider(ctx, nc, "node-b")
	if err != nil || provider != "node-b" {
		t.Fatalf("explicit discovery: provider=%q err=%v", provider, err)
	}
}
