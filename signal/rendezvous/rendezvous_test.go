package rendezvous

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/richinsley/p2pstore"
)

func TestEncryptedRendezvousRoundTripAndCapabilityRejection(t *testing.T) {
	server := NewServer()
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	listener, err := NewProviderListener(ctx, httpServer.URL, "provider-a", httpServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	parsed, err := ParseJoinCode(listener.JoinCode())
	if err != nil || parsed.ProviderID != "provider-a" {
		t.Fatalf("join code: %+v err=%v", parsed, err)
	}
	provider, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := NewDialer(listener.JoinCode(), httpServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	client, err := dialer.Dial(ctx, parsed.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	want := p2pstore.Signal{
		ProtocolVersion: 1, Type: p2pstore.SignalHello, SessionID: parsed.SessionID,
		PeerID: "client-a", Role: p2pstore.RoleClient, ICEUfrag: "secret-ufrag", ICEPassword: "secret-password",
		ExpiresAt: time.Now().Add(time.Minute),
	}
	if err = client.Send(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := provider.Receive(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.ICEUfrag != want.ICEUfrag || got.ICEPassword != want.ICEPassword {
		t.Fatalf("got %+v", got)
	}

	server.mu.Lock()
	stored, _ := json.Marshal(server.sessions[parsed.SessionID].messages["provider"])
	server.mu.Unlock()
	if strings.Contains(string(stored), "secret-ufrag") || strings.Contains(string(stored), "secret-password") {
		t.Fatalf("server stored plaintext signaling: %s", stored)
	}

	bad := parsed
	bad.Capability = strings.Repeat("A", 43)
	badDialer := &Dialer{Code: bad, Client: httpServer.Client()}
	badChannel, err := badDialer.Dial(ctx, bad.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	err = badChannel.Send(ctx, want)
	if !p2pstore.IsCode(err, p2pstore.CodeUnauthenticated) {
		t.Fatalf("expected capability rejection, got %v", err)
	}
	if err = client.Close(); err != nil {
		t.Fatal(err)
	}
	if err = listener.Close(); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	_, retained := server.sessions[parsed.SessionID]
	server.mu.Unlock()
	if retained {
		t.Fatal("used rendezvous session was retained")
	}
}

func TestRendezvousExpiryAndHTTPSRequirement(t *testing.T) {
	if _, err := NewJoinCode("http://example.com", "provider"); err == nil {
		t.Fatal("non-loopback HTTP rendezvous URL was accepted")
	}
	server := NewServer()
	server.MaxSessionTTL = 20 * time.Millisecond
	httpServer := httptest.NewServer(server)
	defer httpServer.Close()
	ctx := context.Background()
	listener, err := NewProviderListener(ctx, httpServer.URL, "provider", httpServer.Client())
	if err != nil {
		t.Fatal(err)
	}
	code, _ := ParseJoinCode(listener.JoinCode())
	dialer, _ := NewDialer(listener.JoinCode(), httpServer.Client())
	client, err := dialer.Dial(ctx, code.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond)
	err = client.Send(ctx, p2pstore.Signal{ProtocolVersion: 1})
	if !p2pstore.IsCode(err, p2pstore.CodeUnauthenticated) {
		t.Fatalf("expired session error = %v", err)
	}
}
