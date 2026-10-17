package p2pstore_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/richinsley/p2pstore"
	"github.com/richinsley/p2pstore/signal/rendezvous"
)

func TestCommWithMountedHTTPRendezvous(t *testing.T) {
	mux := http.NewServeMux()
	mux.Handle("/connect/", http.StripPrefix("/connect", rendezvous.NewServer()))
	server := httptest.NewServer(mux)
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	listener, err := rendezvous.NewProviderListener(ctx, server.URL+"/connect", "provider", server.Client())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	code, err := rendezvous.ParseJoinCode(listener.JoinCode())
	if err != nil {
		t.Fatal(err)
	}
	dialer, err := rendezvous.NewDialer(listener.JoinCode(), server.Client())
	if err != nil {
		t.Fatal(err)
	}
	providerChannel, err := listener.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	clientChannel, err := dialer.Dial(ctx, code.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	providerConfig := p2pstore.DefaultICEConfig(code.SessionID, code.ProviderID)
	providerConfig.HostOnly = true
	clientConfig := p2pstore.DefaultICEConfig(code.SessionID, "client")
	clientConfig.HostOnly = true

	providerCh := make(chan *p2pstore.CommSession, 1)
	providerErr := make(chan error, 1)
	go func() {
		comm, acceptErr := p2pstore.AcceptComm(ctx, providerChannel, providerConfig)
		if acceptErr != nil {
			providerErr <- acceptErr
			return
		}
		providerCh <- comm
	}()
	client, err := p2pstore.DialComm(ctx, clientChannel, clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var provider *p2pstore.CommSession
	select {
	case provider = <-providerCh:
	case err = <-providerErr:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer provider.Close()

	outgoing, err := client.OpenConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer outgoing.Close()
	incoming, err := provider.AcceptConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer incoming.Close()
	if _, err := outgoing.Write([]byte("mesh")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(incoming, got); err != nil || string(got) != "mesh" {
		t.Fatalf("mounted rendezvous comm: got %q, err %v", got, err)
	}
}
