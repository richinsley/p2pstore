package p2pstore

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

type memorySignal struct {
	send chan<- Signal
	recv <-chan Signal
}

func memorySignalPair() (*memorySignal, *memorySignal) {
	aToB := make(chan Signal, 64)
	bToA := make(chan Signal, 64)
	return &memorySignal{send: aToB, recv: bToA}, &memorySignal{send: bToA, recv: aToB}
}

func (m *memorySignal) Send(ctx context.Context, signal Signal) error {
	select {
	case m.send <- signal:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *memorySignal) Receive(ctx context.Context) (Signal, error) {
	select {
	case signal := <-m.recv:
		return signal, nil
	case <-ctx.Done():
		return Signal{}, ctx.Err()
	}
}

func (m *memorySignal) Close() error { return nil }

func TestHostICEPeerSessionEndToEnd(t *testing.T) {
	providerSignal, clientSignal := memorySignalPair()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	providerConfig := DefaultICEConfig("session", "provider")
	providerConfig.HostOnly = true
	clientConfig := DefaultICEConfig("session", "client")
	clientConfig.HostOnly = true
	providerCh := make(chan *PeerSession, 1)
	errCh := make(chan error, 2)
	go func() {
		session, err := AcceptPeer(ctx, providerSignal, providerConfig)
		if err != nil {
			errCh <- err
			return
		}
		providerCh <- session
	}()
	clientSession, err := DialPeer(ctx, clientSignal, clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()
	var providerSession *PeerSession
	select {
	case providerSession = <-providerCh:
	case err = <-errCh:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	defer providerSession.Close()

	store := newTestStore(t, nil)
	go func() { errCh <- (&RPCServer{Store: store}).Serve(ctx, providerSession.Conn) }()
	client, err := NewClient(clientSession.Conn)
	if err != nil {
		t.Fatal(err)
	}
	want := bytes.Repeat([]byte("p2p"), 1024*1024)
	info, err := client.Put(ctx, "bucket", "large/object", bytes.NewReader(want), PutOptions{Size: int64(len(want))})
	if err != nil {
		t.Fatal(err)
	}
	gotInfo, body, err := client.Get(ctx, "bucket", "large/object")
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(body)
	_ = body.Close()
	if err != nil || !bytes.Equal(got, want) || gotInfo.ETag != info.ETag {
		t.Fatalf("end-to-end mismatch: bytes=%d err=%v", len(got), err)
	}
}
