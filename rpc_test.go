package p2pstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/richinsley/p2pstore/internal/wire"
)

func TestRPCStreamingCRUDAndConcurrentStreams(t *testing.T) {
	store := newTestStore(t, nil)
	client, stop := directQUICPair(t, store)
	defer stop()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := client.Ping(ctx); err != nil {
		t.Fatal(err)
	}

	oversized, err := client.conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err = wire.WriteHeader(oversized, rpcRequest{
		Version: ProtocolVersion, Operation: opPut, Bucket: "bucket", Key: "oversized", BodySize: 3,
		Put: PutOptions{Size: 3},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = oversized.Write([]byte("four")); err != nil {
		t.Fatal(err)
	}
	if err = oversized.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = readResponse(oversized); !IsCode(err, CodeInvalidArgument) {
		t.Fatalf("oversized PUT returned %v", err)
	}
	if _, err = store.Head(ctx, "bucket", "oversized"); !IsCode(err, CodeNotFound) {
		t.Fatalf("oversized PUT became visible: %v", err)
	}

	const transfers = 8
	const objectSize = 2 * 1024 * 1024
	var wg sync.WaitGroup
	errs := make(chan error, transfers)
	for i := range transfers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := "concurrent/" + string(rune('a'+i))
			payload := bytes.Repeat([]byte{byte(i + 1)}, objectSize)
			info, err := client.Put(ctx, "bucket", key, bytes.NewReader(payload), PutOptions{Size: int64(len(payload)), ContentType: "application/octet-stream"})
			if err != nil {
				errs <- err
				return
			}
			wantHash := sha256.Sum256(payload)
			if info.Size != objectSize || info.ETag == "" || wantHash == [32]byte{} {
				errs <- errors.New("invalid PUT metadata")
				return
			}
			gotInfo, body, err := client.Get(ctx, "bucket", key)
			if err != nil {
				errs <- err
				return
			}
			got, readErr := io.ReadAll(body)
			_ = body.Close()
			if readErr != nil || !bytes.Equal(got, payload) || gotInfo.ETag != info.ETag {
				errs <- errors.New("GET payload or metadata mismatch")
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	result, err := client.List(ctx, "bucket", ListOptions{Prefix: "concurrent/", Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Truncated || len(result.Objects) != 3 {
		t.Fatalf("unexpected first list page: %+v", result)
	}
	next, err := client.List(ctx, "bucket", ListOptions{Prefix: "concurrent/", Limit: 100, Cursor: result.NextCursor})
	if err != nil || next.Truncated || len(next.Objects) != transfers-3 {
		t.Fatalf("unexpected second list page: %+v err=%v", next, err)
	}
	if err = client.Delete(ctx, "bucket", result.Objects[0].Key); err != nil {
		t.Fatal(err)
	}
	if err = client.Delete(ctx, "bucket", result.Objects[0].Key); err != nil {
		t.Fatal(err)
	}
	_, err = client.Head(ctx, "bucket", result.Objects[0].Key)
	if !IsCode(err, CodeNotFound) {
		t.Fatalf("remote typed not-found error lost: %v", err)
	}
}

func TestRPCRejectsWrongCertificatePin(t *testing.T) {
	serverUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer serverUDP.Close()
	certificate, err := NewSessionCertificate(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, _ := certificate.ServerTLSConfig()
	listener, err := quic.Listen(serverUDP, serverTLS, QUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	go func() {
		_, _ = listener.Accept(ctx)
	}()
	clientUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer clientUDP.Close()
	wrong := make([]byte, sha256.Size)
	wrongTLS, err := PinnedClientTLSConfig(bytesToHex(wrong))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = quic.Dial(ctx, clientUDP, serverUDP.LocalAddr(), wrongTLS, QUICConfig()); err == nil {
		t.Fatal("QUIC accepted the wrong certificate fingerprint")
	}
}

func TestRPCServerCancellationUnblocksActiveStream(t *testing.T) {
	serverUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer serverUDP.Close()
	certificate, err := NewSessionCertificate(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := certificate.ServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.Listen(serverUDP, serverTLS, QUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverCtx, cancelServer := context.WithCancel(context.Background())
	defer cancelServer()
	accepted := make(chan *quic.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept(serverCtx)
		if acceptErr == nil {
			accepted <- conn
		}
	}()
	clientUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer clientUDP.Close()
	clientTLS, err := PinnedClientTLSConfig(certificate.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	clientConn, err := quic.Dial(serverCtx, clientUDP, serverUDP.LocalAddr(), clientTLS, QUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	defer clientConn.CloseWithError(0, "test complete")
	serverConn := <-accepted

	blocked := &blockingPutStore{started: make(chan struct{})}
	serveDone := make(chan error, 1)
	go func() { serveDone <- (&RPCServer{Store: blocked}).Serve(serverCtx, serverConn) }()
	stream, err := clientConn.OpenStreamSync(serverCtx)
	if err != nil {
		t.Fatal(err)
	}
	if err = wire.WriteHeader(stream, rpcRequest{
		Version: ProtocolVersion, Operation: opPut, Bucket: "bucket", Key: "blocked", BodySize: -1,
		Put: PutOptions{Size: -1},
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocked.started:
	case <-time.After(2 * time.Second):
		t.Fatal("PUT handler did not begin reading the active stream")
	}

	cancelServer()
	select {
	case err = <-serveDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Serve returned %v, want context cancellation", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("RPC server did not release an active stream during cancellation")
	}
}

type blockingPutStore struct {
	ObjectStore
	started chan struct{}
}

func (s *blockingPutStore) Put(_ context.Context, _, _ string, body io.Reader, _ PutOptions) (ObjectInfo, error) {
	close(s.started)
	var one [1]byte
	_, err := body.Read(one[:])
	return ObjectInfo{}, err
}

func directQUICPair(t *testing.T, store ObjectStore) (*Client, func()) {
	t.Helper()
	serverUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := NewSessionCertificate(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	serverTLS, err := certificate.ServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	listener, err := quic.Listen(serverUDP, serverTLS, QUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	serverConnCh := make(chan *quic.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept(ctx)
		if acceptErr == nil {
			serverConnCh <- conn
		}
	}()
	clientUDP, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	clientTLS, err := PinnedClientTLSConfig(certificate.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	clientConn, err := quic.Dial(ctx, clientUDP, serverUDP.LocalAddr(), clientTLS, QUICConfig())
	if err != nil {
		t.Fatal(err)
	}
	serverConn := <-serverConnCh
	go func() { _ = (&RPCServer{Store: store}).Serve(ctx, serverConn) }()
	client, err := NewClient(clientConn)
	if err != nil {
		t.Fatal(err)
	}
	return client, func() {
		cancel()
		_ = client.Close()
		_ = serverConn.CloseWithError(0, "test complete")
		_ = listener.Close()
		_ = clientUDP.Close()
		_ = serverUDP.Close()
	}
}

func bytesToHex(value []byte) string {
	const digits = "0123456789abcdef"
	result := make([]byte, len(value)*2)
	for i, b := range value {
		result[i*2] = digits[b>>4]
		result[i*2+1] = digits[b&15]
	}
	return string(result)
}
