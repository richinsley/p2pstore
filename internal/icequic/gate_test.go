package icequic

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/ice/v4"
	quic "github.com/quic-go/quic-go"
)

// TestICEQUICTransportGate is deliberately an end-to-end feasibility gate.
// Storage RPCs rely on all properties exercised here.
func TestICEQUICTransportGate(t *testing.T) {
	leftICE, rightICE := connectedICEPair(t)
	left, err := New(leftICE)
	if err != nil {
		t.Fatal(err)
	}
	right, err := New(rightICE)
	if err != nil {
		t.Fatal(err)
	}

	// ICE Conn and the adapter must preserve datagram boundaries and MTU-sized
	// payloads before ownership passes to quic-go.
	wantPackets := [][]byte{[]byte("first"), bytes.Repeat([]byte{0xa5}, 1280)}
	for _, want := range wantPackets {
		if _, err = left.WriteTo(want, left.remote); err != nil {
			t.Fatalf("raw WriteTo: %v", err)
		}
		got := make([]byte, 1500)
		n, from, readErr := right.ReadFrom(got)
		if readErr != nil {
			t.Fatalf("raw ReadFrom: %v", readErr)
		}
		if from.String() != right.remote.String() || !bytes.Equal(got[:n], want) {
			t.Fatalf("datagram mismatch: from=%v size=%d", from, n)
		}
	}

	if err = right.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, _, err = right.ReadFrom(make([]byte, 1))
	var netErr net.Error
	if !errorsAs(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("read deadline did not produce timeout: %v", err)
	}
	if err = right.SetReadDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}

	serverTLS, fingerprint := gateCertificate(t)
	clientTLS := &tls.Config{
		InsecureSkipVerify: true, // Verification is replaced by mandatory fingerprint pinning below.
		NextProtos:         []string{"p2pstore/1"},
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 {
				return fmt.Errorf("unexpected certificate chain length %d", len(state.PeerCertificates))
			}
			got := sha256.Sum256(state.PeerCertificates[0].Raw)
			if !bytes.Equal(got[:], fingerprint[:]) {
				return fmt.Errorf("certificate fingerprint mismatch")
			}
			return nil
		},
	}
	qconf := &quic.Config{
		HandshakeIdleTimeout:    10 * time.Second,
		MaxIdleTimeout:          2 * time.Minute,
		MaxIncomingStreams:      128,
		MaxIncomingUniStreams:   -1,
		Allow0RTT:               false,
		DisablePathMTUDiscovery: true,
	}
	listener, err := quic.Listen(right, serverTLS, qconf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	testCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	serverConnCh := make(chan *quic.Conn, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept(testCtx)
		if acceptErr != nil {
			serverErrCh <- acceptErr
			return
		}
		serverConnCh <- conn
	}()
	clientConn, err := quic.Dial(testCtx, left, left.remote, clientTLS, qconf)
	if err != nil {
		t.Fatalf("QUIC handshake through ICE: %v", err)
	}
	t.Cleanup(func() { _ = clientConn.CloseWithError(0, "test complete") })
	var serverConn *quic.Conn
	select {
	case serverConn = <-serverConnCh:
	case err = <-serverErrCh:
		t.Fatalf("accept QUIC: %v", err)
	case <-testCtx.Done():
		t.Fatal(testCtx.Err())
	}
	t.Cleanup(func() { _ = serverConn.CloseWithError(0, "test complete") })
	if clientConn.ConnectionState().TLS.NegotiatedProtocol != "p2pstore/1" {
		t.Fatalf("unexpected ALPN %q", clientConn.ConnectionState().TLS.NegotiatedProtocol)
	}
	if clientConn.ConnectionState().Used0RTT {
		t.Fatal("0-RTT was used")
	}

	const streams = 8
	var serveWG sync.WaitGroup
	serveWG.Add(streams)
	for range streams {
		go func() {
			defer serveWG.Done()
			stream, acceptErr := serverConn.AcceptStream(testCtx)
			if acceptErr != nil {
				serverErrCh <- acceptErr
				return
			}
			body, readErr := io.ReadAll(stream)
			if readErr != nil {
				serverErrCh <- readErr
				return
			}
			_, writeErr := stream.Write(body)
			if writeErr == nil {
				writeErr = stream.Close()
			}
			if writeErr != nil {
				serverErrCh <- writeErr
			}
		}()
	}

	var clientWG sync.WaitGroup
	clientWG.Add(streams)
	for i := range streams {
		go func(i int) {
			defer clientWG.Done()
			stream, openErr := clientConn.OpenStreamSync(testCtx)
			if openErr != nil {
				serverErrCh <- openErr
				return
			}
			want := bytes.Repeat([]byte{byte(i + 1)}, 1280)
			if _, writeErr := stream.Write(want); writeErr != nil {
				serverErrCh <- writeErr
				return
			}
			if closeErr := stream.Close(); closeErr != nil {
				serverErrCh <- closeErr
				return
			}
			got, readErr := io.ReadAll(stream)
			if readErr != nil || !bytes.Equal(got, want) {
				serverErrCh <- fmt.Errorf("stream %d mismatch: read=%v size=%d", i, readErr, len(got))
			}
		}(i)
	}
	clientWG.Wait()
	serveWG.Wait()
	select {
	case err = <-serverErrCh:
		t.Fatal(err)
	default:
	}

	cancelled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if _, err = clientConn.OpenStreamSync(cancelled); err == nil {
		t.Fatal("canceled stream open unexpectedly succeeded")
	}
}

func connectedICEPair(t *testing.T) (*ice.Conn, *ice.Conn) {
	t.Helper()
	cfg := &ice.AgentConfig{
		NetworkTypes:     []ice.NetworkType{ice.NetworkTypeUDP4, ice.NetworkTypeUDP6},
		CandidateTypes:   []ice.CandidateType{ice.CandidateTypeHost},
		MulticastDNSMode: ice.MulticastDNSModeDisabled,
	}
	a, err := ice.NewAgent(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ice.NewAgent(cfg)
	if err != nil {
		_ = a.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })

	var gather sync.WaitGroup
	gather.Add(2)
	if err = a.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			gather.Done()
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err = b.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			gather.Done()
		}
	}); err != nil {
		t.Fatal(err)
	}
	if err = a.GatherCandidates(); err != nil {
		t.Fatal(err)
	}
	if err = b.GatherCandidates(); err != nil {
		t.Fatal(err)
	}
	gather.Wait()
	exchange := func(from, to *ice.Agent) {
		candidates, getErr := from.GetLocalCandidates()
		if getErr != nil {
			t.Fatal(getErr)
		}
		for _, candidate := range candidates {
			clone, parseErr := ice.UnmarshalCandidate(candidate.Marshal())
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			if addErr := to.AddRemoteCandidate(clone); addErr != nil {
				t.Fatal(addErr)
			}
		}
	}
	exchange(a, b)
	exchange(b, a)

	aUfrag, aPwd, err := a.GetLocalUserCredentials()
	if err != nil {
		t.Fatal(err)
	}
	bUfrag, bPwd, err := b.GetLocalUserCredentials()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	type result struct {
		conn *ice.Conn
		err  error
	}
	accepted := make(chan result, 1)
	go func() {
		conn, acceptErr := a.Accept(ctx, bUfrag, bPwd)
		accepted <- result{conn, acceptErr}
	}()
	bConn, err := b.Dial(ctx, aUfrag, aPwd)
	if err != nil {
		t.Fatal(err)
	}
	aResult := <-accepted
	if aResult.err != nil {
		t.Fatal(aResult.err)
	}
	return bConn, aResult.conn
}

func gateCertificate(t *testing.T) (*tls.Config, [sha256.Size]byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "p2pstore ephemeral " + hex.EncodeToString(serial.Bytes())},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * time.Minute),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"p2pstore/1"}}, sha256.Sum256(der)
}

// Kept local so the gate test doesn't use assertion dependencies.
func errorsAs(err error, target any) bool { return errors.As(err, target) }
