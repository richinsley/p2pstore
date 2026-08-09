package p2pstore

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// ALPN is the TLS application protocol negotiated by p2pstore v1 QUIC peers.
const ALPN = "p2pstore/1"

// SessionCertificate holds one ephemeral provider certificate and the pin sent
// to a client over authenticated signaling.
type SessionCertificate struct {
	// Certificate contains the ECDSA leaf and private key used by the QUIC server.
	Certificate tls.Certificate
	// Fingerprint is the lowercase hexadecimal SHA-256 digest of the leaf DER.
	Fingerprint string
}

// NewSessionCertificate creates a short-lived ECDSA certificate. Callers send
// only Fingerprint through their authenticated signaling channel.
func NewSessionCertificate(validFor time.Duration) (SessionCertificate, error) {
	if validFor <= 0 {
		validFor = 10 * time.Minute
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return SessionCertificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return SessionCertificate{}, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "p2pstore ephemeral"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(validFor),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return SessionCertificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return SessionCertificate{}, err
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		return SessionCertificate{}, err
	}
	fingerprint := sha256.Sum256(der)
	return SessionCertificate{Certificate: certificate, Fingerprint: hex.EncodeToString(fingerprint[:])}, nil
}

// ServerTLSConfig returns a TLS 1.3 server configuration restricted to ALPN.
func (c SessionCertificate) ServerTLSConfig() (*tls.Config, error) {
	if len(c.Certificate.Certificate) == 0 || c.Fingerprint == "" {
		return nil, errorf(CodeInvalidArgument, "session certificate is empty")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{c.Certificate},
		NextProtos:   []string{ALPN},
	}, nil
}

// PinnedClientTLSConfig accepts a self-signed peer certificate only when its
// leaf SHA-256 fingerprint exactly matches the authenticated signaling value.
func PinnedClientTLSConfig(fingerprint string) (*tls.Config, error) {
	normalized := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(fingerprint)), ":", "")
	pin, err := hex.DecodeString(normalized)
	if err != nil || len(pin) != sha256.Size {
		return nil, errorf(CodeInvalidArgument, "TLS fingerprint must be a 32-byte SHA-256 digest")
	}
	return &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // Mandatory pinning below replaces PKI verification.
		NextProtos:         []string{ALPN},
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 {
				return fmt.Errorf("p2pstore: expected one ephemeral peer certificate, got %d", len(state.PeerCertificates))
			}
			got := sha256.Sum256(state.PeerCertificates[0].Raw)
			if !bytes.Equal(got[:], pin) {
				return &Error{Code: CodeUnauthenticated, Message: "TLS certificate fingerprint mismatch"}
			}
			return nil
		},
	}, nil
}
