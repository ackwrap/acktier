package transport

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

const (
	alpnQUIC = "acktier-quic-v1"
	alpnWSS  = "http/1.1"
)

// GenerateEphemeralTLSConfig creates an in-memory Ed25519 TLS 1.3 configuration
// for QUIC and WSS transports. Peer identity & payload authenticity are enforced
// end-to-end by AckTier's X25519 + AES-256-GCM Noise layer.
func GenerateEphemeralTLSConfig(nextProtos ...string) (*tls.Config, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "acktier.overlay.local"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, pub, priv)
	if err != nil {
		return nil, err
	}
	cert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	return &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // Inner Noise_IK layer authenticates Peer NodeKey
		MinVersion:         tls.VersionTLS13,
		NextProtos:         nextProtos,
	}, nil
}
