package owner

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	AdminChallengePath   = "/api/v1/admin/challenge"
	AdminAuthScheme      = "AckTier-Controller"
	controllerBindDomain = "AckTier controller bind v1\x00"
	controllerReqDomain  = "AckTier controller admin request v1\x00"
)

// AdminChallenge is returned by GET /api/v1/admin/challenge for one-time signed controller requests.
type AdminChallenge struct {
	Challenge string `json:"challenge"`
	NetworkID string `json:"networkId"`
}

// ControllerTrust binds a dedicated Ed25519 management public key (distinct from
// the owner's policy-signing key) to a specific networkId, carrying a self-signed
// proof that the holder possesses the corresponding private key.
type ControllerTrust struct {
	NetworkID string `json:"networkId"`
	PublicKey string `json:"publicKey"` // Lowercase hex Ed25519 public key
	Proof     string `json:"proof"`     // Base64URL Ed25519 signature over controllerBindDomain + networkId
	Label     string `json:"label,omitempty"`
}

// NewControllerTrust constructs a self-proven controller delegation bundle.
func NewControllerTrust(ownerTrust Trust, key ed25519.PrivateKey, label string) (ControllerTrust, error) {
	if err := ownerTrust.Validate(); err != nil {
		return ControllerTrust{}, err
	}
	if len(key) != ed25519.PrivateKeySize {
		return ControllerTrust{}, errors.New("invalid controller private key")
	}
	pubHex := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	if pubHex == ownerTrust.PublicKey {
		return ControllerTrust{}, errors.New("controller API key must be distinct from the owner policy-signing key")
	}
	netID := ownerTrust.NetworkID()
	sig := ed25519.Sign(key, controllerBindInput(netID))
	return ControllerTrust{
		NetworkID: netID,
		PublicKey: pubHex,
		Proof:     base64.RawURLEncoding.EncodeToString(sig),
		Label:     strings.TrimSpace(label),
	}, nil
}

// Verify checks that ct belongs to ownerTrust's network, uses a separate key from
// the owner root, and carries a valid private-key possession signature.
func (ct ControllerTrust) Verify(ownerTrust Trust) (ed25519.PublicKey, error) {
	if err := ownerTrust.Validate(); err != nil {
		return nil, err
	}
	if ct.NetworkID != ownerTrust.NetworkID() {
		return nil, errors.New("controller credential belongs to a different network")
	}
	if ct.PublicKey == ownerTrust.PublicKey {
		return nil, errors.New("controller API key must not reuse the owner policy-signing key")
	}
	pubRaw, err := hex.DecodeString(ct.PublicKey)
	if err != nil || len(pubRaw) != ed25519.PublicKeySize || ct.PublicKey != hex.EncodeToString(pubRaw) ||
		bytes.Equal(pubRaw, make([]byte, ed25519.PublicKeySize)) {
		return nil, errors.New("invalid controller Ed25519 public key")
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(ct.Proof)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("invalid controller possession proof encoding")
	}
	pub := ed25519.PublicKey(pubRaw)
	if !ed25519.Verify(pub, controllerBindInput(ct.NetworkID), sig) {
		return nil, errors.New("controller possession proof signature check failed")
	}
	return pub, nil
}

func controllerBindInput(networkID string) []byte {
	var b bytes.Buffer
	b.WriteString(controllerBindDomain)
	b.WriteString(networkID)
	return b.Bytes()
}

// AdminProof represents a parsed Authorization header for a signed controller request.
type AdminProof struct {
	Challenge string
	BodyHash  [sha256.Size]byte
	Signature []byte
}

func controllerRequestInput(networkID, challenge, method, requestURI string, bodyHash [sha256.Size]byte) []byte {
	var b bytes.Buffer
	b.WriteString(controllerReqDomain)
	b.WriteString(networkID)
	b.WriteByte('\n')
	b.WriteString(challenge)
	b.WriteByte('\n')
	b.WriteString(strings.ToUpper(method))
	b.WriteByte('\n')
	b.WriteString(requestURI)
	b.WriteByte('\n')
	b.Write(bodyHash[:])
	return b.Bytes()
}

// FormatAdminProof signs an HTTP request and returns the Authorization header value.
func FormatAdminProof(key ed25519.PrivateKey, networkID, challenge, method, requestURI string, body []byte) (string, error) {
	if len(key) != ed25519.PrivateKeySize || networkID == "" || challenge == "" {
		return "", errors.New("missing controller signing key, networkId, or challenge")
	}
	sum := sha256.Sum256(body)
	sig := ed25519.Sign(key, controllerRequestInput(networkID, challenge, method, requestURI, sum))
	return fmt.Sprintf("%s challenge=%s,sha256=%s,sig=%s",
		AdminAuthScheme,
		challenge,
		hex.EncodeToString(sum[:]),
		base64.RawURLEncoding.EncodeToString(sig),
	), nil
}

// ParseAdminProof parses an `AckTier-Controller challenge=...,sha256=...,sig=...` header.
func ParseAdminProof(header string) (AdminProof, bool) {
	var p AdminProof
	prefix := AdminAuthScheme + " "
	if !strings.HasPrefix(header, prefix) {
		return p, false
	}
	var gotChallenge, gotHash, gotSig bool
	for _, part := range strings.Split(strings.TrimSpace(header[len(prefix):]), ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 || kv[1] == "" {
			return AdminProof{}, false
		}
		switch kv[0] {
		case "challenge":
			if gotChallenge {
				return AdminProof{}, false
			}
			p.Challenge, gotChallenge = kv[1], true
		case "sha256":
			if gotHash {
				return AdminProof{}, false
			}
			raw, err := hex.DecodeString(kv[1])
			if err != nil || len(raw) != sha256.Size {
				return AdminProof{}, false
			}
			copy(p.BodyHash[:], raw)
			gotHash = true
		case "sig":
			if gotSig {
				return AdminProof{}, false
			}
			sig, err := base64.RawURLEncoding.Strict().DecodeString(kv[1])
			if err != nil || len(sig) != ed25519.SignatureSize {
				return AdminProof{}, false
			}
			p.Signature, gotSig = sig, true
		default:
			return AdminProof{}, false
		}
	}
	if !gotChallenge || !gotHash || !gotSig {
		return AdminProof{}, false
	}
	return p, true
}

// Verify checks the Ed25519 request signature against the pinned controller public key.
func (p AdminProof) Verify(pubKeyHex, networkID, method, requestURI string) bool {
	pubRaw, err := hex.DecodeString(pubKeyHex)
	if err != nil || len(pubRaw) != ed25519.PublicKeySize || len(p.Signature) != ed25519.SignatureSize {
		return false
	}
	msg := controllerRequestInput(networkID, p.Challenge, method, requestURI, p.BodyHash)
	return ed25519.Verify(ed25519.PublicKey(pubRaw), msg, p.Signature)
}
