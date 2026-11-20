package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// PublicJWK represents an RFC 7517 JSON Web Key for ES256 (P-256).
type PublicJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Kid string `json:"kid,omitempty"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`
}

// JWKS represents a JSON Web Key Set served at /.well-known/jwks.json.
type JWKS struct {
	Keys []PublicJWK `json:"keys"`
}

// KeyManager simulates an HSM/KMS with active and staged rotation keys.
type KeyManager struct {
	mu         sync.RWMutex
	activeKey  *ecdsa.PrivateKey
	activeKid  string
	stagedKey  *ecdsa.PrivateKey
	stagedKid  string
	rotatedAt  time.Time
	nextRotate time.Time
}

func NewKeyManager() (*KeyManager, error) {
	active, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	staged, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	return &KeyManager{
		activeKey:  active,
		activeKid:  "agent-id-kms-2026-11-active",
		stagedKey:  staged,
		stagedKid:  "agent-id-kms-2026-12-staged",
		rotatedAt:  now,
		nextRotate: now.Add(30 * 24 * time.Hour),
	}, nil
}

func (km *KeyManager) ActiveSigner() (*ecdsa.PrivateKey, string) {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.activeKey, km.activeKid
}

func (km *KeyManager) PublicJWKS() JWKS {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return JWKS{
		Keys: []PublicJWK{
			PublicKeyToJWK(&km.activeKey.PublicKey, km.activeKid),
			PublicKeyToJWK(&km.stagedKey.PublicKey, km.stagedKid),
		},
	}
}

// PublicKeyToJWK converts an ECDSA P-256 public key into an RFC 7517 JWK.
func PublicKeyToJWK(pub *ecdsa.PublicKey, kid string) PublicJWK {
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	xBytes := make([]byte, byteLen)
	yBytes := make([]byte, byteLen)
	pub.X.FillBytes(xBytes)
	pub.Y.FillBytes(yBytes)

	return PublicJWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64UrlEncode(xBytes),
		Y:   base64UrlEncode(yBytes),
		Kid: kid,
		Use: "sig",
		Alg: "ES256",
	}
}

// JWKToPublicKey reconstructs an ECDSA P-256 public key from a PublicJWK.
func JWKToPublicKey(jwk PublicJWK) (*ecdsa.PublicKey, error) {
	if jwk.Kty != "EC" || jwk.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported JWK kty/crv: %s/%s", jwk.Kty, jwk.Crv)
	}
	xBytes, err := base64UrlDecode(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("invalid JWK x coordinate: %w", err)
	}
	yBytes, err := base64UrlDecode(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("invalid JWK y coordinate: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

// ComputeJWKThumbprint computes the RFC 7638 SHA-256 JWK Thumbprint (cnf.jkt).
func ComputeJWKThumbprint(jwk PublicJWK) string {
	canonical := fmt.Sprintf(`{"crv":"%s","kty":"%s","x":"%s","y":"%s"}`, jwk.Crv, jwk.Kty, jwk.X, jwk.Y)
	sum := sha256.Sum256([]byte(canonical))
	return base64UrlEncode(sum[:])
}

func base64UrlEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func base64UrlDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func MustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
