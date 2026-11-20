package persist

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"strings"
)

// Sealer encrypts secrets (signing keys) before they are written to the database, using
// AES-256-GCM with a key derived from APP_SECRET (kept in Secret Manager, never in the DB).
type Sealer struct{ aead cipher.AEAD }

func NewSealer(secret string) (*Sealer, error) {
	if secret == "" {
		return &Sealer{}, nil // no secret: values are stored as-is (local development only)
	}
	k := sha256.Sum256([]byte("agent-identity/seal/v1:" + secret))
	block, err := aes.NewCipher(k[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Sealer{aead: aead}, nil
}

func (s *Sealer) Seal(plain []byte) string {
	if s == nil || s.aead == nil {
		return "plain:" + base64.RawStdEncoding.EncodeToString(plain)
	}
	nonce := make([]byte, s.aead.NonceSize())
	_, _ = rand.Read(nonce)
	return "gcm:" + base64.RawStdEncoding.EncodeToString(s.aead.Seal(nonce, nonce, plain, nil))
}

func (s *Sealer) Open(sealed string) ([]byte, error) {
	switch {
	case strings.HasPrefix(sealed, "plain:"):
		return base64.RawStdEncoding.DecodeString(strings.TrimPrefix(sealed, "plain:"))
	case strings.HasPrefix(sealed, "gcm:"):
		if s == nil || s.aead == nil {
			return nil, errors.New("sealed value needs APP_SECRET to decrypt")
		}
		raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(sealed, "gcm:"))
		if err != nil {
			return nil, err
		}
		n := s.aead.NonceSize()
		if len(raw) < n {
			return nil, errors.New("sealed value too short")
		}
		return s.aead.Open(nil, raw[:n], raw[n:], nil)
	}
	return nil, errors.New("unknown sealed value format")
}
