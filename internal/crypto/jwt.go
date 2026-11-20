package crypto

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// AuthorizationDetail represents an RFC 9396 Rich Authorization Request (RAR) entry.
type AuthorizationDetail struct {
	Type          string   `json:"type"`
	Locations     []string `json:"locations"`
	Actions       []string `json:"actions"`
	DataResidency string   `json:"data_residency,omitempty"`
	MaxAmountINR  int      `json:"max_amount_inr,omitempty"`
}

// ActorClaim represents an RFC 8693 nested actor delegation chain (User -> Parent Agent -> Sub-Agent).
type ActorClaim struct {
	Sub string      `json:"sub"`
	Act *ActorClaim `json:"act,omitempty"`
}

// AgentAccessTokenClaims represents the Layer 1 OAuth 2.1 + DPoP + RAR + RFC 8693 access token payload.
type AgentAccessTokenClaims struct {
	Iss                  string                `json:"iss"`
	Sub                  string                `json:"sub"`
	ClientID             string                `json:"client_id"`
	Aud                  string                `json:"aud"`
	Scope                string                `json:"scope"`
	JTI                  string                `json:"jti"`
	FamilyID             string                `json:"family_id"`
	ParentJTI            string                `json:"parent_jti,omitempty"`
	IAT                  int64                 `json:"iat"`
	EXP                  int64                 `json:"exp"`
	CNF                  map[string]string     `json:"cnf"`
	AuthorizationDetails []AuthorizationDetail `json:"authorization_details"`
	Risk                 map[string]any        `json:"risk"`
	Act                  *ActorClaim           `json:"act,omitempty"`
}

type JWTHeader struct {
	Typ string     `json:"typ"`
	Alg string     `json:"alg"`
	Kid string     `json:"kid,omitempty"`
	JWK *PublicJWK `json:"jwk,omitempty"`
}

// SignAccessToken signs an AgentAccessTokenClaims using ES256 (ECDSA P-256 + SHA-256).
func SignAccessToken(priv *ecdsa.PrivateKey, kid string, claims AgentAccessTokenClaims) (string, error) {
	header := JWTHeader{
		Typ: "at+jwt",
		Alg: "ES256",
		Kid: kid,
	}
	return signES256JWT(priv, header, claims)
}

// VerifyAccessToken verifies the ES256 signature and expiration of an AgentAccessTokenClaims.
func VerifyAccessToken(pub *ecdsa.PublicKey, tokenStr string) (*JWTHeader, *AgentAccessTokenClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("malformed JWT: expected 3 dot-separated parts")
	}

	var header JWTHeader
	headerBytes, err := base64UrlDecode(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid JWT header encoding: %w", err)
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, nil, fmt.Errorf("invalid JWT header JSON: %w", err)
	}
	if header.Alg != "ES256" {
		return nil, nil, fmt.Errorf("unexpected JWT alg: %s", header.Alg)
	}

	signingInput := parts[0] + "." + parts[1]
	if err := verifyES256Signature(pub, signingInput, parts[2]); err != nil {
		return nil, nil, fmt.Errorf("JWT signature verification failed: %w", err)
	}

	payloadBytes, err := base64UrlDecode(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid JWT payload encoding: %w", err)
	}
	var claims AgentAccessTokenClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, nil, fmt.Errorf("invalid JWT claims JSON: %w", err)
	}

	now := time.Now().Unix()
	if claims.EXP > 0 && now > claims.EXP {
		return &header, &claims, errors.New("access token has expired")
	}

	return &header, &claims, nil
}

func signES256JWT(priv *ecdsa.PrivateKey, header JWTHeader, claims any) (string, error) {
	hBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	signingInput := base64UrlEncode(hBytes) + "." + base64UrlEncode(cBytes)
	hash := sha256.Sum256([]byte(signingInput))

	r, s, err := ecdsa.Sign(rand.Reader, priv, hash[:])
	if err != nil {
		return "", err
	}

	sig := make([]byte, 64)
	r.FillBytes(sig[0:32])
	s.FillBytes(sig[32:64])

	return signingInput + "." + base64UrlEncode(sig), nil
}

func verifyES256Signature(pub *ecdsa.PublicKey, signingInput string, encodedSig string) error {
	sig, err := base64UrlDecode(encodedSig)
	if err != nil {
		return err
	}
	if len(sig) != 64 {
		return fmt.Errorf("invalid ES256 signature length: %d", len(sig))
	}
	r := new(big.Int).SetBytes(sig[0:32])
	s := new(big.Int).SetBytes(sig[32:64])
	hash := sha256.Sum256([]byte(signingInput))
	if !ecdsa.Verify(pub, hash[:], r, s) {
		return errors.New("ECDSA signature mismatch")
	}
	return nil
}
