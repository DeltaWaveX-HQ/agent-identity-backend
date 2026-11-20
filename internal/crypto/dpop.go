package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// DPoPClaims represents an RFC 9449 DPoP proof JWT payload.
type DPoPClaims struct {
	JTI string `json:"jti"`
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	IAT int64  `json:"iat"`
	ATH string `json:"ath,omitempty"` // base64url(SHA-256(access_token))
}

// EphemeralAgentKeypair holds an agent's in-memory-only DPoP keypair.
type EphemeralAgentKeypair struct {
	PrivateKey *ecdsa.PrivateKey
	PublicJWK  PublicJWK
	Thumbprint string // RFC 7638 cnf.jkt
}

func GenerateAgentDPoPKeypair(agentID string) (*EphemeralAgentKeypair, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	jwk := PublicKeyToJWK(&priv.PublicKey, "")
	jkt := ComputeJWKThumbprint(jwk)
	return &EphemeralAgentKeypair{
		PrivateKey: priv,
		PublicJWK:  jwk,
		Thumbprint: jkt,
	}, nil
}

// CreateDPoPProof signs an RFC 9449 DPoP proof for a specific HTTP method, target URI, and optional access token.
func (kp *EphemeralAgentKeypair) CreateDPoPProof(method, targetURI, accessToken string) (string, *DPoPClaims, error) {
	jtiBytes := make([]byte, 12)
	_, _ = rand.Read(jtiBytes)

	claims := DPoPClaims{
		JTI: "dpop_" + base64UrlEncode(jtiBytes),
		HTM: strings.ToUpper(method),
		HTU: targetURI,
		IAT: time.Now().Unix(),
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims.ATH = base64UrlEncode(sum[:])
	}

	header := JWTHeader{
		Typ: "dpop+jwt",
		Alg: "ES256",
		JWK: &kp.PublicJWK,
	}
	jwtStr, err := signES256JWT(kp.PrivateKey, header, claims)
	if err != nil {
		return "", nil, err
	}
	return jwtStr, &claims, nil
}

// VerifyDPoPProof verifies an RFC 9449 DPoP proof header and checks sender-constrained binding against expectedJKT.
func VerifyDPoPProof(dpopJWT, expectedMethod, expectedURI, accessToken, expectedJKT string) (*PublicJWK, *DPoPClaims, error) {
	if dpopJWT == "" {
		return nil, nil, errors.New("missing DPoP proof header (RFC 9449 sender-constraint required)")
	}
	parts := strings.Split(dpopJWT, ".")
	if len(parts) != 3 {
		return nil, nil, errors.New("malformed DPoP JWT")
	}

	var header JWTHeader
	hBytes, err := base64UrlDecode(parts[0])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid DPoP header base64: %w", err)
	}
	if err := json.Unmarshal(hBytes, &header); err != nil {
		return nil, nil, fmt.Errorf("invalid DPoP header JSON: %w", err)
	}
	if header.Typ != "dpop+jwt" || header.Alg != "ES256" || header.JWK == nil {
		return nil, nil, errors.New("DPoP header must have typ=dpop+jwt, alg=ES256, and embedded public jwk")
	}

	pubKey, err := JWKToPublicKey(*header.JWK)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid embedded DPoP JWK: %w", err)
	}

	signingInput := parts[0] + "." + parts[1]
	if err := verifyES256Signature(pubKey, signingInput, parts[2]); err != nil {
		return nil, nil, fmt.Errorf("DPoP cryptographic signature invalid: %w", err)
	}

	var claims DPoPClaims
	pBytes, err := base64UrlDecode(parts[1])
	if err != nil {
		return nil, nil, fmt.Errorf("invalid DPoP payload base64: %w", err)
	}
	if err := json.Unmarshal(pBytes, &claims); err != nil {
		return nil, nil, fmt.Errorf("invalid DPoP payload JSON: %w", err)
	}

	if expectedMethod != "" && !strings.EqualFold(claims.HTM, expectedMethod) {
		return header.JWK, &claims, fmt.Errorf("DPoP htm mismatch: got %s, expected %s", claims.HTM, expectedMethod)
	}
	if expectedURI != "" && claims.HTU != expectedURI {
		return header.JWK, &claims, fmt.Errorf("DPoP htu mismatch: got %s, expected %s", claims.HTU, expectedURI)
	}

	actualJKT := ComputeJWKThumbprint(*header.JWK)
	if expectedJKT != "" && actualJKT != expectedJKT {
		return header.JWK, &claims, fmt.Errorf("RFC 9449 DPoP thumbprint mismatch: proof key jkt (%s) != token cnf.jkt (%s)", actualJKT, expectedJKT)
	}

	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		expectedATH := base64UrlEncode(sum[:])
		if claims.ATH != expectedATH {
			return header.JWK, &claims, errors.New("DPoP ath (access token hash) mismatch")
		}
	}

	return header.JWK, &claims, nil
}
