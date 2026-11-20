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

// UserAgentContext represents the high-level hierarchical differentiation between the Human User and the AI Agent (Parent or Child).
type UserAgentContext struct {
	UserID   string            `json:"user_id"`
	UserRole string            `json:"user_role"`
	IdP      string            `json:"idp"`
	Agent    AgentIdentityCard `json:"agent"`
}

type AgentIdentityCard struct {
	ID             string             `json:"id"`
	Scope          string             `json:"scope"`
	Authorised     string             `json:"authorised"` // "yes" | "step-up" | "no (revoked)"
	Token          string             `json:"token"`
	Time           string             `json:"time"`
	TypeOfAgent    string             `json:"type_of_agent"` // "parent" | "child"
	Awake          string             `json:"awake"`         // e.g. "gemini-2.5-flash (spawned by user)" or "gemini-2.5-flash (spawned by parent agent:invoice-assistant)"
	Reason         []string           `json:"reason"`
	AuthorisedFlow string             `json:"authorised_flow"` // "oauth2.1 + pkce + rar + dpop" | "oauth2.1 + rfc8693_token_exchange + dpop"
	DPoPKeyBound   string             `json:"dpop_key_bound"`
	ChildAgent     *AgentIdentityCard `json:"child_agent,omitempty"`
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
	IdentityHierarchy    *UserAgentContext     `json:"user_agent_hierarchy,omitempty"`
}

// BuildUserAgentHierarchy constructs the clear user -> agent (parent/child) differentiation model from the token claims.
func BuildUserAgentHierarchy(claims AgentAccessTokenClaims, rawToken string, modelName string, authorisedStatus string, reasons []string) *UserAgentContext {
	shortTok := claims.JTI
	if len(rawToken) > 28 {
		shortTok = rawToken[:14] + "..." + rawToken[len(rawToken)-10:]
	}
	if modelName == "" {
		modelName = "gemini-2.5-flash"
	}
	if authorisedStatus == "" {
		authorisedStatus = "yes"
	}
	if len(reasons) == 0 {
		reasons = []string{"spiffe_workload_attested", "rar_scope_matches_task", "dpop_sender_constrained"}
	}

	folderScope := claims.Scope
	if len(claims.AuthorizationDetails) > 0 && len(claims.AuthorizationDetails[0].Locations) > 0 {
		loc := claims.AuthorizationDetails[0].Locations[0]
		acts := strings.Join(claims.AuthorizationDetails[0].Actions, ",")
		folderScope = fmt.Sprintf("%s:%s (%s)", loc, acts, claims.Scope)
	}

	ttlSec := claims.EXP - claims.IAT
	timeStr := fmt.Sprintf("ttl=%ds (exp=%d)", ttlSec, claims.EXP)

	isChild := claims.Act != nil || claims.ParentJTI != ""
	if !isChild {
		return &UserAgentContext{
			UserID:   claims.Sub,
			UserRole: "Human Principal (OIDC Authenticated)",
			IdP:      "Okta / LoginRadius Federated IdP",
			Agent: AgentIdentityCard{
				ID:             claims.ClientID,
				Scope:          folderScope,
				Authorised:     authorisedStatus,
				Token:          shortTok,
				Time:           timeStr,
				TypeOfAgent:    "parent",
				Awake:          fmt.Sprintf("%s (root parent agent awakened by %s)", modelName, claims.Sub),
				Reason:         reasons,
				AuthorisedFlow: "oauth2.1 + pkce + rfc9396_rar + rfc9449_dpop",
				DPoPKeyBound:   claims.CNF["jkt"],
			},
		}
	}

	parentID := "agent:parent"
	if claims.Act != nil && claims.Act.Sub != "" {
		parentID = claims.Act.Sub
	}

	return &UserAgentContext{
		UserID:   claims.Sub,
		UserRole: "Human Principal (OIDC Authenticated)",
		IdP:      "Okta / LoginRadius Federated IdP",
		Agent: AgentIdentityCard{
			ID:             parentID,
			Scope:          folderScope,
			Authorised:     authorisedStatus,
			Token:          claims.ParentJTI,
			Time:           "ttl=300s (parent session)",
			TypeOfAgent:    "parent",
			Awake:          fmt.Sprintf("%s (parent orchestrator)", modelName),
			Reason:         []string{"spiffe_workload_attested", "delegated_to_child_via_rfc8693"},
			AuthorisedFlow: "oauth2.1 + pkce + rfc9396_rar + rfc9449_dpop",
			DPoPKeyBound:   "parent_ephemeral_es256_key",
			ChildAgent: &AgentIdentityCard{
				ID:             claims.ClientID,
				Scope:          folderScope,
				Authorised:     authorisedStatus,
				Token:          shortTok,
				Time:           timeStr,
				TypeOfAgent:    "child",
				Awake:          fmt.Sprintf("%s (child awakened by parent %s)", modelName, parentID),
				Reason:         reasons,
				AuthorisedFlow: "oauth2.1 + rfc8693_token_exchange (nested act claim)",
				DPoPKeyBound:   claims.CNF["jkt"],
			},
		},
	}
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
