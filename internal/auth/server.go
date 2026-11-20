package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/buildathon2026/agent-identity-backend/internal/crypto"
)

// RegisteredAgent represents an AI agent or sub-agent registered via POST /api/v1/agents/register.
type RegisteredAgent struct {
	AgentID           string            `json:"agent_id"`
	Name              string            `json:"name,omitempty"`
	OwnerUser         string            `json:"owner_user"`
	ParentAgentID     string            `json:"parent_agent_id,omitempty"`
	SPIFFEID          string            `json:"spiffe_id"`
	RuntimeAttested   bool              `json:"runtime_attested"`
	PlatformFramework string            `json:"platform_framework"`
	ModelID           string            `json:"model_id"`
	AllowedScopes     []string          `json:"allowed_scopes,omitempty"`
	DPoPPublicJWK     *crypto.PublicJWK `json:"dpop_public_jwk,omitempty"`
	DPoPThumbprint    string            `json:"dpop_thumbprint"`
	RegisteredAt      int64             `json:"registered_at"`
	Status            string            `json:"status"` // "ACTIVE" | "REVOKED"
}

// ConsentRecord represents a user-approved RFC 9396 RAR consent record.
type ConsentRecord struct {
	ConsentID            string                       `json:"consent_id"`
	Version              int                          `json:"version"`
	UserSub              string                       `json:"user_sub"`
	AgentID              string                       `json:"agent_id"`
	Task                 string                       `json:"task"`
	Scope                string                       `json:"scope"`
	Aud                  string                       `json:"aud"`
	RedirectURI          string                       `json:"redirect_uri,omitempty"`
	State                string                       `json:"state,omitempty"`
	PKCEChallenge        string                       `json:"pkce_challenge"`
	PKCEMethod           string                       `json:"pkce_method"`
	AuthorizationDetails []crypto.AuthorizationDetail `json:"authorization_details"`
	Approved             bool                         `json:"approved"`
	Revoked              bool                         `json:"revoked"`
	AuthCode             string                       `json:"auth_code,omitempty"`
	AuthCodeUsed         bool                         `json:"auth_code_used"`
	FamilyID             string                       `json:"family_id,omitempty"`
	CreatedAt            int64                        `json:"created_at"`
	ExpiresAt            int64                        `json:"expires_at"`
}

// CIBARequest represents an OpenID CIBA (POST /bc-authorize) asynchronous human step-up request.
type CIBARequest struct {
	AuthReqID  string      `json:"auth_req_id"`
	AgentID    string      `json:"agent_id"`
	UserSub    string      `json:"user_sub"`
	Action     string      `json:"action"`
	Resource   string      `json:"resource"`
	RiskScore  float64     `json:"risk_score"`
	Reasons    []string    `json:"reasons"`
	Status     string      `json:"status"` // "PENDING" | "APPROVED" | "DENIED" | "EXPIRED"
	CreatedAt  int64       `json:"created_at"`
	ExpiresAt  int64       `json:"expires_at"`
	ResolvedCh chan string `json:"-"`
}

type Server struct {
	mu           sync.RWMutex
	km           *crypto.KeyManager
	dag          *FamilyDAG
	agents       map[string]*RegisteredAgent
	consents     map[string]*ConsentRecord
	codes        map[string]*ConsentRecord // auth_code -> ConsentRecord
	cibaRequests map[string]*CIBARequest
}

func NewServer(km *crypto.KeyManager, dag *FamilyDAG) *Server {
	s := &Server{
		km:           km,
		dag:          dag,
		agents:       make(map[string]*RegisteredAgent),
		consents:     make(map[string]*ConsentRecord),
		codes:        make(map[string]*ConsentRecord),
		cibaRequests: make(map[string]*CIBARequest),
	}
	s.seedDefaultAgents()
	return s
}

func (s *Server) seedDefaultAgents() {
	kp1, _ := crypto.GenerateAgentDPoPKeypair("agent:invoice-assistant")
	kp2, _ := crypto.GenerateAgentDPoPKeypair("agent:invoice-assistant/summariser")
	kp3, _ := crypto.GenerateAgentDPoPKeypair("agent:treasury-payment-bot")

	now := time.Now().Unix()
	s.agents["agent:invoice-assistant"] = &RegisteredAgent{
		AgentID:           "agent:invoice-assistant",
		Name:              "Finance Q3 Invoice Assistant",
		OwnerUser:         "user:priya@acme.in",
		SPIFFEID:          "spiffe://acme.in/ns/finance/sa/invoice-assistant",
		RuntimeAttested:   true,
		PlatformFramework: "Google ADK / Gemini 2.5 Flash + MCP",
		ModelID:           "gemini-2.5-flash",
		AllowedScopes:     []string{"invoices.read", "invoices.summarize"},
		DPoPPublicJWK:     &kp1.PublicJWK,
		DPoPThumbprint:    kp1.Thumbprint,
		RegisteredAt:      now - 3600,
		Status:            "ACTIVE",
	}
	s.agents["agent:invoice-assistant/summariser"] = &RegisteredAgent{
		AgentID:           "agent:invoice-assistant/summariser",
		Name:              "Invoice PDF Summariser Sub-Agent",
		OwnerUser:         "user:priya@acme.in",
		ParentAgentID:     "agent:invoice-assistant",
		SPIFFEID:          "spiffe://acme.in/ns/finance/sa/invoice-summariser",
		RuntimeAttested:   true,
		PlatformFramework: "Google ADK Sub-Agent Worker",
		ModelID:           "gemini-2.5-flash",
		AllowedScopes:     []string{"invoices.read"},
		DPoPPublicJWK:     &kp2.PublicJWK,
		DPoPThumbprint:    kp2.Thumbprint,
		RegisteredAt:      now - 1800,
		Status:            "ACTIVE",
	}
	s.agents["agent:treasury-payment-bot"] = &RegisteredAgent{
		AgentID:           "agent:treasury-payment-bot",
		Name:              "Treasury NEFT Settlement Agent",
		OwnerUser:         "user:priya@acme.in",
		SPIFFEID:          "spiffe://acme.in/ns/treasury/sa/payment-bot",
		RuntimeAttested:   true,
		PlatformFramework: "LangGraph + MCP Client",
		ModelID:           "gemini-2.5-pro",
		AllowedScopes:     []string{"invoices.read", "payments.transfer"},
		DPoPPublicJWK:     &kp3.PublicJWK,
		DPoPThumbprint:    kp3.Thumbprint,
		RegisteredAt:      now - 7200,
		Status:            "ACTIVE",
	}
}

func (s *Server) Reset() {
	s.mu.Lock()
	s.consents = make(map[string]*ConsentRecord)
	s.codes = make(map[string]*ConsentRecord)
	s.cibaRequests = make(map[string]*CIBARequest)
	s.mu.Unlock()
	s.dag.Reset()
	s.seedDefaultAgents()
}

func (s *Server) RegisterAgent(req RegisteredAgent) (*RegisteredAgent, error) {
	if req.SPIFFEID == "" || !req.RuntimeAttested {
		return nil, errors.New("workload attestation failed: valid SPIFFE workload certificate required")
	}
	if req.AgentID == "" {
		req.AgentID = "agent:" + strings.ToLower(strings.ReplaceAll(req.Name, " ", "-"))
	}
	if req.DPoPThumbprint == "" {
		if req.DPoPPublicJWK != nil {
			req.DPoPThumbprint = crypto.ComputeJWKThumbprint(*req.DPoPPublicJWK)
		} else {
			kp, _ := crypto.GenerateAgentDPoPKeypair(req.AgentID)
			req.DPoPPublicJWK = &kp.PublicJWK
			req.DPoPThumbprint = kp.Thumbprint
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	req.RegisteredAt = time.Now().Unix()
	req.Status = "ACTIVE"
	s.agents[req.AgentID] = &req
	return &req, nil
}

func (s *Server) GetAgent(agentID string) (*RegisteredAgent, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[agentID]
	return a, ok
}

func (s *Server) RevokeAgent(agentID, reason string) (*RegisteredAgent, []*FamilyGraphSnapshot, error) {
	s.mu.Lock()
	a, ok := s.agents[agentID]
	if !ok {
		s.mu.Unlock()
		return nil, nil, fmt.Errorf("agent %s not found", agentID)
	}
	a.Status = "REVOKED"
	// Also revoke any sub-agents whose parent is agentID
	for _, child := range s.agents {
		if child.ParentAgentID == agentID {
			child.Status = "REVOKED"
		}
	}
	s.mu.Unlock()

	snaps := s.dag.RevokeAll("Agent Revoked by Admin/User: " + agentID + " (" + reason + ")")
	return a, snaps, nil
}

func (s *Server) ListAgents() []*RegisteredAgent {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*RegisteredAgent, 0, len(s.agents))
	for _, a := range s.agents {
		out = append(out, a)
	}
	return out
}

func (s *Server) CreateConsentPrompt(userSub, agentID, task, scope, aud, pkceChallenge string, details []crypto.AuthorizationDetail) *ConsentRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := "rar_consent_" + randomID(6)
	rec := &ConsentRecord{
		ConsentID:            id,
		Version:              1,
		UserSub:              userSub,
		AgentID:              agentID,
		Task:                 task,
		Scope:                scope,
		Aud:                  aud,
		PKCEChallenge:        pkceChallenge,
		PKCEMethod:           "S256",
		AuthorizationDetails: details,
		Approved:             false,
		CreatedAt:            time.Now().Unix(),
		ExpiresAt:            time.Now().Add(1 * time.Hour).Unix(),
	}
	s.consents[id] = rec
	return rec
}

func (s *Server) GetConsent(consentID string) (*ConsentRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.consents[consentID]
	return c, ok
}

func (s *Server) ListConsents() []*ConsentRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*ConsentRecord, 0, len(s.consents))
	for _, c := range s.consents {
		out = append(out, c)
	}
	return out
}

func (s *Server) RevokeConsent(consentID string) (*ConsentRecord, *FamilyGraphSnapshot, error) {
	s.mu.Lock()
	c, ok := s.consents[consentID]
	if !ok {
		s.mu.Unlock()
		return nil, nil, fmt.Errorf("consent %s not found", consentID)
	}
	c.Revoked = true
	famID := c.FamilyID
	s.mu.Unlock()

	var snap *FamilyGraphSnapshot
	if famID != "" {
		snap = s.dag.RevokeFamily(famID, "User Withdrew RFC 9396 RAR Consent ("+consentID+")")
	}
	return c, snap, nil
}

func (s *Server) ApproveConsent(consentID string, narrowedActions []string) (*ConsentRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.consents[consentID]
	if !ok {
		return nil, fmt.Errorf("consent record %s not found", consentID)
	}
	if len(narrowedActions) > 0 && len(rec.AuthorizationDetails) > 0 {
		rec.AuthorizationDetails[0].Actions = narrowedActions
	}
	rec.Approved = true
	rec.AuthCode = "code_pkce_" + randomID(8)
	s.codes[rec.AuthCode] = rec
	return rec, nil
}

// ExchangeAuthCodeForTokens executes OAuth 2.1 Authorization Code + PKCE + DPoP binding.
func (s *Server) ExchangeAuthCodeForTokens(code, pkceVerifier, dpopJKT string, issuanceRisk float64) (accessJWT string, claims *crypto.AgentAccessTokenClaims, refreshJTI string, err error) {
	s.mu.Lock()
	rec, ok := s.codes[code]
	if !ok {
		s.mu.Unlock()
		return "", nil, "", errors.New("invalid authorization code")
	}
	if rec.AuthCodeUsed {
		fam := rec.FamilyID
		s.mu.Unlock()
		if fam != "" {
			s.dag.RevokeFamily(fam, "OAuth 2.1 Violation: Single-use Authorization Code Replayed")
		}
		return "", nil, "", errors.New("OAuth 2.1 violation: single-use authorization code replayed (token family revoked)")
	}
	if rec.PKCEChallenge != "" && pkceVerifier != "" {
		sum := sha256.Sum256([]byte(pkceVerifier))
		expectedChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
		if expectedChallenge != rec.PKCEChallenge {
			s.mu.Unlock()
			return "", nil, "", errors.New("PKCE S256 code_verifier mismatch")
		}
	}
	rec.AuthCodeUsed = true
	familyID := "fam_" + randomID(6)
	rec.FamilyID = familyID
	s.mu.Unlock()

	now := time.Now().Unix()
	jti := "tok_parent_" + randomID(6)

	tokenClaims := crypto.AgentAccessTokenClaims{
		Iss:                  "https://auth.agentidentity.local",
		Sub:                  rec.UserSub,
		ClientID:             rec.AgentID,
		Aud:                  rec.Aud,
		Scope:                rec.Scope,
		JTI:                  jti,
		FamilyID:             familyID,
		IAT:                  now,
		EXP:                  now + 300, // 5 min short-lived access token
		CNF:                  map[string]string{"jkt": dpopJKT},
		AuthorizationDetails: rec.AuthorizationDetails,
		Risk: map[string]any{
			"issuance_score": issuanceRisk,
			"model":          "issuance-xgb-v3",
		},
	}

	priv, kid := s.km.ActiveSigner()
	jwtStr, err := crypto.SignAccessToken(priv, kid, tokenClaims)
	if err != nil {
		return "", nil, "", err
	}

	s.dag.RegisterToken(&TokenNode{
		JTI:       jti,
		FamilyID:  familyID,
		TokenType: "parent_access",
		ClientID:  rec.AgentID,
		UserSub:   rec.UserSub,
		Scope:     rec.Scope,
		DPoPJKT:   dpopJKT,
		Status:    TokenActive,
		IssuedAt:  now,
		ExpiresAt: now + 300,
		Claims:    &tokenClaims,
		RawJWT:    jwtStr,
	})

	refJTI := "rt_rot_" + randomID(6)
	s.dag.RegisterToken(&TokenNode{
		JTI:       refJTI,
		FamilyID:  familyID,
		ParentJTI: jti,
		TokenType: "refresh_token",
		ClientID:  rec.AgentID,
		UserSub:   rec.UserSub,
		Scope:     rec.Scope,
		DPoPJKT:   dpopJKT,
		Status:    TokenActive,
		IssuedAt:  now,
		ExpiresAt: now + 28800,
	})

	return jwtStr, &tokenClaims, refJTI, nil
}

// ExchangeSubAgentToken implements RFC 8693 OAuth 2.0 Token Exchange with scope attenuation & nested act claim.
func (s *Server) ExchangeSubAgentToken(parentClaims *crypto.AgentAccessTokenClaims, subAgentID, subDPoPJKT, narrowedScope string) (string, *crypto.AgentAccessTokenClaims, error) {
	if revoked, reason := s.dag.IsRevoked(parentClaims.JTI); revoked {
		return "", nil, fmt.Errorf("cannot exchange revoked parent token: %s", reason)
	}

	now := time.Now().Unix()
	subJTI := "tok_sub_" + randomID(6)
	scope := narrowedScope
	if scope == "" {
		scope = parentClaims.Scope
	}

	subClaims := crypto.AgentAccessTokenClaims{
		Iss:                  "https://auth.agentidentity.local",
		Sub:                  parentClaims.Sub,
		ClientID:             subAgentID,
		Aud:                  parentClaims.Aud,
		Scope:                scope,
		JTI:                  subJTI,
		FamilyID:             parentClaims.FamilyID,
		ParentJTI:            parentClaims.JTI,
		IAT:                  now,
		EXP:                  now + 180,
		CNF:                  map[string]string{"jkt": subDPoPJKT},
		AuthorizationDetails: parentClaims.AuthorizationDetails,
		Risk:                 parentClaims.Risk,
		Act: &crypto.ActorClaim{
			Sub: parentClaims.ClientID,
			Act: &crypto.ActorClaim{
				Sub: parentClaims.Sub,
			},
		},
	}

	priv, kid := s.km.ActiveSigner()
	jwtStr, err := crypto.SignAccessToken(priv, kid, subClaims)
	if err != nil {
		return "", nil, err
	}

	s.dag.RegisterToken(&TokenNode{
		JTI:       subJTI,
		FamilyID:  parentClaims.FamilyID,
		ParentJTI: parentClaims.JTI,
		TokenType: "sub_agent_access",
		ClientID:  subAgentID,
		UserSub:   parentClaims.Sub,
		Scope:     scope,
		DPoPJKT:   subDPoPJKT,
		Status:    TokenActive,
		IssuedAt:  now,
		ExpiresAt: now + 180,
		Claims:    &subClaims,
		RawJWT:    jwtStr,
	})

	return jwtStr, &subClaims, nil
}

// IntrospectToken implements RFC 7662 OAuth 2.0 Token Introspection.
func (s *Server) IntrospectToken(tokenStr string) map[string]any {
	priv, _ := s.km.ActiveSigner()
	_, claims, err := crypto.VerifyAccessToken(&priv.PublicKey, tokenStr)
	if err != nil {
		return map[string]any{
			"active": false,
			"error":  err.Error(),
		}
	}
	revoked, cause := s.dag.IsRevoked(claims.JTI)
	if revoked {
		return map[string]any{
			"active":        false,
			"revoked":       true,
			"revoke_reason": cause,
			"jti":           claims.JTI,
			"family_id":     claims.FamilyID,
			"client_id":     claims.ClientID,
			"sub":           claims.Sub,
		}
	}
	return map[string]any{
		"active":                true,
		"iss":                   claims.Iss,
		"sub":                   claims.Sub,
		"client_id":             claims.ClientID,
		"aud":                   claims.Aud,
		"scope":                 claims.Scope,
		"jti":                   claims.JTI,
		"family_id":             claims.FamilyID,
		"parent_jti":            claims.ParentJTI,
		"iat":                   claims.IAT,
		"exp":                   claims.EXP,
		"cnf":                   claims.CNF,
		"authorization_details": claims.AuthorizationDetails,
		"act":                   claims.Act,
		"risk":                  claims.Risk,
	}
}

// CreateCIBARequest initiates an OpenID CIBA step-up approval push notification.
func (s *Server) CreateCIBARequest(agentID, userSub, action, resource string, score float64, reasons []string) *CIBARequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := "ciba_req_" + randomID(6)
	now := time.Now().Unix()
	req := &CIBARequest{
		AuthReqID:  id,
		AgentID:    agentID,
		UserSub:    userSub,
		Action:     action,
		Resource:   resource,
		RiskScore:  score,
		Reasons:    reasons,
		Status:     "PENDING",
		CreatedAt:  now,
		ExpiresAt:  now + 120,
		ResolvedCh: make(chan string, 1),
	}
	s.cibaRequests[id] = req
	return req
}

func (s *Server) ListCIBARequests() []*CIBARequest {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*CIBARequest, 0, len(s.cibaRequests))
	for _, r := range s.cibaRequests {
		out = append(out, r)
	}
	return out
}

func (s *Server) ResolveCIBARequest(authReqID string, approved bool) (*CIBARequest, error) {
	s.mu.Lock()
	req, ok := s.cibaRequests[authReqID]
	if !ok {
		s.mu.Unlock()
		return nil, fmt.Errorf("CIBA request %s not found", authReqID)
	}
	if approved {
		req.Status = "APPROVED"
	} else {
		req.Status = "DENIED"
	}
	s.mu.Unlock()

	select {
	case req.ResolvedCh <- req.Status:
	default:
	}
	return req, nil
}

func randomID(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
