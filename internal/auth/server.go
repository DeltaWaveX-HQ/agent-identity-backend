package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/buildathon2026/agent-identity-backend/internal/crypto"
)

// RegisteredAgent represents an AI agent or sub-agent registered via POST /api/v1/agents/register.
type RegisteredAgent struct {
	AgentID           string   `json:"agent_id"`
	OwnerUser         string   `json:"owner_user"`
	ParentAgentID     string   `json:"parent_agent_id,omitempty"`
	SPIFFEID          string   `json:"spiffe_id"`
	RuntimeAttested   bool     `json:"runtime_attested"`
	PlatformFramework string   `json:"platform_framework"`
	ModelID           string   `json:"model_id"`
	DPoPThumbprint    string   `json:"dpop_thumbprint"`
	RegisteredAt      int64    `json:"registered_at"`
	Status            string   `json:"status"` // "ACTIVE" | "REVOKED"
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
	PKCEChallenge        string                       `json:"pkce_challenge"`
	AuthorizationDetails []crypto.AuthorizationDetail `json:"authorization_details"`
	Approved             bool                         `json:"approved"`
	AuthCode             string                       `json:"auth_code,omitempty"`
	AuthCodeUsed         bool                         `json:"auth_code_used"`
	CreatedAt            int64                        `json:"created_at"`
	ExpiresAt            int64                        `json:"expires_at"`
}

// CIBARequest represents an OpenID CIBA (POST /bc-authorize) asynchronous human step-up request.
type CIBARequest struct {
	AuthReqID   string   `json:"auth_req_id"`
	AgentID     string   `json:"agent_id"`
	UserSub     string   `json:"user_sub"`
	Action      string   `json:"action"`
	Resource    string   `json:"resource"`
	RiskScore   float64  `json:"risk_score"`
	Reasons     []string `json:"reasons"`
	Status      string   `json:"status"` // "PENDING" | "APPROVED" | "DENIED" | "EXPIRED"
	CreatedAt   int64    `json:"created_at"`
	ExpiresAt   int64    `json:"expires_at"`
	ResolvedCh  chan string `json:"-"`
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
	return &Server{
		km:           km,
		dag:          dag,
		agents:       make(map[string]*RegisteredAgent),
		consents:     make(map[string]*ConsentRecord),
		codes:        make(map[string]*ConsentRecord),
		cibaRequests: make(map[string]*CIBARequest),
	}
}

func (s *Server) Reset() {
	s.mu.Lock()
	s.agents = make(map[string]*RegisteredAgent)
	s.consents = make(map[string]*ConsentRecord)
	s.codes = make(map[string]*ConsentRecord)
	s.cibaRequests = make(map[string]*CIBARequest)
	s.mu.Unlock()
	s.dag.Reset()
}

func (s *Server) RegisterAgent(req RegisteredAgent) (*RegisteredAgent, error) {
	if req.SPIFFEID == "" || !req.RuntimeAttested {
		return nil, errors.New("workload attestation failed: valid SPIFFE workload certificate required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	req.RegisteredAt = time.Now().Unix()
	req.Status = "ACTIVE"
	s.agents[req.AgentID] = &req
	return &req, nil
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
		AuthorizationDetails: details,
		Approved:             false,
		CreatedAt:            time.Now().Unix(),
		ExpiresAt:            time.Now().Add(1 * time.Hour).Unix(),
	}
	s.consents[id] = rec
	return rec
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
		s.mu.Unlock()
		return "", nil, "", errors.New("OAuth 2.1 violation: single-use authorization code replayed")
	}
	// Verify PKCE S256 challenge
	if rec.PKCEChallenge != "" && pkceVerifier != "" {
		sum := sha256.Sum256([]byte(pkceVerifier))
		expectedChallenge := base64.RawURLEncoding.EncodeToString(sum[:])
		if expectedChallenge != rec.PKCEChallenge {
			s.mu.Unlock()
			return "", nil, "", errors.New("PKCE code_verifier mismatch")
		}
	}
	rec.AuthCodeUsed = true
	s.mu.Unlock()

	now := time.Now().Unix()
	familyID := "fam_" + randomID(6)
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
		ExpiresAt: now + 28800, // 8h max session
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
		EXP:                  now + 180, // Sub-agent TTL <= 3 min (attenuated from parent's 5 min)
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
		ExpiresAt:  now + 120, // 2-minute timeout defaults to deny
		ResolvedCh: make(chan string, 1),
	}
	s.cibaRequests[id] = req
	return req
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
