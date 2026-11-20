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
	RedirectURIs      []string          `json:"redirect_uris,omitempty"`
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
	// Sub-agent delegation (RFC 8693 semantics through the same consent flow)
	SubAgentName    string `json:"sub_agent_name,omitempty"`
	SubAgentID      string `json:"sub_agent_id,omitempty"` // <parent agent id>/<name>: the sub-agent's own identity
	ParentAgentID   string `json:"parent_agent_id,omitempty"`
	ParentConsentID string `json:"parent_consent_id,omitempty"`
	CreatedAt       int64  `json:"created_at"`
	ExpiresAt       int64  `json:"expires_at"`
}

// CIBARequest represents an OpenID CIBA (POST /bc-authorize) asynchronous human step-up request.
type CIBARequest struct {
	AuthReqID string   `json:"auth_req_id"`
	AgentID   string   `json:"agent_id"`
	UserSub   string   `json:"user_sub"`
	Action    string   `json:"action"`
	Resource  string   `json:"resource"`
	RiskScore float64  `json:"risk_score"`
	Reasons   []string `json:"reasons"`
	Status    string   `json:"status"` // "PENDING" | "APPROVED" | "DENIED" | "EXPIRED"
	// Context so the approver knows exactly who asks for what, and can grant time-boxed access.
	Tool              string   `json:"tool,omitempty"`
	ArgsPreview       string   `json:"args_preview,omitempty"`
	ParentAgentID     string   `json:"parent_agent_id,omitempty"`
	FamilyID          string   `json:"family_id,omitempty"`
	GrantedActions    []string `json:"granted_actions,omitempty"`
	GrantExpiresAt    int64    `json:"grant_expires_at,omitempty"`
	CanElevate        bool     `json:"can_elevate"`
	MaxElevateSeconds int64    `json:"max_elevate_seconds,omitempty"`
	ElevatedUntil     int64    `json:"elevated_until,omitempty"`
	// Kind is "step_up" (one risky call) or "sub_agent" (a newly spawned sub-agent asks for delegated access).
	Kind            string   `json:"kind"`
	SubAgentType    string   `json:"sub_agent_type,omitempty"`
	OfferActions    []string `json:"offer_actions,omitempty"`     // what the parent can delegate
	OfferMaxSeconds int64    `json:"offer_max_seconds,omitempty"` // never beyond the parent's grant
	ChosenActions   []string `json:"chosen_actions,omitempty"`
	ChosenSeconds   int64    `json:"chosen_seconds,omitempty"`
	// What the parent asked for when it created the sub-agent (token exchange), to pre-fill the card.
	RequestedActions []string    `json:"requested_actions,omitempty"`
	RequestedSeconds int64       `json:"requested_seconds,omitempty"`
	Source           string      `json:"source,omitempty"`
	CreatedAt        int64       `json:"created_at"`
	ExpiresAt        int64       `json:"expires_at"`
	ResolvedCh       chan string `json:"-"`
}

type Server struct {
	mu           sync.RWMutex
	km           *crypto.KeyManager
	dag          *FamilyDAG
	agents       map[string]*RegisteredAgent
	consents     map[string]*ConsentRecord
	codes        map[string]*ConsentRecord // auth_code -> ConsentRecord
	cibaRequests map[string]*CIBARequest
	elevations   map[string]map[string]int64 // familyID -> action -> unix expiry (just-in-time grants)
	delegations  map[string]*Delegation      // sub-agent id -> delegated grant
}

// Delegation is the grant of a sub-agent that the client spawned on its own (e.g. a Claude Code
// sub-agent) and that the gateway detected. It rides on the parent's session and is enforced by
// the gateway: a subset of the parent's actions, for a short time, never beyond the parent.
type Delegation struct {
	ID              string   `json:"id"`
	SubAgentID      string   `json:"sub_agent_id"`
	SubAgentType    string   `json:"sub_agent_type"`
	ClientAgentID   string   `json:"client_agent_id"` // the client-side id (Claude Code agent_id)
	ParentAgentID   string   `json:"parent_agent_id"`
	ParentFamilyID  string   `json:"parent_family_id"`
	ParentConsentID string   `json:"parent_consent_id,omitempty"`
	UserSub         string   `json:"user_sub"`
	Actions         []string `json:"actions"`
	Status          string   `json:"status"` // pending | active | denied | revoked
	CreatedAt       int64    `json:"created_at"`
	ExpiresAt       int64    `json:"expires_at"`
	RequestID       string   `json:"request_id,omitempty"`
	ParentActions   []string `json:"parent_actions,omitempty"`
	Source          string   `json:"source,omitempty"` // token_exchange | mcp_meta | client_hook
}

func NewServer(km *crypto.KeyManager, dag *FamilyDAG) *Server {
	return &Server{
		km:           km,
		dag:          dag,
		agents:       make(map[string]*RegisteredAgent),
		consents:     make(map[string]*ConsentRecord),
		codes:        make(map[string]*ConsentRecord),
		cibaRequests: make(map[string]*CIBARequest),
		elevations:   make(map[string]map[string]int64),
		delegations:  make(map[string]*Delegation),
	}
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
	s.agents = make(map[string]*RegisteredAgent)
	s.consents = make(map[string]*ConsentRecord)
	s.codes = make(map[string]*ConsentRecord)
	s.cibaRequests = make(map[string]*CIBARequest)
	s.elevations = make(map[string]map[string]int64)
	s.delegations = make(map[string]*Delegation)
	s.mu.Unlock()
	s.dag.Reset()
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
	if existing, ok := s.agents[req.AgentID]; ok && existing.Status == "REVOKED" {
		// Kill switch is sticky: re-registering under the same identity must not resurrect it.
		return nil, fmt.Errorf("agent %s was revoked by an administrator; restore it from the console first", req.AgentID)
	}
	req.RegisteredAt = time.Now().Unix()
	req.Status = "ACTIVE"
	s.agents[req.AgentID] = &req
	return &req, nil
}

// RestoreAgent re-activates an agent that was revoked by the kill switch.
func (s *Server) RestoreAgent(agentID string) (*RegisteredAgent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[agentID]
	if !ok {
		return nil, fmt.Errorf("agent %s not found", agentID)
	}
	a.Status = "ACTIVE"
	return a, nil
}

// IsAgentRevoked reports whether a registered agent has been killed. Unknown agents are not revoked.
func (s *Server) IsAgentRevoked(agentID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.agents[agentID]
	return ok && a.Status == "REVOKED"
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
	clientIDs := []string{agentID}
	// Also revoke any sub-agents whose parent is agentID
	for _, child := range s.agents {
		if child.ParentAgentID == agentID {
			child.Status = "REVOKED"
			clientIDs = append(clientIDs, child.AgentID)
		}
	}
	s.mu.Unlock()

	// Only this agent's token families — not every agent in the tenant.
	snaps := s.dag.RevokeByClient(clientIDs, "Agent Revoked by Admin/User: "+agentID+" ("+reason+")")
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

// ApproveConsentAs records a consent approved by an authenticated human on the browser consent
// screen: binds it to that user, narrows it to the actions they ticked and sets how long it lasts.
func (s *Server) ApproveConsentAs(consentID, userSub string, actions []string, ttl time.Duration) (*ConsentRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.consents[consentID]
	if !ok {
		return nil, fmt.Errorf("consent record %s not found", consentID)
	}
	if rec.Approved || rec.Revoked {
		return nil, fmt.Errorf("consent record %s was already decided", consentID)
	}
	if len(actions) == 0 {
		return nil, errors.New("select at least one permission to approve")
	}
	rec.UserSub = userSub
	if a, ok := s.agents[rec.AgentID]; ok && (a.OwnerUser == "" || a.OwnerUser == "pending-consent") {
		a.OwnerUser = userSub
	}
	if len(rec.AuthorizationDetails) == 0 {
		rec.AuthorizationDetails = []crypto.AuthorizationDetail{{Type: "mcp_tool_execution", Locations: []string{rec.Aud}}}
	}
	rec.AuthorizationDetails[0].Actions = actions
	rec.Approved = true
	rec.Version++
	rec.ExpiresAt = time.Now().Add(ttl).Unix()
	rec.AuthCode = "code_pkce_" + randomID(16)
	s.codes[rec.AuthCode] = rec
	return rec, nil
}

// ConsentStatus summarises a consent for the console: pending | active | expired | revoked.
func (s *Server) ConsentStatus(c *ConsentRecord) string {
	switch {
	case c.Revoked:
		if !c.Approved {
			return "denied"
		}
		return "revoked"
	case !c.Approved:
		return "pending"
	case c.ExpiresAt > 0 && time.Now().Unix() > c.ExpiresAt:
		return "expired"
	case c.FamilyID != "":
		if snap := s.dag.GetSnapshot(c.FamilyID); snap != nil && snap.Revoked {
			return "revoked"
		}
	}
	return "active"
}

// ActiveParentGrants lists approved, unexpired, unrevoked top-level grants that already have
// tokens — the grants a sub-agent may be delegated from. Optionally limited to one user.
func (s *Server) ActiveParentGrants(aud, userSub string) []*ConsentRecord {
	s.mu.RLock()
	list := make([]*ConsentRecord, 0)
	for _, c := range s.consents {
		if c.ParentConsentID == "" && c.Approved && c.FamilyID != "" && c.Aud == aud && (userSub == "" || c.UserSub == userSub) {
			list = append(list, c)
		}
	}
	s.mu.RUnlock()
	out := list[:0]
	for _, c := range list {
		if s.ConsentStatus(c) == "active" && !s.IsAgentRevoked(c.AgentID) {
			out = append(out, c)
		}
	}
	return out
}

// ApproveSubAgentConsent approves a sub-agent under one of the signing-in user's active parent
// grants. The sub-agent can only receive a subset of the parent's actions (never payments) and
// can never outlive the parent's grant.
func (s *Server) ApproveSubAgentConsent(consentID, userSub, parentConsentID string, actions []string, ttl time.Duration) (*ConsentRecord, error) {
	parent, ok := s.GetConsent(parentConsentID)
	if !ok || parent.ParentConsentID != "" {
		return nil, errors.New("choose a parent agent")
	}
	if parent.UserSub != userSub {
		return nil, errors.New("you can only delegate from agents you approved yourself")
	}
	if s.ConsentStatus(parent) != "active" || parent.FamilyID == "" {
		return nil, errors.New("the parent agent's access is no longer active")
	}
	allowed := map[string]bool{}
	for _, ad := range parent.AuthorizationDetails {
		for _, a := range ad.Actions {
			allowed[a] = true
		}
	}
	var narrowed []string
	for _, a := range actions {
		if a == "payment_transfer" {
			return nil, errors.New("sub-agents can never move money")
		}
		if !allowed[a] {
			return nil, fmt.Errorf("the parent agent was not granted %q, so it cannot delegate it", a)
		}
		narrowed = append(narrowed, a)
	}
	if remaining := time.Until(time.Unix(parent.ExpiresAt, 0)); ttl > remaining {
		ttl = remaining
	}
	pending, ok := s.GetConsent(consentID)
	if !ok || pending.SubAgentName == "" {
		return nil, errors.New("not a sub-agent request")
	}
	// The sub-agent gets its own identity under the parent, even when the MCP client presents the
	// same OAuth client_id for every connection (Claude Code does: one CIMD URL for all of them).
	subID := parent.AgentID + "/" + pending.SubAgentName
	s.mu.RLock()
	existing, exists := s.agents[subID]
	clientAgent := s.agents[pending.AgentID]
	s.mu.RUnlock()
	if exists && existing.Status == "REVOKED" {
		return nil, fmt.Errorf("sub-agent %s was revoked by an administrator", subID)
	}
	if !exists {
		platform, model, spiffe := "Sub-agent", "", "spiffe://acme.in/ns/sub-agents/sa/"+pending.SubAgentName
		if clientAgent != nil {
			platform = "Sub-agent via " + clientAgent.Name
			model = clientAgent.ModelID
			spiffe = clientAgent.SPIFFEID + "/" + pending.SubAgentName
		}
		if _, err := s.RegisterAgent(RegisteredAgent{
			AgentID: subID, Name: pending.SubAgentName, OwnerUser: userSub, ParentAgentID: parent.AgentID,
			SPIFFEID: spiffe, RuntimeAttested: true, PlatformFramework: platform, ModelID: model,
		}); err != nil {
			return nil, err
		}
	}
	rec, err := s.ApproveConsentAs(consentID, userSub, narrowed, ttl)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	rec.ParentAgentID = parent.AgentID
	rec.ParentConsentID = parent.ConsentID
	rec.SubAgentID = subID
	if a, ok := s.agents[subID]; ok {
		a.ParentAgentID = parent.AgentID
		a.OwnerUser = userSub
	}
	s.mu.Unlock()
	return rec, nil
}

// ConsentForCode returns the consent an authorization code was issued from.
func (s *Server) ConsentForCode(code string) (*ConsentRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.codes[code]
	return c, ok
}

// ConsentByFamily returns the consent that started a token family.
func (s *Server) ConsentByFamily(familyID string) (*ConsentRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.consents {
		if c.FamilyID == familyID {
			return c, true
		}
	}
	return nil, false
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
	if rec.Revoked {
		s.mu.Unlock()
		return "", nil, "", errors.New("consent was withdrawn")
	}
	if rec.PKCEChallenge != "" {
		// OAuth 2.1: a code issued against a PKCE challenge is useless without the verifier.
		if pkceVerifier == "" {
			s.mu.Unlock()
			return "", nil, "", errors.New("PKCE code_verifier required")
		}
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
	agentID := rec.AgentID
	if rec.SubAgentID != "" {
		agentID = rec.SubAgentID
	}
	exp := now + 300 // 5 min short-lived access token
	if rec.ExpiresAt > 0 && rec.ExpiresAt < exp {
		exp = rec.ExpiresAt
	}
	var cnf map[string]string
	if dpopJKT != "" {
		cnf = map[string]string{"jkt": dpopJKT}
	}

	tokenClaims := crypto.AgentAccessTokenClaims{
		Iss:                  "https://auth.agentidentity.local",
		Sub:                  rec.UserSub,
		ClientID:             agentID,
		Aud:                  rec.Aud,
		Scope:                rec.Scope,
		JTI:                  jti,
		FamilyID:             familyID,
		IAT:                  now,
		EXP:                  exp,
		CNF:                  cnf,
		AuthorizationDetails: rec.AuthorizationDetails,
		Risk: map[string]any{
			"issuance_score": issuanceRisk,
			"model":          "issuance-xgb-v3",
		},
	}

	tokenType := "parent_access"
	if rec.ParentConsentID != "" {
		// Sub-agent: the token records who delegated to whom (user → parent agent → sub-agent),
		// and its family hangs under the parent's so revoking the parent revokes the child.
		tokenClaims.Act = &crypto.ActorClaim{Sub: rec.ParentAgentID, Act: &crypto.ActorClaim{Sub: rec.UserSub}}
		tokenType = "sub_agent_access"
		if parent, ok := s.GetConsent(rec.ParentConsentID); ok && parent.FamilyID != "" {
			s.dag.LinkFamily(familyID, parent.FamilyID)
		}
	}

	tokenClaims.IdentityHierarchy = crypto.BuildUserAgentHierarchy(tokenClaims, "", "gemini-2.5-flash", "yes", []string{"spiffe_workload_attested", "rar_scope_matches_task", "dpop_sender_constrained"})

	priv, kid := s.km.ActiveSigner()
	jwtStr, err := crypto.SignAccessToken(priv, kid, tokenClaims)
	if err != nil {
		return "", nil, "", err
	}
	tokenClaims.IdentityHierarchy = crypto.BuildUserAgentHierarchy(tokenClaims, jwtStr, "gemini-2.5-flash", "yes", []string{"spiffe_workload_attested", "rar_scope_matches_task", "dpop_sender_constrained"})

	s.dag.RegisterToken(&TokenNode{
		JTI:       jti,
		FamilyID:  familyID,
		TokenType: tokenType,
		ClientID:  agentID,
		UserSub:   rec.UserSub,
		Scope:     rec.Scope,
		DPoPJKT:   dpopJKT,
		Status:    TokenActive,
		IssuedAt:  now,
		ExpiresAt: exp,
		Claims:    &tokenClaims,
		RawJWT:    jwtStr,
	})

	refJTI := "rt_rot_" + randomID(16)
	refExp := now + 28800 // session max 8 h
	if rec.ExpiresAt > 0 && rec.ExpiresAt < refExp {
		refExp = rec.ExpiresAt
	}
	s.dag.RegisterToken(&TokenNode{
		JTI:       refJTI,
		FamilyID:  familyID,
		ParentJTI: jti,
		TokenType: "refresh_token",
		ClientID:  agentID,
		UserSub:   rec.UserSub,
		Scope:     rec.Scope,
		DPoPJKT:   dpopJKT,
		Status:    TokenActive,
		IssuedAt:  now,
		ExpiresAt: refExp,
	})

	return jwtStr, &tokenClaims, refJTI, nil
}

// RefreshAccessToken implements OAuth 2.1 refresh-token rotation: the presented refresh token is
// spent, a new 5-minute access token and a new refresh token are issued in the same family.
// Replaying a spent refresh token revokes the whole family (theft signal).
func (s *Server) RefreshAccessToken(refreshJTI, clientID string) (accessJWT string, claims *crypto.AgentAccessTokenClaims, newRefresh string, err error) {
	node, ok := s.dag.GetToken(refreshJTI)
	if !ok || node.TokenType != "refresh_token" {
		return "", nil, "", errors.New("unknown refresh token")
	}
	famConsent, hasConsent := s.ConsentByFamily(node.FamilyID)
	if clientID != "" && node.ClientID != clientID && !(hasConsent && famConsent.AgentID == clientID) {
		return "", nil, "", errors.New("refresh token was not issued to this client")
	}
	if revoked, cause := s.dag.IsRevoked(refreshJTI); revoked {
		return "", nil, "", fmt.Errorf("token family revoked: %s", cause)
	}
	if reused, famID := s.dag.RotateRefreshToken(refreshJTI); reused {
		return "", nil, "", fmt.Errorf("refresh token replay detected; token family %s revoked", famID)
	}
	now := time.Now().Unix()
	if node.ExpiresAt > 0 && now > node.ExpiresAt {
		return "", nil, "", errors.New("refresh token expired (session or consent ended)")
	}
	if s.IsAgentRevoked(node.ClientID) || (hasConsent && s.IsAgentRevoked(famConsent.AgentID)) {
		return "", nil, "", errors.New("agent revoked by administrator")
	}
	rec, ok := famConsent, hasConsent
	if !ok || rec.Revoked {
		return "", nil, "", errors.New("consent withdrawn")
	}
	parent, ok := s.dag.GetToken(node.ParentJTI)
	if !ok || parent.Claims == nil {
		return "", nil, "", errors.New("token family has no parent access token")
	}

	newClaims := *parent.Claims
	newClaims.JTI = "tok_parent_" + randomID(6)
	newClaims.IAT = now
	newClaims.EXP = now + 300
	if rec.ExpiresAt > 0 && rec.ExpiresAt < newClaims.EXP {
		newClaims.EXP = rec.ExpiresAt
	}
	newClaims.IdentityHierarchy = nil

	priv, kid := s.km.ActiveSigner()
	jwtStr, err := crypto.SignAccessToken(priv, kid, newClaims)
	if err != nil {
		return "", nil, "", err
	}
	s.dag.RegisterToken(&TokenNode{
		JTI:       newClaims.JTI,
		FamilyID:  newClaims.FamilyID,
		TokenType: "parent_access",
		ClientID:  newClaims.ClientID,
		UserSub:   newClaims.Sub,
		Scope:     newClaims.Scope,
		DPoPJKT:   parent.DPoPJKT,
		Status:    TokenActive,
		IssuedAt:  now,
		ExpiresAt: newClaims.EXP,
		Claims:    &newClaims,
		RawJWT:    jwtStr,
	})
	newRefresh = "rt_rot_" + randomID(16)
	s.dag.RegisterToken(&TokenNode{
		JTI:       newRefresh,
		FamilyID:  newClaims.FamilyID,
		ParentJTI: newClaims.JTI,
		TokenType: "refresh_token",
		ClientID:  newClaims.ClientID,
		UserSub:   newClaims.Sub,
		Scope:     newClaims.Scope,
		DPoPJKT:   parent.DPoPJKT,
		Status:    TokenActive,
		IssuedAt:  now,
		ExpiresAt: node.ExpiresAt,
	})
	return jwtStr, &newClaims, newRefresh, nil
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

	subClaims.IdentityHierarchy = crypto.BuildUserAgentHierarchy(subClaims, "", "gemini-2.5-flash", "yes", []string{"rfc8693_attenuated_from_parent", "ttl_shrunk_5m_to_3m", "distinct_sub_agent_dpop_key"})

	priv, kid := s.km.ActiveSigner()
	jwtStr, err := crypto.SignAccessToken(priv, kid, subClaims)
	if err != nil {
		return "", nil, err
	}
	subClaims.IdentityHierarchy = crypto.BuildUserAgentHierarchy(subClaims, jwtStr, "gemini-2.5-flash", "yes", []string{"rfc8693_attenuated_from_parent", "ttl_shrunk_5m_to_3m", "distinct_sub_agent_dpop_key"})

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
	if !revoked && s.IsAgentRevoked(claims.ClientID) {
		revoked, cause = true, "agent revoked by administrator"
	}
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
		Kind:       "step_up",
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
	if req.Status != "PENDING" {
		s.mu.Unlock()
		return req, fmt.Errorf("CIBA request %s already %s", authReqID, req.Status)
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

// ExpireCIBARequest marks an unanswered step-up as expired (silence means no).
func (s *Server) ExpireCIBARequest(authReqID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if req, ok := s.cibaRequests[authReqID]; ok && req.Status == "PENDING" {
		req.Status = "EXPIRED"
	}
}

// AnnotateCIBA attaches approval context to a pending step-up request.
func (s *Server) AnnotateCIBA(authReqID string, fn func(*CIBARequest)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r, ok := s.cibaRequests[authReqID]; ok {
		fn(r)
	}
}

// GetCIBARequest returns one step-up request.
func (s *Server) GetCIBARequest(authReqID string) (*CIBARequest, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.cibaRequests[authReqID]
	return r, ok
}

// Elevate grants a token family one extra action until `until` (just-in-time, time-boxed access
// approved by a human). It never outlives the family's consent.
func (s *Server) Elevate(familyID, action string, until int64) int64 {
	if c, ok := s.ConsentByFamily(familyID); ok && c.ExpiresAt > 0 && until > c.ExpiresAt {
		until = c.ExpiresAt
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.elevations[familyID] == nil {
		s.elevations[familyID] = map[string]int64{}
	}
	s.elevations[familyID][action] = until
	return until
}

// ActiveElevations returns the unexpired just-in-time grants of a token family.
func (s *Server) ActiveElevations(familyID string) map[string]int64 {
	now := time.Now().Unix()
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]int64{}
	for a, until := range s.elevations[familyID] {
		if until > now {
			out[a] = until
		}
	}
	return out
}

// ParentGrantedActions returns the actions of the parent grant for a sub-agent family (nil if not a sub-agent).
func (s *Server) ParentGrantedActions(familyID string) (actions []string, isSub bool) {
	c, ok := s.ConsentByFamily(familyID)
	if !ok || c.ParentConsentID == "" {
		return nil, false
	}
	p, ok := s.GetConsent(c.ParentConsentID)
	if !ok {
		return []string{}, true
	}
	for _, ad := range p.AuthorizationDetails {
		actions = append(actions, ad.Actions...)
	}
	return actions, true
}

// GetDelegation returns a detected sub-agent's delegated grant.
func (s *Server) GetDelegation(subID string) (*Delegation, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.delegations[subID]
	return d, ok
}

// PutDelegation stores or replaces a sub-agent's delegated grant.
func (s *Server) PutDelegation(d *Delegation) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.delegations[d.SubAgentID] = d
}

// ListDelegations returns every detected sub-agent grant.
func (s *Server) ListDelegations() []*Delegation {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Delegation, 0, len(s.delegations))
	for _, d := range s.delegations {
		out = append(out, d)
	}
	return out
}

// RevokeDelegation cuts off one sub-agent without touching its parent.
func (s *Server) RevokeDelegation(idOrSub string) (*Delegation, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.delegations {
		if d.ID == idOrSub || d.SubAgentID == idOrSub {
			d.Status = "revoked"
			return d, true
		}
	}
	return nil, false
}

// DelegationStatus is the effective status: expired once past its time, revoked if the parent
// session was revoked.
func (s *Server) DelegationStatus(d *Delegation) string {
	if d.Status == "active" {
		if time.Now().Unix() > d.ExpiresAt {
			return "expired"
		}
		if snap := s.dag.GetSnapshot(d.ParentFamilyID); snap != nil && snap.Revoked {
			return "revoked"
		}
		if s.IsAgentRevoked(d.SubAgentID) || s.IsAgentRevoked(d.ParentAgentID) {
			return "revoked"
		}
	}
	return d.Status
}

// ResolveSubAgentRequest answers a "new sub-agent" approval with the chosen actions and time.
func (s *Server) ResolveSubAgentRequest(authReqID string, approved bool, actions []string, seconds int64) (*CIBARequest, error) {
	s.mu.Lock()
	req, ok := s.cibaRequests[authReqID]
	if !ok || req.Kind != "sub_agent" {
		s.mu.Unlock()
		return nil, fmt.Errorf("sub-agent request %s not found", authReqID)
	}
	if req.Status != "PENDING" {
		s.mu.Unlock()
		return req, fmt.Errorf("request already %s", req.Status)
	}
	if approved {
		offer := map[string]bool{}
		for _, a := range req.OfferActions {
			offer[a] = true
		}
		var chosen []string
		for _, a := range actions {
			if offer[a] {
				chosen = append(chosen, a)
			}
		}
		if len(chosen) == 0 {
			s.mu.Unlock()
			return nil, errors.New("choose at least one permission the parent has")
		}
		if seconds <= 0 || seconds > req.OfferMaxSeconds {
			seconds = req.OfferMaxSeconds
		}
		req.ChosenActions, req.ChosenSeconds, req.Status = chosen, seconds, "APPROVED"
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

// IssueDelegatedToken mints a sub-agent's own access token (RFC 8693 token exchange) from an
// active delegation: its own identity, only the delegated actions, the user→parent→sub-agent
// chain in `act`, and a family linked under the parent so revoking the parent revokes it.
// Lifetime is 5 minutes at most and never beyond the delegation; the sub-agent re-exchanges.
func (s *Server) IssueDelegatedToken(parent *crypto.AgentAccessTokenClaims, dl *Delegation, aud, dpopJKT string) (string, *crypto.AgentAccessTokenClaims, error) {
	now := time.Now().Unix()
	exp := now + 300
	if dl.ExpiresAt < exp {
		exp = dl.ExpiresAt
	}
	if exp <= now {
		return "", nil, errors.New("delegation expired")
	}
	var cnf map[string]string
	if dpopJKT != "" {
		cnf = map[string]string{"jkt": dpopJKT}
	}
	familyID := "fam_" + randomID(6)
	claims := crypto.AgentAccessTokenClaims{
		Iss:                  "https://auth.agentidentity.local",
		Sub:                  parent.Sub,
		ClientID:             dl.SubAgentID,
		Aud:                  aud,
		Scope:                strings.Join(dl.Actions, " "),
		JTI:                  "tok_sub_" + randomID(6),
		FamilyID:             familyID,
		ParentJTI:            parent.JTI,
		IAT:                  now,
		EXP:                  exp,
		CNF:                  cnf,
		AuthorizationDetails: []crypto.AuthorizationDetail{{Type: "delegated_by_parent", Locations: []string{aud}, Actions: dl.Actions}},
		Risk:                 parent.Risk,
		Act:                  &crypto.ActorClaim{Sub: parent.ClientID, Act: &crypto.ActorClaim{Sub: parent.Sub}},
	}
	priv, kid := s.km.ActiveSigner()
	jwtStr, err := crypto.SignAccessToken(priv, kid, claims)
	if err != nil {
		return "", nil, err
	}
	s.dag.LinkFamily(familyID, parent.FamilyID)
	s.dag.RegisterToken(&TokenNode{
		JTI: claims.JTI, FamilyID: familyID, TokenType: "sub_agent_access", ClientID: dl.SubAgentID,
		UserSub: parent.Sub, Scope: claims.Scope, DPoPJKT: dpopJKT, Status: TokenActive,
		IssuedAt: now, ExpiresAt: exp, Claims: &claims, RawJWT: jwtStr,
	})
	return jwtStr, &claims, nil
}
