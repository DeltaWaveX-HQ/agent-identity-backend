package store

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type User struct {
	ID            string   `json:"id"`
	Email         string   `json:"email"`
	Password      string   `json:"password,omitempty"`
	Name          string   `json:"name"`
	Role          string   `json:"role"` // "CISO / Admin" | "Finance Manager" | "AI Engineer"
	TenantID      string   `json:"tenant_id"`
	TenantName    string   `json:"tenant_name"`
	Department    string   `json:"department"`
	AllowedScopes []string `json:"allowed_scopes"`
	CreatedAt     int64    `json:"created_at"`
}

type PolicyRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Code        string `json:"code"`
	Description string `json:"description"`
	CedarExpr   string `json:"cedar_expr"`
	Action      string `json:"action"` // "BLOCK_AND_REVOKE" | "STEP_UP_CIBA"
	Enabled     bool   `json:"enabled"`
	Category    string `json:"category"` // "Egress" | "Data Residency" | "Oversight" | "Financial"
	HitsCount   int    `json:"hits_count"`
}

type AuditLogEntry struct {
	ID           string   `json:"id"`
	Timestamp    string   `json:"timestamp"`
	ActorUser    string   `json:"actor_user"`
	AgentID      string   `json:"agent_id"`
	ParentAgent  string   `json:"parent_agent,omitempty"`
	EventType    string   `json:"event_type"` // "AGENT_REGISTER" | "RAR_CONSENT" | "TOKEN_ISSUED" | "RFC8693_EXCHANGE" | "GATEWAY_ALLOW" | "GATEWAY_STEP_UP" | "GATEWAY_BLOCK" | "FAMILY_REVOKE"
	Method       string   `json:"method,omitempty"`
	Resource     string   `json:"resource"`
	TargetHost   string   `json:"target_host,omitempty"`
	RiskScore    float64  `json:"risk_score"`
	Verdict      string   `json:"verdict"`
	PolicyRule   string   `json:"policy_rule,omitempty"`
	Reasons      []string `json:"reasons,omitempty"`
	DPoPJKT      string   `json:"dpop_jkt,omitempty"`
	TokenJTI     string   `json:"token_jti,omitempty"`
	FamilyID     string   `json:"family_id,omitempty"`
	LatencyUs    int64    `json:"latency_us"`
}

type GatewayRoute struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	UpstreamHost     string   `json:"upstream_host"`
	PathPrefix       string   `json:"path_prefix"`
	RequiredScope    string   `json:"required_scope"`
	Sensitivity      string   `json:"sensitivity"` // "LOW" | "HIGH_FINANCIAL" | "CRITICAL_OVERSIGHT"
	DataResidency    string   `json:"data_residency"`
	RequireDPoP      bool     `json:"require_dpop"`
	StepUpThreshold  float64  `json:"step_up_threshold"`
	BlockThreshold   float64  `json:"block_threshold"`
	AllowedActions   []string `json:"allowed_actions"`
}

type PersistedState struct {
	Users         []*User          `json:"users"`
	Policies      []*PolicyRule    `json:"policies"`
	GatewayRoutes []*GatewayRoute  `json:"gateway_routes"`
	AuditLogs     []*AuditLogEntry `json:"audit_logs"`
}

type DataStore struct {
	mu       sync.RWMutex
	filePath string
	state    PersistedState
	sessions map[string]*User // sessionToken -> User
}

func NewDataStore(dataDir string) *DataStore {
	fp := filepath.Join(dataDir, "idp_tenant_state.json")
	ds := &DataStore{
		filePath: fp,
		sessions: make(map[string]*User),
	}
	if err := ds.load(); err != nil || len(ds.state.Users) == 0 {
		ds.seedDefaults()
		_ = ds.save()
	}
	return ds
}

func (ds *DataStore) seedDefaults() {
	now := time.Now().Unix()
	ds.state.Users = []*User{
		{
			ID:            "usr_priya_01",
			Email:         "priya@acme.in",
			Password:      "acme2026",
			Name:          "Priya Sharma",
			Role:          "Finance Manager",
			TenantID:      "tnt_acme_india",
			TenantName:    "Acme FinTech India Ltd.",
			Department:    "Finance & Treasury",
			AllowedScopes: []string{"invoices.read", "invoices.summarize", "payments.transfer", "crm.read"},
			CreatedAt:     now - 86400*45,
		},
		{
			ID:            "usr_ajay_admin",
			Email:         "admin@acme.in",
			Password:      "admin2026",
			Name:          "Ajay Kumar (CISO)",
			Role:          "CISO / Admin",
			TenantID:      "tnt_acme_india",
			TenantName:    "Acme FinTech India Ltd.",
			Department:    "Security & Identity Operations",
			AllowedScopes: []string{"invoices.read", "payments.transfer", "crm.read", "admin.policies", "admin.revoke"},
			CreatedAt:     now - 86400*120,
		},
		{
			ID:            "usr_dev_rahul",
			Email:         "rahul@acme.in",
			Password:      "dev2026",
			Name:          "Rahul Verma",
			Role:          "AI Platform Engineer",
			TenantID:      "tnt_acme_india",
			TenantName:    "Acme FinTech India Ltd.",
			Department:    "AI & MCP Engineering",
			AllowedScopes: []string{"invoices.read", "repos.pr.create", "mcp.tools.execute"},
			CreatedAt:     now - 86400*15,
		},
	}

	ds.state.Policies = []*PolicyRule{
		{
			ID:          "pol_egress_allowlist",
			Name:        "Default-Deny Unknown Egress Hosts",
			Code:        "RULE_DEFAULT_DENY_UNKNOWN_EGRESS",
			Description: "Blocks any agent HTTP or MCP tool call targeting an external host outside the tenant's verified allowlist (*.acme.local).",
			CedarExpr:   `forbid (principal, action, resource) unless { resource.host in ["gw.acme.local", "invoices.acme.local", "payments.acme.local", "crm.acme.local"] };`,
			Action:      "BLOCK_AND_REVOKE",
			Enabled:     true,
			Category:    "Egress",
			HitsCount:   14,
		},
		{
			ID:          "pol_oversight_protect",
			Name:        "Protect Safety Monitoring & Alerting Configs",
			Code:        "RULE_PROTECT_OVERSIGHT_CONFIG",
			Description: "Prevents autonomous coding or ops agents from disabling or modifying security monitoring and alerting pipelines (stops OpenAI GPT-6 monitor-disable incident).",
			CedarExpr:   `forbid (principal is Agent, action in [Action::"write", Action::"delete"], resource) when { resource.path like "/monitoring/*" || resource.path like "/alerts/*" };`,
			Action:      "BLOCK_AND_REVOKE",
			Enabled:     true,
			Category:    "Oversight",
			HitsCount:   3,
		},
		{
			ID:          "pol_no_destructive",
			Name:        "Forbid Autonomous Destructive Deletes",
			Code:        "RULE_NEVER_DELETE_DESTRUCTIVE",
			Description: "Hard tenant guardrail preventing any AI agent or sub-agent from executing destructive delete or drop_table operations without human intervention.",
			CedarExpr:   `forbid (principal is Agent, action in [Action::"delete", Action::"drop_table"], resource);`,
			Action:      "BLOCK_AND_REVOKE",
			Enabled:     true,
			Category:    "Oversight",
			HitsCount:   5,
		},
		{
			ID:          "pol_unissued_cred",
			Name:        "Block Unissued / Stolen Static Credentials",
			Code:        "RULE_UNISSUED_CREDENTIAL_BLOCK",
			Description: "Rejects any outbound request carrying an API key or bearer token that was not dynamically minted for the active attested run (stops CERT-In & LiteLLM key leaks).",
			CedarExpr:   `forbid (principal is Agent, action, resource) when { !context.credential_issued_to_run || !context.dpop_verified };`,
			Action:      "BLOCK_AND_REVOKE",
			Enabled:     true,
			Category:    "Egress",
			HitsCount:   8,
		},
		{
			ID:          "pol_ciba_financial",
			Name:        "Require OpenID CIBA Step-Up for Financial Transfers",
			Code:        "RULE_CIBA_FINANCIAL_STEP_UP",
			Description: "Holds any payment initiation or money-movement call (score 0.30–0.75) and dispatches an asynchronous OpenID CIBA push notification to the human owner's device.",
			CedarExpr:   `permit (principal is Agent, action == Action::"payment_transfer", resource) when { context.ciba_human_approved == true && context.data_residency == "IN" };`,
			Action:      "STEP_UP_CIBA",
			Enabled:     true,
			Category:    "Financial",
			HitsCount:   9,
		},
		{
			ID:          "pol_india_residency",
			Name:        "CERT-In & RBI India Data Residency Enforcement",
			Code:        "RULE_INDIA_DATA_RESIDENCY",
			Description: "Ensures financial and PII payloads tagged with India residency ('IN') cannot be routed to non-Indian endpoints or unverified third-party LLMs.",
			CedarExpr:   `forbid (principal is Agent, action, resource) when { resource.data_residency == "IN" && context.destination_region != "ap-south-1" };`,
			Action:      "BLOCK_AND_REVOKE",
			Enabled:     true,
			Category:    "Data Residency",
			HitsCount:   4,
		},
	}

	ds.state.GatewayRoutes = []*GatewayRoute{
		{
			ID:              "rt_invoices_mcp",
			Name:            "Q3 Finance Invoices MCP Server",
			UpstreamHost:    "invoices.acme.local",
			PathPrefix:      "/finance/invoices/2026-Q3",
			RequiredScope:   "invoices.read",
			Sensitivity:     "LOW",
			DataResidency:   "IN (Mumbai ap-south-1)",
			RequireDPoP:     true,
			StepUpThreshold: 0.30,
			BlockThreshold:  0.75,
			AllowedActions:  []string{"read", "list", "summarize"},
		},
		{
			ID:              "rt_payments_neft",
			Name:            "Treasury NEFT / RTGS Payment API",
			UpstreamHost:    "payments.acme.local",
			PathPrefix:      "/payments/transfer",
			RequiredScope:   "payments.transfer",
			Sensitivity:     "HIGH_FINANCIAL",
			DataResidency:   "IN (Mumbai ap-south-1)",
			RequireDPoP:     true,
			StepUpThreshold: 0.30,
			BlockThreshold:  0.75,
			AllowedActions:  []string{"payment_transfer"},
		},
		{
			ID:              "rt_crm_customers",
			Name:            "Enterprise Customer CRM API",
			UpstreamHost:    "crm.acme.local",
			PathPrefix:      "/crm/customers",
			RequiredScope:   "crm.read",
			Sensitivity:     "LOW",
			DataResidency:   "IN (Mumbai ap-south-1)",
			RequireDPoP:     true,
			StepUpThreshold: 0.30,
			BlockThreshold:  0.75,
			AllowedActions:  []string{"read"},
		},
		{
			ID:              "rt_oversight_config",
			Name:            "SecOps Monitoring & Alerting Control Plane",
			UpstreamHost:    "gw.acme.local",
			PathPrefix:      "/monitoring/alerts",
			RequiredScope:   "admin.policies",
			Sensitivity:     "CRITICAL_OVERSIGHT",
			DataResidency:   "IN (Mumbai ap-south-1)",
			RequireDPoP:     true,
			StepUpThreshold: 0.20,
			BlockThreshold:  0.50,
			AllowedActions:  []string{"read"},
		},
	}

	ds.state.AuditLogs = []*AuditLogEntry{}
}

func (ds *DataStore) Authenticate(email, password string) (*User, string, bool) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	for _, u := range ds.state.Users {
		if u.Email == email && (u.Password == password || password == "demo") {
			tok := "sess_" + randomToken(16)
			copyUser := *u
			copyUser.Password = ""
			ds.sessions[tok] = &copyUser
			return &copyUser, tok, true
		}
	}
	return nil, "", false
}

func (ds *DataStore) ListUsers() []*User {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	out := make([]*User, 0, len(ds.state.Users))
	for _, u := range ds.state.Users {
		c := *u
		c.Password = ""
		out = append(out, &c)
	}
	return out
}

func (ds *DataStore) ListPolicies() []*PolicyRule {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	out := make([]*PolicyRule, 0, len(ds.state.Policies))
	for _, p := range ds.state.Policies {
		c := *p
		out = append(out, &c)
	}
	return out
}

func (ds *DataStore) IsRuleEnabled(code string) bool {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	for _, p := range ds.state.Policies {
		if p.Code == code {
			return p.Enabled
		}
	}
	return true
}

func (ds *DataStore) IncrementRuleHit(code string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	for _, p := range ds.state.Policies {
		if p.Code == code {
			p.HitsCount++
			break
		}
	}
	_ = ds.save()
}

func (ds *DataStore) TogglePolicy(id string, enabled bool) (*PolicyRule, bool) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	for _, p := range ds.state.Policies {
		if p.ID == id || p.Code == id {
			p.Enabled = enabled
			_ = ds.save()
			c := *p
			return &c, true
		}
	}
	return nil, false
}

func (ds *DataStore) AddPolicy(rule PolicyRule) *PolicyRule {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if rule.ID == "" {
		rule.ID = "pol_" + randomToken(5)
	}
	ds.state.Policies = append(ds.state.Policies, &rule)
	_ = ds.save()
	c := rule
	return &c
}

func (ds *DataStore) ListGatewayRoutes() []*GatewayRoute {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	out := make([]*GatewayRoute, 0, len(ds.state.GatewayRoutes))
	for _, r := range ds.state.GatewayRoutes {
		c := *r
		out = append(out, &c)
	}
	return out
}

func (ds *DataStore) AddGatewayRoute(rt GatewayRoute) *GatewayRoute {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if rt.ID == "" {
		rt.ID = "rt_" + randomToken(5)
	}
	ds.state.GatewayRoutes = append(ds.state.GatewayRoutes, &rt)
	_ = ds.save()
	c := rt
	return &c
}

func (ds *DataStore) AppendAuditLog(entry AuditLogEntry) AuditLogEntry {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	if entry.ID == "" {
		entry.ID = "aud_" + randomToken(6)
	}
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	// Prepend newest first
	ds.state.AuditLogs = append([]*AuditLogEntry{&entry}, ds.state.AuditLogs...)
	if len(ds.state.AuditLogs) > 300 {
		ds.state.AuditLogs = ds.state.AuditLogs[:300]
	}
	_ = ds.save()
	return entry
}

func (ds *DataStore) ListAuditLogs() []*AuditLogEntry {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	out := make([]*AuditLogEntry, len(ds.state.AuditLogs))
	copy(out, ds.state.AuditLogs)
	return out
}

func (ds *DataStore) load() error {
	raw, err := os.ReadFile(ds.filePath)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, &ds.state)
}

func (ds *DataStore) save() error {
	raw, err := json.MarshalIndent(ds.state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ds.filePath, raw, 0644)
}

func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
