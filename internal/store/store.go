package store

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID            string   `json:"id"`
	Email         string   `json:"email"`
	Password      string   `json:"password,omitempty"`
	Name          string   `json:"name"`
	Role          string   `json:"role"`
	OrgID         string   `json:"org_id"`
	OrgName       string   `json:"org_name"`
	OrgDomain     string   `json:"org_domain"`
	AllowedScopes []string `json:"allowed_scopes"`
	CreatedAt     int64    `json:"created_at"`
}

type Organization struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Domain      string `json:"domain"`
	OwnerEmail  string `json:"owner_email"`
	DCREnabled  bool   `json:"dcr_enabled"`
	CAMDEnabled bool   `json:"camd_enabled"`
	CRMEnabled  bool   `json:"crm_enabled"`
	DPoPEnabled bool   `json:"dpop_enabled"`
	CIBAEnabled bool   `json:"ciba_enabled"`
	CreatedAt   int64  `json:"created_at"`
}

type PolicyRule struct {
	ID          string `json:"id"`
	OrgID       string `json:"org_id,omitempty"`
	Name        string `json:"name"`
	Code        string `json:"code"`
	Description string `json:"description"`
	CedarExpr   string `json:"cedar_expr"`
	Action      string `json:"action"` // "BLOCK_AND_REVOKE" | "STEP_UP_CIBA"
	Enabled     bool   `json:"enabled"`
	Category    string `json:"category"`
	HitsCount   int    `json:"hits_count"`
}

type AuditLogEntry struct {
	ID          string   `json:"id"`
	OrgID       string   `json:"org_id,omitempty"`
	Timestamp   string   `json:"timestamp"`
	ActorUser   string   `json:"actor_user"`
	AgentID     string   `json:"agent_id"`
	ParentAgent string   `json:"parent_agent,omitempty"`
	EventType   string   `json:"event_type"`
	Method      string   `json:"method,omitempty"`
	Resource    string   `json:"resource"`
	TargetHost  string   `json:"target_host,omitempty"`
	RiskScore   float64  `json:"risk_score"`
	Verdict     string   `json:"verdict"`
	PolicyRule  string   `json:"policy_rule,omitempty"`
	Reasons     []string `json:"reasons,omitempty"`
	DPoPJKT     string   `json:"dpop_jkt,omitempty"`
	TokenJTI    string   `json:"token_jti,omitempty"`
	FamilyID    string   `json:"family_id,omitempty"`
	LatencyUs   int64    `json:"latency_us"`
	Seq         int64    `json:"seq,omitempty"` // monotonic order (newest = largest), survives reloads
}

type GatewayRoute struct {
	ID              string   `json:"id"`
	OrgID           string   `json:"org_id,omitempty"`
	Name            string   `json:"name"`
	UpstreamHost    string   `json:"upstream_host"`
	PathPrefix      string   `json:"path_prefix"`
	RequiredScope   string   `json:"required_scope"`
	Sensitivity     string   `json:"sensitivity"`
	DataResidency   string   `json:"data_residency"`
	RequireDPoP     bool     `json:"require_dpop"`
	StepUpThreshold float64  `json:"step_up_threshold"`
	BlockThreshold  float64  `json:"block_threshold"`
	AllowedActions  []string `json:"allowed_actions"`
}

type PersistedState struct {
	Users         []*User          `json:"users"`
	Organizations []*Organization  `json:"organizations"`
	Policies      []*PolicyRule    `json:"policies"`
	GatewayRoutes []*GatewayRoute  `json:"gateway_routes"`
	AuditLogs     []*AuditLogEntry `json:"audit_logs"`
}

type DataStore struct {
	mu       sync.RWMutex
	filePath string
	state    PersistedState
	sessions map[string]*Session // sessionToken -> session
	hookKeys map[string]*HookKey // sha256(key) -> key metadata
}

// SessionTTL is how long a console sign-in stays valid.
const SessionTTL = 7 * 24 * time.Hour

type Session struct {
	UserID    string `json:"user_id"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
}

// hashPassword stores passwords with bcrypt; never in plain text.
func hashPassword(pw string) string {
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return ""
	}
	return string(h)
}

// checkPassword verifies a password. Accounts created before hashing (plain-text value) still
// sign in once; the caller then upgrades them to a hash.
func checkPassword(stored, pw string) (ok, needsUpgrade bool) {
	if strings.HasPrefix(stored, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(pw)) == nil, false
	}
	return stored != "" && stored == pw, true
}

func (ds *DataStore) newSessionLocked(userID string) string {
	tok := "sess_" + randomToken(24)
	now := time.Now()
	ds.sessions[tok] = &Session{UserID: userID, CreatedAt: now.Unix(), ExpiresAt: now.Add(SessionTTL).Unix()}
	return tok
}

// Logout ends a console session.
func (ds *DataStore) Logout(token string) {
	ds.mu.Lock()
	delete(ds.sessions, token)
	ds.mu.Unlock()
}

// DetachFile stops writing the local JSON file; state is then persisted by the database syncer.
func (ds *DataStore) DetachFile() {
	ds.mu.Lock()
	ds.filePath = ""
	ds.mu.Unlock()
}

func NewDataStore(dataDir string) *DataStore {
	fp := filepath.Join(dataDir, "idp_tenant_state.json")
	ds := &DataStore{
		filePath: fp,
		sessions: make(map[string]*Session),
	}
	if err := ds.load(); err != nil {
		ds.seedGuardrailTemplates()
		_ = ds.save()
	}
	return ds
}

func (ds *DataStore) seedGuardrailTemplates() {
	ds.state.Users = []*User{}
	ds.state.Organizations = []*Organization{}
	ds.state.AuditLogs = []*AuditLogEntry{}

	ds.state.Policies = []*PolicyRule{
		{
			ID:          "pol_egress_allowlist",
			Name:        "Default-Deny Unknown Egress Hosts",
			Code:        "RULE_DEFAULT_DENY_UNKNOWN_EGRESS",
			Description: "Blocks any agent HTTP or MCP tool call targeting an external host outside your organization's verified domain allowlist.",
			CedarExpr:   `forbid (principal, action, resource) unless { resource.host in context.org_allowed_hosts };`,
			Action:      "BLOCK_AND_REVOKE",
			Enabled:     true,
			Category:    "Egress",
			HitsCount:   0,
		},
		{
			ID:          "pol_oversight_protect",
			Name:        "Protect Safety Monitoring & Alerting Configs",
			Code:        "RULE_PROTECT_OVERSIGHT_CONFIG",
			Description: "Prevents autonomous coding or ops agents from disabling or modifying security monitoring and alerting pipelines.",
			CedarExpr:   `forbid (principal is Agent, action in [Action::"write", Action::"delete"], resource) when { resource.path like "/monitoring/*" || resource.path like "/alerts/*" };`,
			Action:      "BLOCK_AND_REVOKE",
			Enabled:     true,
			Category:    "Oversight",
			HitsCount:   0,
		},
		{
			ID:          "pol_no_destructive",
			Name:        "Forbid Autonomous Destructive Deletes",
			Code:        "RULE_NEVER_DELETE_DESTRUCTIVE",
			Description: "Hard guardrail preventing any AI agent or sub-agent from executing destructive delete or drop_table operations without human intervention.",
			CedarExpr:   `forbid (principal is Agent, action in [Action::"delete", Action::"drop_table"], resource);`,
			Action:      "BLOCK_AND_REVOKE",
			Enabled:     true,
			Category:    "Oversight",
			HitsCount:   0,
		},
		{
			ID:          "pol_unissued_cred",
			Name:        "Block Unissued / Stolen Static Credentials",
			Code:        "RULE_UNISSUED_CREDENTIAL_BLOCK",
			Description: "Rejects any outbound request carrying an API key or bearer token that was not dynamically minted for the active attested run.",
			CedarExpr:   `forbid (principal is Agent, action, resource) when { !context.credential_issued_to_run || !context.dpop_verified };`,
			Action:      "BLOCK_AND_REVOKE",
			Enabled:     true,
			Category:    "Egress",
			HitsCount:   0,
		},
		{
			ID:          "pol_ciba_financial",
			Name:        "Require OpenID CIBA Step-Up for High-Risk Actions",
			Code:        "RULE_CIBA_FINANCIAL_STEP_UP",
			Description: "Holds any high-sensitivity mutation or money-movement call (score 0.30–0.75) and dispatches a live approval request to the dashboard.",
			CedarExpr:   `permit (principal is Agent, action == Action::"payment_transfer", resource) when { context.ciba_human_approved == true };`,
			Action:      "STEP_UP_CIBA",
			Enabled:     true,
			Category:    "Financial",
			HitsCount:   0,
		},
	}

	ds.state.GatewayRoutes = []*GatewayRoute{}
}

// RegisterUserAndOrg signs up a real user and creates their organization tenant.
func (ds *DataStore) RegisterUserAndOrg(name, email, password, orgName, orgDomain string) (*User, *Organization, string, error) {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	email = strings.TrimSpace(strings.ToLower(email))
	if email == "" || password == "" {
		return nil, nil, "", fmt.Errorf("email and password are required")
	}
	if len(password) < 8 {
		return nil, nil, "", fmt.Errorf("password must be at least 8 characters")
	}
	for _, u := range ds.state.Users {
		if strings.EqualFold(u.Email, email) {
			return nil, nil, "", fmt.Errorf("account with email %s already exists (please sign in)", email)
		}
	}

	if orgName == "" {
		parts := strings.Split(email, "@")
		orgName = parts[0] + "-org"
	}
	slug := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(orgName), " ", "-"))
	if orgDomain == "" {
		orgDomain = slug + ".agentidentity.local"
	}

	now := time.Now().Unix()
	org := &Organization{
		ID:          "org_" + randomToken(6),
		Name:        orgName,
		Slug:        slug,
		Domain:      orgDomain,
		OwnerEmail:  email,
		DCREnabled:  true,
		CAMDEnabled: true,
		CRMEnabled:  true,
		DPoPEnabled: true,
		CIBAEnabled: true,
		CreatedAt:   now,
	}
	ds.state.Organizations = append(ds.state.Organizations, org)

	user := &User{
		ID:            "usr_" + randomToken(6),
		Email:         email,
		Password:      hashPassword(password),
		Name:          name,
		Role:          "Organization Owner",
		OrgID:         org.ID,
		OrgName:       org.Name,
		OrgDomain:     org.Domain,
		AllowedScopes: []string{"crm.read", "crm.write", "invoices.read", "payments.transfer", "files.read", "mcp.tools.execute"},
		CreatedAt:     now,
	}
	ds.state.Users = append(ds.state.Users, user)
	_ = ds.save()

	tok := ds.newSessionLocked(user.ID)
	copyUser := *user
	copyUser.Password = ""
	return &copyUser, org, tok, nil
}

func (ds *DataStore) Authenticate(email, password string) (*User, *Organization, string, bool) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	email = strings.TrimSpace(strings.ToLower(email))
	for _, u := range ds.state.Users {
		if !strings.EqualFold(u.Email, email) {
			continue
		}
		if ok, upgrade := checkPassword(u.Password, password); ok {
			if upgrade {
				u.Password = hashPassword(password)
				_ = ds.save()
			}
			tok := ds.newSessionLocked(u.ID)
			copyUser := *u
			copyUser.Password = ""
			var userOrg *Organization
			for _, o := range ds.state.Organizations {
				if o.ID == u.OrgID {
					co := *o
					userOrg = &co
					break
				}
			}
			return &copyUser, userOrg, tok, true
		}
	}
	return nil, nil, "", false
}

func (ds *DataStore) GetSession(token string) (*User, *Organization, bool) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	sess, ok := ds.sessions[token]
	if !ok || sess.ExpiresAt < time.Now().Unix() {
		return nil, nil, false
	}
	var u *User
	for _, x := range ds.state.Users {
		if x.ID == sess.UserID {
			c := *x
			c.Password = ""
			u = &c
			break
		}
	}
	if u == nil {
		return nil, nil, false
	}
	var userOrg *Organization
	for _, o := range ds.state.Organizations {
		if o.ID == u.OrgID {
			co := *o
			userOrg = &co
			break
		}
	}
	return u, userOrg, true
}

func (ds *DataStore) CreateOrganization(ownerEmail, orgName, orgDomain string) *Organization {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	slug := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(orgName), " ", "-"))
	if orgDomain == "" {
		orgDomain = slug + ".agentidentity.local"
	}
	org := &Organization{
		ID:          "org_" + randomToken(6),
		Name:        orgName,
		Slug:        slug,
		Domain:      orgDomain,
		OwnerEmail:  ownerEmail,
		DCREnabled:  true,
		CAMDEnabled: true,
		CRMEnabled:  true,
		DPoPEnabled: true,
		CIBAEnabled: true,
		CreatedAt:   time.Now().Unix(),
	}
	ds.state.Organizations = append(ds.state.Organizations, org)
	_ = ds.save()
	c := *org
	return &c
}

func (ds *DataStore) ListOrganizations(ownerEmail string) []*Organization {
	ds.mu.RLock()
	defer ds.mu.RUnlock()
	out := make([]*Organization, 0)
	for _, o := range ds.state.Organizations {
		if ownerEmail == "" || strings.EqualFold(o.OwnerEmail, ownerEmail) {
			c := *o
			out = append(out, &c)
		}
	}
	return out
}

func (ds *DataStore) UpdateOrgFlows(orgID string, dcr, camd, crm, dpop, ciba bool) (*Organization, bool) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	for _, o := range ds.state.Organizations {
		if o.ID == orgID || o.Slug == orgID {
			o.DCREnabled = dcr
			o.CAMDEnabled = camd
			o.CRMEnabled = crm
			o.DPoPEnabled = dpop
			o.CIBAEnabled = ciba
			_ = ds.save()
			c := *o
			return &c, true
		}
	}
	return nil, false
}

func (ds *DataStore) ResetAllData() {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.seedGuardrailTemplates()
	_ = ds.save()
}

func (ds *DataStore) ClearOrgActivity(orgID string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.state.AuditLogs = []*AuditLogEntry{}
	for _, p := range ds.state.Policies {
		p.HitsCount = 0
	}
	_ = ds.save()
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
	entry.Seq = time.Now().UnixNano()
	ds.state.AuditLogs = append([]*AuditLogEntry{&entry}, ds.state.AuditLogs...)
	if len(ds.state.AuditLogs) > 2000 {
		ds.state.AuditLogs = ds.state.AuditLogs[:2000]
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
	if ds.filePath == "" {
		return nil // persisted by the database syncer
	}
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
