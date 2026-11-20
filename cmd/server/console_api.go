package main

// Console API: read models shaped for the tenant admin console (agent-identity-ui).
// Every console page maps to one of these endpoints plus a few existing action endpoints;
// see docs/03_backend_frontend_map.md for the full page → endpoint → handler map.
//
//	GET /api/v1/console/overview      Overview page (KPIs, pending approvals, recent activity)
//	GET /api/v1/console/agents        Agents page (directory with parent → sub-agent tree)
//	GET /api/v1/console/agent?id=…    Agent detail page (grants, tokens, sub-agents, activity)
//	GET /api/v1/console/grants        Access grants page
//	GET /api/v1/console/approvals     Approvals page (pending human step-ups)
//	GET /api/v1/console/connections   Connected tools page (proxied from the MCP gateway)

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/buildathon2026/agent-identity-backend/internal/auth"
	"github.com/buildathon2026/agent-identity-backend/internal/store"
)

type grantView struct {
	ConsentID     string   `json:"consent_id"`
	AgentID       string   `json:"agent_id"`
	AgentName     string   `json:"agent_name"`
	UserSub       string   `json:"user_sub"`
	Status        string   `json:"status"` // pending | active | expired | revoked | denied
	Actions       []string `json:"actions"`
	Resource      string   `json:"resource"`
	IsSubAgent    bool     `json:"is_sub_agent"`
	SubAgentName  string   `json:"sub_agent_name,omitempty"`
	ParentAgentID string   `json:"parent_agent_id,omitempty"`
	ParentGrantID string   `json:"parent_grant_id,omitempty"`
	FamilyID      string   `json:"family_id,omitempty"`
	CreatedAt     int64    `json:"created_at"`
	ExpiresAt     int64    `json:"expires_at"`
	// Extra actions a human allowed for a limited time from an approval (action -> unix expiry).
	Temporary map[string]int64 `json:"temporary,omitempty"`
}

type agentView struct {
	AgentID       string     `json:"agent_id"`
	Name          string     `json:"name"`
	Kind          string     `json:"kind"`   // agent | sub-agent
	Status        string     `json:"status"` // active | idle | revoked
	OwnerUser     string     `json:"owner_user"`
	ParentAgentID string     `json:"parent_agent_id,omitempty"`
	Platform      string     `json:"platform"`
	RegisteredAt  int64      `json:"registered_at"`
	ActiveGrant   *grantView `json:"active_grant,omitempty"`
	LastActivity  string     `json:"last_activity,omitempty"`
	Calls24h      int        `json:"calls_24h"`
	Blocked24h    int        `json:"blocked_24h"`
	Children      []string   `json:"children"`
}

func registerConsoleAPI(mux *http.ServeMux, d *serverDeps) {
	mux.HandleFunc("/api/v1/console/overview", d.consoleOverview)
	mux.HandleFunc("/api/v1/console/agents", d.consoleAgents)
	mux.HandleFunc("/api/v1/console/agent", d.consoleAgent)
	mux.HandleFunc("/api/v1/console/grants", d.consoleGrants)
	mux.HandleFunc("/api/v1/console/approvals", d.consoleApprovals)
	mux.HandleFunc("/api/v1/console/connections", d.consoleConnections)
}

func (d *serverDeps) grantViews() []grantView {
	var out []grantView
	for _, c := range d.authServer.ListConsents() {
		if c.RedirectURI == "" && c.SubAgentName == "" && !c.Approved {
			continue // internal sandbox prompts that never reached a human
		}
		g := grantView{
			ConsentID: c.ConsentID, AgentID: c.AgentID, AgentName: c.AgentID, UserSub: c.UserSub,
			Status: d.authServer.ConsentStatus(c), Resource: c.Aud, IsSubAgent: c.ParentConsentID != "" || c.SubAgentName != "",
			SubAgentName: c.SubAgentName, ParentAgentID: c.ParentAgentID, ParentGrantID: c.ParentConsentID,
			FamilyID: c.FamilyID, CreatedAt: c.CreatedAt, ExpiresAt: c.ExpiresAt,
		}
		if c.SubAgentID != "" {
			g.AgentID, g.AgentName = c.SubAgentID, c.SubAgentID
		}
		if a, ok := d.authServer.GetAgent(g.AgentID); ok && a.Name != "" {
			g.AgentName = a.Name
		}
		if c.FamilyID != "" {
			if el := d.authServer.ActiveElevations(c.FamilyID); len(el) > 0 {
				g.Temporary = el
			}
		}
		for _, ad := range c.AuthorizationDetails {
			g.Actions = append(g.Actions, ad.Actions...)
		}
		out = append(out, g)
	}
	// Sub-agents the client spawned on its own (detected by the gateway) and the access delegated to them.
	for _, dl := range d.authServer.ListDelegations() {
		g := grantView{
			ConsentID: dl.ID, AgentID: dl.SubAgentID, AgentName: dl.SubAgentType, UserSub: dl.UserSub,
			Status: d.authServer.DelegationStatus(dl), Actions: dl.Actions, Resource: "delegated by " + dl.ParentAgentID,
			IsSubAgent: true, SubAgentName: dl.SubAgentType, ParentAgentID: dl.ParentAgentID, ParentGrantID: dl.ParentConsentID,
			CreatedAt: dl.CreatedAt, ExpiresAt: dl.ExpiresAt,
		}
		if a, ok := d.authServer.GetAgent(dl.SubAgentID); ok && a.Name != "" {
			g.AgentName = a.Name
		}
		if el := d.authServer.ActiveElevations("deleg:" + dl.SubAgentID); len(el) > 0 {
			g.Temporary = el
		}
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

func isCall(e *store.AuditLogEntry) bool { return strings.HasPrefix(e.EventType, "GATEWAY_") }
func isBlock(e *store.AuditLogEntry) bool {
	return e.EventType == "GATEWAY_BLOCK" || strings.HasPrefix(e.EventType, "GATEWAY_STEP_UP_DENIED") || strings.HasPrefix(e.EventType, "GATEWAY_STEP_UP_EXPIRED")
}

func within24h(ts string) bool {
	t, err := time.Parse(time.RFC3339, ts)
	return err == nil && time.Since(t) < 24*time.Hour
}

func (d *serverDeps) agentViews() []agentView {
	grants := d.grantViews()
	logs := d.dataStore.ListAuditLogs() // newest first
	agents := d.authServer.ListAgents()

	children := map[string][]string{}
	for _, a := range agents {
		if a.ParentAgentID != "" {
			children[a.ParentAgentID] = append(children[a.ParentAgentID], a.AgentID)
		}
	}
	// An OAuth client that has only ever been used to connect sub-agents is plumbing, not an agent:
	// the sub-agents it carries are listed under their parent instead.
	topLevelUse, subOnlyUse := map[string]bool{}, map[string]bool{}
	for _, c := range d.authServer.ListConsents() {
		if c.SubAgentName != "" {
			subOnlyUse[c.AgentID] = true
		} else {
			topLevelUse[c.AgentID] = true
		}
	}
	out := make([]agentView, 0, len(agents))
	for _, a := range agents {
		if subOnlyUse[a.AgentID] && !topLevelUse[a.AgentID] {
			continue
		}
		v := agentView{
			AgentID: a.AgentID, Name: firstNonEmpty(a.Name, a.AgentID), Kind: "agent", Status: "idle",
			OwnerUser: a.OwnerUser, ParentAgentID: a.ParentAgentID, Platform: a.PlatformFramework,
			RegisteredAt: a.RegisteredAt, Children: children[a.AgentID],
		}
		if v.Children == nil {
			v.Children = []string{}
		}
		if a.ParentAgentID != "" {
			v.Kind = "sub-agent"
		}
		for i := range grants {
			if grants[i].AgentID == a.AgentID && grants[i].Status == "active" {
				g := grants[i]
				v.ActiveGrant, v.Status = &g, "active"
				break
			}
		}
		if a.Status == "REVOKED" {
			v.Status = "revoked"
		}
		for _, e := range logs {
			if e.AgentID != a.AgentID {
				continue
			}
			if v.LastActivity == "" {
				v.LastActivity = e.Timestamp
			}
			if within24h(e.Timestamp) && isCall(e) {
				v.Calls24h++
				if isBlock(e) {
					v.Blocked24h++
				}
			}
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RegisteredAt > out[j].RegisteredAt })
	return out
}

func (d *serverDeps) pendingApprovals() []*auth.CIBARequest {
	now := time.Now().Unix()
	var out []*auth.CIBARequest
	for _, c := range d.authServer.ListCIBARequests() {
		if c.Status == "PENDING" && c.ExpiresAt > now {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	return out
}

func (d *serverDeps) consoleOverview(w http.ResponseWriter, r *http.Request) {
	agents := d.agentViews()
	var active, subs, revoked int
	for _, a := range agents {
		if a.Kind == "sub-agent" {
			subs++
		}
		switch a.Status {
		case "active":
			active++
		case "revoked":
			revoked++
		}
	}
	activeGrants := 0
	for _, g := range d.grantViews() {
		if g.Status == "active" {
			activeGrants++
		}
	}
	logs := d.dataStore.ListAuditLogs()
	counts := map[string]int{"allowed": 0, "approved": 0, "stepped_up": 0, "blocked": 0}
	reasons := map[string]int{}
	var recent []*store.AuditLogEntry
	for _, e := range logs {
		if len(recent) < 12 {
			recent = append(recent, e)
		}
		if !within24h(e.Timestamp) {
			continue
		}
		switch e.EventType {
		case "GATEWAY_ALLOW":
			counts["allowed"]++
		case "GATEWAY_STEP_UP_APPROVED":
			counts["approved"]++
		case "GATEWAY_STEP_UP_CIBA":
			counts["stepped_up"]++
		case "GATEWAY_BLOCK":
			counts["blocked"]++
			if e.PolicyRule != "" {
				reasons[strings.Split(e.PolicyRule, ":")[0]]++
			} else if len(e.Reasons) > 0 {
				reasons[strings.Split(e.Reasons[0], " ")[0]]++
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"agents":            map[string]int{"total": len(agents), "active": active, "sub_agents": subs, "revoked": revoked},
		"active_grants":     activeGrants,
		"pending_approvals": d.pendingApprovals(),
		"calls_24h":         counts,
		"top_block_reasons": reasons,
		"recent_activity":   recent,
	})
}

func (d *serverDeps) consoleAgents(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, d.agentViews())
}

func (d *serverDeps) consoleAgent(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	var view *agentView
	for _, a := range d.agentViews() {
		if a.AgentID == id {
			a := a
			view = &a
			break
		}
	}
	if view == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "agent not found"})
		return
	}
	var grants []grantView
	families := map[string]bool{}
	for _, g := range d.grantViews() {
		if g.AgentID == id {
			grants = append(grants, g)
			if g.FamilyID != "" {
				families[g.FamilyID] = true
			}
		}
	}
	var tokens []*auth.FamilyGraphSnapshot
	for f := range families {
		tokens = append(tokens, d.dag.GetSnapshot(f))
	}
	var activity []*store.AuditLogEntry
	for _, e := range d.dataStore.ListAuditLogs() {
		if e.AgentID == id && len(activity) < 100 {
			activity = append(activity, e)
		}
	}
	var subAgents []agentView
	for _, a := range d.agentViews() {
		if a.ParentAgentID == id {
			subAgents = append(subAgents, a)
		}
	}
	reg, _ := d.authServer.GetAgent(id)
	writeJSON(w, http.StatusOK, map[string]any{
		"agent":          view,
		"registration":   reg,
		"grants":         grants,
		"token_families": tokens,
		"sub_agents":     subAgents,
		"activity":       activity,
	})
}

func (d *serverDeps) consoleGrants(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, d.grantViews())
}

func (d *serverDeps) consoleApprovals(w http.ResponseWriter, r *http.Request) {
	out := d.pendingApprovals()
	if out == nil {
		out = []*auth.CIBARequest{}
	}
	writeJSON(w, http.StatusOK, out)
}

// consoleConnections proxies the MCP gateway's status so the UI needs only one API base URL.
func (d *serverDeps) consoleConnections(w http.ResponseWriter, r *http.Request) {
	gw := os.Getenv("GATEWAY_URL")
	if gw == "" {
		gw = strings.TrimSuffix(d.mcpResource, "/mcp")
	}
	hc := &http.Client{Timeout: 3 * time.Second}
	resp, err := hc.Get(gw + "/gateway/status")
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"online": false, "gateway_url": gw, "mcp_url": d.mcpResource, "error": "gateway not reachable"})
		return
	}
	defer resp.Body.Close()
	var status map[string]any
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&status); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"online": false, "gateway_url": gw, "error": err.Error()})
		return
	}
	status["online"] = true
	status["gateway_url"] = gw
	status["mcp_url"] = d.mcpResource
	writeJSON(w, http.StatusOK, status)
}
