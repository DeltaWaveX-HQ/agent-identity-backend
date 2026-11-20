package main

// Tenant isolation for the console API.
//
// Every console user belongs to one organization. Grants, approvals, delegations and audit
// entries carry the user who approved or triggered them, so a record belongs to the
// organization of that user. A console session only ever sees and acts on its own
// organization's records.
//
// Agents are different: one OAuth client can serve many tenants (Claude Code uses the same CIMD
// client_id for everybody). So "Revoke agent" from a tenant that shares the agent with others
// revokes only that tenant's grants; the agent itself is disabled globally only when no other
// tenant uses it.
//
// Platform-wide settings (the policy engine's rules, the egress allowlist, workspace reset) and
// the older demo endpoints are limited to platform admins: ADMIN_EMAILS (comma-separated). With
// ADMIN_EMAILS unset (local development) every signed-in user is an admin.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/buildathon2026/agent-identity-backend/internal/auth"
	"github.com/buildathon2026/agent-identity-backend/internal/store"
)

type tenant struct {
	orgID string
	email string
	admin bool
	orgOf map[string]string // user email -> org id
}

func normEmail(sub string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(sub)), "user:")
}

func adminEmails() map[string]bool {
	out := map[string]bool{}
	for _, e := range strings.Split(os.Getenv("ADMIN_EMAILS"), ",") {
		if e = normEmail(e); e != "" {
			out[e] = true
		}
	}
	return out
}

// tenantFor returns the caller's tenant, or nil for calls without a console session
// (the gateway, which is trusted with every tenant's records).
func (d *serverDeps) tenantFor(r *http.Request) *tenant {
	u := sessionUser(r)
	if u == nil {
		return nil
	}
	t := &tenant{orgID: u.OrgID, email: normEmail(u.Email), orgOf: map[string]string{}}
	for _, x := range d.dataStore.ListUsers() {
		t.orgOf[normEmail(x.Email)] = x.OrgID
	}
	admins := adminEmails()
	t.admin = len(admins) == 0 || admins[t.email]
	return t
}

// owns reports whether a record approved/triggered by userSub belongs to this tenant.
func (t *tenant) owns(userSub string) bool {
	if t == nil {
		return true
	}
	org, ok := t.orgOf[normEmail(userSub)]
	return ok && org == t.orgID
}

func (t *tenant) ownsAudit(e *store.AuditLogEntry) bool {
	if t == nil {
		return true
	}
	return (e.OrgID != "" && e.OrgID == t.orgID) || t.owns(e.ActorUser)
}

// Endpoints every signed-in tenant user may call (all tenant-scoped). Any other console
// endpoint is for platform admins only.
var tenantPaths = map[string]bool{
	"/api/v1/console/overview":         true,
	"/api/v1/console/agents":           true,
	"/api/v1/console/agent":            true,
	"/api/v1/console/grants":           true,
	"/api/v1/console/approvals":        true,
	"/api/v1/console/connections":      true,
	"/api/v1/console/hook-key":         true,
	"/api/v1/audit-logs":               true,
	"/api/v1/ciba":                     true,
	"/api/v1/oauth/ciba-resolve":       true,
	"/api/v1/consents/revoke":          true,
	"/api/v1/agents/revoke":            true,
	"/api/v1/agents/restore":           true,
	"/api/v1/events/stream":            true,
	"/api/v1/auth/me":                  true,
	"/api/v1/auth/logout":              true,
	"/api/v1/benchmark/incidents":      true,
	"/api/v1/datasets":                 true,
	"/api/v1/policies":                 true, // GET only (see below)
	"/api/v1/gateway/egress-allowlist": true, // GET only for tenants; the gateway and admins may POST
}

// tenancyMiddleware runs after authentication (sessionUser is set for console calls).
func (d *serverDeps) tenancyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t := d.tenantFor(r)
		if t == nil || !strings.HasPrefix(r.URL.Path, "/api/") || accessFor(r.URL.Path) == accessPublic {
			next.ServeHTTP(w, r)
			return
		}
		p := r.URL.Path
		readOnly := p == "/api/v1/policies" || p == "/api/v1/gateway/egress-allowlist"
		if !t.admin && (!tenantPaths[p] || (readOnly && r.Method != http.MethodGet)) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "Only platform admins can change this setting: it applies to every organization on this deployment."})
			return
		}

		switch p {
		case "/api/v1/ciba":
			var out []*auth.CIBARequest
			for _, c := range d.authServer.ListCIBARequests() {
				if t.owns(c.UserSub) {
					out = append(out, c)
				}
			}
			if out == nil {
				out = []*auth.CIBARequest{}
			}
			writeJSON(w, http.StatusOK, out)
			return
		case "/api/v1/audit-logs":
			if r.Method == http.MethodGet {
				out := []*store.AuditLogEntry{}
				for _, e := range d.dataStore.ListAuditLogs() {
					if t.ownsAudit(e) {
						out = append(out, e)
					}
				}
				writeJSON(w, http.StatusOK, out)
				return
			}
		}

		if r.Method != http.MethodPost {
			next.ServeHTTP(w, r)
			return
		}
		// Ownership checks on actions. Read the body once and hand it on unchanged.
		raw, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		r.Body = io.NopCloser(bytes.NewReader(raw))
		var body struct {
			AgentID   string `json:"agent_id"`
			ConsentID string `json:"consent_id"`
			AuthReqID string `json:"auth_req_id"`
			Reason    string `json:"reason"`
		}
		_ = json.Unmarshal(raw, &body)
		notFound := func(what string) { writeJSON(w, http.StatusNotFound, map[string]string{"error": what + " not found"}) }

		switch p {
		case "/api/v1/oauth/ciba-resolve":
			c, ok := d.authServer.GetCIBARequest(body.AuthReqID)
			if !ok || !t.owns(c.UserSub) {
				notFound("approval request " + body.AuthReqID)
				return
			}
		case "/api/v1/consents/revoke":
			if !d.tenantOwnsGrant(t, body.ConsentID) {
				notFound("grant " + body.ConsentID)
				return
			}
		case "/api/v1/agents/restore":
			mine, _ := d.agentUse(t, body.AgentID)
			if !mine {
				notFound("agent " + body.AgentID)
				return
			}
		case "/api/v1/agents/revoke":
			mine, shared := d.agentUse(t, body.AgentID)
			if !mine {
				notFound("agent " + body.AgentID)
				return
			}
			if shared {
				// Other organizations use this agent too: cut off only this tenant's access.
				n := d.revokeTenantGrants(t, body.AgentID, body.Reason)
				writeJSON(w, http.StatusOK, map[string]any{"agent_id": body.AgentID, "scope": "organization", "revoked_grants": n})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (d *serverDeps) tenantOwnsGrant(t *tenant, id string) bool {
	if strings.HasPrefix(id, "deleg_") {
		for _, dl := range d.authServer.ListDelegations() {
			if dl.ID == id {
				return t.owns(dl.UserSub)
			}
		}
		return false
	}
	c, ok := d.authServer.GetConsent(id)
	return ok && t.owns(c.UserSub)
}

// agentUse reports whether this tenant has anything to do with the agent, and whether another
// organization uses it too.
func (d *serverDeps) agentUse(t *tenant, agentID string) (mine, shared bool) {
	if agentID == "" {
		return false, false
	}
	seen := func(userSub string) {
		if userSub == "" || userSub == "pending-consent" {
			return
		}
		if t.owns(userSub) {
			mine = true
		} else {
			shared = true
		}
	}
	if a, ok := d.authServer.GetAgent(agentID); ok {
		seen(a.OwnerUser)
	}
	for _, c := range d.authServer.ListConsents() {
		if c.UserSub != "" && (c.AgentID == agentID || c.SubAgentID == agentID || c.ParentAgentID == agentID) {
			seen(c.UserSub)
		}
	}
	for _, dl := range d.authServer.ListDelegations() {
		if dl.SubAgentID == agentID || dl.ParentAgentID == agentID {
			seen(dl.UserSub)
		}
	}
	return mine, shared
}

// revokeTenantGrants revokes every grant and delegation this tenant gave the agent (and its
// sub-agents), leaving other organizations' access untouched.
func (d *serverDeps) revokeTenantGrants(t *tenant, agentID, reason string) int {
	n := 0
	for _, c := range d.authServer.ListConsents() {
		if c.Revoked || !t.owns(c.UserSub) {
			continue
		}
		if c.AgentID == agentID || c.SubAgentID == agentID || c.ParentAgentID == agentID {
			if _, _, err := d.authServer.RevokeConsent(c.ConsentID); err == nil {
				n++
			}
		}
	}
	for _, dl := range d.authServer.ListDelegations() {
		if (dl.SubAgentID == agentID || dl.ParentAgentID == agentID) && t.owns(dl.UserSub) && dl.Status != "revoked" {
			if _, ok := d.authServer.RevokeDelegation(dl.ID); ok {
				n++
			}
		}
	}
	d.dataStore.AppendAuditLog(store.AuditLogEntry{
		OrgID: t.orgID, ActorUser: t.email, AgentID: agentID, EventType: "AGENT_REVOKED",
		Method: "POST /api/v1/agents/revoke", Verdict: "block_and_revoke",
		Reasons: []string{firstNonEmpty(reason, "Revoked from tenant console") + " (this organization's access only; the agent is shared)"},
	})
	return n
}
