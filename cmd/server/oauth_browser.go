package main

// Real browser-based OAuth 2.1 authorization for off-the-shelf MCP clients
// (Claude Code, Claude Desktop, ChatGPT connectors, Gemini CLI, MCPJam, Cursor…).
//
// Flow: client hits the MCP gateway → 401 + resource metadata → discovers this server →
// registers (RFC 7591 DCR) or presents a client-ID metadata document URL (CIMD) →
// opens GET /oauth/authorize in the user's browser → the user signs in with their
// dashboard account, picks what the agent may do and for how long → redirect with code →
// client swaps code + PKCE verifier for a 5-minute token at /oauth/token.

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/buildathon2026/agent-identity-backend/internal/auth"
	"github.com/buildathon2026/agent-identity-backend/internal/crypto"
	"github.com/buildathon2026/agent-identity-backend/internal/events"
	"github.com/buildathon2026/agent-identity-backend/internal/risk"
	"github.com/buildathon2026/agent-identity-backend/internal/store"
)

// Permissions a user can grant on the consent screen, mapped to gateway action classes.
var grantableActions = []struct {
	Action, Label, Hint string
	Default             bool
}{
	{"read", "Read data", "list, search and read files, records and accounts", true},
	{"write", "Change data", "create or edit files and records", false},
	{"payment_transfer", "Move money", "initiate payments (each one still needs your approval)", false},
	{"export", "Send data out", "export reports to approved external destinations", false},
}

var consentTTLs = map[string]time.Duration{"1h": time.Hour, "8h": 8 * time.Hour, "24h": 24 * time.Hour}

// Sub-agents are short-lived by design: 5 minutes, 10 minutes or 1 hour, never beyond the parent.
var subAgentTTLs = map[string]time.Duration{"5m": 5 * time.Minute, "10m": 10 * time.Minute, "1h": time.Hour}

var subNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)

// subAgentName returns the sub-agent name when the requested resource is <gateway>/mcp/sub/<name>.
func (d *serverDeps) subAgentName(aud string) (string, bool) {
	name, ok := strings.CutPrefix(aud, d.mcpResource+"/sub/")
	if !ok || !subNameRe.MatchString(name) {
		return "", false
	}
	return name, true
}

func humanDuration(sec int64) string {
	switch {
	case sec <= 0:
		return "expired"
	case sec < 3600:
		return fmt.Sprintf("%dm left", (sec+59)/60)
	default:
		return fmt.Sprintf("%dh %dm left", sec/3600, (sec%3600)/60)
	}
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func clientSlug(name string) string {
	s := strings.Trim(slugRe.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if s == "" {
		s = "mcp-client"
	}
	return s
}

// isLoopback reports whether a redirect URI points at the user's own machine (RFC 8252 §7.3).
func isLoopback(u *url.URL) bool {
	h := u.Hostname()
	return u.Scheme == "http" && (h == "localhost" || h == "127.0.0.1" || h == "::1")
}

// redirectAllowed checks a redirect_uri against the client's registered ones. Loopback URIs may
// differ only by port, because native clients pick a free port at run time.
func redirectAllowed(agent *auth.RegisteredAgent, redirectURI string) bool {
	ru, err := url.Parse(redirectURI)
	if err != nil || ru.Scheme == "" {
		return false
	}
	if len(agent.RedirectURIs) == 0 {
		return isLoopback(ru)
	}
	for _, reg := range agent.RedirectURIs {
		if reg == redirectURI {
			return true
		}
		gu, err := url.Parse(reg)
		if err == nil && isLoopback(gu) && isLoopback(ru) && gu.Path == ru.Path {
			return true
		}
	}
	return false
}

// resolveCIMDClient fetches a Client ID Metadata Document when client_id is an https URL.
func (d *serverDeps) resolveCIMDClient(clientID string) (*auth.RegisteredAgent, error) {
	u, err := url.Parse(clientID)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("unknown client_id %q", clientID)
	}
	hc := &http.Client{Timeout: 5 * time.Second}
	resp, err := hc.Get(clientID)
	if err != nil {
		return nil, fmt.Errorf("could not fetch client metadata document: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client metadata document returned HTTP %d", resp.StatusCode)
	}
	var doc struct {
		ClientID     string   `json:"client_id"`
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("invalid client metadata document: %v", err)
	}
	if doc.ClientID != clientID {
		return nil, fmt.Errorf("client metadata document client_id mismatch")
	}
	name := doc.ClientName
	if name == "" {
		name = u.Host
	}
	return d.authServer.RegisterAgent(auth.RegisteredAgent{
		AgentID:           clientID,
		Name:              name + " (CIMD)",
		OwnerUser:         "pending-consent",
		SPIFFEID:          "spiffe://acme.in/ns/cimd/sa/" + clientSlug(u.Host),
		RuntimeAttested:   true,
		PlatformFramework: "MCP client · Client ID Metadata Document",
		ModelID:           "unknown (external MCP client)",
		RedirectURIs:      doc.RedirectURIs,
	})
}

func (d *serverDeps) oauthErrorPage(w http.ResponseWriter, status int, title, detail string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorization error</title>
<body style="font-family:-apple-system,system-ui,sans-serif;background:#f8fafc;color:#0f172a;display:grid;place-items:center;min-height:100vh;margin:0;padding:16px">
<div style="background:#fff;border:1px solid #e2e8f0;border-radius:14px;max-width:460px;padding:24px"><h1 style="font-size:18px;margin:0 0 8px">%s</h1><p style="color:#475569;font-size:14px;line-height:1.5;margin:0">%s</p></div></body>`,
		html.EscapeString(title), html.EscapeString(detail))
}

func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, desc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, desc, http.StatusBadRequest)
		return
	}
	q := u.Query()
	q.Set("error", code)
	q.Set("error_description", desc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// handleBrowserAuthorize serves GET /oauth/authorize?response_type=code&client_id=…&redirect_uri=…
func (d *serverDeps) handleBrowserAuthorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	clientID, redirectURI, state := q.Get("client_id"), q.Get("redirect_uri"), q.Get("state")

	agent, ok := d.authServer.GetAgent(clientID)
	if !ok {
		var err error
		if agent, err = d.resolveCIMDClient(clientID); err != nil {
			d.oauthErrorPage(w, http.StatusBadRequest, "Unknown agent", err.Error()+". The MCP client must register first (RFC 7591).")
			return
		}
	}
	if agent.Status == "REVOKED" {
		d.oauthErrorPage(w, http.StatusForbidden, "Agent revoked", agent.AgentID+" was revoked by an administrator. Restore it from the console before it can ask for access again.")
		return
	}
	if !redirectAllowed(agent, redirectURI) {
		// Never redirect to an unregistered URI: show the error here instead.
		d.oauthErrorPage(w, http.StatusBadRequest, "Redirect URI not registered", redirectURI+" is not registered for "+agent.AgentID+".")
		return
	}
	if q.Get("response_type") != "code" {
		redirectWithError(w, r, redirectURI, state, "unsupported_response_type", "only response_type=code is supported")
		return
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		redirectWithError(w, r, redirectURI, state, "invalid_request", "PKCE with code_challenge_method=S256 is required (OAuth 2.1)")
		return
	}
	aud := q.Get("resource")
	if aud == "" {
		aud = d.mcpResource
	}
	scope := q.Get("scope")
	if scope == "" {
		scope = "mcp:tools"
	}

	issuance := d.riskEngine.Decide(risk.ScoreRequest{
		Stage:          "issuance",
		AgentID:        agent.AgentID,
		RequestedScope: scope,
	})
	if issuance.Verdict == risk.VerdictBlockAndRevoke {
		redirectWithError(w, r, redirectURI, state, "access_denied", "issuance risk too high")
		return
	}

	rec := d.authServer.CreateConsentPrompt("", agent.AgentID, "Use tools behind the Agent Identity Gateway", scope, aud, q.Get("code_challenge"),
		[]crypto.AuthorizationDetail{{Type: "mcp_tool_execution", Locations: []string{aud}, DataResidency: "IN"}})
	rec.RedirectURI = redirectURI
	rec.State = state
	if name, ok := d.subAgentName(aud); ok {
		rec.SubAgentName = name
	} else if aud != d.mcpResource {
		redirectWithError(w, r, redirectURI, state, "invalid_target", "unknown resource "+aud)
		return
	}

	d.dataStore.AppendAuditLog(store.AuditLogEntry{
		ActorUser: "pending-login", AgentID: agent.AgentID, EventType: "OAUTH_AUTHORIZE_RAR", Method: "GET /oauth/authorize",
		Resource: aud, RiskScore: issuance.Score, Verdict: string(issuance.Verdict), Reasons: issuance.TopReasons, LatencyUs: issuance.LatencyUs,
	})
	d.hub.Publish(events.TelemetryEvent{
		StepNumber: 1, FromLane: "agent", ToLane: "user", FlowNode: "consent",
		Label:        "Consent screen opened (" + agent.AgentID + ")",
		Who:          agent.AgentID + " → user's browser",
		Headline:     agent.Name + " is asking for access",
		PlainText:    fmt.Sprintf("Consent screen opened in the user's browser for %s. Issuance risk %.2f.", aud, issuance.Score),
		UnderTheHood: "GET /oauth/authorize · PKCE S256 · consent_id=" + rec.ConsentID,
		Status:       "warn", StatusText: "Waiting for user", RiskDecision: issuance,
	})
	d.renderConsentPage(w, http.StatusOK, rec, agent, issuance.Score, "", "")
}

func (d *serverDeps) renderConsentPage(w http.ResponseWriter, status int, rec *auth.ConsentRecord, agent *auth.RegisteredAgent, issuanceScore float64, email, errMsg string) {
	ru, _ := url.Parse(rec.RedirectURI)
	redirectHost := rec.RedirectURI
	if ru != nil {
		redirectHost = ru.Host
	}
	isSub := rec.SubAgentName != ""
	title := agent.Name + " wants access"
	intro := "It will reach your tools only through the Agent Identity Gateway. Every call is checked; risky ones come to you for approval."
	ttlSelect := `<select name="ttl"><option value="1h" selected>1 hour</option><option value="8h">8 hours</option><option value="24h">24 hours</option></select>`

	var perms strings.Builder
	if isSub {
		title = "Sub-agent “" + rec.SubAgentName + "” wants delegated access"
		intro = "A sub-agent works on behalf of one of your agents. It gets a subset of that agent's permissions, for a short time, and is revoked automatically if the parent is."
		ttlSelect = `<select name="ttl"><option value="5m">5 minutes</option><option value="10m" selected>10 minutes</option><option value="1h">1 hour</option></select>`
		parents := d.authServer.ActiveParentGrants(d.mcpResource, "")
		perms.WriteString(`<fieldset><legend>Works under</legend>`)
		if len(parents) == 0 {
			perms.WriteString(`<div class="err">No parent agent has active access. Connect and approve a parent agent first (` + html.EscapeString(d.mcpResource) + `).</div>`)
		} else {
			perms.WriteString(`<select name="parent_consent_id" required>`)
			for _, pc := range parents {
				name := pc.AgentID
				if pa, ok := d.authServer.GetAgent(pc.AgentID); ok && pa.Name != "" {
					name = pa.Name
				}
				var acts []string
				for _, ad := range pc.AuthorizationDetails {
					acts = append(acts, ad.Actions...)
				}
				fmt.Fprintf(&perms, `<option value="%s">%s · %s · can %s · %s</option>`, html.EscapeString(pc.ConsentID), html.EscapeString(name),
					html.EscapeString(strings.TrimPrefix(pc.UserSub, "user:")), html.EscapeString(strings.Join(acts, ", ")), humanDuration(pc.ExpiresAt-time.Now().Unix()))
			}
			perms.WriteString(`</select><small class="hint">You can only delegate permissions the parent already has.</small>`)
		}
		perms.WriteString(`</fieldset><fieldset><legend>Allow this sub-agent to</legend>`)
	} else {
		perms.WriteString(`<fieldset><legend>Allow this agent to</legend>`)
	}
	for _, a := range grantableActions {
		if isSub && a.Action == "payment_transfer" {
			perms.WriteString(`<label class="perm off"><input type="checkbox" disabled><span><b>Move money</b><small>never allowed for sub-agents</small></span></label>`)
			continue
		}
		checked := ""
		if a.Default {
			checked = " checked"
		}
		fmt.Fprintf(&perms, `<label class="perm"><input type="checkbox" name="actions" value="%s"%s><span><b>%s</b><small>%s</small></span></label>`,
			a.Action, checked, html.EscapeString(a.Label), html.EscapeString(a.Hint))
	}
	errHTML := ""
	if errMsg != "" {
		errHTML = `<div class="err">` + html.EscapeString(errMsg) + `</div>`
	}
	noUsers := ""
	if len(d.dataStore.ListUsers()) == 0 {
		noUsers = `<div class="err">No accounts exist yet. Create one in the dashboard (http://localhost:3000) first, then retry.</div>`
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize agent</title>
<style>
:root{--bg:#f8fafc;--card:#fff;--ink:#0f172a;--muted:#64748b;--line:#e2e8f0;--soft:#f1f5f9;--accent:#1d4ed8;--ok:#047857;--bad:#be123c}
@media (prefers-color-scheme:dark){:root{--bg:#0b1220;--card:#111a2b;--ink:#e5ecf5;--muted:#93a3b6;--line:#243247;--soft:#16223a;--accent:#7d9bff;--ok:#34d399;--bad:#fb7185}}
*{box-sizing:border-box}body{font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:var(--bg);color:var(--ink);margin:0;padding:24px 16px;display:grid;place-items:center;min-height:100vh}
.card{background:var(--card);border:1px solid var(--line);border-radius:16px;max-width:480px;width:100%%;padding:24px}
.eyebrow{font:600 11px/1 ui-monospace,Menlo,monospace;letter-spacing:.08em;text-transform:uppercase;color:var(--accent)}
h1{font-size:20px;margin:8px 0 4px}p{color:var(--muted);margin:0 0 16px}
.meta{background:var(--soft);border-radius:10px;padding:10px 12px;font-size:12px;margin-bottom:16px}
.meta div{display:flex;justify-content:space-between;gap:12px;padding:3px 0}.meta span:first-child{color:var(--muted)}.meta span:last-child{font-family:ui-monospace,Menlo,monospace;text-align:right;word-break:break-all}
fieldset{border:0;padding:0;margin:0 0 16px}legend{font-weight:600;margin-bottom:8px}
.perm{display:flex;gap:10px;align-items:flex-start;padding:8px 0;border-top:1px solid var(--line);cursor:pointer}.perm b{display:block;font-weight:600}.perm small{color:var(--muted)}
.perm input{margin-top:4px}.never{color:var(--muted);font-size:12px;padding-top:8px;border-top:1px solid var(--line)}
input[type=email],input[type=password],select{width:100%%;padding:9px 10px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--ink);font:inherit;margin:4px 0 10px}
.btns{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-top:8px}button{font:600 14px/1 inherit;padding:12px;border-radius:10px;cursor:pointer;border:1px solid var(--line)}
.approve{background:var(--ok);color:#fff;border-color:var(--ok)}.deny{background:transparent;color:var(--bad)}
.perm.off{opacity:.55;cursor:default}.hint{display:block;color:var(--muted);font-size:12px;margin-top:-4px}
.err{background:color-mix(in srgb,var(--bad) 12%%,transparent);color:var(--bad);border-radius:8px;padding:8px 10px;margin-bottom:12px;font-size:13px}
</style></head><body><main class="card">
<span class="eyebrow">Agent Identity · authorization</span>
<h1>%s</h1>
<p>%s</p>
<div class="meta">
<div><span>Agent</span><span>%s</span></div>
<div><span>Returns to</span><span>%s</span></div>
<div><span>Gateway</span><span>%s</span></div>
<div><span>Issuance risk</span><span>%.2f</span></div>
</div>
%s%s
<form method="POST" action="/oauth/authorize/decision">
<input type="hidden" name="consent_id" value="%s">
<fieldset><legend>Sign in as</legend>
<input type="email" name="email" placeholder="you@company.in" value="%s" autocomplete="username" required>
<input type="password" name="password" placeholder="Dashboard password" autocomplete="current-password" required>
</fieldset>
%s
<div class="never">Never allowed: deleting data, sending data to unapproved hosts, changing monitoring.</div></fieldset>
<fieldset><legend>For how long</legend>
%s</fieldset>
<div class="btns"><button class="deny" type="submit" name="decision" value="deny" formnovalidate>Deny</button><button class="approve" type="submit" name="decision" value="approve">Approve</button></div>
</form></main></body></html>`,
		html.EscapeString(title), html.EscapeString(intro), html.EscapeString(agent.AgentID), html.EscapeString(redirectHost), html.EscapeString(rec.Aud),
		issuanceScore, noUsers, errHTML, html.EscapeString(rec.ConsentID), html.EscapeString(email), perms.String(), ttlSelect)
}

// handleBrowserDecision serves POST /oauth/authorize/decision from the consent page.
func (d *serverDeps) handleBrowserDecision(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	_ = r.ParseForm()
	rec, ok := d.authServer.GetConsent(r.FormValue("consent_id"))
	if !ok || rec.RedirectURI == "" {
		d.oauthErrorPage(w, http.StatusBadRequest, "Consent not found", "This authorization request is unknown or has expired. Start again from your AI client.")
		return
	}
	if rec.Approved || rec.Revoked {
		d.oauthErrorPage(w, http.StatusBadRequest, "Already decided", "This authorization request was already approved or denied.")
		return
	}
	agent, _ := d.authServer.GetAgent(rec.AgentID)
	if agent == nil {
		agent = &auth.RegisteredAgent{AgentID: rec.AgentID, Name: rec.AgentID}
	}

	if r.FormValue("decision") != "approve" {
		_, _, _ = d.authServer.RevokeConsent(rec.ConsentID)
		d.dataStore.AppendAuditLog(store.AuditLogEntry{ActorUser: "browser-user", AgentID: rec.AgentID, EventType: "OAUTH_CONSENT_DENIED", Method: "POST /oauth/authorize/decision", Resource: rec.Aud, Verdict: "deny"})
		d.hub.Publish(events.TelemetryEvent{FromLane: "user", ToLane: "as", FlowNode: "consent", Label: "Consent denied", Headline: "User denied " + rec.AgentID, Status: "bad", StatusText: "Denied"})
		redirectWithError(w, r, rec.RedirectURI, rec.State, "access_denied", "The user denied the request")
		return
	}

	email := strings.TrimSpace(r.FormValue("email"))
	user, _, _, ok := d.dataStore.Authenticate(email, r.FormValue("password"))
	if !ok {
		d.renderConsentPage(w, http.StatusUnauthorized, rec, agent, 0, email, "Wrong email or password.")
		return
	}
	var actions []string
	picked := map[string]bool{}
	for _, a := range r.Form["actions"] {
		picked[a] = true
	}
	for _, g := range grantableActions {
		if picked[g.Action] {
			actions = append(actions, g.Action)
		}
	}
	userSub := "user:" + strings.ToLower(user.Email)
	var approved *auth.ConsentRecord
	var ttl time.Duration
	var err error
	if rec.SubAgentName != "" {
		if ttl, ok = subAgentTTLs[r.FormValue("ttl")]; !ok {
			ttl = 10 * time.Minute
		}
		approved, err = d.authServer.ApproveSubAgentConsent(rec.ConsentID, userSub, r.FormValue("parent_consent_id"), actions, ttl)
	} else {
		if ttl, ok = consentTTLs[r.FormValue("ttl")]; !ok {
			ttl = time.Hour
		}
		approved, err = d.authServer.ApproveConsentAs(rec.ConsentID, userSub, actions, ttl)
	}
	if err != nil {
		d.renderConsentPage(w, http.StatusBadRequest, rec, agent, 0, email, err.Error())
		return
	}

	d.behavior.ClearDenials(rec.AgentID)
	d.dataStore.AppendAuditLog(store.AuditLogEntry{
		ActorUser: userSub, AgentID: rec.AgentID, EventType: "OAUTH_CONSENT_APPROVED", Method: "POST /oauth/authorize/decision",
		Resource: rec.Aud, Verdict: "allow", Reasons: append([]string{"ttl " + ttl.String()}, actions...), ParentAgent: approved.ParentAgentID,
	})
	d.hub.Publish(events.TelemetryEvent{
		StepNumber: 2, FromLane: "user", ToLane: "as", FlowNode: "consent",
		Label:     "Consent approved (" + rec.AgentID + ")",
		Who:       userSub + " → Auth server",
		Headline:  userSub + " approved " + agent.Name,
		PlainText: fmt.Sprintf("Allowed actions %v on %s for %s.", actions, rec.Aud, ttl),
		Status:    "ok", StatusText: "Consent given",
	})

	u, _ := url.Parse(rec.RedirectURI)
	qv := u.Query()
	qv.Set("code", approved.AuthCode)
	if rec.State != "" {
		qv.Set("state", rec.State)
	}
	u.RawQuery = qv.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
