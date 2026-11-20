package main

// Layer 2 → Layer 3 bridge for real MCP traffic.
//
// The MCP gateway (cmd/mcp-gateway) terminates MCP connections from Claude / ChatGPT / Gemini /
// MCPJam, authenticates them with the bearer token our authorization server issued, and calls
// POST /api/v1/gateway/mcp/decide before forwarding any tools/call to an upstream server.
// After the upstream answers it calls POST /api/v1/gateway/mcp/report so the risk engine can
// learn from what came back (e.g. a prompt injection inside a file the agent just read).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/buildathon2026/agent-identity-backend/internal/auth"
	"github.com/buildathon2026/agent-identity-backend/internal/crypto"
	"github.com/buildathon2026/agent-identity-backend/internal/events"
	"github.com/buildathon2026/agent-identity-backend/internal/risk"
	"github.com/buildathon2026/agent-identity-backend/internal/store"
)

type serverDeps struct {
	authServer  *auth.Server
	dag         *auth.FamilyDAG
	km          *crypto.KeyManager
	riskEngine  *risk.Engine
	behavior    *risk.BehaviorTracker
	dataStore   *store.DataStore
	hub         *events.Hub
	mcpResource string // default audience for browser OAuth flows (the MCP gateway's /mcp URL)
	issuerURL   string
}

// How long the gateway holds a tool call while waiting for a human (CIBA). Silence means no.
const cibaWait = 120 * time.Second

type mcpDecideRequest struct {
	AccessToken      string   `json:"access_token"`
	Resource         string   `json:"resource"`
	SessionID        string   `json:"mcp_session_id"`
	Upstream         string   `json:"upstream"`
	Tool             string   `json:"tool"`
	Action           string   `json:"action"`
	TargetHosts      []string `json:"target_hosts"`
	AmountINR        int      `json:"amount_inr"`
	BulkRead         bool     `json:"bulk_read"`
	ArgumentsPreview string   `json:"arguments_preview"`
	// SubAgent is set when the client told the gateway this call came from a sub-agent it spawned
	// (Claude Code reports it through its PreToolUse hook).
	SubAgent *struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Type   string `json:"type"`
		Source string `json:"source"` // mcp_meta | client_hook
	} `json:"sub_agent,omitempty"`
}

type mcpDecideResponse struct {
	Allowed       bool         `json:"allowed"`
	Verdict       string       `json:"verdict"`
	Status        int          `json:"status"`
	Score         float64      `json:"score"`
	Reasons       []string     `json:"reasons,omitempty"`
	HardRule      string       `json:"hard_rule,omitempty"`
	Message       string       `json:"message"`
	CIBAAuthReqID string       `json:"ciba_auth_req_id,omitempty"`
	ClientID      string       `json:"client_id,omitempty"`
	UserSub       string       `json:"user_sub,omitempty"`
	FamilyID      string       `json:"family_id,omitempty"`
	Signals       risk.Signals `json:"signals"`
	LatencyUs     int64        `json:"latency_us"`
}

func registerMCPEnforcement(mux *http.ServeMux, d *serverDeps) {
	mux.HandleFunc("/api/v1/gateway/mcp/decide", d.handleMCPDecide)
	mux.HandleFunc("/api/v1/gateway/mcp/report", d.handleMCPReport)

	// Egress allowlist: the MCP gateway registers the hosts its tenant config allows.
	mux.HandleFunc("/api/v1/gateway/egress-allowlist", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var body struct {
				Hosts []string `json:"hosts"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			for _, h := range body.Hosts {
				d.riskEngine.AllowHost(h)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"hosts": d.riskEngine.AllowedHostList()})
	})
}

func (d *serverDeps) handleMCPDecide(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	var req mcpDecideRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	deny := func(status int, verdict, msg string) {
		writeJSON(w, http.StatusOK, mcpDecideResponse{Allowed: false, Verdict: verdict, Status: status, Message: msg, LatencyUs: time.Since(start).Microseconds()})
	}

	// 1. Token: signature, expiry, revocation, audience, agent status.
	priv, _ := d.km.ActiveSigner()
	_, claims, err := crypto.VerifyAccessToken(&priv.PublicKey, req.AccessToken)
	if err != nil {
		deny(401, "invalid_token", "Access token rejected: "+err.Error())
		return
	}
	if revoked, cause := d.dag.IsRevoked(claims.JTI); revoked {
		deny(401, "invalid_token", "Access token revoked: "+cause)
		return
	}
	if req.Resource != "" && claims.Aud != req.Resource {
		deny(401, "invalid_token", fmt.Sprintf("Token audience %q does not match this gateway (%q)", claims.Aud, req.Resource))
		return
	}
	if d.authServer.IsAgentRevoked(claims.ClientID) {
		deny(403, string(risk.VerdictBlockAndRevoke), "Agent "+claims.ClientID+" was revoked by an administrator (kill switch)")
		return
	}

	// 1b. A sub-agent the client spawned on its own: it acts on the parent's session, but only with
	// what a human delegated to it, for a short time. The first call asks the human.
	parentClaims := claims
	elevKey := claims.FamilyID
	var deleg *auth.Delegation
	if claims.Act != nil {
		// A sub-agent token (from token exchange): its delegation must still be active.
		if dl, ok := d.authServer.GetDelegation(claims.ClientID); ok {
			if st := d.authServer.DelegationStatus(dl); st != "active" {
				deny(401, "invalid_token", "Sub-agent access is "+st+". Exchange a new token after the user approves again.")
				return
			}
			deleg = dl
			elevKey = "deleg:" + dl.SubAgentID
		}
	} else if req.SubAgent != nil && (req.SubAgent.ID != "" || req.SubAgent.Name != "") {
		var why string
		if deleg, why = d.delegate(r, claims, subAgentRequest{
			Name: req.SubAgent.Name, InstanceID: req.SubAgent.ID, Type: req.SubAgent.Type, Source: firstNonEmpty(req.SubAgent.Source, "client_hook"),
			Action: req.Action, Tool: req.Tool, ArgsPreview: req.ArgumentsPreview,
		}); deleg == nil {
			deny(403, "sub_agent_not_authorized", why)
			return
		}
		eff := *claims
		eff.ClientID = deleg.SubAgentID
		eff.Act = &crypto.ActorClaim{Sub: parentClaims.ClientID, Act: &crypto.ActorClaim{Sub: parentClaims.Sub}}
		eff.AuthorizationDetails = []crypto.AuthorizationDetail{{Type: "delegated_by_parent", Locations: []string{parentClaims.Aud}, Actions: deleg.Actions}}
		claims = &eff
		elevKey = "deleg:" + deleg.SubAgentID
	}

	// 2. Signals the gateway derives itself.
	targetHost := ""
	for _, h := range req.TargetHosts {
		if targetHost == "" {
			targetHost = h
		}
		if !d.riskEngine.IsHostAllowed(h) {
			targetHost = h // the riskiest destination drives the decision
			break
		}
	}
	sig := d.behavior.Observe(claims.FamilyID, claims.ClientID, req.Tool, req.Action, targetHost)

	var consented []string
	for _, ad := range claims.AuthorizationDetails {
		consented = append(consented, ad.Actions...)
	}
	granted := append([]string(nil), consented...)
	elevated := d.authServer.ActiveElevations(elevKey)
	for a := range elevated {
		consented = append(consented, a) // human-approved, time-boxed extra permission
	}
	depth := 0
	if claims.Act != nil {
		depth = 1
	}
	dpopBound := claims.CNF != nil && claims.CNF["jkt"] != ""

	decision := d.riskEngine.Decide(risk.ScoreRequest{
		Stage:             "runtime",
		AgentID:           claims.ClientID,
		UserSub:           claims.Sub,
		HasAgentToken:     true,
		HasDPoPProof:      dpopBound,
		DelegationDepth:   depth,
		UntrustedContext:  sig.UntrustedContext,
		RequestedScope:    claims.Scope,
		ConsentedActions:  consented,
		Action:            req.Action,
		TargetResource:    "mcp://" + req.Upstream + "/" + req.Tool,
		TargetHost:        targetHost,
		DeniedThenRetried: sig.DeniedThenRetried,
		ActionsPerMinute:  sig.ActionsPerMinute,
		AmountINR:         req.AmountINR,
		NewDestination:    sig.NewDestination,
		BulkRead:          req.BulkRead,
	})
	if sig.UntrustedContext && sig.TaintReason != "" {
		decision.TopReasons = append(decision.TopReasons, "context tainted by: "+sig.TaintReason)
	}
	if decision.HardRuleHit != "" {
		d.dataStore.IncrementRuleHit(strings.Split(decision.HardRuleHit, ":")[0])
	}

	resp := mcpDecideResponse{
		Verdict:  string(decision.Verdict),
		Score:    decision.Score,
		Reasons:  decision.TopReasons,
		HardRule: decision.HardRuleHit,
		ClientID: claims.ClientID,
		UserSub:  claims.Sub,
		FamilyID: claims.FamilyID,
		Signals:  sig,
	}
	resource := "mcp://" + req.Upstream + "/" + req.Tool

	switch decision.Verdict {
	case risk.VerdictAllow:
		resp.Allowed, resp.Status = true, 200
		resp.Message = "Allowed by policy and runtime risk model"
		d.logMCP(claims, req, decision, "GATEWAY_ALLOW", "ok", "ALLOWED", targetHost, start, nil)

	case risk.VerdictStepUpCIBA:
		ciba := d.authServer.CreateCIBARequest(claims.ClientID, claims.Sub, req.Action, resource, decision.Score, decision.TopReasons)
		resp.CIBAAuthReqID = ciba.AuthReqID
		d.annotateApproval(ciba.AuthReqID, claims, parentClaims, deleg, elevKey, req, granted, consented)
		d.logMCP(claims, req, decision, "GATEWAY_STEP_UP_CIBA", "warn", "WAITING FOR HUMAN", targetHost, start, &events.PhonePrompt{
			PromptID:          ciba.AuthReqID,
			Type:              "ciba_step_up",
			Title:             "Agent needs your approval",
			User:              claims.Sub,
			AgentID:           claims.ClientID,
			TaskDescription:   fmt.Sprintf("%s wants to run %s %s", claims.ClientID, req.Tool, truncate(req.ArgumentsPreview, 160)),
			RequestedResource: resource,
			RequestedActions:  []string{req.Action},
			TTLDisplay:        "2 minutes, then denied",
			RiskScore:         decision.Score,
			RiskReasons:       decision.TopReasons,
			ExpiresInSeconds:  int(cibaWait.Seconds()),
		})

		outcome := "EXPIRED"
		select {
		case outcome = <-ciba.ResolvedCh:
		case <-time.After(cibaWait):
			d.authServer.ExpireCIBARequest(ciba.AuthReqID)
		case <-r.Context().Done():
			d.authServer.ExpireCIBARequest(ciba.AuthReqID)
		}
		d.hub.Publish(events.TelemetryEvent{FromLane: "user", ToLane: "gw", Label: "Step-up " + outcome, PhonePrompt: &events.PhonePrompt{Type: "dismiss"},
			Headline: fmt.Sprintf("Human step-up %s for %s", strings.ToLower(outcome), req.Tool), FlowNode: "runtime",
			Status: map[bool]string{true: "ok", false: "bad"}[outcome == "APPROVED"], StatusText: outcome})

		if outcome == "APPROVED" {
			resp.Allowed, resp.Status = true, 200
			resp.Message = "Approved by " + claims.Sub + " (CIBA step-up)"
			if r, ok := d.authServer.GetCIBARequest(ciba.AuthReqID); ok && r.ElevatedUntil > 0 {
				resp.Message += fmt.Sprintf("; %q allowed until %s", req.Action, time.Unix(r.ElevatedUntil, 0).Format("15:04"))
			}
			d.audit(claims, req, decision, "GATEWAY_STEP_UP_APPROVED", "allow", targetHost, start)
		} else {
			resp.Status = 403
			resp.Message = "Step-up approval " + strings.ToLower(outcome) + "; action not performed"
			d.behavior.RecordDenial(claims.ClientID, req.Tool, req.Action)
			d.audit(claims, req, decision, "GATEWAY_STEP_UP_"+outcome, "deny", targetHost, start)
		}

	default: // block & revoke
		if deleg != nil {
			// Only the sub-agent loses its access; the parent keeps working.
			d.authServer.RevokeDelegation(deleg.SubAgentID)
			if parentClaims.Act != nil { // the caller holds its own sub-agent token: kill that family only
				d.dag.RevokeFamily(parentClaims.FamilyID, "Sub-agent blocked on "+req.Tool)
			}
			d.behavior.RecordDenial(claims.ClientID, req.Tool, req.Action)
			resp.Status = 403
			resp.Message = "Blocked. This sub-agent's delegated access was revoked; its parent agent keeps its own access."
			d.logMCP(claims, req, decision, "GATEWAY_BLOCK", "bad", "SUB-AGENT BLOCKED", targetHost, start, nil)
			break
		}
		snap := d.dag.RevokeFamily(claims.FamilyID, fmt.Sprintf("Runtime risk %.2f on %s (%s)", decision.Score, req.Tool, firstNonEmpty(decision.HardRuleHit, "score ≥ 0.75")))
		d.behavior.RecordDenial(claims.ClientID, req.Tool, req.Action)
		resp.Status = 403
		resp.Message = "Blocked. The agent's whole token family was revoked; it must ask the user again."
		d.logMCP(claims, req, decision, "GATEWAY_BLOCK", "bad", "BLOCKED + REVOKED", targetHost, start, nil, snap)
	}

	resp.LatencyUs = time.Since(start).Microseconds()
	writeJSON(w, http.StatusOK, resp)
}

type mcpReportRequest struct {
	AccessToken      string   `json:"access_token"`
	Upstream         string   `json:"upstream"`
	Tool             string   `json:"tool"`
	IsError          bool     `json:"is_error"`
	Bytes            int      `json:"bytes"`
	LatencyMs        int64    `json:"latency_ms"`
	InjectionMarkers []string `json:"injection_markers"`
	UntrustedSource  bool     `json:"untrusted_source"`
}

func (d *serverDeps) handleMCPReport(w http.ResponseWriter, r *http.Request) {
	var req mcpReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	priv, _ := d.km.ActiveSigner()
	_, claims, err := crypto.VerifyAccessToken(&priv.PublicKey, req.AccessToken)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
		return
	}
	resource := "mcp://" + req.Upstream + "/" + req.Tool
	status, statusText := "ok", fmt.Sprintf("%d bytes in %d ms", req.Bytes, req.LatencyMs)
	if req.IsError {
		status, statusText = "warn", "upstream returned an error"
	}
	d.hub.Publish(events.TelemetryEvent{
		FromLane: "res", ToLane: "agent", FlowNode: "allow",
		Label:      "Result: " + req.Tool,
		Who:        req.Upstream + " → Gateway → " + claims.ClientID,
		Headline:   fmt.Sprintf("Upstream %s answered %s", req.Upstream, req.Tool),
		PlainText:  fmt.Sprintf("%s returned %d bytes to %s (acting for %s).", resource, req.Bytes, claims.ClientID, claims.Sub),
		Status:     status,
		StatusText: statusText,
		LatencyUs:  req.LatencyMs * 1000,
	})

	tainted := len(req.InjectionMarkers) > 0 || req.UntrustedSource
	if tainted {
		why := "untrusted internet content from " + resource
		if len(req.InjectionMarkers) > 0 {
			why = fmt.Sprintf("possible prompt injection in %s (%s)", resource, strings.Join(req.InjectionMarkers, ", "))
		}
		d.behavior.Taint(claims.FamilyID, why)
		d.dataStore.AppendAuditLog(store.AuditLogEntry{
			ActorUser: claims.Sub, AgentID: claims.ClientID, EventType: "UNTRUSTED_CONTENT_IN_CONTEXT",
			Method: "MCP tools/call result", Resource: resource, RiskScore: 0.34, Verdict: "taint",
			Reasons: req.InjectionMarkers, TokenJTI: claims.JTI, FamilyID: claims.FamilyID,
		})
		d.hub.Publish(events.TelemetryEvent{
			FromLane: "res", ToLane: "risk", FlowNode: "runtime",
			Label:        "Context tainted: " + req.Tool,
			Who:          "Gateway → Risk engine",
			Headline:     "Untrusted content entered the agent's context",
			PlainText:    why + ". Later risky actions from this run will score higher.",
			UnderTheHood: "POST /api/v1/gateway/mcp/report · family " + claims.FamilyID,
			Status:       "warn",
			StatusText:   "TAINTED",
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"tainted": tainted, "family_id": claims.FamilyID})
}

func (d *serverDeps) audit(c *crypto.AgentAccessTokenClaims, req mcpDecideRequest, dec risk.RiskDecision, evType, verdict, host string, start time.Time) {
	d.dataStore.AppendAuditLog(store.AuditLogEntry{
		ActorUser:  c.Sub,
		AgentID:    c.ClientID,
		EventType:  evType,
		Method:     "MCP tools/call " + req.Tool,
		Resource:   "mcp://" + req.Upstream + "/" + req.Tool,
		TargetHost: host,
		RiskScore:  dec.Score,
		Verdict:    verdict,
		PolicyRule: dec.HardRuleHit,
		Reasons:    dec.TopReasons,
		TokenJTI:   c.JTI,
		FamilyID:   c.FamilyID,
		LatencyUs:  time.Since(start).Microseconds(),
	})
}

func (d *serverDeps) logMCP(c *crypto.AgentAccessTokenClaims, req mcpDecideRequest, dec risk.RiskDecision, evType, status, statusText, host string, start time.Time, prompt *events.PhonePrompt, snap ...*auth.FamilyGraphSnapshot) {
	d.audit(c, req, dec, evType, string(dec.Verdict), host, start)
	var fam any
	if len(snap) > 0 && snap[0] != nil {
		fam = snap[0]
	}
	target := "mcp://" + req.Upstream + "/" + req.Tool
	if host != "" {
		target += " → " + host
	}
	d.hub.Publish(events.TelemetryEvent{
		StepNumber:   3,
		FromLane:     "agent",
		ToLane:       "gw",
		Label:        fmt.Sprintf("%s (%s)", req.Tool, dec.Verdict),
		Who:          fmt.Sprintf("%s → Gateway → %s", c.ClientID, req.Upstream),
		Headline:     fmt.Sprintf("%s called %s", c.ClientID, req.Tool),
		PlainText:    fmt.Sprintf("Agent '%s' acting for %s called %s (action: %s). Verdict: %s, risk %.2f.", c.ClientID, c.Sub, target, req.Action, dec.Verdict, dec.Score),
		UnderTheHood: fmt.Sprintf("POST /api/v1/gateway/mcp/decide · args %s · jti=%s", truncate(req.ArgumentsPreview, 200), c.JTI),
		FlowNode:     "runtime",
		Status:       status,
		StatusText:   statusText,
		LatencyUs:    time.Since(start).Microseconds(),
		TokenClaims:  c,
		RiskDecision: dec,
		FamilyGraph:  fam,
		PhonePrompt:  prompt,
	})
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// annotateApproval tells the approver who is asking (agent or sub-agent and its parent), what it
// may do today, and whether this action can be granted for a limited time instead of just once.
func (d *serverDeps) annotateApproval(id string, c, parent *crypto.AgentAccessTokenClaims, deleg *auth.Delegation, elevKey string, req mcpDecideRequest, granted, consented []string) {
	grantExp := int64(0)
	if deleg != nil {
		grantExp = deleg.ExpiresAt
	} else if rec, ok := d.authServer.ConsentByFamily(c.FamilyID); ok {
		grantExp = rec.ExpiresAt
	}
	inConsent := false
	for _, a := range consented {
		if a == req.Action {
			inConsent = true
		}
	}
	// Elevation only makes sense for actions outside the grant. Money and deletes always need a
	// human per call; a sub-agent can never get more than its parent was granted.
	canElevate := !inConsent && req.Action != "payment_transfer" && req.Action != "delete"
	parentAgent := ""
	if c.Act != nil {
		parentAgent = c.Act.Sub
	}
	parentActions, isSub := d.authServer.ParentGrantedActions(c.FamilyID)
	if deleg != nil {
		parentActions, isSub = deleg.ParentActions, true
	}
	if isSub {
		has := false
		for _, a := range parentActions {
			if a == req.Action {
				has = true
			}
		}
		canElevate = canElevate && has
	}
	maxSec := grantExp - time.Now().Unix()
	if maxSec <= 0 {
		canElevate = false
	}
	d.authServer.AnnotateCIBA(id, func(r *auth.CIBARequest) {
		r.Tool, r.ArgsPreview, r.FamilyID, r.ParentAgentID = req.Tool, truncate(req.ArgumentsPreview, 300), elevKey, parentAgent
		r.GrantedActions, r.GrantExpiresAt = granted, grantExp
		r.CanElevate, r.MaxElevateSeconds = canElevate, maxSec
	})
}

var subSlugRe = regexp.MustCompile(`[^a-z0-9]+`)

func subSlug(v string) string {
	return strings.Trim(subSlugRe.ReplaceAllString(strings.ToLower(v), "-"), "-")
}

// subAgentRequest is how any client says "this is a sub-agent of the agent holding this token".
// It can arrive four ways, all ending in the same delegation:
//   - RFC 8693 token exchange (any OAuth-capable framework: ADK, OpenAI Agents SDK, LangGraph…)
//   - an MCP `_meta` tag on a tools/call made over the parent's connection (any MCP client/SDK)
//   - a client adapter such as Claude Code's PreToolUse hook (closed clients)
//   - the parent connecting a named sub-agent endpoint (/mcp/sub/<name>, consent-based)
type subAgentRequest struct {
	Name             string // stable name chosen by the parent ("researcher")
	InstanceID       string // per-spawn id from the client (Claude agent_id); used when there is no name
	Type             string // kind of sub-agent ("general-purpose", "Explore", "summariser")
	Source           string // token_exchange | mcp_meta | client_hook
	Action, Tool     string // the first thing it tries (for the approval card)
	ArgsPreview      string
	RequestedActions []string // what the parent asked to delegate (token exchange)
	RequestedSeconds int64
}

func (sr subAgentRequest) identity(parentID string) (subID, display string) {
	typ := strings.TrimSpace(sr.Type)
	if sr.Name != "" {
		n := subSlug(sr.Name)
		if typ == "" {
			typ = n
		}
		return parentID + "/" + n, n
	}
	if typ == "" {
		typ = "sub-agent"
	}
	short := subSlugRe.ReplaceAllString(strings.ToLower(sr.InstanceID), "")
	if len(short) > 6 {
		short = short[len(short)-6:]
	}
	return parentID + "/" + subSlug(typ) + "-" + short, typ + " #" + short
}

// delegate returns the active delegation for a sub-agent, asking the human (and holding the
// request up to two minutes) the first time that sub-agent shows up or after its time ran out.
func (d *serverDeps) delegate(r *http.Request, parent *crypto.AgentAccessTokenClaims, sr subAgentRequest) (*auth.Delegation, string) {
	if parent.Act != nil {
		return nil, "A sub-agent cannot create its own sub-agents (one level of delegation)."
	}
	subID, display := sr.identity(parent.ClientID)
	typ := strings.TrimSpace(sr.Type)
	if typ == "" {
		typ = display
	}
	if d.authServer.IsAgentRevoked(subID) {
		return nil, "This sub-agent was revoked by an administrator."
	}
	if dl, ok := d.authServer.GetDelegation(subID); ok {
		switch d.authServer.DelegationStatus(dl) {
		case "active":
			return dl, ""
		case "revoked":
			return nil, "This sub-agent's access was revoked. Use a new sub-agent to ask again."
		case "denied":
			if time.Now().Unix()-dl.CreatedAt < 60 {
				return nil, "The user did not approve this sub-agent."
			}
		case "pending":
			return nil, "This sub-agent is already waiting for approval."
		}
		// expired, or denied more than a minute ago: ask again below
	}

	parentExp, parentConsent := int64(0), ""
	if rec, ok := d.authServer.ConsentByFamily(parent.FamilyID); ok {
		parentExp, parentConsent = rec.ExpiresAt, rec.ConsentID
	}
	var parentActions, offer []string
	for _, ad := range parent.AuthorizationDetails {
		for _, a := range ad.Actions {
			parentActions = append(parentActions, a)
			if a != "payment_transfer" { // sub-agents never move money
				offer = append(offer, a)
			}
		}
	}
	maxSec := parentExp - time.Now().Unix()
	if maxSec > 3600 {
		maxSec = 3600
	}
	if len(offer) == 0 || maxSec <= 0 {
		return nil, "The parent agent has nothing it can delegate right now."
	}

	resource := "mcp://gateway/" + sr.Tool
	reasons := []string{"new sub-agent of " + parent.ClientID + " (via " + sr.Source + ")"}
	ciba := d.authServer.CreateCIBARequest(subID, parent.Sub, sr.Action, resource, 0, reasons)
	d.authServer.AnnotateCIBA(ciba.AuthReqID, func(c *auth.CIBARequest) {
		c.Kind, c.SubAgentType = "sub_agent", display
		c.OfferActions, c.OfferMaxSeconds = offer, maxSec
		c.Tool, c.ArgsPreview = sr.Tool, truncate(sr.ArgsPreview, 300)
		c.ParentAgentID, c.FamilyID = parent.ClientID, parent.FamilyID
		c.GrantedActions, c.GrantExpiresAt = parentActions, parentExp
		c.RequestedActions, c.RequestedSeconds, c.Source = sr.RequestedActions, sr.RequestedSeconds, sr.Source
	})
	dl := &auth.Delegation{
		ID: "deleg_" + ciba.AuthReqID, SubAgentID: subID, SubAgentType: typ, ClientAgentID: sr.InstanceID,
		ParentAgentID: parent.ClientID, ParentFamilyID: parent.FamilyID, ParentConsentID: parentConsent,
		ParentActions: parentActions, UserSub: parent.Sub, Status: "pending", CreatedAt: time.Now().Unix(),
		RequestID: ciba.AuthReqID, Source: sr.Source,
	}
	d.authServer.PutDelegation(dl)
	d.dataStore.AppendAuditLog(store.AuditLogEntry{
		ActorUser: parent.Sub, AgentID: subID, ParentAgent: parent.ClientID, EventType: "SUB_AGENT_DETECTED",
		Method: sr.Source, Resource: firstNonEmpty(sr.Tool, "token exchange"), Verdict: "pending", FamilyID: parent.FamilyID,
		Reasons: []string{"spawned by " + parent.ClientID + " as " + display},
	})
	d.hub.Publish(events.TelemetryEvent{
		FromLane: "agent", ToLane: "user", FlowNode: "exchange", Status: "warn", StatusText: "WAITING FOR HUMAN",
		Label:     "New sub-agent: " + display,
		Who:       parent.ClientID + " → " + subID,
		Headline:  parent.ClientID + " created a sub-agent (" + display + ")",
		PlainText: fmt.Sprintf("Sub-agent %s asks for delegated access (via %s). Waiting for the user.", subID, sr.Source),
	})

	outcome := "EXPIRED"
	select {
	case outcome = <-ciba.ResolvedCh:
	case <-time.After(cibaWait):
		d.authServer.ExpireCIBARequest(ciba.AuthReqID)
	case <-r.Context().Done():
		d.authServer.ExpireCIBARequest(ciba.AuthReqID)
	}
	if outcome != "APPROVED" {
		dl.Status = "denied"
		d.authServer.PutDelegation(dl)
		d.dataStore.AppendAuditLog(store.AuditLogEntry{ActorUser: parent.Sub, AgentID: subID, ParentAgent: parent.ClientID, EventType: "SUB_AGENT_" + outcome, Resource: sr.Source, Verdict: "deny"})
		return nil, "The user did not approve this sub-agent (" + strings.ToLower(outcome) + ")."
	}
	approved, _ := d.authServer.GetCIBARequest(ciba.AuthReqID)
	parentName := parent.ClientID
	if pa, ok := d.authServer.GetAgent(parent.ClientID); ok && pa.Name != "" {
		parentName = pa.Name
	}
	_, _ = d.authServer.RegisterAgent(auth.RegisteredAgent{
		AgentID: subID, Name: display, OwnerUser: parent.Sub, ParentAgentID: parent.ClientID,
		SPIFFEID: "spiffe://acme.in/ns/sub-agents/sa/" + subSlug(display), RuntimeAttested: true,
		PlatformFramework: "Sub-agent of " + parentName + " (" + sr.Source + ")",
	})
	dl.Actions, dl.Status = approved.ChosenActions, "active"
	dl.ExpiresAt = time.Now().Unix() + approved.ChosenSeconds
	d.authServer.PutDelegation(dl)
	d.dataStore.AppendAuditLog(store.AuditLogEntry{
		ActorUser: parent.Sub, AgentID: subID, ParentAgent: parent.ClientID, EventType: "SUB_AGENT_DELEGATED",
		Resource: sr.Source, Verdict: "allow", FamilyID: parent.FamilyID,
		Reasons: append([]string{fmt.Sprintf("for %d min", approved.ChosenSeconds/60)}, approved.ChosenActions...),
	})
	return dl, ""
}

// exchangeForSubAgent implements RFC 8693 token exchange for sub-agents created by any agent
// framework. The parent presents its own access token and names the sub-agent; the user approves
// the delegation in the console (once), and the sub-agent gets its own short-lived token.
//
//	POST /oauth/token
//	grant_type=urn:ietf:params:oauth:grant-type:token-exchange
//	subject_token=<parent access token>&subject_token_type=urn:ietf:params:oauth:token-type:access_token
//	sub_agent=researcher&sub_agent_type=summariser&scope=read write&requested_ttl=600
func (d *serverDeps) exchangeForSubAgent(w http.ResponseWriter, r *http.Request, subjectToken, clientID, name, typ, scope, resource string, ttl int64) {
	oauthErr := func(status int, code, desc string) {
		writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
	}
	priv, _ := d.km.ActiveSigner()
	_, parent, err := crypto.VerifyAccessToken(&priv.PublicKey, subjectToken)
	if err != nil {
		oauthErr(400, "invalid_grant", "subject_token: "+err.Error())
		return
	}
	if revoked, cause := d.dag.IsRevoked(parent.JTI); revoked {
		oauthErr(400, "invalid_grant", "subject_token revoked: "+cause)
		return
	}
	if d.authServer.IsAgentRevoked(parent.ClientID) {
		oauthErr(400, "invalid_grant", "parent agent revoked by administrator")
		return
	}
	if clientID != "" && clientID != parent.ClientID {
		if rec, ok := d.authServer.ConsentByFamily(parent.FamilyID); !ok || rec.AgentID != clientID {
			oauthErr(400, "invalid_client", "subject_token was not issued to this client")
			return
		}
	}
	if resource == "" {
		resource = parent.Aud
	}
	if resource != parent.Aud {
		oauthErr(400, "invalid_target", "a sub-agent can only be delegated to its parent's resource ("+parent.Aud+")")
		return
	}
	if !subNameRe.MatchString(subSlug(name)) {
		oauthErr(400, "invalid_request", "sub_agent must be a short name (letters, digits, dashes)")
		return
	}
	var requested []string
	for _, a := range strings.Fields(scope) {
		if _, ok := map[string]bool{"read": true, "write": true, "export": true, "payment_transfer": true}[a]; ok {
			requested = append(requested, a)
		}
	}
	first := "read"
	if len(requested) > 0 {
		first = requested[0]
	}
	dl, why := d.delegate(r, parent, subAgentRequest{
		Name: name, Type: typ, Source: "token_exchange", Action: first,
		RequestedActions: requested, RequestedSeconds: ttl,
	})
	if dl == nil {
		oauthErr(403, "access_denied", why)
		return
	}
	jkt := ""
	if h := r.Header.Get("DPoP"); h != "" {
		if pub, _, err := crypto.VerifyDPoPProof(h, "POST", d.issuerURL+"/oauth/token", "", ""); err == nil && pub != nil {
			jkt = crypto.ComputeJWKThumbprint(*pub)
		}
	}
	tok, claims, err := d.authServer.IssueDelegatedToken(parent, dl, resource, jkt)
	if err != nil {
		oauthErr(400, "invalid_grant", err.Error())
		return
	}
	d.dataStore.AppendAuditLog(store.AuditLogEntry{
		ActorUser: parent.Sub, AgentID: dl.SubAgentID, ParentAgent: parent.ClientID, EventType: "TOKEN_ISSUED",
		Method: "POST /oauth/token (RFC 8693 token exchange)", Resource: resource, Verdict: "allow",
		TokenJTI: claims.JTI, FamilyID: claims.FamilyID, DPoPJKT: jkt,
	})
	tokType := "Bearer"
	if jkt != "" {
		tokType = "DPoP"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":          tok,
		"issued_token_type":     "urn:ietf:params:oauth:token-type:access_token",
		"token_type":            tokType,
		"expires_in":            claims.EXP - time.Now().Unix(),
		"scope":                 claims.Scope,
		"sub_agent_id":          dl.SubAgentID,
		"delegation_expires_at": dl.ExpiresAt,
	})
}
