package main

// MCP *server* side: the authenticated front door that Claude Code, Claude Desktop, ChatGPT,
// Gemini CLI, Cursor and MCPJam connect to. Implements MCP Streamable HTTP (2025-03-26 →
// 2025-11-25) with the MCP authorization spec: unauthenticated requests get 401 + RFC 9728
// protected-resource metadata pointing at our authorization server.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const gatewayVersion = "0.3.0"

// subAgentMetaKey is the MCP `_meta` key a client sets on tools/call to say a sub-agent made it.
const subAgentMetaKey = "io.agentidentity/sub_agent"

var supportedProtocolVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

type toolRoute struct {
	Exposed  string
	Upstream Upstream
	Original string
	Policy   ToolPolicy
	Raw      map[string]any
}

type tokenInfo struct {
	Active   bool   `json:"active"`
	ClientID string `json:"client_id"`
	Sub      string `json:"sub"`
	Aud      string `json:"aud"`
	Scope    string `json:"scope"`
	Exp      int64  `json:"exp"`
	FamilyID string `json:"family_id"`
	Error    string `json:"error"`
	Reason   string `json:"revoke_reason"`
}

type cachedToken struct {
	info    tokenInfo
	expires time.Time
}

type mcpSession struct {
	ClientID string
	Created  time.Time
}

type Gateway struct {
	cfg      *Config
	resource string
	routes   map[string]*toolRoute
	order    []string
	ups      []Upstream
	upErrors map[string]string

	authClient *http.Client

	cacheMu sync.Mutex
	cache   map[string]cachedToken

	sessMu   sync.Mutex
	sessions map[string]*mcpSession

	attrib attributionBook
}

var (
	toolNameRe = regexp.MustCompile(`[^A-Za-z0-9_-]`)
	subPathRe  = regexp.MustCompile(`^/mcp/sub/([a-z0-9][a-z0-9-]{0,31})$`)
)

// resourceFor maps a request path to the protected resource it belongs to:
// /mcp → the parent endpoint, /mcp/sub/<name> → a sub-agent endpoint with its own audience.
func (g *Gateway) resourceFor(path string) (string, bool) {
	if path == "/mcp" {
		return g.resource, true
	}
	if subPathRe.MatchString(path) {
		return g.cfg.PublicURL + path, true
	}
	return "", false
}

func newGateway(cfg *Config) *Gateway {
	return &Gateway{
		cfg:        cfg,
		resource:   cfg.PublicURL + "/mcp",
		routes:     map[string]*toolRoute{},
		upErrors:   map[string]string{},
		authClient: &http.Client{Timeout: 150 * time.Second, Transport: gatewayKeyTransport{secret: cfg.SharedSecret}}, // > CIBA wait (120 s)
		cache:      map[string]cachedToken{},
		sessions:   map[string]*mcpSession{},
	}
}

// startUpstreams connects to every enabled upstream and builds the aggregated tool catalogue.
// A broken upstream is logged and skipped; the gateway still serves the others.
func (g *Gateway) startUpstreams(ctx context.Context) {
	type result struct {
		up  Upstream
		err error
	}
	var enabled []UpstreamConfig
	for _, uc := range g.cfg.Upstreams {
		if uc.enabled() {
			enabled = append(enabled, uc)
		} else {
			log.Printf("upstream %-8s disabled in config", uc.Name)
		}
	}
	results := make([]result, len(enabled))
	var wg sync.WaitGroup
	for i, uc := range enabled {
		wg.Add(1)
		go func(i int, uc UpstreamConfig) {
			defer wg.Done()
			up, err := newUpstream(uc)
			if err == nil {
				sctx, cancel := context.WithTimeout(ctx, 120*time.Second) // first npx/uvx run downloads packages
				err = up.Start(sctx)
				cancel()
			}
			results[i] = result{up, err}
		}(i, uc)
	}
	wg.Wait()

	for i, r := range results {
		name := enabled[i].Name
		if r.err != nil {
			g.upErrors[name] = r.err.Error()
			log.Printf("upstream %-8s FAILED: %v", name, r.err)
			continue
		}
		g.ups = append(g.ups, r.up)
		count := 0
		for _, t := range r.up.Tools() {
			pol := enabled[i].Tools[t.Name]
			if pol.Hidden {
				continue
			}
			exposed := toolNameRe.ReplaceAllString(name+"__"+t.Name, "_")
			if len(exposed) > 64 {
				exposed = exposed[:64]
			}
			g.routes[exposed] = &toolRoute{Exposed: exposed, Upstream: r.up, Original: t.Name, Policy: pol, Raw: t.Raw}
			g.order = append(g.order, exposed)
			count++
		}
		log.Printf("upstream %-8s ready: %d tools", name, count)
	}
	sort.Strings(g.order)
}

func (g *Gateway) close() {
	for _, u := range g.ups {
		u.Close()
	}
}

// gatewayKeyTransport authenticates every gateway -> authorization server call with the shared
// secret (X-Gateway-Key). The server rejects decide/report/introspect calls without it.
type gatewayKeyTransport struct{ secret string }

func (t gatewayKeyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.secret != "" {
		r = r.Clone(r.Context())
		r.Header.Set("X-Gateway-Key", t.secret)
	}
	return http.DefaultTransport.RoundTrip(r)
}

// registerEgressAllowlist tells the policy engine which hosts this tenant allows. It retries in
// the background, because on a fresh deploy the authorization server may still be starting.
func (g *Gateway) registerEgressAllowlist() {
	go func() {
		body, _ := json.Marshal(map[string]any{"hosts": g.cfg.EgressAllowlist})
		for attempt := 1; attempt <= 30; attempt++ {
			resp, err := g.authClient.Post(g.cfg.AuthServerInternal+"/api/v1/gateway/egress-allowlist", "application/json", bytes.NewReader(body))
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					return
				}
				if resp.StatusCode == http.StatusUnauthorized {
					log.Printf("WARNING: authorization server rejected the gateway key: GATEWAY_SHARED_SECRET must match on both services")
					return
				}
			}
			if attempt == 1 {
				log.Printf("WARNING: could not reach authorization server at %s (%v); retrying. Start it with: go run ./cmd/server", g.cfg.AuthServerInternal, err)
			}
			time.Sleep(4 * time.Second)
		}
	}()
}

// ---------------------------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------------------------

func (g *Gateway) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/oauth-protected-resource", g.handlePRM)
	mux.HandleFunc("/.well-known/oauth-protected-resource/", g.handlePRM)
	mux.HandleFunc("/.well-known/oauth-authorization-server", g.handleASMetadata)
	mux.HandleFunc("/.well-known/oauth-authorization-server/", g.handleASMetadata)
	mux.HandleFunc("/.well-known/openid-configuration", g.handleASMetadata)
	mux.HandleFunc("/.well-known/openid-configuration/", g.handleASMetadata)
	mux.HandleFunc("/mcp", g.handleMCP)
	mux.HandleFunc("/mcp/sub/", g.handleMCP)
	mux.HandleFunc("/gateway/status", g.handleStatus)
	mux.HandleFunc("/gateway/attribution", g.handleAttribution)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintf(w, "Agent Identity MCP Gateway %s\nMCP endpoint: %s\nStatus: %s/gateway/status\n", gatewayVersion, g.resource, g.cfg.PublicURL)
			return
		}
		http.NotFound(w, r)
	})
	return withCORS(mux)
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, Mcp-Session-Id, MCP-Protocol-Version, Last-Event-ID")
		w.Header().Set("Access-Control-Expose-Headers", "Mcp-Session-Id, WWW-Authenticate")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSONResp(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// RFC 9728 Protected Resource Metadata.
func (g *Gateway) handlePRM(w http.ResponseWriter, r *http.Request) {
	resource := g.resource
	if suffix := strings.TrimPrefix(r.URL.Path, "/.well-known/oauth-protected-resource"); suffix != "" && suffix != "/" {
		res, ok := g.resourceFor(suffix)
		if !ok {
			http.NotFound(w, r)
			return
		}
		resource = res
	}
	writeJSONResp(w, http.StatusOK, map[string]any{
		"resource":                 resource,
		"authorization_servers":    []string{g.cfg.AuthServer},
		"scopes_supported":         []string{"mcp:tools"},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            "Agent Identity Gateway",
		"resource_documentation":   consoleURL(),
	})
}

// Older clients (MCP 2025-03-26) look for AS metadata on the MCP server's own origin: relay ours.
func (g *Gateway) handleASMetadata(w http.ResponseWriter, r *http.Request) {
	resp, err := g.authClient.Get(g.cfg.AuthServerInternal + "/.well-known/oauth-authorization-server")
	if err != nil {
		writeJSONResp(w, http.StatusBadGateway, map[string]string{"error": "authorization server unreachable"})
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

func (g *Gateway) handleStatus(w http.ResponseWriter, r *http.Request) {
	type upStatus struct {
		Name, Description, Transport, Error string
		Tools                               []string
	}
	var out []upStatus
	for _, uc := range g.cfg.Upstreams {
		s := upStatus{Name: uc.Name, Description: uc.Description, Transport: uc.Transport, Error: g.upErrors[uc.Name]}
		if !uc.enabled() {
			s.Error = "disabled"
		}
		for _, name := range g.order {
			if rt := g.routes[name]; rt.Upstream.Config().Name == uc.Name {
				s.Tools = append(s.Tools, name)
			}
		}
		out = append(out, s)
	}
	writeJSONResp(w, http.StatusOK, map[string]any{"version": gatewayVersion, "resource": g.resource, "upstreams": out, "egress_allowlist": g.cfg.EgressAllowlist})
}

func (g *Gateway) unauthorized(w http.ResponseWriter, path, errCode, desc string) {
	h := fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource%s", scope="mcp:tools"`, g.cfg.PublicURL, path)
	if errCode != "" {
		h += fmt.Sprintf(`, error="%s", error_description="%s"`, errCode, strings.ReplaceAll(desc, `"`, "'"))
	}
	w.Header().Set("WWW-Authenticate", h)
	writeJSONResp(w, http.StatusUnauthorized, map[string]string{"error": firstNonEmptyStr(errCode, "unauthorized"), "error_description": desc})
}

func firstNonEmptyStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func tokenKey(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// authenticate validates the bearer token via RFC 7662 introspection, cached ≤ 5 s
// (the blueprint's revocation-propagation budget).
func (g *Gateway) authenticate(r *http.Request) (string, *tokenInfo, string) {
	authz := r.Header.Get("Authorization")
	scheme, tok, _ := strings.Cut(authz, " ")
	if tok == "" || !strings.EqualFold(scheme, "Bearer") {
		return "", nil, ""
	}
	key := tokenKey(tok)
	g.cacheMu.Lock()
	if c, ok := g.cache[key]; ok && time.Now().Before(c.expires) {
		g.cacheMu.Unlock()
		info := c.info
		return tok, &info, ""
	}
	g.cacheMu.Unlock()

	body, _ := json.Marshal(map[string]string{"token": tok})
	resp, err := g.authClient.Post(g.cfg.AuthServerInternal+"/oauth/introspect", "application/json", bytes.NewReader(body))
	if err != nil {
		return tok, nil, "authorization server unreachable"
	}
	defer resp.Body.Close()
	var info tokenInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return tok, nil, "bad introspection response"
	}
	g.cacheMu.Lock()
	g.cache[key] = cachedToken{info: info, expires: time.Now().Add(5 * time.Second)}
	g.cacheMu.Unlock()
	return tok, &info, ""
}

func (g *Gateway) forgetToken(tok string) {
	g.cacheMu.Lock()
	delete(g.cache, tokenKey(tok))
	g.cacheMu.Unlock()
}

func newSessionID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ---------------------------------------------------------------------------------------------
// MCP endpoint
// ---------------------------------------------------------------------------------------------

func (g *Gateway) handleMCP(w http.ResponseWriter, r *http.Request) {
	resource, ok := g.resourceFor(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	tok, info, authErr := g.authenticate(r)
	switch {
	case authErr != "":
		writeJSONResp(w, http.StatusServiceUnavailable, map[string]string{"error": authErr})
		return
	case tok == "":
		g.unauthorized(w, r.URL.Path, "", "Bearer token required. Your MCP client should start the OAuth flow.")
		return
	case !info.Active:
		g.unauthorized(w, r.URL.Path, "invalid_token", firstNonEmptyStr(info.Reason, firstNonEmptyStr(info.Error, "token inactive")))
		return
	case info.Aud != resource:
		// A parent token cannot be used on a sub-agent endpoint and vice versa.
		g.unauthorized(w, r.URL.Path, "invalid_token", fmt.Sprintf("token audience %q is not this endpoint (%s)", info.Aud, resource))
		return
	}

	sid := r.Header.Get("Mcp-Session-Id")
	if sid != "" {
		g.sessMu.Lock()
		s, ok := g.sessions[sid]
		g.sessMu.Unlock()
		if !ok {
			http.Error(w, "unknown or expired MCP session", http.StatusNotFound) // client re-initialises
			return
		}
		if s.ClientID != info.ClientID {
			http.Error(w, "session belongs to a different agent", http.StatusForbidden)
			return
		}
	}

	switch r.Method {
	case http.MethodGet:
		// No server-initiated stream in this prototype (allowed by the Streamable HTTP spec).
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "server-sent stream not offered; use POST", http.StatusMethodNotAllowed)
		return
	case http.MethodDelete:
		g.sessMu.Lock()
		delete(g.sessions, sid)
		g.sessMu.Unlock()
		w.WriteHeader(http.StatusNoContent)
		return
	case http.MethodPost:
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	raw, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if t := bytes.TrimSpace(raw); len(t) > 0 && t[0] == '[' {
		writeJSONResp(w, http.StatusBadRequest, rpcErr(nil, -32600, "JSON-RPC batches are not supported"))
		return
	}
	var msg jsonrpcMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		writeJSONResp(w, http.StatusBadRequest, rpcErr(nil, -32700, "parse error"))
		return
	}
	if msg.Method == "" || len(msg.ID) == 0 { // notification or client response
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if msg.Method == "initialize" {
		sid = newSessionID()
		g.sessMu.Lock()
		g.sessions[sid] = &mcpSession{ClientID: info.ClientID, Created: time.Now()}
		g.sessMu.Unlock()
		w.Header().Set("Mcp-Session-Id", sid)
		log.Printf("session  %s… opened by %s for %s", sid[:8], info.ClientID, info.Sub)
	}

	result, rerr, status := g.dispatch(r.Context(), tok, info, sid, resource, msg)
	if status == http.StatusUnauthorized {
		g.forgetToken(tok)
		g.unauthorized(w, r.URL.Path, "invalid_token", rerr.Message)
		return
	}
	resp := jsonrpcMessage{JSONRPC: "2.0", ID: msg.ID}
	if rerr != nil {
		resp.Error = rerr
	} else {
		resp.Result = result
	}
	writeJSONResp(w, http.StatusOK, resp)
}

func rpcErr(id json.RawMessage, code int, m string) jsonrpcMessage {
	return jsonrpcMessage{JSONRPC: "2.0", ID: id, Error: &jsonrpcError{Code: code, Message: m}}
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

func (g *Gateway) dispatch(ctx context.Context, tok string, info *tokenInfo, sid, resource string, msg jsonrpcMessage) (json.RawMessage, *jsonrpcError, int) {
	switch msg.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(msg.Params, &p)
		version := supportedProtocolVersions[0]
		for _, v := range supportedProtocolVersions {
			if v == p.ProtocolVersion {
				version = v
			}
		}
		return mustJSON(map[string]any{
			"protocolVersion": version,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "agent-identity-gateway", "title": "Agent Identity Gateway", "version": gatewayVersion},
			"instructions": "Tools from several internal systems, served through an identity-aware gateway. Tool names are prefixed with their system (e.g. bank__, files__). " +
				"Every call is checked against the user's consent and a runtime risk model. Some actions wait for the user to approve them on their dashboard; " +
				"if a call is blocked, explain the reason to the user rather than retrying. " +
				"Sub-agents: either exchange the parent token for a sub-agent token (RFC 8693, sub_agent=<name>) or tag calls with " +
				"_meta {\"io.agentidentity/sub_agent\": {\"name\": \"<name>\"}}; the user approves each new sub-agent once.",
		}), nil, 200

	case "ping":
		return json.RawMessage(`{}`), nil, 200

	case "tools/list":
		tools := make([]map[string]any, 0, len(g.order))
		for _, name := range g.order {
			rt := g.routes[name]
			t := make(map[string]any, len(rt.Raw)+1)
			for k, v := range rt.Raw {
				t[k] = v
			}
			t["name"] = name
			desc, _ := rt.Raw["description"].(string)
			t["description"] = strings.TrimSpace(fmt.Sprintf("[%s] %s", rt.Upstream.Config().Name, desc))
			tools = append(tools, t)
		}
		return mustJSON(map[string]any{"tools": tools}), nil, 200

	case "tools/call":
		return g.callTool(ctx, tok, info, sid, resource, msg.Params)

	case "resources/list":
		return json.RawMessage(`{"resources":[]}`), nil, 200
	case "resources/templates/list":
		return json.RawMessage(`{"resourceTemplates":[]}`), nil, 200
	case "prompts/list":
		return json.RawMessage(`{"prompts":[]}`), nil, 200
	case "logging/setLevel":
		return json.RawMessage(`{}`), nil, 200
	}
	return nil, &jsonrpcError{Code: -32601, Message: "method not found: " + msg.Method}, 200
}

type decideResponse struct {
	Allowed       bool     `json:"allowed"`
	Verdict       string   `json:"verdict"`
	Status        int      `json:"status"`
	Score         float64  `json:"score"`
	Reasons       []string `json:"reasons"`
	HardRule      string   `json:"hard_rule"`
	Message       string   `json:"message"`
	CIBAAuthReqID string   `json:"ciba_auth_req_id"`
}

func toolText(text string, isErr bool) json.RawMessage {
	return mustJSON(map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": isErr})
}

func (g *Gateway) postAuth(ctx context.Context, path string, body any, out any) error {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.cfg.AuthServerInternal+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.authClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("%s: HTTP %d %s", path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (g *Gateway) callTool(ctx context.Context, tok string, info *tokenInfo, sid, resource string, params json.RawMessage) (json.RawMessage, *jsonrpcError, int) {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
		Meta      map[string]any  `json:"_meta"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &jsonrpcError{Code: -32602, Message: "invalid params"}, 200
	}
	rt, ok := g.routes[p.Name]
	if !ok {
		return nil, &jsonrpcError{Code: -32602, Message: "unknown tool: " + p.Name}, 200
	}
	var args map[string]any
	if len(p.Arguments) > 0 {
		_ = json.Unmarshal(p.Arguments, &args)
	}
	ann, _ := rt.Raw["annotations"].(map[string]any)
	cls := classifyCall(rt.Original, ann, rt.Policy, args)
	preview := string(p.Arguments)
	if len(preview) > 400 {
		preview = preview[:400] + "…"
	}

	// Was this call made by a sub-agent of the token holder? Two client-agnostic signals:
	//  1. MCP _meta tag set by the client/SDK:  "_meta": {"io.agentidentity/sub_agent": {"name": "...", "type": "..."}}
	//  2. a client adapter notice (e.g. Claude Code's PreToolUse hook) matched to this exact call
	// (A sub-agent holding its own exchanged token needs neither: its token says who it is.)
	var subAgent map[string]string
	hookNotice, hasNotice := g.attrib.take(p.Name + "|" + canonicalArgs(p.Arguments))
	if tag, ok := p.Meta[subAgentMetaKey].(map[string]any); ok {
		subAgent = map[string]string{"source": "mcp_meta"}
		for _, k := range []string{"name", "type", "id"} {
			if v, ok := tag[k].(string); ok {
				subAgent[k] = v
			}
		}
		if subAgent["name"] == "" && subAgent["id"] == "" {
			subAgent = nil
		}
	} else if hasNotice && hookNotice.agentID != "" {
		subAgent = map[string]string{"id": hookNotice.agentID, "type": hookNotice.agentType, "source": "client_hook"}
	}

	// 1. Ask the policy + risk engine (may block up to 2 minutes while a human decides).
	var dec decideResponse
	err := g.postAuth(ctx, "/api/v1/gateway/mcp/decide", map[string]any{
		"sub_agent":         subAgent,
		"access_token":      tok,
		"resource":          resource,
		"mcp_session_id":    sid,
		"upstream":          rt.Upstream.Config().Name,
		"tool":              p.Name,
		"action":            cls.Action,
		"target_hosts":      cls.Hosts,
		"amount_inr":        cls.AmountINR,
		"bulk_read":         cls.Bulk,
		"arguments_preview": preview,
	}, &dec)
	if err != nil {
		log.Printf("decide    %-28s FAIL-CLOSED: %v", p.Name, err)
		return toolText("The Agent Identity Gateway could not reach its policy engine, so it refused this call (fail-closed).", true), nil, 200
	}
	who := info.ClientID
	if subAgent != nil {
		who += " › " + firstNonEmptyStr(subAgent["name"], subAgent["type"]) + " (" + subAgent["source"] + ")"
	}
	log.Printf("decide    %-28s %-6s %-16s risk=%.2f %s", p.Name, cls.Action, dec.Verdict, dec.Score, who)
	if dec.Status == http.StatusUnauthorized {
		return nil, &jsonrpcError{Code: -32001, Message: dec.Message}, http.StatusUnauthorized
	}
	if !dec.Allowed {
		if dec.Verdict == "block_and_revoke" {
			g.forgetToken(tok)
		}
		var sb strings.Builder
		fmt.Fprintf(&sb, "BLOCKED by the Agent Identity Gateway (verdict: %s, risk %.2f).\n%s\n", dec.Verdict, dec.Score, dec.Message)
		if dec.HardRule != "" {
			fmt.Fprintf(&sb, "Policy: %s\n", dec.HardRule)
		}
		if len(dec.Reasons) > 0 {
			fmt.Fprintf(&sb, "Reasons: %s\n", strings.Join(dec.Reasons, "; "))
		}
		sb.WriteString("Do not retry this action; tell the user what was blocked and why.")
		return toolText(sb.String(), true), nil, 200
	}

	// 2. Forward to the real upstream.
	start := time.Now()
	cctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	res, err := rt.Upstream.Call(cctx, rt.Original, p.Arguments)
	latency := time.Since(start)
	if err != nil {
		if je, ok := err.(*jsonrpcError); ok {
			return nil, je, 200
		}
		return toolText("Upstream "+rt.Upstream.Config().Name+" failed: "+err.Error(), true), nil, 200
	}

	// 3. Tell the risk engine what came back (taints the run on injected or untrusted content).
	markers, size := scanForInjection(res)
	var isErr struct {
		IsError bool `json:"isError"`
	}
	_ = json.Unmarshal(res, &isErr)
	rctx, rcancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer rcancel()
	if err := g.postAuth(rctx, "/api/v1/gateway/mcp/report", map[string]any{
		"access_token":      tok,
		"upstream":          rt.Upstream.Config().Name,
		"tool":              p.Name,
		"is_error":          isErr.IsError,
		"bytes":             size,
		"latency_ms":        latency.Milliseconds(),
		"injection_markers": markers,
		"untrusted_source":  rt.Upstream.Config().UntrustedOutput,
	}, nil); err != nil {
		log.Printf("report    %-28s failed: %v", p.Name, err)
	}
	if len(markers) > 0 {
		log.Printf("taint     %-28s injection markers: %v", p.Name, markers)
	}
	return res, nil, 200
}

// consoleURL is the tenant console's public address (CONSOLE_URL), shown to clients and humans.
func consoleURL() string {
	if v := os.Getenv("CONSOLE_URL"); v != "" {
		return strings.TrimRight(v, "/")
	}
	return "http://localhost:3000"
}
