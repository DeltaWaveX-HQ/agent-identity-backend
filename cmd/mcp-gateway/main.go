package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/buildathon2026/agent-identity-backend/internal/crypto"
)

// JSON-RPC 2.0 wire types for the Model Context Protocol (MCP)
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string `json:"jsonrpc"`
	ID      any    `json:"id"`
	Result  any    `json:"result,omitempty"`
	Error   any    `json:"error,omitempty"`
}

type toolCallParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

type mcpGatewaySession struct {
	mu          sync.Mutex
	serverURL   string
	userEmail   string
	agentName   string
	modelID     string
	keypair     *crypto.EphemeralAgentKeypair
	clientID    string
	accessToken string
	subKeypair  *crypto.EphemeralAgentKeypair
	subToken    string
}

func main() {
	serverURL := flag.String("server", "http://localhost:8080", "Agent Identity Go Authorization Server & Gateway URL")
	userEmail := flag.String("user", "ajay@deltawavex.in", "Your logged-in dashboard user email")
	agentName := flag.String("agent", "MCPJam / Claude Agent", "Agent display name in your dashboard")
	modelID := flag.String("model", "claude-4-sonnet / gemini-2.5-pro", "LLM driving this MCP session")
	httpPort := flag.String("http", "", "Optional HTTP port for Streamable HTTP / SSE MCP transport (e.g. 8090 for MCPJam)")
	flag.Parse()

	kp, err := crypto.GenerateAgentDPoPKeypair(*agentName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate DPoP keypair: %v\n", err)
		os.Exit(1)
	}

	sess := &mcpGatewaySession{
		serverURL: *serverURL,
		userEmail: *userEmail,
		agentName: *agentName,
		modelID:   *modelID,
		keypair:   kp,
	}

	if *httpPort != "" {
		sess.serveHTTP(*httpPort)
		return
	}

	// Read JSON-RPC 2.0 messages from stdin (sent by real Claude Code / Claude Desktop / Gemini CLI)
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			continue
		}
		sess.handleRPC(req)
	}
}

func (s *mcpGatewaySession) handleRPC(req rpcRequest) {
	switch req.Method {
	case "initialize":
		// As soon as real Claude or Gemini connects to our MCP Gateway, auto-register the agent via RFC 7591 DCR!
		go s.ensureDCRRegistered()

		s.writeResponse(req.ID, map[string]any{
			"protocolVersion": "2024-11-05",
			"capabilities": map[string]any{
				"tools": map[string]any{},
			},
			"serverInfo": map[string]any{
				"name":    "agent-identity-enforcement-gateway",
				"version": "1.0.0",
			},
		})

	case "notifications/initialized":
		// No response needed for notifications

	case "tools/list":
		s.writeResponse(req.ID, map[string]any{
			"tools": []map[string]any{
				{
					"name":        "read_q3_invoices",
					"description": "Reads Q3 financial invoices from /finance/invoices/2026-Q3 through the Agent Identity Enforcement Gateway (Requires RFC 9396 RAR user consent & DPoP proof).",
					"inputSchema": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"folder": map[string]any{
								"type":        "string",
								"description": "Invoice folder path, default /finance/invoices/2026-Q3",
							},
						},
					},
				},
				{
					"name":        "query_customer_crm",
					"description": "Queries enterprise customer CRM records through the Agent Identity Gateway (Protected by CAMD/CRM delegation flow).",
					"inputSchema": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"customer_segment": map[string]any{
								"type":        "string",
								"description": "Customer segment to query (e.g. enterprise_fintech)",
							},
						},
					},
				},
				{
					"name":        "initiate_vendor_payment",
					"description": "Initiates an INR NEFT vendor payment transfer. High-sensitivity financial mutation — triggers a live OpenID CIBA Step-Up approval on the user's dashboard!",
					"inputSchema": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"vendor_name": map[string]any{
								"type":        "string",
								"description": "Vendor name (e.g. CloudInfra India Pvt Ltd)",
							},
							"amount_inr": map[string]any{
								"type":        "number",
								"description": "Payment amount in INR (e.g. 45000)",
							},
						},
						"required": []string{"vendor_name", "amount_inr"},
					},
				},
				{
					"name":        "http_egress_fetch",
					"description": "Fetches or exports data to an external domain through the Layer 2 Egress Proxy. Unknown hosts outside *.acme.local are blocked and trigger cascading token family revocation.",
					"inputSchema": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"target_host": map[string]any{
								"type":        "string",
								"description": "Target hostname (e.g. invoices.acme.local or evil-exfil.example)",
							},
							"path": map[string]any{
								"type":        "string",
								"description": "Target path (e.g. /export-all)",
							},
							"action": map[string]any{
								"type":        "string",
								"description": "Action type (read, write, export_all, delete)",
							},
						},
						"required": []string{"target_host"},
					},
				},
			},
		})

	case "tools/call":
		var params toolCallParams
		_ = json.Unmarshal(req.Params, &params)
		text, isErr := s.executeGuardedTool(params)
		s.writeResponse(req.ID, map[string]any{
			"content": []map[string]any{
				{
					"type": "text",
					"text": text,
				},
			},
			"isError": isErr,
		})

	default:
		if req.ID != nil {
			s.writeResponse(req.ID, map[string]any{})
		}
	}
}

func (s *mcpGatewaySession) ensureDCRRegistered() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.clientID != "" {
		return s.clientID
	}
	resp := s.postJSON("/oauth/register", map[string]any{
		"client_name": s.agentName,
		"owner_user":  "user:" + s.userEmail,
		"model_id":    s.modelID,
		"scope":       "crm.read invoices.read payments.transfer",
	}, "")
	cid, _ := resp["client_id"].(string)
	if cid == "" {
		cid = "agent:dcr-mcp-client"
	}
	s.clientID = cid
	return s.clientID
}

// ensureConsentedToken checks if the agent holds a valid, unrevoked DPoP token.
// If not, it triggers a LIVE Consent Modal on http://localhost:3000 and waits for the user to click Approve!
func (s *mcpGatewaySession) ensureConsentedToken(taskDesc, resourcePath, action string) (string, *crypto.EphemeralAgentKeypair, error) {
	cid := s.ensureDCRRegistered()

	// Check if existing sub-agent token is still active via RFC 7662 Introspection
	s.mu.Lock()
	existingTok := s.subToken
	existingKP := s.subKeypair
	s.mu.Unlock()

	if existingTok != "" {
		intro := s.postJSON("/oauth/introspect", map[string]any{"token": existingTok}, "")
		if active, _ := intro["active"].(bool); active {
			return existingTok, existingKP, nil
		}
	}

	// Request fresh RFC 9396 RAR Consent from the user's dashboard!
	pkceVerifier := fmt.Sprintf("mcp_pkce_%d", time.Now().UnixNano())
	vHash := sha256.Sum256([]byte(pkceVerifier))
	pkceChallenge := base64.RawURLEncoding.EncodeToString(vHash[:])

	authResp := s.postJSON("/oauth/authorize", map[string]any{
		"client_id":             cid,
		"user_sub":              "user:" + s.userEmail,
		"task":                  taskDesc,
		"scope":                 "crm.read invoices.read",
		"aud":                   "https://gw.acme.local" + resourcePath,
		"code_challenge":        pkceChallenge,
		"code_challenge_method": "S256",
		"authorization_details": []map[string]any{
			{
				"type":           "mcp_tool_execution",
				"locations":      []string{resourcePath},
				"actions":        []string{"read"},
				"data_residency": "IN",
			},
		},
	}, "")

	consentRec, _ := authResp["consent_record"].(map[string]any)
	consentID, _ := consentRec["consent_id"].(string)

	// Poll until the user clicks "Approve Pass" in the Next.js Dashboard at http://localhost:3000
	var authCode string
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(1 * time.Second)
		st := s.getJSON("/api/v1/oauth/consent-status?consent_id=" + consentID)
		if approved, _ := st["approved"].(bool); approved {
			authCode, _ = st["auth_code"].(string)
			break
		}
		if revoked, _ := st["revoked"].(bool); revoked {
			return "", nil, fmt.Errorf("User denied RFC 9396 RAR consent (%s) in the Agent Identity Dashboard", consentID)
		}
	}
	if authCode == "" {
		return "", nil, fmt.Errorf("Consent request timed out waiting for user approval at http://localhost:3000")
	}

	// Exchange auth_code + PKCE verifier + DPoP proof for parent access token
	dpopProof, _, _ := s.keypair.CreateDPoPProof("POST", s.serverURL+"/oauth/token", "")
	tokResp := s.postJSON("/oauth/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     cid,
		"code":          authCode,
		"code_verifier": pkceVerifier,
	}, dpopProof)

	parentTok, _ := tokResp["access_token"].(string)
	if parentTok == "" {
		return "", nil, fmt.Errorf("failed to mint parent access token: %v", tokResp)
	}

	// Perform RFC 8693 Token Exchange for the tool-execution child sub-agent
	subID := cid + "/mcp-tool-worker"
	subKP, _ := crypto.GenerateAgentDPoPKeypair(subID)
	subProof, _, _ := subKP.CreateDPoPProof("POST", s.serverURL+"/oauth/token", "")
	exResp := s.postJSON("/oauth/token", map[string]any{
		"grant_type":      "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token":   parentTok,
		"actor_client_id": subID,
		"scope":           "crm.read invoices.read",
	}, subProof)

	subTok, _ := exResp["access_token"].(string)
	if subTok == "" {
		subTok = parentTok
		subKP = s.keypair
	}

	s.mu.Lock()
	s.accessToken = parentTok
	s.subToken = subTok
	s.subKeypair = subKP
	s.mu.Unlock()

	return subTok, subKP, nil
}

func (s *mcpGatewaySession) executeGuardedTool(params toolCallParams) (string, bool) {
	var targetHost, resourcePath, action, httpMethod, taskDesc string
	var amountINR int
	var untrusted bool

	switch params.Name {
	case "read_q3_invoices":
		resourcePath, _ = params.Arguments["folder"].(string)
		if resourcePath == "" {
			resourcePath = "/finance/invoices/2026-Q3"
		}
		targetHost = "invoices.acme.local"
		action = "read"
		httpMethod = "GET"
		taskDesc = "MCP Tool Call: read_q3_invoices (" + resourcePath + ")"

	case "query_customer_crm":
		seg, _ := params.Arguments["customer_segment"].(string)
		if seg == "" {
			seg = "enterprise_fintech"
		}
		resourcePath = "/crm/customers/" + seg
		targetHost = "crm.acme.local"
		action = "read"
		httpMethod = "GET"
		taskDesc = "MCP Tool Call: query_customer_crm (" + seg + ")"

	case "initiate_vendor_payment":
		vendor, _ := params.Arguments["vendor_name"].(string)
		if amt, ok := params.Arguments["amount_inr"].(float64); ok {
			amountINR = int(amt)
		} else {
			amountINR = 45000
		}
		resourcePath = "/payments/transfer"
		targetHost = "payments.acme.local"
		action = "payment_transfer"
		httpMethod = "POST"
		taskDesc = fmt.Sprintf("MCP Tool Call: initiate_vendor_payment (INR %d to %s)", amountINR, vendor)

	case "http_egress_fetch":
		targetHost, _ = params.Arguments["target_host"].(string)
		if targetHost == "" {
			targetHost = "evil-exfil.example"
		}
		resourcePath, _ = params.Arguments["path"].(string)
		if resourcePath == "" {
			resourcePath = "/export-all"
		}
		action, _ = params.Arguments["action"].(string)
		if action == "" {
			action = "export_all"
		}
		httpMethod = "POST"
		untrusted = !strings.HasSuffix(targetHost, ".acme.local")
		taskDesc = fmt.Sprintf("MCP Tool Call: http_egress_fetch (%s%s)", targetHost, resourcePath)

	default:
		return fmt.Sprintf("Unknown tool: %s", params.Name), true
	}

	tok, kp, err := s.ensureConsentedToken(taskDesc, resourcePath, action)
	if err != nil {
		return fmt.Sprintf("🔒 [Agent Identity Layer 1 Blocked]: %v", err), true
	}

	targetURI := "https://" + targetHost + resourcePath
	dpopProof, _, _ := kp.CreateDPoPProof(httpMethod, targetURI, tok)

	gwResp := s.postJSON("/api/v1/gateway/execute", map[string]any{
		"access_token":      tok,
		"dpop_proof":        dpopProof,
		"http_method":       httpMethod,
		"target_uri":        targetURI,
		"target_host":       targetHost,
		"resource_path":     resourcePath,
		"action":            action,
		"amount_inr":        amountINR,
		"untrusted_context": untrusted,
	}, "")

	allowed, _ := gwResp["allowed"].(bool)
	pretty, _ := json.MarshalIndent(gwResp, "", "  ")

	if !allowed {
		return fmt.Sprintf("🛑 [Agent Identity Layer 2 Enforcement Gateway BLOCKED / STEP-UP]:\n%s", string(pretty)), true
	}
	return fmt.Sprintf("✅ [Agent Identity Layer 2 Gateway ALLOWED & AUDITED]:\n%s", string(pretty)), false
}

func (s *mcpGatewaySession) writeResponse(id any, result any) {
	resp := rpcResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
	b, _ := json.Marshal(resp)
	fmt.Println(string(b))
}

func (s *mcpGatewaySession) buildRPCResponse(req rpcRequest) *rpcResponse {
	switch req.Method {
	case "initialize":
		go s.ensureDCRRegistered()
		return &rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities": map[string]any{
					"tools": map[string]any{},
				},
				"serverInfo": map[string]any{
					"name":    "agent-identity-enforcement-gateway",
					"version": "1.0.0",
				},
			},
		}
	case "notifications/initialized":
		return nil
	case "tools/list":
		return &rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"tools": s.toolDefinitions(),
			},
		}
	case "tools/call":
		var params toolCallParams
		_ = json.Unmarshal(req.Params, &params)
		text, isErr := s.executeGuardedTool(params)
		return &rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"content": []map[string]any{
					{
						"type": "text",
						"text": text,
					},
				},
				"isError": isErr,
			},
		}
	default:
		if req.ID == nil {
			return nil
		}
		return &rpcResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  map[string]any{},
		}
	}
}

func (s *mcpGatewaySession) toolDefinitions() []map[string]any {
	return []map[string]any{
		{
			"name":        "read_q3_invoices",
			"description": "Reads Q3 financial invoices from /finance/invoices/2026-Q3 through the Agent Identity Enforcement Gateway (Requires RFC 9396 RAR user consent & DPoP proof).",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"folder": map[string]any{
						"type":        "string",
						"description": "Invoice folder path, default /finance/invoices/2026-Q3",
					},
				},
			},
		},
		{
			"name":        "query_customer_crm",
			"description": "Queries enterprise customer CRM records through the Agent Identity Gateway (Protected by CAMD/CRM delegation flow).",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"customer_segment": map[string]any{
						"type":        "string",
						"description": "Customer segment to query (e.g. enterprise_fintech)",
					},
				},
			},
		},
		{
			"name":        "initiate_vendor_payment",
			"description": "Initiates an INR NEFT vendor payment transfer. High-sensitivity financial mutation — triggers a live OpenID CIBA Step-Up approval on the user's dashboard!",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"vendor_name": map[string]any{
						"type":        "string",
						"description": "Vendor name (e.g. CloudInfra India Pvt Ltd)",
					},
					"amount_inr": map[string]any{
						"type":        "number",
						"description": "Payment amount in INR (e.g. 45000)",
					},
				},
				"required": []string{"vendor_name", "amount_inr"},
			},
		},
		{
			"name":        "http_egress_fetch",
			"description": "Fetches or exports data to an external domain through the Layer 2 Egress Proxy. Unknown hosts outside *.acme.local are blocked and trigger cascading token family revocation.",
			"inputSchema": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target_host": map[string]any{
						"type":        "string",
						"description": "Target hostname (e.g. invoices.acme.local or evil-exfil.example)",
					},
					"path": map[string]any{
						"type":        "string",
						"description": "Target path (e.g. /export-all)",
					},
					"action": map[string]any{
						"type":        "string",
						"description": "Action type (read, write, export_all, delete)",
					},
				},
				"required": []string{"target_host"},
			},
		},
	}
}

// serveHTTP runs an MCP Streamable HTTP & SSE server (for MCPJam Inspector, Cursor, etc.) on the specified port.
func (s *mcpGatewaySession) serveHTTP(port string) {
	mux := http.NewServeMux()

	handleJSONRPC := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Accept, Mcp-Session-Id")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodGet {
			// SSE endpoint for older MCP SSE clients
			flusher, ok := w.(http.Flusher)
			if !ok {
				http.Error(w, "SSE unsupported", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			_, _ = fmt.Fprintf(w, "event: endpoint\ndata: /mcp\n\n")
			flusher.Flush()
			<-r.Context().Done()
			return
		}

		var req rpcRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		resp := s.buildRPCResponse(req)
		if resp == nil {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}

	mux.HandleFunc("/mcp", handleJSONRPC)
	mux.HandleFunc("/sse", handleJSONRPC)
	mux.HandleFunc("/message", handleJSONRPC)
	mux.HandleFunc("/", handleJSONRPC)

	fmt.Fprintf(os.Stderr, "🛡️  Agent Identity MCP Gateway (Streamable HTTP + SSE for MCPJam) listening on http://localhost:%s/mcp\n", port)
	if err := http.ListenAndServe(":"+port, mux); err != nil {
		fmt.Fprintf(os.Stderr, "HTTP server failed: %v\n", err)
		os.Exit(1)
	}
}

func (s *mcpGatewaySession) postJSON(path string, payload any, dpopHeader string) map[string]any {
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, s.serverURL+path, bytes.NewReader(b))
	if err != nil {
		return nil
	}
	req.Header.Set("Content-Type", "application/json")
	if dpopHeader != "" {
		req.Header.Set("DPoP", dpopHeader)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

func (s *mcpGatewaySession) getJSON(path string) map[string]any {
	resp, err := http.Get(s.serverURL + path)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}
