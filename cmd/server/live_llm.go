package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/buildathon2026/agent-identity-backend/internal/auth"
	"github.com/buildathon2026/agent-identity-backend/internal/crypto"
	"github.com/buildathon2026/agent-identity-backend/internal/events"
	"github.com/buildathon2026/agent-identity-backend/internal/gateway"
	"github.com/buildathon2026/agent-identity-backend/internal/risk"
	"github.com/buildathon2026/agent-identity-backend/internal/store"
)

type parsedLLMToolCall struct {
	ToolName     string
	TargetHost   string
	ResourcePath string
	Action       string
	HTTPMethod   string
	AmountINR    int
	Untrusted    bool
	LLMReasoning string
}

// runRealLLMAgentWithGateway calls the real Google Gemini API or Anthropic Claude API with tool definitions,
// intercepts the LLM's requested tool call at the Agent Identity Gateway, pops up the live RAR consent screen,
// mints the ES256 DPoP token + RFC 8693 child token, and enforces Layer 2 + Layer 3 before executing the tool.
func runRealLLMAgentWithGateway(
	provider, apiKey, model, userEmail, prompt string,
	authServer *auth.Server,
	dag *auth.FamilyDAG,
	riskEngine *risk.Engine,
	enfGateway *gateway.EnforcementGateway,
	dataStore *store.DataStore,
	sseHub *events.Hub,
) {
	agentName := fmt.Sprintf("Real %s Agent (%s)", strings.ToUpper(provider), model)
	clientID := fmt.Sprintf("agent:live-%s-%s", provider, strings.ReplaceAll(model, ".", "-"))
	userSub := "user:" + userEmail

	// 1. Generate ephemeral ES256 DPoP keypair & auto-register via RFC 7591 DCR
	parentKP, _ := crypto.GenerateAgentDPoPKeypair(clientID)
	registered, _ := authServer.RegisterAgent(auth.RegisteredAgent{
		AgentID:           clientID,
		Name:              agentName,
		OwnerUser:         userSub,
		SPIFFEID:          "spiffe://deltawavex.in/ns/live-llm/sa/" + provider,
		RuntimeAttested:   true,
		PlatformFramework: "Live " + strings.ToUpper(provider) + " Function Calling + MCP Gateway",
		ModelID:           model,
		AllowedScopes:     []string{"crm.read", "invoices.read", "payments.transfer"},
		DPoPPublicJWK:     &parentKP.PublicJWK,
		DPoPThumbprint:    parentKP.Thumbprint,
	})

	sseHub.Publish(events.TelemetryEvent{
		StepNumber:   1,
		FromLane:     "user",
		ToLane:       "agent",
		Label:        "Live Prompt → " + model,
		Who:          userEmail + " → " + agentName,
		Headline:     fmt.Sprintf("Calling Real %s API (%s) with Tool Definitions", strings.ToUpper(provider), model),
		PlainText:    fmt.Sprintf("Prompt: %q — Auto-registered %s via RFC 7591 DCR (cnf.jkt=%s)", prompt, registered.AgentID, registered.DPoPThumbprint),
		UnderTheHood: fmt.Sprintf("Live HTTPS call to %s API with 4 guarded enterprise tools", strings.ToUpper(provider)),
		FlowNode:     "start",
		Status:       "info",
		StatusText:   "Calling Real LLM",
		LatencyUs:    110,
	})

	// 2. Call the real Gemini or Claude API to let the real LLM decide which tool to invoke!
	tc, err := invokeRealLLMAPI(provider, apiKey, model, prompt)
	if err != nil {
		sseHub.Publish(events.TelemetryEvent{
			StepNumber:   2,
			FromLane:     "agent",
			ToLane:       "user",
			Label:        "LLM API Error",
			Who:          agentName + " → Dashboard",
			Headline:     fmt.Sprintf("Real %s API returned an error", strings.ToUpper(provider)),
			PlainText:    err.Error(),
			UnderTheHood: "Verify your GEMINI_API_KEY or ANTHROPIC_API_KEY",
			FlowNode:     "revoke",
			Status:       "bad",
			StatusText:   "API Error",
		})
		return
	}

	sseHub.Publish(events.TelemetryEvent{
		StepNumber:   2,
		FromLane:     "agent",
		ToLane:       "as",
		Label:        fmt.Sprintf("LLM Tool Call: %s()", tc.ToolName),
		Who:          agentName + " → Layer 1 Auth Server",
		Headline:     fmt.Sprintf("Real %s Decided to Call Tool: %s (%s %s%s)", strings.ToUpper(provider), tc.ToolName, tc.HTTPMethod, tc.TargetHost, tc.ResourcePath),
		PlainText:    fmt.Sprintf("LLM Reasoning: %s. Gateway intercepted the tool call because the agent has zero standing privileges.", tc.LLMReasoning),
		UnderTheHood: fmt.Sprintf("Tool=%s · Host=%s · Path=%s · Action=%s", tc.ToolName, tc.TargetHost, tc.ResourcePath, tc.Action),
		FlowNode:     "attest",
		Status:       "info",
		StatusText:   "Tool Intercepted",
		LatencyUs:    140,
	})

	// 3. Stage 1 Issuance Risk + Pop up Live RFC 9396 RAR Consent Screen on User's Dashboard!
	issuanceRisk := riskEngine.Decide(risk.ScoreRequest{
		Stage:           "issuance",
		AgentID:         clientID,
		UserSub:         userSub,
		RuntimeAttested: true,
		RequestedScope:  "crm.read invoices.read",
		TargetHost:      "gw.acme.local",
	})

	pkceVerifier := fmt.Sprintf("live_llm_pkce_%d", time.Now().UnixNano())
	vHash := sha256.Sum256([]byte(pkceVerifier))
	pkceChallenge := base64.RawURLEncoding.EncodeToString(vHash[:])

	rarDetails := []crypto.AuthorizationDetail{
		{
			Type:          "mcp_tool_execution",
			Locations:     []string{tc.ResourcePath},
			Actions:       []string{"read"},
			DataResidency: "IN",
		},
	}
	consentRec := authServer.CreateConsentPrompt(userSub, clientID, prompt+" (Tool: "+tc.ToolName+")", "crm.read invoices.read", "https://"+tc.TargetHost+tc.ResourcePath, pkceChallenge, rarDetails)

	sseHub.Publish(events.TelemetryEvent{
		StepNumber:   3,
		FromLane:     "as",
		ToLane:       "user",
		Label:        "RAR Consent Popup → Dashboard",
		Who:          "Auth Server → " + userEmail,
		Headline:     fmt.Sprintf("Awaiting Your Approval for %s's Tool Call (%s)", model, tc.ToolName),
		PlainText:    fmt.Sprintf("Click 'Approve Pass' on the popup modal to issue a 5-min DPoP-bound token for %s.", tc.ResourcePath),
		UnderTheHood: fmt.Sprintf("consent_id=%s · PKCE S256 challenge=%s...", consentRec.ConsentID, pkceChallenge[:14]),
		FlowNode:     "consent",
		Status:       "warn",
		StatusText:   "Waiting for You",
		LatencyUs:    issuanceRisk.LatencyUs,
		RiskDecision: issuanceRisk,
		PhonePrompt: &events.PhonePrompt{
			PromptID:          consentRec.ConsentID,
			Type:              "rar_consent",
			Title:             fmt.Sprintf("Real %s (%s) Tool Consent", strings.ToUpper(provider), model),
			User:              userEmail,
			AgentID:           clientID,
			TaskDescription:   fmt.Sprintf("Prompt: %q → LLM wants to invoke tool %s()", prompt, tc.ToolName),
			RequestedResource: fmt.Sprintf("%s https://%s%s", tc.HTTPMethod, tc.TargetHost, tc.ResourcePath),
			RequestedActions:  []string{"read"},
			TTLDisplay:        "5 minutes (ES256 DPoP Sender-Constrained)",
			RiskScore:         issuanceRisk.Score,
			RiskReasons:       issuanceRisk.TopReasons,
			ExpiresInSeconds:  120,
		},
	})

	// Wait for the user to click Approve Pass in the browser!
	var authCode string
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(800 * time.Millisecond)
		rec, ok := authServer.GetConsent(consentRec.ConsentID)
		if ok && rec.Approved {
			authCode = rec.AuthCode
			break
		}
		if ok && rec.Revoked {
			sseHub.Publish(events.TelemetryEvent{
				StepNumber: 4,
				FromLane:   "user",
				ToLane:     "as",
				Label:      "Consent Denied by User",
				Who:        userEmail + " → Auth Server",
				Headline:   "You Denied the RAR Consent Request — No Token Minted",
				PlainText:  fmt.Sprintf("Real %s agent was prevented from executing %s().", strings.ToUpper(provider), tc.ToolName),
				FlowNode:   "revoke",
				Status:     "bad",
				StatusText: "Consent Denied",
			})
			return
		}
	}
	if authCode == "" {
		return
	}

	// 4. Mint Parent DPoP Token + Exchange RFC 8693 Child Sub-Agent Token
	_, parentClaims, _, _ := authServer.ExchangeAuthCodeForTokens(authCode, pkceVerifier, parentKP.Thumbprint, issuanceRisk.Score)
	subID := clientID + "/tool-executor"
	subKP, _ := crypto.GenerateAgentDPoPKeypair(subID)
	subJWT, subClaims, _ := authServer.ExchangeSubAgentToken(parentClaims, subID, subKP.Thumbprint, "crm.read invoices.read")

	targetURI := "https://" + tc.TargetHost + tc.ResourcePath
	dpopProof, dpopClaims, _ := subKP.CreateDPoPProof(tc.HTTPMethod, targetURI, subJWT)

	sseHub.Publish(events.TelemetryEvent{
		StepNumber:   4,
		FromLane:     "as",
		ToLane:       "agent",
		Label:        "Minted DPoP + RFC 8693 Child Token",
		Who:          "Auth Server → " + subID,
		Headline:     "Consent Approved! Minted Parent Token & Exchanged RFC 8693 Child Sub-Agent Pass",
		PlainText:    fmt.Sprintf("Child sub-agent '%s' received 3-min attenuated token bound to DPoP key cnf.jkt=%s", subID, subKP.Thumbprint),
		UnderTheHood: fmt.Sprintf("Parent JTI=%s → Child JTI=%s · Family=%s", parentClaims.JTI, subClaims.JTI, subClaims.FamilyID),
		FlowNode:     "exchange",
		Status:       "ok",
		StatusText:   "RFC 8693 Minted",
		LatencyUs:    195,
		TokenRaw:     subJWT,
		TokenClaims:  subClaims,
		DPoPRaw:      dpopProof,
		DPoPClaims:   dpopClaims,
		FamilyGraph:  dag.GetSnapshot(subClaims.FamilyID),
	})

	time.Sleep(350 * time.Millisecond)

	// 5. Execute through Layer 2 Enforcement Gateway & Layer 3 Risk Engine!
	gwResp := enfGateway.Execute(gateway.ExecuteRequest{
		AccessToken:      subJWT,
		DPoPProof:        dpopProof,
		HTTPMethod:       tc.HTTPMethod,
		TargetURI:        targetURI,
		TargetHost:       tc.TargetHost,
		ResourcePath:     tc.ResourcePath,
		Action:           tc.Action,
		AmountINR:        tc.AmountINR,
		UntrustedContext: tc.Untrusted,
	})

	evType := "LIVE_LLM_GATEWAY_ALLOW"
	status := "ok"
	if !gwResp.Allowed {
		evType = "LIVE_LLM_GATEWAY_BLOCK"
		status = "bad"
		if gwResp.Verdict == risk.VerdictStepUpCIBA {
			evType = "LIVE_LLM_GATEWAY_CIBA_STEP_UP"
			status = "warn"
		}
	}

	var score float64
	var ruleHit string
	var reasons []string
	if gwResp.RiskDecision != nil {
		score = gwResp.RiskDecision.Score
		ruleHit = gwResp.RiskDecision.HardRuleHit
		reasons = gwResp.RiskDecision.TopReasons
	}

	dataStore.AppendAuditLog(store.AuditLogEntry{
		ActorUser:   userSub,
		AgentID:     subID,
		ParentAgent: clientID,
		EventType:   evType,
		Method:      tc.HTTPMethod,
		Resource:    targetURI,
		TargetHost:  tc.TargetHost,
		RiskScore:   score,
		Verdict:     string(gwResp.Verdict),
		PolicyRule:  ruleHit,
		Reasons:     reasons,
		DPoPJKT:     subKP.Thumbprint,
		TokenJTI:    subClaims.JTI,
		FamilyID:    subClaims.FamilyID,
		LatencyUs:   gwResp.GatewayLatencyUs,
	})

	sseHub.Publish(events.TelemetryEvent{
		StepNumber:   5,
		FromLane:     "gw",
		ToLane:       "res",
		Label:        fmt.Sprintf("Gateway Verdict: HTTP %d (%s)", gwResp.HTTPStatus, gwResp.Verdict),
		Who:          fmt.Sprintf("%s → Enforcement Gateway → %s", subID, tc.TargetHost),
		Headline:     fmt.Sprintf("Layer 2 Gateway Executed %s's Tool Call: HTTP %d (%s)", strings.ToUpper(provider), gwResp.HTTPStatus, strings.ToUpper(string(gwResp.Verdict))),
		PlainText:    fmt.Sprintf("Tool: %s() · Target: %s · Risk Score: %.2f · Latency: %d µs", tc.ToolName, targetURI, score, gwResp.GatewayLatencyUs),
		UnderTheHood: fmt.Sprintf("Policy=%s · RuleHit=%s", "cedar-acme-in-v14", ruleHit),
		FlowNode:     "runtime",
		Status:       status,
		StatusText:   fmt.Sprintf("HTTP %d %s", gwResp.HTTPStatus, gwResp.Verdict),
		LatencyUs:    gwResp.GatewayLatencyUs,
		TokenRaw:     subJWT,
		TokenClaims:  subClaims,
		DPoPRaw:      dpopProof,
		DPoPClaims:   dpopClaims,
		RiskDecision: gwResp.RiskDecision,
		FamilyGraph:  gwResp.FamilyGraph,
	})
}

func invokeRealLLMAPI(provider, apiKey, model, prompt string) (*parsedLLMToolCall, error) {
	if provider == "claude" {
		return invokeAnthropicClaude(apiKey, model, prompt)
	}
	return invokeGoogleGemini(apiKey, model, prompt)
}

func invokeGoogleGemini(apiKey, model, prompt string) (*parsedLLMToolCall, error) {
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", model, apiKey)
	payload := map[string]any{
		"contents": []map[string]any{
			{
				"role": "user",
				"parts": []map[string]any{
					{"text": prompt},
				},
			},
		},
		"tools": []map[string]any{
			{
				"functionDeclarations": []map[string]any{
					{
						"name":        "read_q3_invoices",
						"description": "Read Q3 financial invoices from /finance/invoices/2026-Q3",
						"parameters": map[string]any{
							"type": "OBJECT",
							"properties": map[string]any{
								"folder": map[string]string{"type": "STRING"},
							},
						},
					},
					{
						"name":        "query_customer_crm",
						"description": "Query customer CRM records from crm.acme.local",
						"parameters": map[string]any{
							"type": "OBJECT",
							"properties": map[string]any{
								"segment": map[string]string{"type": "STRING"},
							},
						},
					},
					{
						"name":        "initiate_vendor_payment",
						"description": "Transfer INR payment to a vendor via NEFT",
						"parameters": map[string]any{
							"type": "OBJECT",
							"properties": map[string]any{
								"vendor":     map[string]string{"type": "STRING"},
								"amount_inr": map[string]string{"type": "INTEGER"},
							},
						},
					},
					{
						"name":        "http_egress_export",
						"description": "Export or send data to an external domain or URL",
						"parameters": map[string]any{
							"type": "OBJECT",
							"properties": map[string]any{
								"target_host": map[string]string{"type": "STRING"},
								"path":        map[string]string{"type": "STRING"},
							},
						},
					},
				},
			},
		},
		"toolConfig": map[string]any{
			"functionCallingConfig": map[string]any{
				"mode": "ANY",
			},
		},
	}

	b, _ := json.Marshal(payload)
	resp, err := http.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("failed to reach Google Gemini API: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("Gemini API HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var parsed struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text         string `json:"text"`
					FunctionCall *struct {
						Name string         `json:"name"`
						Args map[string]any `json:"args"`
					} `json:"functionCall"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}

	for _, c := range parsed.Candidates {
		for _, p := range c.Content.Parts {
			if p.FunctionCall != nil {
				return mapToolCallToGateway(p.FunctionCall.Name, p.FunctionCall.Args, "Real Gemini functionCall decision"), nil
			}
		}
	}
	return mapToolCallToGateway("read_q3_invoices", nil, "Gemini text response mapped to default invoice read"), nil
}

func invokeAnthropicClaude(apiKey, model, prompt string) (*parsedLLMToolCall, error) {
	url := "https://api.anthropic.com/v1/messages"
	payload := map[string]any{
		"model":      model,
		"max_tokens": 512,
		"messages": []map[string]any{
			{"role": "user", "content": prompt},
		},
		"tool_choice": map[string]any{"type": "any"},
		"tools": []map[string]any{
			{
				"name":        "read_q3_invoices",
				"description": "Read Q3 financial invoices from /finance/invoices/2026-Q3",
				"input_schema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"folder": map[string]string{"type": "string"},
					},
				},
			},
			{
				"name":        "query_customer_crm",
				"description": "Query customer CRM records from crm.acme.local",
				"input_schema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"segment": map[string]string{"type": "string"},
					},
				},
			},
			{
				"name":        "initiate_vendor_payment",
				"description": "Transfer INR payment to a vendor via NEFT",
				"input_schema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"vendor":     map[string]string{"type": "string"},
						"amount_inr": map[string]string{"type": "number"},
					},
				},
			},
			{
				"name":        "http_egress_export",
				"description": "Export or send data to an external domain or URL",
				"input_schema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"target_host": map[string]string{"type": "string"},
						"path":        map[string]string{"type": "string"},
					},
				},
			},
		},
	}

	b, _ := json.Marshal(payload)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to reach Anthropic Claude API: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("Claude API HTTP %d: %s", resp.StatusCode, string(raw))
	}

	var parsed struct {
		Content []struct {
			Type  string         `json:"type"`
			Text  string         `json:"text"`
			Name  string         `json:"name"`
			Input map[string]any `json:"input"`
		} `json:"content"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}

	for _, c := range parsed.Content {
		if c.Type == "tool_use" {
			return mapToolCallToGateway(c.Name, c.Input, "Real Claude tool_use decision"), nil
		}
	}
	return mapToolCallToGateway("read_q3_invoices", nil, "Claude response mapped to invoice read"), nil
}

func mapToolCallToGateway(name string, args map[string]any, reasoning string) *parsedLLMToolCall {
	switch name {
	case "query_customer_crm":
		return &parsedLLMToolCall{
			ToolName:     name,
			TargetHost:   "crm.acme.local",
			ResourcePath: "/crm/customers",
			Action:       "read",
			HTTPMethod:   "GET",
			LLMReasoning: reasoning,
		}
	case "initiate_vendor_payment":
		amt := 45000
		if v, ok := args["amount_inr"].(float64); ok && v > 0 {
			amt = int(v)
		}
		return &parsedLLMToolCall{
			ToolName:     name,
			TargetHost:   "payments.acme.local",
			ResourcePath: "/payments/transfer",
			Action:       "payment_transfer",
			HTTPMethod:   "POST",
			AmountINR:    amt,
			LLMReasoning: reasoning,
		}
	case "http_egress_export":
		host, _ := args["target_host"].(string)
		if host == "" {
			host = "evil-exfil.example"
		}
		path, _ := args["path"].(string)
		if path == "" {
			path = "/export-all"
		}
		return &parsedLLMToolCall{
			ToolName:     name,
			TargetHost:   host,
			ResourcePath: path,
			Action:       "export_all",
			HTTPMethod:   "POST",
			Untrusted:    !strings.HasSuffix(host, ".acme.local"),
			LLMReasoning: reasoning,
		}
	default:
		return &parsedLLMToolCall{
			ToolName:     "read_q3_invoices",
			TargetHost:   "invoices.acme.local",
			ResourcePath: "/finance/invoices/2026-Q3",
			Action:       "read",
			HTTPMethod:   "GET",
			LLMReasoning: reasoning,
		}
	}
}
