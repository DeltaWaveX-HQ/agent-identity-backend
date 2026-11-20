package main

import (
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
	"time"

	"github.com/buildathon2026/agent-identity-backend/internal/crypto"
)

func main() {
	serverURL := flag.String("server", "http://localhost:8080", "Agent Identity Authorization Server & Gateway URL")
	userEmail := flag.String("user", "ajay@deltawavex.in", "Logged-in user email in your dashboard")
	agentName := flag.String("agent", "My Claude / Gemini Assistant", "Name of your AI Agent")
	modelID := flag.String("model", "gemini-2.5-flash", "Foundation model (e.g. gemini-2.5-flash, claude-opus-4.7)")
	task := flag.String("task", "Read Q3 customer CRM records and summarize invoices", "Task description shown on your dashboard consent screen")
	resourcePath := flag.String("path", "/crm/customers/2026-Q3", "Target resource path")
	targetHost := flag.String("host", "crm.acme.local", "Target host (use evil-exfil.example to test gateway block)")
	action := flag.String("action", "read", "Action to request (read, write, export_all, payment_transfer)")
	spawnChild := flag.Bool("spawn-child", true, "Also spawn a child sub-agent via RFC 8693 Token Exchange")
	flag.Parse()

	fmt.Println("================================================================================")
	fmt.Printf("🤖  CONNECTING YOUR LIVE AI AGENT (%s · %s) TO %s\n", *agentName, *modelID, *serverURL)
	fmt.Println("================================================================================")

	// 1. Generate real in-memory ES256 DPoP Keypair for the Parent Agent
	parentKP, err := crypto.GenerateAgentDPoPKeypair(*agentName)
	if err != nil {
		fatal("Failed to generate ES256 DPoP keypair: %v", err)
	}
	fmt.Printf("\n[1/5] 🔑 Generated In-Memory ES256 DPoP Keypair (RFC 9449)\n")
	fmt.Printf("      DPoP JWK Thumbprint (cnf.jkt): %s\n", parentKP.Thumbprint)

	// 2. Dynamic Client Registration (RFC 7591 DCR) -> Zero-touch agent registration!
	fmt.Printf("\n[2/5] 🪪 Auto-Registering Agent via RFC 7591 DCR (POST %s/oauth/register)...\n", *serverURL)
	dcrPayload := map[string]any{
		"client_name": *agentName,
		"owner_user":  "user:" + *userEmail,
		"model_id":    *modelID,
		"scope":       "crm.read invoices.read",
	}
	dcrResp := postJSON(*serverURL+"/oauth/register", dcrPayload, "")
	clientID, _ := dcrResp["client_id"].(string)
	fmt.Printf("      ✅ Registered! Assigned Client ID: %s\n", clientID)
	fmt.Printf("      👉 Check your Dashboard -> 'Applications & Agents': %s is now live!\n", clientID)

	// 3. Initiate OAuth 2.1 + PKCE + RFC 9396 Rich Authorization Request (RAR) Consent
	pkceVerifier := fmt.Sprintf("pkce_live_verifier_%d", time.Now().UnixNano())
	vHash := sha256.Sum256([]byte(pkceVerifier))
	pkceChallenge := base64.RawURLEncoding.EncodeToString(vHash[:])

	fmt.Printf("\n[3/5] 📱 Requesting User Consent on Dashboard (POST %s/oauth/authorize)...\n", *serverURL)
	authPayload := map[string]any{
		"client_id":             clientID,
		"user_sub":              "user:" + *userEmail,
		"task":                  *task,
		"scope":                 "crm.read invoices.read",
		"aud":                   "https://" + *targetHost + *resourcePath,
		"code_challenge":        pkceChallenge,
		"code_challenge_method": "S256",
		"authorization_details": []map[string]any{
			{
				"type":           "file_access",
				"locations":      []string{*resourcePath},
				"actions":        []string{*action},
				"data_residency": "IN",
			},
		},
	}
	authResp := postJSON(*serverURL+"/oauth/authorize", authPayload, "")
	consentRec, _ := authResp["consent_record"].(map[string]any)
	consentID, _ := consentRec["consent_id"].(string)

	fmt.Println("      ------------------------------------------------------------------------")
	fmt.Printf("      ⏳ WAITING FOR YOU TO APPROVE CONSENT (%s) IN YOUR DASHBOARD!\n", consentID)
	fmt.Println("      👉 Go to http://localhost:3000 and click 'Approve Pass' on the Consent banner/phone!")
	fmt.Println("      ------------------------------------------------------------------------")

	var authCode string
	for {
		time.Sleep(1200 * time.Millisecond)
		statusResp := getJSON(fmt.Sprintf("%s/api/v1/oauth/consent-status?consent_id=%s", *serverURL, consentID))
		if approved, _ := statusResp["approved"].(bool); approved {
			authCode, _ = statusResp["auth_code"].(string)
			fmt.Printf("      ✅ Consent Approved by %s! Received one-time Auth Code: %s\n", *userEmail, authCode)
			break
		}
		if revoked, _ := statusResp["revoked"].(bool); revoked {
			fatal("      ❌ Consent was denied/revoked from the dashboard.")
		}
	}

	// 4. Exchange Authorization Code + PKCE Verifier + Signed DPoP Proof for Access Token
	fmt.Printf("\n[4/5] 🔐 Swapping Code + PKCE + DPoP Proof for ES256 Access Token (POST %s/oauth/token)...\n", *serverURL)
	dpopTokenProof, _, _ := parentKP.CreateDPoPProof("POST", *serverURL+"/oauth/token", "")
	tokResp := postJSON(*serverURL+"/oauth/token", map[string]any{
		"grant_type":    "authorization_code",
		"client_id":     clientID,
		"code":          authCode,
		"code_verifier": pkceVerifier,
	}, dpopTokenProof)

	activeToken, _ := tokResp["access_token"].(string)
	activeKP := parentKP
	fmt.Printf("      ✅ Parent Agent Access Token Minted (DPoP Bound to cnf.jkt=%s)\n", parentKP.Thumbprint)

	if *spawnChild {
		subAgentID := clientID + "/sub-worker"
		subKP, _ := crypto.GenerateAgentDPoPKeypair(subAgentID)
		fmt.Printf("\n[4b/5] 🌿 Spawning Child Sub-Agent (%s) via RFC 8693 Token Exchange...\n", subAgentID)
		subProof, _, _ := subKP.CreateDPoPProof("POST", *serverURL+"/oauth/token", "")
		exResp := postJSON(*serverURL+"/oauth/token", map[string]any{
			"grant_type":      "urn:ietf:params:oauth:grant-type:token-exchange",
			"subject_token":   activeToken,
			"actor_client_id": subAgentID,
			"scope":           "crm.read",
		}, subProof)
		if subTok, ok := exResp["access_token"].(string); ok && subTok != "" {
			activeToken = subTok
			activeKP = subKP
			fmt.Printf("      ✅ Child Sub-Agent Token Minted (3-min attenuated TTL + nested 'act' chain)!\n")
		}
	}

	// 5. Execute Tool / API Call through the Layer 2 Enforcement Gateway
	targetURI := "https://" + *targetHost + *resourcePath
	fmt.Printf("\n[5/5] 💂 Executing Tool Call through Layer 2 Enforcement Gateway (POST %s/api/v1/gateway/execute)...\n", *serverURL)
	fmt.Printf("      Target: GET %s (Action: %s)\n", targetURI, *action)

	gwProof, _, _ := activeKP.CreateDPoPProof("GET", targetURI, activeToken)
	gwResp := postJSON(*serverURL+"/api/v1/gateway/execute", map[string]any{
		"access_token":      activeToken,
		"dpop_proof":        gwProof,
		"http_method":       "GET",
		"target_uri":        targetURI,
		"target_host":       *targetHost,
		"resource_path":     *resourcePath,
		"action":            *action,
		"untrusted_context": strings.Contains(*targetHost, "evil") || *action == "export_all",
	}, "")

	pretty, _ := json.MarshalIndent(gwResp, "      ", "  ")
	fmt.Printf("\n      Gateway Response:\n      %s\n", string(pretty))
	fmt.Println("\n================================================================================")
	fmt.Println("✨ Done! Look at your dashboard at http://localhost:3000 to inspect the live")
	fmt.Println("   trace, user -> agent JSON hierarchy, and SIEM audit log of your agent's run.")
	fmt.Println("================================================================================")
}

func postJSON(url string, payload any, dpopHeader string) map[string]any {
	b, _ := json.Marshal(payload)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		fatal("request error: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if dpopHeader != "" {
		req.Header.Set("DPoP", dpopHeader)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fatal("failed to connect to %s: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

func getJSON(url string) map[string]any {
	resp, err := http.Get(url)
	if err != nil {
		fatal("failed to GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return out
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
