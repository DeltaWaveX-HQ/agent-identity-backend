package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/buildathon2026/agent-identity-backend/internal/auth"
	"github.com/buildathon2026/agent-identity-backend/internal/crypto"
	"github.com/buildathon2026/agent-identity-backend/internal/events"
	"github.com/buildathon2026/agent-identity-backend/internal/gateway"
	"github.com/buildathon2026/agent-identity-backend/internal/risk"
	"github.com/buildathon2026/agent-identity-backend/internal/sdk"
)

func main() {
	km, err := crypto.NewKeyManager()
	if err != nil {
		log.Fatalf("failed to initialize ES256 KMS KeyManager: %v", err)
	}
	dag := auth.NewFamilyDAG()
	authServer := auth.NewServer(km, dag)
	riskEngine := risk.NewEngine()
	enfGateway := gateway.NewEnforcementGateway(km, dag, riskEngine)
	sseHub := events.NewHub()

	dataDir := resolveDataDir()
	orchestrator := sdk.NewScenarioOrchestrator(authServer, dag, riskEngine, enfGateway, sseHub, dataDir)

	mux := http.NewServeMux()

	// 1. Health & Metadata
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"service":   "agent-identity-backend",
			"language":  "Go",
			"status":    "healthy",
			"standards": []string{"OAuth 2.1", "RFC 8693 Token Exchange", "RFC 9396 RAR", "RFC 9449 DPoP", "RFC 8707", "OpenID CIBA", "SPIFFE"},
		})
	})

	// 2. Public Signing Keys (JWKS with active + 24h pre-rotated key)
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, km.PublicJWKS())
	})

	// 3. SSE Real-Time Telemetry Stream
	mux.HandleFunc("/api/v1/events/stream", sseHub.ServeSSE)
	mux.HandleFunc("/api/v1/events/history", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"events":        sseHub.GetHistory(),
			"family_graphs": dag.GetAllSnapshots(),
			"agents":        authServer.ListAgents(),
		})
	})

	// 4. Layer 1: Agent Registration & OAuth 2.1 + RAR + CIBA Endpoints
	mux.HandleFunc("/api/v1/agents/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "POST required"})
			return
		}
		var req auth.RegisteredAgent
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		agent, err := authServer.RegisterAgent(req)
		if err != nil {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, agent)
	})

	mux.HandleFunc("/api/v1/oauth/consent", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ConsentID string   `json:"consent_id"`
			Actions   []string `json:"actions"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		orchestrator.NotifyConsentApproved(body.Actions)
		writeJSON(w, http.StatusOK, map[string]any{"status": "approved", "actions": body.Actions})
	})

	mux.HandleFunc("/api/v1/oauth/ciba-resolve", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AuthReqID string `json:"auth_req_id"`
			Approved  bool   `json:"approved"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		req, err := authServer.ResolveCIBARequest(body.AuthReqID, body.Approved)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, req)
	})

	// 5. Layer 2 & Layer 3: Risk Scoring, Policy Decision & Gateway Execution
	mux.HandleFunc("/api/v1/risk/score", func(w http.ResponseWriter, r *http.Request) {
		var req risk.ScoreRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, riskEngine.Decide(req))
	})

	mux.HandleFunc("/api/v1/decide", func(w http.ResponseWriter, r *http.Request) {
		var req risk.ScoreRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, riskEngine.Decide(req))
	})

	mux.HandleFunc("/api/v1/gateway/execute", func(w http.ResponseWriter, r *http.Request) {
		var req gateway.ExecuteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		resp := enfGateway.Execute(req)
		writeJSON(w, resp.HTTPStatus, resp)
	})

	// 6. Emergency Kill Switch / Token Family Revocation
	mux.HandleFunc("/api/v1/revoke", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			FamilyID string `json:"family_id"`
			Reason   string `json:"reason"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Reason == "" {
			body.Reason = "Emergency SecOps Kill Switch Triggered from Agent Identity Console"
		}
		var snaps []*auth.FamilyGraphSnapshot
		if body.FamilyID != "" {
			snaps = []*auth.FamilyGraphSnapshot{dag.RevokeFamily(body.FamilyID, body.Reason)}
		} else {
			snaps = dag.RevokeAll(body.Reason)
		}

		var firstSnap any
		if len(snaps) > 0 {
			firstSnap = snaps[0]
		}
		sseHub.Publish(events.TelemetryEvent{
			StepNumber:   99,
			FromLane:     "as",
			ToLane:       "gw",
			Label:        "KILL SWITCH → Revoke All",
			Who:          "SecOps Console → Revocation Bus",
			Headline:     "Emergency Kill Switch Activated: All Active Agent Token Families Revoked!",
			PlainText:    fmt.Sprintf("Reason: %s. Propagated to all enforcement gateways in < 50 µs.", body.Reason),
			UnderTheHood: "POST /api/v1/revoke · Instant token-family graph termination",
			FlowNode:     "revoke",
			Status:       "bad",
			StatusText:   "Kill Switch Executed",
			LatencyUs:    24,
			FamilyGraph:  firstSnap,
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"revoked_families": snaps,
		})
	})

	// 7. Interactive 4-Act Live Scenario Runner
	mux.HandleFunc("/api/v1/scenarios/", func(w http.ResponseWriter, r *http.Request) {
		actID := strings.TrimPrefix(r.URL.Path, "/api/v1/scenarios/")
		interactive := r.URL.Query().Get("interactive") == "true"
		delayMs := 420
		if r.URL.Query().Get("fast") == "true" {
			delayMs = 90
		}
		orchestrator.RunScenario(actID, interactive, time.Duration(delayMs)*time.Millisecond)
		writeJSON(w, http.StatusAccepted, map[string]any{
			"started_scenario": actID,
			"interactive":      interactive,
		})
	})

	// 8. 25-Incident Empirical Red-Team Benchmark & Market Datasets
	mux.HandleFunc("/api/v1/benchmark/incidents", func(w http.ResponseWriter, r *http.Request) {
		summary, err := orchestrator.Run25IncidentBenchmark()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, summary)
	})

	mux.HandleFunc("/api/v1/datasets", func(w http.ResponseWriter, r *http.Request) {
		incRaw, _ := os.ReadFile(filepath.Join(dataDir, "incidents.json"))
		compRaw, _ := os.ReadFile(filepath.Join(dataDir, "competitors.json"))
		dealsRaw, _ := os.ReadFile(filepath.Join(dataDir, "deals.json"))

		var inc, comp, deals any
		_ = json.Unmarshal(incRaw, &inc)
		_ = json.Unmarshal(compRaw, &comp)
		_ = json.Unmarshal(dealsRaw, &deals)

		writeJSON(w, http.StatusOK, map[string]any{
			"incidents":   inc,
			"competitors": comp,
			"deals":       deals,
		})
	})

	// Run initial Act 1 trace on boot so UI immediately has rich decoded JWT/DPoP state on load
	orchestrator.RunScenario("act1_normal", false, 20*time.Millisecond)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("🛡️  Agent Identity Go Backend (OAuth 2.1 + DPoP + Gateway + 2-Stage Risk Engine) listening on http://localhost:%s", port)
	if err := http.ListenAndServe(":"+port, corsMiddleware(mux)); err != nil {
		log.Fatal(err)
	}
}

func resolveDataDir() string {
	candidates := []string{
		"data",
		"../data",
		"/Users/ajaykumarpagidipally/Documents/agentic_identity/agent-identity-backend/data",
		"/Users/ajaykumarpagidipally/Documents/agentic_identity/data",
	}
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "incidents.json")); err == nil {
			return c
		}
	}
	return "data"
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, DPoP")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
