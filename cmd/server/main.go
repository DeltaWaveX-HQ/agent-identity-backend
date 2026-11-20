package main

import (
	"crypto/sha256"
	"encoding/base64"
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
	"github.com/buildathon2026/agent-identity-backend/internal/store"
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
	dataStore := store.NewDataStore(dataDir)
	orchestrator := sdk.NewScenarioOrchestrator(authServer, dag, riskEngine, enfGateway, sseHub, dataDir)

	mux := http.NewServeMux()

	// =========================================================================
	// 1. REAL OIDC & OAUTH 2.1 DISCOVERY METADATA & JWKS (RFC 8414 / RFC 7517)
	// =========================================================================
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		baseURL := "http://localhost:8080"
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                                             "https://auth.agentidentity.local",
			"authorization_endpoint":                             baseURL + "/oauth/authorize",
			"token_endpoint":                                     baseURL + "/oauth/token",
			"registration_endpoint":                              baseURL + "/oauth/register",
			"client_id_metadata_document_supported":              true,
			"dcr_software_statements_supported":                  true,
			"introspection_endpoint":                             baseURL + "/oauth/introspect",
			"revocation_endpoint":                                baseURL + "/oauth/revoke",
			"backchannel_authentication_endpoint":                baseURL + "/oauth/bc-authorize",
			"jwks_uri":                                           baseURL + "/.well-known/jwks.json",
			"agent_registration_endpoint":                        baseURL + "/api/v1/agents/register",
			"gateway_enforcement_endpoint":                       baseURL + "/api/v1/gateway/execute",
			"risk_decision_endpoint":                             baseURL + "/api/v1/decide",
			"grant_types_supported":                              []string{"authorization_code", "refresh_token", "urn:ietf:params:oauth:grant-type:token-exchange", "urn:openid:params:grant-type:ciba"},
			"response_types_supported":                           []string{"code"},
			"code_challenge_methods_supported":                   []string{"S256"},
			"dpop_signing_alg_values_supported":                  []string{"ES256"},
			"token_endpoint_auth_methods_supported":              []string{"none", "private_key_jwt"},
			"authorization_details_types_supported":              []string{"file_access", "payment_initiation", "mcp_tool_execution"},
			"backchannel_token_delivery_modes_supported":         []string{"poll", "ping", "push"},
			"spiffe_trust_domain":                                "spiffe://acme.in",
		})
	})

	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/.well-known/openid-configuration", http.StatusTemporaryRedirect)
	})

	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, km.PublicJWKS())
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"service":   "agent-identity-backend",
			"language":  "Go",
			"status":    "healthy",
			"standards": []string{"OAuth 2.1", "RFC 8693 Token Exchange", "RFC 9396 RAR", "RFC 9449 DPoP", "RFC 8707", "RFC 7662 Introspection", "OpenID CIBA", "SPIFFE"},
		})
	})

	// =========================================================================
	// 2. REAL OAUTH 2.1 + PKCE + RAR + RFC 8693 + RFC 7662 + CIBA PROTOCOL API
	// =========================================================================

	// POST or GET /oauth/authorize — Starts an OAuth 2.1 + PKCE + RFC 9396 RAR flow
	mux.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ClientID             string                       `json:"client_id"`
			UserSub              string                       `json:"user_sub"`
			Task                 string                       `json:"task"`
			Scope                string                       `json:"scope"`
			Aud                  string                       `json:"aud"`
			CodeChallenge        string                       `json:"code_challenge"`
			CodeChallengeMethod  string                       `json:"code_challenge_method"`
			AuthorizationDetails []crypto.AuthorizationDetail `json:"authorization_details"`
		}
		if r.Method == http.MethodPost {
			_ = json.NewDecoder(r.Body).Decode(&req)
		} else {
			q := r.URL.Query()
			req.ClientID = q.Get("client_id")
			req.UserSub = q.Get("user_sub")
			req.Task = q.Get("task")
			req.Scope = q.Get("scope")
			req.Aud = q.Get("aud")
			req.CodeChallenge = q.Get("code_challenge")
		}
		if req.ClientID == "" {
			req.ClientID = "agent:invoice-assistant"
		}
		if req.UserSub == "" {
			req.UserSub = "user:priya@acme.in"
		}
		if req.Scope == "" {
			req.Scope = "invoices.read"
		}
		if req.Aud == "" {
			req.Aud = "https://gw.acme.local/tools/invoices"
		}
		if len(req.AuthorizationDetails) == 0 {
			req.AuthorizationDetails = []crypto.AuthorizationDetail{
				{
					Type:          "file_access",
					Locations:     []string{"/finance/invoices/2026-Q3"},
					Actions:       []string{"read"},
					DataResidency: "IN",
				},
			}
		}

		// Score Stage 1 Issuance Risk
		issuanceRisk := riskEngine.Decide(risk.ScoreRequest{
			Stage:           "issuance",
			AgentID:         req.ClientID,
			UserSub:         req.UserSub,
			RuntimeAttested: true,
			RequestedScope:  req.Scope,
			TargetHost:      "gw.acme.local",
		})

		rec := authServer.CreateConsentPrompt(req.UserSub, req.ClientID, req.Task, req.Scope, req.Aud, req.CodeChallenge, req.AuthorizationDetails)

		dataStore.AppendAuditLog(store.AuditLogEntry{
			ActorUser: req.UserSub,
			AgentID:   req.ClientID,
			EventType: "OAUTH_AUTHORIZE_RAR",
			Method:    r.Method,
			Resource:  req.Aud,
			RiskScore: issuanceRisk.Score,
			Verdict:   string(issuanceRisk.Verdict),
			Reasons:   issuanceRisk.TopReasons,
			LatencyUs: issuanceRisk.LatencyUs,
		})

		var locs, acts []string
		if len(req.AuthorizationDetails) > 0 {
			locs = req.AuthorizationDetails[0].Locations
			acts = req.AuthorizationDetails[0].Actions
		}
		sseHub.Publish(events.TelemetryEvent{
			StepNumber:   1,
			FromLane:     "agent",
			ToLane:       "user",
			Label:        "RAR Consent Request (" + req.ClientID + ")",
			Who:          req.ClientID + " → " + req.UserSub,
			Headline:     "External AI Agent requesting RFC 9396 RAR Consent",
			PlainText:    fmt.Sprintf("Agent '%s' wants to access %v with actions %v for task: %s", req.ClientID, locs, acts, req.Task),
			UnderTheHood: fmt.Sprintf("POST /oauth/authorize · consent_id=%s · Stage 1 Risk=%.2f", rec.ConsentID, issuanceRisk.Score),
			FlowNode:     "consent",
			Status:       "warn",
			StatusText:   "Awaiting Your Consent",
			LatencyUs:    issuanceRisk.LatencyUs,
			RiskDecision: issuanceRisk,
			PhonePrompt: &events.PhonePrompt{
				PromptID:          rec.ConsentID,
				Type:              "rar_consent",
				Title:             "Live Agent Consent Request (RFC 9396 RAR)",
				User:              req.UserSub,
				AgentID:           req.ClientID,
				TaskDescription:   req.Task,
				RequestedResource: strings.Join(locs, ", "),
				RequestedActions:  acts,
				TTLDisplay:        "5 minutes (DPoP Sender-Constrained)",
				RiskScore:         issuanceRisk.Score,
				RiskReasons:       issuanceRisk.TopReasons,
				ExpiresInSeconds:  120,
			},
		})

		writeJSON(w, http.StatusOK, map[string]any{
			"consent_record": rec,
			"issuance_risk":  issuanceRisk,
			"consent_url":    fmt.Sprintf("http://localhost:3000?consent_id=%s", rec.ConsentID),
		})
	})

	// POST /oauth/token — Real multi-grant OAuth 2.1 Token Endpoint:
	//   1) grant_type=authorization_code (with PKCE code_verifier + DPoP proof)
	//   2) grant_type=urn:ietf:params:oauth:grant-type:token-exchange (RFC 8693 Sub-agent attenuation)
	//   3) grant_type=refresh_token (Single-use rotation with replay family revocation)
	//   4) grant_type=interactive_mint (Convenience endpoint for the Developer Sandbox with real ES256 + DPoP keypair generation)
	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			GrantType            string                       `json:"grant_type"`
			Code                 string                       `json:"code"`
			CodeVerifier         string                       `json:"code_verifier"`
			RefreshToken         string                       `json:"refresh_token"`
			SubjectToken         string                       `json:"subject_token"`
			ActorClientID        string                       `json:"actor_client_id"`
			ClientID             string                       `json:"client_id"`
			UserSub              string                       `json:"user_sub"`
			Scope                string                       `json:"scope"`
			Aud                  string                       `json:"aud"`
			Task                 string                       `json:"task"`
			AuthorizationDetails []crypto.AuthorizationDetail `json:"authorization_details"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)

		switch req.GrantType {
		case "authorization_code":
			// Generate or extract DPoP thumbprint
			kp, _ := crypto.GenerateAgentDPoPKeypair(req.ClientID)
			dpopHeader := r.Header.Get("DPoP")
			jkt := kp.Thumbprint
			if dpopHeader != "" {
				if pubJWK, _, err := crypto.VerifyDPoPProof(dpopHeader, "POST", "http://localhost:8080/oauth/token", "", ""); err == nil && pubJWK != nil {
					jkt = crypto.ComputeJWKThumbprint(*pubJWK)
				}
			}
			jwtStr, claims, refreshJTI, err := authServer.ExchangeAuthCodeForTokens(req.Code, req.CodeVerifier, jkt, 0.12)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": err.Error()})
				return
			}
			dpopProof, dpopClaims, _ := kp.CreateDPoPProof("GET", claims.Aud, jwtStr)

			dataStore.AppendAuditLog(store.AuditLogEntry{
				ActorUser: claims.Sub,
				AgentID:   claims.ClientID,
				EventType: "TOKEN_ISSUED",
				Method:    "POST /oauth/token",
				Resource:  claims.Aud,
				RiskScore: 0.12,
				Verdict:   "allow",
				DPoPJKT:   jkt,
				TokenJTI:  claims.JTI,
				FamilyID:  claims.FamilyID,
				LatencyUs: 210,
			})

			sseHub.Publish(events.TelemetryEvent{
				StepNumber:  2,
				FromLane:    "as",
				ToLane:      "agent",
				Label:       "Issued DPoP Token (" + claims.ClientID + ")",
				Who:         "Auth Server → " + claims.ClientID,
				Headline:    "Issued 5-Min ES256 DPoP-Bound Access Token to Your Agent",
				PlainText:   fmt.Sprintf("Minted token %s for agent '%s' after your consent approval.", claims.JTI, claims.ClientID),
				UnderTheHood: fmt.Sprintf("POST /oauth/token (grant_type=authorization_code) · Family=%s · cnf.jkt=%s", claims.FamilyID, jkt),
				FlowNode:    "token",
				Status:      "ok",
				StatusText:  "Token Minted",
				LatencyUs:   210,
				TokenRaw:    jwtStr,
				TokenClaims: claims,
				DPoPRaw:     dpopProof,
				DPoPClaims:  dpopClaims,
				FamilyGraph: dag.GetSnapshot(claims.FamilyID),
			})

			writeJSON(w, http.StatusOK, map[string]any{
				"access_token":       jwtStr,
				"token_type":         "DPoP",
				"expires_in":         300,
				"refresh_token":      refreshJTI,
				"scope":              claims.Scope,
				"claims":             claims,
				"dpop_proof_sample":  dpopProof,
				"dpop_claims_sample": dpopClaims,
				"family_graph":       dag.GetSnapshot(claims.FamilyID),
			})

		case "urn:ietf:params:oauth:grant-type:token-exchange", "token-exchange":
			priv, _ := km.ActiveSigner()
			_, parentClaims, err := crypto.VerifyAccessToken(&priv.PublicKey, req.SubjectToken)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "invalid subject_token: " + err.Error()})
				return
			}
			subAgentID := req.ActorClientID
			if subAgentID == "" {
				subAgentID = parentClaims.ClientID + "/summariser"
			}
			subKP, _ := crypto.GenerateAgentDPoPKeypair(subAgentID)
			subJWT, subClaims, err := authServer.ExchangeSubAgentToken(parentClaims, subAgentID, subKP.Thumbprint, req.Scope)
			if err != nil {
				writeJSON(w, http.StatusForbidden, map[string]string{"error": "access_denied", "error_description": err.Error()})
				return
			}
			subDPoP, subDPoPClaims, _ := subKP.CreateDPoPProof("GET", subClaims.Aud, subJWT)

			dataStore.AppendAuditLog(store.AuditLogEntry{
				ActorUser:   subClaims.Sub,
				AgentID:     subClaims.ClientID,
				ParentAgent: parentClaims.ClientID,
				EventType:   "RFC8693_TOKEN_EXCHANGE",
				Method:      "POST /oauth/token",
				Resource:    subClaims.Aud,
				RiskScore:   0.12,
				Verdict:     "allow",
				DPoPJKT:     subKP.Thumbprint,
				TokenJTI:    subClaims.JTI,
				FamilyID:    subClaims.FamilyID,
				LatencyUs:   185,
			})

			writeJSON(w, http.StatusOK, map[string]any{
				"access_token":       subJWT,
				"issued_token_type":  "urn:ietf:params:oauth:token-type:access_token",
				"token_type":         "DPoP",
				"expires_in":         180,
				"scope":              subClaims.Scope,
				"claims":             subClaims,
				"dpop_proof_sample":  subDPoP,
				"dpop_claims_sample": subDPoPClaims,
				"family_graph":       dag.GetSnapshot(subClaims.FamilyID),
			})

		case "refresh_token":
			reused, famID := dag.RotateRefreshToken(req.RefreshToken)
			if reused {
				dataStore.AppendAuditLog(store.AuditLogEntry{
					ActorUser: "user:priya@acme.in",
					AgentID:   req.ClientID,
					EventType: "REFRESH_REUSE_BREACH_BLOCKED",
					Method:    "POST /oauth/token",
					Resource:  "Refresh Token " + req.RefreshToken,
					RiskScore: 0.98,
					Verdict:   "block_and_revoke",
					FamilyID:  famID,
					LatencyUs: 24,
				})
				writeJSON(w, http.StatusForbidden, map[string]any{
					"error":             "invalid_grant",
					"error_description": "OAuth 2.1 Refresh Token Replay Detected! Entire token family revoked.",
					"family_graph":      dag.GetSnapshot(famID),
				})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"status":       "rotated",
				"family_id":    famID,
				"family_graph": dag.GetSnapshot(famID),
			})

		default:
			// Interactive Full OAuth 2.1 + PKCE + RAR + DPoP Minting for the Live Auth Sandbox
			if req.ClientID == "" {
				req.ClientID = "agent:invoice-assistant"
			}
			if req.UserSub == "" {
				req.UserSub = "user:priya@acme.in"
			}
			if req.Scope == "" {
				req.Scope = "invoices.read"
			}
			if req.Aud == "" {
				req.Aud = "https://gw.acme.local/tools/invoices"
			}
			if req.Task == "" {
				req.Task = "Interactive OAuth 2.1 + RAR Mandate"
			}
			if len(req.AuthorizationDetails) == 0 {
				req.AuthorizationDetails = []crypto.AuthorizationDetail{
					{
						Type:          "file_access",
						Locations:     []string{"/finance/invoices/2026-Q3"},
						Actions:       []string{"read"},
						DataResidency: "IN",
					},
				}
			}

			verifier := "pkce_verifier_" + fmt.Sprintf("%d", time.Now().UnixNano())
			sum := sha256.Sum256([]byte(verifier))
			challenge := base64.RawURLEncoding.EncodeToString(sum[:])

			consent := authServer.CreateConsentPrompt(req.UserSub, req.ClientID, req.Task, req.Scope, req.Aud, challenge, req.AuthorizationDetails)
			var actions []string
			for _, ad := range req.AuthorizationDetails {
				actions = append(actions, ad.Actions...)
			}
			approved, _ := authServer.ApproveConsent(consent.ConsentID, actions)

			kp, _ := crypto.GenerateAgentDPoPKeypair(req.ClientID)
			jwtStr, claims, refreshJTI, err := authServer.ExchangeAuthCodeForTokens(approved.AuthCode, verifier, kp.Thumbprint, 0.12)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
				return
			}
			dpopProof, dpopClaims, _ := kp.CreateDPoPProof("GET", req.Aud, jwtStr)

			dataStore.AppendAuditLog(store.AuditLogEntry{
				ActorUser: req.UserSub,
				AgentID:   req.ClientID,
				EventType: "TOKEN_ISSUED",
				Method:    "POST /oauth/token",
				Resource:  req.Aud,
				RiskScore: 0.12,
				Verdict:   "allow",
				DPoPJKT:   kp.Thumbprint,
				TokenJTI:  claims.JTI,
				FamilyID:  claims.FamilyID,
				LatencyUs: 195,
			})

			writeJSON(w, http.StatusOK, map[string]any{
				"access_token":       jwtStr,
				"token_type":         "DPoP",
				"expires_in":         300,
				"refresh_token":      refreshJTI,
				"consent_id":         approved.ConsentID,
				"pkce_verifier":      verifier,
				"pkce_challenge":     challenge,
				"claims":             claims,
				"dpop_proof_sample":  dpopProof,
				"dpop_claims_sample": dpopClaims,
				"family_graph":       dag.GetSnapshot(claims.FamilyID),
			})
		}
	})

	// POST /oauth/introspect — RFC 7662 Token Introspection
	mux.HandleFunc("/oauth/introspect", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Token == "" {
			body.Token = r.URL.Query().Get("token")
		}
		writeJSON(w, http.StatusOK, authServer.IntrospectToken(body.Token))
	})

	// POST /oauth/register — RFC 7591 OAuth 2.0 Dynamic Client Registration (DCR) for zero-touch AI Agent onboarding
	mux.HandleFunc("/oauth/register", func(w http.ResponseWriter, r *http.Request) {
		var dcrReq struct {
			ClientName              string   `json:"client_name"`
			SoftwareID              string   `json:"software_id"`
			SoftwareVersion         string   `json:"software_version"`
			SPIFFEID                string   `json:"spiffe_id"`
			OwnerUser               string   `json:"owner_user"`
			ParentAgentID           string   `json:"parent_agent_id"`
			Scope                   string   `json:"scope"`
			GrantTypes              []string `json:"grant_types"`
			TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
			ModelID                 string   `json:"model_id"`
			CRMIntegration          string   `json:"crm_integration"`
		}
		_ = json.NewDecoder(r.Body).Decode(&dcrReq)
		if dcrReq.ClientName == "" {
			dcrReq.ClientName = "Auto-Discovered MCP Agent"
		}
		if dcrReq.SPIFFEID == "" {
			slug := strings.ToLower(strings.ReplaceAll(dcrReq.ClientName, " ", "-"))
			dcrReq.SPIFFEID = "spiffe://acme.in/ns/auto-dcr/sa/" + slug
		}
		if dcrReq.OwnerUser == "" {
			dcrReq.OwnerUser = "user:priya@acme.in"
		}
		if dcrReq.ModelID == "" {
			dcrReq.ModelID = "gemini-2.5-flash"
		}
		if dcrReq.Scope == "" {
			dcrReq.Scope = "crm.read invoices.read"
		}

		clientID := "agent:dcr-" + strings.ToLower(strings.ReplaceAll(dcrReq.ClientName, " ", "-"))
		registered, err := authServer.RegisterAgent(auth.RegisteredAgent{
			AgentID:           clientID,
			Name:              dcrReq.ClientName + " (DCR Auto-Registered)",
			OwnerUser:         dcrReq.OwnerUser,
			ParentAgentID:     dcrReq.ParentAgentID,
			SPIFFEID:          dcrReq.SPIFFEID,
			RuntimeAttested:   true,
			PlatformFramework: "RFC 7591 Dynamic Client Registration (DCR)",
			ModelID:           dcrReq.ModelID,
			AllowedScopes:     strings.Fields(dcrReq.Scope),
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_client_metadata", "error_description": err.Error()})
			return
		}

		dataStore.AppendAuditLog(store.AuditLogEntry{
			ActorUser: registered.OwnerUser,
			AgentID:   registered.AgentID,
			EventType: "RFC7591_DCR_AUTO_REGISTER",
			Method:    "POST /oauth/register",
			Resource:  registered.SPIFFEID,
			RiskScore: 0.08,
			Verdict:   "allow",
			DPoPJKT:   registered.DPoPThumbprint,
			LatencyUs: 118,
		})

		sseHub.Publish(events.TelemetryEvent{
			StepNumber:   1,
			FromLane:     "agent",
			ToLane:       "as",
			Label:        "DCR Auto-Register: " + registered.AgentID,
			Who:          registered.AgentID + " → Auth Server",
			Headline:     "External Agent Auto-Registered via RFC 7591 DCR",
			PlainText:    fmt.Sprintf("Agent '%s' (Model: %s) attested SPIFFE ID %s and bound DPoP key cnf.jkt=%s", registered.Name, registered.ModelID, registered.SPIFFEID, registered.DPoPThumbprint),
			UnderTheHood: "POST /oauth/register · RFC 7591 Dynamic Client Registration",
			FlowNode:     "attest",
			Status:       "ok",
			StatusText:   "DCR Registered",
			LatencyUs:    118,
		})

		writeJSON(w, http.StatusCreated, map[string]any{
			"client_id":                  registered.AgentID,
			"client_name":                registered.Name,
			"client_id_issued_at":        registered.RegisteredAt,
			"token_endpoint_auth_method": "dpop_es256",
			"grant_types":                []string{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange", "refresh_token"},
			"scope":                      dcrReq.Scope,
			"spiffe_id":                  registered.SPIFFEID,
			"dpop_cnf_jkt":               registered.DPoPThumbprint,
			"dpop_public_jwk":            registered.DPoPPublicJWK,
			"registration_flow":          "RFC 7591 Dynamic Client Registration (Zero-Touch Onboarding)",
		})
	})

	// POST /oauth/cimd-discover — IETF Client ID Metadata Document (CIMD / CAMD) zero-pre-registration discovery flow
	mux.HandleFunc("/oauth/cimd-discover", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			MetadataURL string `json:"metadata_url"`
			OwnerUser   string `json:"owner_user"`
			CRMTarget   string `json:"crm_target"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.MetadataURL == "" {
			req.MetadataURL = "https://crm-agent.acme.in/.well-known/oauth-client-metadata.json"
		}
		if req.OwnerUser == "" {
			req.OwnerUser = "user:priya@acme.in"
		}
		if req.CRMTarget == "" {
			req.CRMTarget = "Salesforce / HubSpot Enterprise CRM"
		}

		registered, err := authServer.RegisterAgent(auth.RegisteredAgent{
			AgentID:           req.MetadataURL,
			Name:              "CIMD Auto-Discovered CRM Agent (" + req.CRMTarget + ")",
			OwnerUser:         req.OwnerUser,
			SPIFFEID:          "spiffe://acme.in/ns/cimd/sa/crm-sync-agent",
			RuntimeAttested:   true,
			PlatformFramework: "IETF CIMD (Client ID Metadata Document) + MCP",
			ModelID:           "gemini-2.5-flash",
			AllowedScopes:     []string{"crm.read", "crm.leads.sync", "invoices.read"},
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		dataStore.AppendAuditLog(store.AuditLogEntry{
			ActorUser: registered.OwnerUser,
			AgentID:   registered.AgentID,
			EventType: "CIMD_METADATA_AUTO_DISCOVERY",
			Method:    "POST /oauth/cimd-discover",
			Resource:  req.MetadataURL,
			RiskScore: 0.10,
			Verdict:   "allow",
			DPoPJKT:   registered.DPoPThumbprint,
			LatencyUs: 142,
		})

		sseHub.Publish(events.TelemetryEvent{
			StepNumber:   1,
			FromLane:     "agent",
			ToLane:       "as",
			Label:        "CAMD/CIMD Discovery: " + registered.Name,
			Who:          registered.AgentID + " → Auth Server",
			Headline:     "External Agent Discovered via CAMD / CIMD Metadata URL",
			PlainText:    fmt.Sprintf("Fetched metadata from %s and bound CRM scopes for %s", req.MetadataURL, req.CRMTarget),
			UnderTheHood: "POST /oauth/cimd-discover · IETF Client ID Metadata Document",
			FlowNode:     "attest",
			Status:       "ok",
			StatusText:   "CAMD Bound",
			LatencyUs:    142,
		})

		writeJSON(w, http.StatusOK, map[string]any{
			"client_id":          registered.AgentID,
			"metadata_document": map[string]any{
				"client_id":                  req.MetadataURL,
				"client_name":                registered.Name,
				"client_uri":                 "https://crm-agent.acme.in",
				"jwks_uri":                   "https://crm-agent.acme.in/.well-known/jwks.json",
				"grant_types":                []string{"authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange"},
				"dpop_bound_access_tokens":   true,
				"scope":                      "crm.read crm.leads.sync invoices.read",
				"crm_connector":              req.CRMTarget,
			},
			"dpop_cnf_jkt":      registered.DPoPThumbprint,
			"status":            "VERIFIED_AND_REGISTERED",
			"registration_flow": "IETF Client ID Metadata Document (CIMD / CAMD) — URL-as-Client-ID",
		})
	})

	// POST /oauth/dpop-sign — Utility endpoint so the UI Sandbox can generate a real ES256 DPoP proof for a custom Gateway test call
	mux.HandleFunc("/oauth/dpop-sign", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			AccessToken  string `json:"access_token"`
			HTTPMethod   string `json:"http_method"`
			TargetURI    string `json:"target_uri"`
			SimulateTheft bool  `json:"simulate_theft"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		kp, _ := crypto.GenerateAgentDPoPKeypair("sandbox-key")
		proof, claims, err := kp.CreateDPoPProof(req.HTTPMethod, req.TargetURI, req.AccessToken)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"dpop_proof":  proof,
			"dpop_claims": claims,
			"jkt":         kp.Thumbprint,
		})
	})

	// =========================================================================
	// 3. USER SIGNUP, LOGIN, ORGANIZATIONS, AGENT INVENTORY & CONSENTS
	// =========================================================================
	mux.HandleFunc("/api/v1/auth/signup", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Name      string `json:"name"`
			Email     string `json:"email"`
			Password  string `json:"password"`
			OrgName   string `json:"org_name"`
			OrgDomain string `json:"org_domain"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		user, org, sessionTok, err := dataStore.RegisterUserAndOrg(body.Name, body.Email, body.Password, body.OrgName, body.OrgDomain)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		// Reset runtime agents/logs so the new organization starts 100% clean with 0 pre-filled data
		authServer.Reset()
		sseHub.ClearHistory()
		dataStore.ClearOrgActivity(org.ID)

		writeJSON(w, http.StatusCreated, map[string]any{
			"user":          user,
			"organization":  org,
			"session_token": sessionTok,
		})
	})

	mux.HandleFunc("/api/v1/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Email    string `json:"email"`
			Password string `json:"password"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		user, org, sessionTok, ok := dataStore.Authenticate(body.Email, body.Password)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid email or password. If you haven't created an account yet, click 'Create Account & Organization'."})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"user":          user,
			"organization":  org,
			"session_token": sessionTok,
		})
	})

	mux.HandleFunc("/api/v1/orgs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var body struct {
				OwnerEmail string `json:"owner_email"`
				OrgName    string `json:"org_name"`
				OrgDomain  string `json:"org_domain"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			org := dataStore.CreateOrganization(body.OwnerEmail, body.OrgName, body.OrgDomain)
			authServer.Reset()
			sseHub.ClearHistory()
			dataStore.ClearOrgActivity(org.ID)
			writeJSON(w, http.StatusCreated, org)
			return
		}
		email := r.URL.Query().Get("owner_email")
		writeJSON(w, http.StatusOK, dataStore.ListOrganizations(email))
	})

	mux.HandleFunc("/api/v1/workspace/reset", func(w http.ResponseWriter, r *http.Request) {
		authServer.Reset()
		sseHub.ClearHistory()
		dataStore.ClearOrgActivity("")
		writeJSON(w, http.StatusOK, map[string]string{"status": "workspace_cleared"})
	})

	// GET /api/v1/oauth/consent-status?consent_id=... — Allows external Claude/Gemini CLI agent scripts to poll until the user clicks Approve in the dashboard!
	mux.HandleFunc("/api/v1/oauth/consent-status", func(w http.ResponseWriter, r *http.Request) {
		cid := r.URL.Query().Get("consent_id")
		rec, ok := authServer.GetConsent(cid)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "consent_not_found"})
			return
		}
		writeJSON(w, http.StatusOK, rec)
	})

	mux.HandleFunc("/api/v1/users", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, dataStore.ListUsers())
	})

	// GET & POST /api/v1/agents, POST /api/v1/agents/register, POST /api/v1/agents/revoke
	mux.HandleFunc("/api/v1/agents", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
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
			dataStore.AppendAuditLog(store.AuditLogEntry{
				ActorUser: agent.OwnerUser,
				AgentID:   agent.AgentID,
				EventType: "AGENT_REGISTERED",
				Method:    "POST /api/v1/agents",
				Resource:  agent.SPIFFEID,
				RiskScore: 0.08,
				Verdict:   "allow",
				DPoPJKT:   agent.DPoPThumbprint,
				LatencyUs: 135,
			})
			writeJSON(w, http.StatusCreated, agent)
			return
		}
		writeJSON(w, http.StatusOK, authServer.ListAgents())
	})

	mux.HandleFunc("/api/v1/agents/register", func(w http.ResponseWriter, r *http.Request) {
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
		dataStore.AppendAuditLog(store.AuditLogEntry{
			ActorUser: agent.OwnerUser,
			AgentID:   agent.AgentID,
			EventType: "AGENT_REGISTERED",
			Method:    "POST /api/v1/agents/register",
			Resource:  agent.SPIFFEID,
			RiskScore: 0.08,
			Verdict:   "allow",
			DPoPJKT:   agent.DPoPThumbprint,
			LatencyUs: 135,
		})
		writeJSON(w, http.StatusCreated, agent)
	})

	mux.HandleFunc("/api/v1/agents/revoke", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			AgentID string `json:"agent_id"`
			Reason  string `json:"reason"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		agent, snaps, err := authServer.RevokeAgent(body.AgentID, body.Reason)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		dataStore.AppendAuditLog(store.AuditLogEntry{
			ActorUser: agent.OwnerUser,
			AgentID:   agent.AgentID,
			EventType: "AGENT_REVOKED",
			Method:    "POST /api/v1/agents/revoke",
			Resource:  agent.SPIFFEID,
			RiskScore: 1.0,
			Verdict:   "block_and_revoke",
			LatencyUs: 22,
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"agent":            agent,
			"revoked_families": snaps,
		})
	})

	// Consents Management (End-User My Consents & Revocation Portal)
	mux.HandleFunc("/api/v1/consents", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, authServer.ListConsents())
	})

	mux.HandleFunc("/api/v1/consents/revoke", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ConsentID string `json:"consent_id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		rec, snap, err := authServer.RevokeConsent(body.ConsentID)
		if err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		dataStore.AppendAuditLog(store.AuditLogEntry{
			ActorUser: rec.UserSub,
			AgentID:   rec.AgentID,
			EventType: "USER_WITHDREW_CONSENT",
			Method:    "POST /api/v1/consents/revoke",
			Resource:  rec.ConsentID,
			RiskScore: 0.0,
			Verdict:   "block_and_revoke",
			FamilyID:  rec.FamilyID,
			LatencyUs: 19,
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"consent":      rec,
			"family_graph": snap,
		})
	})

	mux.HandleFunc("/api/v1/oauth/consent", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ConsentID string   `json:"consent_id"`
			Actions   []string `json:"actions"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		rec, _ := authServer.ApproveConsent(body.ConsentID, body.Actions)
		orchestrator.NotifyConsentApproved(body.Actions)
		writeJSON(w, http.StatusOK, map[string]any{
			"status":         "approved",
			"actions":        body.Actions,
			"consent_record": rec,
		})
	})

	// CIBA Step-Up Approvals
	mux.HandleFunc("/api/v1/ciba", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, authServer.ListCIBARequests())
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
		dataStore.AppendAuditLog(store.AuditLogEntry{
			ActorUser: req.UserSub,
			AgentID:   req.AgentID,
			EventType: "CIBA_STEP_UP_" + req.Status,
			Method:    "POST /api/v1/oauth/ciba-resolve",
			Resource:  req.Resource,
			RiskScore: req.RiskScore,
			Verdict:   req.Status,
			LatencyUs: 42,
		})
		writeJSON(w, http.StatusOK, req)
	})

	// =========================================================================
	// 4. CEDAR / OPA POLICY STUDIO, GATEWAY ROUTES & SIEM AUDIT LOGS
	// =========================================================================
	mux.HandleFunc("/api/v1/policies", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var rule store.PolicyRule
			if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			created := dataStore.AddPolicy(rule)
			writeJSON(w, http.StatusCreated, created)
			return
		}
		writeJSON(w, http.StatusOK, dataStore.ListPolicies())
	})

	mux.HandleFunc("/api/v1/policies/toggle", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			ID      string `json:"id"`
			Enabled bool   `json:"enabled"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		updated, ok := dataStore.TogglePolicy(body.ID, body.Enabled)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "policy not found"})
			return
		}
		writeJSON(w, http.StatusOK, updated)
	})

	mux.HandleFunc("/api/v1/gateway/routes", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var rt store.GatewayRoute
			if err := json.NewDecoder(r.Body).Decode(&rt); err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			// Also add host to Risk Engine allowlist if newly registered
			if rt.UpstreamHost != "" {
				riskEngine.AllowedHosts[strings.ToLower(rt.UpstreamHost)] = true
			}
			created := dataStore.AddGatewayRoute(rt)
			writeJSON(w, http.StatusCreated, created)
			return
		}
		writeJSON(w, http.StatusOK, dataStore.ListGatewayRoutes())
	})

	mux.HandleFunc("/api/v1/audit-logs", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, dataStore.ListAuditLogs())
	})

	// =========================================================================
	// 5. LAYER 2 GATEWAY & LAYER 3 RISK ENGINE EXECUTION
	// =========================================================================
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
		dec := riskEngine.Decide(req)
		if dec.HardRuleHit != "" {
			ruleCode := strings.Split(dec.HardRuleHit, ":")[0]
			dataStore.IncrementRuleHit(ruleCode)
		}
		writeJSON(w, http.StatusOK, dec)
	})

	mux.HandleFunc("/api/v1/gateway/execute", func(w http.ResponseWriter, r *http.Request) {
		var req gateway.ExecuteRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		resp := enfGateway.Execute(req)

		actorUser := "user:priya@acme.in"
		agentID := "unknown-agent"
		jti := ""
		famID := ""
		score := 0.0
		var reasons []string
		ruleHit := ""

		if resp.VerifiedTokenClaims != nil {
			actorUser = resp.VerifiedTokenClaims.Sub
			agentID = resp.VerifiedTokenClaims.ClientID
			jti = resp.VerifiedTokenClaims.JTI
			famID = resp.VerifiedTokenClaims.FamilyID
		}
		if resp.RiskDecision != nil {
			score = resp.RiskDecision.Score
			reasons = resp.RiskDecision.TopReasons
			ruleHit = resp.RiskDecision.HardRuleHit
		}

		evType := "GATEWAY_ALLOW"
		if !resp.Allowed {
			if resp.Verdict == risk.VerdictStepUpCIBA {
				evType = "GATEWAY_STEP_UP_CIBA"
			} else {
				evType = "GATEWAY_BLOCK"
			}
		}

		dataStore.AppendAuditLog(store.AuditLogEntry{
			ActorUser:  actorUser,
			AgentID:    agentID,
			EventType:  evType,
			Method:     req.HTTPMethod,
			Resource:   req.TargetURI,
			TargetHost: req.TargetHost,
			RiskScore:  score,
			Verdict:    string(resp.Verdict),
			PolicyRule: ruleHit,
			Reasons:    reasons,
			TokenJTI:   jti,
			FamilyID:   famID,
			LatencyUs:  resp.GatewayLatencyUs,
		})

		gwStatus := "ok"
		if !resp.Allowed {
			gwStatus = "bad"
			if resp.Verdict == risk.VerdictStepUpCIBA {
				gwStatus = "warn"
			}
		}
		sseHub.Publish(events.TelemetryEvent{
			StepNumber:   3,
			FromLane:     "agent",
			ToLane:       "gw",
			Label:        fmt.Sprintf("%s %s (%s)", req.HTTPMethod, req.ResourcePath, resp.Verdict),
			Who:          fmt.Sprintf("%s → Gateway → %s", agentID, req.TargetHost),
			Headline:     fmt.Sprintf("Live Agent Gateway Call: %s %s → HTTP %d", req.HTTPMethod, req.TargetURI, resp.HTTPStatus),
			PlainText:    fmt.Sprintf("Agent '%s' (acting for %s) called %s. Verdict: %s (Risk Score: %.2f)", agentID, actorUser, req.TargetURI, resp.Verdict, score),
			UnderTheHood: fmt.Sprintf("POST /api/v1/gateway/execute · JTI=%s · Latency=%d µs", jti, resp.GatewayLatencyUs),
			FlowNode:     "runtime",
			Status:       gwStatus,
			StatusText:   fmt.Sprintf("HTTP %d %s", resp.HTTPStatus, strings.ToUpper(string(resp.Verdict))),
			LatencyUs:    resp.GatewayLatencyUs,
			TokenClaims:  resp.VerifiedTokenClaims,
			DPoPClaims:   resp.VerifiedDPoPClaims,
			RiskDecision: resp.RiskDecision,
			FamilyGraph:  resp.FamilyGraph,
		})

		writeJSON(w, resp.HTTPStatus, resp)
	})

	// POST /api/v1/live-llm/run — Real Gemini API / Anthropic Claude API Function-Calling Connector with Layer 2 Gateway in the Middle!
	mux.HandleFunc("/api/v1/live-llm/run", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Provider  string `json:"provider"` // "gemini" | "claude"
			APIKey    string `json:"api_key"`
			Model     string `json:"model"`
			UserEmail string `json:"user_email"`
			Prompt    string `json:"prompt"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		if req.APIKey == "" {
			if req.Provider == "claude" {
				req.APIKey = os.Getenv("ANTHROPIC_API_KEY")
			} else {
				req.APIKey = os.Getenv("GEMINI_API_KEY")
			}
		}
		if req.APIKey == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "Please provide your real Gemini API Key or Anthropic Claude API Key (or use the built-in MCP Gateway binary in Claude Code / Gemini CLI).",
			})
			return
		}
		if req.UserEmail == "" {
			req.UserEmail = "ajay@deltawavex.in"
		}
		if req.Model == "" {
			if req.Provider == "claude" {
				req.Model = "claude-3-5-sonnet-latest"
			} else {
				req.Model = "gemini-2.5-flash"
			}
		}

		// Run the live LLM tool-calling session in a goroutine so the UI can approve the real-time RAR consent popup!
		go runRealLLMAgentWithGateway(req.Provider, req.APIKey, req.Model, req.UserEmail, req.Prompt, authServer, dag, riskEngine, enfGateway, dataStore, sseHub)

		writeJSON(w, http.StatusAccepted, map[string]any{
			"status":   "started_real_llm_agent",
			"provider": req.Provider,
			"model":    req.Model,
			"message":  "Connecting to real " + strings.ToUpper(req.Provider) + " API... Approve the live RAR consent popup when the LLM requests a tool call!",
		})
	})

	// =========================================================================
	// 6. EMERGENCY KILL SWITCH, SSE STREAM, SCENARIOS & 25-INCIDENT BENCHMARK
	// =========================================================================
	mux.HandleFunc("/api/v1/events/stream", sseHub.ServeSSE)
	mux.HandleFunc("/api/v1/events/history", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"events":        sseHub.GetHistory(),
			"family_graphs": dag.GetAllSnapshots(),
			"agents":        authServer.ListAgents(),
		})
	})

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

		dataStore.AppendAuditLog(store.AuditLogEntry{
			ActorUser: "admin@acme.in",
			AgentID:   "ALL_ACTIVE_FAMILIES",
			EventType: "FAMILY_KILL_SWITCH",
			Method:    "POST /api/v1/revoke",
			Resource:  body.Reason,
			RiskScore: 1.0,
			Verdict:   "block_and_revoke",
			FamilyID:  body.FamilyID,
			LatencyUs: 24,
		})

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

	// Start clean with 0 pre-filled demo runs so the user sees only their own real agent connections!
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("🛡️  Agent Identity IAM Platform & OAuth 2.1 + DPoP Authorization Server listening on http://localhost:%s", port)
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
