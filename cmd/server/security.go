package main

import (
	"context"
	"crypto/subtle"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/buildathon2026/agent-identity-backend/internal/persist"
	"github.com/buildathon2026/agent-identity-backend/internal/store"
)

// Access rules for the HTTP API.
//
//	public          OAuth/MCP protocol endpoints, discovery, JWKS, health, sign-up/sign-in
//	gateway         called only by the MCP gateway: X-Gateway-Key must equal GATEWAY_SHARED_SECRET
//	gateway|console either of the above
//	console         everything else under /api/v1: a signed-in tenant user (Authorization: Bearer sess_…)
type access int

const (
	accessPublic access = iota
	accessGateway
	accessGatewayOrConsole
	accessConsole
)

var gatewayOnly = map[string]bool{
	"/api/v1/gateway/mcp/decide": true,
	"/api/v1/gateway/mcp/report": true,
	"/oauth/introspect":          true, // RFC 7662 requires the caller (a resource server) to authenticate
}

var publicAPI = map[string]bool{
	"/api/v1/auth/signup": true,
	"/api/v1/auth/login":  true,
	"/api/v1/auth/logout": true,
}

// Protocol helpers that would be abusable if open (server-side DPoP signing; fetching arbitrary URLs).
var consoleOnlyOAuth = map[string]bool{
	"/oauth/dpop-sign":     true,
	"/oauth/cimd-discover": true,
}

func accessFor(path string) access {
	switch {
	case gatewayOnly[path]:
		return accessGateway
	case path == "/api/v1/gateway/egress-allowlist":
		return accessGatewayOrConsole
	case consoleOnlyOAuth[path]:
		return accessConsole
	case publicAPI[path]:
		return accessPublic
	case strings.HasPrefix(path, "/api/"):
		return accessConsole
	}
	return accessPublic
}

type ctxKey int

const userKey ctxKey = 1

// sessionUser returns the signed-in console user for this request (nil for gateway/public calls).
func sessionUser(r *http.Request) *store.User {
	u, _ := r.Context().Value(userKey).(*store.User)
	return u
}

func sessionToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer sess_") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	// EventSource cannot set headers, so the live event stream takes the session in the query.
	if r.URL.Path == "/api/v1/events/stream" {
		return r.URL.Query().Get("access_token")
	}
	return ""
}

type security struct {
	ds             *store.DataStore
	gatewaySecret  string
	consoleOrigins map[string]bool // empty = allow any origin (local development)
	syncer         *persist.Syncer // nil = no database
}

func newSecurity(ds *store.DataStore, syncer *persist.Syncer) *security {
	s := &security{ds: ds, gatewaySecret: os.Getenv("GATEWAY_SHARED_SECRET"), consoleOrigins: map[string]bool{}, syncer: syncer}
	for _, o := range strings.Split(os.Getenv("CONSOLE_ORIGINS"), ",") {
		if o = strings.TrimRight(strings.TrimSpace(o), "/"); o != "" {
			s.consoleOrigins[o] = true
		}
	}
	if s.gatewaySecret == "" {
		log.Printf("⚠️  GATEWAY_SHARED_SECRET is not set: gateway endpoints accept any caller (local development only)")
	}
	if len(s.consoleOrigins) == 0 {
		log.Printf("⚠️  CONSOLE_ORIGINS is not set: the console API accepts browser calls from any origin (local development only)")
	}
	return s
}

func (s *security) gatewayOK(r *http.Request) bool {
	if s.gatewaySecret == "" {
		return true
	}
	got := r.Header.Get("X-Gateway-Key")
	return subtle.ConstantTimeCompare([]byte(got), []byte(s.gatewaySecret)) == 1
}

func (s *security) cors(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	origin := r.Header.Get("Origin")
	if strings.HasPrefix(r.URL.Path, "/api/") && len(s.consoleOrigins) > 0 {
		// The tenant console API answers only the console's own origin.
		if s.consoleOrigins[strings.TrimRight(origin, "/")] {
			h.Set("Access-Control-Allow-Origin", origin)
			h.Add("Vary", "Origin")
		}
	} else {
		// OAuth discovery, token and registration endpoints are called by browser-based MCP clients
		// (MCPJam, web IDEs) from any origin; they carry no ambient credentials.
		h.Set("Access-Control-Allow-Origin", "*")
	}
	h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	h.Set("Access-Control-Allow-Headers", "Content-Type, Authorization, DPoP, X-Gateway-Key, Mcp-Protocol-Version")
	h.Set("Access-Control-Max-Age", "600")
}

func (s *security) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.cors(w, r)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		switch accessFor(r.URL.Path) {
		case accessGateway:
			if !s.gatewayOK(r) {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "gateway_auth_required"})
				return
			}
		case accessGatewayOrConsole:
			if r.Header.Get("X-Gateway-Key") != "" {
				if !s.gatewayOK(r) {
					writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "gateway_auth_required"})
					return
				}
				break
			}
			if u, ok := s.consoleUser(r); ok {
				r = r.WithContext(context.WithValue(r.Context(), userKey, u))
				break
			}
			if s.gatewaySecret == "" && r.Method == http.MethodPost && r.Header.Get("Origin") == "" {
				break // local development: the gateway calls without a key
			}
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "sign_in_required"})
			return
		case accessConsole:
			u, ok := s.consoleUser(r)
			if !ok {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "sign_in_required"})
				return
			}
			r = r.WithContext(context.WithValue(r.Context(), userKey, u))
		}

		next.ServeHTTP(w, r)

		// Persist changes before the request finishes (Cloud Run may throttle CPU between requests).
		if s.syncer != nil && r.Method != http.MethodGet && r.Method != http.MethodHead {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			if err := s.syncer.Flush(ctx); err != nil {
				log.Printf("persist: flush after %s %s: %v", r.Method, r.URL.Path, err)
			}
			cancel()
		}
	})
}

func (s *security) consoleUser(r *http.Request) (*store.User, bool) {
	tok := sessionToken(r)
	if tok == "" {
		return nil, false
	}
	u, _, ok := s.ds.GetSession(tok)
	return u, ok
}
