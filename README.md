# Agent Identity — Go Backend (`agent-identity-backend`)

High-throughput, zero-external-dependency **Go** implementation of the **3-Layer Agentic Identity & Runtime Authorization Platform**:
1. **Layer 1 — Identity & Consent (`internal/auth`, `internal/crypto`)**: OAuth 2.1 + PKCE, `ES256` JWKS (`/.well-known/jwks.json`), `RFC 9396` Rich Authorization Requests (RAR), `RFC 8693` Sub-Agent Token Exchange (nested `act` provenance), `RFC 9449` DPoP Sender-Constrained Proof Verification (`cnf.jkt`), OpenID CIBA human step-up (`POST /api/v1/oauth/ciba-resolve`), and `< 1 ms` Token Family DAG cascading revocation.
2. **Layer 2 — Inline Enforcement Gateway (`internal/gateway`)**: Verifies JWT signature, expiry, audience, revocation status, and DPoP proof before querying Layer 3.
3. **Layer 3 — Two-Stage Risk & Cedar-Style Policy Engine (`internal/risk`)**: Model 1 (Issuance) + Model 2 (Runtime sequence drift) + Hard Tenant Rules (default-deny unknown egress, oversight config protection, India data residency).

## Quick Start

```bash
cd agent-identity-backend
go test ./...
go run ./cmd/server
```

The server listens on `http://localhost:8080`.
