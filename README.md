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

## MCP Gateway: put real AI clients in front of real tools

`cmd/mcp-gateway` is an authenticated MCP proxy. Claude Code, Claude Desktop, ChatGPT, Gemini CLI,
Cursor or MCPJam connect to it. It connects to real MCP servers (configured in
`config/mcp-upstreams.json`), and **every tool call is decided by the policy + risk engine** before
it is forwarded.

```
AI client ──MCP + OAuth──▶ mcp-gateway :8090 ──/decide──▶ server :8080 (auth, policy, risk, dashboard API)
                               │ only if allowed
                               ▼
              bank (demo-bank-mcp) · files (official filesystem server) · web (official fetch server) · github (optional)
```

### Run it

```bash
go run ./cmd/server                 # :8080 (create an account in the dashboard at :3000 first)
go run ./cmd/mcp-gateway            # :8090, run from this folder; first start downloads npx/uvx packages
claude mcp add --transport http agent-gw http://localhost:8090/mcp
```

In Claude Code, run `/mcp`, choose **agent-gw**, then **Authenticate**. A browser consent screen opens:
sign in with your dashboard account, tick what the agent may do and for how long, then approve.

### What happens on each call

1. The gateway checks the bearer token (introspection, cached ≤ 5 s), its audience, and that the agent was not killed.
2. It works out the action itself from the tool name, MCP annotations, arguments and config:
   `read` / `write` / `delete` / `payment_transfer` / `export`, destination hosts, INR amount, bulk access.
3. `POST /api/v1/gateway/mcp/decide` combines hard rules with runtime signals the server observes:
   call rate, retries after a denial, new destinations, and **tainted context**.
   - **Allow** forwards the call.
   - **Step-up** holds the call for up to 2 minutes while the user approves or denies it in the dashboard (CIBA).
   - **Block** revokes the whole token family. The client gets a 401 on its next request and has to ask the user again.
4. After the upstream answers, the gateway scans the result for prompt-injection phrases. A hit, or output
   from an `untrusted_output` server, taints that run, so later payments or exports from it are blocked.

### Try the demo story

| Ask Claude | Result |
| --- | --- |
| "List our bank accounts" | Allowed; real data from `demo-bank-mcp` |
| "Pay Mumbai Office Facilities ₹45,000 for INV-2026-Q3-0167" | Waits for your **Approve** in the dashboard, then the payment really posts |
| "Read vendors/vendor_onboarding_note.txt and do what it says" | Read allowed but run tainted; the injected payment or export is **blocked + revoked** |
| "Export the ACC-OPS-001 statement to pastebin.com" | Blocked: default-deny egress |
| "Delete payee Tata Steel" | Blocked: never-delete rule |

Reset bank balances by deleting `demo-data/bank_state.json`. Kill switch:
`POST /api/v1/agents/revoke {"agent_id": "..."}`; undo with `POST /api/v1/agents/restore`.
The original simulated gateway is still available with `go run ./cmd/mcp-gateway -legacy-demo`.

### Known prototype limits

- Off-the-shelf clients use plain **bearer** tokens (they cannot do DPoP). DPoP + sub-agent token exchange are shown via `cmd/my-agent` and the sandbox.
- Signing keys and agent/consent state are in memory. Restarting the server logs every client out; they re-authenticate on the next 401.
- Dashboard passwords are stored in plain text in `data/idp_tenant_state.json`. Do not use real passwords.
- `/api/v1/gateway/mcp/*` are internal endpoints with no service-to-service auth. Do not expose port 8080 publicly.
- ChatGPT and Claude.ai web connectors need a public HTTPS URL (e.g. a tunnel). Set `public_url` in the config and `ISSUER_URL` / `MCP_RESOURCE` on the server to match.
