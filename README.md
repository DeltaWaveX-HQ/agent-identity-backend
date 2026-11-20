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

- Off-the-shelf clients use plain **bearer** tokens (they cannot do DPoP). DPoP + sub-agent token exchange are shown via the Python example and the sandbox.
- The API and gateway each run as a single instance: state is held in memory and written through to Postgres, then read back at start. Scaling out needs a shared cache first.
- Policy rules and the egress allowlist are platform-wide (one engine for every organization), so only `ADMIN_EMAILS` may change them.
- Client-hook sub-agent detection (`/gateway/attribution`) accepts loopback calls only, so it works when the gateway runs on the same machine as the client. Hosted gateways detect sub-agents through token exchange, MCP `_meta`, or `/mcp/sub/<name>`.

## Configuration

| Variable | Service | Purpose |
|---|---|---|
| `DATABASE_URL` | server, gateway (bank) | Postgres. Unset = in-memory (local development) |
| `APP_SECRET` | server | Encrypts the token-signing keys stored in the database |
| `GATEWAY_SHARED_SECRET` | server, gateway | Gateway → server authentication (`X-Gateway-Key`) for decide / report / introspect |
| `CONSOLE_ORIGINS` | server | Browser origins allowed to call the console API (CORS) |
| `ADMIN_EMAILS` | server | Users allowed to change platform-wide settings |
| `ISSUER_URL`, `MCP_RESOURCE`, `GATEWAY_URL` | server | Public URLs advertised in OAuth discovery metadata |
| `PUBLIC_URL`, `AUTH_SERVER_URL` | gateway | Public gateway URL; authorization server URL |
| `GITHUB_TOKEN` | gateway | Turns on GitHub's official MCP server as an upstream |

Unset secrets fall back to open local-development behaviour, with a warning in the log.

## Security model

- **Console API:** every `/api/v1/*` call needs a signed-in session (`Authorization: Bearer sess_…`, 7 days). Passwords are bcrypt-hashed.
- **Tenant isolation:** a session only sees and acts on its own organization's agents, grants, approvals and audit entries. "Revoke agent" for an agent other organizations also use (e.g. Claude Code's shared client id) revokes only your organization's access.
- **Gateway endpoints:** decide, report and introspect accept only the gateway's shared key.
- **CORS:** the console API answers only `CONSOLE_ORIGINS`. OAuth discovery, token and registration stay open to browser-based MCP clients.
- **Upstream MCP servers:** each gets a minimal environment, never the gateway's secrets. Pass a secret explicitly through the upstream's `env` block.
- **Live event stream:** carries only "something changed" signals, never payloads.

## Deploy to Google Cloud

```bash
gcloud auth login
PROJECT_ID=<your-project> ADMIN_EMAILS=you@example.com ./deploy/gcp.sh
```

The script is safe to re-run. It creates or updates:
- **Cloud SQL** for PostgreSQL 17;
- **Secret Manager** secrets;
- an **Artifact Registry** repository;
- three **Cloud Run** services in `asia-south1`:
  - `agentid-api` (this server),
  - `agentid-gateway` (MCP gateway with the bank, filesystem and fetch upstreams),
  - `agentid-console` (the Next.js console from `../agent-identity-ui`).

Images are built with Cloud Build, so no local Docker is needed. At the end it prints the console URL and the `claude mcp add` command for the hosted gateway.

### Continuous deployment

After the first `deploy/gcp.sh`, run `PROJECT_ID=<your-project> ./deploy/setup-cd.sh` once. It connects GitHub through a one-time browser approval and creates two Cloud Build triggers. From then on, every push to `main` or `deploy-gcp` redeploys automatically:

| Repo | What a push does | Time |
|---|---|---|
| `agent-identity-backend` | Builds the image, rolls out `agentid-api` and `agentid-gateway`, then runs a smoke test (database, gateway, OAuth challenge) | ~6 min |
| `agent-identity-ui` | Builds the console and rolls out `agentid-console` | ~4 min |

Builds run as `agentid-deployer`, which can only deploy, push images and write logs. A push changes only the container image: secrets, URLs, Cloud SQL and scaling stay as `deploy/gcp.sh` set them.

