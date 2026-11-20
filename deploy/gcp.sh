#!/usr/bin/env bash
# Deploys the Agent Identity platform to Google Cloud. Safe to re-run: every step checks what
# already exists, so re-running just builds and rolls out new revisions.
#
#   Cloud Run  agentid-api       authorization server + policy/risk engine + console API  (cmd/server)
#   Cloud Run  agentid-gateway   MCP enforcement gateway + upstream MCP servers            (cmd/mcp-gateway)
#   Cloud Run  agentid-console   tenant console (Next.js)                                  (../agent-identity-ui)
#   Cloud SQL  agentid-pg        PostgreSQL 17: agents, grants, tokens, keys, audit, bank state
#   Secret Manager               database URL, APP_SECRET (encrypts signing keys), gateway key
#
# Usage:
#   gcloud auth login
#   PROJECT_ID=my-project ADMIN_EMAILS=me@example.com ./deploy/gcp.sh
#
# Optional: REGION (default asia-south1), UI_DIR (default ../agent-identity-ui),
#           GITHUB_TOKEN (turns on GitHub's MCP server behind the gateway; stored in Secret Manager).
set -euo pipefail

PROJECT_ID="${PROJECT_ID:?set PROJECT_ID}"
REGION="${REGION:-asia-south1}"
ADMIN_EMAILS="${ADMIN_EMAILS:?set ADMIN_EMAILS (comma-separated platform admins)}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
UI_DIR="${UI_DIR:-$HERE/../agent-identity-ui}"
REPO=agentid
SQL_INSTANCE=agentid-pg
DB_NAME=agentidentity
DB_USER=agentid
SA_NAME=agentid-run
TAG="$(date +%Y%m%d-%H%M%S)"

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
gc() { gcloud --project "$PROJECT_ID" --quiet "$@"; }

say "Project $PROJECT_ID, region $REGION"
PROJECT_NUMBER="$(gc projects describe "$PROJECT_ID" --format='value(projectNumber)')"
SA="$SA_NAME@$PROJECT_ID.iam.gserviceaccount.com"
IMG="$REGION-docker.pkg.dev/$PROJECT_ID/$REPO"
# Cloud Run's deterministic service URLs, known before the first deploy (verified at the end).
url_of() { echo "https://$1-$PROJECT_NUMBER.$REGION.run.app"; }
API_URL="$(url_of agentid-api)"
GW_URL="$(url_of agentid-gateway)"
UI_URL="$(url_of agentid-console)"

say "Enabling APIs"
gc services enable run.googleapis.com sqladmin.googleapis.com cloudbuild.googleapis.com \
  artifactregistry.googleapis.com secretmanager.googleapis.com iam.googleapis.com

say "Artifact Registry repository"
gc artifacts repositories describe "$REPO" --location "$REGION" >/dev/null 2>&1 ||
  gc artifacts repositories create "$REPO" --location "$REGION" --repository-format docker \
    --description "Agent Identity images"

say "Cloud Build permissions"
# New projects build with the default compute service account, which needs the builder role.
gc projects add-iam-policy-binding "$PROJECT_ID" \
  --member "serviceAccount:$PROJECT_NUMBER-compute@developer.gserviceaccount.com" \
  --role roles/cloudbuild.builds.builder --condition=None >/dev/null

say "Runtime service account"
gc iam service-accounts describe "$SA" >/dev/null 2>&1 ||
  gc iam service-accounts create "$SA_NAME" --display-name "Agent Identity Cloud Run"
for role in roles/cloudsql.client roles/secretmanager.secretAccessor; do
  gc projects add-iam-policy-binding "$PROJECT_ID" --member "serviceAccount:$SA" --role "$role" \
    --condition=None >/dev/null
done

say "Cloud SQL for PostgreSQL (first creation takes ~10 minutes)"
if ! gc sql instances describe "$SQL_INSTANCE" >/dev/null 2>&1; then
  gc sql instances create "$SQL_INSTANCE" --database-version POSTGRES_17 --edition enterprise \
    --tier db-f1-micro --region "$REGION" --storage-size 10 --storage-auto-increase \
    --backup-start-time 20:30
fi
gc sql databases describe "$DB_NAME" --instance "$SQL_INSTANCE" >/dev/null 2>&1 ||
  gc sql databases create "$DB_NAME" --instance "$SQL_INSTANCE"
CONN="$PROJECT_ID:$REGION:$SQL_INSTANCE"

secret_exists() { gc secrets describe "$1" >/dev/null 2>&1; }
put_secret() { # name value  (creates the secret or adds a new version)
  if secret_exists "$1"; then printf '%s' "$2" | gc secrets versions add "$1" --data-file=- >/dev/null
  else printf '%s' "$2" | gc secrets create "$1" --replication-policy automatic --data-file=- >/dev/null; fi
}

say "Secrets"
if ! secret_exists agentid-database-url; then
  DB_PASS="$(openssl rand -hex 24)"
  if gc sql users describe "$DB_USER" --instance "$SQL_INSTANCE" >/dev/null 2>&1; then
    gc sql users set-password "$DB_USER" --instance "$SQL_INSTANCE" --password "$DB_PASS"
  else
    gc sql users create "$DB_USER" --instance "$SQL_INSTANCE" --password "$DB_PASS"
  fi
  put_secret agentid-database-url "postgres://$DB_USER:$DB_PASS@/$DB_NAME?host=/cloudsql/$CONN&sslmode=disable"
fi
# APP_SECRET encrypts the token-signing keys stored in the database. Never rotate it casually:
# a new value makes the stored keys unreadable (the server then refuses to start).
secret_exists agentid-app-secret || put_secret agentid-app-secret "$(openssl rand -hex 32)"
secret_exists agentid-gateway-key || put_secret agentid-gateway-key "$(openssl rand -hex 32)"
GH_SECRET=""
if [ -n "${GITHUB_TOKEN:-}" ]; then
  put_secret agentid-github-token "$GITHUB_TOKEN"
fi
secret_exists agentid-github-token && GH_SECRET=",GITHUB_TOKEN=agentid-github-token:latest"

say "Building the backend image (Cloud Build)"
gc builds submit "$HERE" --tag "$IMG/backend:$TAG"

say "Building the console image (Cloud Build), API at $API_URL"
BUILD_CFG="$(mktemp)"
cat >"$BUILD_CFG" <<EOF
steps:
- name: gcr.io/cloud-builders/docker
  args: ["build", "--build-arg", "NEXT_PUBLIC_API_URL=$API_URL", "-t", "$IMG/console:$TAG", "."]
images: ["$IMG/console:$TAG"]
EOF
gc builds submit "$UI_DIR" --config "$BUILD_CFG"
rm -f "$BUILD_CFG"

# Both backend services keep their working state in memory (Postgres is written through within
# every changing request and read back at start), so each runs as exactly one warm instance.
# CPU is request-billed: approvals and event streams are requests, so nothing needs always-on CPU.
COMMON=(--region "$REGION" --service-account "$SA" --add-cloudsql-instances "$CONN"
  --allow-unauthenticated --min-instances 1 --max-instances 1 --cpu-boost
  --timeout 3600 --port 8080)

say "Deploying agentid-api"
gc run deploy agentid-api --image "$IMG/backend:$TAG" "${COMMON[@]}" --memory 512Mi --cpu 1 \
  --set-secrets "DATABASE_URL=agentid-database-url:latest,APP_SECRET=agentid-app-secret:latest,GATEWAY_SHARED_SECRET=agentid-gateway-key:latest" \
  --set-env-vars "^|^ISSUER_URL=$API_URL|MCP_RESOURCE=$GW_URL/mcp|GATEWAY_URL=$GW_URL|CONSOLE_ORIGINS=$UI_URL|CONSOLE_URL=$UI_URL|ADMIN_EMAILS=$ADMIN_EMAILS" \
  --startup-probe "httpGet.path=/health,httpGet.port=8080,periodSeconds=5,failureThreshold=24,timeoutSeconds=4"

say "Deploying agentid-gateway"
gc run deploy agentid-gateway --image "$IMG/backend:$TAG" "${COMMON[@]}" --memory 1Gi --cpu 1 \
  --command /app/mcp-gateway --args=-config,/app/config/mcp-upstreams.cloud.json \
  --set-secrets "DATABASE_URL=agentid-database-url:latest,GATEWAY_SHARED_SECRET=agentid-gateway-key:latest$GH_SECRET" \
  --set-env-vars "PUBLIC_URL=$GW_URL,AUTH_SERVER_URL=$API_URL,CONSOLE_URL=$UI_URL" \
  --startup-probe "httpGet.path=/gateway/status,httpGet.port=8080,periodSeconds=5,failureThreshold=36,timeoutSeconds=4"

say "Deploying agentid-console"
gc run deploy agentid-console --image "$IMG/console:$TAG" --region "$REGION" --allow-unauthenticated \
  --min-instances 0 --max-instances 3 --memory 512Mi --port 8080

say "Checking service URLs"
for s in agentid-api agentid-gateway agentid-console; do
  # A service answers on several URLs (legacy hashed + deterministic); ours must be among them.
  urls="$(gc run services describe "$s" --region "$REGION" --format 'value(metadata.annotations."run.googleapis.com/urls")')"
  case "$urls" in *"$(url_of "$s")"*) ;; *) echo "WARNING: $s does not answer on $(url_of "$s") (has: $urls)";; esac
done
curl -fsS "$API_URL/health" && echo
curl -fsS "$GW_URL/gateway/status" | head -c 400 && echo

cat <<EOF

Deployed.
  Console        $UI_URL
  Auth server    $API_URL   (discovery: $API_URL/.well-known/oauth-authorization-server)
  MCP gateway    $GW_URL/mcp

Connect an agent:
  claude mcp add --transport http agent-gw $GW_URL/mcp
  MCPJam / any MCP client: Streamable HTTP, URL $GW_URL/mcp, OAuth (no client ID needed)
EOF
