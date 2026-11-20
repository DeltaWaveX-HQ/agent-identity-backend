#!/usr/bin/env bash
# One-time setup of continuous deployment: every push to main or deploy-gcp in the two GitHub
# repos builds and redeploys through Cloud Build (cloudbuild.yaml in each repo).
# Run deploy/gcp.sh first (it creates the services this rolls forward).
#
#   PROJECT_ID=my-project ./deploy/setup-cd.sh
#
# The GitHub connection needs a one-time approval in the browser: the script prints a link and
# stops; approve it (and install the Cloud Build GitHub app on the organization), then re-run.
set -euo pipefail

PROJECT_ID="${PROJECT_ID:?set PROJECT_ID}"
REGION="${REGION:-asia-south1}"
GH_OWNER="${GH_OWNER:-DeltaWaveX-HQ}"
BACKEND_REPO="${BACKEND_REPO:-agent-identity-backend}"
UI_REPO="${UI_REPO:-agent-identity-ui}"
BRANCHES="${BRANCHES:-^(main|deploy-gcp)$}"
CONN=agentid-github
DEPLOYER=agentid-deployer

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
gc() { gcloud --project "$PROJECT_ID" --quiet "$@"; }

PROJECT_NUMBER="$(gc projects describe "$PROJECT_ID" --format='value(projectNumber)')"
DEPLOYER_SA="$DEPLOYER@$PROJECT_ID.iam.gserviceaccount.com"
RUNTIME_SA="agentid-run@$PROJECT_ID.iam.gserviceaccount.com"
COMPUTE_SA="$PROJECT_NUMBER-compute@developer.gserviceaccount.com" # the console service runs as this
CB_AGENT="service-$PROJECT_NUMBER@gcp-sa-cloudbuild.iam.gserviceaccount.com"
API_URL="https://agentid-api-$PROJECT_NUMBER.$REGION.run.app"

say "APIs"
gc services enable cloudbuild.googleapis.com secretmanager.googleapis.com

say "Deployer service account (least privilege for the triggers)"
gc iam service-accounts describe "$DEPLOYER_SA" >/dev/null 2>&1 ||
  gc iam service-accounts create "$DEPLOYER" --display-name "Agent Identity CD (Cloud Build)"
for role in roles/run.developer roles/artifactregistry.writer roles/logging.logWriter; do
  gc projects add-iam-policy-binding "$PROJECT_ID" --member "serviceAccount:$DEPLOYER_SA" --role "$role" --condition=None >/dev/null
done
# Deploying a revision that runs as another identity needs actAs on that identity only.
for sa in "$RUNTIME_SA" "$COMPUTE_SA"; do
  gc iam service-accounts add-iam-policy-binding "$sa" --member "serviceAccount:$DEPLOYER_SA" \
    --role roles/iam.serviceAccountUser >/dev/null
done

say "GitHub connection"
# Cloud Build stores the GitHub OAuth token in Secret Manager on our behalf.
gc projects add-iam-policy-binding "$PROJECT_ID" --member "serviceAccount:$CB_AGENT" \
  --role roles/secretmanager.admin --condition=None >/dev/null
if ! gc builds connections describe "$CONN" --region "$REGION" >/dev/null 2>&1; then
  gc builds connections create github "$CONN" --region "$REGION" >/dev/null || true
fi
STAGE="$(gc builds connections describe "$CONN" --region "$REGION" --format 'value(installationState.stage)')"
if [ "$STAGE" != "COMPLETE" ]; then
  LINK="$(gc builds connections describe "$CONN" --region "$REGION" --format 'value(installationState.actionUri)')"
  MSG="$(gc builds connections describe "$CONN" --region "$REGION" --format 'value(installationState.message)')"
  cat <<EOF

ACTION NEEDED ($STAGE): $MSG
  1. Open: $LINK
  2. Sign in to GitHub and authorize Google Cloud Build.
  3. Install the Cloud Build app on the "$GH_OWNER" organization (both repos, or all repos).
Then re-run this script.
EOF
  exit 2
fi

say "Linking repositories"
for repo in "$BACKEND_REPO" "$UI_REPO"; do
  gc builds repositories describe "$repo" --connection "$CONN" --region "$REGION" >/dev/null 2>&1 ||
    gc builds repositories create "$repo" --connection "$CONN" --region "$REGION" \
      --remote-uri "https://github.com/$GH_OWNER/$repo.git" >/dev/null
done

trigger() { # name repo substitutions
  local name="$1" repo="$2" subs="$3"
  gc builds triggers delete "$name" --region "$REGION" >/dev/null 2>&1 || true
  gc builds triggers create github --name "$name" --region "$REGION" \
    --repository "projects/$PROJECT_ID/locations/$REGION/connections/$CONN/repositories/$repo" \
    --branch-pattern "$BRANCHES" --build-config cloudbuild.yaml \
    --service-account "projects/$PROJECT_ID/serviceAccounts/$DEPLOYER_SA" \
    ${subs:+--substitutions "$subs"} \
    --description "Build and redeploy on push to $BRANCHES" >/dev/null
  echo "trigger $name: $repo, branches $BRANCHES"
}

say "Triggers"
trigger agentid-backend-cd "$BACKEND_REPO" ""
trigger agentid-console-cd "$UI_REPO" "_API_URL=$API_URL"

cat <<EOF

Continuous deployment is on. Every push to $BRANCHES in
  github.com/$GH_OWNER/$BACKEND_REPO  -> rebuilds and redeploys agentid-api + agentid-gateway (then a smoke test)
  github.com/$GH_OWNER/$UI_REPO       -> rebuilds and redeploys agentid-console
Watch builds: https://console.cloud.google.com/cloud-build/builds;region=$REGION?project=$PROJECT_ID
Run one now:  gcloud builds triggers run agentid-backend-cd --region $REGION --branch deploy-gcp --project $PROJECT_ID
EOF
