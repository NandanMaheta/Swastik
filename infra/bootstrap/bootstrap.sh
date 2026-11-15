#!/usr/bin/env bash
# One-time bootstrap (OWNER STEP, run in Cloud Shell): state bucket, GitHub WIF pool/provider, tofu SA.
# Usage: bootstrap.sh [--dry-run]   (dry-run prints the commands, runs nothing)
# Requires GITHUB_REPOSITORY_ID (numeric, `gh api repos/<owner>/<repo> --jq .id`) when not dry-run.
set -euo pipefail

PROJECT="swastik-4fcc9"
REGION="asia-south1"
BUCKET="swastik-4fcc9-tofu-state"
TOFU_SA="tofu@${PROJECT}.iam.gserviceaccount.com"
ISSUER="https://token.actions.githubusercontent.com"

dry=0
case "${1:-}" in
  --dry-run) dry=1 ;;
  "") ;;
  *) echo "usage: bootstrap.sh [--dry-run]" >&2; exit 2 ;;
esac
[ "$#" -le 1 ] || { echo "usage: bootstrap.sh [--dry-run]" >&2; exit 2; }

if [ "$dry" -eq 1 ]; then
  REPO_ID="${GITHUB_REPOSITORY_ID:-<GITHUB_REPOSITORY_ID>}"
else
  REPO_ID="${GITHUB_REPOSITORY_ID:?set GITHUB_REPOSITORY_ID (numeric repo id)}"
fi

run() {
  if [ "$dry" -eq 1 ]; then
    echo "+ $*"
  else
    "$@"
  fi
}

PROJECT_NUMBER='<PROJECT_NUMBER>'
if [ "$dry" -eq 0 ]; then
  PROJECT_NUMBER=$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')
fi

run gcloud services enable iam.googleapis.com iamcredentials.googleapis.com \
  sts.googleapis.com cloudresourcemanager.googleapis.com storage.googleapis.com \
  --project="$PROJECT"

run gcloud storage buckets create "gs://${BUCKET}" --project="$PROJECT" \
  --location="$REGION" --uniform-bucket-level-access --public-access-prevention
run gcloud storage buckets update "gs://${BUCKET}" --versioning

run gcloud iam workload-identity-pools create github --project="$PROJECT" \
  --location=global --display-name="GitHub Actions"
run gcloud iam workload-identity-pools providers create-oidc swastik-repo \
  --project="$PROJECT" --location=global --workload-identity-pool=github \
  --issuer-uri="$ISSUER" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.repository_id=assertion.repository_id,attribute.environment=assertion.environment" \
  --attribute-condition="assertion.repository_id=='${REPO_ID}'"

run gcloud iam service-accounts create tofu --project="$PROJECT" \
  --display-name="OpenTofu (infra environment only)"
run gcloud storage buckets add-iam-policy-binding "gs://${BUCKET}" \
  --member="serviceAccount:${TOFU_SA}" --role=roles/storage.objectAdmin
run gcloud iam service-accounts add-iam-policy-binding "$TOFU_SA" --project="$PROJECT" \
  --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github/attribute.environment/infra"

# Rights the tofu SA needs to manage the stack (no owner, no project IAM admin, no pool admin).
# Project-level roles are limited to the services tofu creates. Secret Manager rights are the custom
# role tofuSecretMeta, granted per secret by secrets.sh. Acting as the runtime/tick SAs is a custom
# role with the single permission iam.serviceAccounts.actAs, conditioned to SAs named api-* / tick-*.
for role in roles/run.admin roles/artifactregistry.admin roles/cloudscheduler.admin \
  roles/iam.serviceAccountAdmin roles/serviceusage.serviceUsageAdmin; do
  run gcloud projects add-iam-policy-binding "$PROJECT" \
    --member="serviceAccount:${TOFU_SA}" --role="$role" --condition=None
done

# Secret Manager: tofu manages secret resources and their IAM but can never read a value. The role is
# bound per secret by secrets.sh (no project-wide secretmanager role).
run gcloud iam roles create tofuSecretMeta --project="$PROJECT" \
  --title="Tofu secret metadata and IAM (no values)" \
  --permissions=secretmanager.secrets.get,secretmanager.secrets.getIamPolicy,secretmanager.secrets.setIamPolicy

run gcloud iam roles create tofuActAs --project="$PROJECT" \
  --title="Tofu act-as runtime SAs" --permissions=iam.serviceAccounts.actAs
run gcloud projects add-iam-policy-binding "$PROJECT" \
  --member="serviceAccount:${TOFU_SA}" --role="projects/${PROJECT}/roles/tofuActAs" \
  --condition="title=actAs-api-and-tick-only,expression=resource.name.startsWith('projects/${PROJECT}/serviceAccounts/api-') || resource.name.startsWith('projects/${PROJECT}/serviceAccounts/tick-')"

echo "# done. Set GitHub infra variable GCP_WIF_PROVIDER=projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/github/providers/swastik-repo, GCP_TOFU_SA=${TOFU_SA}"
