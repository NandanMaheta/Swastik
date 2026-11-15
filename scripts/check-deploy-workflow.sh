#!/usr/bin/env bash
# Contract checks on the 027 workflows (FR-001, FR-004, FR-005, FR-006, FR-011, FR-013, D-14).
#   check-deploy-workflow.sh            deploy.yml (T015)
#   check-deploy-workflow.sh --pages    + Pages build/upload and headers (T016)
#   check-deploy-workflow.sh --infra    + infra.yml and pr.yml (T018)
#   check-deploy-workflow.sh --nightly  + nightly.yml (T019)
# Flags can be combined. Text-level checks on comment-stripped workflow files; ordering is by line.
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
wf="$root/.github/workflows"
fail=0
bad() { echo "FAIL: $*" >&2; fail=1; }

strip() { sed -E 's/^[[:space:]]*#.*$//; s/[[:space:]]+#[[:space:]].*$//' "$1"; }
need() { # file-text, regex, message
  grep -Eq -- "$2" <<<"$1" || bad "$3"
}
forbid() { # file-text, regex, message
  if grep -Eq -- "$2" <<<"$1"; then bad "$3"; fi
}
line_of() { grep -En -- "$2" <<<"$1" | head -1 | cut -d: -f1; }
before() { # text, regexA, regexB, message : first A must come before first B
  local a b
  a=$(line_of "$1" "$2"); b=$(line_of "$1" "$3")
  if [ -z "$a" ] || [ -z "$b" ]; then bad "$4 (missing step)"; return; fi
  [ "$a" -lt "$b" ] || bad "$4"
}

want_pages=0; want_infra=0; want_nightly=0
for a in "$@"; do
  case "$a" in
    --pages) want_pages=1 ;;
    --infra) want_infra=1 ;;
    --nightly) want_nightly=1 ;;
    *) echo "unknown flag $a" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------- deploy.yml
f="$wf/deploy.yml"
if [ ! -f "$f" ]; then bad "deploy.yml missing"; else
  d=$(strip "$f")
  # FR-005 safe traffic switch
  need "$d" 'gcloud run deploy' "deploy.yml must deploy with gcloud run deploy"
  need "$d" '--no-traffic' "new revision must be created with --no-traffic (FR-005)"
  need "$d" '--tag[ =]c-' "revision must carry a c-<sha7> tag (FR-005)"
  need "$d" 'readyz' "tagged revision must be checked on /readyz (FR-005)"
  need "$d" 'update-traffic' "traffic must be moved with update-traffic"
  need "$d" '--to-latest' "traffic move must use --to-latest"
  need "$d" 'healthz' "public /healthz check after the switch (FR-005)"
  before "$d" 'readyz' 'update-traffic' "tagged /readyz must run BEFORE traffic moves (FR-005)"
  before "$d" 'update-traffic' 'healthz' "public /healthz must run AFTER traffic moves"
  before "$d" '--no-traffic' 'update-traffic' "--no-traffic deploy must come before update-traffic"
  # migrations from CI (D-5)
  need "$d" 'MIGRATE_DATABASE_URL' "migrations use the MIGRATE_DATABASE_URL environment secret (D-5)"
  need "$d" 'migrate up' "migrations run with 'migrate up' (D-5)"
  before "$d" 'migrate up' '--no-traffic' "migrate must finish before the new revision is created"
  forbid "$d" 'gcloud run jobs' "no Cloud Run job for migrations any more (D-5)"
  # FR-004 tofu owns configuration
  forbid "$d" '--set-env-vars|--update-env-vars|--set-secrets|--update-secrets|--remove-env-vars|--clear-env-vars' "deploy.yml must not touch env vars or secrets (FR-004, D-2)"
  # D-14 no worker deploy
  forbid "$d" 'swastik-worker|apps/worker|/worker:' "deploy.yml must not build or deploy apps/worker (D-14)"
  # FR-006 environment selection, concurrency
  need "$d" "environment:.*refs/tags/v.*production.*staging" "environment is production for v* tags, staging otherwise (FR-006)"
  need "$d" '^concurrency:' "deploy needs a concurrency group"
  grp=$(grep -E '^[[:space:]]+group:' <<<"$d" | head -1)
  if ! { grep -q 'production' <<<"$grp" && grep -q 'staging' <<<"$grp"; }; then
    bad "concurrency group must be per environment (contain production and staging): $grp"
  fi
  grep -q 'github.ref' <<<"$grp" && bad "concurrency group must not depend on the ref: $grp"
  need "$d" 'cancel-in-progress:[[:space:]]*false' "deploys must not be cancelled mid-flight"
  # config from environment variables, never hard-coded
  need "$d" 'vars\.CLOUD_RUN_SERVICE' "service name comes from vars.CLOUD_RUN_SERVICE"
  need "$d" 'vars\.API_BASE_URL' "public check uses vars.API_BASE_URL"
  need "$d" 'vars\.GCP_WIF_PROVIDER' "WIF provider from environment variables"
  need "$d" 'vars\.GCP_DEPLOY_SA' "deployer SA from environment variables"
  forbid "$d" 'credentials_json|GOOGLE_APPLICATION_CREDENTIALS|service_account_key' "no JSON keys (WIF only, FR-002)"
  need "$d" 'id-token:[[:space:]]*write' "id-token: write for WIF"
  forbid "$d" 'swastik-api[^-_a-zA-Z]' "service name must not be hard-coded"
  need "$d" 'VERSION=' "VERSION build arg (<ref>-<sha7>) required"
  forbid "$d" 'vars\.(APP_ENV|TICK_AUDIENCE|TICK_SERVICE_ACCOUNT)' "these variables moved into tofu"
fi

# ---------------------------------------------------------------- pages (T016)
if [ "$want_pages" -eq 1 ]; then
  d=$(strip "$f")
  need "$d" 'wrangler' "Pages upload uses wrangler (cloudflare/wrangler-action)"
  need "$d" 'pages deploy' "Pages direct upload ('pages deploy')"
  need "$d" 'vars\.ADMIN_PAGES_PROJECT' "admin Pages project from vars"
  need "$d" 'vars\.CLIENT_PAGES_PROJECT' "client Pages project from vars"
  need "$d" 'secrets\.CLOUDFLARE_PAGES_TOKEN' "Pages token from environment secret"
  need "$d" 'vars\.CLOUDFLARE_ACCOUNT_ID' "account id from vars"
  need "$d" 'VITE_API_BASE_URL' "admin build gets VITE_API_BASE_URL"
  need "$d" 'EXPO_PUBLIC_API_BASE_URL' "client build gets EXPO_PUBLIC_API_BASE_URL"
  before "$d" 'healthz' 'pages deploy' "static sites upload only after the API is healthy"
  for app in admin client; do
    for fn in _headers _redirects; do
      [ -f "$root/apps/$app/public/$fn" ] || bad "apps/$app/public/$fn missing"
    done
    h="$root/apps/$app/public/_headers"
    if [ -f "$h" ]; then
      for hdr in 'Content-Security-Policy' 'Strict-Transport-Security' 'X-Frame-Options: DENY' 'Referrer-Policy' 'Permissions-Policy'; do
        grep -qF "$hdr" "$h" || bad "apps/$app/public/_headers lacks $hdr"
      done
    fi
    r="$root/apps/$app/public/_redirects"
    if [ -f "$r" ]; then grep -Eq '^/\*[[:space:]]+/index\.html[[:space:]]+200' "$r" || bad "apps/$app/public/_redirects needs the SPA fallback '/* /index.html 200'"; fi
  done
fi

# ---------------------------------------------------------------- infra / pr (T018)
if [ "$want_infra" -eq 1 ]; then
  i="$wf/infra.yml"
  if [ ! -f "$i" ]; then bad "infra.yml missing"; else
    t=$(strip "$i")
    need "$t" 'pull_request' "infra.yml runs checks on pull_request"
    need "$t" 'workflow_dispatch' "apply is a manual dispatch (D-3)"
    need "$t" 'staging' "dispatch choice staging"; need "$t" 'production' "dispatch choice production"; need "$t" 'shared' "dispatch choice shared"
    need "$t" 'environment:[[:space:]]*infra' "plan/apply run in the infra environment (owner approval)"
    need "$t" 'tofu fmt -check' "fmt -check on PR"
    need "$t" 'tofu .*validate' "validate on PR"
    need "$t" 'tofu .*test' "tofu test on PR"
    need "$t" 'tofu .*plan' "plan before apply"
    need "$t" 'tofu .*apply' "apply step"
    before "$t" 'tofu .*plan' 'tofu .*apply' "plan must precede apply"
    need "$t" 'opentofu/setup-opentofu@[0-9a-f]{40}' "setup-opentofu pinned by SHA"
    need "$t" '\.opentofu-version' "tofu version comes from .opentofu-version"
    need "$t" 'vars\.GCP_TOFU_SA' "tofu SA from environment variable"
    need "$t" 'secrets\.CLOUDFLARE_TOFU_TOKEN' "Cloudflare token from environment secret"
    forbid "$t" 'credentials_json' "no JSON keys"
    forbid "$t" 'pull_request_target' "never pull_request_target"
    need "$t" 'github\.event_name[[:space:]]*==[[:space:]]*.workflow_dispatch.' "apply guarded by workflow_dispatch"
    need "$t" 'cancel-in-progress:[[:space:]]*false' "state lock: do not cancel applies"
  fi
  p=$(strip "$wf/pr.yml")
  need "$p" 'infra/\*\*' "pr.yml path filter for infra/**"
  need "$p" 'shellcheck' "pr.yml runs shellcheck"
  need "$p" 'gitleaks' "pr.yml runs gitleaks (SC-005)"
  need "$p" 'actionlint' "pr.yml lints workflows"
  need "$p" 'tofu fmt|infra\.yml|tofu test' "pr.yml covers tofu static checks"
  need "$p" 'check-deploy-workflow\.sh' "pr.yml runs the workflow contract check"
  need "$p" 'drill\.sh.*--local|drill_test\.sh' "pr.yml runs the restore-drill self test (FR-013)"
fi

# ---------------------------------------------------------------- nightly (T019)
if [ "$want_nightly" -eq 1 ]; then
  n=$(strip "$wf/nightly.yml")
  need "$n" 'environment:[[:space:]]*backups' "backup job runs in environment backups (D-12)"
  need "$n" 'infra/backup/drill\.sh' "nightly uses infra/backup/drill.sh"
  need "$n" 'secrets\.BACKUP_DATABASE_URL' "backup login URL from environment secret"
  need "$n" 'secrets\.R2_ACCESS_KEY_ID' "R2 key from environment secret"
  forbid "$n" 'postgres:18-alpine.*pg_dump|apt-get install.*postgresql-client' "dump must use the server-major image (D-12), not the runner's client"
  need "$n" 'postgres:[0-9]+' "pinned postgres major image"
  forbid "$n" 'Backups not configured|exit 0' "an unconfigured backup must fail loudly, not skip"
fi

[ "$fail" -eq 0 ] && echo "workflow checks passed"
exit "$fail"
