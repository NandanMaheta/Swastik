#!/usr/bin/env bash
# 027 T003 - static checks that tofu plan tests cannot see (FR-002, FR-004).
#   1. cloudrun.tf: lifecycle ignore_changes covers image and traffic (deploy.yml owns them, D-2).
#   2. No project-level IAM resources anywhere in the tofu code (only resource-level grants, D-1).
#   3. No JSON key resources (WIF only).
set -uo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
fail=0
f="$root/modules/env/cloudrun.tf"
if [ ! -f "$f" ]; then
  echo "FAIL: $f missing" >&2; fail=1
else
  block=$(awk '/ignore_changes/{p=1} p{print} p&&/\]/{exit}' "$f")
  [ -n "$block" ] || { echo "FAIL: cloudrun.tf has no lifecycle ignore_changes" >&2; fail=1; }
  grep -q 'image' <<<"$block" || { echo "FAIL: ignore_changes must include the container image" >&2; fail=1; }
  grep -q 'traffic' <<<"$block" || { echo "FAIL: ignore_changes must include traffic" >&2; fail=1; }
fi
if grep -rEn --include='*.tf' 'resource +"google_project_iam_(member|binding|policy|custom_role)"|resource +"google_organization_iam' "$root" >/dev/null 2>&1; then
  echo "FAIL: project/org-level IAM resource found; grant on the individual resource instead" >&2; fail=1
fi
if grep -rEn --include='*.tf' 'google_service_account_key' "$root" >/dev/null 2>&1; then
  echo "FAIL: service account keys are forbidden (WIF only)" >&2; fail=1
fi

# ---- 027 review fix 3 (static) ----------------------------------------------------------------
repo=$(cd "$root/../.." && pwd)
for e in staging production; do
  for v in auth_keys_enabled jwt_active_kid pii_active_key_id; do
    grep -Eq "variable +\"$v\"" "$root/envs/$e/variables.tf" || { echo "FAIL: envs/$e/variables.tf must declare $v" >&2; fail=1; }
    grep -Eq "^[[:space:]]*$v[[:space:]]*=[[:space:]]*var\.$v" "$root/envs/$e/main.tf" || { echo "FAIL: envs/$e/main.tf must pass $v to module.env" >&2; fail=1; }
  done
done
grep -rq --include='*.tf' 'onetimepin' "$root/modules/env" || { echo "FAIL: no one-time-PIN identity provider (type onetimepin) in modules/env" >&2; fail=1; }
if grep -n 'os.Getenv("SENTRY_ENVIRONMENT")' "$repo/apps/api/cmd/swastik/main.go" >/dev/null 2>&1; then
  echo "FAIL: main.go reads SENTRY_ENVIRONMENT directly; read it through internal/platform/config" >&2; fail=1
fi
# Secret VALUES never enter tofu state; the Worker's PROXY_KEY is pushed outside tofu by secrets.sh.
if grep -rEn --include='*.tf' --include='*.tftest.hcl' 'google_secret_manager_secret_version' "$root" >/dev/null 2>&1; then
  echo "FAIL: google_secret_manager_secret_version(_access) reads secret values into state; forbidden" >&2; fail=1
fi
if grep -rEn --include='*.tf' 'PROXY_KEY' "$root" >/dev/null 2>&1; then
  echo "FAIL: PROXY_KEY must not be managed by tofu (set via secrets.sh / wrangler secret put)" >&2; fail=1
fi
[ "$fail" -eq 0 ] && echo "lifecycle checks passed"
exit "$fail"
