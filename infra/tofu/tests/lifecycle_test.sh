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
[ "$fail" -eq 0 ] && echo "lifecycle checks passed"
exit "$fail"
