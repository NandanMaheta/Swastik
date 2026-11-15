#!/usr/bin/env bash
# 027 T002 - bootstrap.sh / secrets.sh --dry-run tests (FR-002, FR-003).
#
# Contract for the scripts under test:
#   - `--dry-run` prints every gcloud/openssl command it WOULD run to stdout, one per line, prefixed
#     `+ `, executes nothing (no gcloud on PATH is needed) and exits 0.
#   - Missing/unknown arguments exit non-zero with a usage message on stderr.
#   - secrets.sh never prints a secret value: it is read from a hidden prompt (`read -s`) or generated
#     with openssl and piped to `gcloud secrets versions add --data-file=-`.
set -uo pipefail
cd "$(dirname "$0")" || exit 1
fail=0
check() { # name, haystack, needle (fixed string)
  if ! grep -qF -- "$3" <<<"$2"; then echo "FAIL: $1: missing: $3" >&2; fail=1; fi
}
absent() { # name, haystack, needle
  if grep -qF -- "$3" <<<"$2"; then echo "FAIL: $1: must not contain: $3" >&2; fail=1; fi
}

# A sandbox PATH without gcloud proves dry-run never calls it.
sandbox=$(mktemp -d)
trap 'rm -rf "$sandbox"' EXIT
for t in bash env cat grep sed awk tr head date dirname basename mktemp openssl printf; do
  p=$(command -v "$t" 2>/dev/null) && ln -s "$p" "$sandbox/$t"
done

# ---- bootstrap.sh --------------------------------------------------------------------------
out=$(PATH="$sandbox" bash ./bootstrap.sh --dry-run 2>&1); rc=$?
[ "$rc" -eq 0 ] || { echo "FAIL: bootstrap.sh --dry-run exit $rc: $out" >&2; fail=1; }
check bootstrap "$out" "swastik-4fcc9-tofu-state"
check bootstrap "$out" "gcloud storage buckets create gs://swastik-4fcc9-tofu-state"
check bootstrap "$out" "--location=asia-south1"
check bootstrap "$out" "--uniform-bucket-level-access"
check bootstrap "$out" "--public-access-prevention"
check bootstrap "$out" "gcloud storage buckets update gs://swastik-4fcc9-tofu-state --versioning"
check bootstrap "$out" "gcloud iam workload-identity-pools create github"
check bootstrap "$out" "gcloud iam workload-identity-pools providers create-oidc swastik-repo"
check bootstrap "$out" "https://token.actions.githubusercontent.com"
check bootstrap "$out" "attribute.environment=assertion.environment"
check bootstrap "$out" "attribute.repository_id=assertion.repository_id"
check bootstrap "$out" "--attribute-condition="
check bootstrap "$out" "assertion.repository_id"
check bootstrap "$out" "gcloud iam service-accounts create tofu"
check bootstrap "$out" "tofu@swastik-4fcc9.iam.gserviceaccount.com"
check bootstrap "$out" "roles/iam.workloadIdentityUser"
check bootstrap "$out" "attribute.environment/infra"
check bootstrap "$out" "gcloud services enable"
absent bootstrap "$out" "keys create"
absent bootstrap "$out" "--format=json > "
absent bootstrap "$out" "roles/owner"
absent bootstrap "$out" "allUsers"
# Every command line is a plan line, nothing executes.
if grep -vE '^(\+ |#|$)' <<<"$out" | grep -qE 'ERROR|command not found'; then
  echo "FAIL: bootstrap dry-run executed or errored" >&2; fail=1
fi

# ---- secrets.sh ----------------------------------------------------------------------------
for env in staging production; do
  out=$(printf 'postgresql://swastik_app.ref:S3CRET-pw@host:5432/postgres\n' |
    PATH="$sandbox" bash ./secrets.sh "$env" --dry-run 2>&1); rc=$?
  [ "$rc" -eq 0 ] || { echo "FAIL: secrets.sh $env --dry-run exit $rc: $out" >&2; fail=1; }
  for s in database-url jwt-signing-keys pii-encryption-keys blind-index-key; do
    check "secrets $env" "$out" "gcloud secrets create $s-$env"
    check "secrets $env" "$out" "gcloud secrets versions add $s-$env --data-file=-"
  done
  check "secrets $env" "$out" "--replication-policy=user-managed"
  check "secrets $env" "$out" "--locations=asia-south1"
  check "secrets $env" "$out" "openssl rand"
  absent "secrets $env" "$out" "S3CRET"
  absent "secrets $env" "$out" "postgresql://"
  absent "secrets $env" "$out" "--data-file=/"
  absent "secrets $env" "$out" "--data="
  absent "secrets $env" "$out" "echo "
done

# ---- argument errors ------------------------------------------------------------------------
PATH="$sandbox" bash ./secrets.sh --dry-run >/dev/null 2>&1 && { echo "FAIL: secrets.sh without env must fail" >&2; fail=1; }
PATH="$sandbox" bash ./secrets.sh qa --dry-run >/dev/null 2>&1 && { echo "FAIL: secrets.sh with env qa must fail" >&2; fail=1; }

# ---- static: no secret echo in scripts ------------------------------------------------------
if grep -nE 'echo[^|]*\$\{?(DB_URL|DATABASE_URL|secret|SECRET|value|VALUE)' secrets.sh >/dev/null 2>&1; then
  echo "FAIL: secrets.sh echoes a secret-looking variable" >&2; fail=1
fi
grep -q 'read -s' secrets.sh || { echo "FAIL: secrets.sh must read the database URL with read -s" >&2; fail=1; }

[ "$fail" -eq 0 ] && echo "bootstrap tests passed"
exit "$fail"
