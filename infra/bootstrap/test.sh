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
for t in bash env cat grep sed awk tr head date dirname basename mktemp openssl printf base64 od cut wc rm mkdir dd; do
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
# review fix 2: least privilege for the tofu SA
absent bootstrap "$out" "roles/resourcemanager.projectIamAdmin"
absent bootstrap "$out" "workloadIdentityPoolAdmin"
absent bootstrap "$out" "roles/secretmanager.admin"
if grep -E 'projects add-iam-policy-binding' <<<"$out" | grep -q 'roles/iam.serviceAccountUser'; then
  echo "FAIL: bootstrap: roles/iam.serviceAccountUser must not be granted project-wide" >&2; fail=1
fi
# Every command line is a plan line, nothing executes.
if grep -vE '^(\+ |#|$)' <<<"$out" | grep -qE 'ERROR|command not found'; then
  echo "FAIL: bootstrap dry-run executed or errored" >&2; fail=1
fi

# ---- secrets.sh ----------------------------------------------------------------------------
for env in staging production; do
  # Without --with-auth only the database URL secret exists (0 rupees before feature 003).
  out=$(printf 'postgresql://swastik_app.ref:S3CRET-pw@host:5432/postgres\n' |
    PATH="$sandbox" bash ./secrets.sh "$env" --dry-run 2>&1); rc=$?
  [ "$rc" -eq 0 ] || { echo "FAIL: secrets.sh $env --dry-run exit $rc: $out" >&2; fail=1; }
  check "secrets $env" "$out" "gcloud secrets create database-url-$env"
  check "secrets $env" "$out" "gcloud secrets versions add database-url-$env --data-file=-"
  for s_ in jwt-signing-keys pii-encryption-keys blind-index-key; do
    absent "secrets $env (no --with-auth)" "$out" "$s_-$env"
  done
  out=$(printf 'postgresql://swastik_app.ref:S3CRET-pw@host:5432/postgres\n' |
    PATH="$sandbox" bash ./secrets.sh "$env" --with-auth --dry-run 2>&1); rc=$?
  [ "$rc" -eq 0 ] || { echo "FAIL: secrets.sh $env --with-auth --dry-run exit $rc: $out" >&2; fail=1; }
  for s_ in database-url jwt-signing-keys pii-encryption-keys blind-index-key; do
    check "secrets $env" "$out" "gcloud secrets create $s_-$env"
    check "secrets $env" "$out" "gcloud secrets versions add $s_-$env --data-file=-"
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

# ---- secrets.sh behaviour with a fake gcloud (review fix 1) ---------------------------------
# The fake records every call; `secrets describe NAME` succeeds iff NAME is listed in $FAKE_EXISTING;
# `secrets versions add NAME --data-file=-` saves stdin to $FAKE_OUT/NAME.val.
fake=$(mktemp -d)
cp -P "$sandbox"/* "$fake"/ 2>/dev/null
cat >"$fake/gcloud" <<'FAKE'
#!/usr/bin/env bash
echo "$*" >>"$FAKE_OUT/calls.log"
case "$1 $2 $3" in
  "secrets describe "*) grep -qxF "$3" "$FAKE_EXISTING" ;;
  "secrets create "*) exit 0 ;;
  "secrets versions add") cat >"$FAKE_OUT/$4.val" ;;
  *) exit 0 ;;
esac
FAKE
chmod +x "$fake/gcloud"
run_secrets() { # existing-list, then script args; fresh output dir each call
  export FAKE_OUT; FAKE_OUT=$(mktemp -d); export FAKE_EXISTING="$FAKE_OUT/existing"
  printf '%s' "$1" >"$FAKE_EXISTING"; shift
  sout=$(printf 'postgresql://swastik_app.ref:S3CRET-pw@host:5432/postgres\n' | PATH="$fake" bash ./secrets.sh "$@" 2>&1); srcode=$?
}
b64_32() { # value must be std base64 (with padding) of exactly 32 bytes
  [[ "$1" =~ ^[A-Za-z0-9+/]{43}=$ ]] && [ "$(printf '%s' "$1" | base64 -d 2>/dev/null | wc -c)" -eq 32 ]
}

run_secrets "" staging
[ "$srcode" -eq 0 ] || { echo "FAIL: secrets.sh staging (fake gcloud) exit $srcode: $sout" >&2; fail=1; }
grep -q 'secrets create database-url-staging' "$FAKE_OUT/calls.log" || { echo "FAIL: database-url-staging not created" >&2; fail=1; }
grep -qE 'jwt-signing-keys|pii-encryption-keys|blind-index-key' "$FAKE_OUT/calls.log" && { echo "FAIL: auth secrets touched without --with-auth" >&2; fail=1; }
[ "$(cat "$FAKE_OUT/database-url-staging.val" 2>/dev/null)" = 'postgresql://swastik_app.ref:S3CRET-pw@host:5432/postgres' ] || { echo "FAIL: database URL not piped to the secret version" >&2; fail=1; }
absent "secrets values" "$sout" "S3CRET"

run_secrets "" staging --with-auth
[ "$srcode" -eq 0 ] || { echo "FAIL: secrets.sh --with-auth exit $srcode: $sout" >&2; fail=1; }
jwt=$(cat "$FAKE_OUT/jwt-signing-keys-staging.val" 2>/dev/null)
pii=$(cat "$FAKE_OUT/pii-encryption-keys-staging.val" 2>/dev/null)
blind=$(cat "$FAKE_OUT/blind-index-key-staging.val" 2>/dev/null)
[[ "$jwt" == k1:* ]] && b64_32 "${jwt#k1:}" || { echo "FAIL: JWT_SIGNING_KEYS must be k1:<std base64 of 32 bytes>" >&2; fail=1; }
[[ "$pii" == 1:* ]] && b64_32 "${pii#1:}" || { echo "FAIL: PII_ENCRYPTION_KEYS must be 1:<std base64 of 32 bytes>" >&2; fail=1; }
b64_32 "$blind" || { echo "FAIL: BLIND_INDEX_KEY must be bare std base64 of 32 bytes" >&2; fail=1; }
[ "$blind" != "${pii#1:}" ] && [ "$blind" != "${jwt#k1:}" ] && [ "${pii#1:}" != "${jwt#k1:}" ] || { echo "FAIL: the three key values must be distinct" >&2; fail=1; }
for v in "$jwt" "$pii" "$blind"; do [ -n "${v#*:}" ] && absent "secrets values" "$sout" "${v#*:}"; done
absent "secrets values" "$sout" "S3CRET"

run_secrets "$(printf 'database-url-staging\njwt-signing-keys-staging\npii-encryption-keys-staging\nblind-index-key-staging\n')" staging --with-auth
[ "$srcode" -eq 0 ] || { echo "FAIL: idempotent re-run exit $srcode: $sout" >&2; fail=1; }
grep -qE 'secrets create' "$FAKE_OUT/calls.log" && { echo "FAIL: existing secrets must not be created again" >&2; fail=1; }
grep -qE 'versions add' "$FAKE_OUT/calls.log" && { echo "FAIL: existing secrets must not get a new version without --rotate" >&2; fail=1; }

run_secrets "$(printf 'database-url-staging\njwt-signing-keys-staging\npii-encryption-keys-staging\nblind-index-key-staging\n')" staging --with-auth --rotate
[ "$srcode" -eq 0 ] || { echo "FAIL: --rotate exit $srcode: $sout" >&2; fail=1; }
grep -qE 'secrets create' "$FAKE_OUT/calls.log" && { echo "FAIL: --rotate must add versions, not create" >&2; fail=1; }
for s_ in jwt-signing-keys pii-encryption-keys blind-index-key; do
  grep -q "versions add $s_-staging" "$FAKE_OUT/calls.log" || { echo "FAIL: --rotate must add a version to $s_-staging" >&2; fail=1; }
done
rm -rf "$fake"

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
