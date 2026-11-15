#!/usr/bin/env bash
# shellcheck disable=SC2015 # `check && valid || { mark failure; }` is intended: C must run when A or B fails.
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
# review fix 4: custom metadata-only role for tofu on secrets (no versions.access, no admin)
rolecmd=$(grep -E 'iam roles create' <<<"$out" | grep -F 'secretmanager.secrets.get')
[ -n "$rolecmd" ] || { echo "FAIL: bootstrap must create a custom role with secretmanager.secrets.get" >&2; fail=1; }
for perm in secretmanager.secrets.getIamPolicy secretmanager.secrets.setIamPolicy; do check "bootstrap secret role" "$rolecmd" "$perm"; done
absent bootstrap "$out" "secretmanager.versions.access"
absent bootstrap "$out" "secretmanager.secretAccessor"
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
  absent "secrets $env" "$out" "roles/secretmanager.admin"
  absent "secrets $env" "$out" "secretmanager.versions.access"
  check "secrets $env" "$out" "projects/swastik-4fcc9/roles/"
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
  "secrets versions access") n=; p=; for a in "$@"; do case $a in --secret=*) n=${a#--secret=};; *) [ "$p" = --secret ] && n=$a;; esac; p=$a; done; cat "$FAKE_OUT/cur.$n" ;;
  "secrets versions add") cat >"$FAKE_OUT/$4.val" ;;
  *) exit 0 ;;
esac
FAKE
chmod +x "$fake/gcloud"
# Fake wrangler (the script must call "$WRANGLER_CMD secret put PROXY_KEY ..."); records args, saves stdin.
cat >"$fake/wrangler" <<'FAKE'
#!/usr/bin/env bash
echo "$*" >>"$FAKE_OUT/wrangler.log"
if [ "$1 $2" = "secret list" ]; then cat "$FAKE_OUT/wrangler.list" 2>/dev/null || echo '[]'; exit 0; fi
cat >"$FAKE_OUT/wrangler.stdin"
FAKE
chmod +x "$fake/wrangler"
run_secrets() { # existing-list, then script args; fresh output dir each call
  export FAKE_OUT; FAKE_OUT=$(mktemp -d); export FAKE_EXISTING="$FAKE_OUT/existing"
  printf '%s' "$1" >"$FAKE_EXISTING"; shift
  [ -n "${CUR_JWT:-}" ] && printf '%s' "$CUR_JWT" >"$FAKE_OUT/cur.jwt-signing-keys-staging"
  [ -n "${CUR_PII:-}" ] && printf '%s' "$CUR_PII" >"$FAKE_OUT/cur.pii-encryption-keys-staging"
  export WRANGLER_CMD="$fake/wrangler"
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

# Default run (no --with-auth) must create the proxy secret and push PROXY_KEY (Worker fails closed without it).
run_secrets "" staging
grep -q 'secrets create proxy-shared-secrets-staging' "$FAKE_OUT/calls.log" || { echo "FAIL: default run must create proxy-shared-secrets-staging" >&2; fail=1; }
dproxy=$(cat "$FAKE_OUT/proxy-shared-secrets-staging.val" 2>/dev/null)
b64_32 "$dproxy" || { echo "FAIL: default run proxy secret must be base64 32 bytes" >&2; fail=1; }
grep -qE '^secret put PROXY_KEY( |$)' "$FAKE_OUT/wrangler.log" 2>/dev/null || { echo "FAIL: default run must push PROXY_KEY to the Worker" >&2; fail=1; }
[ "$(cat "$FAKE_OUT/wrangler.stdin" 2>/dev/null)" = "$dproxy" ] || { echo "FAIL: default run Worker PROXY_KEY must equal stored secret" >&2; fail=1; }
# --with-auth on top creates only the auth key secrets (proxy not duplicated when it already exists).
run_secrets "$(printf 'database-url-staging\nproxy-shared-secrets-staging\n')" staging --with-auth
grep -q 'secrets create proxy-shared-secrets-staging' "$FAKE_OUT/calls.log" && { echo "FAIL: --with-auth must not recreate existing proxy secret" >&2; fail=1; }
grep -q 'versions add proxy-shared-secrets-staging' "$FAKE_OUT/calls.log" && { echo "FAIL: --with-auth must not add a proxy version" >&2; fail=1; }
for s_ in jwt-signing-keys pii-encryption-keys blind-index-key; do
  grep -q "secrets create $s_-staging" "$FAKE_OUT/calls.log" || { echo "FAIL: --with-auth must create $s_-staging" >&2; fail=1; }
done
# Re-run: secret exists but Worker lacks it -> re-push the current value, no new version.
for flag in "" "--push-proxy"; do
  CUR_PROXY="CURRENTPROXYVALUE" run_secrets "$(printf 'database-url-staging\nproxy-shared-secrets-staging\n')" staging $flag
  printf '%s' 'CURRENTPROXYVALUE' >"$FAKE_OUT/cur.proxy-shared-secrets-staging"
  printf '[]' >"$FAKE_OUT/wrangler.list"
  export FAKE_EXISTING="$FAKE_OUT/existing"
  sout=$(printf 'postgresql://x@h/p\n' | PATH="$fake" bash ./secrets.sh staging $flag 2>&1); srcode=$?
  [ "$srcode" -eq 0 ] || { echo "FAIL: re-push run ($flag) exit $srcode: $sout" >&2; fail=1; }
  grep -qE '^secret put PROXY_KEY( |$)' "$FAKE_OUT/wrangler.log" || { echo "FAIL: re-run ($flag) must re-push PROXY_KEY when Worker secret missing" >&2; fail=1; }
  [ "$(cat "$FAKE_OUT/wrangler.stdin" 2>/dev/null)" = "CURRENTPROXYVALUE" ] || { echo "FAIL: re-push ($flag) must send the current stored value" >&2; fail=1; }
  grep -q 'versions add proxy-shared-secrets-staging' "$FAKE_OUT/calls.log" && { echo "FAIL: re-push ($flag) must not add a version" >&2; fail=1; }
  absent "re-push output" "$sout" "CURRENTPROXYVALUE"
done

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

ALL5=$(printf 'database-url-staging\njwt-signing-keys-staging\npii-encryption-keys-staging\nblind-index-key-staging\nproxy-shared-secrets-staging\n')
OLDJ=$(openssl rand -base64 32); OLDP=$(openssl rand -base64 32)
CUR_JWT="k1:$OLDJ" CUR_PII="1:$OLDP" run_secrets "$ALL5" staging --with-auth --rotate
[ "$srcode" -eq 0 ] || { echo "FAIL: --rotate exit $srcode: $sout" >&2; fail=1; }
grep -qE 'secrets create' "$FAKE_OUT/calls.log" && { echo "FAIL: --rotate must add versions, not create" >&2; fail=1; }
for s_ in jwt-signing-keys pii-encryption-keys; do
  grep -q "versions add $s_-staging" "$FAKE_OUT/calls.log" || { echo "FAIL: --rotate must add a version to $s_-staging" >&2; fail=1; }
done
# BLIND_INDEX_KEY cannot be rotated without reindexing: --rotate never touches it.
grep -q "versions add blind-index-key-staging" "$FAKE_OUT/calls.log" && { echo "FAIL: --rotate must NOT rotate blind-index-key (needs reindex; separate explicit flag)" >&2; fail=1; }
# Append, never replace: ring is "<old ring>,<new id>:<new b64>".
jwt=$(cat "$FAKE_OUT/jwt-signing-keys-staging.val" 2>/dev/null)
pii=$(cat "$FAKE_OUT/pii-encryption-keys-staging.val" 2>/dev/null)
[[ "$jwt" == "k1:$OLDJ,k2:"* ]] && b64_32 "${jwt#*,k2:}" || { echo "FAIL: JWT rotate must write k1:<old>,k2:<new b64 32 bytes>" >&2; fail=1; }
[[ "$pii" == "1:$OLDP,2:"* ]] && b64_32 "${pii#*,2:}" || { echo "FAIL: PII rotate must write 1:<old>,2:<new b64 32 bytes>" >&2; fail=1; }
absent "rotate output" "$sout" "$OLDJ"
absent "rotate output" "$sout" "$OLDP"

# Explicit ids are honoured and a ring that already has the new id is refused (nothing written).
CUR_JWT="k1:$OLDJ,k2:$OLDJ" CUR_PII="1:$OLDP" run_secrets "$ALL5" staging --with-auth --rotate
[ "$srcode" -ne 0 ] || { echo "FAIL: --rotate must refuse when new JWT key id k2 already exists" >&2; fail=1; }
grep -q "versions add jwt-signing-keys-staging" "$FAKE_OUT/calls.log" && { echo "FAIL: refused rotate must not add a jwt version" >&2; fail=1; }
CUR_JWT="k1:$OLDJ" CUR_PII="1:$OLDP,2:$OLDP" run_secrets "$ALL5" staging --with-auth --rotate
[ "$srcode" -ne 0 ] || { echo "FAIL: --rotate must refuse when new PII key id 2 already exists" >&2; fail=1; }
grep -q "versions add pii-encryption-keys-staging" "$FAKE_OUT/calls.log" && { echo "FAIL: refused rotate must not add a pii version" >&2; fail=1; }
ROTATE_JWT_KID=k3 CUR_JWT="k1:$OLDJ,k2:$OLDJ" CUR_PII="1:$OLDP" run_secrets "$ALL5" staging --with-auth --rotate
[ "$srcode" -eq 0 ] && [[ "$(cat "$FAKE_OUT/jwt-signing-keys-staging.val" 2>/dev/null)" == "k1:$OLDJ,k2:$OLDJ,k3:"* ]] || { echo "FAIL: ROTATE_JWT_KID=k3 must append k3 to the existing ring" >&2; fail=1; }

# ---- proxy key reaches the Cloudflare Worker via the script, never printed (review fix) ---------
run_secrets "" staging --with-auth
proxy=$(cat "$FAKE_OUT/proxy-shared-secrets-staging.val" 2>/dev/null)
b64_32 "$proxy" || { echo "FAIL: proxy-shared-secrets must hold a bare std base64 32-byte value" >&2; fail=1; }
grep -qE '^secret put PROXY_KEY( |$)' "$FAKE_OUT/wrangler.log" 2>/dev/null || { echo "FAIL: script must run \$WRANGLER_CMD secret put PROXY_KEY ..." >&2; fail=1; }
grep -q 'swastik-api-proxy-staging' "$FAKE_OUT/wrangler.log" 2>/dev/null || { echo "FAIL: wrangler must target worker swastik-api-proxy-staging" >&2; fail=1; }
[ "$(cat "$FAKE_OUT/wrangler.stdin" 2>/dev/null)" = "$proxy" ] || { echo "FAIL: Worker PROXY_KEY must equal the stored proxy secret (piped on stdin)" >&2; fail=1; }
[ -n "$proxy" ] && { absent "proxy key output" "$sout" "$proxy"; absent "proxy key args" "$(cat "$FAKE_OUT/wrangler.log" 2>/dev/null)" "$proxy"; absent "proxy key gcloud args" "$(cat "$FAKE_OUT/calls.log")" "$proxy"; }
# Least privilege: tofu never gets secretmanager.admin nor any value-reading role.
absent "secrets.sh grants" "$(cat "$FAKE_OUT/calls.log")" "secretmanager.admin"
absent "secrets.sh grants" "$(cat "$FAKE_OUT/calls.log")" "secretmanager.secretAccessor"
grep -q "add-iam-policy-binding database-url-staging.*projects/swastik-4fcc9/roles/" "$FAKE_OUT/calls.log" || { echo "FAIL: tofu SA must be granted the custom role projects/swastik-4fcc9/roles/<id> per secret" >&2; fail=1; }
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
