#!/usr/bin/env bash
# Create the Secret Manager secrets for one environment (OWNER STEP, run in Cloud Shell).
# Usage: secrets.sh <staging|production> [--with-auth] [--rotate] [--rotate-proxy] [--push-proxy] [--rotate-blind-index] [--dry-run]
#   (default)    the database URL secret and proxy-shared-secrets (bare <b64>, PROXY_SHARED_SECRETS). The
#                proxy value is also pushed to the Cloudflare Worker as secret PROXY_KEY with
#                `$WRANGLER_CMD secret put` (default `npx wrangler`, value on stdin); the Worker answers 500
#                without it. If the secret exists but the Worker lacks it (checked with `secret list`), the
#                stored value is re-sent without a new version.
#   --with-auth  also the 003 auth secrets: JWT_SIGNING_KEYS (k1:<b64>), PII_ENCRYPTION_KEYS (1:<b64>),
#                BLIND_INDEX_KEY (bare <b64>); distinct random 32-byte values
#   --push-proxy re-send the stored proxy key to the Worker even if it already has one
#   --rotate     add a version to the JWT and PII key rings: the current version is read and the new key is
#                APPENDED (k1:<old>,k2:<new> and 1:<old>,2:<new>). New ids: ROTATE_JWT_KID (default k2) and
#                ROTATE_PII_KEY_ID (default 2); an id already in the ring is refused. Then change
#                jwt_active_kid / pii_active_key_id in tfvars via the infra workflow; remove old keys only
#                after sessions and data are migrated.
#   --rotate-proxy       append a new proxy key (old,new) and push the new one to the Worker
#   --rotate-blind-index  new BLIND_INDEX_KEY version. Existing blind indexes stop matching: REQUIRES A REINDEX.
# Existing secrets are never recreated and get no new version unless a rotate flag says so.
# Values never appear on the command line or in output: the database URL is read with a hidden
# prompt, keys are generated with openssl; both are piped to `--data-file=-`.
set -euo pipefail

PROJECT="swastik-4fcc9"
REGION="asia-south1"
META_ROLE="projects/${PROJECT}/roles/tofuSecretMeta" # created by bootstrap.sh; no versions.access
usage() {
  echo "usage: secrets.sh <staging|production> [--with-auth] [--rotate] [--rotate-proxy] [--push-proxy] [--rotate-blind-index] [--dry-run]" >&2
  exit 2
}

[ "$#" -ge 1 ] || usage
env="$1"; shift
case "$env" in staging | production) ;; *) usage ;; esac
dry=0; auth=0; rotate=0; rotate_proxy=0; rotate_blind=0; push_proxy=0
for a in "$@"; do
  case "$a" in
    --dry-run) dry=1 ;;
    --with-auth) auth=1 ;;
    --rotate) rotate=1 ;;
    --rotate-proxy) rotate_proxy=1 ;;
    --push-proxy) push_proxy=1 ;;
    --rotate-blind-index) rotate_blind=1 ;;
    *) usage ;;
  esac
done
JWT_KID="${ROTATE_JWT_KID:-k2}"
PII_KID="${ROTATE_PII_KEY_ID:-2}"
WRANGLER="${WRANGLER_CMD:-npx wrangler}"

read -s -r -p "DATABASE_URL for ${env} (swastik_app login, hidden): " DB_URL || true
echo >&2
[ -n "${DB_URL:-}" ] || { echo "no database URL given" >&2; [ "$dry" -eq 1 ] || exit 1; }

exists() { # name
  [ "$dry" -eq 0 ] && gcloud secrets describe "$1" --project="$PROJECT" >/dev/null 2>&1
}
current() { # name -> latest value on stdout (dry-run: empty)
  [ "$dry" -eq 1 ] || gcloud secrets versions access latest --secret="$1" --project="$PROJECT"
}
ring_has() { # ring id
  local e
  IFS=, read -r -a entries <<<"$1"
  for e in "${entries[@]}"; do [ "${e%%:*}" = "$2" ] && return 0; done
  return 1
}
create() { # name
  if [ "$dry" -eq 1 ]; then
    echo "+ gcloud secrets create $1 --project=$PROJECT --replication-policy=user-managed --locations=$REGION"
  else
    gcloud secrets create "$1" --project="$PROJECT" --replication-policy=user-managed --locations="$REGION"
  fi
}
# value <kind> <name>: new secret version content on stdout (never printed by this script).
value() {
  local cur new
  case "$1" in
    db) printf '%s' "$DB_URL" ;;
    jwt) printf 'k1:%s' "$(openssl rand -base64 32)" ;;
    pii) printf '1:%s' "$(openssl rand -base64 32)" ;;
    blind) openssl rand -base64 32 ;;
    proxy) printf '%s' "$PROXY_VALUE" ;;
    jwt+ | pii+)
      cur=$(current "$2")
      new=$(openssl rand -base64 32)
      if [ "$1" = jwt+ ]; then printf '%s,%s:%s' "$cur" "$JWT_KID" "$new"; else printf '%s,%s:%s' "$cur" "$PII_KID" "$new"; fi ;;
    proxy+) printf '%s,%s' "$(current "$2")" "$PROXY_VALUE" ;;
  esac
}
add_version() { # name, kind
  if [ "$dry" -eq 1 ]; then
    if [ "$2" = db ]; then
      echo "+ (hidden input) | gcloud secrets versions add $1 --data-file=- --project=$PROJECT"
    else
      echo "+ openssl rand -base64 32 ($2) | gcloud secrets versions add $1 --data-file=- --project=$PROJECT"
    fi
  else
    value "$2" "$1" | gcloud secrets versions add "$1" --data-file=- --project="$PROJECT"
  fi
}
grant_tofu() { # name: metadata-only custom role so tofu can read the secret resource and set its IAM; never the value
  local cmd=(gcloud secrets add-iam-policy-binding "$1" --project="$PROJECT"
    --member="serviceAccount:tofu@${PROJECT}.iam.gserviceaccount.com" --role="$META_ROLE")
  if [ "$dry" -eq 1 ]; then echo "+ ${cmd[*]}"; else "${cmd[@]}" >/dev/null; fi
}
put_worker_key() { # pushes PROXY_VALUE to the Worker (value on stdin only)
  local wcmd="$WRANGLER secret put PROXY_KEY --name swastik-api-proxy-$env"
  if [ "$dry" -eq 1 ]; then
    echo "+ (generated proxy key) | $wcmd"
  else
    # shellcheck disable=SC2086  # WRANGLER_CMD may hold several words (npx wrangler)
    printf '%s' "$PROXY_VALUE" | $WRANGLER secret put PROXY_KEY --name "swastik-api-proxy-$env" >/dev/null ||
      echo "could not set PROXY_KEY on the Worker (it exists only after the first Infra apply); run secrets.sh again afterwards" >&2
  fi
}
# ensure <name> <kind> <rotate-kind|"">: create if absent; add a version only when rotating.
ensure() {
  if exists "$1"; then
    if [ -n "$3" ]; then add_version "$1" "$3"; else echo "exists, left unchanged: $1" >&2; fi
  else
    create "$1"
    add_version "$1" "$2"
  fi
  grant_tofu "$1"
}

# Validate every rotation before anything is written.
if [ "$dry" -eq 0 ] && [ "$auth" -eq 1 ] && [ "$rotate" -eq 1 ]; then
  ring_has "$(current "jwt-signing-keys-$env")" "$JWT_KID" && { echo "JWT key id $JWT_KID already exists in the ring; choose ROTATE_JWT_KID" >&2; exit 1; }
  ring_has "$(current "pii-encryption-keys-$env")" "$PII_KID" && { echo "PII key id $PII_KID already exists in the ring; choose ROTATE_PII_KEY_ID" >&2; exit 1; }
fi

worker_has_key() { # true when the Worker already has the PROXY_KEY secret (never prints values)
  # shellcheck disable=SC2086  # WRANGLER_CMD may hold several words (npx wrangler)
  $WRANGLER secret list --name "swastik-api-proxy-$env" 2>/dev/null | grep -q 'PROXY_KEY'
}

ensure "database-url-$env" db ""

# The proxy key always exists: the Worker answers 500 without it, so it is part of the default run.
proxy="proxy-shared-secrets-$env"
if [ "$dry" -eq 1 ] || ! exists "$proxy"; then
  PROXY_VALUE=$(openssl rand -base64 32)
  ensure "$proxy" proxy ""
  put_worker_key
elif [ "$rotate_proxy" -eq 1 ]; then
  PROXY_VALUE=$(openssl rand -base64 32)
  ensure "$proxy" proxy "proxy+"
  put_worker_key
elif [ "$push_proxy" -eq 1 ] || ! worker_has_key; then
  # Secret exists but the Worker lost (or never got) it: re-send the stored value, no new version.
  if PROXY_VALUE=$(current "$proxy" 2>/dev/null) && [ -n "$PROXY_VALUE" ]; then
    put_worker_key
  else
    echo "could not read the stored proxy key; Worker not updated (run again with access to $proxy)" >&2
  fi
  grant_tofu "$proxy"
else
  ensure "$proxy" proxy ""
fi
unset PROXY_VALUE

if [ "$auth" -eq 1 ]; then
  ensure "jwt-signing-keys-$env" jwt "$([ "$rotate" -eq 1 ] && echo 'jwt+')"
  ensure "pii-encryption-keys-$env" pii "$([ "$rotate" -eq 1 ] && echo 'pii+')"
  ensure "blind-index-key-$env" blind "$([ "$rotate_blind" -eq 1 ] && echo 'blind')"
fi
unset DB_URL
