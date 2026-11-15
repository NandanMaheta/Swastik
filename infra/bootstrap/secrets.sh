#!/usr/bin/env bash
# Create the Secret Manager secrets for one environment (OWNER STEP, run in Cloud Shell).
# Usage: secrets.sh <staging|production> [--with-auth] [--rotate] [--dry-run]
#   (default)    only the database URL secret (feature 003 not deployed yet)
#   --with-auth  also the 003 auth keys: JWT_SIGNING_KEYS (k1:<b64>), PII_ENCRYPTION_KEYS (1:<b64>),
#                BLIND_INDEX_KEY (bare <b64>); three distinct random 32-byte values
#   --rotate     add a NEW VERSION to secrets that already exist (new key id from
#                ROTATE_JWT_KID, default k2, and ROTATE_PII_KEY_ID, default 2)
# Existing secrets are never recreated and get no new version unless --rotate is given.
# Values never appear on the command line or in output: the database URL is read with a hidden
# prompt, keys are generated with openssl; both are piped to `--data-file=-`.
set -euo pipefail

PROJECT="swastik-4fcc9"
REGION="asia-south1"
usage() { echo "usage: secrets.sh <staging|production> [--with-auth] [--rotate] [--dry-run]" >&2; exit 2; }

[ "$#" -ge 1 ] || usage
env="$1"; shift
case "$env" in staging | production) ;; *) usage ;; esac
dry=0; auth=0; rotate=0
for a in "$@"; do
  case "$a" in
    --dry-run) dry=1 ;;
    --with-auth) auth=1 ;;
    --rotate) rotate=1 ;;
    *) usage ;;
  esac
done

read -s -r -p "DATABASE_URL for ${env} (swastik_app login, hidden): " DB_URL || true
echo >&2
[ -n "${DB_URL:-}" ] || { echo "no database URL given" >&2; [ "$dry" -eq 1 ] || exit 1; }

exists() { # name
  [ "$dry" -eq 0 ] && gcloud secrets describe "$1" --project="$PROJECT" >/dev/null 2>&1
}
create() { # name
  if [ "$dry" -eq 1 ]; then
    echo "+ gcloud secrets create $1 --project=$PROJECT --replication-policy=user-managed --locations=$REGION"
  else
    gcloud secrets create "$1" --project="$PROJECT" --replication-policy=user-managed --locations="$REGION"
  fi
}
value() { # kind: db | jwt | pii | blind (never printed)
  case "$1" in
    db) printf '%s' "$DB_URL" ;;
    jwt) printf '%s:%s' "${ROTATE_JWT_KID:-k1}" "$(openssl rand -base64 32)" ;;
    pii) printf '%s:%s' "${ROTATE_PII_KEY_ID:-1}" "$(openssl rand -base64 32)" ;;
    blind) openssl rand -base64 32 ;;
  esac
}
add_version() { # name, kind
  if [ "$dry" -eq 1 ]; then
    if [ "$2" = db ]; then
      echo "+ (hidden input) | gcloud secrets versions add $1 --data-file=- --project=$PROJECT"
    else
      echo "+ openssl rand -base64 32 ($2 format) | gcloud secrets versions add $1 --data-file=- --project=$PROJECT"
    fi
  else
    value "$2" | gcloud secrets versions add "$1" --data-file=- --project="$PROJECT"
  fi
}
grant_tofu() { # name: resource-level admin so tofu can read it and grant the runtime SA access
  local cmd=(gcloud secrets add-iam-policy-binding "$1" --project="$PROJECT"
    --member="serviceAccount:tofu@${PROJECT}.iam.gserviceaccount.com" --role=roles/secretmanager.admin)
  if [ "$dry" -eq 1 ]; then echo "+ ${cmd[*]}"; else "${cmd[@]}" >/dev/null; fi
}
ensure() { # name, kind
  if exists "$1"; then
    if [ "$rotate" -eq 1 ]; then add_version "$1" "$2"; else echo "exists, left unchanged: $1" >&2; fi
  else
    create "$1"
    add_version "$1" "$2"
  fi
  grant_tofu "$1"
}

if [ "$rotate" -eq 1 ]; then
  export ROTATE_JWT_KID="${ROTATE_JWT_KID:-k2}" ROTATE_PII_KEY_ID="${ROTATE_PII_KEY_ID:-2}"
fi

ensure "database-url-$env" db
if [ "$auth" -eq 1 ]; then
  ensure "jwt-signing-keys-$env" jwt
  ensure "pii-encryption-keys-$env" pii
  ensure "blind-index-key-$env" blind
fi
unset DB_URL
