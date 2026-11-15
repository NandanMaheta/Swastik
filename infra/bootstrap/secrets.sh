#!/usr/bin/env bash
# Create the Secret Manager secrets for one environment (OWNER STEP, run in Cloud Shell).
# Usage: secrets.sh <staging|production> [--dry-run]
# Values never appear on the command line or in output: the database URL is read with a hidden
# prompt, keys are generated with openssl; both are piped to `--data-file=-`.
set -euo pipefail

PROJECT="swastik-4fcc9"
REGION="asia-south1"
usage() { echo "usage: secrets.sh <staging|production> [--dry-run]" >&2; exit 2; }

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ]; then usage; fi
env="$1"
case "$env" in staging | production) ;; *) usage ;; esac
dry=0
if [ "$#" -eq 2 ]; then
  [ "$2" = "--dry-run" ] || usage
  dry=1
fi

read -s -r -p "DATABASE_URL for ${env} (swastik_app login, hidden): " DB_URL || true
echo >&2
[ -n "${DB_URL:-}" ] || { echo "no database URL given" >&2; [ "$dry" -eq 1 ] || exit 1; }

create() { # name
  if [ "$dry" -eq 1 ]; then
    echo "+ gcloud secrets create $1 --project=$PROJECT --replication-policy=user-managed --locations=$REGION"
  else
    gcloud secrets create "$1" --project="$PROJECT" --replication-policy=user-managed --locations="$REGION"
  fi
}
add_stdin() { # name, generator (db|rand32)
  if [ "$dry" -eq 1 ]; then
    if [ "$2" = db ]; then
      echo "+ (hidden input) | gcloud secrets versions add $1 --data-file=- --project=$PROJECT"
    else
      echo "+ openssl rand -base64 32 | gcloud secrets versions add $1 --data-file=- --project=$PROJECT"
    fi
  elif [ "$2" = db ]; then
    printf '%s' "$DB_URL" | gcloud secrets versions add "$1" --data-file=- --project="$PROJECT"
  else
    openssl rand -base64 32 | gcloud secrets versions add "$1" --data-file=- --project="$PROJECT"
  fi
}

create "database-url-$env"
add_stdin "database-url-$env" db
for s in jwt-signing-keys pii-encryption-keys blind-index-key; do
  create "$s-$env"
  add_stdin "$s-$env" rand32
done
unset DB_URL
