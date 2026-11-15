#!/usr/bin/env bash
# Backup dump and restore drill (027 FR-013, D-12). All Postgres tools run inside a pinned image so the
# client major always matches the server; connection URLs are passed through the environment and never printed.
#   drill.sh --dump <source-url> <out-dir>        pg_dump (custom format, public schema) + per-table row counts
#   drill.sh --restore-only <dump> <target-url>   replace public in the target, restore, compare every table count
#   drill.sh --local                              throwaway end-to-end run (needs docker)
# shellcheck disable=SC2016  # single quotes are intentional: variables expand inside the container
set -euo pipefail

IMAGE=${DRILL_PG_IMAGE:-postgres:18-alpine}
name=""
work=""

usage() {
  echo "usage: drill.sh --dump <source-url> <out-dir> | --restore-only <dump> <target-url> | --local" >&2
  exit 2
}

# docker_pg <url> <docker args...> -- <command...>: run a client tool in the image, URL via env only.
docker_pg() {
  local url=$1
  shift
  DRILL_URL=$url docker run --rm --network host -e DRILL_URL -u "$(id -u):$(id -g)" "$@"
}

# Table row counts of schema public as sorted `table<TAB>rows` lines (empty tables included).
counts() {
  docker_pg "$1" "$IMAGE" sh -c 'psql "$DRILL_URL" -v ON_ERROR_STOP=1 -q -At -F "	" -c "
    SELECT c.relname, (xpath('"'"'/row/c/text()'"'"', query_to_xml(format('"'"'SELECT count(*) AS c FROM public.%I'"'"', c.relname), false, true, '"'"''"'"')))[1]::text
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = '"'"'public'"'"' AND c.relkind IN ('"'"'r'"'"','"'"'p'"'"')"' | LC_ALL=C sort
}

do_dump() {
  local url=$1 out=$2 ts dump
  mkdir -p "$out"
  out=$(cd "$out" && pwd)
  ts=$(date -u +%Y%m%dT%H%M%SZ)
  dump="swastik-$ts.dump"
  docker_pg "$url" -v "$out:/out" "$IMAGE" sh -c 'pg_dump --format=custom --schema=public --no-owner --no-privileges --file="/out/'"$dump"'" "$DRILL_URL"'
  counts "$url" >"$out/$dump.counts"
  echo "dump written: $dump ($(wc -l <"$out/$dump.counts") tables)"
}

do_restore() {
  local dump=$1 url=$2 dir base want got rc=0
  [ -f "$dump" ] || { echo "dump not found" >&2; exit 1; }
  [ -f "$dump.counts" ] || { echo "counts file missing: $dump.counts" >&2; exit 1; }
  dir=$(cd "$(dirname "$dump")" && pwd)
  base=$(basename "$dump")
  docker_pg "$url" "$IMAGE" sh -c 'psql "$DRILL_URL" -v ON_ERROR_STOP=1 -q -c "DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public;"'
  # The schema itself was just recreated, so skip its CREATE entry from the dump.
  docker_pg "$url" -v "$dir:/in:ro" "$IMAGE" sh -c 'pg_restore -l "/in/'"$base"'" | grep -v " SCHEMA - public " >/tmp/list; pg_restore --no-owner --no-privileges --exit-on-error -L /tmp/list --dbname="$DRILL_URL" "/in/'"$base"'"'
  want=$(LC_ALL=C sort "$dump.counts")
  got=$(counts "$url")
  while IFS=$'\t' read -r table n; do
    [ -n "$table" ] || continue
    g=$(awk -F'\t' -v t="$table" '$1 == t { print $2 }' <<<"$got")
    if [ -z "$g" ]; then
      echo "MISSING $table want=$n"
      rc=1
    elif [ "$g" = "$n" ]; then
      echo "OK $table $n"
    else
      echo "MISMATCH $table want=$n got=$g"
      rc=1
    fi
  done <<<"$want"
  while IFS=$'\t' read -r table n; do
    [ -n "$table" ] || continue
    if ! awk -F'\t' -v t="$table" '$1 == t { f = 1 } END { exit !f }' <<<"$want"; then
      echo "EXTRA $table got=$n"
      rc=1
    fi
  done <<<"$got"
  return "$rc"
}

do_local() {
  local pw port1 port2 rc=0
  name="swastik-drill-$$"
  work=$(mktemp -d)
  pw=$(openssl rand -hex 8)
  cleanup() {
    docker rm -f "$name-src" "$name-dst" >/dev/null 2>&1 || true
    rm -rf "$work"
  }
  trap cleanup EXIT
  for side in src dst; do
    docker run -d --name "$name-$side" -e POSTGRES_PASSWORD="$pw" -p 127.0.0.1::5432 "$IMAGE" >/dev/null
  done
  for side in src dst; do
    for _ in $(seq 1 60); do
      docker exec "$name-$side" pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1 && break
      sleep 1
    done
  done
  sleep 1
  port1=$(docker port "$name-src" 5432/tcp | head -1 | sed 's/.*://')
  port2=$(docker port "$name-dst" 5432/tcp | head -1 | sed 's/.*://')
  docker exec -i "$name-src" psql -U postgres -v ON_ERROR_STOP=1 -q >/dev/null <<'SQL'
CREATE TABLE orgs (id serial PRIMARY KEY, name text NOT NULL);
CREATE TABLE audit_log (id serial PRIMARY KEY, org_id int NOT NULL REFERENCES orgs(id), action text);
INSERT INTO orgs (name) SELECT 'org ' || g FROM generate_series(1, 3) g;
INSERT INTO audit_log (org_id, action) VALUES (1, 'a'), (2, 'b');
SQL
  do_dump "postgresql://postgres:$pw@127.0.0.1:$port1/postgres" "$work" >/dev/null
  do_restore "$(find "$work" -maxdepth 1 -name 'swastik-*.dump' | head -1)" "postgresql://postgres:$pw@127.0.0.1:$port2/postgres" || rc=$?
  return "$rc"
}

case "${1:-}" in
  --dump) [ "$#" -eq 3 ] || usage; do_dump "$2" "$3" ;;
  --restore-only) [ "$#" -eq 3 ] || usage; do_restore "$2" "$3" ;;
  --local) [ "$#" -eq 1 ] || usage; do_local ;;
  *) usage ;;
esac
