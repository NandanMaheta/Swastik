#!/usr/bin/env bash
# 027 T005 - restore drill tests (FR-013, D-12, US-5). Needs docker. Run: bash infra/backup/drill_test.sh
#
# Contract for infra/backup/drill.sh (image from $DRILL_PG_IMAGE, default pinned to the Supabase major;
# pg_dump/pg_restore/psql run INSIDE that image via `docker run`, never from the host client):
#   drill.sh --dump <source-url> <out-dir>        writes <out-dir>/swastik-<UTC ts>.dump (custom format) and
#                                                 <dump>.counts (TSV `table<TAB>rows`, every public table
#                                                 incl. empty ones, sorted); exit 0
#   drill.sh --restore-only <dump> <target-url>   restores into the target (replacing public), recounts every
#                                                 table and compares with <dump>.counts; prints one line per
#                                                 table `OK <table> <n>` or `MISMATCH <table> want=<a> got=<b>`;
#                                                 exit non-zero on any mismatch, missing or extra table
#   drill.sh --local                              self-contained end to end run with throwaway containers
#                                                 named swastik-drill-*; removes them; exit 0 on success
# No URL, password or row content is ever printed.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
drill="$here/drill.sh"
image=${DRILL_PG_IMAGE:-postgres:18-alpine}
export DRILL_PG_IMAGE=$image
pw="drillpw-9f3k2"
work=$(mktemp -d)
fail=0
prefix="swastik-drilltest-$$"
# shellcheck disable=SC2317
# shellcheck disable=SC2329 # invoked through `trap cleanup EXIT`
cleanup() {
  docker ps -aq --filter "name=$prefix" | xargs -r docker rm -f >/dev/null 2>&1
  rm -rf "$work"
}
trap cleanup EXIT
bad() { echo "FAIL: $*" >&2; fail=1; }

start_pg() { # prints "<cid> <port>"
  local cid port
  cid=$(docker run -d --name "$prefix-$RANDOM" -e POSTGRES_PASSWORD="$pw" -p 127.0.0.1::5432 "$image") || return 1
  for _ in $(seq 1 60); do
    docker exec "$cid" pg_isready -U postgres -h 127.0.0.1 >/dev/null 2>&1 && break
    sleep 1
  done
  sleep 1
  port=$(docker port "$cid" 5432/tcp | head -1 | sed 's/.*://')
  echo "$cid $port"
}
psql_in() { docker exec -i "$1" psql -U postgres -v ON_ERROR_STOP=1 -q -t -A "${@:2}"; }

read -r src_cid src_port < <(start_pg) || { bad "cannot start source postgres"; exit 1; }
read -r dst_cid dst_port < <(start_pg) || { bad "cannot start target postgres"; exit 1; }
src_url="postgresql://postgres:$pw@127.0.0.1:$src_port/postgres"
dst_url="postgresql://postgres:$pw@127.0.0.1:$dst_port/postgres"

psql_in "$src_cid" <<'SQL' || { bad "seed failed"; exit 1; }
CREATE TABLE orgs (id serial PRIMARY KEY, name text NOT NULL);
CREATE TABLE audit_log (id serial PRIMARY KEY, org_id int NOT NULL REFERENCES orgs(id), action text);
CREATE TABLE empty_table (id int);
INSERT INTO orgs (name) SELECT 'org ' || g FROM generate_series(1, 3) g;
INSERT INTO audit_log (org_id, action) VALUES (1, 'a'), (2, 'b');
SQL

# ---- --dump
out=$(bash "$drill" --dump "$src_url" "$work" 2>&1); rc=$?
[ "$rc" -eq 0 ] || bad "--dump exit $rc: $out"
dump=$(find "$work" -maxdepth 1 -name 'swastik-*.dump' | head -1)
[ -n "$dump" ] || { bad "no swastik-<ts>.dump written to out dir"; exit 1; }
counts="$dump.counts"
[ -f "$counts" ] || bad "counts file $counts missing"
if [ -f "$counts" ]; then
  for want in $'orgs\t3' $'audit_log\t2' $'empty_table\t0'; do
    grep -qxF "$want" "$counts" || bad "counts file lacks line: $want (got: $(tr '\t\n' '= '<"$counts"))"
  done
  sort -c "$counts" 2>/dev/null || bad "counts file must be sorted"
fi
grep -qF "$pw" <<<"$out" && bad "--dump printed the password"
grep -qF "127.0.0.1:$src_port" <<<"$out" && bad "--dump printed the connection URL"

# ---- --restore-only success
out=$(bash "$drill" --restore-only "$dump" "$dst_url" 2>&1); rc=$?
[ "$rc" -eq 0 ] || bad "--restore-only exit $rc: $out"
for want in "OK orgs 3" "OK audit_log 2" "OK empty_table 0"; do
  grep -qF "$want" <<<"$out" || bad "--restore-only output lacks '$want': $out"
done
grep -qF "$pw" <<<"$out" && bad "--restore-only printed the password"
got=$(psql_in "$dst_cid" -c "select count(*) from orgs")
[ "$got" = "3" ] || bad "target orgs has $got rows after restore, want 3"

# ---- restoring twice into a used target must still work (drill reuses a database)
bash "$drill" --restore-only "$dump" "$dst_url" >/dev/null 2>&1 || bad "second restore into the same target failed (must replace, not append)"
got=$(psql_in "$dst_cid" -c "select count(*) from orgs")
[ "$got" = "3" ] || bad "second restore appended rows: orgs=$got"

# ---- altered count must fail
cp "$counts" "$counts.orig"
sed -i $'s/^orgs\t3$/orgs\t4/' "$counts"
out=$(bash "$drill" --restore-only "$dump" "$dst_url" 2>&1); rc=$?
[ "$rc" -ne 0 ] || bad "altered count (orgs 4) did not fail the drill"
grep -qF "MISMATCH orgs want=4 got=3" <<<"$out" || bad "mismatch not reported per table: $out"
grep -qF "OK audit_log 2" <<<"$out" || bad "other tables should still be reported OK: $out"

# ---- a table missing from the restore (extra row in counts) must fail
cp "$counts.orig" "$counts"
printf 'ghost\t1\n' >>"$counts"
sort -o "$counts" "$counts"
bash "$drill" --restore-only "$dump" "$dst_url" >/dev/null 2>&1 && bad "expected table missing after restore did not fail"

# ---- an extra table in the restore (counts lack a table) must fail
cp "$counts.orig" "$counts"
grep -v '^empty_table' "$counts.orig" >"$counts"
bash "$drill" --restore-only "$dump" "$dst_url" >/dev/null 2>&1 && bad "restored table absent from counts did not fail"

# ---- missing counts file / bad arguments
rm -f "$counts"
bash "$drill" --restore-only "$dump" "$dst_url" >/dev/null 2>&1 && bad "missing counts file did not fail"
bash "$drill" >/dev/null 2>&1 && bad "no arguments must fail with usage"
bash "$drill" --bogus >/dev/null 2>&1 && bad "unknown flag must fail"
bash "$drill" --dump >/dev/null 2>&1 && bad "--dump without arguments must fail"

# ---- review fix 5: counts come from the SAME snapshot as the dump -----------------------------------
# Rows keep arriving in the source while --dump runs (psql \watch inserts every 50 ms). A dump whose
# counts were taken before/after the dump window would report a false MISMATCH on restore.
race="$work/race"
mkdir -p "$race"
printf "INSERT INTO orgs (name) VALUES ('racer') \\watch i=0.05 c=400\n" |
  docker exec -i "$src_cid" psql -U postgres -q -t -A >/dev/null 2>&1 &
racer=$!
sleep 1
out=$(bash "$drill" --dump "$src_url" "$race" 2>&1); rc=$?
[ "$rc" -eq 0 ] || bad "--dump during concurrent inserts exit $rc: $out"
docker exec "$src_cid" pkill psql >/dev/null 2>&1
wait "$racer" 2>/dev/null
rdump=$(find "$race" -maxdepth 1 -name 'swastik-*.dump' | head -1)
if [ -n "$rdump" ]; then
  out=$(bash "$drill" --restore-only "$rdump" "$dst_url" 2>&1); rc=$?
  [ "$rc" -eq 0 ] || bad "false MISMATCH: counts and dump are from different snapshots: $out"
  grep -q '^MISMATCH' <<<"$out" && bad "MISMATCH reported for a dump taken during concurrent inserts: $out"
else
  bad "no dump written during concurrent inserts"
fi
grep -q -- '--snapshot' "$drill" || bad "drill.sh must pass an exported snapshot to pg_dump (--snapshot)"
grep -q 'pg_export_snapshot' "$drill" || bad "drill.sh must export the snapshot with pg_export_snapshot()"

# ---- --local end to end, and it cleans up after itself
before=$(docker ps -aq --filter name=swastik-drill | wc -l)
out=$(bash "$drill" --local 2>&1); rc=$?
[ "$rc" -eq 0 ] || bad "--local exit $rc: $out"
grep -qE '^OK ' <<<"$out" || bad "--local printed no per-table OK lines: $out"
after=$(docker ps -aq --filter name=swastik-drill | wc -l)
[ "$after" -eq "$before" ] || bad "--local left $((after - before)) containers behind"

# ---- static: image pinned, no host client, no URL echo
grep -Eq 'DRILL_PG_IMAGE' "$drill" || bad "drill.sh must take the postgres image from DRILL_PG_IMAGE"
grep -Eq 'postgres:[0-9]+' "$drill" || bad "drill.sh must default to a pinned postgres:<major> image"
if grep -nE '(^|[;&| ])(pg_dump|pg_restore)[[:space:]]' "$drill" | grep -v 'docker' | grep -vE '^[0-9]+:[[:space:]]*#' | grep -q .; then
  bad "pg_dump/pg_restore must run inside the postgres image, not on the host"
fi

[ "$fail" -eq 0 ] && echo "drill tests passed"
exit "$fail"
