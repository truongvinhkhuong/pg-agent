#!/usr/bin/env bash
# Cross-system generality (§5.5 / RQ9): run tools/rls_demo.sql against the postgres:16
# in the ISOLATED `pgagent-ae` compose stack (db service only — no Odoo), on a THROWAWAY
# database `rlsdemo`. Regenerates results/repro/rls.csv (NEVER overwrites the committed
# reference), byte-diffs vs committed results/rls.csv, prints RLS: PASS|FAIL. Self-cleaning.
# Reads NO .env / credentials (trust auth, synthetic data). Host postgres untouched.
set -uo pipefail
cd "$(dirname "$0")/.."                     # repo root
PROJ="pgagent-ae"
DB="rlsdemo"
HEADER="variant,role,table_name,tenant,probe,row_count,cross_tenant_rows,verdict"

DC="docker compose -p $PROJ"
cleanup() { $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

echo "== RLS cross-system probe (isolated project: $PROJ, db-only) =="
$DC up -d db
for i in $(seq 1 30); do $DC exec -T db pg_isready -U odoo >/dev/null 2>&1 && break; sleep 1; done

# throwaway database (never postgres/authzbench/scale)
$DC exec -T db psql -U odoo -d postgres -q -c "DROP DATABASE IF EXISTS $DB;" -c "CREATE DATABASE $DB;" >/dev/null

mkdir -p results/repro
OUT="results/repro/rls.csv"
echo "$HEADER" > "$OUT"
# the four COPY ... TO STDOUT statements are the only stdout; append under the header.
$DC exec -T db psql -U odoo -d "$DB" -q -f - < tools/rls_demo.sql >> "$OUT"

echo "-- regenerated $OUT --"; cat "$OUT"

REF="results/rls.csv"
if [ ! -f "$REF" ]; then
  echo "============================================================"
  echo "RLS: no committed reference yet ($REF). Review $OUT, then commit it as the reference."
  exit 0
fi

echo "-- byte-diff $OUT vs committed $REF --"
if diff -q "$REF" "$OUT" >/dev/null 2>&1; then
  echo "============================================================"
  echo "RLS: PASS  (cross-engine result byte-identical to committed reference)"
  exit 0
fi
diff "$REF" "$OUT" || true
echo "============================================================"
echo "RLS: FAIL  (diff above; if this is a first-run/reference refresh, copy $OUT -> $REF and re-verify)"
exit 1
