#!/usr/bin/env bash
# Real-Odoo-schema enforcement (§5.6 / read plane): run the SAME PG-Agent PEP guard against the REAL upstream
# Odoo `sale.order` / `sale.order.line` in the ISOLATED `pgagent-ae` compose stack, on a THROWAWAY database
# `realsale`. Installs the official `sale_management` app + the guard, seeds synthetic orders for two
# salespersons, reproduces the owner-axis confused-deputy gap and the PEP fix. Regenerates
# results/repro/real_sale.csv (NEVER overwrites the committed reference), byte-diffs vs results/real_sale.csv,
# prints REAL-SALE: PASS|FAIL. Self-cleaning. Reads NO .env / credentials (synthetic data). User containers
# (odoo-web / odoo-postgres / tte_*) are a DIFFERENT compose project and are untouched.
set -uo pipefail
cd "$(dirname "$0")/.."                     # repo root
PROJ="pgagent-ae"
DB="realsale"
ADDONS="/repo/addons,/usr/lib/python3/dist-packages/odoo/addons"

DC="docker compose -p $PROJ"
cleanup() { $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

echo "== Real-Odoo-schema enforcement (isolated project: $PROJ, db: $DB) =="
$DC up -d db
for i in $(seq 1 30); do $DC exec -T db pg_isready -U odoo >/dev/null 2>&1 && break; sleep 1; done

# throwaway database (never postgres/authzbench/scale/rlsdemo)
$DC exec -T db psql -U odoo -d postgres -q -c "DROP DATABASE IF EXISTS $DB;" >/dev/null 2>&1

echo "-- install pco_core_mock,pg_agent_guard,sale_management (real Odoo sale app) --"
$DC run --rm --entrypoint odoo odoo -d "$DB" --addons-path="$ADDONS" \
  --db_host=db --db_port=5432 --db_user=odoo \
  -i pco_core_mock,pg_agent_guard,sale_management --stop-after-init --no-http --without-demo=all 2>&1 | tail -2

mkdir -p results/repro
echo "-- seed + probe (real sale.order / sale.order.line): READ plane + WRITE plane --"
$DC run --rm -T --entrypoint odoo odoo shell -d "$DB" --addons-path="$ADDONS" \
  --db_host=db --db_port=5432 --db_user=odoo --no-http <<'PY' 2>&1 | grep -v -e 'INFO' -e 'WARNING' -e '^odoo\.' -e '^$'
exec(open('tools/real_schema.py').read())
real_schema_run(env, outdir='results/repro')          # §5.6 read plane  -> real_sale.csv
real_schema_write_run(env, outdir='results/repro')    # §5.6 write plane -> real_sale_write.csv (savepoint-isolated)
env.cr.commit()
PY

FILES="real_sale.csv real_sale_write.csv"   # read plane + write plane
for f in $FILES; do
  OUT="results/repro/$f"
  if [ ! -f "$OUT" ]; then
    echo "============================================================"
    echo "REAL-SALE: FAIL  (driver did not emit $OUT — see the shell output above)"; exit 1
  fi
  echo "-- regenerated $OUT --"; cat "$OUT"
done

MISSING_REF=0; DIFFS=0
for f in $FILES; do
  OUT="results/repro/$f"; REF="results/$f"
  if [ ! -f "$REF" ]; then echo "  (no committed reference yet: $REF)"; MISSING_REF=$((MISSING_REF+1)); continue; fi
  if ! diff -q "$REF" "$OUT" >/dev/null 2>&1; then echo "  DIFF: $f"; diff "$REF" "$OUT" || true; DIFFS=$((DIFFS+1)); fi
done

echo "============================================================"
if [ "$MISSING_REF" -gt 0 ]; then
  echo "REAL-SALE: no committed reference yet for $MISSING_REF file(s). Review results/repro/, then commit as references."
  exit 0
fi
if [ "$DIFFS" -eq 0 ]; then
  echo "REAL-SALE: PASS  (read + write planes byte-identical to committed references)"; exit 0
fi
echo "REAL-SALE: FAIL  ($DIFFS diff(s) above; if this is a first-run/reference refresh, copy results/repro/* -> results/ and re-verify)"
exit 1
