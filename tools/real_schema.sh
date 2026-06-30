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
echo "-- seed + probe (real sale.order / sale.order.line) --"
$DC run --rm -T --entrypoint odoo odoo shell -d "$DB" --addons-path="$ADDONS" \
  --db_host=db --db_port=5432 --db_user=odoo --no-http <<'PY' 2>&1 | grep -v -e 'INFO' -e 'WARNING' -e '^odoo\.' -e '^$'
exec(open('tools/real_schema.py').read())
real_schema_run(env, outdir='results/repro')
env.cr.commit()
PY

OUT="results/repro/real_sale.csv"
REF="results/real_sale.csv"
if [ ! -f "$OUT" ]; then
  echo "============================================================"
  echo "REAL-SALE: FAIL  (driver did not emit $OUT — see the shell output above)"; exit 1
fi
echo "-- regenerated $OUT --"; cat "$OUT"

if [ ! -f "$REF" ]; then
  echo "============================================================"
  echo "REAL-SALE: no committed reference yet ($REF). Review $OUT, then commit it as the reference."
  exit 0
fi

echo "-- byte-diff $OUT vs committed $REF --"
if diff -q "$REF" "$OUT" >/dev/null 2>&1; then
  echo "============================================================"
  echo "REAL-SALE: PASS  (real-schema enforcement byte-identical to committed reference)"
  exit 0
fi
diff "$REF" "$OUT" || true
echo "============================================================"
echo "REAL-SALE: FAIL  (diff above; if this is a first-run/reference refresh, copy $OUT -> $REF and re-verify)"
exit 1
