#!/usr/bin/env bash
# Scale tier (env-sensitive): installs ~11 Odoo CE business apps in the isolated `pgagent-ae` stack and
# runs the PCC-ERP scanners — §5.2 coverage, §5.2.1 endemicity, §5.3 emit-classify, §5.3.1 soundness
# frontier — into results/scale/repro/. These embed live Odoo model/field/domain strings tied to the
# installed image, so they reproduce STRUCTURALLY (gap/domain counts), not byte-for-byte. Self-cleaning.
set -uo pipefail
cd "$(dirname "$0")/.."
PROJ="pgagent-ae"
ADDONS="/usr/lib/python3/dist-packages/odoo/addons"
DB="scale"
APPS="sale_management,account,stock,purchase,mrp,project,crm,hr,fleet,repair,maintenance"
ROOTS='("sale","account","stock","purchase","mrp","project","crm","hr","fleet","repair","maintenance")'

DC="docker compose -p $PROJ"
cleanup() { $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

echo "== scale scan (isolated project: $PROJ) — installing CE apps, this takes a few minutes =="
$DC up -d db
for i in $(seq 1 30); do $DC exec -T db pg_isready -U odoo >/dev/null 2>&1 && break; sleep 1; done
$DC run --rm --entrypoint odoo odoo -d "$DB" --addons-path="$ADDONS" \
  --db_host=db --db_port=5432 --db_user=odoo -i "$APPS" --stop-after-init --no-http --without-demo=all 2>&1 | tail -2

mkdir -p results/scale/repro
$DC run --rm -T --entrypoint odoo odoo shell -d "$DB" --addons-path="$ADDONS" \
  --db_host=db --db_port=5432 --db_user=odoo --no-http <<PY 2>/dev/null
exec(open('tests/policy_scan.py').read())
scan(env, modules=("sale","account","stock"), outdir="results/scale/repro")
emit_classify(env, modules=("sale","account","stock"), outdir="results/scale/repro")
scan_corpus(env, modules=$ROOTS, outdir="results/scale/repro/corpus")
soundness_report(env, modules=("sale","account","stock"), outdir="results/scale/repro")
PY

echo "-- structural compare vs committed (gap/domain counts, not byte-exact) --"
python3 - <<'PY'
import csv, os
def n(p, key, val): return sum(1 for r in csv.DictReader(open(p)) if r.get(key) == val) if os.path.exists(p) else "n/a"
print("  coverage GAPs    committed=%s  repro=%s" % (n("results/scale/coverage.csv","verdict","GAP"),
                                                     n("results/scale/repro/coverage.csv","verdict","GAP")))
print("  soundness sound  committed=%s  repro=%s" % (n("results/scale/soundness.csv","theorem","sound"),
                                                     n("results/scale/repro/soundness.csv","theorem","sound")))
print("  (endemicity + emit tables in results/scale/repro/ ; the §5.2.1/§5.3.1 numbers track the pinned odoo:19 image)")
PY
echo "scale scan done -> results/scale/repro/"
