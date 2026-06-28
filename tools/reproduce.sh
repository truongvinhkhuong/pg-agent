#!/usr/bin/env bash
# One-command reproduce for Artifact Evaluation. Spins up the ISOLATED `pgagent-ae` compose stack
# (postgres:16 + odoo:19), installs the public addons, regenerates the paper's CORE tables into
# results/repro/ (NEVER overwriting the committed reference), byte-diffs them against results/, runs
# the regression gate on BOTH schema variants, and prints REPRODUCE: PASS|FAIL. Self-cleaning.
#
#   tools/reproduce.sh            # core: §4.1-§4.6 (both variants) + ci_gate
#   tools/reproduce.sh --all      # + §5.4/§6/§7/§10.1/§10.1.1-replay drivers
#
# The user's own containers are untouched (distinct compose project). See REPRODUCE.md.
set -uo pipefail
cd "$(dirname "$0")/.."                     # repo root
PROJ="pgagent-ae"
ADDONS="/repo/addons,/usr/lib/python3/dist-packages/odoo/addons"
DB="authzbench"
MANIFEST="addons/pco_core_mock/__manifest__.py"
ALL=0; [ "${1:-}" = "--all" ] && ALL=1

DC="docker compose -p $PROJ"
cleanup() { git checkout -- "$MANIFEST" 2>/dev/null; $DC down -v >/dev/null 2>&1; }
trap cleanup EXIT

_odoo() { $DC run --rm --entrypoint odoo odoo "$@"; }                       # explicit-flags path
_shell() { $DC run --rm -T -e REPRO_ALL="$ALL" --entrypoint odoo odoo shell -d "$DB" \
             --addons-path="$ADDONS" --db_host=db --db_port=5432 --db_user=odoo --no-http; }

_install() {                                # (re)install the two addons against the chosen variant
  $DC exec -T db psql -U odoo -d postgres -c "DROP DATABASE IF EXISTS $DB;" >/dev/null 2>&1
  _odoo -d "$DB" --addons-path="$ADDONS" --db_host=db --db_port=5432 --db_user=odoo \
    -i pco_core_mock,pg_agent_guard --stop-after-init --no-http --without-demo=all 2>&1 | tail -2
}

echo "== AE reproduce (isolated project: $PROJ) =="
$DC up -d db
for i in $(seq 1 30); do $DC exec -T db pg_isready -U odoo >/dev/null 2>&1 && break; sleep 1; done

rm -rf results/repro && mkdir -p results/repro/vrule

# ── V-vuln (default manifest) ────────────────────────────────────────────────
echo "-- install + run (V-vuln) --"; _install
GATE1=$(_shell <<'PY' 2>/dev/null
exec(open('tests/evaluation_script.py').read())
export_results(env, outdir='results/repro')
if __import__('os').environ.get('REPRO_ALL') == '1':
    redteam(env, outdir='results/repro'); policy_model(env, outdir='results/repro')
    docrag(env, outdir='results/repro'); agent_loop(env, outdir='results/repro')
    integrity(env, outdir='results/repro'); integrity_formula(env, outdir='results/repro')
    try: llm_eval(env, plans_path='results/llm/plans.json', outdir='results/repro/llm')
    except Exception as e: print('llm_eval skipped:', e)
print('GATE1:', ci_gate(env))
PY
)
echo "$GATE1" | grep -q 'BENCH_GATE: PASS' && G1=PASS || G1=FAIL

# ── V-rule (naive-fix variant) ───────────────────────────────────────────────
echo "-- install + run (V-rule) --"
sed -i.bak 's#"security/team_security[A-Za-z_]*\.xml"#"security/team_security_vrule.xml"#' "$MANIFEST" && rm -f "$MANIFEST.bak"
_install
GATE2=$(_shell <<'PY' 2>/dev/null
exec(open('tests/evaluation_script.py').read())
export_results(env, outdir='results/repro/vrule')
print('GATE2:', ci_gate(env))
PY
)
echo "$GATE2" | grep -q 'BENCH_GATE: PASS' && G2=PASS || G2=FAIL
git checkout -- "$MANIFEST"

# ── byte-diff the core tables vs the committed reference ──────────────────────
echo "-- byte-diff results/repro vs committed results --"
CORE="plane_comparison.csv ablation.csv adaptive_probing.csv denial_channel.csv results.json"
# --all also regenerates these byte-stable driver tables (RQ6/RQ7/RQ8 + agent-loop + LLM-replay
# + RQ10 write plane + §4.8 structural overhead; write_attacks/overhead are emitted by export_results).
EXTRA="redteam.csv policy_model.csv docrag.csv agent_loop.csv integrity.csv integrity_formula.csv write_attacks.csv overhead.csv llm/eval.csv"
[ "$ALL" = 1 ] && CHECK="$CORE $EXTRA" || CHECK="$CORE"
DIFFS=0
for f in $CHECK; do
  if ! diff -q "results/$f" "results/repro/$f" >/dev/null 2>&1; then echo "  DIFF (V-vuln): $f"; DIFFS=$((DIFFS+1)); fi
done
VCHECK="$CORE"; [ "$ALL" = 1 ] && VCHECK="$CORE write_attacks.csv"   # V-rule write plane (RQ10 sibling parallel)
for f in $VCHECK; do
  if [ -f "results/vrule/$f" ] && ! diff -q "results/vrule/$f" "results/repro/vrule/$f" >/dev/null 2>&1; then
    echo "  DIFF (V-rule): $f"; DIFFS=$((DIFFS+1)); fi
done

echo "============================================================"
echo "gates: V-vuln=$G1  V-rule=$G2   core byte-diffs: $DIFFS"
if [ "$G1" = PASS ] && [ "$G2" = PASS ] && [ "$DIFFS" -eq 0 ]; then
  echo "REPRODUCE: PASS  (core tables byte-identical to committed; gate green on both variants)"; exit 0
fi
echo "REPRODUCE: FAIL  (see diffs/gates above; if diffs are first-run vs an older image, regenerate the reference)"
exit 1
