# Artifact Evaluation — pg-agent / ERP-AuthZBench

A permission-aware PEP guard for ERP LLM agents + the ERP-AuthZBench benchmark + the PCC-ERP
policy-closure compiler. **Public, synthetic-only, no private code, no API key needed for the core path.**

## Badges targeted
**Available** (public repo, MIT-style use) · **Functional** (`make test`) · **Reproduced** (`make reproduce`).

## Prerequisites
- **Docker 24+** with `docker compose` v2. ~4 GB RAM, ~2 vCPU.
- No network and no credentials for the core path. Python 3 (for `make test` / `make lint`).
- Runtimes: `make test` ≈ seconds · `make reproduce` ≈ 3–5 min · `make scale` ≈ 10–20 min.
- Images: `postgres:16`, `odoo:19` (pulled on first run). For *exact* string reproduction of the scale
  tier, pin a digest (e.g. `odoo:19@sha256:…`); the core tables do not depend on it (see Caveats).

## 1. Functional badge (no Docker)
```
make test          # 13 offline unit suites — no Odoo, no LLM, no network — seconds
```
These cover the pure cores (guard output-validator, sensitivity, policy-closure derivation, the PCC-ERP
soundness theorem, the numeric verifier, the red-team grammar, etc.) and self-check against committed
reference data.

## 2. Reproduced badge (the headline)
```
make reproduce     # isolated postgres:16 + odoo:19 (compose project `pgagent-ae`)
```
This installs the two public addons, regenerates the **core paper tables into `results/repro/`** (it never
overwrites the committed reference), **byte-diffs** them against the committed `results/`, runs the regression
gate on **both schema variants** (V-vuln + V-rule), and prints `REPRODUCE: PASS` only when every core table is
byte-identical **and** both gates pass. A green diff is the reviewer-visible proof.

```
make reproduce-all # also regenerates AND byte-diffs RQ6/RQ7/RQ8 + agent-loop + the LLM replay (committed plans.json)
make clean         # tears down ONLY the pgagent-ae stack + removes results/repro
```

## 3. Claim → command → output → paper section
| § | claim | command | output | tier |
|---|---|---|---|---|
| 4.1 | plane comparison (headline) | `export_results(env)` | `results/plane_comparison.csv` | **core (byte-stable)** |
| 4.2 | defense-in-depth ablation | `export_results(env)` | `results/ablation.csv` | **core** |
| 4.3 | adaptive probing residual | `export_results(env)` ; `redteam(env)` | `adaptive_probing.csv` ; `redteam.csv` | **core** ; reproduce-all |
| 4.4 | denial channel 1/1→0/1 | `export_results(env)` | `results/denial_channel.csv` | **core** |
| 4.5 | non-composability (V-rule) | reinstall V-rule → `export_results` | `results/vrule/*.csv` | **core (2nd variant)** |
| 4.6 | regression gate | `ci_gate(env)` (both variants) | stdout `BENCH_GATE: PASS` | **core** |
| 5.2 | CE scale scan | `scan(env, …)` | `results/scale/coverage.csv` | scale |
| 5.2.1 | endemicity (11 CE apps) | `scan_corpus(env, …)` | `results/scale/corpus/` | **scale (env-sensitive)** |
| 5.3 | emit + verify | `emit_classify(env)` | `results/scale/emit.csv` | scale |
| 5.3.1 | soundness frontier 1/5→3/5 | `soundness_report(env)` | `results/scale/soundness.csv` | **scale (env-sensitive)** |
| 5.5 | cross-engine RLS gap+fix (RQ9) | `make rls` (`tools/rls_probe.sh`) | `results/rls.csv` | **opt-in (db-only, byte-stable)** |
| 5.4 | ABAC/ReBAC round-trip (RQ7) | `policy_model(env)` | `results/policy_model.csv` | reproduce-all |
| 6.1 / 6.2 | integrity (RQ6) | `integrity(env)` ; `integrity_formula(env)` | `results/integrity*.csv` | reproduce-all |
| 7 | Doc-RAG plane (RQ8) | `docrag(env)` | `results/docrag.csv` | reproduce-all |
| 10.1 | agent-loop proxy (no LLM) | `agent_loop(env)` | `results/agent_loop.csv` | reproduce-all |
| 10.1.1 | real-LLM run | `tools/llm_planner.py` (key, **not reproducible**) ; `llm_eval(env)` (replay) | `results/llm/eval.csv` | **opt-in** |
| 10.2 | private production validation | — | — | **not reproducible (private)** |

`make scale` runs §5.2 / §5.2.1 / §5.3 / §5.3.1 (installs the CE apps; structural compare).

## 4. Expected headline numbers
- **§4.1** PG-Agent is `safe` on every row+field leak class; inherited-RBAC and action-authz both leak.
- **§4.2** each defense layer zeroes a distinct metric; full stack → Unauthorized 0/4, Data-Leakage 0/2,
  Answer-Leak safe, Existence-Inference 0/1.
- **§4.4** Existence-Inference 1/1 (denial OFF) → 0/1 (denial ON).
- **§4.6** `BENCH_GATE: PASS` on V-vuln **and** V-rule.
- **§5.3.1** the soundness theorem lifts emit 1/5 → 3/5 (4/6 on the Sales-app scan).
- **§5.5** Postgres RLS, as `app_user`: V-native child read leaks 12 rows / 6 cross-tenant (LEAK); the
  pushdown policy → 6 rows / 0 cross-tenant (SAFE); both positive controls `CONTROL-OK` (parent count 3<6).
- **§10.1.1** real-LLM ASR-without-guard 2/12, **guarded 0/12** (one run, one model — see caveats).

## 5. Isolation / safety
The reproduce stack is a pinned compose project **`pgagent-ae`** with its own network
(`pgagent-ae_default`), named volume (`pgagent-ae_pgdata`), and `pgagent-ae-*` containers. It **cannot** touch
any container or volume you run outside this repo; `make clean` (`docker compose -p pgagent-ae down -v`) removes
only `pgagent-ae_*`. No `.env`/credentials are read by the core path.

## 6. Honest caveats (please read)
- The **core 5 tables** are guard-logic outputs over fixed synthetic data (`seed=42`) and fixed attack/adaptive
  lists — **byte-stable** across runs and Odoo patch versions; `make reproduce` proves this by byte-diff.
- The **scale tier** (§5.2.1, §5.3.1) embeds live Odoo model/field/domain strings from the *installed CE module
  set at the pinned image*. We reproduce its **structure** (gap/domain/sound counts), not byte-equality, across
  patch versions; pin a digest for exact strings.
- **§10.1.1**: ASR 2/12 is **not a stable rate** (one run, one model, temperature 0, N=12, synthetic). The
  load-bearing claim is **guarded-leak = 0 regardless of model output**, replayed deterministically from the
  committed `results/llm/plans.json` with **no** model call. Phase-1 (`llm_planner.py`) needs your own API key
  and is **not** part of reproduction.
- **§10.2** (private production numbers) is **not reproducible** from this artifact by design — no real data and
  no real model are included; only the *measurement instrument* (`evaluation_script.py` / `ci_gate`) is public.
- `config/odoo.mock.conf` documents the **source-install** addons layout; the Docker path passes
  `--addons-path` explicitly (the image layout differs).
- **§5.5 (cross-engine RLS)** is a **demonstration of a gap *class*, not a defect or a rate**. Neither Odoo nor
  Postgres is "broken": both apply security per-relation by design and default-allow an ungoverned child. The
  vulnerable state is a realistic DBA misconfiguration (parent governed, FK-child not); the fix is the same
  predicate pushdown. The probe runs as a `NOSUPERUSER NOBYPASSRLS` role (a superuser/owner would bypass RLS) —
  the committed `parent-control` rows are the in-band proof that RLS actually fired. One schema, `postgres:16`,
  two tenants; reads no `.env`/credentials.
