# Artifact Evaluation — pg-agent / ERP-AuthZBench

A permission-aware PEP guard for ERP LLM agents + the ERP-AuthZBench benchmark + the PCC-ERP
policy-closure compiler. **Public, synthetic-only, no private code, no API key needed for the core path.**

## Badges targeted
**Available** (public repo, [MIT](LICENSE)-licensed, Zenodo DOI — §7) · **Functional** (`make test`) · **Reproduced** (`make reproduce`).

## Prerequisites
- **Docker 24+** with `docker compose` v2. ~4 GB RAM, ~2 vCPU.
- No network and no credentials for the core path. Python 3 (for `make test` / `make lint`).
- Runtimes: `make test` ≈ seconds · `make reproduce` ≈ 3–5 min · `make scale` ≈ 10–20 min.
- Images: `postgres:16`, `odoo:19` (pulled on first run). For *exact* string reproduction of the scale
  tier, pin a digest (e.g. `odoo:19@sha256:…`); the core tables do not depend on it (see Caveats).
- **Paper:** `make paper` typesets [`docs/paper.tex`](docs/paper.tex) → `docs/paper.pdf` in an isolated
  `texlive/texlive` container (XeLaTeX; the PDF + aux are gitignored build artifacts). Verified: 15-page PDF,
  no errors. The `.tex` numbers are a faithful port of [`docs/technical-report.md`](docs/technical-report.md).

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
| 4.7 | write-path confused-deputy + fix (RQ10) | `write_attacks(env)` (in `export_results`) | `results/write_attacks.csv` | **reproduce-all (byte-stable)** |
| 4.8 | PEP structural overhead (bounded) | `overhead(env)` (in `export_results`) | `results/overhead.csv` | **reproduce-all (byte-stable)** |
| 5.1 | differential linter (POLICY reproduced on the mock) | `lint(env)` | `results/policy_lint.csv` | reproduce-all |
| 5.2 | CE scale scan | `scan(env, …)` | `results/scale/coverage.csv` | scale |
| 5.2.1 | endemicity (11 CE apps) | `scan_corpus(env, …)` | `results/scale/corpus/` | **scale (env-sensitive)** |
| 5.3 | emit + verify | `emit_classify(env)` | `results/scale/emit.csv` | scale |
| 5.3.1 | soundness frontier 1/5→3/5 | `soundness_report(env)` | `results/scale/soundness.csv` | **scale (env-sensitive)** |
| 5.5 | cross-engine RLS gap+fix (RQ9) | `make rls` (`tools/rls_probe.sh`) | `results/rls.csv` | **opt-in (db-only, byte-stable)** |
| 5.6 | real-Odoo-schema enforcement | `make real-sale` (`tools/real_schema.sh`, installs `sale`) | `results/real_sale.csv` | **opt-in (byte-stable)** |
| 5.4 | ABAC/ReBAC round-trip (RQ7) | `policy_model(env)` | `results/policy_model.csv` | reproduce-all |
| 6.1 / 6.2 | integrity (RQ6) | `integrity(env)` ; `integrity_formula(env)` | `results/integrity*.csv` | reproduce-all |
| 7 | Doc-RAG plane (RQ8) | `docrag(env)` | `results/docrag.csv` | reproduce-all |
| 10.1 | agent-loop proxy (no LLM) | `agent_loop(env)` | `results/agent_loop.csv` | reproduce-all |
| 10.1.1 | real-LLM run (4 models / 2 providers) | `tools/llm_planner.py` (keys, **not reproducible**) ; `llm_eval(env)` (replay) | `results/llm/eval.csv` + `eval_summary.csv` | **opt-in** |
| 10.1.2 | indirect / tool-output injection (real 2-turn) | `tools/llm_planner.py --mode indirect` (keys) ; `llm_eval(env)` (replay) | `results/llm/eval_summary.csv` (scope=indirect) | **opt-in** |
| 10.2 | private production validation | — | — | **not reproducible (private)** |

`make scale` runs §5.2 / §5.2.1 / §5.3 / §5.3.1 (installs the CE apps; structural compare).

## 4. Expected headline numbers
- **§4.1** PG-Agent is `safe` on every row+field leak class; inherited-RBAC and action-authz both leak.
- **§4.2** each defense layer zeroes a distinct metric; full stack → Unauthorized 0/4, Data-Leakage 0/2,
  Answer-Leak safe, Existence-Inference 0/1.
- **§4.4** Existence-Inference 1/1 (denial OFF) → 0/1 (denial ON).
- **§4.8** PEP overhead is **statically bounded**: ≤3 indexed conjuncts, closure depth ≤1 (one indexed-FK hop),
  O(result×masked_fields) post-fetch masking — no per-row query / join explosion / quadratic term (`overhead.csv`,
  20 rows, byte-stable); a wall-clock ratio is **printed** (indicative, one machine, not committed).
- **§4.7** write/mutation plane: all 12 confused-deputy writes breach undefended → **guarded 0 residual-leak**
  (every one `held`); under V-rule the naive line rule plugs line create/overwrite/unlink but reassignment +
  the payment/guarantee siblings still breach (all held by the PEP).
- **§4.6** `BENCH_GATE: PASS` on V-vuln **and** V-rule.
- **§5.3.1** the soundness theorem lifts emit 1/5 → 3/5 (4/6 on the Sales-app scan).
- **§5.5** Postgres RLS, as `app_user`: V-native child read leaks 12 rows / 6 cross-tenant (LEAK); the
  pushdown policy → 6 rows / 0 cross-tenant (SAFE); both positive controls `CONTROL-OK` (parent count 3<6).
- **§5.6** real Odoo `sale.order.line` (bespoke restricted role, owner axis): V-native child read leaks 12 lines /
  6 cross-owner (LEAK); the PEP owner-pushdown → 6 lines / 0 cross-owner (SAFE); positive control `CONTROL-OK`
  (parent count 3<6 = the rule binds, run non-bypassing).
- **§10.1.1** real-LLM pooled ASR-without-guard **0.377** (26/69, Wilson 95% CI [0.272, 0.495]), **guarded 0/72**
  across 4 models / 2 providers (see caveats).
- **§10.1.2** indirect / tool-output injection (real 2-turn, poisoned RAG/ERP-note): **7/20** probes induced a
  cross-team call (10/20 resisted; `gpt-4o` resisted all 5), **guarded 0/20** — PEP provenance-invariance.

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
- **§10.1.1**: the pooled undefended **ASR 0.377 (Wilson 95% CI [0.272, 0.495])** over 4 models / 2 providers /
  72 prompts is **not a stable production rate** (one generation per model at temperature 0, small N, synthetic;
  *per-population* CIs, not seed/temperature variance). The load-bearing claim is **guarded-leak = 0 regardless
  of model output, across every model**, replayed deterministically (byte-stable) from the committed
  `results/llm/plans.json` with **no** model call. Phase-1 (`llm_planner.py`) needs your own API key(s)
  (`OPENAI_API_KEY` and/or `DEEPSEEK_API_KEY`; a provider whose key is unset is skipped) and is **not** part of
  reproduction.
- **§10.2** (private production numbers) is **not reproducible** from this artifact by design — no real data and
  no real model are included; only the *measurement instrument* (`evaluation_script.py` / `ci_gate`) is public.
- `config/odoo.mock.conf` documents the **source-install** addons layout; the Docker path passes
  `--addons-path` explicitly (the image layout differs).
- **§4.8 (overhead)** `overhead.csv` records **STRUCTURAL bounds** (leaf/hop/mask-surface counts — pure functions
  of POLICY+SENSITIVITY), byte-stable. The wall-clock microbenchmark is **PRINTED** by `overhead(env)` (one
  machine, N=200, relative medians — Python/Odoo timing is noisy), **NOT** byte-committed. We claim the added work
  is *statically bounded*, not a latency; no production load test, no committed `EXPLAIN`; the uniform-denial floor
  is a configurable knob (=0 here), not counted as overhead.
- **§4.7 (write/mutation plane)** is a deliberate, justified **scope expansion** (the read suite is read-only;
  the agent genuinely issues create/write/unlink tool-calls). It needs operational write ACL on the child models
  (the realistic ERP misconfiguration: write granted, record-rule scoping forgotten); this is **read-safe** — the
  read CORE tables stay byte-identical (the reproduce byte-diff proves it). `write_attacks.csv` records
  **verdicts only** (breach/denied/held), never auto-ids/timestamps, and every mutation is **savepoint-isolated**
  (rolled back; the driver asserts zero residue) → byte-stable. Not "Odoo is broken": a confused-deputy WRITE from
  a header-incomplete config; the PEP adds the missing USING + WITH-CHECK.
- **§5.5 (cross-engine RLS)** is a **demonstration of a gap *class*, not a defect or a rate**. Neither Odoo nor
  Postgres is "broken": both apply security per-relation by design and default-allow an ungoverned child. The
  vulnerable state is a realistic DBA misconfiguration (parent governed, FK-child not); the fix is the same
  predicate pushdown. The probe runs as a `NOSUPERUSER NOBYPASSRLS` role (a superuser/owner would bypass RLS) —
  the committed `parent-control` rows are the in-band proof that RLS actually fired. One schema, `postgres:16`,
  two tenants; reads no `.env`/credentials.

## 7. Archival and citation (Zenodo)

The "Artifacts Available" badge wants a **permanent, immutable** archive — a GitHub URL does not count, a Zenodo
DOI does. One-time setup (free):

1. At [zenodo.org](https://zenodo.org), **Log in with GitHub** and authorize.
2. Account → **GitHub** → toggle the **`pg-agent`** repository **on**. *(Must be on before the release.)*
3. On GitHub, publish a **Release** with a tag (e.g. `v1.0.0`). Zenodo's webhook archives the tagged source
   tree — driven by [`.zenodo.json`](.zenodo.json) / [`CITATION.cff`](CITATION.cff) — and mints a **DOI**
   (a *concept* DOI for all versions + a *version* DOI per release; cite the concept DOI).
4. Paste the concept DOI into the README badge + `CITATION.cff` `identifiers`.

The archived snapshot is the **git tree at the tag** — `.env` (gitignored, never committed) is **not** included.
Because the archive is immutable, only tag a release that is green end-to-end (`make test` + `make reproduce-all`
+ `make paper`). Rotating the local `OPENAI_API_KEY` is a separate, unrelated good-hygiene step.
