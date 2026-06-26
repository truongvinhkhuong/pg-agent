# PG-Agent — Permission-aware RAG over Odoo ERP + ERP-AuthZBench

[![CI](https://github.com/truongvinhkhuong/pg-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/truongvinhkhuong/pg-agent/actions/workflows/ci.yml)

Public academic artifact for a permission-aware RAG agent on Odoo. It ships:

- **`pg_agent_guard`** — a model-agnostic Policy Enforcement Point (PEP), the research CORE.
- **`pco_core_mock`** — a 4-model sale-cluster schema skeleton (no business logic, no real data).
- **`ERP-AuthZBench`** — an adversarial benchmark with a 5-class authorization-bypass taxonomy.
- **`PCC-ERP`** — a policy-closure compiler (discover → derive → emit → verify) over the ORM relation graph.

📄 **[Technical report](docs/technical-report.md)** — results-led synthesis (problem, benchmark, PEP, the real
result tables, the closure compiler, related work, limitations).

It runs **end-to-end on the mock + synthetic data with no access to any private code** — so the
results are reproducible by reviewers. The same `pg_agent_guard` is separately validated against
the real private `pco_core` inside the company monorepo.

## Architecture principle (read first)

> **The public repo NEVER references the private one. Only the private repo references the public one.**

The real business code (`pco_core`) is *not* embedded here. The private monorepo consumes this
public repo as a pinned submodule for validation (see `scripts/setup_submodule.sh`). This keeps
public git history clean by construction and removes the leak foot-gun of a public→private link.

Design rationale and the public/mock/private boundary: **`docs/pg-agent/mock-boundary-spec.md`**
(currently in the private monorepo; move it here when publishing).

## Layout

```
pg-agent/
├── addons/
│   ├── pco_core_mock/              # Layer 1 — schema skeleton (4 sale models, KEEP fields only)
│   │   ├── models/                 #   pco.sale.order (+ .line/.payment/.guarantee)
│   │   └── security/
│   │       ├── security_groups.xml         # group lattice (TTV/TTF/TTR/view_all)
│   │       ├── team_security.xml           # V-vuln: header-only ir.rule (= prod today)
│   │       ├── team_security_vrule.xml     # V-rule: naive fix (line rule added)
│   │       └── ir.model.access.csv
│   └── pg_agent_guard/             # Layer 2 — the PEP (research CORE)
│       ├── models/pep_guard.py     #   T1.2 row-domain + T2.2 masking + T2.4 uniform-deny + T2.3 wrapper
│       ├── models/sensitivity.py   #   T2.1 sensitivity registry + clearance resolution (code-default)
│       ├── services/denial.py      #   T2.4 uniform empty result + constant-time floor/jitter
│       ├── services/output_validator.py  # T2.3 pure answer scanner (no Odoo/LLM)
│       ├── audit/audit_log.py      #   INDEPENDENT audit (stdlib logging + ir.logging; no tdh_audit)
│       └── security/pep_groups.xml
├── data/erp_authzbench/
│   ├── generate_synthetic.py       # deterministic synthetic generator (no real data)
│   ├── attacks.py                  # core suite (v3.1) + tagged extensions
│   ├── adaptive.py                 # T4.5 adaptive-probing variant suite
│   ├── policy_closure.py           # F10: pure closure-derivation core — derive_closures + derive_gaps (no Odoo)
│   ├── domain_ast.py               # F10: pure ir.rule domain extractor (parse_domain + governance_fields)
│   ├── policy_emit.py              # F10 Increment 2: pure emit core (POLICY + native ir.rule, no Odoo)
│   └── attacks_experimental.py     # ungrounded generality demos (ownership-bypass)
├── tests/
│   ├── evaluation_script.py        # benchmark harness -> environment × attack matrix + metrics
│   ├── policy_linter.py            # F10 PoC: pco-mock policy-closure differential linter
│   ├── policy_scan.py              # F10 Increment 1: module-agnostic scale scan (real Odoo CE)
│   ├── test_output_validator.py    # offline pytest (no Odoo)
│   ├── test_sensitivity_registry.py  # offline pytest (no Odoo)
│   ├── test_policy_closure.py      # offline pytest — closure-derivation core (no Odoo)
│   ├── test_policy_scan.py         # offline pytest — derive_gaps + governance_fields (no Odoo)
│   └── test_policy_emit.py         # offline pytest — emit core (no Odoo)
├── config/
│   ├── odoo.mock.conf              # PUBLIC mode (no private path)
│   └── odoo.prod.conf              # PRIVATE/validation mode
├── dependencies/pco_core/          # submodule mount — EMPTY in public (internal only)
├── scripts/
│   ├── setup_submodule.sh          # inverted submodule wiring (run in PRIVATE repo)
│   ├── colab_bootstrap.py          # (A) reviewer no-token path + (B) internal token path
│   └── check_no_raw_dumps.py       # custom anti-leak pre-commit hook
├── .gitignore
├── .pre-commit-config.yaml
└── .detect-secrets.baseline
```

## ERP-AuthZBench attack suite

**Core (maps to proposal v3.1 §8):**

| Class | Axis | What it shows |
|---|---|---|
| `relational-traversal` | team | header has the ir.rule, child doesn't → query the child directly |
| `aggregation-leak` | team | `read_group` exposes sums via a sibling the naive fix forgets |
| `sensitive-field-extraction` | field | confidential field (`payment.amount`) must be masked (T2.2) |
| `sensitive-measure-aggregation` | field | confidential measure dropped from `read_group` (T2.2) |
| `existence-inference` | existence | denied vs empty must be indistinguishable (T2.4 uniform-denial) |

**Extensions (beyond v3.1, grounded, tagged `tier=extension`):** `tenant-bypass` (company axis,
same N1 mechanism), `attribute-confusion` (decoy `sale_team_group` vs `team_code`).
**Experimental (ungrounded, separate file):** `ownership-bypass`.

Two schema variants (toggle the data file in `pco_core_mock/__manifest__.py`):
- **V-vuln** (`team_security.xml`) — faithful to production; header-only team rule.
- **V-rule** (`team_security_vrule.xml`) — naive line-only fix.

The guard is **safe on every class in both variants** (variant-independent by design). Exact
pass/fail is *measured* by the harness, not asserted.

### Plane comparison — the headline result (Odoo 19, V-vuln; verified)

Two baselines vs the PG-Agent PEP. **inherited-RBAC** = native Odoo record rules only
(Cortex-Analyst-style "inherit governance"); **action-authz** = OAP-style — authorize the
call (model allow-list + valid params) but do **not** filter result rows.

| attack | inherited-RBAC (native ir.rule) | action-authz (OAP) | PG-Agent (PEP) |
|---|---|---|---|
| relational-traversal | LEAK | LEAK | **safe** |
| aggregation-leak | LEAK | LEAK | **safe** |
| sensitive-field / measure | LEAK | LEAK | **safe** |
| tenant-bypass | LEAK | LEAK | **safe** |

**N4a/N5:** action-authz *denies a call to a non-whitelisted model* (it enforces the action plane)
but still **leaks rows of permitted models** — the confused-deputy / BOLA gap; and inheriting native
governance is incomplete. Only the **data-result-plane** PEP closes case #1.

### Variant + denial-channel results

- **V-rule** (naive line-only fix): inherited-RBAC/action-authz flip to *safe* for the line but
  `aggregation-leak` (payment) **still leaks** for both — point fixes don't compose. PG-Agent stays safe.
- **existence-inference**: inferable under inherited-RBAC and under the denial-rich PG-Agent baseline,
  **indistinguishable** once uniform-denial is on (T2.4) — Existence-Inference Rate 1→0.

Guard rates with uniform-denial ON: Unauthorized-Access 0/4, Data-Leakage 0/2, False-Block 0/2,
Existence-Inference 0/1 (→ 1/1 with the denial-rich baseline). The V-rule column is the
non-composability evidence: the naive per-model fix plugs `line` but forgets the `payment` sibling.

Committed reference copies of the **full V-rule matrix** live in [`results/vrule/`](results/vrule/)
(V-vuln stays in [`results/`](results/)). The V-rule plane table differs from V-vuln by a **single
row** — `relational-traversal` flips to `safe,safe` while `aggregation-leak` stays `LEAK,LEAK` — and
adaptive `adpt-trav-line*` go `non-firing` while the `payment`/`guarantee` sibling pivots stay
`held`: the same non-composability at the pivot level. PG-Agent is `safe`/`held` in both variants.

### Defense-in-depth ablation (each layer zeroes a distinct metric)

| rung | Unauthorized | DataLeakage | AnswerLeak | Existence-Inf |
|---|---|---|---|---|
| no-defense (sudo) | 4/4 | 2/2 | leak | infer |
| +ir.rule (native) | 3/4 | 2/2 | leak | infer |
| +PEP (row-domain) | **0/4** | 2/2 | leak | infer |
| +masking | 0/4 | **0/2** | leak | infer |
| +output-validation | 0/4 | 0/2 | **safe** | infer |
| +uniform-denial | 0/4 | 0/2 | safe | **0/1** |

Removing any single layer reopens exactly one metric → defense-in-depth is necessary (RQ3).

### Adaptive probing — residual authorization risk (T4.5)

Beyond the canonical attack of each class, [`adaptive`](data/erp_authzbench/adaptive.py) runs
*families of semantically-equivalent variants* that pursue one goal through different ORM paths
(pivots). Each variant is run **undefended** (must actually fire — meaningfulness) and **defended**;
the outcome is one of `held` / `RESIDUAL-LEAK` / `residual-known` / `non-firing`.

| family | pivots | residual-leak / fired |
|---|---|---|
| `traversal-pivot` | read cross-team rows via each sibling (line/payment/guarantee + cross-sibling read_group) | **0/4** |
| `field-extraction-pivot` | confidential value via direct field, related-stored child, aggregate measure, groupby-label | **0/4** |
| `aggregation-structure-pivot` | `search_count` inference; mixed allowed+confidential `groupby` | **0/2** |
| `existence-pivot` | denial-channel via fail-closed on denied models (res.users, res.company) | **0/2** |
| `answer-channel-paraphrase` | spelled-out number / space-split code that evade the output validator | **2 `residual-known`** |

In-scope families hold across every pivot → the PEP is robust to path-switching, not just the
canonical attack. The `answer-channel-paraphrase` family is **out of PEP scope** (`in_scope=False`)
and reports a *real* output-validator limit — measured by an independent ground-truth oracle, not by
the validator under test — so it is **documented, not hidden** ("report truthfully, don't claim
eliminated"). The integrity half of T4.5 (wrong-number variants) is deferred — blocked-on the
integrity test set (T4.3) and numeric verifier (TB.1), which are not part of this artifact yet.

## Run the benchmark (mock, no private access)

```bash
# 1) Offline unit tests — no Odoo, no LLM needed (validator + sensitivity registry):
python -m pytest tests/test_output_validator.py tests/test_sensitivity_registry.py
#    (or run directly: python tests/test_output_validator.py)

pip install pre-commit detect-secrets        # anti-leak tooling
pre-commit install

# 2) Start Odoo with the public config, install the two addons:
odoo-bin -c config/odoo.mock.conf -d authzbench -i pco_core_mock,pg_agent_guard --stop-after-init

# 3) Run the matrix from an Odoo shell (defended, then denial-rich baseline):
odoo-bin shell -c config/odoo.mock.conf -d authzbench --no-http <<'PY'
exec(open('tests/evaluation_script.py').read())
run(env)                        # uniform-denial ON  (defended)
run(env, denial_enabled=False)  # denial-rich baseline -> Existence-Inference Rate 1/1
ablation(env)                   # defense-in-depth ladder
adaptive(env)                   # adaptive probing -> residual-risk per family (T4.5)
export_results(env)             # regenerate every paper table -> results/*.csv + results.json
PY
```

`export_results(env)` is the one-command artifact: it writes `results/plane_comparison.csv`,
`results/ablation.csv`, `results/adaptive_probing.csv`, `results/denial_channel.csv`, and
`results/results.json` — the tables the paper cites (committed reference copies live in
[`results/`](results/)).

### Policy-closure differential linter (F10 PoC)

The guard's `POLICY` row-level closures are hand-written today. [`tests/policy_linter.py`](tests/policy_linter.py)
is the de-risking PoC for **F10** (an ERP Policy-Closure Compiler): it reads the ORM relation graph
(`ir.model.fields`) + existing `ir.rule`s, then for each `(model, axis)` decides
`GOVERNED` / `GAP` / `ROOT-UNGOVERNED` and **derives** the closure path that would fix a gap — confirming
each gap with a runtime differential test (child-direct vs closure-allowed rows as a restricted persona).

```bash
odoo-bin shell -c config/odoo.mock.conf -d authzbench --no-http <<'PY'
exec(open('tests/evaluation_script.py').read())   # harness globals (seed/personas/_write_csv)
exec(open('tests/policy_linter.py').read())
lint(env)        # -> results/policy_lint.csv  (re-run V-rule with outdir="results/vrule")
lint_gate(env)   # report-only: PASS unless a team GAP is un-POLICY'd or a path != POLICY
PY
```

Two payoffs it demonstrates on the mock: (1) the derived team/company paths **reproduce the hand-written
`POLICY`** (`matches_policy` column — a soundness check); (2) on **V-rule** it auto-flags the
`payment`/`guarantee` team `GAP` the naive line-only fix forgot (the static `GAP` verdict and the runtime
`LEAK` agree). The pure derivation core ([`data/erp_authzbench/policy_closure.py`](data/erp_authzbench/policy_closure.py))
is offline-unit-tested by `tests/test_policy_closure.py`. Company axis comes back `ROOT-UNGOVERNED` on every
model — no native company rule exists anywhere (the tenant-bypass vector). Committed reference copies:
[`results/policy_lint.csv`](results/policy_lint.csv) (V-vuln) and [`results/vrule/policy_lint.csv`](results/vrule/policy_lint.csv).

### Scale scan on real Odoo CE (F10 Increment 1)

[`tests/policy_scan.py`](tests/policy_scan.py) generalizes the linter to *any* module set and runs it on **vanilla
Odoo CE `sale`+`account`+`stock`** — a real, large schema (the private `pco_core` is validated separately via
`odoo.prod.conf`, never in this public repo). It is **purely static/read-only**: it auto-discovers the governance
graph from `ir.model.fields` + `ir.rule` with two semantic filters — **context-bound discriminators** (a field is
an axis only if a rule leaf binds it to the user/company context, via
[`domain_ast.governance_fields`](data/erp_authzbench/domain_ast.py)) and **containment-only edges**
(`required + ondelete=cascade`, so closures follow the composing parent, not audit/owner FKs).

Result (62 models, 15 containment edges, 6 discriminators; committed in
[`results/scale/coverage.csv`](results/scale/coverage.csv) + `rules.csv`):

- **5 genuine relational-traversal GAPs auto-discovered in vanilla Odoo CE** — a child reachable to a row-governed
  parent but lacking its own rule, e.g. `sale.order.line` → closure `order_id.user_id` (no own salesperson rule),
  `account.payment.term.line` → `payment_id.company_id`, `account.fiscal.position.account` →
  `position_id.company_id`, `stock.storage.category.capacity` → `storage_category_id.company_id`,
  `account.bank.statement.line` → `move_id.invoice_user_id`. The same data-result-plane failure class as the pco
  mock, now confirmed on a real ERP it does not own.
- **Governance-map correctness:** `company_id` is broadly `GOVERNED` (34/41 reachable) — the scanner agrees with
  Odoo's per-model multi-company design (soundness evidence; the noisy first pass that mis-classified
  `state`/`id`/`create_uid` as axes is gone).
- **Manual-burden (secondary, honest):** 11 relational closures auto-derived vs the 9 hand-written `POLICY` paths
  (~1.2×). CE containment chains are shallow, so the burden ratio is modest here; the heavier-burden / heavier-gap
  target is the bespoke `pco_core` (private) or a larger module set.

The pure derivation core (`policy_closure.derive_gaps`) + the AST extractor are offline-unit-tested by
[`tests/test_policy_scan.py`](tests/test_policy_scan.py) (20 cases incl. the audit-FK-closure regression).

### Emit + verify (F10 Increment 2)

The final step closes the loop: **emit** the derived closures as an enforceable artifact and **runtime-verify**
they close the gaps ([`data/erp_authzbench/policy_emit.py`](data/erp_authzbench/policy_emit.py), offline-tested by
[`tests/test_policy_emit.py`](tests/test_policy_emit.py)).

- **pco mock (end-to-end, runtime-verified):** [`policy_linter.emit_verify`](tests/policy_linter.py) emits a guard
  `POLICY` dict from the derived closures, asserts it **reproduces the hand-written `POLICY`** on the team/company
  axes (owner is a local field, out of closure scope → `None`), then **rebinds the guard's `POLICY` to the emitted
  one and re-runs `ci_gate`** → `BENCH_GATE: PASS` (the guard driven by the *auto-emitted* policy is leak-free, same
  as hand-written; `ci_gate`'s `noguard_leaks ≥ 3` gate is the meaningfulness contrast). So the bespoke `POLICY`
  table is **derivable, not hand-authored**.
- **real Odoo CE (emit-classify, read-only):** [`policy_scan.emit_classify`](tests/policy_scan.py) proposes a native
  `ir.rule` per gap, **gated on the PARENT rule's pushdownability** ([`results/scale/emit.csv`](results/scale/emit.csv)).
  Honest result: **1 of 5** gaps is soundly emittable (`stock.storage.category.capacity` →
  `[('storage_category_id.company_id','in',company_ids)]`); the other **4 are `manual-review`** because their parent
  rule is OR / `parent_of` / multi-field — we **refuse to push a complex parent domain into one child leaf** (not
  sound in general). That honest 1/5 is the real soundness frontier, surfaced by `parse_domain`, not hidden.

This proves the `POLICY` is mechanically derivable + enforces identically at runtime, and that native-rule emission
is sound exactly where the parent rule is pushdownable. It does **not** claim novel soundness on arbitrary domains
(4/5 manual-review by design), owner-axis derivability, or anything beyond read operations.

Repeat after switching `pco_core_mock/__manifest__.py` to `team_security_vrule.xml` and
reinstalling (`-u pco_core_mock`) to produce the V-rule row of the matrix —
`export_results(env, outdir="results/vrule")` writes it alongside the V-vuln copies
(committed reference copies live in [`results/vrule/`](results/vrule/)).

On Google Colab: `scripts/colab_bootstrap.py` → `public_path()` (no token needed).

## Continuous integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) gates every push to `main` and every PR:

- **`static-checks`** — syntax (`compileall`), the offline unit tests, and the **secret + raw-data
  regression gate** (`detect-secrets` against `.detect-secrets.baseline` + `check_no_raw_dumps.py`,
  run via `pre-commit`). A new secret or invoice-like blob turns CI red.
- **`authzbench`** — installs `pco_core_mock` + `pg_agent_guard` in **Odoo 19** (+ Postgres) and runs
  `ci_gate(env)` over **both schema variants** (V-vuln and V-rule). It fails unless the guard is
  clean (Unauthorized-Access = Data-Leakage = Existence-Inference = False-Block = 0), **no in-scope
  adaptive pivot survives the guard** (T4.5 residual-risk = 0; `residual-known` / `non-firing` never
  fail the gate), **and** the benchmark is meaningful (canonical attacks and adaptive pivots actually
  fire when undefended). This is the regression gate: any change that reopens a leak — on the
  canonical path **or** any pivot path — turns CI red.

## Anti-leak

- Pre-commit (`detect-secrets` + `check_no_raw_dumps.py`) is **defense-in-depth and bypassable**.
  The real controls are **server-side**: enable GitHub *Secret Scanning + Push Protection* and a
  branch-protection CI job that re-runs `detect-secrets` on every PR.
- Regenerate the baseline once locally: `detect-secrets scan > .detect-secrets.baseline`.
- Synthetic data is **generated**, never anonymized from production.

## Open decision

- **License:** deferred. The guard's `audit/` is deliberately isolated from the company's AGPL
  `tdh_audit`, so the academic/commercial license can be chosen later without AGPL network-clause
  contamination. Pick before publishing.

## First-time setup of this repo (clean history)

```bash
cd pg-agent
git init
git add .
git commit -m "feat: PG-Agent guard + pco_core_mock + ERP-AuthZBench scaffold"
# create the PUBLIC remote, then:
# git remote add origin git@github.com:<org>/pg-agent.git && git push -u origin main
```
