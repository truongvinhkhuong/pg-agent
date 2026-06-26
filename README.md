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
│       ├── services/numeric_verifier.py   # TB.1 pure numeric verifier — RQ6 (no Odoo/LLM)
│       ├── audit/audit_log.py      #   INDEPENDENT audit (stdlib logging + ir.logging; no tdh_audit)
│       └── security/pep_groups.xml
├── data/erp_authzbench/
│   ├── generate_synthetic.py       # deterministic synthetic generator (no real data)
│   ├── attacks.py                  # core suite (v3.1) + tagged extensions
│   ├── adaptive.py                 # T4.5 adaptive-probing variant suite
│   ├── redteam.py                  # T4.5+ automated red-team: deterministic ORM-pivot grammar generator (no LLM)
│   ├── policy_closure.py           # F10: pure closure-derivation core — derive_closures + derive_gaps (no Odoo)
│   ├── domain_ast.py               # F10: pure ir.rule domain extractor (parse_domain + governance_fields)
│   ├── policy_emit.py              # F10 Increment 2: pure emit core (POLICY + native ir.rule, no Odoo)
│   ├── endemic.py                  # corpus endemicity aggregator: breadth + per-domain distribution (pure)
│   ├── policy_model.py             # RQ7: pure ABAC×ReBAC formalization of POLICY (round-trips to _authz_domain)
│   ├── docrag.py                   # RQ8 L5: pure Doc-RAG corpus + deterministic lexical retriever (no LLM)
│   ├── agent_loop.py               # End-to-end agent-loop proxy: ScriptedAgent + LLMAgent seam (no LLM in CI)
│   ├── integrity.py                # T4.3 integrity test set + wrong-formula set (symbolic gold) — RQ6
│   ├── metrics.py                  # TB.3 governed-metrics registry (no Odoo)
│   ├── consistency.py              # TB.2 pure execution-voting core (no Odoo)
│   └── attacks_experimental.py     # ungrounded generality demos (ownership-bypass)
├── tests/
│   ├── evaluation_script.py        # benchmark harness -> environment × attack matrix + metrics
│   ├── policy_linter.py            # F10 PoC: pco-mock policy-closure differential linter
│   ├── policy_scan.py              # F10 Increment 1: module-agnostic scale scan (real Odoo CE)
│   ├── test_output_validator.py    # offline pytest (no Odoo)
│   ├── test_sensitivity_registry.py  # offline pytest (no Odoo)
│   ├── test_policy_closure.py      # offline pytest — closure-derivation core (no Odoo)
│   ├── test_policy_scan.py         # offline pytest — derive_gaps + governance_fields (no Odoo)
│   ├── test_policy_emit.py         # offline pytest — emit core (no Odoo)
│   ├── test_numeric_verifier.py    # offline pytest — numeric verifier (no Odoo)
│   └── test_metrics_and_consistency.py  # offline pytest — metrics + voting + TB.1 blind-spot (no Odoo)
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
eliminated"). The integrity counterpart (wrong-number variants) is now covered by the integrity set
(T4.3) + numeric verifier (TB.1) — see below.

### Automated red-team (T4.5+)

[`redteam.py`](data/erp_authzbench/redteam.py) replaces the 14 hand-picked pivots with a
**deterministic combinatorial generator** that *exhausts* a defined ORM-pivot grammar — a strict
**super-set** of the manual families. Every generated variant is emitted in the `ADAPTIVE` schema and
runs through the **same two-mode oracle** (undefended = the automatic meaningfulness filter; defended =
the reported result), so [`ci_gate`](tests/evaluation_script.py) fails on **any** in-scope variant that
survives the guard. Generated on the V-vuln schema (Odoo 19, verified):

| family | enumerated | residual-leak / fired |
|---|---|---|
| `traversal-pivot` | child rows via every model × type-valid op over visible fields | **0/5** |
| `field-extraction-pivot` | every confidential field × `search_read`/`read_group` path | **0/19** *(1 non-firing — empty seed value)* |
| `aggregation-structure-pivot` | `search_count` per model + confidential-first mixed `groupby` | **0/4** |
| `existence-pivot` | one denial probe per non-governed model (res.users/company/partner/groups/currency, ir.config_parameter) | **0/6** |
| `answer-channel-paraphrase` | VN/EN spelled-out numbers + space/dash/dot/underscore-split codes | **6 `residual-known`** |

**41 variants, 34 in-scope fired, residual-leak 0** (V-vuln); under V-rule more pivots go `non-firing`
(the native `order_id.team_code` rule blocks line-traversal undefended) while the forgotten
payment/guarantee siblings still fire and are held. The grammar's safety is proven **offline before the
gate runs** by [`tests/test_redteam.py`](tests/test_redteam.py) — most importantly that every
`expect_masked` equals the exact set the `sensitivity` registry would mask for the persona, so the gate
can never red-fail on a legitimately-visible field.

**Honest framing.** This is a *grammar generator*: **NO LLM** (structured enumeration, not an "AI
red-team"); **not** random/fuzzing (fully deterministic — stable ids, sorted tuples); **exhaustive over
the grammar** (which models the child-traversal / field-extraction / aggregation-structure /
existence-inference surface), **not** over the universe of all attacks. A green gate ⇒ *no bypass at any
enumerated grammar point and a regression that opens one fails CI*, **not** a proof the guard is
universally correct.

### Integrity — numeric verifier (RQ6)

The proposal's **applied / adopt-not-invent** pillar: the LLM must not do arithmetic — every number in
the answer must **bind to the execution result** (present in the governed table, or a deterministic
derivation: sum / diff / ratio / pct-change / share, within tolerance). [`numeric_verifier.py`](addons/pg_agent_guard/services/numeric_verifier.py)
is a pure, offline-tested scanner (14 cases incl. the no-false-flag derived ones); the guard wraps it as
`guarded_verify_numbers`. The integrity set [`integrity.py`](data/erp_authzbench/integrity.py) has 6
questions across **5 kinds** (aggregation / ratio / growth-% / period-comparison / multi-step), each with
a **symbolic gold** computed via a trusted sudo path.

`integrity(env)` ([committed results](results/integrity.csv)) plants a gold-derived **correct** answer and a
silently-**wrong** one per question and runs the verifier:

| metric | result |
|---|---|
| Silently-Wrong-Number Rate | raw text-to-ORM **6/6** (wrong present) → **+numeric-verifier 0/6** (slips through) |
| false-flag rate on correct/derived answers | **0/6** (passes growth-%, ratios, negative diffs — the hard case) |
| coverage | **5/5 kinds** |

**Honest scope:** no LLM in the public artifact — this demonstrates the verifier's *mechanism* (catch
unbindable, pass legitimate derivations), not a measured model hallucination rate (validated privately).
TB.1 catches **fabricated / cross-data** numbers but **misses correct-arithmetic-with-the-wrong-formula**
(a number that *is* a valid derivation of the data yet answers a different question) — closed by TB.2/TB.3 below.

#### Wrong-formula — governed metrics (TB.3) + self-consistency (TB.2)

[`metrics.py`](data/erp_authzbench/metrics.py) is a governed-metric registry (5 metrics; `metric_engine` computes
each deterministically *through the guard* — the authz domain pins the rows, the registry pins measure+agg → the
right formula over the right rows by construction). [`consistency.py`](data/erp_authzbench/consistency.py) is a pure
execution-voting core (strict majority; a minority wrong-formula is outvoted, a no-majority question is refused).
[`integrity_formula(env)`](results/integrity_formula.csv) runs the ladder on 6 wrong-formula questions whose wrong
value **binds under TB.1** (it equals a legitimate derivation target — an *identity*, *pairwise-diff* or *share* —
while answering a different question, e.g. one team's total reported as the all-team total):

| config | wrong-formula caught |
|---|---|
| TB.1 only (numeric verifier) | **0/6** — every wrong value binds → silently wrong |
| + TB.3 (governed metric, `raw != governed`) | **4/6** — the in-scope questions |
| + TB.2 (self-consistency vote) | **6/6** — the out-of-scope tail (no metric) |

Governed-metric coverage **4/6** (hybrid: out-of-scope carried by the vote). A 7th *contrast* question
(`sum(amount_subtotal)` — forgot tax) is **caught by TB.1 already** (unbindable) — kept to mark the taxonomy
boundary, excluded from the 0/6. Offline-tested by [`tests/test_metrics_and_consistency.py`](tests/test_metrics_and_consistency.py)
(17 cases incl. deterministic proofs that WF-A..D bind TB.1 and the contrast does not). **Does not** claim a
real-LLM wrong-formula rate (candidates/metric-selection are planted; mechanism demo only) or universal coverage.

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
redteam(env)                    # automated red-team: enumerate the ORM-pivot grammar -> results/redteam.csv (T4.5+)
policy_model(env)               # ABAC/ReBAC formalization: round-trip vs _authz_domain -> results/policy_model.csv (RQ7)
docrag(env)                     # L5 Doc-RAG: retrieval-plane PEP (drop unauthorized + mask) -> results/docrag.csv (RQ8)
agent_loop(env)                 # end-to-end agent loop (ScriptedAgent): utility + answer channel -> results/agent_loop.csv
integrity(env)                  # numeric verifier vs silently-wrong numbers -> results/integrity.csv (RQ6)
integrity_formula(env)          # wrong-formula ladder: TB.1 -> +TB.3 -> +TB.2 -> results/integrity_formula.csv
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

**Endemicity (corpus scan):** [`policy_scan.scan_corpus`](tests/policy_scan.py) runs the same scanner over **11
CE business apps** (148 models) and summarizes the result via the pure
[`endemic.endemic_summary`](data/erp_authzbench/endemic.py): the gap recurs in **6 of 8 at-risk domains** (15
gaps — hr/project/account/sale/crm/stock; mrp/purchase clean), **0 verdict drift** vs the 3-module baseline
([`results/scale/corpus/`](results/scale/corpus/)). The headline is *breadth + the per-domain distribution*,
not a pooled % (15 of 2 072 reachable pairs = 0.7% — low per model, systematic across domains).

The pure derivation core (`policy_closure.derive_gaps`) + the AST extractor + the endemic aggregator are
offline-unit-tested by [`tests/test_policy_scan.py`](tests/test_policy_scan.py) and
[`tests/test_endemic.py`](tests/test_endemic.py) (incl. the calibration anchor vs the committed coverage.csv).

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

### ABAC/ReBAC formalization (RQ7)

The guard's bespoke per-model `POLICY` (`team_path` / `company_path` / `owner_path`) is, named
explicitly, an **instance of a general subject-context model** — every grant is a
**ReBAC relation-path** × an **ABAC attribute-predicate** × a **subject-context**.
[`policy_model.py`](data/erp_authzbench/policy_model.py) (pure, no Odoo) makes this formal and
**reuses the PCC-ERP machinery** it already rests on: `policy_closure._derive_path` (the relation
closure) and `domain_ast._CONTEXT_NAMES` (the recognized ABAC context-tokens).

`compile_policy` is a faithful transcription of `pep_guard._authz_domain` (leaves, order, fail-closed
`None`, the belongs-to-no-team `[('id','=',0)]` short-circuit). The driver
[`policy_model(env)`](tests/evaluation_script.py) proves the **live round-trip** — `compile_policy(...)
== guard._authz_domain(model)` for **20/20 persona × model** combinations (Odoo 19, verified) — and
emits the classification matrix ([`results/policy_model.csv`](results/policy_model.csv)):

| axis | relation_path (hops) | subject-context | kind |
|---|---|---|---|
| team | `team_code` (0) / `order_id.team_code` (1) | group-membership | **RBAC** as a data predicate |
| company | `company_id` (0) / `order_id.company_id` (1) | `company_ids` | **ABAC** tenant-set |
| owner | `salesperson_id` (0) | `user.id` | **ReBAC** principal-id |

Every team/company `relation_path` equals the **PCC-ERP BFS closure** (`closure_matches` ✓); the
company and owner contexts are recognized ABAC tokens, while **team is RBAC** (resolved via
`has_group`, its `group-membership` token is deliberately *not* in `_CONTEXT_NAMES`).

**Honest framing.** This is **formalization, not new enforcement** — it names what the guard already
does. It adds **zero** enforcement, ir.rule, or attack coverage; `ci_gate` and every benchmark number
are untouched (the driver is not called by the gate). It formalizes only the team/company/owner
predicates actually enforced — **no ABAC over state/date/region** (the generator does not populate
those, so such a predicate would be vacuous). It mirrors the **guard** (`_authz_domain`), which
intentionally differs from the leak oracle (`ground_truth_domain`, `= code` vs the guard's
`in [codes]`). No LLM.

### L5 Doc-RAG retrieval plane (RQ8)

The PEP extends from the structured-data plane to a **retrieval** plane. A RAG agent retrieves
document **chunks** (derived from records) to answer a question; the confused-deputy is the
RETRIEVER, which ranks the most *relevant* chunks regardless of whether the persona may read the
source record. [`docrag.py`](data/erp_authzbench/docrag.py) (pure, no Odoo) is a **deterministic
lexical retriever** + the chunk template; the enforcement is
[`guard.guarded_retrieve`](addons/pg_agent_guard/models/pep_guard.py) — it routes each retrieved
chunk's provenance back through the SAME data-plane guard (`guarded_search_read`): a chunk whose
source record is not row-authorized is **dropped**, and a survivor is delivered only **re-rendered
from the clearance-masked source**.

The driver [`docrag(env)`](tests/evaluation_script.py) measures retrieval leak UNDEFENDED vs guarded
against **independent oracles** — the full row-authz permitted set (unauthorized delivery) and the
SUDO cleartext value (`output_validator` as a presence scanner, never the guard's own verdict)
([`results/docrag.csv`](results/docrag.csv), Odoo 19, verified):

| attack | undef unauth/confid | guarded | note |
|---|---|---|---|
| cross-team-direct (`nhóm ttf` query) | 8/8 | **0/0** | every cross-team source row dropped |
| cross-team-incidental (generic query) | 8/12 | **0/0** | top-k spans teams; the ranker can't enforce team, the PEP does |
| confidential (own-team) | 4/8 | **0/0** | authorized rows survive, confidential spans masked |
| utility / false-block | 4/8 | **0/0** | same-team chunks survive, public `name` verbatim |

**undefended leaks 60 → guarded unauthorized 0, confidential 0, false-block 0.**

**Honest framing.** **NO LLM** — a deterministic lexical ranker stands in for the embedding retriever;
the security property (re-check provenance + mask at delivery) is **independent of the ranker**.
Threat model: the index holds **cleartext** and the ranker is **untrusted** — the PEP gates
**delivery, not the index** (so rank order can be influenced by confidential content even though that
content is never delivered: a named residual, not a value leak). Chunks here are **structured**
(field provenance), so masking is structural and avoids the output-validator paraphrase residual; a
true unstructured free-text chunk has no provenance, falls back to content-scanning, and inherits
that residual — carried as one `in_scope=False` free-prose probe. **Must NOT claim** a real-LLM/
embedding RAG rate, a secured index/ranker, or universal correctness.

## Continuous integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) gates every push to `main` and every PR:

- **`static-checks`** — syntax (`compileall`), the offline unit tests, and the **secret + raw-data
  regression gate** (`detect-secrets` against `.detect-secrets.baseline` + `check_no_raw_dumps.py`,
  run via `pre-commit`). A new secret or invoice-like blob turns CI red.
- **`authzbench`** — installs `pco_core_mock` + `pg_agent_guard` in **Odoo 19** (+ Postgres) and runs
  `ci_gate(env)` over **both schema variants** (V-vuln and V-rule). It fails unless the guard is
  clean (Unauthorized-Access = Data-Leakage = Existence-Inference = False-Block = 0), **no in-scope
  adaptive pivot survives the guard** (T4.5 residual-risk = 0; `residual-known` / `non-firing` never
  fail the gate), **no in-scope variant of the automated red-team grammar survives** (T4.5+ — the full
  enumerated ORM-pivot grammar, a super-set of the manual pivots), **and** the benchmark is meaningful
  (canonical attacks, adaptive pivots, and ≥12 generated red-team variants actually fire when
  undefended). This is the regression gate: any change that reopens a leak — on the canonical path,
  any hand-picked pivot, **or** any enumerated grammar point — turns CI red.

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
