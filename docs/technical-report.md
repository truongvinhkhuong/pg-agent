# PG-Agent & ERP-AuthZBench: Authorization-Preserving LLM Agents over ERP, with a Policy-Closure Compiler

**Technical report** (results-led). Every number below is produced by the committed harness on the public
mock + synthetic data, or on vanilla Odoo CE — reproducible with no access to any private code. Reference
result tables live in [`results/`](../results/).

---

## Abstract

Enterprises are wiring tool-calling LLM agents into ERP systems to answer business questions in natural
language. We identify an authorization failure these agents expose at the **data-result plane**: a tool call
that is perfectly valid at the *control plane* (an allowed model, valid parameters) still returns rows the
user may not see, because the agent autonomously queries a **child model whose row-level record rule is
missing** while the parent's rule is present — *relational-traversal bypass*. This is a confused-deputy / BOLA
gap that warehouse-native governed-NL-analytics platforms (which inherit complete governance from the
warehouse) and action-plane authorization frameworks (which authorize the call, not the rows) do not address
for ERP. We contribute: (i) **ERP-AuthZBench**, an adversarial benchmark for row-level authorization of ERP
LLM agents; (ii) **PG-Agent**, a model-agnostic data-result-plane Policy Enforcement Point (PEP) that is
clean on every benchmark class; and (iii) **PCC-ERP**, a policy-closure compiler that *derives* the per-model
row-level closures from the ORM relation graph + existing record rules, emits them as enforceable policy, and
runtime-verifies gap closure — validated on the mock end-to-end and on vanilla Odoo CE `sale`+`account`+`stock`.

The contribution is scoped honestly to **applied security + benchmark + reference implementation** for an
under-served setting (ERP record-rule governance that is incomplete on child models), not to a novel
unification of authorization and integrity (prior art) nor to novel soundness on arbitrary policy domains.

---

## 1. Problem

### 1.1 Control plane vs data-result plane

- **Control plane (action):** "may the agent call tool *T* with parameters *P*?" — the plane that pre-action
  authorization frameworks (OAP, PCAS, SEAgent, AgentGuardian) govern.
- **Data-result plane:** "do the rows *T* returns match the record-rule the user is entitled to?" This is the
  axis we attack, in the setting where ERP governance is **incomplete**.

### 1.2 Why ERP differs from warehouse-native

Warehouse-native governed-NL-analytics (Snowflake Cortex Analyst, Databricks Genie, MS Fabric Data Agent)
**inherit complete governance** from the warehouse (RBAC, RLS, column masks applied uniformly at query time).
ERP (Odoo) enforces row security via **ORM record rules** that, in practice, **do not cover every relation**:
a team rule sits on the order header but not on its lines/payments/guarantees. Odoo record rules are
**default-allow** — if an ACL grants access and no rule applies to the model/operation/user, the rows are
returned. An LLM agent enlarges the attack surface precisely because it autonomously chooses the child/tool
path a human rarely takes. (This direct-child-query bypass is documented native RLS behavior in other engines
too — e.g. SQL Server applies a parent predicate only when the child is queried *via* the parent — so the
phenomenon is general; the novelty is its agent-driven exploitation in ERP + the benchmark + the closure
compiler.)

### 1.3 Threat model (summary)

Attacker = an employee probing beyond scope / prompt-injection / chaining, with a real role, natural-language
prompts only, no code or policy edits, observing refusal responses + latency. Defender = a deterministic PEP
at the data-result plane, with the **LLM kept outside the security boundary** (it does not decide
authorization — OrgAccess shows GPT-4.1 reaches only F1≈0.27 on RBAC reasoning). Out of scope: infrastructure
RCE, write/create/unlink, model extraction.

---

## 2. ERP-AuthZBench

A public, reproducible adversarial benchmark for row-level authorization of ERP LLM agents.

- **Schema mock** ([`addons/pco_core_mock`](../addons/pco_core_mock)): a 4-model sale cluster —
  `pco.sale.order` (header, carries `team_code` + `company_id`) and three children
  (`.line`/`.payment`/`.guarantee`, each `order_id → header`). Authz-relevant field *names* are kept verbatim
  (they are the guard contract); no business logic, no real data.
- **Two schema variants** (the heart of the benchmark): **V-vuln** = team rule on the header only (faithful to
  production); **V-rule** = a *naïve fix* that adds a rule on the line but forgets the payment/guarantee
  siblings. The guard column is variant-independent by construction.
- **Synthetic data** ([`generate_synthetic.py`](../data/erp_authzbench/generate_synthetic.py)): deterministic
  (`seed=42`), generated — never anonymized from production.
- **Attack suite** ([`attacks.py`](../data/erp_authzbench/attacks.py)): 5 core classes
  (`relational-traversal`, `aggregation-leak`, `sensitive-field-extraction`, `sensitive-measure-aggregation`,
  `existence-inference`) + grounded extensions (`tenant-bypass`, `attribute-confusion`) + an **adaptive**
  residual-risk suite ([`adaptive.py`](../data/erp_authzbench/adaptive.py)).
- **Oracle harness** ([`evaluation_script.py`](../tests/evaluation_script.py)): each attack runs against a
  ground-truth oracle under three planes (native ir.rule, OAP-style action-authz, PG-Agent PEP); pass/fail is
  **measured, not asserted**. *Caveat:* the public harness is oracle-based (deterministic ORM-level attacks);
  it does not drive a real LLM loop — that integration is validated separately in the private monorepo.

---

## 3. PG-Agent: the data-result-plane PEP

A model-agnostic PEP ([`pg_agent_guard`](../addons/pg_agent_guard)) the agent must call instead of the ORM:

1. **Row-domain enforcement** — inject a forced row-level domain (team/company/owner) per model, including the
   relation-traversal path for children (`order_id.team_code`); **fail-closed** on any model not in policy.
2. **Sensitivity-aware masking** — drop above-clearance fields *before* the LLM context; deny confidential
   `read_group` measures and above-clearance group-keys.
3. **Output validation** — scan the final answer for leaked masked / cross-team values.
4. **Uniform denial** — identical empty result + constant-time/jitter, defeating existence-inference via the
   denial channel.
5. **Independent audit** — per-call decision log (stdlib, isolated from any AGPL audit module).

---

## 4. Evaluation (real numbers)

All tables below are the committed reference copies in [`results/`](../results/) (V-vuln) and
[`results/vrule/`](../results/vrule/), regenerated by `export_results(env)` in an Odoo 19 shell.

### 4.1 Plane comparison — the headline (V-vuln) · [`plane_comparison.csv`](../results/plane_comparison.csv)

| attack | inherited-RBAC (native ir.rule) | action-authz (OAP) | PG-Agent (PEP) |
|---|---|---|---|
| relational-traversal | LEAK | LEAK | **safe** |
| aggregation-leak | LEAK | LEAK | **safe** |
| sensitive-field-extraction | LEAK | LEAK | **safe** |
| sensitive-measure-aggregation | LEAK | LEAK | **safe** |
| tenant-bypass | LEAK | LEAK | **safe** |
| existence-inference | infer | indist | indist |

Row+field leak rate: inherited-RBAC **5/6**, action-authz **5/6**, PG-Agent **0/6** (false-block 0/2).
**N4a/N5:** action-authz *denies a call to a non-whitelisted model* yet still **leaks rows of permitted
models** (the confused-deputy gap); inheriting native governance is incomplete. Only the data-result-plane PEP
closes the case.

### 4.2 Defense-in-depth ablation (V-vuln) · [`ablation.csv`](../results/ablation.csv)

| rung | Unauthorized | DataLeakage | AnswerLeak | Existence-Inf |
|---|---|---|---|---|
| no-defense (sudo) | 4/4 | 2/2 | leak | infer |
| +ir.rule (native) | 3/4 | 2/2 | leak | infer |
| +PEP (row-domain) | **0/4** | 2/2 | leak | infer |
| +masking | 0/4 | **0/2** | leak | infer |
| +output-validation | 0/4 | 0/2 | **safe** | infer |
| +uniform-denial | 0/4 | 0/2 | safe | **0/1** |

Each layer zeroes exactly one metric → defense-in-depth is necessary (no layer is redundant).

### 4.3 Adaptive probing — residual risk · [`adaptive_probing.csv`](../results/adaptive_probing.csv)

14 pivot variants test whether the PEP holds as an adversary switches paths. Every **in-scope** family holds
with **0 residual leaks**: traversal-pivot 0/4, field-extraction-pivot 0/4, aggregation-structure-pivot 0/2,
existence-pivot 0/2 (all fire undefended → not vacuous). The `answer-channel-paraphrase` family is **out of PEP
scope** and reports **2 documented residuals** (a confidential value spelled in words / a code split by spaces
evades the output validator's regex) — measured by an independent ground-truth oracle, reported not hidden.

### 4.4 Denial channel · [`denial_channel.csv`](../results/denial_channel.csv)

Existence-Inference Rate: **1/1 with uniform-denial OFF** (denial-rich baseline leaks existence) → **0/1 with
uniform-denial ON**. The denial channel is real and the uniform-denial layer closes it.

### 4.5 Variant comparison — non-composability (V-rule) · [`results/vrule/`](../results/vrule/)

The V-rule plane table differs from V-vuln by a **single row**: `relational-traversal` flips to `safe,safe`
(the line rule plugs it) while `aggregation-leak` (payment) **stays `LEAK,LEAK`** for both baselines — the
naïve per-model fix forgets the sibling. Ablation `+ir.rule` improves to 2/4 (vs 3/4) but PEP is still needed
for the rest. Adaptive mirrors it: `adpt-trav-line*` go `non-firing` (rule added) while payment/guarantee
pivots stay `held`. **PG-Agent is safe/held in both variants** — point fixes don't compose; the PEP does.

### 4.6 Regression gate

CI (`.github/workflows/ci.yml`) installs the addons in **Odoo 19 + Postgres** and runs `ci_gate(env)` over
**both variants**; it fails unless Unauthorized = Data-Leakage = Existence-Inference = False-Block = 0, **no
in-scope adaptive RESIDUAL-LEAK**, and the benchmark is meaningful (attacks fire undefended). Any change that
reopens a leak — canonical path or pivot path — turns CI red.

---

## 5. PCC-ERP: a policy-closure compiler

PG-Agent's per-model row closures are a hand-written `POLICY` today. PCC-ERP **derives** them and closes the
loop **discover → derive → emit → enforce → verify**. Pure cores
([`policy_closure.py`](../data/erp_authzbench/policy_closure.py),
[`domain_ast.py`](../data/erp_authzbench/domain_ast.py),
[`policy_emit.py`](../data/erp_authzbench/policy_emit.py)) are offline-unit-tested; drivers run in an Odoo
shell, read-only.

### 5.1 Differential linter on the mock · [`policy_lint.csv`](../results/policy_lint.csv)

From `ir.model.fields` + `ir.rule`, classify each `(model, axis)` as GOVERNED/GAP/ROOT-UNGOVERNED and derive
the closure path; confirm each gap with a runtime differential test (child-direct vs closure-allowed rows).
**V-vuln:** 3 team GAPs (line/payment/guarantee, closure `order_id.team_code`) + `LEAK`; company axis
ROOT-UNGOVERNED everywhere (the tenant-bypass vector); **all derived paths reproduce the hand-written POLICY**
(soundness). **V-rule:** line GOVERNED, payment/guarantee still GAP — the linter auto-flags exactly the
non-composable siblings the naïve fix missed.

### 5.2 Scale on vanilla Odoo CE · [`results/scale/coverage.csv`](../results/scale/coverage.csv)

Generalized to any module set and run on **`sale`+`account`+`stock`** (private `pco_core` is off-limits to the
public repo; validated separately via `odoo.prod.conf` in the private monorepo). Two semantic filters make it
credible: **context-bound discriminators** (a field is an axis only if a rule leaf binds it to the
user/company context — `governance_fields`) and **containment-only edges** (`required + ondelete=cascade`, so
closures follow the composing parent, not audit/owner FKs).

Result: **62 models, 15 containment edges, 6 discriminators**; `company_id` broadly **GOVERNED (34/41
reachable)** — the scanner agrees with Odoo's multi-company design (soundness evidence); and **5 genuine
relational-traversal GAPs auto-discovered** on a real ERP it does not own:

| child model | discriminator | derived closure |
|---|---|---|
| `sale.order.line` | user_id | `order_id.user_id` |
| `account.payment.term.line` | company_id | `payment_id.company_id` |
| `account.fiscal.position.account` | company_id | `position_id.company_id` |
| `account.bank.statement.line` | invoice_user_id | `move_id.invoice_user_id` |
| `stock.storage.category.capacity` | company_id | `storage_category_id.company_id` |

Manual-burden (secondary, honest): 11 relational closures auto-derived vs the 9 hand-written `POLICY` paths
(~1.2×) — CE containment chains are shallow, so the ratio is modest; the heavier target is the bespoke
`pco_core` / larger module sets.

### 5.3 Emit + runtime-verify · [`results/scale/emit.csv`](../results/scale/emit.csv)

- **pco mock (end-to-end):** emit a guard `POLICY` from the derived closures; it **reproduces the hand-written
  POLICY** on team/company (owner is a local field, out of closure scope); rebinding the guard's POLICY to the
  emitted dict and re-running `ci_gate` yields **BENCH_GATE: PASS** — the guard driven by the *auto-emitted*
  policy is leak-free, identical to hand-written. The bespoke POLICY is **derivable, not hand-authored**.
- **real Odoo CE (emit-classify, read-only):** propose a native `ir.rule` per gap, **gated on the parent
  rule's pushdownability**. Honest result: **1 of 5** is soundly emittable
  (`stock.storage.category.capacity → [('storage_category_id.company_id','in',company_ids)]`); the other **4
  are manual-review** because their parent rule is OR / `parent_of` / multi-field. We **refuse to push a
  complex parent domain into one child leaf** (not sound in general) — that 1/5 is the real soundness frontier,
  surfaced by `parse_domain`, not hidden.

---

## 6. Related work & positioning

- **Governed + secure NL analytics (prior art for the "unified" pillar):** Cortex Analyst, Databricks Genie,
  MS Fabric Data Agent (industry); SAFEFLOW (IFC, integrity+confidentiality). All **assume complete/inherited
  governance** and do not target ERP record rules or adversarial row-level testing.
- **Action/flow-plane authorization for agents:** OAP, PCAS, SEAgent, AgentGuardian, ClawGuard, AgentBound —
  govern the call, **not** the result rows; we use an OAP-style baseline.
- **Database access-control synthesis:** DePLOI/IBAC-DB synthesizes/audits **table-level** grants from NL
  intent; OPA partial-eval / predicate pushdown compile policy→filter. PCC-ERP differs in **relational-closure
  derivation across the ORM graph** (which child needs which parent's pushed-down rule), not the filter
  mechanics.
- **RBAC / agent-security benchmarks:** OrgAccess (RBAC reasoning, GPT-4.1 F1≈0.27 — motivates LLM-outside),
  ASB, SecureMCP (table/column RBAC), Role-Conditioned Refusals (text-to-SQL).

**Novelty (honest):** the *combination* — ERP record-rule incompleteness on child models × agent-driven
relational-traversal exploitation × the first adversarial benchmark × a relational-closure compiler — not any
single mechanism. We explicitly do **not** claim a novel authz+integrity unification (prior art) or a general
policy compiler for agents (PCAS/OAP-adjacent). Subtitle framing: *"Policy-Closure Compilation for Row-Level
Authorization in ERP LLM Agents."*

---

## 7. Limitations & honest scope

- **Oracle harness, no LLM loop (public artifact):** attacks are deterministic ORM-level probes; the
  end-to-end agent loop is validated privately. The PEP correctness claim is at the data-result plane.
- **CE gap count is modest:** standard Odoo is broadly company-governed; the 5 gaps are real but the heavier
  gap/burden target is the bespoke `pco_core` or larger module sets.
- **Emit soundness is bounded:** only pushdownable parent rules (single simple leaf) are soundly emittable
  (1/5 on CE); complex domains (OR/parent_of/multi-field) are flagged manual-review — sound pushdown of
  arbitrary domains is the research frontier, not claimed.
- **Owner axis** is a local opt-in field, out of relational-closure scope by construction.
- **Read-scoped:** write/create/unlink, prompt-injection elimination, and infrastructure threats are out of
  scope; prompt injection is "reduced + measured", not "eliminated".

---

## 8. Reproducibility

- Offline (no Odoo): `python tests/test_output_validator.py … test_sensitivity_registry.py …
  test_policy_closure.py … test_policy_scan.py … test_policy_emit.py` (run in CI static-checks).
- Full benchmark + linter + emit: an Odoo 19 shell over the mock (V-vuln/V-rule) and over Odoo CE
  `sale,account,stock`; see [`README.md`](../README.md) for the exact `odoo shell` recipes. All runs in this
  report were produced in **isolated ephemeral Odoo 19 + Postgres containers**; committed reference copies live
  in [`results/`](../results/).

---

## 9. Conclusion

ERP LLM agents leak rows at the data-result plane when record-rule governance is incomplete on child models —
a gap the warehouse-native and action-plane lines of work do not close for ERP. ERP-AuthZBench measures it,
PG-Agent closes it (clean on every class, in both schema variants, robust to adaptive path-switching), and
PCC-ERP shows the per-model closures are *derivable*: it reconstructs the guard policy on the mock end-to-end
and surfaces 5 genuine relational-traversal gaps in vanilla Odoo CE, emitting sound native rules exactly where
the parent rule is pushdownable. The work is applied-security + benchmark + reference implementation for an
under-served setting, with an explicitly honest soundness frontier.
