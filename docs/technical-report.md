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
runtime-verifies gap closure — validated on the mock end-to-end and at corpus scale on vanilla Odoo CE, where
the relational-traversal gap proves **endemic** (15 gaps recurring across 6 of 8 business domains).
On the orthogonal reliability axis (RQ6) we adopt a three-layer **integrity** stack (numeric verifier + governed
metrics + execution-guided self-consistency) that drives the silently-wrong-number rate to zero and catches
correct-arithmetic-with-the-wrong-formula — framed as applied, not novelty. We additionally (iv) regression-gate
the residual-risk surface with a deterministic, LLM-free **red-team grammar** that exhausts the ORM-pivot space
(T4.5+); (v) **formalize** the bespoke POLICY as an instance of a general **ABAC×ReBAC** subject-context model
whose compiler reproduces the guard's exact authorization domain (RQ7); and (vi) extend the PEP to a **Doc-RAG
retrieval plane** that delivers chunks only re-rendered from row-authorized, clearance-masked sources (RQ8).

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

**Automated red-team (T4.5+)** · [`redteam.csv`](../results/redteam.csv). The 14 hand-picked pivots are a subset
of a **deterministically-enumerated ORM-pivot grammar** (`redteam.py`) — a strict super-set across the five
families, expanded over the type-safe model × op × field axis to **41 variants**. Run through the same two-mode
oracle (undefended = the automatic meaningfulness filter that prunes non-firing cells), every in-scope variant
**holds — residual-leak 0/41**: 34 fire on V-vuln; under V-rule more go `non-firing` (the native rule blocks
line-traversal) while the forgotten payment/guarantee siblings still fire and hold. `ci_gate` fails on **any**
in-scope grammar point that survives the guard. Honest: exhaustive over the *grammar* (a modeled threat surface),
**not** the universe of attacks; deterministic enumeration, **NO LLM** — a structured fuzzer, not an "AI red-team".

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
in-scope adaptive RESIDUAL-LEAK**, **no in-scope variant of the automated red-team grammar survives** (§4.3),
and the benchmark is meaningful (attacks fire undefended). Any change that reopens a leak — canonical path, a
hand-picked pivot, **or** any enumerated grammar point — turns CI red.

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

### 5.2.1 Endemicity across the CE corpus · [`results/scale/corpus/`](../results/scale/corpus/)

Three modules are an anecdote. Running the *same* validated scanner over a corpus of **11 installed Odoo 19 CE
business apps** (sale, account, stock, purchase, mrp, project, crm, hr, fleet, repair, maintenance — 148
in-scope models, 33 containment edges, 14 context-bound discriminators) shows the relational-traversal gap is
**endemic**: it recurs in **6 of the 8 business domains** that contain an *at-risk* child model (a child
reachable through a containment edge to a parent that enforces a context-bound team/company/owner rule — the
`parent_governed` predicate is already strict, so the denominator means exactly "the parent guards this axis").
The 3-module baseline reproduces **with zero verdict drift** ([`drift.csv`](../results/scale/corpus/) empty;
the 5 known gaps are unchanged, the rest are additions).

| domain | gaps / at-risk child×axis | domain | gaps / at-risk |
|---|---|---|---|
| hr | **5 / 7** | account | **3 / 6** |
| project | **3 / 4** | sale | **2 / 4** |
| crm | **1 / 1** | stock | **1 / 1** |
| mrp | 0 / 2 | purchase | 0 / 2 |

**15 gaps across 6 domains** (vs 5 across 3). New gaps include `hr.employee.skill`/`hr.resume.line` →
`employee_id.company_id`, `project.task.stage.personal` → `task_id.{company_id,partner_id,user_ids}`,
`crm.team.member` → `crm_team_id.company_id`, `sale.order.template.line` → `sale_order_template_id.company_id`.

**The finding is breadth, not frequency.** Per *model* the gap is rare — only **15 of 2 072** reachable
child×axis pairs (0.7%) — because being at-risk requires a containment chain to a context-governed parent. But
*among* that at-risk population the gap is common and **crosses nearly every domain** (pooled 15/27; per-domain
rate 0–1, table). Two domains (mrp, purchase) are clean — not every domain is vulnerable, which is the honest
counterpoint. Endemic here means **ubiquitous-across-domains and systematic** (the direct consequence of
record-rule-on-the-parent-only), **not** "X% of Odoo is vulnerable". We do **not** claim exploitability on a
live tenant (that depends on the deployed rules/ACLs/agent) nor completeness (the corpus is the installed
union; community add-ons — OCA — are a higher-burden target left to future work). Manual-burden at corpus
scale rises to **37 closures vs 9 hand-written (4.1×)**.

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

### 5.4 ABAC/ReBAC formalization (RQ7) · [`results/policy_model.csv`](../results/policy_model.csv)

The bespoke per-model POLICY is, named explicitly, an **instance of a general subject-context model**: each grant
= a **ReBAC relation-path** (the M2O closure to the field's defining model — the same `_derive_path` BFS as §5)
× an **ABAC attribute-predicate** (terminal field + operator + context RHS) × a **subject-context** of one of
three kinds {group-membership, tenant-set, principal-id}. `policy_model.py` (pure) `compile_policy` is a faithful
transcription of the guard's `_authz_domain`; a live round-trip proves **`compile_policy == guard._authz_domain`
for 20/20 persona × model** (Odoo 19). Every team/company `relation_path` equals the PCC-ERP BFS closure (hops 0
on the header, 1 on a child); the company/owner contexts are recognized ABAC tokens while **team is RBAC**
(group-membership, resolved via `has_group` — deliberately not a domain context). **Honest: formalization, not
new enforcement** — it names what the guard already does (zero new ir.rule/attack; `ci_gate` untouched), and
ABAC over un-populated attributes (state/region — vacuous on the synthetic data) is deliberately omitted.

---

## 6. Integrity — RQ6 (applied / adopt-not-invent)

A reliability threat orthogonal to authorization: an LLM agent that retrieves the *right* rows can still report a
*silently-wrong number* (a hallucinated or mis-derived value that looks plausible). We adopt the warehouse-native
principle — **the LLM must not do arithmetic; every number binds to an execution result** — down to ERP. Framed
explicitly as applied (not a research-novelty claim). No LLM in the public artifact, so (as for authz) the demos
are deterministic: planted answers + a trusted symbolic gold; what is demonstrated is the *mechanism*, with the
real-LLM rate validated privately.

Three complementary layers (TB.1/TB.2/TB.3), a strict division of labor:

### 6.1 Numeric verifier (TB.1) · [`results/integrity.csv`](../results/integrity.csv)

A pure, offline-tested scanner: each answer number must bind to the governed execution table or a **bounded
derivation** of it (sum / pairwise-diff / ratio% / pct-change / share-of-total; magnitude + rounding tolerance;
VN/EN decimals). 6 questions across **5 kinds** (aggregation / ratio / growth-% / period-comparison / multi-step),
each with a symbolic gold.

| metric | result |
|---|---|
| Silently-Wrong-Number Rate | raw text-to-ORM **6/6** (wrong present) → **+verifier 0/6** (slips through) |
| false-flag rate on correct/derived answers | **0/6** (passes growth-%, ratios, negative diffs) |
| coverage | **5/5 kinds** |

TB.1 catches numbers **not derivable** from the data (fabricated / cross-data). Its **blind spot**:
*correct-arithmetic-with-the-wrong-formula* — a number that *is* a valid derivation (so it binds) yet answers a
*different* question (wrong rows/field/agg/dimension).

### 6.2 Governed metrics (TB.3) + execution-guided self-consistency (TB.2) · [`results/integrity_formula.csv`](../results/integrity_formula.csv)

A governed-metric registry pins `(model, measure, agg, dimension, filter)`; the engine computes each
**through the guard** (the authz domain pins the rows, the registry pins measure+agg → the right formula over the
right rows by construction, so a covered question *cannot* be wrong-formula). Self-consistency votes over executed
candidates (strict majority; minority outvoted; no-majority refused). On 6 wrong-formula questions whose wrong
value **binds under TB.1** (it equals an *identity* / *pairwise-diff* / *share* target while answering a different
question — e.g. one team's total reported as the all-team total):

| config | wrong-formula caught |
|---|---|
| TB.1 only | **0/6** — every wrong value binds → silently wrong |
| + TB.3 (governed metric, `raw ≠ governed`) | **4/6** (in-scope) |
| + TB.2 (self-consistency vote) | **6/6** (the out-of-scope tail, no metric) |

Governed-metric coverage **4/6** (hybrid: out-of-scope carried by the vote). A 7th *contrast* question
(`sum(amount_subtotal)`, forgot tax) is **caught by TB.1 already** (unbindable) — kept to mark the taxonomy
boundary, excluded from the 0/6. **Honest scope:** mechanism demo only — candidates / metric-selection are
planted (no LLM), coverage is partial by design, and this catches the wrong *use* of a right metric, not a wrong
metric *definition*.

---

## 7. Doc-RAG retrieval plane (RQ8)

The PEP extends from the structured-data plane to a **retrieval** plane. A RAG agent retrieves document **chunks**
(derived from records) to answer a question; the confused-deputy is the **retriever**, which ranks the most
*relevant* chunks regardless of whether the persona may read the source record. The mechanism reuses the
data-plane guard: `guard.guarded_retrieve` routes each retrieved chunk's provenance back through
`guarded_search_read` — a chunk whose source record is **not row-authorized is dropped**, and a survivor is
delivered only **re-rendered from the clearance-masked source**. A deterministic lexical (term-overlap) retriever
stands in for the embedding ranker; the security property is **independent of the ranker**. No LLM.

Oracles are **independent** of the guard's verdict: the full row-authz permitted set (unauthorized-row delivery)
and the SUDO cleartext value (`output_validator` as a presence scanner, not the guard's own verdict).
· [`results/docrag.csv`](../results/docrag.csv):

| attack | undefended (unauth / confid) | guarded |
|---|---|---|
| cross-team-direct (`nhóm ttf` query) | 8/8 | **0/0** |
| cross-team-incidental (generic query, top-k spans teams) | 8/12 | **0/0** |
| confidential (own-team, spans masked) | 4/8 | **0/0** |
| utility / false-block | 4/8 | **0/0** |

**Undefended leaks 60 → guarded unauthorized 0, confidential 0, false-block 0** (Odoo 19); `ci_gate` unaffected
(the driver self-asserts, like §5.4, rather than gating). **Honest scope:** the PEP gates **delivery, not the
index** — cleartext indexing is an assumption and rank order can be influenced by confidential content (a named
residual, not a value leak). Structural masking avoids the output-validator paraphrase residual *because* chunks
are provenance-tracked; true unstructured prose has no provenance, falls back to content-scanning, and inherits
that residual (carried as one out-of-scope free-prose probe). **No real-LLM / embedding RAG rate is claimed.**

---

## 8. Related work & positioning

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
- **Concurrent agent-authorization work (2025–26)** — a fast-moving wave, all **orthogonal to the
  data-result plane**: *τ-bench* and *PolicyBank* evaluate/refine agent adherence to natural-language
  **policy text** at the tool-capability level (not row-level DB enforcement); mandatory-access-control
  frameworks for multi-agent **privilege escalation** (the "Taming Privilege Escalation"/SEAgent line, 0%
  ASR across prompt-injection / RAG-poisoning / confused-deputy *across agents*) and *Agent-GrantBox*
  (least-privilege at the **tool/API** interface) govern the **call/permission**, not the returned rows;
  *"A Vision for Access Control in LLM Agent Systems"* is a position paper. None targets ERP record-rule
  incompleteness on child models or the relational-traversal row bypass.
- **Denial-channel leakage:** *"Causality Laundering: Denial-Feedback Leakage in Tool-Calling LLM Agents"*
  **formalizes** (causal theory) and **detects** information leakage through an agent's refusal/denial
  feedback — the same channel our **uniform-denial** layer (T2.4/RQ5) attacks, but from the opposite end:
  they characterize/measure the leak, we **operationally close** the observable (identical empty result +
  constant-time, measured as Existence-Inference Rate 1/1 → 0/1, §4.4). Complementary: their lens is the
  theory of the channel; ours is a deployable PEP defense + a benchmark metric for it.

**Novelty (honest):** the *combination* — ERP record-rule incompleteness on child models × agent-driven
relational-traversal exploitation × the first adversarial benchmark × a relational-closure compiler — not any
single mechanism, and (per the 2025–26 wave above) **the data-result plane is the un-occupied niche**:
concurrent agent-authorization work targets the control/permission plane, policy-text compliance, multi-agent
MAC, or the denial-channel *theory*; none enforces or compiles **row-level** ERP record rules. We explicitly do
**not** claim a novel authz+integrity unification (prior art) or a general policy compiler for agents
(PCAS/OAP-adjacent). Subtitle framing: *"Policy-Closure Compilation for Row-Level Authorization in ERP LLM
Agents."*

---

## 9. Limitations & honest scope

- **Oracle harness, no LLM loop (public artifact):** attacks are deterministic ORM-level probes; the
  end-to-end agent loop is validated privately. The PEP correctness claim is at the data-result plane. The
  integrity layers (§6) likewise demonstrate *mechanisms* on planted answers/candidates — not measured LLM
  hallucination or wrong-formula rates — and the governed-metric coverage is partial by design (hybrid).
- **CE gap rate is low per model but endemic across domains (§5.2.1):** standard Odoo is broadly
  company-governed, so per model the gap is rare (15 of 2 072 reachable child×axis pairs, 0.7%); the finding is
  **breadth** — it recurs in 6 of 8 at-risk domains — not a high per-model rate. The headline is the per-domain
  distribution + the breadth fraction, never a pooled percentage; mrp/purchase are clean. We do not claim
  live-tenant exploitability (depends on deployed rules/ACLs/agent) or completeness (corpus = the installed CE
  union; OCA community add-ons are a higher-burden future target). The heaviest target remains the bespoke
  `pco_core`.
- **Emit soundness is bounded:** only pushdownable parent rules (single simple leaf) are soundly emittable
  (1/5 on CE); complex domains (OR/parent_of/multi-field) are flagged manual-review — sound pushdown of
  arbitrary domains is the research frontier, not claimed.
- **Owner axis** is a local opt-in field, out of relational-closure scope by construction.
- **Red-team is grammar-exhaustive, not exhaustive (§4.3):** the automated red-team enumerates a *defined*
  ORM-pivot grammar (a modeled threat surface) deterministically and without an LLM; a green gate means no bypass
  at any enumerated point, not a universal-correctness proof.
- **RQ7 is formalization, not enforcement (§5.4):** it names the team/company/owner predicates the guard already
  enforces (no new ir.rule/attack); ABAC over un-populated attributes would be vacuous and is omitted.
- **RQ8 gates delivery, not the index (§7):** the retrieval PEP re-checks provenance at delivery; the cleartext
  index and rank-order are named residuals, structural masking depends on field provenance (unstructured prose
  inherits the paraphrase residual), and no real-LLM / embedding RAG rate is claimed.
- **Read-scoped:** write/create/unlink, prompt-injection elimination, and infrastructure threats are out of
  scope; prompt injection is "reduced + measured", not "eliminated".

---

## 10. Reproducibility

- Offline (no Odoo): the `tests/test_*.py` suite (output-validator, sensitivity, policy-closure, policy-scan,
  policy-emit, policy-model, numeric-verifier, metrics-and-consistency, redteam, docrag, agent-loop) — run in CI
  static-checks.
- Full benchmark + linter + emit: an Odoo 19 shell over the mock (V-vuln/V-rule) and over Odoo CE
  `sale,account,stock`; see [`README.md`](../README.md) for the exact `odoo shell` recipes. All runs in this
  report were produced in **isolated ephemeral Odoo 19 + Postgres containers**; committed reference copies live
  in [`results/`](../results/).

### 10.1 End-to-end agent-loop proxy (reproducible, no LLM) · [`results/agent_loop.csv`](../results/agent_loop.csv)

The ORM-level probes above prove the row-level security rate; this proxy adds the one axis they do not exercise
as a *loop* — the full **intent → tool-calls → guard → synthesized NL answer → output validator** pipeline, and
**UTILITY**: is a benign business query answered *correctly* and *persona-scoped*? A `ScriptedAgent` (a
deterministic NL→tool-call map — **not** a language model) drives `agent_loop(env)`; the utility gold is an
**independent** sudo recomputation over the persona's full authorized set (team AND company), never the guarded
output.

| query | intent | utility (correct / scoped) | answer-leak | outcome |
|---|---|---|---|---|
| total quantity by product (own team) | benign | **yes / yes** | safe | answered |
| list my orders | benign | **yes / yes** | safe | answered |
| "give me team TTF's totals" | adversarial | n/a | **safe** | blocked-at-guard (guard AND-s the ttv scope) |
| spelled-out cross-team value | adversarial (out-of-scope) | n/a | leak | documented paraphrase residual |

Benign queries are answered correctly and scoped; the adversarial cross-team request is silently narrowed to the
persona's own scope (the cross-team value never reaches the answer); the spelled-out value is the documented
answer-channel residual (§4.3). The **row-level security rate is delegated to §4.1/§4.3**, not re-measured here —
this is a *mechanism + utility* demo, not a security re-proof. The `LLMAgent` **seam** (an interface + recipe,
deliberately not a shipped SDK client) is where a real model plugs in.

### 10.2 Private validation (corroborating, not reproducible)

Because the guard rewrites the query domain **below the LLM trust boundary** — the model only emits ORM
tool-calls and the PEP forces the authorization domain before the database — the row-level security property is
**independent of which LLM (or whether any LLM) drives the loop**; the deterministic public proof (leak 0 on
every class, variant, and enumerated grammar point) is the security proof, and the private real-LLM run measures
only what the mechanism does not guarantee a priori (utility, the answer-channel paraphrase residual, and
wrong-formula rate).

The private end-to-end rates are obtained with the **same instrument** as this artifact — `evaluation_script.py`
/ `ci_gate`, the public `PERSONAS`, and the public ERP-AuthZBench + adaptive + red-team attack sets — pointed at
the production data with a real tool-calling model via the `LLMAgent` seam (§10.1). **Only the data and the
resulting numbers are private; the measurement instrument is the audited public one.** A reader reproduces the
*method* by instantiating `LLMAgent` against their own model + the synthetic seed=42 corpus.

Honest scope of this section: **(1)** the private numbers carry **no headline security claim** — the
deterministic proof (§4) and the reproducible proxy (§10.1) carry the security load; the private run only
*corroborates* and characterizes utility/residual. **(2)** They are **privately measured, not reproducible from
this artifact** (real data + a real model the public repo deliberately does not contain). **(3)** The committed
proxy (§10.1) is a *mechanism + utility* demo, **not** a stand-in for the real-LLM rate. **(4)** We **report
negative results**: any case the private real-LLM loop surfaces that the deterministic harness missed is fed
back as a new public ERP-AuthZBench variant — that feedback loop, not a clean private number, is the evidence of
good faith. *(Production figures and an internal-attestation line are filled in the private build; they are
omitted here rather than shown as placeholders.)*

---

## 11. Conclusion

ERP LLM agents leak rows at the data-result plane when record-rule governance is incomplete on child models —
a gap the warehouse-native and action-plane lines of work do not close for ERP. ERP-AuthZBench measures it,
PG-Agent closes it (clean on every class, in both schema variants, robust to adaptive path-switching), and
PCC-ERP shows the per-model closures are *derivable*: it reconstructs the guard policy on the mock end-to-end
and shows the relational-traversal gap is **endemic** across vanilla Odoo CE — recurring in 6 of 8 business
domains (15 gaps), low per model but systematic — emitting sound native rules exactly where the parent rule is
pushdownable. On the reliability axis (RQ6), the three-layer integrity stack drives the
silently-wrong-number rate to zero and closes the numeric verifier's wrong-formula blind spot (TB.1 0/6 → +TB.3
4/6 → +TB.2 6/6) via deterministic governed metrics + execution-voting. Beyond the canonical results, the
residual-risk surface is regression-gated by an exhaustive ORM-pivot **red-team grammar** (residual-leak 0/41);
the bespoke POLICY is shown to be an instance of a general **ABAC×ReBAC** subject-context model whose formal
compiler reproduces the guard's exact domain (RQ7, 20/20); and the PEP extends to a **Doc-RAG retrieval plane**
that delivers chunks only re-rendered from row-authorized, clearance-masked sources (RQ8, guarded leak 0). The
work is applied-security + benchmark + reference implementation for an under-served setting, with an explicitly
honest soundness frontier.
