# PG-Agent — Permission-aware RAG over Odoo ERP + ERP-AuthZBench

[![CI](https://github.com/truongvinhkhuong/pg-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/truongvinhkhuong/pg-agent/actions/workflows/ci.yml)

Public academic artifact for a permission-aware RAG agent on Odoo. It ships:

- **`pg_agent_guard`** — a model-agnostic Policy Enforcement Point (PEP), the research CORE.
- **`pco_core_mock`** — a 4-model sale-cluster schema skeleton (no business logic, no real data).
- **`ERP-AuthZBench`** — an adversarial benchmark with a 5-class authorization-bypass taxonomy.

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
│   └── attacks_experimental.py     # ungrounded generality demos (ownership-bypass)
├── tests/
│   ├── evaluation_script.py        # benchmark harness -> environment × attack matrix + metrics
│   ├── test_output_validator.py    # offline pytest (no Odoo)
│   └── test_sensitivity_registry.py  # offline pytest (no Odoo)
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

### Verified result (Odoo 19, both variants)

| attack | no-guard (V-vuln) | no-guard (V-rule) | guard |
|---|---|---|---|
| relational-traversal | LEAK | safe (naive fix patched line) | safe |
| aggregation-leak (payment) | LEAK | **LEAK** (sibling forgotten) | safe |
| sensitive-field / measure | LEAK | LEAK | safe |
| tenant-bypass | LEAK | LEAK | safe |
| existence-inference | inferable (denial-rich) | — | **indistinguishable** (uniform-denial) |

Guard rates with uniform-denial ON: Unauthorized-Access 0/4, Data-Leakage 0/2, False-Block 0/2,
Existence-Inference 0/1 (→ 1/1 with the denial-rich baseline). The V-rule column is the
non-composability evidence: the naive per-model fix plugs `line` but forgets the `payment` sibling.

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
PY
```

Repeat after switching `pco_core_mock/__manifest__.py` to `team_security_vrule.xml` and
reinstalling (`-u pco_core_mock`) to produce the V-rule row of the matrix.

On Google Colab: `scripts/colab_bootstrap.py` → `public_path()` (no token needed).

## Continuous integration

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) gates every push to `main` and every PR:

- **`static-checks`** — syntax (`compileall`), the offline unit tests, and the **secret + raw-data
  regression gate** (`detect-secrets` against `.detect-secrets.baseline` + `check_no_raw_dumps.py`,
  run via `pre-commit`). A new secret or invoice-like blob turns CI red.
- **`authzbench`** — installs `pco_core_mock` + `pg_agent_guard` in **Odoo 19** (+ Postgres) and runs
  `ci_gate(env)` over **both schema variants** (V-vuln and V-rule). It fails unless the guard is
  clean (Unauthorized-Access = Data-Leakage = Existence-Inference = False-Block = 0) **and** the
  benchmark is meaningful (attacks actually fire when undefended). This is the regression gate: any
  change that reopens a leak turns CI red.

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
