# -*- coding: utf-8 -*-
"""PG-Agent Policy Enforcement Point (PEP).

The RAG agent's data tools must call the `guarded_*` methods here instead of
`env[model].search_read/read_group/search_count`. Integration in the private
`pco_ai_chat` agent_orchestrator becomes, e.g.::

    guard = env["pg.agent.guard"]
    rows = guard.guarded_read_group("pco.sale.order.line",
                                    domain=tool_args.get("domain", []),
                                    fields=["amount_total"],
                                    groupby=["customer_name"])

Design properties:
  * Runs as the CURRENT user (no sudo on data) — Odoo ACL/record rules still apply;
    the guard ADDS a mandatory authorization domain on top of them.
  * Model-agnostic: one POLICY table maps each allowed model to the path that
    reaches the team discriminator / tenant / owner.
  * FAIL-CLOSED: a model absent from POLICY is denied (unlike per-model ir.rules,
    which silently leak any model someone forgot to cover).
  * UNIFORM DENIAL (T2.4): a denied query returns the same empty value + timing as a
    genuinely-empty one, so it is not an existence/denial oracle. The real reason is
    still audited. Flip `denial.DENIAL_CONFIG["enabled"]=False` for the denial-rich
    baseline (informative AccessError), used by the ablation in proposal §11.
"""

import time
from collections import namedtuple

from odoo import _, models
from odoo.exceptions import AccessError

from ..audit.audit_log import audit_decision
from ..services import denial, numeric_verifier, output_validator
from . import sensitivity

# Uniform redaction sentinel for masked field values (T2.2).
MASK_SENTINEL = "***"

# Ablation toggle for the benchmark's defense-in-depth ladder. Production keeps this
# True; the harness flips it off to measure masking's marginal contribution. (Uniform
# denial has its own toggle in services/denial.DENIAL_CONFIG.)
GUARD_CONFIG = {"enforce_masking": True}

# Per-model authorization policy. Paths use ONLY contract-surface fields that are
# guaranteed present in both the public mock and the real private pco_core.
POLICY = {
    "pco.sale.order": {
        "team_path": "team_code",
        "company_path": "company_id",
        "owner_path": None,
    },
    "pco.sale.order.line": {
        "team_path": "order_id.team_code",
        "company_path": "order_id.company_id",
        "owner_path": "salesperson_id",
    },
    "pco.sale.order.payment": {
        "team_path": "order_id.team_code",
        "company_path": "order_id.company_id",
        "owner_path": None,
    },
    "pco.sale.order.guarantee": {
        "team_path": "order_id.team_code",
        "company_path": "order_id.company_id",
        "owner_path": None,
    },
}

_TEAM_GROUPS = (
    ("ttv", "pco_core_mock.group_team_ttv"),
    ("ttf", "pco_core_mock.group_team_ttf"),
    ("ttr", "pco_core_mock.group_team_ttr"),
)

# Outcome of a guard check. `domain` is the effective domain when allowed.
_GuardDecision = namedtuple("_GuardDecision", ["allowed", "domain", "reason"])

# Sentinel: a write-check leaf whose governed field is neither being set nor pre-existing.
_UNRESOLVED = object()


def _leaf_ok(op, actual, expected):
    """Does a resolved write-check value satisfy one authz leaf operator?"""
    if op == "in":
        return bool(set(actual) & set(expected)) if isinstance(actual, list) else actual in expected
    if op == "=":
        return actual == expected
    return False  # unsupported operator in a write-check -> fail-closed


class PgAgentGuard(models.AbstractModel):
    _name = "pg.agent.guard"
    _description = "PG-Agent Policy Enforcement Point (PEP)"

    # ── policy resolution ───────────────────────────────────────────────────
    def _user_teams(self):
        """Return list of team codes the user is scoped to, or None for see-all."""
        user = self.env.user
        if user.has_group("base.group_system") or user.has_group(
            "pco_core_mock.group_team_view_all"
        ):
            return None
        return [code for code, xmlid in _TEAM_GROUPS if user.has_group(xmlid)]

    def _is_own_only(self):
        return self.env.user.has_group("pg_agent_guard.group_pep_own_only")

    def _user_clearance(self):
        """Sensitivity clearance of the current user (T2.1)."""
        return sensitivity.user_clearance(self.env.user.has_group)

    def _mask_rows(self, model, rows, clearance):
        """Redact above-clearance field values in-place to MASK_SENTINEL.

        `id` is always kept (not business-sensitive). Relational (id, name) tuples
        are redacted whole. Returns the set of field names that were masked.
        """
        if not GUARD_CONFIG.get("enforce_masking"):
            return set()
        masked = set()
        for row in rows:
            # reassigning existing keys during iteration is safe (dict size unchanged)
            for key in tuple(row.keys()):
                if key == "id":
                    continue
                if not sensitivity.can_see(clearance, sensitivity.field_level(model, key)):
                    row[key] = MASK_SENTINEL
                    masked.add(key)
        return masked

    def _authz_domain(self, model, policy=None):
        """List of leaves to AND with the user domain, or None to DENY (fail-closed).

        `policy` is an optional per-call policy registry ({model: {team_path/company_path/owner_path}}).
        When None (every in-tree caller), the module-level POLICY is used — byte-identical behavior. A caller
        MAY pass a LOCAL registry to enforce on a model that is not in the global POLICY (e.g. a real upstream
        Odoo model) WITHOUT mutating POLICY (which is consumed by exact-equality/count asserts elsewhere)."""
        registry = POLICY if policy is None else policy
        policy = registry.get(model)
        if policy is None:
            return None

        leaves = []

        teams = self._user_teams()
        if teams is not None:  # restricted user
            team_path = policy.get("team_path")
            if not team_path:
                return None  # no way to scope this model by team -> deny
            if not teams:
                return [("id", "=", 0)]  # belongs to no team -> empty set
            leaves.append((team_path, "in", teams))

        company_path = policy.get("company_path")
        if company_path:
            leaves.append((company_path, "in", self.env.companies.ids))

        owner_path = policy.get("owner_path")
        if owner_path and self._is_own_only():
            leaves.append((owner_path, "=", self.env.uid))

        return leaves

    def _guard(self, model, operation, domain, policy=None):
        """Decide allow/deny + build effective domain. Audits every decision.

        Never raises on an authorization decision — the caller turns a deny into a
        uniform empty result (T2.4). The real reason is recorded in the audit log.
        `policy` (optional) is forwarded to `_authz_domain` for per-call local registries.
        """
        domain = list(domain or [])
        authz = self._authz_domain(model, policy)
        if authz is None:
            audit_decision(
                self.env, model, operation, domain, allowed=False,
                reason="fail-closed: model not in POLICY or no team path",
                denial_uniformized=bool(denial.DENIAL_CONFIG.get("enabled")),
            )
            return _GuardDecision(False, None, "fail-closed")
        # Flat list concatenation = implicit AND in Odoo domain prefix notation,
        # correct even when `domain` contains its own OR operators.
        effective = authz + domain
        audit_decision(
            self.env, model, operation, effective, allowed=True,
            reason="authz domain applied",
        )
        return _GuardDecision(True, effective, "allow")

    def _deny(self, operation, t0):
        """Uniform denial: same empty shape + timing as a genuinely-empty result.

        When uniform denial is disabled (denial-rich baseline), raise an informative
        error instead — this reproduces the pre-T2.4 behaviour for the ablation.
        """
        if denial.DENIAL_CONFIG.get("enabled"):
            denial.pad_latency(t0)
            return denial.empty_result(operation)
        # denial-rich baseline (informative + fast) — leaks model name & deny reason
        raise AccessError(_("PG-Agent guard từ chối: '%s' không được phép cho agent.") % operation)

    # ── Guarded ORM surface (the agent MUST call these, not env[model] directly) ──
    def guarded_search_read(self, model, domain=None, fields=None,
                            offset=0, limit=None, order=None, policy=None):
        t0 = time.monotonic()
        dec = self._guard(model, "search_read", domain, policy=policy)
        if not dec.allowed:
            return self._deny("search_read", t0)
        rows = self.env[model].search_read(
            dec.domain, fields or [], offset=offset, limit=limit, order=order,
        )
        masked = self._mask_rows(model, rows, self._user_clearance())
        if masked:
            audit_decision(
                self.env, model, "search_read", dec.domain, allowed=True,
                reason="masking applied", masked_fields=masked,
            )
        denial.pad_latency(t0)
        return rows

    def guarded_retrieve(self, candidates):
        """Retrieval-plane PEP (L5 / RQ8): re-validate retrieved-chunk PROVENANCE at delivery.

        The retriever (ranking) is UNTRUSTED and lives OUTSIDE this boundary; it may surface a chunk
        from any source record. This re-routes each candidate's provenance through the SAME data-plane
        guard (`guarded_search_read`): a chunk whose source record is not row-authorized is DROPPED,
        and a surviving chunk's source is returned with confidential fields MASKED to the user's
        clearance — so the caller can only ever re-render from what the persona may read.

        `candidates` = [{"model", "record_id", "fields"}]. Returns
        [{"model", "record_id", "record"}] for ALLOWED candidates only (`record` = the masked field
        dict). Reuses `guarded_search_read` — no new enforcement logic. (Gates DELIVERY, not the index.)
        """
        by_model = {}
        for c in candidates:
            by_model.setdefault(c["model"], {"ids": [], "fields": set()})
            by_model[c["model"]]["ids"].append(c["record_id"])
            by_model[c["model"]]["fields"].update(c["fields"])
        allowed = {}
        for model, spec in by_model.items():
            rows = self.guarded_search_read(model, [("id", "in", spec["ids"])], sorted(spec["fields"]))
            allowed[model] = {r["id"]: r for r in rows}
        out = []
        for c in candidates:
            rec = allowed.get(c["model"], {}).get(c["record_id"])
            if rec is not None:
                out.append({"model": c["model"], "record_id": c["record_id"], "record": rec})
        return out

    def guarded_search_count(self, model, domain=None):
        t0 = time.monotonic()
        dec = self._guard(model, "search_count", domain)
        if not dec.allowed:
            return self._deny("search_count", t0)
        res = self.env[model].search_count(dec.domain)
        denial.pad_latency(t0)
        return res

    def guarded_read_group(self, model, domain=None, fields=None, groupby=None,
                           offset=0, limit=None, orderby=False, lazy=True):
        t0 = time.monotonic()
        dec = self._guard(model, "read_group", domain)
        if not dec.allowed:
            return self._deny("read_group", t0)

        groupby = groupby or []
        fields = fields or []
        allowed_fields, masked = fields, set()

        if GUARD_CONFIG.get("enforce_masking"):
            clearance = self._user_clearance()
            # A group-key above clearance would leak its distinct values as group labels
            # even if every measure is masked -> deny the whole aggregation (uniform).
            for g in groupby:
                base = g.split(":")[0]
                if not sensitivity.can_see(clearance, sensitivity.field_level(model, base)):
                    audit_decision(
                        self.env, model, "read_group", dec.domain, allowed=False,
                        reason="masking: groupby field above clearance",
                        masked_fields=[base],
                        denial_uniformized=bool(denial.DENIAL_CONFIG.get("enabled")),
                    )
                    return self._deny("read_group", t0)
            # Drop above-clearance measures BEFORE aggregating — never materialize a
            # confidential aggregate.
            allowed_fields, masked = [], set()
            for f in fields:
                base = f.split(":")[0]
                if sensitivity.can_see(clearance, sensitivity.field_level(model, base)):
                    allowed_fields.append(f)
                else:
                    masked.add(base)

        rows = self.env[model].read_group(
            dec.domain, allowed_fields, groupby,
            offset=offset, limit=limit, orderby=orderby, lazy=lazy,
        )
        if masked:
            audit_decision(
                self.env, model, "read_group", dec.domain, allowed=True,
                reason="masking applied (confidential measures dropped)",
                masked_fields=masked,
            )
        denial.pad_latency(t0)
        return rows

    # ── Guarded WRITE surface (RQ10 — mutation plane) ─────────────────────────
    # The agent's create/write/unlink tool-calls MUST route through these. The read
    # wrappers force a USING domain on what the persona may SEE; these add the missing
    # write-check: USING (a write/unlink target row must be inside `_authz_domain`) plus
    # WITH-CHECK (any governed FK/field being SET must resolve to a parent/value inside
    # the domain). Same fail-closed + uniform-deny + audit contract as the read surface.
    # Closes the confused-deputy WRITE gap: native Odoo does NOT re-apply a parent record
    # rule when a child is mutated directly, so a child with no rule of its own is writable
    # across teams. We never trust the FK target's apparent team — `_vals_in_authz` reads
    # the parent's TRUE governing fields via sudo.
    def _authz_roots(self, authz):
        """Root field names of the authz-leaf paths (e.g. order_id.team_code -> order_id)."""
        return {path.split(".")[0] for (path, _op, _v) in authz}

    @staticmethod
    def _id_of(value):
        """Normalize a relational value (recordset / id / id-list) to an id or id-list."""
        if hasattr(value, "ids"):
            return value.ids
        return value.id if hasattr(value, "id") else value

    def _resolve_leaf(self, model, path, vals, base):
        """Actual record-side value of authz-leaf `path` for a record carrying `vals`
        (falling back to the existing `base` record for governed fields not in `vals`).
        A one-hop FK path reads the parent's TRUE field via sudo. _UNRESOLVED if a
        governed field is neither set nor pre-existing."""
        root = path.split(".")[0]
        if root in vals:
            raw = vals[root]
        elif base is not None:
            raw = base[root]
        else:
            return _UNRESOLVED
        if "." not in path:
            return self._id_of(raw)
        rid = raw.id if hasattr(raw, "id") else raw
        if not rid:
            return _UNRESOLVED
        comodel = self.env[model]._fields[root].comodel_name
        parent = self.env[comodel].sudo().browse(int(rid))
        return self._id_of(parent[path.split(".", 1)[1]])

    def _vals_in_authz(self, model, vals, base=None):
        """WITH-CHECK: would a record carrying `vals` satisfy every authz leaf?
        Fail-closed on any unresolved leaf or unsupported operator."""
        authz = self._authz_domain(model)
        if authz is None or authz == [("id", "=", 0)]:
            return False
        for path, op, expected in authz:
            actual = self._resolve_leaf(model, path, vals, base)
            if actual is _UNRESOLVED or not _leaf_ok(op, actual, expected):
                return False
        return True

    def guarded_create(self, model, vals):
        """Create only if the new record falls inside the persona's authorization domain.

        WITH-CHECK on every governed FK/field in `vals` (e.g. a child's `order_id` must
        point at an in-team parent). Returns the new id, or the uniform deny value.
        """
        t0 = time.monotonic()
        if self._authz_domain(model) is None or not self._vals_in_authz(model, vals):
            audit_decision(
                self.env, model, "create", [], allowed=False,
                reason="write-check: create target outside authorization domain",
                denial_uniformized=bool(denial.DENIAL_CONFIG.get("enabled")),
            )
            return self._deny("create", t0)
        rec = self.env[model].create(vals)
        audit_decision(self.env, model, "create", [("id", "=", rec.id)], allowed=True,
                       reason="write-check: create within domain")
        denial.pad_latency(t0)
        return rec.id

    def guarded_write(self, model, ids, vals):
        """Write only if every target row is in-domain (USING) and the result stays
        in-domain (WITH-CHECK on any governed FK/field being reassigned)."""
        t0 = time.monotonic()
        ids = list(ids) if isinstance(ids, (list, tuple)) else [ids]
        authz = self._authz_domain(model)
        if authz is None:
            return self._write_deny(model, "write", t0)
        in_scope = self.env[model].sudo().search([("id", "in", ids)] + authz)
        if set(in_scope.ids) != set(ids):          # USING: a foreign target row
            return self._write_deny(model, "write", t0)
        if any(r in vals for r in self._authz_roots(authz)):   # WITH-CHECK: reassignment
            for rec in self.env[model].sudo().browse(ids):
                if not self._vals_in_authz(model, vals, base=rec):
                    return self._write_deny(model, "write", t0)
        self.env[model].browse(ids).write(vals)
        audit_decision(self.env, model, "write", [("id", "in", ids)], allowed=True,
                       reason="write-check: write within domain")
        denial.pad_latency(t0)
        return True

    def guarded_unlink(self, model, ids):
        """Unlink only if every target row is inside the persona's authorization domain."""
        t0 = time.monotonic()
        ids = list(ids) if isinstance(ids, (list, tuple)) else [ids]
        authz = self._authz_domain(model)
        if authz is None:
            return self._write_deny(model, "unlink", t0)
        in_scope = self.env[model].sudo().search([("id", "in", ids)] + authz)
        if set(in_scope.ids) != set(ids):          # USING: a foreign target row
            return self._write_deny(model, "unlink", t0)
        self.env[model].browse(ids).unlink()
        audit_decision(self.env, model, "unlink", [("id", "in", ids)], allowed=True,
                       reason="write-check: unlink within domain")
        denial.pad_latency(t0)
        return True

    def _write_deny(self, model, operation, t0):
        """Audit + uniform deny for a write/unlink (no row named -> no existence leak)."""
        audit_decision(
            self.env, model, operation, [], allowed=False,
            reason="write-check: target outside authorization domain",
            denial_uniformized=bool(denial.DENIAL_CONFIG.get("enabled")),
        )
        return self._deny(operation, t0)

    # ── Output validation (T2.3) ─────────────────────────────────────────────
    def guarded_validate_answer(self, answer_text, forbidden_values, *, redact=True):
        """Scan a final NL answer for leaked masked/cross-team values; audit if any."""
        result = output_validator.validate_answer(
            answer_text, forbidden_values, redact=redact,
        )
        if result.leaked:
            audit_decision(
                self.env, "(answer)", "output_validate", [], allowed=False,
                reason="output-validator: leaked masked/cross-team value",
            )
        return result

    # ── Numeric verification (TB.1 — integrity) ──────────────────────────────
    def guarded_verify_numbers(self, answer_text, execution_values, *, rel_tol=0.005):
        """Bind every number in a final NL answer to a derivation of the execution result;
        audit any unbindable (silently-wrong) number. The LLM must not do arithmetic."""
        result = numeric_verifier.verify_numbers(answer_text, execution_values, rel_tol=rel_tol)
        if result.unbound:
            audit_decision(
                self.env, "(answer)", "numeric_verify", [], allowed=False,
                reason="numeric-verifier: answer contains unbindable number(s)",
            )
        return result
