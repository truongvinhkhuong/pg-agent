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
from ..services import denial, output_validator
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

    def _authz_domain(self, model):
        """List of leaves to AND with the user domain, or None to DENY (fail-closed)."""
        policy = POLICY.get(model)
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

    def _guard(self, model, operation, domain):
        """Decide allow/deny + build effective domain. Audits every decision.

        Never raises on an authorization decision — the caller turns a deny into a
        uniform empty result (T2.4). The real reason is recorded in the audit log.
        """
        domain = list(domain or [])
        authz = self._authz_domain(model)
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
                            offset=0, limit=None, order=None):
        t0 = time.monotonic()
        dec = self._guard(model, "search_read", domain)
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
