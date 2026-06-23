# -*- coding: utf-8 -*-
"""T2.1 — Sensitivity registry + clearance resolution (code-default).

Mirrors the code-default `POLICY` style in pep_guard.py (no DB model `pco.ai.sensitivity`
for the public artifact — reproducibility). Two registries:

  * SENSITIVITY: (model, field) -> level. Fields not listed default to `internal`
    (fail-closed: an unknown field is treated as sensitive, not public).
  * CLEARANCE_BY_GROUP: res.groups xmlid -> clearance level (highest rank wins),
    mirroring production (accounting/view-all = confidential, admin = restricted).

Resolution helpers are pure (no Odoo) except where a `has_group` callable is passed,
so they unit-test offline (see tests/test_sensitivity_registry.py).
"""

# Ordered low -> high. A user sees a field iff user_rank >= field_rank.
LEVELS = ["public", "internal", "confidential", "restricted"]
LEVEL_RANK = {name: i for i, name in enumerate(LEVELS)}

DEFAULT_FIELD_LEVEL = "internal"   # unlisted field => fail-closed (sensitive)
DEFAULT_CLEARANCE = "public"       # logged-in user with none of the groups below

# (model, field) -> level. Only non-default levels are listed; everything else is
# `internal` by DEFAULT_FIELD_LEVEL. `public` is set explicitly where a field is
# genuinely non-sensitive (so it stays visible to the lowest clearance).
SENSITIVITY = {
    "pco.sale.order": {
        "name": "public",
        "team_code": "internal",
        "sale_team_group": "internal",
        "company_id": "internal",
        "contract_date": "public",
        "booking_date": "public",
        "state": "public",
        "is_closed": "public",
        "currency_id": "public",
        "customer_id": "confidential",
        "customer_name": "confidential",
        "amount_subtotal": "confidential",
        "amount_tax": "confidential",
        "amount_total": "confidential",
    },
    "pco.sale.order.line": {
        "product_name": "public",
        "product_category_id": "public",
        "quantity": "internal",
        "salesperson_id": "internal",
        "customer_id": "confidential",
        "customer_name": "confidential",
        "vat_amount": "confidential",
        "amount_subtotal": "confidential",
        "amount_total": "confidential",
        "price_unit": "restricted",   # supplier price / margin intelligence (top tier)
    },
    "pco.sale.order.payment": {
        "payment_type": "internal",
        "percent": "confidential",
        "amount": "confidential",
    },
    "pco.sale.order.guarantee": {
        "guarantee_type": "internal",
        "guarantee_percent": "confidential",
        "guarantee_value": "confidential",
        "deposit_amount": "confidential",
    },
}

# Highest matched rank wins. Mirrors prod: accounting (read-all) = confidential,
# admin = restricted, team members = internal.
CLEARANCE_BY_GROUP = [
    ("base.group_system", "restricted"),
    ("pco_core_mock.group_team_view_all", "confidential"),
    ("pco_core_mock.group_team_ttv", "internal"),
    ("pco_core_mock.group_team_ttf", "internal"),
    ("pco_core_mock.group_team_ttr", "internal"),
    ("pco_core_mock.group_team_base", "internal"),
]


def field_level(model, field):
    """Sensitivity level of a field; unlisted => DEFAULT_FIELD_LEVEL (internal)."""
    return SENSITIVITY.get(model, {}).get(field, DEFAULT_FIELD_LEVEL)


def _has(has_group, xmlid):
    """Accept either a callable has_group(xmlid)->bool or a set/list of xmlids."""
    if callable(has_group):
        return bool(has_group(xmlid))
    return xmlid in has_group


def user_clearance(has_group):
    """Highest clearance implied by the user's groups, else DEFAULT_CLEARANCE.

    `has_group` is the user's `has_group` method, or a set/list of group xmlids
    (for offline tests).
    """
    best = DEFAULT_CLEARANCE
    for xmlid, level in CLEARANCE_BY_GROUP:
        if _has(has_group, xmlid) and LEVEL_RANK[level] > LEVEL_RANK[best]:
            best = level
    return best


def can_see(clearance, level):
    """True iff a user with `clearance` may see a field of sensitivity `level`."""
    return LEVEL_RANK[clearance] >= LEVEL_RANK[level]


def partition_fields(model, fields, clearance):
    """Split `fields` into (visible, masked) for the given clearance."""
    visible, masked = [], []
    for f in fields:
        (visible if can_see(clearance, field_level(model, f)) else masked).append(f)
    return visible, masked
