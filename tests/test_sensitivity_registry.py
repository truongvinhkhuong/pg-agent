# -*- coding: utf-8 -*-
"""Offline unit tests for the sensitivity registry / clearance resolution (T2.1).

Run:  python -m pytest tests/test_sensitivity_registry.py  (or)  python tests/test_sensitivity_registry.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "addons",
                                "pg_agent_guard", "models"))
import sensitivity as S  # noqa: E402


def test_field_level_known_and_default():
    assert S.field_level("pco.sale.order.payment", "amount") == "confidential"
    assert S.field_level("pco.sale.order.line", "price_unit") == "restricted"
    assert S.field_level("pco.sale.order", "name") == "public"
    # unlisted field -> fail-closed default
    assert S.field_level("pco.sale.order", "totally_unknown_field") == "internal"


def test_user_clearance_from_group_set():
    assert S.user_clearance({"pco_core_mock.group_team_ttv"}) == "internal"
    assert S.user_clearance({"pco_core_mock.group_team_view_all"}) == "confidential"
    assert S.user_clearance({"base.group_system"}) == "restricted"
    assert S.user_clearance(set()) == "public"
    # highest rank wins when multiple groups present
    assert S.user_clearance({"pco_core_mock.group_team_ttv",
                             "base.group_system"}) == "restricted"


def test_user_clearance_accepts_callable():
    groups = {"pco_core_mock.group_team_view_all"}
    assert S.user_clearance(lambda x: x in groups) == "confidential"


def test_can_see_ordering():
    assert S.can_see("restricted", "confidential") is True
    assert S.can_see("internal", "confidential") is False
    assert S.can_see("confidential", "confidential") is True
    assert S.can_see("public", "internal") is False


def test_partition_fields():
    visible, masked = S.partition_fields(
        "pco.sale.order.line",
        ["product_name", "customer_name", "price_unit", "quantity"],
        "internal",
    )
    assert "product_name" in visible and "quantity" in visible
    assert "customer_name" in masked   # confidential
    assert "price_unit" in masked      # restricted


def test_confidential_clearance_sees_confidential_not_restricted():
    visible, masked = S.partition_fields(
        "pco.sale.order.line", ["customer_name", "price_unit"], "confidential",
    )
    assert "customer_name" in visible  # confidential <= confidential
    assert "price_unit" in masked      # restricted  > confidential


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\n{len(fns)} tests passed.")
