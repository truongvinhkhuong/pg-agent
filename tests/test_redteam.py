# -*- coding: utf-8 -*-
"""Offline tests for the automated red-team generator (T4.5+) — the GATE'S SAFETY PROOF.

No Odoo, no LLM. Runs in CI static-checks BEFORE the authzbench gate, so a drifted grammar
fails fast and the gate's false-positive surface is zero by construction. The load-bearing
test is `test_expect_masked_matches_sensitivity`: every `expect_masked` equals exactly the
masked set the real `sensitivity` registry would produce for `ttv` — a below-clearance field
wrongly placed in `expect_masked` would FALSE-fail the live gate (the field is legitimately
visible, so the guard "leaks" it), and the undefended oracle cannot prune that. Mirrors
tests/test_metrics_and_consistency.py.
"""
import os
import sys

_D = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_D, "..", "data", "erp_authzbench"))
sys.path.insert(0, os.path.join(_D, "..", "addons", "pg_agent_guard", "models"))
import redteam                                  # noqa: E402
import sensitivity                              # noqa: E402
from adaptive import ADAPTIVE                   # noqa: E402

VARIANTS = redteam.generate()
# Governed models (POLICY keys) — hardcoded structurally (pep_guard imports odoo, can't load
# offline). Every governed model is a `pco.*` model; existence probes must avoid them.
_GOVERNED_PREFIX = "pco."
# All numeric fields the grammar may use as a read_group measure (from the FIELD_POOLS).
_NUMERIC = set()
for _pools in redteam.FIELD_POOLS.values():
    _NUMERIC |= set(_pools[("visible", "num")]) | set(_pools[("sensitive", "num")])


def _requested(v):
    """Fields a variant materializes (search_read fields, or read_group measure + groupby)."""
    q = v["query"]
    return list(q.get("fields", [])) + list(q.get("groupby", []))


def _masked_for_ttv(model, fields):
    """The fields `sensitivity` would mask for ttv (internal clearance)."""
    _vis, masked = sensitivity.partition_fields(model, fields, redteam.PERSONA_CLEARANCE)
    return sorted(masked)


# ── Determinism / identity ───────────────────────────────────────────────────
def test_deterministic():
    assert redteam.generate() == redteam.generate()


def test_ids_unique_and_well_formed():
    ids = [v["id"] for v in VARIANTS]
    assert len(ids) == len(set(ids)), "duplicate ids"
    assert all(i.startswith("rt-") for i in ids)


def test_ids_disjoint_from_adaptive():
    assert not ({v["id"] for v in VARIANTS} & {a["id"] for a in ADAPTIVE})


def test_count_bounded():
    # strict super-set of the 14 hand-curated variants, but bounded for CI cost.
    assert 14 < len(VARIANTS) <= 60, len(VARIANTS)


def test_family_coverage_superset_of_adaptive():
    gen_fams = {v["family"] for v in VARIANTS}
    assert gen_fams == set(redteam.FAMILIES)
    assert {a["family"] for a in ADAPTIVE} <= gen_fams      # every manual family is generated


# ── Per-shape schema ─────────────────────────────────────────────────────────
def test_common_keys_present():
    for v in VARIANTS:
        for k in ("id", "family", "vector", "in_scope", "persona"):
            assert k in v, (v.get("id"), k)
        assert v["persona"] == redteam.PERSONA


def test_shapes_are_well_formed():
    for v in VARIANTS:
        shapes = [("pair" in v), ("answer_probe" in v), ("query" in v)]
        assert sum(shapes) == 1, ("exactly one shape", v["id"])
        if "pair" in v:
            for leg in ("denied_model", "genuine_empty"):
                p = v["pair"][leg]
                assert {"model", "domain", "fields"} <= set(p), (v["id"], leg)
        elif "answer_probe" in v:
            ap = v["answer_probe"]
            assert {"answer", "forbidden", "ground_truth_present"} <= set(ap), v["id"]
        else:
            assert "model" in v and "op" in v, v["id"]


def test_orm_query_typing():
    for v in VARIANTS:
        if "query" not in v:
            continue
        op, q = v["op"], v["query"]
        if op == "read_group":
            assert len(q["fields"]) == 1, ("read_group needs exactly one measure", v["id"])
            assert q["fields"][0] in _NUMERIC, ("measure must be numeric", v["id"])
            assert q.get("groupby"), ("read_group needs a groupby", v["id"])
        elif op == "search_read":
            assert q.get("fields"), ("search_read needs fields", v["id"])
        elif op == "search_count":
            assert set(q) <= {"domain"}, ("search_count query is domain-only", v["id"])
            assert "expect_masked" not in v, ("search_count must NOT carry expect_masked", v["id"])
        else:
            raise AssertionError(("unknown op", v["id"], op))


# ── Clearance / safety proof ─────────────────────────────────────────────────
def test_expect_masked_matches_sensitivity():
    """THE load-bearing invariant: expect_masked == the exact masked set for ttv, so the gate
    never red-fails on a legitimately-visible field."""
    for v in VARIANTS:
        if "query" not in v:
            continue
        masked = _masked_for_ttv(v["model"], _requested(v))
        assert sorted(v.get("expect_masked", [])) == masked, (v["id"], v.get("expect_masked"), masked)


def test_traversal_uses_only_visible_fields():
    for v in VARIANTS:
        if v["family"] != "traversal-pivot":
            continue
        assert "expect_masked" not in v, v["id"]
        assert _masked_for_ttv(v["model"], _requested(v)) == [], v["id"]


def test_field_extraction_actually_masks():
    for v in VARIANTS:
        if v["family"] != "field-extraction-pivot":
            continue
        assert v.get("expect_masked"), ("field-extraction must mask something", v["id"])


def test_confidential_groupby_key_at_index_0():
    for v in VARIANTS:
        if v.get("op") != "read_group":
            continue
        gb = v["query"].get("groupby", [])
        masked_keys = [k for k in gb if _masked_for_ttv(v["model"], [k])]
        if masked_keys:
            assert gb[0] in masked_keys, ("masked groupby key must be first", v["id"], gb)


def test_existence_targets_only_nongoverned_models():
    for v in VARIANTS:
        if "pair" not in v:
            continue
        dm = v["pair"]["denied_model"]["model"]
        assert not dm.startswith(_GOVERNED_PREFIX), ("denied model must be non-governed", v["id"], dm)


def test_answer_probe_ground_truth_actually_present():
    """The oracle substring must really be in the answer, else the variant can't fire."""
    for v in VARIANTS:
        if "answer_probe" not in v:
            continue
        ap = v["answer_probe"]
        assert ap["ground_truth_present"].lower() in ap["answer"].lower(), v["id"]
        assert v["in_scope"] is False, ("answer-channel is documented residual", v["id"])


# ── Registry sanity: the grammar's pools agree with the real sensitivity registry ──
def test_persona_clearance_matches_registry():
    assert redteam.PERSONA_CLEARANCE == sensitivity.user_clearance({"pco_core_mock.group_team_ttv"})


def test_pools_visibility_consistent_with_registry():
    cl = redteam.PERSONA_CLEARANCE
    for model, pools in redteam.FIELD_POOLS.items():
        for f in pools[("visible", "txt")] + pools[("visible", "num")]:
            assert sensitivity.can_see(cl, sensitivity.field_level(model, f)), (model, f, "should be visible")
        for f in pools[("sensitive", "txt")] + pools[("sensitive", "num")]:
            assert not sensitivity.can_see(cl, sensitivity.field_level(model, f)), (model, f, "should be sensitive")


if __name__ == "__main__":
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\nAll {len(fns)} red-team generator tests passed. ({len(VARIANTS)} variants enumerated.)")
