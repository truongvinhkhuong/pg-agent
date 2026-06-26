# -*- coding: utf-8 -*-
"""Offline tests for the L5 Doc-RAG retrieval plane (RQ8).

No Odoo, no LLM. Covers the pure pieces (render / deterministic ranker / provenance oracle) and a
MOCK of the `guarded_retrieve` contract (drop denied source rows + mask confidential spans + preserve
public fields) — proving the driver's oracle logic without Odoo. The confidential-presence oracle uses
the REAL output_validator (drift-proof), exactly as the live driver does. Mirrors
test_output_validator.py (plain test_* + __main__).
"""
import os
import sys

_D = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(_D, "..", "data", "erp_authzbench"))
sys.path.insert(0, os.path.join(_D, "..", "addons", "pg_agent_guard", "services"))
import docrag                                   # noqa: E402
import output_validator as ov                   # noqa: E402

MODEL = "pco.sale.order"


def _rec(oid, team, cust, amt):
    return {"name": "SO-%05d" % oid, "team_code": team, "customer_name": cust, "amount_total": amt}


def _corpus():
    # ttv ids 1-8, ttf ids 9-16 (mirrors the seed's team-by-team creation order).
    rng = __import__("random").Random(42)
    out = []
    for team, base in (("ttv", 0), ("ttf", 8)):
        for i in range(1, 9):
            oid = base + i
            rec = _rec(oid, team, "KH-%s-%03d" % (team.upper(), rng.randint(1, 50)),
                       rng.randint(10, 90) * 1_000_000)
            out.append({"record_id": oid, "source_team": team,
                        "text": docrag.render_chunk(MODEL, rec), "rec": rec})
    return out


# ── render ───────────────────────────────────────────────────────────────────
def test_render_public_verbatim_confidential_passthrough():
    txt = docrag.render_chunk(MODEL, _rec(3, "ttf", "KH-TTF-010", 50000000))
    assert "SO-00003" in txt and "ttf" in txt and "KH-TTF-010" in txt and "50000000" in txt


def test_render_masked_dict_yields_sentinel_structurally():
    txt = docrag.render_chunk(MODEL, {"name": "SO-00003", "team_code": "ttf",
                                      "customer_name": "***", "amount_total": "***"})
    assert "SO-00003" in txt and "ttf" in txt          # public/internal survive
    assert "KH-" not in txt and "***" in txt            # confidential gone, sentinel present


# ── deterministic ranker ─────────────────────────────────────────────────────
def test_rank_deterministic_and_tie_breaks_by_id():
    c = _corpus()
    assert docrag.lexical_rank("x", c, 5) == docrag.lexical_rank("x", c, 5)
    # generic terms shared by all -> tie -> ascending record_id
    top = docrag.lexical_rank("hợp đồng khách hàng tổng giá trị", c, 4)
    assert [t["record_id"] for t in top] == [1, 2, 3, 4]


def test_rank_team_token_surfaces_cross_team():
    c = _corpus()
    top = docrag.lexical_rank("nhóm ttf khách hàng tổng giá trị hợp đồng", c, 8)
    assert all(t["source_team"] == "ttf" for t in top)  # ttf token ranks ttf above ttv


def test_rank_incidental_top_k_spans_teams():
    c = _corpus()
    top = docrag.lexical_rank("hợp đồng khách hàng tổng giá trị", c, 12)
    assert sum(t["source_team"] == "ttf" for t in top) == 4    # ids 1-8 ttv, 9-12 ttf


# ── provenance + confidential oracles ────────────────────────────────────────
def test_is_cross_team():
    assert docrag.is_cross_team({"source_team": "ttf"}, "ttv") is True
    assert docrag.is_cross_team({"source_team": "ttv"}, "ttv") is False
    assert docrag.is_cross_team({"source_team": "ttf"}, None) is False   # see-all never cross-team


def test_confidential_oracle_via_real_validator():
    # cleartext value present -> leaked; masked text -> not leaked (non-circular: SUDO value, not "***")
    cleartext = docrag.render_chunk(MODEL, _rec(3, "ttf", "KH-TTF-010", 50000000))
    masked = docrag.render_chunk(MODEL, {"name": "SO-00003", "team_code": "ttf",
                                         "customer_name": "***", "amount_total": "***"})
    assert ov.validate_answer(cleartext, ["KH-TTF-010", 50000000], redact=False).leaked is True
    assert ov.validate_answer(masked, ["KH-TTF-010", 50000000], redact=False).leaked is False


# ── mock of the guarded_retrieve contract: drop denied + mask confidential + keep public ──
def _mock_guarded_retrieve(candidates, persona_team, by_id):
    """Mirror pep_guard.guarded_retrieve: drop source rows not row-authorized (team), return the
    surviving record with confidential fields masked to '***' (internal-clearance persona)."""
    out = []
    for c in candidates:
        rec = by_id[c["record_id"]]
        if persona_team is not None and rec["team_code"] != persona_team:
            continue                                       # row-authz drop (cross-team)
        masked = dict(rec)
        for f in ("customer_name", "amount_total"):        # confidential -> masked for internal
            masked[f] = "***"
        out.append({"model": MODEL, "record_id": c["record_id"], "record": masked})
    return out


def test_mock_composition_drops_crossteam_masks_confidential_keeps_public():
    c = _corpus()
    by_id = {x["record_id"]: x["rec"] for x in c}
    cands = docrag.lexical_rank("nhóm ttf khách hàng tổng giá trị hợp đồng", c, 8)  # all ttf
    secure = _mock_guarded_retrieve([{"record_id": x["record_id"]} for x in cands], "ttv", by_id)
    assert secure == []                                    # every cross-team chunk dropped

    cands2 = docrag.lexical_rank("nhóm ttv khách hàng tổng giá trị hợp đồng", c, 8)  # all ttv
    secure2 = _mock_guarded_retrieve([{"record_id": x["record_id"]} for x in cands2], "ttv", by_id)
    assert len(secure2) == 8                               # same-team survive (no false-block)
    for s in secure2:
        text = docrag.render_chunk(MODEL, s["record"])
        sudo = by_id[s["record_id"]]
        assert ov.validate_answer(text, [sudo["customer_name"], sudo["amount_total"]],
                                  redact=False).leaked is False     # confidential masked
        assert s["record"]["name"] == sudo["name"]         # public preserved (no over-redaction)


if __name__ == "__main__":
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\nAll {len(fns)} Doc-RAG (RQ8) tests passed.")
