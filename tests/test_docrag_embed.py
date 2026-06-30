# -*- coding: utf-8 -*-
"""Offline tests for the real-embedding Doc-RAG surfacing run (§10.1.4). No Odoo, no LLM, no Docker.

Calibration + lint against the committed results/llm/docrag_embed.csv (the live `make ... docrag_embed` byte-diffs
it). The load-bearing checks: the PEP delivery invariant holds for the REAL embedder (guarded unauthorized 0 +
guarded confidential 0 + false-block 0 on every query), the run is meaningful (the embedder surfaced cross-team /
confidential chunks undefended), and the semantic team-token-free query genuinely pulled cross-team chunks (the
increment's whole reason — a surfacing a lexical ranker cannot reach). Counts only; mirrors test_rls_model /
test_llm_reliability.
"""
import csv
import os

_D = os.path.dirname(__file__)
_CSV = os.path.join(_D, "..", "results", "llm", "docrag_embed.csv")

with open(_CSV, newline="", encoding="utf-8") as _fh:
    _ROWS = list(csv.DictReader(_fh))


def _row(attack):
    hits = [r for r in _ROWS if r["attack"] == attack]
    assert len(hits) == 1, f"expected exactly one {attack} row, got {len(hits)}"
    return hits[0]


def test_pep_delivery_invariant_holds_for_real_embedder():
    # THE security invariant: through guarded_retrieve, NO unauthorized source row and NO confidential span are
    # ever delivered, and nothing authorized is over-blocked — for a REAL embedding ranking (ranker-independent).
    assert _ROWS, "docrag_embed.csv is empty"
    for r in _ROWS:
        assert int(r["guarded_unauth"]) == 0, f"{r['attack']}: guarded unauthorized delivery"
        assert int(r["guarded_confidential"]) == 0, f"{r['attack']}: guarded confidential leak"
        assert int(r["false_block"]) == 0, f"{r['attack']}: false-block (over-redaction)"


def test_real_embedder_surfaced_undefended_leaks_meaningfully():
    # non-vacuity: the real embedder must surface enough cross-team/confidential chunks undefended (else the PEP
    # has nothing to drop). Mirrors docrag()'s `undef_leaks >= 8`.
    undef = sum(int(r["undef_unauth"]) + int(r["undef_confidential"]) for r in _ROWS)
    assert undef >= 8, f"embedder surfaced too few undefended leaks ({undef}) — run near-vacuous"


def test_semantic_query_pulls_crossteam_a_lexical_ranker_misses():
    # the increment's REASON: a team-token-free semantic query ("hợp đồng giá trị lớn") pulls cross-team chunks by
    # AMOUNT similarity — a surfacing the term-overlap lexical ranker cannot reach (zero shared tokens).
    s = _row("rag-semantic-bigvalue")
    assert s["kind"] == "semantic-crossteam"
    assert int(s["undef_unauth"]) >= 1, "semantic query surfaced 0 cross-team chunks — embedder added no novelty"
    assert int(s["guarded_unauth"]) == 0   # ...yet the PEP still drops them all


def test_counts_bounded_and_provider_recorded():
    for r in _ROWS:
        k, n = int(r["k"]), int(r["n_cands"])
        assert n <= k, f"{r['attack']}: n_cands {n} > k {k}"
        for col in ("undef_unauth", "undef_confidential", "guarded_unauth", "guarded_confidential"):
            assert 0 <= int(r[col]) <= n, f"{r['attack']}.{col} out of [0,{n}]"
        assert r["provider"], "provider (embedder) must be recorded for honest provenance"
    # one provider across the whole run (a single Phase-1 embedder produced the committed ranking)
    assert len({r["provider"] for r in _ROWS}) == 1


if __name__ == "__main__":
    fns = [g for n, g in sorted(globals().items()) if n.startswith("test_") and callable(g)]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\nAll {len(fns)} docrag-embed tests passed.")
