# -*- coding: utf-8 -*-
"""Offline unit tests for the numeric verifier (TB.1; no Odoo, no LLM). Mirrors test_output_validator."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "addons", "pg_agent_guard", "services"))
import numeric_verifier as nv   # noqa: E402


def _verified(answer, vals, **kw):
    return nv.verify_numbers(answer, vals, **kw).verified


# ── catches silently-wrong numbers ───────────────────────────────────────────
def test_catches_fabricated_sum():
    r = nv.verify_numbers("Tổng cộng 1.300.000 VND.", [500000, 700000])   # true sum 1.2M
    assert r.verified is False and 1300000.0 in r.unbound


def test_catches_fabricated_growth():
    # true pct-change of (1234,1097) ≈ 12.49%; 13.0% is ~4% off -> flagged
    assert _verified("Tăng trưởng 13,0%.", [1234, 1097]) is False


def test_catches_crossteam_total():
    # a number computed over the WRONG (unfiltered) rows is unbindable to the governed table
    assert _verified("Doanh thu toàn công ty: 9.000.000.", [1000000, 2000000]) is False


# ── passes legitimate derivations (NO false-flag — the load-bearing cases) ────
def test_passes_full_sum():
    assert _verified("Tổng cộng 1.200.000 VND.", [500000, 700000]) is True


def test_passes_growth_pct_no_false_flag():
    # (1234-1097)/1097*100 = 12.49% -> reported 12,5% must bind; raws bind by identity
    assert _verified("Tăng trưởng 12,5% (H1 1.234 vs H2 1.097).", [1234, 1097]) is True


def test_passes_ratio_share():
    # share 300/1000 = 30% (not an identity value) must bind
    assert _verified("Nhóm A chiếm 30% tổng.", [300, 700]) is True


def test_passes_pairwise_diff_multistep():
    assert _verified("Chênh lệch giữa hai team là 300.", [800, 500]) is True


def test_multiple_numbers_all_must_bind():
    ok = nv.verify_numbers("H1 1.234, H2 1.097, tăng 12,5%.", [1234, 1097])
    assert ok.verified is True
    bad = nv.verify_numbers("H1 1.234, H2 1.097, tăng 12,5%, doanh thu 9.999.", [1234, 1097])
    assert bad.verified is False and bad.unbound == [9999.0]


# ── tolerance / formats ──────────────────────────────────────────────────────
def test_tolerance_clear_cases():
    assert _verified("12,5%", [1234, 1097]) is True       # correct rounding of 12.49
    assert _verified("13,0%", [1234, 1097]) is False      # clearly wrong


def test_vn_formats_and_magnitude():
    assert _verified("Doanh thu 50.000.000 VND.", [50000000]) is True
    assert _verified("Doanh thu 50 triệu.", [50000000]) is True
    assert _verified("Doanh thu 1,5 tỷ.", [1500000000]) is True


def test_dual_candidate_decimal():
    # "12,5" parses as both 12.5 and 125; binds if EITHER is a target
    assert _verified("Giá trị 12,5.", [125]) is True       # 125 (thousands reading)
    assert _verified("Tỷ lệ 12,5.", [10, 80]) is True      # 12.5 = ratio 10/80*100


def test_never_raises():
    for a, v in [("", []), (None, [100]), ("junk %$# !!!", [100]),
                 ("0% và 100.", [0, 100]), ("chữ không số", [5])]:
        nv.verify_numbers(a, v)   # must not raise


def test_benign_no_number_verifies_vacuously():
    r = nv.verify_numbers("Có ba đơn hàng phù hợp.", [1, 2, 3])   # spelled-out -> not extracted
    assert r.verified is True and r.unbound == []


def test_empty_table_flags_any_number():
    assert _verified("Tổng 100.", []) is False             # no execution values to bind to


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\n{len(fns)} tests passed.")
