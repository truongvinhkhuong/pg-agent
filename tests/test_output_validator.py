# -*- coding: utf-8 -*-
"""Offline unit tests for the output validator (T2.3). No Odoo, no LLM.

Run:  python -m pytest tests/test_output_validator.py   (or)   python tests/test_output_validator.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "addons",
                                "pg_agent_guard", "services"))
import output_validator as ov  # noqa: E402


def test_number_format_variants_all_caught():
    for rendered in ("50.000.000", "50,000,000", "50000000", "50 000 000"):
        res = ov.validate_answer(f"Doanh thu là {rendered} đồng", [50_000_000])
        assert res.leaked is True, rendered
        assert "50" not in res.clean_text.replace("***", "") or "***" in res.clean_text
        assert "***" in res.clean_text


def test_magnitude_words_caught():
    assert ov.validate_answer("Khoảng 50 triệu", [50_000_000]).leaked is True
    assert ov.validate_answer("Tổng 2 tỷ VND", [2_000_000_000]).leaked is True


def test_name_substring_case_insensitive():
    res = ov.validate_answer("Khách hàng kh-ttr-012 đã ký", ["KH-TTR-012"])
    assert res.leaked is True
    assert "***" in res.clean_text
    assert "ttr-012" not in res.clean_text.lower()


def test_benign_answer_not_flagged():
    res = ov.validate_answer("Có 3 đơn trong team của bạn.", [50_000_000, "KH-TTR-012"])
    assert res.leaked is False
    assert res.clean_text == "Có 3 đơn trong team của bạn."


def test_redact_false_keeps_text_but_flags():
    res = ov.validate_answer("Giá trị 50.000.000", [50_000_000], redact=False)
    assert res.leaked is True
    assert res.clean_text == "Giá trị 50.000.000"  # unchanged
    assert 50_000_000 in res.leaked_values


def test_zero_and_empty_values_ignored():
    res = ov.validate_answer("Số 0 và rỗng", [0, "", None, False])
    assert res.leaked is False


def test_mixed_forbidden_set():
    answer = "Team TTF doanh thu 1.234.000, KH la ACME-9"
    res = ov.validate_answer(answer, [1_234_000, "ACME-9"])
    assert res.leaked is True
    assert set(res.leaked_values) == {1_234_000, "ACME-9"}
    assert "1.234.000" not in res.clean_text
    assert "ACME-9" not in res.clean_text


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for fn in fns:
        fn()
        print("ok:", fn.__name__)
    print(f"\n{len(fns)} tests passed.")
