# -*- coding: utf-8 -*-
"""T2.3 — Output validator (pure function, no Odoo / no LLM).

Last line of defence: even when structured rows were masked (T2.2) and row-filtered
(T1.2), the LLM might *restate* a masked or cross-team value in its prose answer.
This scans the final answer text for forbidden values and redacts/flags them.

The private `pco_ai_chat` wires this over the real LLM answer (via
`pg.agent.guard.guarded_validate_answer`). Here it is a pure function so it is fully
unit-testable offline with synthetic answer strings (tests/test_output_validator.py).

Matching favours RECALL over precision (a false redaction is safer than a leak):
  * numbers are matched across VN/EN formats — 50000000 / 50,000,000 / 50.000.000 /
    50 000 000 and magnitude words "50 triệu" / "1.5 tỷ";
  * names/codes are matched case-insensitively as substrings.
"""

import re
from collections import namedtuple

AnswerValidation = namedtuple("AnswerValidation", ["clean_text", "leaked", "leaked_values"])

MASK = "***"

_SEP = re.compile(r"[.,\s_]")
_NUM_RUN = re.compile(r"\d[\d.,\s_]*\d|\d")
_MAGNITUDE = {
    "nghìn": 1_000, "ngàn": 1_000, "k": 1_000,
    "triệu": 1_000_000, "tr": 1_000_000,
    "tỷ": 1_000_000_000, "tỉ": 1_000_000_000,
}
_MAG_RE = re.compile(r"(\d[\d.,]*)\s*(nghìn|ngàn|triệu|tỷ|tỉ|tr|k)\b", re.IGNORECASE)


def normalize_number(s):
    """Strip thousands separators / spaces / underscores -> bare digits."""
    return _SEP.sub("", str(s))


def _is_number(val):
    if isinstance(val, bool):
        return False
    if isinstance(val, (int, float)):
        return True
    if isinstance(val, str):
        return normalize_number(val).isdigit() and any(c.isdigit() for c in val)
    return False


def _ci_replace(text, sub, repl):
    return re.sub(re.escape(sub), repl, text, flags=re.IGNORECASE)


def _redact_number(text, target):
    """Redact occurrences of integer `target` (digit-runs + magnitude words). Returns (text, hit)."""
    state = {"hit": False}
    tdigits = str(target)

    def _repl_run(m):
        digits = normalize_number(m.group())
        if digits.isdigit() and int(digits) == target:
            state["hit"] = True
            return MASK
        return m.group()

    text = _NUM_RUN.sub(_repl_run, text)

    def _repl_mag(m):
        base = normalize_number(m.group(1))
        if base.isdigit():
            value = int(base) * _MAGNITUDE[m.group(2).lower()]
            if value == target:
                state["hit"] = True
                return MASK
        return m.group()

    text = _MAG_RE.sub(_repl_mag, text)
    return text, state["hit"]


def validate_answer(answer_text, forbidden_values, *, redact=True):
    """Scan `answer_text` for any of `forbidden_values`.

    Returns AnswerValidation(clean_text, leaked, leaked_values). `clean_text` has
    each leaked value replaced by MASK when redact=True; otherwise it equals the input.
    """
    clean = answer_text or ""
    leaked = []
    for val in forbidden_values or []:
        if val is None or val is False or val == "":
            continue
        if _is_number(val):
            target = int(normalize_number(val))
            if target == 0:
                continue  # avoid pathological over-redaction of every "0"
            new_text, hit = _redact_number(clean, target)
            if hit:
                leaked.append(val)
                if redact:
                    clean = new_text
        else:
            s = str(val)
            if s.lower() in clean.lower():
                leaked.append(val)
                if redact:
                    clean = _ci_replace(clean, s, MASK)
    return AnswerValidation(clean, bool(leaked), leaked)
