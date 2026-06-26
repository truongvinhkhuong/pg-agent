# -*- coding: utf-8 -*-
"""TB.1 — Numeric verifier (pure function, no Odoo / no LLM).

Integrity guard (applied / adopt-not-invent): the LLM must NOT do arithmetic. Every number
in the final answer must BIND to the execution result — present in the governed table, or a
deterministic DERIVATION of its values (sum / diff / ratio / pct-change / share-of-total),
within a rounding tolerance. A number no derivation yields is a *silently-wrong* candidate.

Self-contained (like output_validator / domain_ast): no Odoo, no cross-import, fully offline
unit-testable (tests/test_numeric_verifier.py). The private `pco_ai_chat` wires this over the
real LLM answer via `pg.agent.guard.guarded_verify_numbers`.

Number extraction is DERIVATION-AWARE and decimal-aware (output_validator is integer-only):
a digit-run yields a *candidate set* to resolve VN/EN ambiguity — "50.000.000" -> {50000000},
"12,5" -> {12.5, 125} — and binds iff its set intersects the derivation targets.
"""
import re
from collections import namedtuple

NumericVerification = namedtuple("NumericVerification", ["verified", "unbound", "bound"])

_SEP = re.compile(r"[.,\s_]")
_NUM_RUN = re.compile(r"\d[\d.,\s_]*\d|\d")
_DECIMAL = re.compile(r"(\d+)[.,](\d{1,2})$")          # single sep, 1-2 trailing -> a real decimal
_MAGNITUDE = {
    "nghìn": 1_000, "ngàn": 1_000, "k": 1_000,
    "triệu": 1_000_000, "tr": 1_000_000,
    "tỷ": 1_000_000_000, "tỉ": 1_000_000_000,
}
_MAG_RE = re.compile(r"(\d[\d.,]*)\s*(nghìn|ngàn|triệu|tỷ|tỉ|tr|k)\b", re.IGNORECASE)


def _candidates(run):
    """Candidate numeric values for one digit-run token (VN/EN format ambiguity)."""
    cands = set()
    bare = _SEP.sub("", run)
    if bare.isdigit():
        cands.add(float(int(bare)))                    # separators-as-thousands -> integer
    m = _DECIMAL.fullmatch(run.strip())
    if m:
        cands.add(float(m.group(1) + "." + m.group(2)))  # single-sep decimal: 12,5 -> 12.5
    return cands


def extract_numbers(text):
    """List of candidate-sets, one per textual number. Magnitude words consumed first so a
    base like '1,5' in '1,5 tỷ' is not also counted as a bare 1.5."""
    out = []

    def _mag_repl(m):
        mult = _MAGNITUDE[m.group(2).lower()]
        base = _candidates(m.group(1))
        if base:
            out.append({c * mult for c in base})
        return " " * len(m.group(0))

    remainder = _MAG_RE.sub(_mag_repl, text or "")
    for m in _NUM_RUN.finditer(remainder):
        if m.start() > 0 and remainder[m.start() - 1].isalpha():
            continue   # digit glued to a preceding letter -> identifier (H1, Q3), not a number
        c = _candidates(m.group())
        if c:
            out.append(c)
    return out


def _add_rounded(targets, x):
    targets.add(x)
    for d in (0, 1, 2):
        targets.add(round(x, d))


def _build_targets(execution_values):
    """The bounded set a legitimate answer number may equal: identity, full aggregate, and
    pairwise diff / ratio% / pct-change / share-of-total. O(k^2), no 2^k subset-sum."""
    vals = [float(v) for v in (execution_values or [])
            if isinstance(v, (int, float)) and not isinstance(v, bool)]
    targets = set(vals)
    if not vals:
        return targets
    total = sum(vals)
    targets.add(total)
    for i, a in enumerate(vals):
        if total:
            _add_rounded(targets, a / total * 100.0)            # share of total %
        for j, b in enumerate(vals):
            if i == j:
                continue
            targets.add(a - b)                                  # period diff
            if b:
                _add_rounded(targets, a / b * 100.0)            # ratio %
                _add_rounded(targets, (a - b) / b * 100.0)      # growth / pct-change
    # Prose drops the sign ("giảm 75,2%", "chênh lệch 94") -> bind by magnitude.
    targets.update({abs(t) for t in targets})
    return targets


def _binds(cands, targets, rel_tol):
    for c in cands:
        for t in targets:
            if abs(c - t) <= rel_tol * max(abs(t), abs(c), 1.0):
                return True
    return False


def verify_numbers(answer_text, execution_values, *, rel_tol=0.005):
    """Bind every number in `answer_text` to a derivation of `execution_values`.

    Returns NumericVerification(verified, unbound, bound). `verified` is True iff EVERY
    extracted number binds (an answer with no numbers verifies vacuously). `unbound` numbers
    are silently-wrong candidates. Never raises.
    """
    targets = _build_targets(execution_values)
    bound, unbound = [], []
    for cands in extract_numbers(answer_text):
        (bound if (targets and _binds(cands, targets, rel_tol)) else unbound).append(min(cands))
    return NumericVerification(not unbound, unbound, bound)
