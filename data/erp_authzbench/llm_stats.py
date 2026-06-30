# -*- coding: utf-8 -*-
"""Pure statistics for the real-LLM evaluation (§10.1.1) — no Odoo, no LLM, no deps.

Deterministic + byte-stable: a fixed z-constant (no scipy), one rounding rule (`round(x, 3)` applied once at
the boundary), and a `valid==0` guard. So the Phase-2 replay of the committed `plans.json` yields a byte-stable
`eval_summary.csv`. Wilson SCORE interval (not the normal approximation) — honest for small N / extreme p.
"""
import math

# z for a two-sided 95% interval. Fixed constant (NOT statistics.NormalDist) so there is zero dependency or
# cross-version drift; this is the standard 1.96 to 6 dp.
Z95 = 1.959964


def asr(leaked, valid):
    """Point attack-success-rate = leaked / valid (valid = emitted calls that were well-formed); 0.0 if none."""
    return round(leaked / valid, 3) if valid else 0.0


def wilson_ci(k, n, z=Z95):
    """Wilson score 95% CI (low, high) for k successes in n trials. (0.0, 0.0) when n == 0.

    Closed-form, deterministic; rounded once to 3 dp at the boundary."""
    if n <= 0:
        return (0.0, 0.0)
    p = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    centre = (p + z2 / (2 * n)) / denom
    half = (z / denom) * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n))
    low, high = centre - half, centre + half
    return (round(max(0.0, low), 3), round(min(1.0, high), 3))


def utility_rate(correct, total):
    """Benign-query utility = correct / total (correct = guarded answer matches gold, not over-blocked)."""
    return round(correct / total, 3) if total else 0.0


def spread(xs):
    """(mean, lo, hi) of a list of numbers, each rounded once to 3 dp. We report mean ± range (min/max) for
    repetition variance — fully deterministic (no N-vs-N-1 stdev ambiguity, no `statistics` module). (0,0,0) when
    empty."""
    if not xs:
        return (0.0, 0.0, 0.0)
    return (round(sum(xs) / len(xs), 3), round(min(xs), 3), round(max(xs), 3))
