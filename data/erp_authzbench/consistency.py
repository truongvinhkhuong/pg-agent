# -*- coding: utf-8 -*-
"""TB.2 — execution-guided self-consistency vote (pure; no Odoo / no LLM).

For an analytical question the agent runs N candidate query-formulations, EXECUTES each, and
votes by execution RESULT (not by the LLM's reasoning — intrinsic self-verification is
unreliable, Huang et al.). A minority wrong-formula candidate is outvoted (caught); a genuinely
ambiguous question (no majority) is refused rather than emitting a silently-wrong number.

This module is the pure voting core (given the already-executed candidate values), so it is
offline unit-testable; the candidates are executed through the guard in the harness. NO LLM:
in the real system the LLM generates the candidates; here they are PLANTED — we demonstrate the
voting MECHANISM, not an LLM's candidate diversity.
"""
from collections import namedtuple

SelfConsistency = namedtuple(
    "SelfConsistency", ["consensus", "agreement", "n", "flagged", "minority", "reason"])


def _agree(a, b, rel_tol):
    return abs(a - b) <= rel_tol * max(abs(a), abs(b), 1.0)   # same form as numeric_verifier._binds


def self_consistency(executed_values, *, rel_tol=0.005, governed=None):
    """Vote over candidate execution results.

    Clusters values by `rel_tol`; the largest cluster is the consensus. STRICT-MAJORITY gate:
    a cluster must hold > n/2 candidates to emit a consensus, else the question is `flagged`
    (refused). Minority candidates are always returned in `minority` (caught even when a
    majority holds). If `governed` (an in-scope metric value) is given, also flag when the
    consensus disagrees with it. Never raises.
    """
    vals = [float(v) for v in (executed_values or [])
            if isinstance(v, (int, float)) and not isinstance(v, bool)]
    n = len(vals)
    if n == 0:
        return SelfConsistency(None, 0, 0, True, [], "no-candidates")

    clusters = []                                   # [representative, [members...]]
    for v in vals:
        for c in clusters:
            if _agree(v, c[0], rel_tol):
                c[1].append(v)
                break
        else:
            clusters.append([v, [v]])
    clusters.sort(key=lambda c: len(c[1]), reverse=True)

    top = clusters[0]
    agreement = len(top[1])
    majority = agreement > n / 2.0
    minority = [v for c in clusters[1:] for v in c[1]]
    consensus = top[0] if majority else None
    flagged = not majority
    reason = "ok" if majority else "no-majority"
    if majority and governed is not None and not _agree(consensus, float(governed), rel_tol):
        flagged, reason = True, "consensus!=governed"
    elif majority and minority:
        reason = "minority-flagged"
    return SelfConsistency(consensus, agreement, n, flagged, minority, reason)
