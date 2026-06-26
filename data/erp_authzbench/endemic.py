# -*- coding: utf-8 -*-
"""Endemic-gap aggregator over policy_closure.derive_gaps records (PURE, no Odoo).

Turns the per-(model, discriminator) verdict records the scale scanner produces into a
corpus-level endemicity picture. The HEADLINE is breadth + distribution, NOT a pooled rate:

  * **at-risk population** = child x axis pairs that are reachable (hops >= 1) to a parent that
    ENFORCES a context-bound (team/company/owner) record rule. `parent_governed` is already strict
    (True only when the nearest definer carries an active rule whose leaf binds the user/company
    context, per governance_fields) — so the denominator means exactly "the parent guards this axis".
  * a **GAP** among the at-risk population = the child lacks its OWN rule (relational-traversal gap).
  * **breadth** = domains with >=1 gap / domains that contain an at-risk child — the robust claim
    ("the gap recurs wherever the pattern is used"); the per-domain distribution is the headline object.
  * the **pooled gap-rate** (gaps/at-risk) is SUPPORTING only and must always be reported with its n
    (it is a small-integer ratio; a single percentage hides per-domain spread).

`diff_baseline` keyed-diffs a corpus scan against the committed 3-module coverage.csv so verdict drift
(a new rule closing a gap, or a re-routed closure) is detected and explained, never silently masked.
"""
import csv

_AT_RISK_VERDICTS = ("GAP", "GOVERNED")


def _truthy(v):
    return v in (True, 1) or (isinstance(v, str) and v.strip().lower() in ("true", "1"))


def _module_of(model):
    return model.split(".", 1)[0]


def _at_risk(r):
    """Reachable child x axis whose parent enforces the (context-bound) axis."""
    return int(r.get("hops") or 0) >= 1 and _truthy(r.get("parent_governed")) and r["verdict"] in _AT_RISK_VERDICTS


def endemic_summary(records):
    """Breadth + per-domain distribution + (supporting) pooled rate over derive_gaps records."""
    at_risk = [r for r in records if _at_risk(r)]
    per = {}
    for r in at_risk:
        d = per.setdefault(_module_of(r["model"]), {"at_risk": 0, "gaps": 0})
        d["at_risk"] += 1
        if r["verdict"] == "GAP":
            d["gaps"] += 1
    for d in per.values():
        d["rate"] = round(d["gaps"] / d["at_risk"], 3) if d["at_risk"] else 0.0

    domains_with_at_risk = sorted(per)
    domains_with_gap = sorted(dm for dm, d in per.items() if d["gaps"] > 0)
    domains_scanned = sorted({_module_of(r["model"]) for r in records})
    gaps_total = sum(d["gaps"] for d in per.values())
    at_risk_total = sum(d["at_risk"] for d in per.values())
    rates = sorted(d["rate"] for d in per.values() if d["at_risk"])
    return {
        # ── HEADLINE: breadth + distribution ──
        "n_domains_scanned": len(domains_scanned),
        "n_domains_with_at_risk": len(domains_with_at_risk),
        "n_domains_with_gap": len(domains_with_gap),
        "domains_scanned": domains_scanned,
        "domains_with_gap": domains_with_gap,
        "per_domain": per,
        "rate_min": rates[0] if rates else 0.0,
        "rate_median": rates[len(rates) // 2] if rates else 0.0,
        "rate_max": rates[-1] if rates else 0.0,
        # ── SUPPORTING: pooled rate (always reported with n = at_risk_total) ──
        "gaps_total": gaps_total,
        "at_risk_total": at_risk_total,
        "pooled_gap_rate": round(gaps_total / at_risk_total, 3) if at_risk_total else 0.0,
        # ── CONTEXT denominators (NOT the headline; for the low-frequency/high-breadth point) ──
        "n_reachable_rows": len(records),
        "gaps_over_reachable": round(gaps_total / len(records), 3) if records else 0.0,
    }


def read_coverage_csv(path):
    """Load a scale-scan coverage CSV into normalized record dicts (hops:int, *_governed:bool)."""
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    for r in rows:
        r["hops"] = int(r["hops"]) if str(r.get("hops", "")).strip() else 0
        for k in ("axis_governed", "native_rule", "parent_governed"):
            if k in r:
                r[k] = _truthy(r[k])
    return rows


def diff_baseline(records, baseline_rows):
    """Keyed (model, discriminator) diff of a corpus scan vs a committed baseline. Returns the rows
    whose verdict / closure changed, each with a cause — so legitimate drift (a new rule closing a
    gap, or a re-routed nearest-definer) is explained, not masked."""
    cur = {(r["model"], r["discriminator"]): r for r in records}
    drift = []
    for b in baseline_rows:
        key = (b["model"], b["discriminator"])
        c = cur.get(key)
        if c is None:
            drift.append({"model": b["model"], "discriminator": b["discriminator"],
                          "before": "%s/%s" % (b["verdict"], b.get("relation_path") or ""),
                          "after": "(absent)", "cause": "row-absent-in-corpus"})
            continue
        b_path, c_path = (b.get("relation_path") or ""), (c.get("relation_path") or "")
        b_def, c_def = (b.get("definer_model") or ""), (c.get("definer_model") or "")
        if c["verdict"] != b["verdict"] or c_path != b_path or c_def != b_def:
            if b["verdict"] == "GAP" and c["verdict"] == "GOVERNED" and _truthy(c.get("native_rule")):
                cause = "new-native-rule (gap genuinely closed)"
            elif c_def != b_def or c_path != b_path:
                cause = "re-routed-definer (new nearer parent in scope)"
            else:
                cause = "verdict-changed"
            drift.append({"model": b["model"], "discriminator": b["discriminator"],
                          "before": "%s/%s" % (b["verdict"], b_path),
                          "after": "%s/%s" % (c["verdict"], c_path), "cause": cause})
    return drift
