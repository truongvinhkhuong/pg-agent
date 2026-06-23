# -*- coding: utf-8 -*-
"""T2.4 — Uniform denial (anti denial-channel / existence-inference, RQ5).

The guard must NOT reveal *why* a query returned nothing. A denied query, a query
for records that exist but are out of the user's scope, and a query that genuinely
matches no rows must all be indistinguishable on the wire:

  * same RESULT SHAPE  -> `empty_result()` is the single source of truth
    (`[]` for search_read/read_group, `0` for search_count),
  * same TIMING        -> `pad_latency()` floors every response (allow AND deny)
    to a configured minimum plus uniform jitter.

This is a *mitigation*, not a proof: Python/Odoo timing is noisy (GC, ORM variance),
so the benchmark MEASURES residual Existence-Inference Rate rather than claiming the
channel is eliminated. The real (un-uniformized) reason is still written to the audit
log — only the caller-visible behaviour is uniform.

`DENIAL_CONFIG["enabled"] = False` reproduces the *denial-rich* baseline (informative,
fast deny) for the ablation row in proposal §11.
"""

import random
import time

# Module-level config; the benchmark flips these to produce ablation rows.
DENIAL_CONFIG = {
    "enabled": True,        # False => denial-rich baseline (no shape/timing uniformity)
    "min_latency_ms": 0,    # constant-time floor applied to ALL responses (allow+deny)
    "jitter_ms": 0,         # uniform random [0, jitter_ms) added on top of the floor
    "uniform_message": "Không có dữ liệu phù hợp.",  # text-channel refusal (used by the agent layer)
}

# Canonical "no data" value per operation. deny == genuine-empty by construction.
_EMPTY = {
    "search_read": list,
    "read_group": list,
    "search_count": lambda: 0,
}


def empty_result(operation):
    """Uniform empty value for an operation (deny and genuine-empty are identical)."""
    factory = _EMPTY.get(operation)
    if factory is None:
        # Unknown op is a programming error, not an authz decision -> surface it.
        raise ValueError("denial.empty_result: unknown operation %r" % operation)
    return factory()


def pad_latency(start_monotonic, cfg=None):
    """Sleep so elapsed since `start_monotonic` reaches the floor + uniform jitter.

    Applied to BOTH allow and deny paths: a floor only on deny would itself be a
    timing oracle (a fast response would mean "allowed/empty"). No-op when disabled
    or when the configured floor is 0.
    """
    cfg = cfg if cfg is not None else DENIAL_CONFIG
    if not cfg.get("enabled"):
        return
    floor_ms = cfg.get("min_latency_ms", 0) or 0
    jitter_ms = cfg.get("jitter_ms", 0) or 0
    if floor_ms <= 0 and jitter_ms <= 0:
        return
    target_s = (floor_ms + random.uniform(0, jitter_ms)) / 1000.0
    elapsed = time.monotonic() - start_monotonic
    remaining = target_s - elapsed
    if remaining > 0:
        time.sleep(remaining)


def uniform_denial_text(cfg=None):
    """Constant refusal string for the natural-language channel (agent-side)."""
    cfg = cfg if cfg is not None else DENIAL_CONFIG
    return cfg.get("uniform_message", "")
