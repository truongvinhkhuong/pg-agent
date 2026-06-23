# -*- coding: utf-8 -*-
"""Independent PEP audit sink.

Records every guard decision using ONLY:
  1. the Python standard `logging` module, and
  2. Odoo core `ir.logging` (persistent, queryable).

It deliberately does NOT depend on the company's AGPL `tdh_audit` module, so the
public guard stays free of AGPL network-clause obligations. Keep this file
dependency-light and self-contained.
"""

import json
import logging

_logger = logging.getLogger("pg_agent_guard.audit")


def audit_decision(env, model, operation, domain, allowed, reason,
                   *, masked_fields=None, denial_uniformized=False):
    """Persist one allow/deny decision. Best-effort; never raises to the caller.

    `masked_fields` (T2.2) and `denial_uniformized` (T2.4) are keyword-only with
    defaults so older call sites keep working. The REAL decision/reason is always
    recorded here even when the caller-visible behaviour is a uniform empty result.
    """
    payload = {
        "uid": env.uid,
        "login": getattr(env.user, "login", None),
        "model": model,
        "operation": operation,
        "allowed": bool(allowed),
        "reason": reason,
        "effective_domain": domain,
        "masked_fields": list(masked_fields) if masked_fields else [],
        "denial_uniformized": bool(denial_uniformized),
    }
    msg = json.dumps(payload, default=str, ensure_ascii=False)

    # 1) stdlib logging — always
    if allowed:
        _logger.info("PEP ALLOW %s", msg)
    else:
        _logger.warning("PEP DENY %s", msg)

    # 2) ir.logging — persistent; best-effort, swallow any failure
    try:
        env["ir.logging"].sudo().create({
            "name": "pg_agent_guard.audit",
            "type": "server",
            "level": "INFO" if allowed else "WARNING",
            "dbname": env.cr.dbname,
            "message": msg,
            "func": operation or "?",
            "path": "pg_agent_guard.pep",
            "line": "0",
        })
    except Exception:  # pragma: no cover - audit must never break the request
        _logger.exception("PEP audit ir.logging write failed")
