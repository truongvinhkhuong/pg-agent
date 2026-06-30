#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Phase 1 of the real-embedding Doc-RAG run (§10.1.4) — OPT-IN, HOST-only, spends a tiny embedding quota.

Embeds the committed seed=42 corpus + the queries with a REAL production embedding model (VoyageAI default,
OpenAI fallback), cosine-ranks each query, and commits the RANKING (ordered `name` keys) to
results/llm/docrag_embed_plans.json. Phase 2 (`evaluation_script.docrag_embed`, Odoo) replays the committed
ranking through the SAME §7 oracle + the PEP `guarded_retrieve`.

The embedder is SECURITY-IRRELEVANT (the guard re-validates provenance at delivery, ranker-independent → guarded 0
for any retriever; §7 is the proof). This run measures realism + the undefended surfacing of a real embedder,
including a team-token-free semantic query (`hợp đồng giá trị lớn`) that pulls cross-team chunks lexical cannot
reach. Re-running is NOT byte-reproducible (provider floats); the committed ranking makes Phase 2 byte-stable.

Byte-stability: keys on the install-stable `name` (`SO-NNNNN`), never the autoincrement record id. Tie-break
`(-cosine, name)` mirrors the §7 lexical ranker's `(-score, record_id)`.

Usage:
    pip install voyageai openai
    # VOYAGEAI_API_KEY and/or OPENAI_API_KEY in .env (gitignored). docrag_embed_inputs.json must exist
    # (run docrag_embed_prepare in the Odoo stack first). EMBEDDING_MODEL optionally overrides the model.
    python tools/docrag_embed.py
"""
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
import llm_planner as lp  # noqa: E402  (host tool; reuse _load_key — same as tools/llm_reliability.py)

_REPO = os.path.dirname(_HERE)
_OUT = os.path.join(_REPO, "results", "llm", "docrag_embed_plans.json")
_INPUTS = os.path.join(_REPO, "results", "llm", "docrag_embed_inputs.json")

# Voyage is a retrieval specialist (asymmetric query/document embeddings — the exact RAG pattern) + multilingual;
# OpenAI is the fallback. The FIRST entry whose key is set wins (Voyage default → OpenAI fallback → skip).
EMBED_REGISTRY = [
    {"name": "voyage:voyage-3.5", "sdk": "voyageai", "key_env": "VOYAGEAI_API_KEY", "model": "voyage-3.5"},
    {"name": "openai:text-embedding-3-small", "sdk": "openai", "key_env": "OPENAI_API_KEY",
     "model": "text-embedding-3-small"},
]


def _pick_embedder():
    for e in EMBED_REGISTRY:
        key = lp._load_key(e["key_env"])
        if key:
            model = os.environ.get("EMBEDDING_MODEL", e["model"])   # optional override (.env EMBEDDING_MODEL)
            return e, key, model
    sys.exit("No embedding key found (VOYAGEAI_API_KEY / OPENAI_API_KEY in env or .env). Values never echoed.")


def _embed_voyage(key, model, texts, input_type):
    import voyageai
    client = voyageai.Client(api_key=key)
    return client.embed(texts, model=model, input_type=input_type).embeddings


def _embed_openai(key, model, texts, _input_type):
    from openai import OpenAI
    client = OpenAI(api_key=key)
    resp = client.embeddings.create(model=model, input=texts)
    return [d.embedding for d in resp.data]


def _cosine(a, b):
    dot = sum(x * y for x, y in zip(a, b))
    na = sum(x * x for x in a) ** 0.5
    nb = sum(y * y for y in b) ** 0.5
    return dot / (na * nb) if na and nb else 0.0


def main():
    if not os.path.exists(_INPUTS):
        sys.exit(f"{_INPUTS} not found — run docrag_embed_prepare in the Odoo stack first.")
    with open(_INPUTS, encoding="utf-8") as fh:
        inputs = json.load(fh)
    corpus, queries = inputs["corpus"], inputs["queries"]

    entry, key, model = _pick_embedder()
    embed = _embed_voyage if entry["sdk"] == "voyageai" else _embed_openai
    sdk_version = __import__(entry["sdk"]).__version__
    print(f"Embedder: {entry['name']} (model={model}, sdk {entry['sdk']} {sdk_version})  "
          f"corpus={len(corpus)} chunks, {len(queries)} queries")

    chunk_keys = [c["key"] for c in corpus]
    chunk_vecs = embed(key, model, [c["text"] for c in corpus], "document")
    query_vecs = embed(key, model, [q["query"] for q in queries], "query")

    out_queries = []
    for q, qv in zip(queries, query_vecs):
        # tie-break (-cosine, key) mirrors the §7 lexical ranker's (-score, record_id) but with the stable key.
        scored = sorted(((-_cosine(qv, cv), ck) for ck, cv in zip(chunk_keys, chunk_vecs)))
        ranking = [ck for _s, ck in scored]
        out_queries.append({"id": q["id"], "kind": q["kind"], "query": q["query"], "k": q["k"],
                            "persona": q["persona"], "in_scope": q["in_scope"], "ranking": ranking})
        print(f"  {q['id']:<26}{q['kind']:<20}top1={ranking[0]}")

    doc = {"run_meta": {"provider": entry["name"], "model": model, "sdk": entry["sdk"],
                        "sdk_version": sdk_version,
                        "note": "opt-in; NOT byte-reproducible (provider/model embedding floats); Phase-2 replays "
                                "the committed ranking. Embedder is security-irrelevant (guard ranker-independent)."},
           "queries": out_queries}
    blob = json.dumps(doc, ensure_ascii=False, indent=2)
    # credential safety: assert no actual key VALUE leaked (provider-agnostic), plus sk-/pa- prefix backstops.
    for e in EMBED_REGISTRY:
        v = lp._load_key(e["key_env"])
        if v:
            assert v not in blob, f"ABORT: {e['key_env']} value leaked into plans"
    assert "sk-" not in blob and "pa-" not in blob, "ABORT: key-like prefix leaked into plans"
    os.makedirs(os.path.dirname(_OUT), exist_ok=True)
    with open(_OUT, "w", encoding="utf-8") as fh:
        fh.write(blob + "\n")
    print(f"\nWrote docrag_embed_plans.json ({len(out_queries)} queries, provider={entry['name']}) "
          f"-> {os.path.relpath(_OUT, _REPO)}")


if __name__ == "__main__":
    main()
