# Artifact-Evaluation entry points for pg-agent / ERP-AuthZBench. See REPRODUCE.md.
# Tiers:  test (offline, seconds)  <  reproduce (core, ~min)  <  reproduce-all  <  scale (CE apps, ~min).
.PHONY: help test reproduce reproduce-all scale rls paper lint clean
PY ?= python3
TEX_IMAGE ?= texlive/texlive:latest      # override with any Docker LaTeX image

# The offline unit tests (no Odoo, no LLM, no network) — mirrors CI static-checks.
OFFLINE := test_output_validator test_sensitivity_registry test_policy_closure test_policy_scan \
           test_policy_emit test_pushdown_soundness test_policy_model test_numeric_verifier \
           test_metrics_and_consistency test_redteam test_docrag test_agent_loop test_endemic \
           test_rls_model test_write_model test_overhead

help:
	@echo "make test          # offline unit tests (no Docker/LLM/network) — seconds"
	@echo "make reproduce     # regenerate + BYTE-DIFF the core paper tables, gate on both variants (Docker) — ~3-5 min"
	@echo "make reproduce-all # + RQ6/RQ7/RQ8 / agent-loop / LLM-replay drivers"
	@echo "make scale         # CE corpus endemicity + soundness frontier (installs ~11 CE apps) — ~10-20 min"
	@echo "make rls           # cross-engine RLS gap+fix on Postgres (db-only, byte-diff) — §5.5/RQ9 — seconds"
	@echo "make paper         # compile docs/paper.tex -> docs/paper.pdf in an isolated Docker LaTeX image"
	@echo "make lint          # pre-commit: detect-secrets + raw-data regression gate"
	@echo "make clean         # tear down the isolated pgagent-ae compose stack"

test:
	@set -e; for t in $(OFFLINE); do $(PY) tests/$$t.py >/dev/null && echo "ok: $$t"; done
	@echo "offline tests: PASS ($(words $(OFFLINE)) suites)"

reproduce:
	@bash tools/reproduce.sh

reproduce-all:
	@bash tools/reproduce.sh --all

scale:
	@bash tools/scale_scan.sh

rls:
	@bash tools/rls_probe.sh

# Compile the LaTeX port in an isolated container (no host TeX). XeLaTeX = the fontspec branch
# (native UTF-8); the PDF + aux are build artifacts (gitignored). The REPO ROOT is mounted (workdir
# docs/) so any data-driven figure can read `../results/*.csv`. Override TEX_IMAGE if desired.
paper:
	@docker run --rm -v "$(PWD)":/repo -w /repo/docs $(TEX_IMAGE) \
		latexmk -xelatex -interaction=nonstopmode -halt-on-error paper.tex
	@echo "built docs/paper.pdf (gitignored)"

# FDSE / Springer LNCS-CCIS variant (docs/paper_fdse.tex) — compiled with pdfLaTeX (the canonical
# Springer/llncs path) + bibtex (splncs04). Build artifacts gitignored.
paper-fdse:
	@docker run --rm -v "$(PWD)":/repo -w /repo/docs $(TEX_IMAGE) \
		latexmk -pdf -interaction=nonstopmode -halt-on-error paper_fdse.tex
	@echo "built docs/paper_fdse.pdf (gitignored)"

lint:
	@pre-commit run --all-files

clean:
	@docker compose -p pgagent-ae down -v 2>/dev/null || true
	@rm -rf results/repro results/scale/repro
	@echo "cleaned: pgagent-ae stack + results/repro"
