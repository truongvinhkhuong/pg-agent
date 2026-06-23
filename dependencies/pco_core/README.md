# dependencies/pco_core — submodule mount (INTERNAL ONLY)

This directory is **empty in the public repo** and stays that way.

In the **inverted** architecture, the public `pg-agent` repo does NOT embed the
private `pco_core`. Instead:

- **Public / reviewer mode:** ignore this folder. The benchmark runs entirely on
  `addons/pco_core_mock` + synthetic data. There is no submodule here.
- **Internal validation mode (private monorepo / internal Colab):** the real
  private `pco_core` addons are mounted here so `pg_agent_guard` can be validated
  against real models. This mount is wired from the PRIVATE side
  (see `scripts/setup_submodule.sh`) and is never committed to the public repo.

> If you ever see real business code committed under this path in the public
> repo, that is a leak — revert it.
