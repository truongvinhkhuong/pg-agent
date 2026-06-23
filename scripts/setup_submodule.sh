#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# INVERTED submodule wiring.
#
# CORE PRINCIPLE: the PUBLIC repo never references the PRIVATE one.
#   - WRONG (original spec): pg-agent (public) embeds pco_core (private)  -> leaks
#                            URL/SHA + permanent foot-gun in public history.
#   - RIGHT (this repo):     the PRIVATE monorepo embeds pg-agent (public) for
#                            validation. Public stays self-contained on the mock.
#
# Run this INSIDE the PRIVATE monorepo, NOT in pg-agent.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

PUBLIC_REPO_URL="git@github.com:truongvinhkhuong/pg-agent.git"   # the PUBLIC academic repo
MOUNT="vendor/pg-agent"                                # where it lands in private

# 1) Add the PUBLIC repo as a submodule of the PRIVATE monorepo.
git submodule add "${PUBLIC_REPO_URL}" "${MOUNT}"

# 2) Pinning is AUTOMATIC: a submodule always records an exact commit SHA in the
#    superproject's gitlink. "Drift" only happens if someone runs
#    `git submodule update --remote`. So you do NOT need a special pin step.
#    To intentionally bump the pin to a reviewed commit:
#
#      cd "${MOUNT}"
#      git fetch origin && git checkout <reviewed_commit_sha>
#      cd -
#      git add "${MOUNT}"
#      git commit -m "chore: bump pg-agent submodule to <sha>"
#
# 3) (Optional) CI guard against accidental drift — assert the pinned SHA:
#      git -C "${MOUNT}" rev-parse HEAD | grep -qx "<expected_sha>" \
#        || { echo "pg-agent submodule drifted!"; exit 1; }

echo "Done. pg-agent (public) is now a pinned submodule of the private repo at ${MOUNT}."
echo "The public repo contains NO pointer back here — by design."
