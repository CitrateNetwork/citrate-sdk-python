#!/usr/bin/env bash
# LOCAL contract-drift check — no GitHub Actions, no token required.
#
# Verifies this SDK's vendored citrate_sdk/_generated/federation_contract.json
# still matches the canonical federation intermediate
# (citrate-federation/contract/federation-contract.json), which federation's
# contract-artifact-drift workflow keeps fresh vs citrate-chain. Run before
# pushing/merging and after every re-roll while org CI is down.
#
#   bash scripts/check-contract-drift.sh
#
# Exit 1 on drift. Local mirror of the `contract-drift` job in
# .github/workflows/ci.yml (CL-C2 / SW-092).
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
CANONICAL="$HERE/../citrate-federation/contract/federation-contract.json"

if [ ! -f "$CANONICAL" ]; then
  echo "[contract-drift] federation sibling not found at $CANONICAL"
  echo "  Ensure citrate-federation is a sibling of this repo under citrate-labs/."
  exit 2
fi

python3 "$HERE/scripts/sync_contract.py" --check
