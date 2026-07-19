#!/usr/bin/env bash
set -euo pipefail
# Regenerate the 4-case fixture Prover.toml files. Run after `pnpm install`.

cd "$(dirname "$0")"
mkdir -p ../fixtures

for kase in valid single-signer invalid-sig wrong-pubkey; do
  out="../fixtures/${kase//-/_}.toml"
  tsx gen-inputs.ts "$kase" > "$out"
  echo "wrote $out"
done
