#!/usr/bin/env bash
set -uo pipefail
# 4-case circuit test pack (issue #165): solve the witness for each fixture and
# assert the expected pass/fail. valid + single-signer must solve; invalid-sig +
# wrong-pubkey must be rejected by the in-circuit pairing check.

cd "$(dirname "$0")/.."   # proof_circuits/auth
export PATH="$HOME/.nargo/bin:$HOME/.bb/bin:$PATH"

declare -A EXPECT=(
  [valid]=pass
  [single_signer]=pass
  [invalid_sig]=fail
  [wrong_pubkey]=fail
)

fail=0
for kase in valid single_signer invalid_sig wrong_pubkey; do
  toml="fixtures/${kase}.toml"
  [ -f "$toml" ] || { echo "MISSING $toml (run gen-fixtures.sh)"; fail=1; continue; }
  cp "$toml" Prover.toml
  if nargo execute "wit_${kase}" >/dev/null 2>&1; then got=pass; else got=fail; fi
  want="${EXPECT[$kase]}"
  if [ "$got" = "$want" ]; then
    echo "ok   ${kase}: ${got} (expected ${want})"
  else
    echo "FAIL ${kase}: ${got} (expected ${want})"
    fail=1
  fi
done

rm -f Prover.toml
[ "$fail" -eq 0 ] && echo "all fixtures behaved as expected" || echo "fixture pack FAILED"
exit "$fail"
