#!/usr/bin/env bash
#
# End-to-end parity test: the proofbridge_mmr SDK generates a real inclusion proof, and the deposit
# circuit must ACCEPT it and bb must VERIFY it. Proves the SDK and circuit implement the same
# commitment scheme (index-bound hashes, single size-bind + domain tag).
#
# Run: ./test-sdk-e2e.sh    (from proof_circuits/tests)
# CI-friendly: exits non-zero on any failure.
#
set -uo pipefail
TESTS="$(cd "$(dirname "$0")" && pwd)"          # proof_circuits/tests/deposits
CIRCUIT="$TESTS/../../deposits"
SDK="$TESTS/../../../packages/proofbridge_mmr"

echo "==> generating a proof with the SDK"
( cd "$SDK" && npx ts-node --project "$TESTS/tsconfig.json" -T "$TESTS/gen-fixture.ts" >/dev/null ) \
  || { echo "FAIL: SDK fixture generation"; exit 1; }

cd "$CIRCUIT"
echo "==> circuit must accept the SDK proof"
nargo compile >/dev/null 2>&1 || { echo "FAIL: nargo compile"; exit 1; }
nargo execute e2e >/dev/null 2>&1 || { echo "FAIL: circuit rejected the SDK proof"; exit 1; }

echo "==> prove + verify"
bb prove    -b target/deposit_circuit.json -w target/e2e.gz -o target >/dev/null 2>&1 || { echo "FAIL: bb prove"; exit 1; }
bb write_vk -b target/deposit_circuit.json -o target >/dev/null 2>&1                   || { echo "FAIL: bb write_vk"; exit 1; }
bb verify   -k target/vk -p target/proof >/dev/null 2>&1                               || { echo "FAIL: bb verify"; exit 1; }

echo "PASS: SDK proof accepted and verified by the production deposit circuit"
