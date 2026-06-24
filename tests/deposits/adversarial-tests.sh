#!/usr/bin/env bash
#
# Adversarial / forgery suite for the deposit circuit. Generates a REAL proof from the SDK, confirms
# the valid proof is accepted, then applies each forgery mutation (sed-based) and confirms every one
# is REJECTED. Exits non-zero if the valid proof is rejected or any forgery is accepted.
#
# Run: ./adversarial-tests.sh    (from proof_circuits/tests)
#
set -uo pipefail
TESTS="$(cd "$(dirname "$0")" && pwd)"          # proof_circuits/tests/deposits
CIRCUIT="$TESTS/../../deposits"
SDK="$TESTS/../../../packages/proofbridge_mmr"
FAKE='0x00000000000000000000000000000000000000000000000000000000deadbeef'

# Apply forgery $1 to Prover.valid.toml -> Prover.toml (in the circuit dir). Each forges one part of a real proof.
mutate() {
  cp Prover.valid.toml Prover.toml
  case "$1" in
    side)         sed -i 's/ad_contract = true/ad_contract = false/' Prover.toml ;;              # wrong side
    peakslen1)    sed -i 's/peaks_len = "[0-9]*"/peaks_len = "1"/' Prover.toml ;;                # peak-count (malleability)
    leafoob)      sed -i 's/leaf_index = "[0-9]*"/leaf_index = "999999"/' Prover.toml ;;         # out-of-bounds
    leafwrong)    sed -i 's/leaf_index = "[0-9]*"/leaf_index = "8"/' Prover.toml ;;              # wrong in-bounds leaf
    chosen1)      sed -i 's/chosen_peak = "[0-9]*"/chosen_peak = "1"/' Prover.toml ;;            # wrong peak
    pathlen2)     sed -i 's/path_len = "[0-9]*"/path_len = "2"/' Prover.toml ;;                  # wrong path length
    flipdir)      sed -i 's/sib_is_left = \[true/sib_is_left = [false/; t; s/sib_is_left = \[false/sib_is_left = [true/' Prover.toml ;; # flip a direction
    parentidx)    sed -i 's/parent_index = \["[0-9]*"/parent_index = ["777"/' Prover.toml ;;     # tamper a parent index
    sibling)      sed -i "s/siblings = \[\"0x[0-9a-f]*\"/siblings = [\"$FAKE\"/" Prover.toml ;;  # tamper a sibling
    forgepeak)    sed -i "s/peaks = \[\"0x[0-9a-f]*\"/peaks = [\"$FAKE\"/" Prover.toml ;;        # forge a peak
    reorderpeaks) sed -i 's/peaks = \[\("0x[0-9a-f]*"\), \("0x[0-9a-f]*"\)/peaks = [\2, \1/' Prover.toml ;; # reorder peaks
    domainstrip)  sed -i "s|target_root = \"0x[0-9a-f]*\"|target_root = \"$(cat untagged_root.txt)\"|" Prover.toml ;; # wrong/missing domain tag
    *) echo "unknown case: $1"; exit 2 ;;
  esac
}

echo "==> generating a real proof fixture from the SDK"
( cd "$SDK" && npx ts-node --project "$TESTS/tsconfig.json" -T "$TESTS/gen-fixture.ts" >/dev/null ) || { echo "fixture generation failed"; exit 2; }

cd "$CIRCUIT"
cp Prover.toml Prover.valid.toml
nargo compile >/dev/null 2>&1 || { echo "circuit compile failed"; exit 2; }

fail=0

# the valid proof MUST be accepted
cp Prover.valid.toml Prover.toml
if nargo execute _ok >/dev/null 2>&1; then
  echo "PASS  valid proof accepted"
else
  echo "FAIL  valid proof REJECTED (false negative)"; fail=1
fi

# every forgery MUST be rejected
CASES=(side peakslen1 leafoob leafwrong chosen1 pathlen2 flipdir parentidx sibling forgepeak reorderpeaks domainstrip)
for c in "${CASES[@]}"; do
  mutate "$c"
  if nargo execute _neg >/dev/null 2>&1; then
    echo "FAIL  forgery ACCEPTED - $c   (SOUNDNESS HOLE)"; fail=1
  else
    echo "PASS  forgery rejected - $c"
  fi
done

cp Prover.valid.toml Prover.toml
echo
if [ "$fail" -eq 0 ]; then echo "ALL ADVERSARIAL TESTS PASSED ($((${#CASES[@]}+1)) cases)"; else echo "ADVERSARIAL TESTS FAILED"; fi
exit $fail
