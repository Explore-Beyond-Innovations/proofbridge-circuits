#!/usr/bin/env bash
#
# Adversarial / forgery suite for the event circuit. Generates REAL claims from the SDK (one tree with
# leaves of every domain), confirms valid deposits (domains 0, 1) and event claims (2, 3, 4, 5) are
# accepted, then applies each forgery mutation (sed-based) and confirms every one is REJECTED.
#
# Run: ./adversarial-tests.sh    (from proof_circuits/tests)
#
set -uo pipefail
TESTS="$(cd "$(dirname "$0")" && pwd)"          # proof_circuits/tests/events
CIRCUIT="$TESTS/../../events"
SDK="$TESTS/../../../packages/proofbridge_mmr"
FAKE='0x00000000000000000000000000000000000000000000000000000000deadbeef'

# Apply forgery $1 to a valid file -> Prover.toml (in the circuit dir). Each forges one part of a real proof.
# Deposit cases start from the domain-1 fixture; ev* cases from the domain-2 event claim.
mutate() {
  case "$1" in ev*) cp Prover_d2.toml Prover.toml ;; ff*) cp Prover_d5.toml Prover.toml ;; *) cp Prover.valid.toml Prover.toml ;; esac
  case "$1" in
    side)         sed -i 's/leaf_domain = "1"/leaf_domain = "0"/' Prover.toml ;;                 # wrong side
    asevent)      sed -i 's/leaf_domain = "1"/leaf_domain = "2"/; s/nullifier_hash = "0x[0-9a-f]*"/nullifier_hash = "0x0"/' Prover.toml ;; # deposit leaf claimed as an event
    nullzero)     sed -i 's/nullifier_hash = "0x[0-9a-f]*"/nullifier_hash = "0x0"/' Prover.toml ;; # deposit without its nullifier
    evnullifier)  sed -i 's/nullifier_hash = "0x0"/nullifier_hash = "0x1234"/' Prover.toml ;;     # event carrying a nullifier
    evasdeposit)  sed -i 's/leaf_domain = "2"/leaf_domain = "1"/' Prover.toml ;;                 # event leaf claimed as a deposit
    evdomain)     sed -i 's/leaf_domain = "2"/leaf_domain = "3"/' Prover.toml ;;                 # appended as 2, claimed as 3
    evasforfeit)  sed -i 's/leaf_domain = "2"/leaf_domain = "5"/' Prover.toml ;;                 # a CANCEL leaf claimed as a FORFEIT
    ffascancel)   sed -i 's/leaf_domain = "5"/leaf_domain = "2"/' Prover.toml ;;                 # a FORFEIT leaf claimed as a CANCEL
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
  # C2-2: the FORFEIT cases mutate the domain-5 fixture; comparing them with the valid domain-1 file
  # always "changed", so a no-op sed would go unnoticed and a forgery could be accepted in silence.
  case "$1" in ff*) ref=Prover_d5.toml ;; ev*) ref=Prover_d2.toml ;; *) ref=Prover.valid.toml ;; esac
  cmp -s Prover.toml "$ref" && { echo "FAIL  mutation $1 changed nothing"; fail=1; }
}

echo "==> generating a real proof fixture from the SDK"
( cd "$SDK" && npx ts-node --project "$TESTS/tsconfig.json" -T "$TESTS/gen-fixture.ts" >/dev/null ) || { echo "fixture generation failed"; exit 2; }

cd "$CIRCUIT"
cp Prover.toml Prover.valid.toml
nargo compile >/dev/null 2>&1 || { echo "circuit compile failed"; exit 2; }

fail=0

# every valid claim MUST be accepted: deposits (0, 1) and events (2, 3, 4, 5)
for p in Prover.valid Prover_d0 Prover_d2 Prover_d3 Prover_d4 Prover_d5; do
  if nargo execute -p "$p" _ok >/dev/null 2>&1; then
    echo "PASS  valid claim accepted - $p"
  else
    echo "FAIL  valid claim REJECTED - $p (false negative)"; fail=1
  fi
done

# an event claim carrying a nullifier MUST fail the event branch itself
mutate evnullifier
out=$(nargo execute _neg 2>&1)
if [ $? -eq 0 ]; then echo "FAIL  forgery ACCEPTED - evnullifier   (SOUNDNESS HOLE)"; fail=1
elif grep -q "event claims carry no nullifier" <<<"$out"; then echo "PASS  forgery rejected by the event branch - evnullifier"
else echo "FAIL  evnullifier rejected, but not by the event branch"; fail=1; fi

# every forgery MUST be rejected
CASES=(side asevent nullzero evasdeposit evdomain evasforfeit ffascancel peakslen1 leafoob leafwrong chosen1 pathlen2 flipdir parentidx sibling forgepeak reorderpeaks domainstrip)
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
if [ "$fail" -eq 0 ]; then echo "ALL ADVERSARIAL TESTS PASSED ($((${#CASES[@]}+7)) cases)"; else echo "ADVERSARIAL TESTS FAILED"; fi
exit $fail
