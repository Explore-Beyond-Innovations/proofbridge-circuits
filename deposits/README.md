# Deposits Proof Circuit

This is a Noir proof circuit that proves the inclusion of an order hash in a Merkle Mountain Range (MMR) **without revealing the secret used for nullifier generation**. The circuit validates that a specific order exists in the MMR and that the prover knows the corresponding secret for nullifier computation.

* We use **Poseidon2 hashing** for cryptographic operations and MMR proof verification.
* The *actual* secret remains private; only its derived nullifier hash is provided publicly.
* This design ensures privacy while proving order inclusion and preventing double-spending.

## Circuit Overview

The deposits circuit performs two main validations:

1. **Nullifier Verification**: Proves knowledge of a secret that generates the expected nullifier hash
2. **MMR Inclusion Proof**: Validates that an order hash exists in the specified MMR at a given index

## Inputs

### Public inputs

* `nullifier_hash: pub Field` — cryptographic commitment derived from the secret (prevents reuse, ensures uniqueness).
* `order_hash: pub Field` — the order hash that must be proven to exist in the MMR.
* `target_root: pub Field` — the expected MMR root hash for validation.
* `ad_contract: pub bool` — determines nullifier computation method: if `true`, uses left half of secret; if `false`, uses right half.

### Private inputs

* `secret: Field` — the private secret used for nullifier generation (256-bit value).
* `target_index: Field` — the index position of the order hash in the MMR.
* `target_elements_count: Field` — total number of elements in the MMR.
* `target_sibling_hashes_len: Field` — number of sibling hashes in the inclusion proof (≤ 20).
* `target_sibling_hashes: [Field; 20]` — array of sibling hashes for the inclusion proof path.
* `target_peak_hashes_len: Field` — number of peak hashes in the MMR (≤ 20).
* `target_peak_hashes: [Field; 20]` — array of MMR peak hashes for root reconstruction.

## Cryptographic Design

### Nullifier Generation

The circuit splits the 256-bit secret into two 128-bit halves:

```rust
(a, b) = split_secret(secret)  // a = left 128 bits, b = right 128 bits
```

Nullifier computation depends on the `ad_contract` flag:
- **If `ad_contract` is true**: `nullifier_hash = poseidon2(a, order_hash)`
- **If `ad_contract` is false**: `nullifier_hash = poseidon2(order_hash, b)`

This dual-mode design allows different participants (ad creators vs. bridgers) to generate unique nullifiers from the same secret.

### MMR Verification Process

1. **Peak Reconstruction**: Computes MMR peaks from the inclusion proof
2. **Root Validation**: Reconstructs the MMR root from peaks and elements count
3. **Inclusion Proof**: Verifies the order hash exists at the specified index
4. **Peak Containment**: Ensures the computed peak exists in the provided peak set

## Prerequisites

* **Node.js** ≥ 18 and **pnpm**
* **Noir / Nargo** (Noir CLI)
* **Barretenberg CLI** (`bb`)

> Install Noir/Nargo and `bb` using the official instructions for your platform.
> After installing, you should have `nargo --version` and `bb --version` working.

## Install JS dependencies

```bash
pnpm install
```

## Build & Check the Circuit

This compiles the circuit and prepares the target artifacts. It also ensures your input schema is valid.

```bash
nargo check
```

## Provide Inputs

We've included a helper and a human-readable reference:

* `./scripts/example.txt` — example input values with proper formatting.
* `./scripts/generate-inputs.sh` — copies example values to `Prover.toml`.

Run:

```bash
./scripts/generate-inputs.sh
```

You can edit `./scripts/example.txt` to provide your own MMR proof data and secret values.

> The secret should be a 256-bit value, and the nullifier hash should be computed according to the ad_contract flag.

## Execute to Produce a Witness

This computes the witness using your `Prover.toml` values.

```bash
nargo execute
```

This will create a witness artifact in `./target/`, commonly `./target/deposit_circuit.gz`.

---

## Prove with Barretenberg

Use `bb` with the ACIR and the witness:

```bash
# ACIR bytecode (JSON) and witness (.gz) are produced in ./target by nargo
bb prove \
  -b ./target/deposit_circuit.json \
  -w ./target/deposit_circuit.gz \
  -o ./target
```

This writes a proof artifact (e.g., `./target/proof` or similar, depending on your `bb` version).

### Verify

Generate a verification key, then verify the proof:

```bash
# Write a verification key from the ACIR
bb write_vk -b ./target/deposit_circuit.json -o ./target

# Verify the proof with the VK
bb verify -k ./target/vk -p ./target/proof
```

---

## MMR Proof Requirements

### Understanding MMR Structure

Merkle Mountain Ranges (MMRs) are append-only binary trees optimized for efficient proofs:

- **Peaks**: Top-level nodes of the MMR forest
- **Elements Count**: Total number of leaf nodes in the MMR
- **Root**: Hash of (elements_count || bagged_peaks)

### Generating MMR Proofs

To generate valid inputs for this circuit, you need:

1. **Order Hash**: The specific order you want to prove inclusion for
2. **MMR Index**: The position where the order hash was inserted
3. **Sibling Path**: Hashes needed to reconstruct the path to a peak
4. **Peak Set**: All current peaks of the MMR
5. **Root**: The current MMR root hash

### Example MMR Proof Structure

```toml
order_hash = "0x0a8bbf0df76dfb05ac821a820c19746de10bd651613a40f6719cbddbca50fd5a"
target_index = "88929"                    # Position in MMR
target_elements_count = "199994"          # Total leaves
target_sibling_hashes_len = "16"          # Number of siblings
target_peak_hashes_len = "6"              # Number of peaks
target_root = "0x2da7e34cf373d78fa4e86575d42f5e694d6b81359ca164d8fab4cde05b48110f"
```

## Security Considerations

### Privacy Guarantees

* **Secret Protection**: The 256-bit secret never leaves the prover's system
* **Nullifier Unlinkability**: Different nullifiers are generated for different roles
* **Order Privacy**: Only proves inclusion, not order contents

### Attack Resistance

* **Double-Spending Prevention**: Nullifiers ensure each secret can only be used once per order
* **Replay Protection**: MMR root validation prevents stale proof acceptance
* **Forgery Resistance**: Cryptographic commitments prevent unauthorized proof generation

### Proof Verification

The circuit ensures:
1. Prover knows the secret corresponding to the nullifier hash
2. Order hash exists at the claimed MMR index
3. MMR proof is valid against the provided root
4. All cryptographic operations use secure Poseidon2 hashing

## Project Layout

```text
.
├─ src/
│  ├─ main.nr               # main proof circuit logic
│  ├─ utils.nr              # secret splitting utilities
│  └─ mmr.nr                # MMR proof verification functions
├─ scripts/
│  ├─ example.txt           # example input values
│  └─ generate-inputs.sh    # input generation script
├─ target/
│  ├─ deposit_circuit.json  # compiled ACIR bytecode
│  ├─ deposit_circuit.gz    # witness file
│  ├─ vk                    # verification key
│  └─ Verifier.sol          # Solidity verifier contract
├─ Nargo.toml               # project configuration
└─ Prover.toml              # input values (generated)
```

## Performance Notes

**Proof Generation Time**: Currently ~1 minute 30 seconds (up from ~30 seconds previously)

This performance regression is due to a necessary change in our MMR implementation. We were originally using a GNU-licensed MMR library, but the licensing issue was announced on Discord just this week. Without sufficient time to properly optimize a new implementation, we built a working MMR tree implementation from scratch 2 days ago that maintains correctness but needs optimization work.

**Future Improvements**: The MMR implementation is functional and correct but still requires performance optimizations. This will be addressed in future updates to bring proof generation times back down.

## Integration with ProofBridge

This circuit is designed to work seamlessly with the ProofBridge protocol:

* **Backend Integration**: The relayer service generates MMR proofs and manages secrets
* **Contract Verification**: The generated Solidity verifier is deployed on-chain
* **Cross-Chain Coordination**: Nullifiers prevent double-spending across different chains
* **Privacy Preservation**: Order details remain private while proving valid inclusion

For more information on the complete ProofBridge system, see the main repository documentation.
