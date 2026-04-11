# Auth Proof Circuit

This is a Noir proof circuit that proves a user is authorized to execute a trade intent **without revealing the signature itself**. The verifier only needs the **hash** of that secret signature.

* We bind authorization to a user's **ECDSA key** (secp256k1).
* The *actual* trade-intent signature remains private; only its hash is provided publicly.
* This design avoids "passwords" and keeps the secret unique to the user.

## Development Status

### Current Status

**ECDSA implementation is not currently active** due to prohibitively large proof sizes generated in combination with deposit verification for the zero-knowledge circuits.

### In Development

**BLS signature aggregation and consensus mechanisms** using BN254 curves for trade fulfillment consensus between bridgers and ad creators. This is part of the project milestones and represents the primary authentication approach moving forward.

#### BLS Trade Consensus Design

**Objective**: Aggregate bridger and ad creator signatures as cryptographic consensus for trade fulfillment, integrated with deposit proofs for complete transaction validation.

**Key Features:**

* **Dual-Party Consensus**: Combines bridger and ad creator BLS signatures into a single aggregated proof
* **Trade Fulfillment Validation**: Cryptographic consensus that both parties agree to trade execution
* **Deposit Proof Integration**: BLS consensus proof will be combined with MMR inclusion proofs from the deposits circuit
* **Atomic Settlement**: Ensures both authentication and deposit validation in a unified ZK proof system
* **BN254 Optimization**: Leverages BN254 curve for efficient pairing operations in zero-knowledge circuits

#### Integration with Deposits Circuit

The BLS consensus mechanism will work in conjunction with the deposits proof circuit:

1. **Deposit Validation**: Deposits circuit proves order inclusion in MMR
2. **Consensus Validation**: BLS aggregation proves both parties consent to fulfillment
3. **Combined Proof**: Single ZK proof validates both deposit existence and trade consensus
4. **Cross-Chain Settlement**: Unified proof enables atomic settlement across chains

#### Technical Implementation

* **Signature Aggregation**: `BLS_Aggregate(bridger_sig, ad_creator_sig) → consensus_sig`
* **Consensus Verification**: Validates aggregated signature against trade parameters
* **Proof Composition**: Combines BLS consensus with MMR inclusion proofs
* **Gas Efficiency**: Single proof verification instead of multiple signature checks

#### Development Roadmap

* **Current Focus**: BLS aggregation for bridger + ad creator consensus (milestone deliverable)
* **Next Phase**: Unified proof system combining BLS consensus with deposit validation
* **Final Phase**: Full integration with cross-chain settlement protocol

#### Why BLS Over ECDSA

* **Proof Size**: ECDSA signature verification generates prohibitively large ZK proofs
* **Efficiency**: BLS signatures are more efficient in zero-knowledge circuits
* **Aggregation**: BLS naturally supports signature aggregation for consensus
* **BN254 Compatibility**: BLS on BN254 curve is optimized for ZK proof systems

> **Note**: Development has shifted focus to BLS consensus mechanisms due to proof size constraints with ECDSA. BLS consensus is part of the project milestones and will be integrated with the deposits circuit to provide complete trade validation in a single ZK proof.

## Inputs

### Public inputs

* `nullifier_hash: pub Field` — hash of the private signature/secret (prevents reuse, links proof to intent).
* `ad_creator: pub Field` — ad creator address.
* `bridger: pub Field` — bridger address.
* `msg_hash: pub [u8; 32]` — 32-byte message hash associated with the intent.
* `ad_contract: pub bool` — if `true`, the **bridger** provides `nullifier_hash`; if `false`, the **ad_creator** provides it.

### Private inputs

* `ad_creator_pub_key: [u8; 65]` — uncompressed secp256k1 pubkey: `0x04 || X(32) || Y(32)`.
* `ad_creator_sig: [u8; 64]` — ECDSA signature **RS** only (drop `V`).
* `bridger_pub_key: [u8; 65]` — uncompressed secp256k1 pubkey.
* `bridger_sig: [u8; 64]` — ECDSA signature **RS** only (drop `V`).

> ℹ️ If your tool returns a 64-byte public key (just `X||Y`), prepend `0x04` to make it 65 bytes.

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

This compiles the circuit and prepares the target artifacts. It also ensures your input schema is valid (and typically generates/refreshes `Prover.toml` if you use Noir’s input annotations).

```bash
nargo check
```

## Provide Inputs

We've included a helper and a human-readable reference:

* `./scripts/inputs.txt` — a readable checklist of the required inputs.
* `./generate-inputs.sh` — fills `Prover.toml` with values based of data in inputs.txt.

Run:

```bash
./scripts/generate-inputs.sh
```

You can edit `./scripts/inputs.txt` to point at your own generated pubkeys/signatures.

> The nullifier hash will be generated in the script based on the ad_contract value.

## Execute to Produce a Witness

This computes the witness using your `Prover.toml` values.

```bash
nargo execute
```

This will create a witness artifact in `./target/`, commonly `./target/<package>.gz`.

---

## Prove with Barretenberg

Use `bb` with the ACIR and the witness:

```bash
# ACIR bytecode (JSON) and witness (.gz) are produced in ./target by nargo
bb prove \
  -b ./target/proof_circuit.json \
  -w ./target/proof_circuit.gz \
  -o ./target
```

This writes a proof artifact (e.g., `./target/proof` or similar, depending on your `bb` version).

### Verify

Generate a verification key, then verify the proof:

```bash
# Write a verification key from the ACIR
bb write_vk -b ./target/proof_circuit.json -o ./target

# Verify the proof with the VK
bb verify -k ./target/vk -p ./target/proof
```

---

## Project Layout

```text
.
├─ src/
|  |─ main.nr               # proof circuit
│  └─ utils.nr              # helper mod to split publickeys
├─ scripts/
│  ├─ inputs.txt            # readable input 
|  |─ hash.ts               # helper script to hash nullifier
│  └─ generate-inputs.sh    # populates Prover.toml
├─ Nargo.toml               
```
