# Deposits Proof Circuit

A Noir circuit that produces a **succinct, on-chain-verifiable attestation** that an order is included
in a Merkle Mountain Range (MMR) under a given root. The destination chain cannot read the source
chain's state directly; this proof carries that cross-chain claim as a single fixed-size object.

The circuit binds three things together:

1. **MMR inclusion** — the order's leaf is in the tree committed by `target_root`.
2. **Nullifier derivation** — `nullifier_hash = poseidon2(secret_half, order_hash)`, so the contract
   records it once and rejects any replay.
3. **Leaf-side binding** — the leaf encodes the trade side (`H(order_hash, side)`), so a proof built
   for one side cannot be reused on the other.

Everything uses **Poseidon2 over BN254**, so the on-chain MMR root is referenced directly by the
circuit without re-encoding. Both chains' Verifiers consume the same fixed-size proof against the same
verification key.

## How inclusion is verified

The circuit does **not** re-derive the tree's shape. The prover supplies the navigation (path
directions, parent node indexes, which peak, the leaf index, width, path length) as **untrusted
hints**, and the circuit re-checks only the **hashes**: it climbs from the leaf to a peak and folds
the peaks into the root. A wrong hint changes a hash, so the climb misses the real peak or the bagging
misses the public `target_root`; forging inclusion would require a Poseidon2 collision. A set of
structural asserts additionally pins the proof's shape (peak count, bounds, path length).

## Inputs

### Public inputs

Order must match the contract's `RequestAuth.buildPublicInputs`: `[nullifier_hash, order_hash,
target_root, ad_contract]`.

* `nullifier_hash: pub Field` — replay guard derived from the secret.
* `order_hash: pub Field` — the order being proven.
* `target_root: pub Field` — the MMR root the proof is checked against (its authenticity is enforced
  upstream by the root registry, not by this circuit).
* `ad_contract: pub bool` — the side flag (`true` = ad side, `false` = order side). Drives both the
  nullifier branch and the leaf-side binding.

### Private inputs

* `secret: Field` — 256-bit secret for the nullifier.
* `leaf_index: u32` — hint: absolute MMR node index of the leaf.
* `width: u32` — hint: number of leaves.
* `path_len: u32` — hint: number of climb steps (leaf to peak).
* `siblings: [Field; 32]` — proof: sibling hash at each climb level.
* `sib_is_left: [bool; 32]` — hint: at each level, whether the sibling is the left child.
* `parent_index: [Field; 32]` — hint: parent node index at each level.
* `peaks: [Field; 32]` — proof: peak hashes, high → low height order.
* `peaks_len: u32` — hint: number of peaks.
* `chosen_peak: u32` — hint: index into `peaks` of the leaf's mountain.

The hint fields are untrusted; soundness comes from the hash chain matching `target_root`.

## Cryptographic design

### Nullifier

The 256-bit secret is split into two 128-bit halves: `(a, b) = split_secret(secret)`.

* `ad_contract == true` → `nullifier_hash = poseidon2(a, order_hash)`
* `ad_contract == false` → `nullifier_hash = poseidon2(order_hash, b)`

### Leaf-side binding

The leaf payload is `value = poseidon2(order_hash, side)` where `side` is `1` (ad) or `0` (order), and
the leaf node is `poseidon2(leaf_index, value)`. The same `side` drives the nullifier, so a proof for
one side cannot satisfy the other. This must match the contract's `appendOrderHash(orderHash,
sideFlag)`.

### MMR root

The root is `poseidon2(DOMAIN_TAG, size, acc)` where:

* `size = 2 * width - popcount(width)` (derived in-circuit, never trusted from input),
* `acc` folds the peaks (high → low), seeded by the first peak (a single size-bind),
* `DOMAIN_TAG = keccak256("ProofBridge.MMR.v1") mod p`, a protocol/version tag that scopes a proof to
  this MMR version. The same constant must be used by the contract and SDK.

## Build & run

Prerequisites: Node.js ≥ 18 + pnpm, Noir/Nargo, Barretenberg (`bb`).

```bash
pnpm install
nargo check                  # compile + validate the input schema
./scripts/generate-inputs.sh # copy scripts/example.txt -> Prover.toml
nargo execute                # produce the witness in ./target/

# prove + verify
bb prove     -b ./target/deposit_circuit.json -w ./target/deposit_circuit.gz -o ./target
bb write_vk  -b ./target/deposit_circuit.json -o ./target
bb verify    -k ./target/vk -p ./target/proof
```

`scripts/example.txt` is a valid sample in the current input format; edit it (or regenerate it from
the SDK) to supply your own proof data. It must be kept in sync with the circuit's input shape.

## Security considerations

* **Replay**: each `nullifier_hash` is recorded on-chain after settlement; later proofs with the same
  value are rejected.
* **Side-binding**: the side is baked into the leaf, so a proof valid on one side is invalid on the other.
* **Root authenticity**: the circuit proves inclusion in `target_root`; it does **not** prove that
  `target_root` is a genuine counterpart-chain root — that is the root registry's job. A fabricated
  tree only helps an attacker if its root passes the registry.
* **Forgery resistance**: the hints cannot forge inclusion — a wrong hint breaks the hash chain and
  fails to match a real peak / the public root, which would require a Poseidon2 collision. Structural
  asserts (peak count == popcount, bounds, path length, leaf-mountain tie) pin the proof's shape.
* **Version scoping**: `DOMAIN_TAG` makes a proof verify only against a ProofBridge-MMR-v1 root; bumping
  the tag retires a version.

## Project layout

```text
.
├─ src/
│  ├─ main.nr      # entrypoint: nullifier + leaf-side binding + inclusion
│  ├─ utils.nr     # secret splitting
│  └─ mmr.nr       # hash-only, hint-based MMR inclusion verification
├─ scripts/
│  ├─ example.txt           # sample inputs (current format)
│  └─ generate-inputs.sh    # example.txt -> Prover.toml
├─ target/                  # compiled ACIR, witness, vk, Verifier
├─ Nargo.toml
└─ Prover.toml              # inputs (generated)
```

## Performance

Proof circuit: ~17.8k gates (2¹⁵ dyadic); `bb prove` ~0.3s on a dev machine. The MMR inclusion is
verified by re-checking hashes against prover-supplied navigation hints, which keeps the circuit small.

## Integration with ProofBridge

* **Backend**: the relayer builds the proof inputs (including the hints) and manages secrets.
* **Contracts**: the generated Solidity / Soroban verifiers are deployed on-chain.
* **Cross-chain**: nullifiers prevent double-spending; `target_root` is authenticated by the root
  registry before an unlock accepts the proof.

For the full system, see the main repository documentation.
