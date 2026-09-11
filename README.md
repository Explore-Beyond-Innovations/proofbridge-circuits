# proofbridge-circuits

The zero-knowledge circuits behind [ProofBridge](https://github.com/Explore-Beyond-Innovations/ProofBridge),
a peer-to-peer cross-chain settlement protocol. Each chain keeps an append-only Merkle Mountain Range
(MMR) of what happened on it: deposits, cancellations, settlements. A contract on one chain cannot read
the other chain, so when it needs to know that something happened over there, whoever wants the outcome
brings a proof that the matching leaf is in the other chain's MMR. These circuits produce those proofs.

Written in [Noir](https://noir-lang.org), proven with UltraHonk ([Barretenberg](https://github.com/AztecProtocol/aztec-packages)).

## Circuits

| Circuit | Folder | Status | What it proves |
| --- | --- | --- | --- |
| **Event** | [`events/`](events/README.md) | production, verified on both chains | a leaf is in the MMR under a given root; for deposits, also that the prover holds the trade secret |
| **Auth** | [`auth/`](auth/README.md) | building block, not used by any contract yet | an aggregated maker + bridger BLS12-381 signature over a settlement message |

### The event circuit, in short

One circuit proves every kind of leaf. The kind is the **leaf domain**, the proof's last public input:

| Domain | Leaf | Needs the trade secret? |
| --- | --- | --- |
| `0` | deposit, unlocked on the order side | yes: proves the nullifier preimage |
| `1` | deposit, unlocked on the ad side | yes: proves the nullifier preimage |
| `2` | order cancelled | no, `nullifier_hash` must be `0` |
| `3` | order settled | no, `nullifier_hash` must be `0` |
| `4` | key registered | no, `nullifier_hash` must be `0` |

Public inputs: `[nullifier_hash, order_hash, target_root, leaf_domain]`. The leaf is
`poseidon2(order_hash, leaf_domain)`, so a proof made for one domain cannot be used for another.

The contracts always build these public inputs themselves (the domain is a constant in the contract,
never something the caller passes in). That is what keeps a secret-free event claim from ever being
used to unlock funds. See [`events/README.md`](events/README.md) for the full design.

## Toolchain

Pinned, and installed automatically by the build script if missing:

- `nargo` **1.0.0-beta.9**
- `bb` **v0.87.0**, `ultra_honk` scheme with the keccak oracle (what both chains' verifiers expect)

Moving either pin changes the verification keys, and therefore the deployed verifiers.

## Build

```bash
# compile + verification key -> events/target/{event_circuit.json, vk}
scripts/build_circuits.sh events

# also execute + prove (needs a Prover.toml) -> events/target/{proof, public_inputs}
scripts/build_circuits.sh events --prove
```

The script takes a circuit folder, or a parent folder, and builds every circuit it finds.

## Tests

```bash
cd tests/events
./adversarial-tests.sh   # real fixtures for every domain; valid claims accepted, 17 forgeries rejected
./test-sdk-e2e.sh        # the SDK builds a real proof; the circuit accepts it and bb verifies it
```

The fixture generator builds its MMR with the `proofbridge-mmr` SDK and imports it by relative path
from `../packages/proofbridge_mmr`, the layout of the ProofBridge monorepo, where this repo sits at
`proof_circuits/`. Outside the monorepo, unpack the published `proofbridge-mmr` package there, as CI does.

CI (`.github/workflows/circuits.yml`) builds the event circuit, fails if it grows past **20,000 gates**
(proving time follows circuit size), and runs the adversarial suite.

## Who uses this

- **[proofbridge-contracts](https://github.com/Explore-Beyond-Innovations/proofbridge-contracts)**:
  `scripts/gen-verifier.sh` turns `events/target/vk` into the EVM `Verifier.sol`, and the Soroban verifier
  is deployed with the same `vk`. Its CI checks out this repo's `main`, so a circuit change reaches it
  immediately.
- **ProofBridge** (the monorepo): includes this repo as the `proof_circuits` submodule. The relayer ships
  a copy of `event_circuit.json` to build proofs.

**Changing a circuit** changes its verification key. After merging one: regenerate `Verifier.sol` in
proofbridge-contracts, refresh the relayer's `event_circuit.json`, and redeploy both chains' verifiers.

## Numbers

| Circuit | Size | `bb prove` |
| --- | --- | --- |
| Event | ~17.8k gates | ~0.3 s on a dev machine |
| Auth | ~4.19M gates | ~28 s, ~8 GB, on a 20-core machine |

## Layout

```
events/                  the event circuit (src/main.nr, src/mmr.nr, README)
auth/                    the BLS aggregate-signature circuit (+ its fixtures and input generator)
tests/events/            fixture generator, adversarial suite, SDK end-to-end test
scripts/build_circuits.sh  compile, prove and write verification keys
```
