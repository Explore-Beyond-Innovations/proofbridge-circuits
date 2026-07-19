# Auth Proof Circuit (BLS aggregate)

A Noir/UltraHonk circuit that proves an **aggregated maker + bridger BLS12-381
signature** is valid over the root-bound **SettlementAuth** message — i.e. that
both counterparties consented to a specific settlement. It is the ZK form of the
consensus check that the on-chain `CounterpartyVerifier` performs natively.

> **Status: building block, not wired into the settlement path.** Today's T1
> unlock verifies the aggregate BLS signature natively on-chain (EIP-2537
> precompiles / Soroban `bls12_381` host functions) and the unlock ZK proof only
> attests deposit inclusion. This circuit is foundational work (issue #157, subs
> #163–#166) for a future context that folds BLS consensus into a ZK proof —
> e.g. replacing the native pairing to save gas, or T2 composition. It is
> **implemented but not consumed** by any contract or the relayer yet.

## What it proves

Minimal-pubkey-size suite (pubkeys in G1; signature and hashed message in G2),
matching `@proofbridge/bls-encodings` and `01-bls-encodings.md`. The circuit calls
`verify_bls_signature`, which checks

```
e(-g1, agg_sig) * e(pk_agg, H(m)) == 1
```

as one shared Miller loop plus a single final exponentiation.

### Inputs (`src/main.nr`)

**Public**
- `pk_agg` — the aggregated G1 public key (`pk_maker + pk_bridger`). The consumer
  binds it to the registry commitments (`keccak256(pk) == keyOf(account)`).
- `msg` — `H(m) = hash_to_g2(preimage, DST_SIG)`, the hashed SettlementAuth
  message in G2. The preimage is the production 192-byte layout
  `SETTLE_TAG || orderChainId || adChainId || orderHash || orderChainRoot ||
  adChainRoot`. Binding `msg` to those roots is the point of the proof, so it is
  public.

**Private**
- `agg_sig` — the aggregated G2 signature.

All curve coordinates are 4×120-bit `u128` limbs (noir-bignum layout).

### Deliberately out of scope

- **Hash-to-curve** and **G1 key aggregation** are done off-circuit (by the helper
  below and natively on-chain), so `msg` and `pk_agg` arrive ready-made. Doing
  RFC 9380 `hash_to_g2` in-circuit would be prohibitively large.
- **No G2 subgroup check** on `agg_sig`. The native EIP-2537 / Soroban BLS ops
  that consume the same published points subgroup-check them. A future
  "replace the native pairing" use must add an in-circuit check (endomorphism /
  Bowe–Scott `ψ(P) == [z]P`); until then the proof is only sound alongside a
  native check that subgroup-validates the signature.

## Dependency

Built on the `bls12_381` library (`Nargo.toml`), a ProofBridge fork of
`critesjosh/noir-bls-signature` pinned to `noir-bignum v0.7.3` so it compiles on
the repo toolchain (`nargo 1.0.0-beta.9` + `bb v0.87.0`). It is consumed as a
**sibling path dependency** (`../../../noir-bls-library`), like `solidity-mmr`;
once that fork is pushed and tagged, switch `Nargo.toml` to the `git` + `tag`
form noted there.

## Build

```bash
# compile + verification key (both chains); add --prove to also prove
scripts/build_circuits.sh proof_circuits/auth
```

Artifacts land in `target/`: `auth_circuit.json` (ACIR), `vk` (+ `vk_fields.json`)
for the reusable Soroban verifier, and `AuthVerifier.sol` for EVM (both generated
with `--oracle_hash keccak`).

## Inputs & fixtures

```bash
cd scripts && pnpm install
pnpm gen valid > ../fixtures/valid.toml   # build a Prover.toml for one case
pnpm fixtures                             # regenerate all four fixtures
pnpm test                                 # solve each and assert pass/fail
```

The helper (`scripts/gen-inputs.ts`, #164) assembles the SettlementAuth preimage,
signs with two deterministic keys, aggregates, and emits limb-encoded inputs — the
same noble code path as the relayer and `scripts/bls-vectors`. The four fixtures
(#165) are documented in `fixtures/README.md`.

## Performance

On a 20-core/30GB machine the aggregate verify is ~4.19M UltraHonk gates,
~28s `bb prove`, ~8GB. The #157 target of ≤30s on an 8-core/16GB reference
machine is not met on this toolchain generation (BLS12-381 pairing emulated over
BN254); expect ~2× that on the reference box. Revisit after the deferred `bb`
upgrade, or trim further with the reserved field-tower optimizations.
