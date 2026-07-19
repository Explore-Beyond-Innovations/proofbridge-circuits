// Auth circuit input helper (issue #164).
//
// Builds the root-bound SettlementAuth message, aggregates the maker + bridger
// BLS12-381 signatures, and emits a Prover.toml for proof_circuits/auth. Uses the
// exact production suite: minimal-pubkey-size (pk G1 / sig G2), DST_SIG, and the
// same 192-byte SETTLE_TAG-prefixed preimage the on-chain CounterpartyVerifier
// rebuilds. Kept dependency-light (@noble/curves only) so it runs standalone.
//
// Usage:
//   tsx gen-inputs.ts <case> > ../<out>.toml
// where <case> is one of: valid | single-signer | invalid-sig | wrong-pubkey.
// Cases and their expected circuit behaviour are documented in fixtures/.

import { bls12_381 as bls } from "@noble/curves/bls12-381";
import { keccak_256 } from "@noble/hashes/sha3";

const blsSigs = bls.longSignatures;

const utf8 = (s: string) => new TextEncoder().encode(s);
const hex = (b: Uint8Array) => "0x" + Buffer.from(b).toString("hex");

// Production constants (see docs/engineering/t1/1.2-build/01-bls-encodings.md).
const SETTLE_TAG = keccak_256(utf8("ProofBridge.Settlement.v1"));
const DST_SIG = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
// sepolia / stellar-testnet chain ids from the encodings spec.
const ORDER_CHAIN_ID = 11155111n;
const AD_CHAIN_ID = 1000001n;

function be(v: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let x = v;
  for (let i = len - 1; i >= 0 && x > 0n; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function concat(...arrs: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let o = 0;
  for (const a of arrs) {
    out.set(a, o);
    o += a.length;
  }
  return out;
}

// Deterministic scalar in [1, order): keccak(label) mod (order-1) + 1.
function skFromLabel(label: string): Uint8Array {
  const order = bls.fields.Fr.ORDER;
  const h = BigInt(hex(keccak_256(utf8(label))));
  return be((h % (order - 1n)) + 1n, 32);
}

// SETTLE_TAG || orderChainId(32) || adChainId(32) || orderHash || orderChainRoot
// || adChainRoot -- fixed 192 bytes, identical to buildSettlementPreimage.
export function settlementPreimage(): Uint8Array {
  const p = concat(
    SETTLE_TAG,
    be(ORDER_CHAIN_ID, 32),
    be(AD_CHAIN_ID, 32),
    keccak_256(utf8("proofbridge.auth.orderHash.1")),
    keccak_256(utf8("proofbridge.auth.orderChainRoot.1")),
    keccak_256(utf8("proofbridge.auth.adChainRoot.1")),
  );
  if (p.length !== 192) throw new Error(`preimage must be 192 bytes, got ${p.length}`);
  return p;
}

// 4 x 120-bit little-endian limbs (noir-bignum layout for BLS12-381 Fq).
function limbs(v: bigint): string[] {
  const mask = (1n << 120n) - 1n;
  const out: string[] = [];
  for (let i = 0; i < 4; i++) out.push("0x" + ((v >> (120n * BigInt(i))) & mask).toString(16));
  return out;
}
const line = (name: string, v: bigint) =>
  `${name} = [${limbs(v).map((l) => `"${l}"`).join(", ")}]`;

type Case = "valid" | "single-signer" | "invalid-sig" | "wrong-pubkey";

export function proverToml(kase: Case): string {
  const preimage = settlementPreimage();
  const msgG2 = blsSigs.hash(preimage, DST_SIG);

  const makerSk = skFromLabel("proofbridge.auth.maker.sk");
  const bridgerSk = skFromLabel("proofbridge.auth.bridger.sk");
  const makerPk = blsSigs.getPublicKey(makerSk);
  const bridgerPk = blsSigs.getPublicKey(bridgerSk);

  let pkAgg = blsSigs.aggregatePublicKeys([makerPk, bridgerPk]);
  let aggSig = blsSigs.aggregateSignatures([
    blsSigs.sign(msgG2, makerSk),
    blsSigs.sign(msgG2, bridgerSk),
  ]);

  if (kase === "single-signer") {
    // Degenerate but valid: one key fills both slots. pk_agg = 2*pk, agg = 2*sig,
    // and e(2*pk, H) == e(g1, 2*sig) still holds -> the circuit must accept it.
    pkAgg = blsSigs.aggregatePublicKeys([makerPk, makerPk]);
    aggSig = blsSigs.aggregateSignatures([
      blsSigs.sign(msgG2, makerSk),
      blsSigs.sign(msgG2, makerSk),
    ]);
  } else if (kase === "invalid-sig") {
    // Bridger signs a DIFFERENT message; the aggregate no longer matches msgG2
    // -> the pairing check must fail (witness unsatisfiable).
    const wrong = blsSigs.hash(concat(preimage, utf8("x")), DST_SIG);
    aggSig = blsSigs.aggregateSignatures([
      blsSigs.sign(msgG2, makerSk),
      blsSigs.sign(wrong, bridgerSk),
    ]);
  } else if (kase === "wrong-pubkey") {
    // Aggregate signature is correct, but pk_agg is a different key -> fail.
    pkAgg = blsSigs.aggregatePublicKeys([makerPk, blsSigs.getPublicKey(skFromLabel("attacker.sk"))]);
  }

  // Self-check the positive cases so the generator never emits a bad "valid" fixture.
  const shouldVerify = kase === "valid" || kase === "single-signer";
  const verifies = blsSigs.verify(aggSig, msgG2, pkAgg);
  if (shouldVerify && !verifies) throw new Error(`case ${kase}: expected verify, got reject`);
  if (!shouldVerify && verifies) throw new Error(`case ${kase}: expected reject, got verify`);

  const pk = pkAgg.toAffine();
  const sig = aggSig.toAffine();
  const msg = msgG2.toAffine();

  return [
    `# auth_circuit fixture: ${kase} (expect ${shouldVerify ? "PASS" : "FAIL"})`,
    line("pk_agg_x", pk.x),
    line("pk_agg_y", pk.y),
    line("msg_x_c0", msg.x.c0),
    line("msg_x_c1", msg.x.c1),
    line("msg_y_c0", msg.y.c0),
    line("msg_y_c1", msg.y.c1),
    line("sig_x_c0", sig.x.c0),
    line("sig_x_c1", sig.x.c1),
    line("sig_y_c0", sig.y.c0),
    line("sig_y_c1", sig.y.c1),
  ].join("\n");
}

const kase = (process.argv[2] ?? "valid") as Case;
const valid: Case[] = ["valid", "single-signer", "invalid-sig", "wrong-pubkey"];
if (!valid.includes(kase)) {
  console.error(`unknown case '${kase}'. one of: ${valid.join(", ")}`);
  process.exit(1);
}
console.log(proverToml(kase));
