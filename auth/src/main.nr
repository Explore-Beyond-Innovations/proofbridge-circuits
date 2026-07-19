use bls12_381::{Fp2, G1Affine, G2Affine, verify_bls_signature};

// ProofBridge auth circuit (issue #157 / #163).
//
// Proves that the aggregated maker + bridger BLS12-381 signature is valid over
// the root-bound SettlementAuth message, i.e. that both counterparties consented
// to this settlement (order_hash + order_chain_root + ad_chain_root are all bound
// through the message point). Minimal-pubkey-size suite: pubkeys in G1, signature
// and hashed message in G2. verify_bls_signature checks
//   e(-g1, agg_sig) * e(pk_agg, H(m)) == 1
// as one shared Miller loop + one final exponentiation.
//
// Public inputs:
//   pk_agg  = pk_maker + pk_bridger, the aggregated G1 public key. The consumer
//             binds it to the two registry-committed keys (keccak256(pk) == keyOf).
//   msg     = H(m) = hash_to_g2(SettlementAuth preimage, DST_SIG), the hashed
//             settlement message in G2. The preimage is
//             SETTLE_TAG || orderChainId || adChainId || orderHash || orderChainRoot ||
//             adChainRoot (192 bytes); binding msg to those roots is the whole
//             point of the proof, so msg is public.
// Private input:
//   agg_sig = the aggregated G2 signature.
//
// Scope notes (see README): hash-to-curve and G1 key aggregation are done
// off-circuit (matching the native on-chain CounterpartyVerifier path), and this
// circuit does NOT subgroup-check agg_sig. Those checks are provided natively by
// the EIP-2537 / Soroban BLS operations that consume the same published points.
// A future "replace the native pairing" use would add an in-circuit G2 subgroup
// check on agg_sig.
fn main(
    pk_agg_x: pub [u128; 4],
    pk_agg_y: pub [u128; 4],
    msg_x_c0: pub [u128; 4],
    msg_x_c1: pub [u128; 4],
    msg_y_c0: pub [u128; 4],
    msg_y_c1: pub [u128; 4],
    sig_x_c0: [u128; 4],
    sig_x_c1: [u128; 4],
    sig_y_c0: [u128; 4],
    sig_y_c1: [u128; 4],
) {
    let pk_agg = G1Affine::new(pk_agg_x, pk_agg_y);
    let msg = G2Affine::new(Fp2::new(msg_x_c0, msg_x_c1), Fp2::new(msg_y_c0, msg_y_c1));
    let agg_sig = G2Affine::new(Fp2::new(sig_x_c0, sig_x_c1), Fp2::new(sig_y_c0, sig_y_c1));

    verify_bls_signature(agg_sig, pk_agg, msg);
}
