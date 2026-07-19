use bls12_381::{Fp2, G1Affine, G2Affine, verify_bls_signature};

// Verifies the aggregated maker+bridger BLS signature over the SettlementAuth
// message. Minimal-pubkey-size: pk in G1, sig and msg in G2. pk_agg and msg
// (= hash_to_g2 of the SettlementAuth preimage) are aggregated/hashed off-circuit
// and bound by the consumer; agg_sig is not subgroup-checked here; the native
// BLS path that consumes the same points does that. See README.
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
