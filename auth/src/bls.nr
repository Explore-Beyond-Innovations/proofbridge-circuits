// use noir_bls12_381_pairing::pairings;
// /// BLS12-381 signature verification:
// /// - Public key in G2
// /// - Signature in G1
// /// - Message hash in G1
// /// Verifies: e(sig, G2) == e(H(m), pk)

// pub fn verify_bls_signature(
//     signature: pairings::G1Affine,
//     public_key: pairings::G2Affine,
//     message_hash: pairings::G1Affine,
// ) {
//     let g2 = pairings::G2Affine::generator();
//     let lhs = pairings::pairing(signature, g2);
//     let rhs = pairings::pairing(message_hash, public_key);
//     assert(lhs.eq(rhs));
// }

// // pub fn hash_to_g1(msg32: Field) -> pairings::G1Affine {
// //     // let s: Field = poseidon_to_scalar(msg32); // scalar in Fr
// //     let g1: pairings::G1Affine = pairings::G1Affine::generator();
// //     let hm: pairings::G1Affine = g1 * msg32; // scalar mul
// //     hm
// // }
