use poseidon::poseidon2;

mod utils;
mod mmr;

fn main(
    nullifier_hash: pub Field,
    order_hash: pub Field,
    target_root: pub Field, // authenticate the root of the MMR with our service
    ad_contract: pub bool,
    secret: Field,
    target_index: Field,
    tree_width: Field,
    target_sibling_hashes_len: Field,
    target_sibling_hashes: [Field; 20],
    target_peak_hashes_len: Field,
    target_peak_hashes: [Field; 20],
) {
    let (a, b) = utils::split_secret(secret);

    if ad_contract {
        // hash left side of secret with orderhash and check against the nullifier
        let expected_nullifier_hash = poseidon2::Poseidon2::hash([a, order_hash], 2);
        assert(expected_nullifier_hash == nullifier_hash);
    } else {
        // hash right side of secret with orderhash and check against the nullifier
        let expected_nullifier_hash = poseidon2::Poseidon2::hash([order_hash, b], 2);
        assert(expected_nullifier_hash == nullifier_hash);
    }

    let valid_target = mmr::verify_proof(
        target_index,
        order_hash,
        target_sibling_hashes_len,
        target_sibling_hashes,
        target_peak_hashes_len,
        target_peak_hashes,
        tree_width,
        target_root,
    );

    assert(valid_target);
}
