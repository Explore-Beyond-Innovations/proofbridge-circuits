use poseidon::poseidon2;

mod utils;
mod mmr;

// Proves the leaf poseidon2(order_hash, leaf_domain) is in MMR(target_root).
// Public inputs: [nullifier_hash, order_hash, target_root, leaf_domain], always written by the contract.
// Domains 0/1 are deposits (the side the leaf is unlocked on: 1 = ad, 0 = order) and prove the
// nullifier preimage; 2+ are event claims (cancel, settled, registered): no secret, nullifier = 0.
fn main(
    nullifier_hash: pub Field,
    order_hash: pub Field,
    target_root: pub Field, // authenticated upstream by the root registry
    leaf_domain: pub Field,
    secret: Field,
    leaf_index: u32,
    width: u32,
    path_len: u32,
    siblings: [Field; 32],
    sib_is_left: [bool; 32],
    parent_index: [Field; 32],
    peaks: [Field; 32],
    peaks_len: u32,
    chosen_peak: u32,
) {
    // --- nullifier: deposits prove one half of the split secret; events carry none ---
    let (a, b) = utils::split_secret(secret);
    if leaf_domain == 1 {
        assert(poseidon2::Poseidon2::hash([a, order_hash], 2) == nullifier_hash);
    } else if leaf_domain == 0 {
        assert(poseidon2::Poseidon2::hash([order_hash, b], 2) == nullifier_hash);
    } else {
        assert(nullifier_hash == 0, "event claims carry no nullifier");
    }

    // --- leaf-domain binding (closes X-1): must match appendOrderHash(orderHash, domain) ---
    let value = poseidon2::Poseidon2::hash([order_hash, leaf_domain], 2);

    // --- inclusion: value is in the MMR committed by target_root (hash-only, hint-driven) ---
    mmr::verify_inclusion(
        value,
        target_root,
        leaf_index,
        width,
        path_len,
        siblings,
        sib_is_left,
        parent_index,
        peaks,
        peaks_len,
        chosen_peak,
    );
}
