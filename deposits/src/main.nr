use poseidon::poseidon2;

mod utils;
mod mmr;

// Deposit circuit: proves the nullifier preimage + that the order's leaf is in MMR(target_root).
// Public inputs match RequestAuth.buildPublicInputs: [nullifier_hash, order_hash, target_root, ad_contract].
// ad_contract is the side flag - the side the leaf is unlocked on (1 = ad, 0 = order), not the contract
// that appends it; it drives the nullifier branch and the leaf binding.
fn main(
    nullifier_hash: pub Field,
    order_hash: pub Field,
    target_root: pub Field, // authenticated upstream by the root registry
    ad_contract: pub bool,
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
    // --- nullifier: prove knowledge of one half of the split secret ---
    let (a, b) = utils::split_secret(secret);
    if ad_contract {
        assert(poseidon2::Poseidon2::hash([a, order_hash], 2) == nullifier_hash);
    } else {
        assert(poseidon2::Poseidon2::hash([order_hash, b], 2) == nullifier_hash);
    }

    // --- leaf-side binding (closes X-1): the leaf encodes the trade side ---
    // side = 1 (ad) / 0 (order); must match the contract's appendOrderHash(orderHash, sideFlag).
    let side: Field = ad_contract as Field;
    let value = poseidon2::Poseidon2::hash([order_hash, side], 2);

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
