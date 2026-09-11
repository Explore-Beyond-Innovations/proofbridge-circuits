use poseidon::poseidon2;

global D: u32 = 32; // max path length (mountain height)
global P: u32 = 32; // max peaks

// keccak256("ProofBridge.MMR.v1") mod p - must match the contract + SDK constant.
global DOMAIN_TAG: Field = 0x1007fd40caf0e39d3ffbecd91e2d9469b3f2294a6794c372eb5406a496b6e4ec;

fn u32_shl(base: u32, amt: u32) -> u32 {
    base << (amt as u8)
}

// Proves `value` (= H(order_hash, side), built in main.nr) is a leaf of the MMR committed by the
// PUBLIC `target_root`.
pub fn verify_inclusion(
    value: Field,
    target_root: Field,
    leaf_index: u32, // hint: absolute MMR node index of the leaf
    width: u32, // hint: number of leaves
    path_len: u32, // hint: number of climb steps (leaf -> peak)
    siblings: [Field; D], // proof
    sib_is_left: [bool; D], // hint: at level i, is the sibling the left child?
    parent_index: [Field; D], // hint: absolute node index of the parent at level i
    peaks: [Field; P], // proof, high -> low height order
    peaks_len: u32, // hint
    chosen_peak: u32, // hint: index into `peaks` of the leaf's mountain
) {
    assert(width > 0u32); // non-empty tree
    assert(width < 0x80000000u32); // guard the `width * 2` u32 overflow below

    // popcount(width) = true peak count, plus the chosen peak's node-index + height, from `width`.
    let mut num_peaks = 0u32;
    let mut chosen_idx = 0u32;
    let mut chosen_ht = 0u32;
    let mut accum = 0u32;
    let mut max_h = 1u32;
    for i in 1..32 {
        if u32_shl(1u32, i) <= width {
            max_h = i + 1u32;
        }
    }
    for off in 0..32 {
        if off < max_h {
            let h = max_h - off; // heights high -> low
            let mask = u32_shl(1u32, h - 1u32);
            if (width & mask) != 0u32 {
                accum = accum + u32_shl(1u32, h) - 1u32; // running node index of this peak
                if num_peaks == chosen_peak {
                    chosen_idx = accum;
                    chosen_ht = h;
                }
                num_peaks += 1u32;
            }
        }
    }

    assert(peaks_len == num_peaks); // peak-count validation (anti-malleability)
    let size = (width * 2u32) - num_peaks; // derived, never trusted; bound into the root below

    assert(path_len <= D); // array bound
    assert(chosen_peak < peaks_len); // chosen peak must be a real, in-range peak
    assert(leaf_index >= 1u32); // leaves are 1-indexed
    assert(leaf_index <= size); // reject out-of-range leaves
    assert(path_len + 1u32 == chosen_ht); // path length must equal the chosen peak's height
    assert(leaf_index <= chosen_idx); // leaf must fall within the chosen mountain

    // Climb leaf -> peak. Leaf = H(leaf_index, value) and branch = H(parent_index, l, r): binding the
    // index into every hash pins each node to its position and separates leaves from internal nodes.
    let mut node = poseidon2::Poseidon2::hash([leaf_index as Field, value], 2);
    for i in 0..D {
        if i < path_len {
            let p = parent_index[i];
            let (l, r) = if sib_is_left[i] {
                (siblings[i], node)
            } else {
                (node, siblings[i])
            };
            node = poseidon2::Poseidon2::hash([p, l, r], 3);
        }
    }
    assert(node == peaks[chosen_peak]); // the climbed value must be one of the supplied peaks

    // Single size-bind + domain bagging. Fold the peaks (seeded by the first peak, not size), then
    // bind size + DOMAIN_TAG once. Matching the public target_root forces (width, peaks) to equal the
    // real tree by collision resistance and scopes the proof to this protocol/version.
    let mut acc: Field = peaks[0];
    for i in 1..P {
        if i < peaks_len {
            acc = poseidon2::Poseidon2::hash([acc, peaks[i]], 2);
        }
    }
    assert(poseidon2::Poseidon2::hash([DOMAIN_TAG, size as Field, acc], 3) == target_root);
}
