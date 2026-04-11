use poseidon::poseidon2;

pub fn verify_proof(
    index: Field,
    order_hash: Field,
    sibling_hashes_len: Field,
    sibling_hashes: [Field; 20],
    peaks_hashes_len: Field,
    peak_hashes: [Field; 20],
    elements_count: Field,
    root: Field,
) -> bool {
    // Basic sanity checks on lengths and index
    assert((sibling_hashes_len as u32) <= 20);
    assert((peaks_hashes_len as u32) <= 20);
    assert((elements_count as u32) > 0u32);
    assert((index as u32) <= (elements_count as u32));

    // Recompute the MMR *root commitment* from peaks and elements_count
    let root_hash = compute_root(peaks_hashes_len, peak_hashes, elements_count);

    // computed root must match expected `root`
    assert(root_hash == root);

    // compute the top peak containing `order_hash`
    let top_peak = get_proof_top_peak(
        0, // initial height
        order_hash, // strarting leaf hash
        index as u128, // mmr_index
        sibling_hashes,
        sibling_hashes_len as u32,
    );

    // Valid if the computed peak exists among the provided peaks (bagged later)
    array_contains(top_peak, peak_hashes, peaks_hashes_len as u32)
}

pub fn compute_root(peaks_len: Field, peaks: [Field; 20], elements_count: Field) -> Field {
    // Combine all peaks into a single hash
    let bagged_peaks = bag_peaks(peaks, peaks_len as u32);

    // Final root is hash of (elements_count || bagged_peaks)
    poseidon2::Poseidon2::hash([elements_count, bagged_peaks], 2)
}

pub fn bag_peaks<let N: u32>(peaks: [Field; N], count: u32) -> Field {
    assert(count >= 1);
    assert(count <= N);

    if count == 1 {
        peaks[0]
    } else {
        // Start by hashing rightmost two peaks
        let mut bags: Field =
            poseidon::poseidon2::Poseidon2::hash([peaks[count - 2], peaks[count - 1]], 2);

        // For more than 2 peaks, fold remaining peaks from right to left
        if count > 2 {
            for i in 0..peaks.len() {
                if i < count - 2 {
                    let idx = count - 3 - i;
                    // Hash current peak with accumulated value
                    bags = poseidon::poseidon2::Poseidon2::hash([peaks[idx], bags], 2);
                }
            }
        }

        bags
    }
}

fn bit_length(n: u128) -> u32 {
    let mut len: u32 = 0u32;
    for i in 0..128 {
        if ((n >> i) & 1u128) == 1u128 {
            len = (i + 1) as u32;
        }
    }
    len
}

pub fn mmr_size_to_leaf_count(mmr_size: u128) -> u128 {
    let mut size: u128 = mmr_size;
    let mut leaf: u128 = 0u128;

    // Get highest set bit position
    let bl: u32 = bit_length(size);

    // Initial max leaf cluster size (2^(height-1))
    let mut mlc: u128 = if bl == 0u32 {
        1u128
    } else {
        1u128 << ((bl - 1u32) as u8)
    };

    // Process each bit position from left to right
    for i in 0..128 {
        if i < bl {
            // Check if current leaf cluster fits
            let fits: bool = mlc <= ((size + 1u128) / 2u128);

            if fits {
                leaf = leaf + mlc;
                // Remove nodes for this level (peak and perfect subtree)
                size = size - (2u128 * mlc - 1u128);
            }
            mlc = mlc >> 1;
        }
    }

    assert(size == 0u128);
    leaf
}

pub fn mmr_index_to_leaf_index(mmr_index: u128) -> u128 {
    assert(mmr_index > 0u128);
    mmr_size_to_leaf_count(mmr_index - 1u128)
}

pub fn get_proof_top_peak<let N: u32>(
    mut height: u32,
    mut hash: Field,
    mut mmr_index: u128,
    proof: [Field; N],
    proof_len: u32,
) -> Field {
    assert(proof_len <= N);

    // Convert element count to leaf index
    let mut leaf_index: u32 = mmr_index_to_leaf_index(mmr_index) as u32;

    // Calculate initial span (2^height)
    let mut span: u32 = 1u32 << (height as u8);

    // Process each level of the proof
    for i in 0..N {
        if i < proof_len {
            let sibling = proof[i];

            let is_right_child: u32 = leaf_index & 1u32;

            if is_right_child == 1u32 {
                hash = poseidon2::Poseidon2::hash([sibling, hash], 2);
                mmr_index = mmr_index + 1u128;
            } else {
                hash = poseidon2::Poseidon2::hash([hash, sibling], 2);
                mmr_index = mmr_index + (2u128 * span as u128);
            }

            // Move up one level in tree
            height = height + 1u32;
            leaf_index = leaf_index >> 1u8;
            span = span << 1u8;
        }
    }

    hash
}

pub fn array_contains<let N: u32>(elem: Field, arr: [Field; N], len: u32) -> bool {
    assert(len <= N);

    let mut found: Field = 0;
    for i in 0..N {
        if i < len {
            let is_eq: Field = if arr[i] == elem { 1 } else { 0 };
            found = found + is_eq - found * is_eq;
        }
    }
    found == 1
}
