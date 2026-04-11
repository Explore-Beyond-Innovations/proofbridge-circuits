use poseidon::poseidon2;

fn u32_shl(base: u32, amt: u32) -> u32 {
    let shift_amt: u8 = amt as u8;
    base << shift_amt
}

// ----------------------------------------------------
// Public verifier entrypoint
// ----------------------------------------------------

pub fn verify_proof(
    index: Field, // global MMR node index (1-indexed)
    value_hash: Field, // Poseidon2-field-modded leaf hash (what TS calls `valueHash` AFTER fieldMod)
    sibling_hashes_len: Field, // siblings.length
    sibling_hashes: [Field; 20], // siblings bottom -> up
    peaks_hashes_len: Field, // peaks.length
    peak_hashes: [Field; 20], // peak hashes, same order as getPeakIndexes(width)
    tree_width: Field, // width
    root: Field, // claimed MMR root
) -> bool {
    let width: u32 = tree_width as u32;
    let idx: u32 = index as u32;
    let sib_len: u32 = sibling_hashes_len as u32;
    let peaks_len: u32 = peaks_hashes_len as u32;

    // sanity checks
    assert(width > 0u32);
    assert(sib_len <= 20u32);
    assert(peaks_len <= 20u32);

    // Cache popcount(width) since it's used multiple times
    let num_peaks: u32 = count_set_bits(width);

    // size must match getSize(width)
    let size_calc: u32 = get_size_cached(width, num_peaks);

    // index must be within range
    assert(idx <= size_calc);

    // recompute root from peaks
    let computed_root: Field =
        peak_bagging_cached(width, size_calc, peak_hashes, peaks_len, num_peaks);

    // require provided `root` matches computed root
    assert(computed_root == root);

    // recompute peak indexes
    let peak_indexes: [u32; 32] = get_peak_indexes_cached(width);

    // must line up with caller's provided peak list length
    assert(num_peaks == peaks_len);

    // get first peak index >= idx
    let (chosen_peak_index, chosen_peak_hash) =
        choose_peak(idx, peak_indexes, num_peaks, peak_hashes);

    // safety: must have found a real peak
    assert(chosen_peak_index != 0u32);

    // build downward path from chosen_peak_index to idx
    let path: [u32; 21] = build_path_to_index(chosen_peak_index, idx, sib_len);

    let reconstructed_peak: Field =
        reconstruct_peak(path, sib_len, idx, value_hash, sibling_hashes);

    // final check: reconstructed peak must match chosen peak hash
    assert(reconstructed_peak == chosen_peak_hash);

    true
}

// ----------------------------------------------------
// Core helpers
// ----------------------------------------------------

// Cached version that reuses precomputed popcount
fn get_size_cached(width: u32, num_peaks: u32) -> u32 {
    (width * 2u32) - num_peaks
}

// count set bits (Kernighan) - optimized
fn count_set_bits(mut n: u32) -> u32 {
    let mut count = 0u32;

    for _i in 0..32 {
        if n != 0u32 {
            let n_minus_1 = n - 1u32;
            n = n & n_minus_1;
            count = count + 1u32;
        }
    }

    count
}

fn get_peak_indexes_cached(width: u32) -> [u32; 32] {
    let mut result: [u32; 32] = [0u32; 32];
    let mut count = 0u32;
    let mut accum_size = 0u32;

    // compute maxH
    let mut max_h = 1u32;
    for i in 1..32 {
        let one_shift_i: u32 = u32_shl(1u32, i);
        if one_shift_i <= width {
            max_h = i + 1u32;
        }
    }

    // emulate "for (h = maxH; h > 0; h--)" in a fixed loop
    for off in 0..32 {
        if off < max_h {
            let height_val = max_h - off;

            if height_val > 0u32 {
                let hm1 = height_val - 1u32;
                let mask: u32 = u32_shl(1u32, hm1);

                if (width & mask) != 0u32 {
                    let one_shift_h = u32_shl(1u32, height_val);
                    let subtree_nodes = one_shift_h - 1u32;
                    accum_size = accum_size + subtree_nodes;
                    result[count] = accum_size;
                    count = count + 1u32;
                }
            }
        }
    }

    result
}

fn peak_bagging_cached(
    width: u32,
    size_val: u32,
    peaks: [Field; 20],
    peaks_len: u32,
    expected_len: u32,
) -> Field {
    // special empty case
    let empty_case: bool = (width == 0u32) & (peaks_len == 0u32);
    let empty_case_f: Field = if empty_case { 1 } else { 0 };

    // acc starts as size (as a Field)
    let mut acc: Field = size_val as Field;

    // we also assert #peaks matches popcount(width), same as TS does logically
    assert(expected_len == peaks_len);

    // fold peaks
    for i in 0..20 {
        let use_this: bool = i < peaks_len;
        let use_this_f: Field = if use_this { 1 } else { 0 };

        let hashed = poseidon2::Poseidon2::hash([acc, peaks[i]], 2);

        // acc = use_this ? hashed : acc
        acc = acc * (1 - use_this_f) + hashed * use_this_f;
    }

    // final outer bind with size
    let final_hash = poseidon2::Poseidon2::hash([size_val as Field, acc], 2);

    // if (width==0 && peaks_len==0) => 0, else final_hash
    let zero_val: Field = 0;
    let out_val: Field = zero_val * empty_case_f + final_hash * (1 - empty_case_f);

    out_val
}

fn choose_peak(
    idx: u32,
    peak_indexes: [u32; 32],
    num_peaks: u32,
    peak_hashes: [Field; 20],
) -> (u32, Field) {
    let mut chosen_idx: u32 = 0u32;
    let mut chosen_hash: Field = 0;
    let mut found: bool = false;

    // Iterate through peaks to find first one covering idx
    for i in 0..32 {
        if (i < num_peaks) & (!found) {
            let pi: u32 = peak_indexes[i];

            // This peak covers idx
            if pi >= idx {
                chosen_idx = pi;
                chosen_hash = peak_hashes[i];
                found = true;
            }
        }
    }

    (chosen_idx, chosen_hash)
}

fn build_path_to_index(start_cursor: u32, leaf_index: u32, siblings_len: u32) -> [u32; 21] {
    let mut path: [u32; 21] = [0u32; 21];

    let mut h_val: u32 = siblings_len + 1u32;
    let mut cursor: u32 = start_cursor;
    let mut done: bool = false;

    for _step in 0..21 {
        if h_val > 0u32 {
            h_val = h_val - 1u32;
            path[h_val] = cursor;

            if cursor == leaf_index {
                done = true;
            }

            if !done {
                let (left_c, right_c) = get_children(cursor);
                cursor = if leaf_index <= left_c {
                    left_c
                } else {
                    right_c
                };
            }
        }
    }

    path
}

fn get_children(node_index: u32) -> (u32, u32) {
    let h: u32 = height_at(node_index);
    let hm1: u32 = if h > 0u32 { h - 1u32 } else { 0u32 };
    let offset: u32 = u32_shl(1u32, hm1);

    (node_index - offset, node_index - 1u32)
}

fn height_at(index: u32) -> u32 {
    let mut reduced = index;
    let mut peak_idx = 0u32;
    let mut h_val = 0u32;

    for _i in 0..32 {
        if reduced > peak_idx {
            let one_shift_h = u32_shl(1u32, h_val);
            let sub_amt = if h_val > 0u32 {
                one_shift_h - 1u32
            } else {
                0u32
            };

            reduced = if reduced >= sub_amt {
                reduced - sub_amt
            } else {
                0u32
            };

            h_val = mountain_height(reduced);

            let one_shift_hv = u32_shl(1u32, h_val);
            peak_idx = if one_shift_hv > 0u32 {
                one_shift_hv - 1u32
            } else {
                0u32
            };
        }
    }

    // slope correction
    if peak_idx >= reduced {
        let diff = peak_idx - reduced;
        if h_val >= diff {
            h_val - diff
        } else {
            0u32
        }
    } else {
        h_val
    }
}

fn mountain_height(size: u32) -> u32 {
    let mut h_val = 1u32;

    for i in 1..32 {
        let lhs = u32_shl(1u32, i);
        let rhs = size + i;
        if lhs <= rhs {
            h_val = i + 1u32;
        }
    }

    // return h_val - 1 if h_val>0 else 0
    if h_val > 0u32 {
        h_val - 1u32
    } else {
        0u32
    }
}
fn reconstruct_peak(
    path: [u32; 21],
    siblings_len: u32,
    leaf_index: u32,
    value_hash: Field,
    siblings: [Field; 20],
) -> Field {
    // 1. find leaf_pos = index of leaf_index in path
    let mut leaf_pos: u32 = 0u32;
    let mut already_found: bool = false;

    for i in 0..21 {
        let match_leaf: bool = path[i] == leaf_index;
        let take_it: bool = match_leaf & (!already_found);
        let take_it_u32: u32 = if take_it { 1u32 } else { 0u32 };

        leaf_pos = leaf_pos * (1u32 - take_it_u32) + (i as u32) * take_it_u32;

        // once we've picked first match, lock it
        let new_found: bool = if take_it { true } else { already_found };
        already_found = new_found;
    }

    // 2. node = hashLeaf(leaf_index, value_hash)
    let mut node: Field = hash_leaf(leaf_index, value_hash);

    // 3. climb steps 1..siblings_len, mixing in siblings
    for step in 1..21 {
        let step_u32: u32 = step as u32;

        // only meaningful if step_u32 <= siblings_len
        let active: bool = step_u32 <= siblings_len;

        // cur_pos = leaf_pos + step_u32
        let cur_pos: u32 = leaf_pos + step_u32;

        // Direct array access instead of selector loop
        let parent_idx: u32 = path[cur_pos];

        // prev_idx = path[cur_pos - 1]
        let prev_pos: u32 = if cur_pos > 0u32 { cur_pos - 1u32 } else { 0u32 };
        let prev_idx: u32 = path[prev_pos];

        // sibling index = step_u32 - 1
        let sib_i: u32 = if step_u32 > 0u32 {
            step_u32 - 1u32
        } else {
            0u32
        };
        // Direct array access instead of selector loop
        let sib_val: Field = siblings[sib_i];

        // prev_was_right = (parent_idx - 1 == prev_idx)
        let parent_minus_1 = if parent_idx > 0u32 {
            parent_idx - 1u32
        } else {
            0u32
        };
        let prev_was_right: bool = parent_minus_1 == prev_idx;
        let prev_was_right_f: Field = if prev_was_right { 1 } else { 0 };
        let not_right_f: Field = 1 - prev_was_right_f;

        // candidate_right = hash_branch(parent_idx, sib_val, node)
        let candidate_right: Field = hash_branch(parent_idx, sib_val, node);

        // candidate_left  = hash_branch(parent_idx, node, sib_val)
        let candidate_left: Field = hash_branch(parent_idx, node, sib_val);

        let merged_node: Field = candidate_right * prev_was_right_f + candidate_left * not_right_f;

        // Only update node if active and parent_idx is valid
        let parent_zero: bool = parent_idx == 0u32;
        let should_update: bool = active & (!parent_zero);

        if should_update {
            node = merged_node;
        }
    }

    node
}

fn hash_leaf(index_val: u32, data_hash: Field) -> Field {
    poseidon2::Poseidon2::hash([index_val as Field, data_hash], 2)
}

fn hash_branch(parent_index: u32, left: Field, right: Field) -> Field {
    poseidon2::Poseidon2::hash([parent_index as Field, left, right], 3)
}
