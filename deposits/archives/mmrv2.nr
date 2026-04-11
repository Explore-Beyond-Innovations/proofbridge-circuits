use poseidon::poseidon2;

pub fn verify_proof(
    index: Field,
    order_hash: Field,
    sibling_hashes_len: Field,
    sibling_hashes: [Field; 20],
    peaks_hashes_len: Field,
    peak_hashes: [Field; 20],
    tree_width: Field,
    root: Field,
) -> bool {
    let width = tree_width as u32;
    let idx = index as u32;

    // Calculate size from width
    let size = get_size(width);
    assert(idx <= size, "Index out of range");

    // Verify root matches peak bagging
    let computed_root = peak_bagging(width, peak_hashes, peaks_hashes_len as u32);
    assert(computed_root == root, "Root mismatch from peaks");

    // Get peak indexes
    let (peak_indexes, num_peaks) = get_peak_indexes(width);
    assert(num_peaks == peaks_hashes_len as u32, "Peak count mismatch");

    // Find target peak containing index (max 32 peaks)
    let mut cursor = 0;
    let mut target_peak: Field = 0;
    for i in 0..32 {
        if i < num_peaks {
            if peak_indexes[i] >= idx {
                if cursor == 0 {
                    target_peak = peak_hashes[i];
                    cursor = peak_indexes[i];
                }
            }
        }
    }
    assert(cursor != 0, "Index not found in any peak");

    // Build path from peak to index (max 20 steps for siblings)
    let path = build_path_to_index(cursor, idx, sibling_hashes_len as u32);

    // Reconstruct node from leaf to peak
    let mut h = 0;
    let reconstructed = reconstruct_peak(
        path,
        sibling_hashes_len as u32,
        idx,
        order_hash,
        sibling_hashes,
        h,
    );

    assert(reconstructed == target_peak, "Reconstructed peak mismatch");
    true
}

// Calculate size from width: (width << 1) - numOfPeaks(width)
fn get_size(width: u32) -> u32 {
    let num_peaks = count_set_bits(width);
    (width << 1) - num_peaks
}

// Count number of set bits (Kernighan's algorithm)
fn count_set_bits(mut n: u32) -> u32 {
    let mut count = 0;
    for _i in 0..32 {
        if n != 0 {
            n = n & (n - 1);
            count += 1;
        }
    }
    count
}

// Get peak indexes for a given width (max 32 peaks)
fn get_peak_indexes(width: u32) -> ([u32; 32], u32) {
    let n = count_set_bits(width);
    let mut result: [u32; 32] = [0; 32];
    let mut count = 0;
    let mut size = 0;

    // Find highest bit position
    let mut max_h: u32 = 1;
    for i in 1..32 {
        let shift_i = i as u8;
        if (1 << shift_i) <= width {
            max_h = i + 1;
        }
    }

    // Build peak indexes from high to low
    for h in 0..32 {
        if h < max_h {
            if max_h > 0 {
                let height = max_h - h;
                if height > 0 {
                    let shift_amt = (height - 1) as u8;
                    let mask = 1 << shift_amt;
                    if (width & mask) != 0 {
                        let height_u8 = height as u8;
                        size += (1 << height_u8) - 1;
                        result[count] = size;
                        count += 1;
                    }
                }
            }
        }
    }

    (result, n)
}

// Peak bagging algorithm matching MMR.ts
// inner = hash(hash(...hash(size, peak1), peak2)...)
// outer = hash(size, inner)
fn peak_bagging(width: u32, peaks: [Field; 20], peaks_len: u32) -> Field {
    let mut result: Field = 0;

    let is_empty = if width == 0 { peaks_len == 0 } else { false };

    if is_empty {
        result = 0;
    } else {
        let size = get_size(width);
        assert(count_set_bits(width) == peaks_len, "Invalid number of peaks");

        // Accumulate: hash(hash(...hash(size, peak1), peak2)...)
        let mut acc = size as Field;
        for i in 0..20 {
            if i < peaks_len {
                acc = poseidon2::Poseidon2::hash([acc, peaks[i]], 2);
            }
        }

        // Final: hash(size, acc)
        result = poseidon2::Poseidon2::hash([size as Field, acc], 2);
    }

    result
}

// Build path from cursor (peak) down to target index (max 20 steps)
fn build_path_to_index(mut cursor: u32, index: u32, siblings_len: u32) -> [u32; 21] {
    let mut path: [u32; 21] = [0; 21];
    let mut h = siblings_len + 1;

    for _i in 0..21 {
        if h > 0 {
            if cursor >= index {
                h -= 1;
                path[h] = cursor;
                if cursor == index {
                    // Found the index, stop
                } else {
                    let (left, right) = get_children(cursor);
                    cursor = if index <= left { left } else { right };
                }
            }
        }
    }

    path
}

// Get children of a node at given index
fn get_children(index: u32) -> (u32, u32) {
    let height = height_at(index);
    let shift_amt = if height > 0 { (height - 1) as u8 } else { 0 };
    let left = index - (1 << shift_amt);
    let right = index - 1;
    (left, right)
}

// Calculate height at a given index
fn height_at(index: u32) -> u32 {
    let mut reduced = index;
    let mut peak_index = 0;
    let mut h: u32 = 0;

    // Max 32 iterations for safety
    for _i in 0..32 {
        if reduced > peak_index {
            if h > 0 {
                let h_u8 = h as u8;
                reduced -= (1 << h_u8) - 1;
            }
            h = mountain_height(reduced);
            if h > 0 {
                let h_u8 = h as u8;
                peak_index = (1 << h_u8) - 1;
            } else {
                peak_index = 0;
            }
        }
    }

    if peak_index >= reduced {
        h - (peak_index - reduced)
    } else {
        h
    }
}

// Calculate mountain height for a given size
fn mountain_height(size: u32) -> u32 {
    let mut h: u32 = 1;
    for i in 1..32 {
        let i_u8 = i as u8;
        if (1 << i_u8) <= size + i {
            h = i + 1;
        }
    }
    if h > 0 {
        h - 1
    } else {
        0
    }
}

// Reconstruct peak from leaf using siblings
fn reconstruct_peak(
    path: [u32; 21],
    path_len: u32,
    index: u32,
    value_hash: Field,
    siblings: [Field; 20],
    start_h: u32,
) -> Field {
    let mut node: Field = 0;
    let mut h = start_h;

    // Find where index appears in path
    let mut found_at = 0;
    for i in 0..21 {
        if path[i] == index {
            found_at = i;
        }
    }

    // Reconstruct from bottom to top
    for i in 0..21 {
        if i <= path_len {
            if i >= found_at {
                if path[i] != 0 {
                    let cursor = path[i];
                    if i == found_at {
                        // Hash leaf: hash([index, dataHash])
                        node = hash_leaf(cursor, value_hash);
                    } else if i > found_at {
                        let sibling_idx = i - found_at - 1;
                        if sibling_idx < 20 {
                            // Determine if previous node was right child
                            let prev_cursor = path[i - 1];
                            let is_right = cursor - 1 == prev_cursor;

                            if is_right {
                                // Previous was right child, so sibling is left
                                node = hash_branch(cursor, siblings[sibling_idx], node);
                            } else {
                                // Previous was left child, so sibling is right
                                node = hash_branch(cursor, node, siblings[sibling_idx]);
                            }
                        }
                    }
                    h += 1;
                }
            }
        }
    }

    node
}

// Hash a leaf node: hash([index, dataHash])
fn hash_leaf(index: u32, data_hash: Field) -> Field {
    poseidon2::Poseidon2::hash([index as Field, data_hash], 2)
}

// Hash a branch node: hash([index, left, right])
fn hash_branch(index: u32, left: Field, right: Field) -> Field {
    poseidon2::Poseidon2::hash([index as Field, left, right], 3)
}
