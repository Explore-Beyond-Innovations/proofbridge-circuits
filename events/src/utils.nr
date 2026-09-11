pub fn split_secret(secret: Field) -> (Field, Field) {
    // Get bytes of the secret field
    let bytes: [u8; 32] = secret.to_be_bytes();

    let mut a_bytes = [0u8; 32];
    let mut b_bytes = [0u8; 32];

    // Fill first 16 bytes for a_bytes, rest remains zero
    for i in 0..16 {
        a_bytes[i] = bytes[i];
    }

    // Fill last 16 bytes for b_bytes, rest remains zero
    for i in 0..16 {
        b_bytes[i + 16] = bytes[i + 16];
    }

    // Convert back to field elements with full 32-byte arrays
    let a = Field::from_be_bytes(a_bytes);
    let b = Field::from_be_bytes(b_bytes);

    (a, b)
}
