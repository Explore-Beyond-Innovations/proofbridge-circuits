pub fn split_uncompressed_pub_key(pub_key: [u8; 65]) -> ([u8; 32], [u8; 32]) {
    let mut pub_key_x: [u8; 32] = [0; 32];
    let mut pub_key_y: [u8; 32] = [0; 32];

    for i in 0..32 {
        pub_key_x[i] = pub_key[i + 1];
        pub_key_y[i] = pub_key[i + 32 + 1];
    }

    (pub_key_x, pub_key_y)
}
