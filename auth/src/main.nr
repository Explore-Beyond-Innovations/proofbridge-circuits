use dep::ecrecover;
use dep::poseidon::poseidon2;

mod utils;
// mod bls;

fn main(
    nullifier_hash: pub Field,
    ad_creator: pub Field,
    bridger: pub Field,
    ad_contract: pub bool,
    msg_hash: pub [u8; 32],
    ad_creator_pub_key: [u8; 65],
    ad_creator_sig: [u8; 64],
    bridger_pub_key: [u8; 65],
    bridger_sig: [u8; 64],
) {
    // convert signatures into a field
    let sig_field: Field = if (ad_contract) {
        Field::from_be_bytes(bridger_sig)
    } else {
        Field::from_be_bytes(ad_creator_sig)
    };

    // check that the nullifier hash matches
    let expected_nullifier_hash = poseidon2::Poseidon2::hash([sig_field], 1);
    assert_eq(expected_nullifier_hash, nullifier_hash);

    // Verify ad_creator signature
    let (ad_creator_x, ad_creator_y) = utils::split_uncompressed_pub_key(ad_creator_pub_key);
    let expected_ad_creator =
        ecrecover::ecrecover(ad_creator_x, ad_creator_y, ad_creator_sig, msg_hash);
    assert_eq(ad_creator, expected_ad_creator);

    // Verify bridger signature
    let (bridger_x, bridger_y) = utils::split_uncompressed_pub_key(bridger_pub_key);
    let expected_bridger = ecrecover::ecrecover(bridger_x, bridger_y, bridger_sig, msg_hash);
    assert_eq(bridger, expected_bridger);
}
