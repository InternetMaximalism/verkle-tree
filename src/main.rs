use franklin_crypto::bellman::bn256::G1Affine;
use verkle_tree::bn256_verkle_tree::proof::VerkleProof;
use verkle_tree::bn256_verkle_tree::VerkleTreeWith32BytesKeyValue;
use verkle_tree::ipa_fr::config::IpaConfig;

fn sample_code() {
    let committer = IpaConfig::new(256);
    let mut tree = VerkleTreeWith32BytesKeyValue::new(committer.clone());

    let key = [1u8; 32];
    let value = [255u8; 32];
    let old_value: Option<[u8; 32]> = VerkleTreeWith32BytesKeyValue::insert(&mut tree, key, value);
    println!("old_value: {:?}", old_value);

    let stored_value: Option<&[u8; 32]> = VerkleTreeWith32BytesKeyValue::get(&tree, &key);
    println!("stored_value: {:?}", stored_value);

    let commitment: G1Affine =
        VerkleTreeWith32BytesKeyValue::compute_commitment(&mut tree).unwrap();
    println!("commitment: {:?}", commitment);

    let keys = [key];
    let (proof, elements) = VerkleProof::create(&mut tree, &keys).unwrap();
    println!("proof: {:?}", proof);
    println!("elements.zs: {:?}", elements.zs);
    println!("elements.ys: {:?}", elements.ys);

    let is_valid: bool =
        VerkleProof::check(&proof, &elements.zs, &elements.ys, &committer).unwrap();
    println!("is_valid: {:?}", is_valid);

    let old_value: Option<[u8; 32]> = VerkleTreeWith32BytesKeyValue::remove(&mut tree, &key);
    println!("old_value: {:?}", old_value);
}

fn main() {
    sample_code();
}
