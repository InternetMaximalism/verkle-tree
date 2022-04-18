use verkle_tree::bn256_verkle_tree::proof::{EncodedVerkleProof, VerkleProof};
use verkle_tree::bn256_verkle_tree::VerkleTreeWith32BytesKeyValue;
use verkle_tree::ipa_fr::config::IpaConfig;

fn sample_code() -> Result<(), Box<dyn std::error::Error>> {
    let domain_size = 256; // = tree width
    let committer = IpaConfig::new(domain_size);

    // prover's view

    let mut tree = VerkleTreeWith32BytesKeyValue::new(committer.clone());

    let key = [1u8; 32];
    let value = [255u8; 32];
    let old_value: Option<[u8; 32]> = tree.insert(key, value);
    println!("old_value: {:?}", old_value);

    let stored_value: Option<&[u8; 32]> = tree.get(&key);
    println!("stored_value: {:?}", stored_value);

    let digest = tree.compute_digest()?;
    println!("digest: {:?}", digest);

    let keys = [key];
    let (proof, _) = VerkleProof::create(&mut tree, &keys)?;
    let encoded_proof = EncodedVerkleProof::encode(&proof);
    println!("encoded_proof: {:?}", encoded_proof);

    // verifier's view

    let (proof, zs, ys) = encoded_proof.decode(&committer)?;
    let is_valid: bool = proof.check(&zs, &ys, &committer)?;
    println!("is_valid: {:?}", is_valid);

    // // prover's view

    // let old_value: Option<[u8; 32]> = VerkleTreeWith32BytesKeyValue::remove(&mut tree, &key);
    // println!("old_value: {:?}", old_value);

    // let keys = [key];
    // let (proof, _) = VerkleProof::create(&mut tree, &keys)?;
    // let encoded_proof = EncodedVerkleProof::encode(&proof);
    // println!("encoded_proof: {:?}", encoded_proof);

    // // verifier's view

    // let (decoded_proof, zs, ys) = encoded_proof.decode()?;
    // let is_valid: bool = VerkleProof::check(&decoded_proof, &zs, &ys, &committer)?;
    // println!("is_valid: {:?}", is_valid);

    Ok(())
}

fn main() {
    sample_code().unwrap();
}
