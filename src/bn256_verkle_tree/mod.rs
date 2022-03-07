use franklin_crypto::bellman::bn256::G1Affine;

use crate::ipa_fr::config::IpaConfig;
use crate::verkle_tree::trie::VerkleTree;

use self::leaf::LeafNodeWith32BytesValue;

pub mod leaf;
pub mod path;
pub mod proof;

pub type VerkleTreeWith32BytesKeyValue =
    VerkleTree<[u8; 32], LeafNodeWith32BytesValue<G1Affine>, G1Affine, IpaConfig<G1Affine>>;

#[cfg(test)]
mod bn256_verkle_tree_tests {
    use std::fs::OpenOptions;
    use std::path::Path;

    use franklin_crypto::bellman::bn256::Fr;
    use franklin_crypto::bellman::Field;

    use crate::bn256_verkle_tree::proof::{
        EncodedCommitmentElements, EncodedEcPoint, EncodedVerkleProof, VerkleProof,
    };
    use crate::ipa_fr::config::IpaConfig;
    use crate::verkle_tree::trie::{AbstractKey, ExtStatus};
    use crate::verkle_tree::witness::CommitmentElements;

    use super::VerkleTreeWith32BytesKeyValue;

    #[test]
    fn test_verkle_verification_with_one_entry() {
        // prover's view

        let domain_size = 256;
        let committer = IpaConfig::new(domain_size);
        let mut tree = VerkleTreeWith32BytesKeyValue::new(committer);
        let mut key = [0u8; 32];
        key[0] = 13;
        let mut value = [0u8; 32];
        value[0] = 27;
        tree.insert(key, value);
        tree.compute_digest().unwrap();

        let result = tree.get_witnesses(&[key]).unwrap();
        println!("commitments: {:?}", result.commitment_elements.commitments);
        println!("zs: {:?}", result.commitment_elements.elements.zs);
        println!("ys: {:?}", result.commitment_elements.elements.ys);

        let (proof, elements) = VerkleProof::create(&mut tree, &[key]).unwrap();

        // verifier's view

        let domain_size = 256;
        let committer = IpaConfig::new(domain_size);
        let success = proof.check(&elements.zs, &elements.ys, &committer).unwrap();

        assert!(
            success,
            "Fail to pass the verification of verkle proof circuit."
        );
    }

    #[test]
    fn test_verkle_tree_with_some_entries() {
        let domain_size = 256;
        let committer = IpaConfig::new(domain_size);
        let mut tree = VerkleTreeWith32BytesKeyValue::new(committer);
        let mut keys = vec![];
        {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 2;
            key[2] = 32;
            key[30] = 164;
            key[31] = 254;
            let value = [255u8; 32];
            tree.insert(key, value);
            keys.push(key);
        }
        {
            let key = [255u8; 32];
            let mut value = [0u8; 32];
            value[0] = 28;
            value[15] = 193;
            value[16] = 60;
            value[31] = 27;
            tree.insert(key, value);
            keys.push(key);
        }
        {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 3;
            key[30] = 164;
            key[31] = 255;
            let value = [0u8; 32];
            tree.insert(key, value);
            keys.push(key);
        }
        {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 3;
            key[30] = 164;
            key[31] = 254;
            let mut value = [0u8; 32];
            value[0] = 235;
            value[15] = 193;
            value[16] = 60;
            value[31] = 136;
            tree.insert(key, value);
            keys.push(key);
        }

        tree.compute_digest().unwrap();

        let result = tree.get_witnesses(&[keys[0]]).unwrap();
        println!("commitments: {:?}", result.commitment_elements.commitments);
        println!("zs: {:?}", result.commitment_elements.elements.zs);
        println!("ys: {:?}", result.commitment_elements.elements.ys);
        println!("extra_data_list: {:?}", result.extra_data_list);
        assert_eq!(
            result.commitment_elements.elements.zs,
            [13, 2, 0, 1, 3, 252, 253]
        );
        assert_eq!(result.commitment_elements.elements.ys.len(), 7);
        assert_eq!(result.commitment_elements.commitments.len(), 7);
        assert_eq!(result.extra_data_list.len(), 1);
        assert_eq!(
            ExtStatus::from(result.extra_data_list[0].ext_status % 8),
            ExtStatus::Present
        );
        assert_eq!(result.extra_data_list[0].ext_status >> 3, 2);
        assert!(result.extra_data_list[0].poa_stem.is_none());

        tree.remove(&keys[0]);

        tree.compute_digest().unwrap();

        let key_empty_leaf = keys[0];

        let result = tree.get_witnesses(&[key_empty_leaf]).unwrap();
        println!("commitments: {:?}", result.commitment_elements.commitments);
        println!("ys: {:?}", result.commitment_elements.elements.ys);
        assert_eq!(result.commitment_elements.elements.zs, [13, 2]);
        assert_eq!(result.commitment_elements.elements.ys.len(), 2);
        assert_eq!(result.commitment_elements.commitments.len(), 2);
        assert_eq!(result.extra_data_list.len(), 1);
        assert_eq!(
            ExtStatus::from(result.extra_data_list[0].ext_status % 8),
            ExtStatus::Empty
        );
        assert_eq!(result.extra_data_list[0].ext_status >> 3, 2);
        assert!(result.extra_data_list[0].poa_stem.is_none());

        let key_other_stem = {
            let mut key = [255u8; 32];
            key[30] = 0;

            key
        };

        let result = tree.get_witnesses(&[key_other_stem]).unwrap();
        println!("commitments: {:?}", result.commitment_elements.commitments);
        println!("ys: {:?}", result.commitment_elements.elements.ys);
        assert_eq!(result.commitment_elements.elements.zs, [255, 0, 1]);
        assert_eq!(result.commitment_elements.elements.ys.len(), 3);
        assert_eq!(result.commitment_elements.commitments.len(), 3);
        assert_eq!(result.extra_data_list[0].poa_stem, keys[1].get_stem());
        assert_eq!(result.extra_data_list.len(), 1);
        assert_eq!(
            ExtStatus::from(result.extra_data_list[0].ext_status % 8),
            ExtStatus::OtherStem
        );
        assert_eq!(result.extra_data_list[0].ext_status >> 3, 1);
        assert!(result.extra_data_list[0].poa_stem.is_some());

        let key_other_key = {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 3;
            key[30] = 164;
            key[31] = 254;

            key
        };

        let result = tree.get_witnesses(&[key_other_key]).unwrap();
        println!("commitments: {:?}", result.commitment_elements.commitments);
        assert_eq!(
            result.commitment_elements.elements.zs,
            [13, 3, 0, 1, 3, 252, 253]
        );
        assert_eq!(format!("{:?}", result.commitment_elements.elements.ys), "[Fr(0x134d9605e15042f91834ec9439445d588f3cedee8796d5629329e86fd2cbec3f), Fr(0x0b4a2652a4ff4dba812f9c44afebac7e50b7fb480262297bbb9c129f258c2e65), Fr(0x0000000000000000000000000000000000000000000000000000000000000001), Fr(0x00a400000000000000000000000000000000000000000000000000000000030d), Fr(0x0928b1fe44b445433665f46d8d19fa337266509babb8e89c0297b667143f1e42), Fr(0x00000000000000000000000000000001c10000000000000000000000000000eb), Fr(0x000000000000000000000000000000008800000000000000000000000000003c)]");
        assert_eq!(result.commitment_elements.commitments.len(), 7);
        assert_eq!(result.extra_data_list.len(), 7);
        assert_eq!(
            ExtStatus::from(result.extra_data_list[0].ext_status % 8),
            ExtStatus::OtherKey
        );
        assert_eq!(result.extra_data_list[0].ext_status >> 3, 1);
        assert!(result.extra_data_list[0].poa_stem.is_none());

        let key_empty_suffix_tree = {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 3;
            key[30] = 164;
            key[31] = 17;

            key
        };

        let result = tree.get_witnesses(&[key_empty_suffix_tree]).unwrap();
        println!("commitments: {:?}", result.commitment_elements.commitments);
        assert_eq!(result.commitment_elements.elements.zs, [5]);
        assert_eq!(result.commitment_elements.elements.ys, [Fr::zero()]);
        assert_eq!(result.commitment_elements.commitments.len(), 1);
        assert_eq!(result.extra_data_list.len(), 1);
        assert_eq!(
            ExtStatus::from(result.extra_data_list[0].ext_status % 8),
            ExtStatus::EmptySuffixTree
        );
        assert_eq!(result.extra_data_list[0].ext_status >> 3, 1);
        assert!(result.extra_data_list[0].poa_stem.is_none());
    }

    #[test]
    fn test_encode_verkle_proof() {
        let domain_size = 256;
        let committer = IpaConfig::new(domain_size);
        let mut tree = VerkleTreeWith32BytesKeyValue::new(committer);
        let mut keys = vec![];
        {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 2;
            key[2] = 32;
            key[30] = 164;
            key[31] = 254;
            let value = [255u8; 32];
            tree.insert(key, value);
            keys.push(key);
        }
        {
            let key = [255u8; 32];
            let mut value = [0u8; 32];
            value[0] = 28;
            value[15] = 193;
            value[16] = 60;
            value[31] = 27;
            tree.insert(key, value);
            keys.push(key);
        }
        {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 3;
            key[30] = 164;
            key[31] = 255;
            let value = [0u8; 32];
            tree.insert(key, value);
            keys.push(key);
        }
        {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 3;
            key[30] = 164;
            key[31] = 254;
            let mut value = [0u8; 32];
            value[0] = 235;
            value[15] = 193;
            value[16] = 60;
            value[31] = 136;
            tree.insert(key, value);
            keys.push(key);
        }

        let key_other_stem = {
            let mut key = [255u8; 32];
            key[30] = 0;

            key
        };

        let key_other_key = {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 3;
            key[30] = 164;
            key[31] = 253;

            key
        };

        let key_empty_suffix_tree = {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 3;
            key[30] = 164;
            key[31] = 17;

            key
        };

        tree.compute_digest().unwrap();

        let mut sorted_keys = [
            keys[3],
            key_other_stem,
            key_other_key,
            key_empty_suffix_tree,
        ];
        sorted_keys.sort();
        let (proof, elements) = VerkleProof::create(&mut tree, &sorted_keys).unwrap();
        let encoded_proof = EncodedVerkleProof::encode(&proof);
        let proof_path = Path::new("./test_cases").join("proof_case2.json");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(proof_path)
            .unwrap();
        serde_json::to_writer(file, &encoded_proof).unwrap();
        let elements_path = Path::new("./test_cases").join("elements_case2.json");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(elements_path)
            .unwrap();
        let commitment_elements = CommitmentElements {
            elements,
            commitments: proof.commitments,
        };
        serde_json::to_writer(
            file,
            &EncodedCommitmentElements::encode(&commitment_elements),
        )
        .unwrap();

        let proof_path = Path::new("./test_cases").join("proof_case2.json");
        let file = OpenOptions::new().read(true).open(proof_path).unwrap();
        let encoded_proof: EncodedVerkleProof = serde_json::from_reader(file).unwrap();
        let (decoded_proof, decoded_zs, decoded_ys) = encoded_proof.decode().unwrap();
        let elements_path = Path::new("./test_cases").join("elements_case2.json");
        let file = OpenOptions::new().read(true).open(elements_path).unwrap();
        let commitment_elements: EncodedCommitmentElements = serde_json::from_reader(file).unwrap();
        let commitment_elements = commitment_elements.decode().unwrap();
        assert_eq!(decoded_zs, commitment_elements.elements.zs);
        assert_eq!(decoded_ys, commitment_elements.elements.ys);
        assert_eq!(
            decoded_proof
                .commitments
                .iter()
                .map(|v| EncodedEcPoint::encode(v))
                .collect::<Vec<_>>(),
            commitment_elements
                .commitments
                .iter()
                .map(|v| EncodedEcPoint::encode(v))
                .collect::<Vec<_>>()
        );

        let domain_size = 256;
        let committer = IpaConfig::new(domain_size);
        let success = decoded_proof
            .check(&decoded_zs, &decoded_ys, &committer)
            .unwrap();

        assert!(
            success,
            "Fail to pass the verification of verkle proof circuit."
        );
    }
}
