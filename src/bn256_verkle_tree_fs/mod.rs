use franklin_crypto::bellman::bn256::Bn256;

use crate::ipa_fs::config::IpaConfig;
use crate::verkle_tree_fs::trie::VerkleTree;

use self::leaf::LeafNodeWith32BytesValue;

pub mod leaf;
pub mod proof;

pub type VerkleTreeWith32BytesKeyValue<'a, 'b> =
    VerkleTree<'b, [u8; 32], LeafNodeWith32BytesValue<Bn256>, Bn256, IpaConfig<'a, Bn256>>;

#[cfg(test)]
mod bn256_verkle_tree_fs_tests {
    use std::fs::OpenOptions;
    use std::path::Path;

    use franklin_crypto::babyjubjub::JubjubBn256;
    use franklin_crypto::bellman::PrimeField;

    use crate::bn256_verkle_tree_fs::proof::{
        EncodedCommitmentElements, EncodedEcPoint, EncodedVerkleProof, VerkleProof,
    };
    use crate::ipa_fr::transcript::{Bn256Transcript, PoseidonBn256Transcript};
    use crate::ipa_fs::config::IpaConfig;
    use crate::verkle_tree::trie::{AbstractKey, ExtStatus};
    use crate::verkle_tree_fs::witness::CommitmentElements;

    use super::VerkleTreeWith32BytesKeyValue;

    #[test]
    fn test_verkle_fs_verification_with_one_entry() {
        let domain_size = 256;
        let jubjub_params = &JubjubBn256::new();
        let committer = &IpaConfig::new(domain_size, jubjub_params);

        // prover's view
        let mut tree = VerkleTreeWith32BytesKeyValue::new(committer);
        let mut key = [0u8; 32];
        key[0] = 13;
        let mut value = [0u8; 32];
        value[0] = 27;
        tree.insert(key, value);
        tree.compute_digest().unwrap();

        let result = tree.get_witnesses(&[key]).unwrap();
        // println!("commitments: {:?}", result.commitment_elements.commitments);
        println!("zs: {:?}", result.commitment_elements.elements.zs);
        println!("ys: {:?}", result.commitment_elements.elements.ys);

        let prover_transcript = PoseidonBn256Transcript::with_bytes(b"verkle_tree");
        let (proof, elements) =
            VerkleProof::create(&mut tree, &[key], prover_transcript.into_params()).unwrap();

        // verifier's view

        let verifier_transcript = PoseidonBn256Transcript::with_bytes(b"verkle_tree");
        let success = proof
            .check(
                &elements.zs,
                &elements.ys,
                verifier_transcript.into_params(),
                &committer,
            )
            .unwrap();

        assert!(
            success,
            "Fail to pass the verification of verkle proof circuit."
        );
    }

    #[test]
    fn test_verkle_tree_fs_with_some_entries() {
        let domain_size = 256;
        let jubjub_params = &JubjubBn256::new();
        let committer = &IpaConfig::new(domain_size, jubjub_params);
        let mut tree = VerkleTreeWith32BytesKeyValue::new(committer);
        let mut keys = vec![];
        {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 102;
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
            key[1] = 103;
            key[30] = 164;
            key[31] = 255;
            let value = [0u8; 32];
            tree.insert(key, value);
            keys.push(key);
        }
        {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 103;
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
        // println!("commitments: {:?}", result.commitment_elements.commitments);
        println!("zs: {:?}", result.commitment_elements.elements.zs);
        println!("ys: {:?}", result.commitment_elements.elements.ys);
        println!("extra_data_list: {:?}", result.extra_data_list);
        assert_eq!(
            result.commitment_elements.elements.zs,
            [13, 102, 0, 1, 3, 252, 253]
        );
        assert_eq!(
            result.commitment_elements.elements.ys.len(),
            result.commitment_elements.elements.zs.len()
        );
        assert_eq!(
            result.commitment_elements.commitments.len(),
            result.commitment_elements.elements.zs.len()
        );
        assert_eq!(result.extra_data_list.len(), 1);
        assert_eq!(result.extra_data_list[0].status, ExtStatus::Present);
        assert_eq!(result.extra_data_list[0].depth, 2);
        assert!(result.extra_data_list[0].poa_stem.is_none());

        tree.remove(&keys[0]);

        tree.compute_digest().unwrap();

        let key_empty_leaf = {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 101;
            key[30] = 164;
            key[31] = 254;

            key
        };

        let result = tree.get_witnesses(&[key_empty_leaf]).unwrap();
        // println!("commitments: {:?}", result.commitment_elements.commitments);
        println!("ys: {:?}", result.commitment_elements.elements.ys);
        assert_eq!(result.commitment_elements.elements.zs, [13, 101]);
        assert_eq!(
            result.commitment_elements.elements.ys.len(),
            result.commitment_elements.elements.zs.len()
        );
        assert_eq!(
            result.commitment_elements.commitments.len(),
            result.commitment_elements.elements.zs.len()
        );
        assert_eq!(result.extra_data_list.len(), 1);
        assert_eq!(result.extra_data_list[0].status, ExtStatus::Empty);
        assert_eq!(result.extra_data_list[0].depth, 2);
        assert!(result.extra_data_list[0].poa_stem.is_none());

        let key_other_stem = {
            let mut key = [255u8; 32];
            key[30] = 0;

            key
        };

        let result = tree.get_witnesses(&[key_other_stem]).unwrap();
        // println!("commitments: {:?}", result.commitment_elements.commitments);
        println!("ys: {:?}", result.commitment_elements.elements.ys);
        assert_eq!(result.commitment_elements.elements.zs, [255, 0, 1]);
        assert_eq!(
            result.commitment_elements.elements.ys.len(),
            result.commitment_elements.elements.zs.len()
        );
        assert_eq!(
            result.commitment_elements.commitments.len(),
            result.commitment_elements.elements.zs.len()
        );
        assert_eq!(result.extra_data_list[0].poa_stem, keys[1].get_stem());
        assert_eq!(result.extra_data_list.len(), 1);
        assert_eq!(result.extra_data_list[0].status, ExtStatus::OtherStem);
        assert_eq!(result.extra_data_list[0].depth, 1);
        assert!(result.extra_data_list[0].poa_stem.is_some());

        let key_other_key = {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 103;
            key[30] = 164;
            key[31] = 253;

            key
        };

        let result = tree.get_witnesses(&[key_other_key]).unwrap();
        // println!("commitments: {:?}", result.commitment_elements.commitments);
        assert_eq!(
            result.commitment_elements.elements.zs,
            [13, 103, 0, 1, 3, 250]
        );
        assert_eq!(
            result.commitment_elements.elements.ys.len(),
            result.commitment_elements.elements.zs.len()
        );
        assert_eq!(
            result.commitment_elements.commitments.len(),
            result.commitment_elements.elements.zs.len()
        );
        assert_eq!(result.extra_data_list.len(), 1);
        assert_eq!(result.extra_data_list[0].status, ExtStatus::OtherKey);
        assert_eq!(result.extra_data_list[0].depth, 2);
        assert!(result.extra_data_list[0].poa_stem.is_none());

        let key_empty_suffix_tree = {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 103;
            key[30] = 164;
            key[31] = 17;

            key
        };

        let result = tree.get_witnesses(&[key_empty_suffix_tree]).unwrap();
        // println!("commitments: {:?}", result.commitment_elements.commitments);
        assert_eq!(result.commitment_elements.elements.zs, [13, 103, 0, 1, 2]);
        assert_eq!(
            result.commitment_elements.elements.ys.len(),
            result.commitment_elements.elements.zs.len()
        );
        assert_eq!(
            result.commitment_elements.commitments.len(),
            result.commitment_elements.elements.zs.len()
        );
        assert_eq!(result.extra_data_list.len(), 1);
        assert_eq!(result.extra_data_list[0].status, ExtStatus::EmptySuffixTree);
        assert_eq!(result.extra_data_list[0].depth, 2);
        assert!(result.extra_data_list[0].poa_stem.is_none());
    }

    #[test]
    fn test_encode_verkle_fs_proof() {
        let domain_size = 256;
        let jubjub_params = &JubjubBn256::new();
        let committer = &IpaConfig::new(domain_size, jubjub_params);
        let mut tree = VerkleTreeWith32BytesKeyValue::new(committer);
        let mut keys = vec![];
        {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 102;
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
            key[1] = 103;
            key[30] = 164;
            key[31] = 255;
            let value = [0u8; 32];
            tree.insert(key, value);
            keys.push(key);
        }
        {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 103;
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

        let key_empty_leaf = {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 101;
            key[30] = 164;
            key[31] = 254;

            key
        };

        let key_other_stem = {
            let mut key = [255u8; 32];
            key[30] = 0;

            key
        };

        let key_other_key = {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 103;
            key[30] = 164;
            key[31] = 253;

            key
        };

        let key_empty_suffix_tree = {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 103;
            key[30] = 164;
            key[31] = 17;

            key
        };

        tree.compute_digest().unwrap();

        let mut sorted_keys = [
            key_empty_leaf,
            keys[3],
            key_other_stem,
            key_other_key,
            key_empty_suffix_tree,
        ];
        sorted_keys.sort();

        let prover_transcript = PoseidonBn256Transcript::with_bytes(b"verkle_tree");
        let (proof, elements) =
            VerkleProof::create(&mut tree, &sorted_keys, prover_transcript.into_params()).unwrap();
        let encoded_proof = EncodedVerkleProof::encode(&proof);
        let proof_path = Path::new("./test_cases")
            .join("fs_case1")
            .join("proof.json");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(proof_path)
            .unwrap();
        serde_json::to_writer(file, &encoded_proof).unwrap();
        let elements_path = Path::new("./test_cases")
            .join("fs_case1")
            .join("elements.json");
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

        let proof_path = Path::new("./test_cases")
            .join("fs_case1")
            .join("proof.json");
        let file = OpenOptions::new().read(true).open(proof_path).unwrap();
        let encoded_proof: EncodedVerkleProof = serde_json::from_reader(file).unwrap();
        let (decoded_proof, decoded_zs, decoded_ys) = encoded_proof.decode(tree.committer).unwrap();
        let elements_path = Path::new("./test_cases")
            .join("fs_case1")
            .join("elements.json");
        let file = OpenOptions::new().read(true).open(elements_path).unwrap();
        let commitment_elements: EncodedCommitmentElements = serde_json::from_reader(file).unwrap();
        let commitment_elements = commitment_elements.decode().unwrap();
        assert_eq!(decoded_zs, commitment_elements.elements.zs);
        for (i, (_y, y)) in decoded_ys
            .iter()
            .zip(&commitment_elements.elements.ys)
            .enumerate()
        {
            if _y != y {
                println!(
                    "{}-th commitment is invalid: {:?} != {:?}",
                    i,
                    _y.into_repr(),
                    y.into_repr()
                );
            }
        }
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
        let jubjub_params = &JubjubBn256::new();
        let committer = IpaConfig::new(domain_size, jubjub_params);
        let verifier_transcript = PoseidonBn256Transcript::with_bytes(b"verkle_tree");
        let success = decoded_proof
            .check(
                &decoded_zs,
                &decoded_ys,
                verifier_transcript.into_params(),
                &committer,
            )
            .unwrap();

        assert!(success, "Fail to pass the verification of verkle proof.");
    }
}
