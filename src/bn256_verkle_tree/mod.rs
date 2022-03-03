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
    use franklin_crypto::bellman::bn256::Fr;
    use franklin_crypto::bellman::Field;

    use crate::bn256_verkle_tree::proof::{EncodedVerkleProof, VerkleProof};
    use crate::ipa_fr::config::IpaConfig;
    use crate::verkle_tree::trie::{AbstractKey, ExtStatus};

    use super::VerkleTreeWith32BytesKeyValue;

    #[test]
    fn test_verkle_verification_with_one_entry() {
        let domain_size = 256;
        let committer = IpaConfig::new(domain_size);
        let mut tree = VerkleTreeWith32BytesKeyValue::new(committer);
        let mut key = [0u8; 32];
        key[0] = 13;
        let mut value = [0u8; 32];
        value[0] = 27;
        tree.insert(key, value);
        tree.compute_commitment().unwrap();

        let result = tree.get_witnesses(&[key]).unwrap();
        println!("commitments: {:?}", result.commitment_elements.commitments);
        println!("zs: {:?}", result.commitment_elements.elements.zs);
        println!("ys: {:?}", result.commitment_elements.elements.ys);

        let (proof, elements) = VerkleProof::create(&mut tree, &[key]).unwrap();
        let encoded_proof = EncodedVerkleProof::encode(&proof);
        let (decoded_proof, decoded_zs, decoded_ys) = encoded_proof.decode().unwrap();
        assert_eq!(decoded_zs, elements.zs);
        assert_eq!(decoded_ys, elements.ys);
        assert_eq!(format!("{:?}", decoded_proof), format!("{:?}", proof));

        let success = proof
            .check(&elements.zs, &elements.ys, &tree.committer)
            .unwrap();

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

        tree.compute_commitment().unwrap();
        let data = tree.get(&keys[2]).unwrap();
        println!("entry[2]: {:?}", data);

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

        tree.compute_commitment().unwrap();

        let key_present_stem = keys[0];

        let result = tree.get_witnesses(&[key_present_stem]).unwrap();
        println!("commitments: {:?}", result.commitment_elements.commitments);
        println!("ys: {:?}", result.commitment_elements.elements.ys);
        assert_eq!(result.commitment_elements.elements.zs, [13, 2]);
        assert_eq!(result.commitment_elements.elements.ys.len(), 2);
        assert_eq!(result.commitment_elements.commitments.len(), 2);
        assert_eq!(result.extra_data_list.len(), 1);
        assert_eq!(
            ExtStatus::from(result.extra_data_list[0].ext_status % 8),
            ExtStatus::OtherStem
        );
        assert_eq!(result.extra_data_list[0].ext_status >> 3, 2);
        assert!(result.extra_data_list[0].poa_stem.is_none());

        let key_absent_other = {
            let mut key = [255u8; 32];
            key[30] = 0;

            key
        };

        let result = tree.get_witnesses(&[key_absent_other]).unwrap();
        println!("commitments: {:?}", result.commitment_elements.commitments);
        println!("ys: {:?}", result.commitment_elements.elements.ys);
        assert_eq!(result.commitment_elements.elements.zs, [255, 0, 1]);
        assert_eq!(result.commitment_elements.elements.ys.len(), 3);
        assert_eq!(result.commitment_elements.commitments.len(), 3);
        assert_eq!(result.extra_data_list[0].poa_stem, keys[1].get_stem());
        assert_eq!(result.extra_data_list.len(), 1);
        assert_eq!(
            ExtStatus::from(result.extra_data_list[0].ext_status % 8),
            ExtStatus::EmptySuffixTree
        );
        assert_eq!(result.extra_data_list[0].ext_status >> 3, 1);
        assert!(result.extra_data_list[0].poa_stem.is_some());

        let key_absent_empty = {
            let mut key = [255u8; 32];
            key[0] = 5;

            key
        };

        let result = tree.get_witnesses(&[key_absent_empty]).unwrap();
        println!("commitments: {:?}", result.commitment_elements.commitments);
        assert_eq!(result.commitment_elements.elements.zs, [5]);
        assert_eq!(result.commitment_elements.elements.ys, [Fr::zero()]);
        assert_eq!(result.commitment_elements.commitments.len(), 1);
        assert_eq!(result.extra_data_list.len(), 1);
        assert_eq!(
            ExtStatus::from(result.extra_data_list[0].ext_status % 8),
            ExtStatus::OtherStem
        );
        assert_eq!(result.extra_data_list[0].ext_status >> 3, 1);
        assert!(result.extra_data_list[0].poa_stem.is_none());
    }
}
