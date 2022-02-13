pub mod bn256_verkle_tree;
pub mod path;
pub mod proof;
pub mod trie;
pub mod utils;

#[cfg(test)]
mod tests {
    use franklin_crypto::bellman::bn256::{Fr, G1Affine};
    use franklin_crypto::bellman::Field;
    use generic_array::typenum::U256;

    use crate::verkle_tree::trie::{AbstractKey, ExtStatus};
    use crate::verkle_tree::{
        bn256_verkle_tree::{Bn256VerkleTree, VerkleTreeZkp},
        trie::{AbstractMerkleTree, VerkleTree},
    };

    #[test]
    fn test_verkle_verification_with_one_entry() {
        let mut tree = VerkleTree::<G1Affine>::default();
        let mut key = [0u8; 32];
        key[0] = 13;
        let mut value = [0u8; 32];
        value[0] = 27;
        tree.insert(key, value).unwrap();
        tree.compute_commitment().unwrap();

        let result = tree.get_commitments_along_path(key).unwrap();
        println!("commitments: {:?}", result.commitment_elements.commitments);
        println!("zs: {:?}", result.commitment_elements.elements.zs);
        println!("ys: {:?}", result.commitment_elements.elements.ys);

        let proof = Bn256VerkleTree::<U256>::create_proof(&tree, &[key], &tree.committer).unwrap();

        let success = Bn256VerkleTree::<U256>::check_proof(
            proof.0,
            &proof.1.zs,
            &proof.1.ys,
            &tree.committer,
        )
        .unwrap();

        assert!(
            success,
            "Fail to pass the verification of verkle proof circuit."
        );
    }

    #[test]
    fn test_verkle_tree_with_three_entries() {
        let mut tree = VerkleTree::<G1Affine>::default();
        let mut keys = vec![];
        {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 2;
            key[30] = 164;
            key[31] = 254;
            let value = [255u8; 32];
            tree.insert(key, value).unwrap();
            keys.push(key);
        }
        {
            let key = [255u8; 32];
            let mut value = [0u8; 32];
            value[0] = 28;
            value[15] = 193;
            value[16] = 60;
            value[31] = 27;
            tree.insert(key, value).unwrap();
            keys.push(key);
        }
        {
            let mut key = [0u8; 32];
            key[0] = 13;
            key[1] = 3;
            key[30] = 164;
            key[31] = 255;
            let value = [0u8; 32];
            tree.insert(key, value).unwrap();
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
            println!("insert entry 3");
            tree.insert(key, value).unwrap();
            println!("end insert entry 3");
            keys.push(key);
        }

        tree.compute_commitment().unwrap();

        let result = tree.get_commitments_along_path(keys[0]).unwrap();
        println!("commitments: {:?}", result.commitment_elements.commitments);
        println!("zs: {:?}", result.commitment_elements.elements.zs);
        println!("ys: {:?}", result.commitment_elements.elements.ys);
        println!("extra_data_list: {:?}", result.extra_data_list);
        assert_eq!(
            result.commitment_elements.elements.zs[0],
            keys[0][0] as usize
        );
        assert_eq!(
            result.commitment_elements.elements.zs[4],
            (keys[0][31] as usize * 2) % 256
        );
        assert_eq!(
            result.commitment_elements.elements.zs[5],
            (keys[0][31] as usize * 2 + 1) % 256
        );
        assert_eq!(
            result.commitment_elements.elements.zs,
            [13, 0, 1, 3, 252, 253]
        );
        assert_eq!(result.commitment_elements.elements.ys.len(), 6);
        assert_eq!(result.commitment_elements.commitments.len(), 6);
        assert_eq!(result.extra_data_list.len(), 1);
        assert_eq!(
            result.extra_data_list[0].ext_status % 8,
            ExtStatus::Present as usize
        );
        assert_eq!(result.extra_data_list[0].ext_status >> 3, 1);
        assert!(result.extra_data_list[0].poa_stems.is_none());

        tree.remove(keys[0]).unwrap();

        tree.compute_commitment().unwrap();

        let key_present_stem = keys[0];

        let result = tree.get_commitments_along_path(key_present_stem).unwrap();
        println!("commitments: {:?}", result.commitment_elements.commitments);
        println!("ys: {:?}", result.commitment_elements.elements.ys);
        assert_eq!(result.commitment_elements.elements.zs, [13, 0, 1, 3, 252]);
        assert_eq!(result.commitment_elements.elements.ys.len(), 5);
        assert_eq!(result.commitment_elements.commitments.len(), 5);
        assert_eq!(result.extra_data_list.len(), 1);
        assert_eq!(
            result.extra_data_list[0].ext_status % 8,
            ExtStatus::Present as usize
        );
        assert_eq!(result.extra_data_list[0].ext_status >> 3, 1);
        assert!(result.extra_data_list[0].poa_stems.is_none());

        let key_absent_other = {
            let mut key = [255u8; 32];
            key[30] = 0;

            key
        };

        let result = tree.get_commitments_along_path(key_absent_other).unwrap();
        println!("commitments: {:?}", result.commitment_elements.commitments);
        println!("ys: {:?}", result.commitment_elements.elements.ys);
        assert_eq!(result.commitment_elements.elements.zs, [255, 0, 1]);
        assert_eq!(result.commitment_elements.elements.ys.len(), 3);
        assert_eq!(result.commitment_elements.commitments.len(), 3);
        assert_eq!(result.extra_data_list[0].poa_stems, keys[1].get_stem());
        assert_eq!(result.extra_data_list.len(), 1);
        assert_eq!(
            result.extra_data_list[0].ext_status % 8,
            ExtStatus::AbsentOther as usize
        );
        assert_eq!(result.extra_data_list[0].ext_status >> 3, 1);
        assert!(result.extra_data_list[0].poa_stems.is_some());

        let key_absent_empty = {
            let mut key = [255u8; 32];
            key[0] = 5;

            key
        };

        let result = tree.get_commitments_along_path(key_absent_empty).unwrap();
        println!("commitments: {:?}", result.commitment_elements.commitments);
        assert_eq!(result.commitment_elements.elements.zs, [5]);
        assert_eq!(result.commitment_elements.elements.ys, [Fr::zero()]);
        assert_eq!(result.commitment_elements.commitments.len(), 1);
        assert_eq!(result.extra_data_list.len(), 1);
        assert_eq!(
            result.extra_data_list[0].ext_status % 8,
            ExtStatus::AbsentEmpty as usize
        );
        assert_eq!(result.extra_data_list[0].ext_status >> 3, 0);
        assert!(result.extra_data_list[0].poa_stems.is_none());
    }
}
