pub mod bn256_verkle_tree;
pub mod proof;
pub mod trie;
pub mod utils;

#[cfg(test)]
mod tests {
    use franklin_crypto::bellman::bn256::G1Affine;
    use generic_array::typenum::U256;

    use crate::verkle_tree::{
        bn256_verkle_tree::{Bn256VerkleTree, VerkleTreeZkp},
        trie::VerkleTree,
    };

    #[test]
    fn test_verkle_tree() {
        let mut tree = VerkleTree::<U256, G1Affine>::default();
        let mut key = [0u8; 32];
        key[0] = 13;
        let mut value = [0u8; 32];
        value[0] = 27;
        tree.insert(key, value).unwrap();
        tree.compute_commitment().unwrap();

        // TODO: Is this a correct result?
        let result = tree.get_commitments_along_path(key).unwrap();
        println!("commitments: {:?}", result.commitment_elements.commitments);
        println!("zs: {:?}", result.commitment_elements.elements.zs);
        println!("ys: {:?}", result.commitment_elements.elements.ys);

        let proof = Bn256VerkleTree::<U256>::create_proof(&tree, &[key], &tree.committer).unwrap();
        // println!("proof: {:?}", proof);

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
}
