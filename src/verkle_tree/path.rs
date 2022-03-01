use franklin_crypto::bellman::PrimeField;

use crate::ipa_fr::utils::read_field_element_le;

use super::trie::{AbstractKey, AbstractPath, AbstractStem, IntoFieldElement};

// 32 bytes key
impl AbstractKey for [u8; 32] {
    type Stem = Option<[u8; 31]>;
    type Path = Vec<usize>;

    fn get_stem(&self) -> Option<[u8; 31]> {
        let result: [u8; 31] = self[..31].to_vec().try_into().unwrap();

        Some(result)
    }

    fn get_suffix(&self) -> usize {
        usize::from(self[31])
    }

    fn to_path(&self) -> Vec<usize> {
        self.iter().map(|&x| x as usize).collect::<Vec<_>>()
    }

    fn get_branch_at(&self, depth: usize) -> usize {
        self[depth] as usize
    }
}

impl AbstractStem for Option<[u8; 31]> {
    type Path = Vec<usize>;

    fn to_path(&self) -> Vec<usize> {
        let bytes = match self {
            Some(inner) => inner.to_vec(),
            None => vec![],
        };

        bytes.iter().map(|x| *x as usize).collect::<Vec<_>>()
    }
}

impl<F: PrimeField> IntoFieldElement<F> for Option<[u8; 31]> {
    type Err = anyhow::Error;

    fn into_field_element(self) -> anyhow::Result<F> {
        match self {
            Some(bytes) => read_field_element_le(&bytes),
            None => {
                anyhow::bail!("None is not converted into a field element.")
            }
        }
    }
}

impl AbstractPath for Vec<usize> {
    type RemovePrefixError = anyhow::Error;

    fn get_next_path_and_branch(&self) -> (Self, usize) {
        let next_branch = *self.first().expect("`next_branch` must be a value.");

        let next_path = self[1..].to_vec();

        (next_path, next_branch)
    }

    fn get_suffix(&self) -> usize {
        self[self.len() - 1]
    }

    fn is_proper_prefix_of(&self, full_path: &Self) -> bool {
        if self.is_empty() {
            return true;
        }

        if self.len() >= full_path.len() {
            return false;
        }

        full_path[..self.len()].eq(self)
    }

    fn remove_prefix(&self, prefix: &Self) -> anyhow::Result<Self> {
        if !prefix.is_proper_prefix_of(self) {
            anyhow::bail!("{:?} is not proper prefix of {:?}", prefix, self,);
        }

        let result = Self::from(&self[prefix.len()..]);

        Ok(result)
    }

    fn len(&self) -> usize {
        Vec::len(self)
    }

    fn is_empty(&self) -> bool {
        Vec::is_empty(self)
    }

    fn push(&mut self, value: usize) {
        Vec::push(self, value)
    }
}
