use std::{
    ops::{Index, IndexMut},
    slice::SliceIndex,
    vec::IntoIter,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreePath {
    pub(crate) inner: Vec<u8>,
}

impl Default for TreePath {
    fn default() -> Self {
        Self { inner: vec![] }
    }
}

impl TreePath {
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl<I: SliceIndex<[u8]>> Index<I> for TreePath {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&*self.inner, index)
    }
}

impl<I: SliceIndex<[u8]>> IndexMut<I> for TreePath {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut *self.inner, index)
    }
}

impl From<Vec<u8>> for TreePath {
    fn from(path: Vec<u8>) -> Self {
        Self { inner: path }
    }
}

impl From<&[u8]> for TreePath {
    fn from(path: &[u8]) -> Self {
        Self::from(path.to_vec())
    }
}

impl IntoIterator for TreePath {
    type Item = u8;
    type IntoIter = IntoIter<u8>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}
