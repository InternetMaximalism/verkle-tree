use std::{
    ops::{Index, IndexMut},
    slice::SliceIndex,
    vec::IntoIter,
};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TreePath {
    pub(crate) inner: Vec<usize>,
}

impl TreePath {
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl<I: SliceIndex<[usize]>> Index<I> for TreePath {
    type Output = I::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&*self.inner, index)
    }
}

impl<I: SliceIndex<[usize]>> IndexMut<I> for TreePath {
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut *self.inner, index)
    }
}

impl From<Vec<u8>> for TreePath {
    fn from(path: Vec<u8>) -> Self {
        Self {
            inner: path.iter().map(|x| *x as usize).collect::<Vec<_>>(),
        }
    }
}

impl From<&[u8]> for TreePath {
    fn from(path: &[u8]) -> Self {
        Self::from(path.to_vec())
    }
}

impl From<Vec<usize>> for TreePath {
    fn from(path: Vec<usize>) -> Self {
        Self { inner: path }
    }
}

impl From<&[usize]> for TreePath {
    fn from(path: &[usize]) -> Self {
        Self::from(path.to_vec())
    }
}

impl IntoIterator for TreePath {
    type Item = usize;
    type IntoIter = IntoIter<usize>;

    fn into_iter(self) -> Self::IntoIter {
        self.inner.into_iter()
    }
}
