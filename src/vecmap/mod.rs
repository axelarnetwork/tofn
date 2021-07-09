use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Index<K>(usize, std::marker::PhantomData<K>)
where
    K: Behave;

/// Alias for all the trait bounds on `K` in order to work around https://stackoverflow.com/a/31371094
pub trait Behave: std::fmt::Debug + Clone + Copy + PartialEq + Send + Sync {}

impl<K> Index<K>
where
    K: Behave,
{
    // TODO provide a range iterator (0..n)?
    // TODO from_usize, as_usize should be private
    pub fn from_usize(index: usize) -> Self {
        Index(index, std::marker::PhantomData)
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
}

impl<K> std::fmt::Display for Index<K>
where
    K: Behave,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// /// Manually impl `Clone`, `Copy`, `PartialEq` because https://stackoverflow.com/a/31371094
// impl<K> Clone for Index<K> {
//     fn clone(&self) -> Self {
//         Self::from_usize(self.0)
//     }
// }
// impl<K> Copy for Index<K> {}

// impl<K> PartialEq for Index<K> {
//     fn eq(&self, other: &Self) -> bool {
//         self.0 == other.0
//     }
// }

mod vecmap;
mod vecmap_iter;
mod vecmap_zip;
pub use vecmap::VecMap;
pub use vecmap_zip::zip2;

mod fillvecmap;
pub use fillvecmap::FillVecMap;

mod holevecmap;
mod holevecmap_iter;
pub use holevecmap::HoleVecMap;

mod fillholevecmap;
pub use fillholevecmap::FillHoleVecMap;

mod p2ps;
pub use p2ps::{FillP2ps, P2ps};
mod p2ps_iter;
pub use p2ps_iter::P2psIter;
