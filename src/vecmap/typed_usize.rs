use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TypedUsize<K>(usize, std::marker::PhantomData<K>)
where
    K: Behave;

/// Alias for all the trait bounds on `K` in order to work around https://stackoverflow.com/a/31371094
pub trait Behave: std::fmt::Debug + Clone + Copy + PartialEq + Send + Sync {}

impl<K> TypedUsize<K>
where
    K: Behave,
{
    pub fn from_usize(index: usize) -> Self {
        TypedUsize(index, std::marker::PhantomData)
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
}

impl<K> std::fmt::Display for TypedUsize<K>
where
    K: Behave,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
