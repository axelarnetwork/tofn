//! A fillable Vec
use serde::{Deserialize, Serialize};
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FillVec<T> {
    vec: Vec<Option<T>>,
    some_count: usize,
}

#[derive(Debug)]
pub enum FillVecError {
    ValueAlreadySet(usize),
}

type Result<T> = std::result::Result<T, FillVecError>;

impl<T> FillVec<T> {
    pub fn with_len(len: usize) -> Self {
        Self {
            vec: new_vec_none(len),
            some_count: 0,
        }
    }
    pub fn insert(&mut self, index: usize, value: T) -> Result<()> {
        if self.vec[index].is_some() {
            return Err(FillVecError::ValueAlreadySet(index));
        }
        self.overwrite(index, value);
        Ok(())
    }
    pub fn overwrite(&mut self, index: usize, value: T) {
        self.overwrite_impl(index, value, false)
    }
    pub fn overwrite_warn(&mut self, index: usize, value: T) {
        self.overwrite_impl(index, value, true)
    }
    fn overwrite_impl(&mut self, index: usize, value: T, warn: bool) {
        let stored = &mut self.vec[index];
        if stored.is_none() {
            self.some_count += 1;
        } else if warn {
            warn!("overwrite existing value at index {}", index);
        }

        *stored = Some(value);
    }
    pub fn len(&self) -> usize {
        self.vec.len()
    }
    pub fn vec_ref(&self) -> &Vec<Option<T>> {
        &self.vec
    }
    pub fn vec_ref_mut(&mut self) -> &mut Vec<Option<T>> {
        &mut self.vec
    }
    pub fn into_vec(self) -> Vec<Option<T>> {
        self.vec
    }
    pub fn some_count(&self) -> usize {
        self.some_count
    }
    pub fn is_none(&self, index: usize) -> bool {
        matches!(self.vec[index], None)
    }
    /// Returns `true` if all items are `Some`, except possibly the `index`th item.
    pub fn is_full_except(&self, index: usize) -> bool {
        (self.is_none(index) && self.some_count() >= self.vec.len() - 1)
            || self.some_count() >= self.vec.len()
    }

    pub fn is_full(&self) -> bool {
        self.some_count() == self.vec.len()
    }

    // Replicate std::vec interface https://doc.rust-lang.org/src/alloc/vec/mod.rs.html#1800
    pub fn is_empty(&self) -> bool {
        self.some_count == 0
    }

    pub fn from_vec(vec: Vec<Option<T>>) -> Self {
        Self {
            some_count: vec.iter().filter(|x| x.is_some()).count(),
            vec,
        }
    }
}

pub fn new_vec_none<T>(len: usize) -> Vec<Option<T>> {
    (0..len).map(|_| None).collect() // can't use vec![None; capacity] https://users.rust-lang.org/t/how-to-initialize-vec-option-t-with-none/30580/2
}

impl std::error::Error for FillVecError {}
impl std::fmt::Display for FillVecError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FillVecError::ValueAlreadySet(i) => write!(f, "value already set for index {:?}", i),
        }
    }
}
