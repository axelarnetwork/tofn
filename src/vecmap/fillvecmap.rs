//! A fillable Vec
// use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{Index, VecMap};

// #[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Debug, Clone)]
pub struct FillVecMap<T, I> {
    vec: VecMap<Option<T>, I>,
    some_count: usize,
}

impl<T, I> FillVecMap<T, I> {
    pub fn with_size(len: usize) -> Self {
        Self {
            vec: VecMap::from_vec(new_vec_none(len)),
            some_count: 0,
        }
    }
    pub fn set(&mut self, index: Index<I>, value: T) {
        self.set_impl(index, value, false)
    }
    pub fn set_warn(&mut self, index: Index<I>, value: T) {
        self.set_impl(index, value, true)
    }
    fn set_impl(&mut self, index: Index<I>, value: T, warn: bool) {
        let stored = self.vec.get_mut(index);
        if stored.is_none() {
            self.some_count += 1;
        } else {
            if warn {
                warn!("overwrite existing value at index {}", index);
            }
        }
        *stored = Some(value);
    }
    pub fn some_count(&self) -> usize {
        self.some_count
    }
    // pub fn is_none(&self, index: usize) -> bool {
    //     matches!(self.vec[index], None)
    // }
    // /// Returns `true` if all items are `Some`, except possibly the `index`th item.
    // pub fn is_full_except(&self, index: usize) -> bool {
    //     (self.is_none(index) && self.some_count() >= self.vec.len() - 1)
    //         || self.some_count() >= self.vec.len()
    // }

    pub fn is_full(&self) -> bool {
        self.some_count() == self.vec.len()
    }

    // Replicate std::vec interface https://doc.rust-lang.org/src/alloc/vec/mod.rs.html#1800
    pub fn is_empty(&self) -> bool {
        self.some_count == 0
    }

    // pub fn from_vec(vec: Vec<Option<T>>) -> Self {
    //     Self {
    //         some_count: vec.iter().filter(|x| x.is_some()).count(),
    //         vec,
    //     }
    // }
}

pub fn new_vec_none<T>(len: usize) -> Vec<Option<T>> {
    (0..len).map(|_| None).collect() // can't use vec![None; capacity] https://users.rust-lang.org/t/how-to-initialize-vec-option-t-with-none/30580/2
}
