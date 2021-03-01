//! A fillable Vec

#[derive(Debug, Clone)]
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
        let stored = &mut self.vec[index];
        if stored.is_some() {
            return Err(FillVecError::ValueAlreadySet(index));
        }
        *stored = Some(value);
        self.some_count += 1;
        Ok(())
    }
    pub fn vec_ref(&self) -> &Vec<Option<T>> {
        &self.vec
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
