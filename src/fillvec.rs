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
    pub fn new_vec_none(capacity: usize) -> Vec<Option<T>> {
        (0..capacity).map(|_| None).collect() // can't use vec![None; capacity]
    }
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            vec: Self::new_vec_none(capacity),
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
    pub fn into_vec(self) -> Vec<Option<T>> {
        self.vec
    }
    pub fn some_count(&self) -> usize {
        self.some_count
    }
}

impl std::error::Error for FillVecError {}
impl std::fmt::Display for FillVecError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            FillVecError::ValueAlreadySet(i) => write!(f, "value already set for index {:?}", i),
        }
    }
}
