//! A fillable Vec

use std::{ops::Index, usize};

#[derive(Debug, Clone)]
pub struct HoleVec<T> {
    vec: Vec<T>,
    hole: usize,
}

// trait Gus = PartialOrd + Sub<Output = I>;

impl<T> HoleVec<T> {
    fn map_index(&self, index: usize) -> Result<usize, &'static str> {
        map_index(index, self.hole, self.vec.len())
    }
}

// TODO don't implement Iterator, Index---it'll just confuse people
// Instead just make a `get` method that skips the hole

impl<'a, T> HoleVec<T> {
    pub fn iter(&'a self) -> HoleVecIter<'a, T> {
        self.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a HoleVec<T> {
    type Item = &'a T;
    type IntoIter = HoleVecIter<'a, T>;

    // note that into_iter() is consuming self
    fn into_iter(self) -> Self::IntoIter {
        HoleVecIter {
            hole_vec: self,
            position: 0,
        }
    }
}

impl<T> Index<usize> for HoleVec<T> {
    type Output = T;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.vec[self.map_index(index).unwrap()]
    }
}

// struct HoleVecIterator<'a, T> {
//     iter: std::slice::Iter<'a, T>,
// }

// impl<'a, T> Iterator for HoleVecIterator<'a, T> {
//     type Item = &'a T;

//     fn next(&mut self) -> Option<Self::Item> {
//         self.iter.next()
//     }
// }

pub struct HoleVecIter<'a, T> {
    hole_vec: &'a HoleVec<T>,
    position: usize,
}

impl<'a, T> Iterator for HoleVecIter<'a, T> {
    type Item = &'a T;

    fn next(&mut self) -> Option<Self::Item> {
        if self.position == self.hole_vec.hole {
            self.position += 1;
            return self.next();
        }
        if self.position > self.hole_vec.vec.len() {
            return None;
        }
        let result = Some(&self.hole_vec.vec[self.hole_vec.map_index(self.position).unwrap()]);
        self.position += 1;
        result
    }

    // don't want the user to use this because we enumerate differently
    fn enumerate(self) -> std::iter::Enumerate<Self>
    where
        Self: Sized,
    {
        panic!("use HoleVec::enumerate instead");
    }
}

#[derive(Debug, Clone)]
pub struct FillVec2<T> {
    vec: Vec<Option<T>>,
    some_count: usize,
    hole: usize,
}

impl<T> FillVec2<T> {
    pub fn with_len(hole: usize, len: usize) -> Result<Self, &'static str> {
        if hole >= len {
            return Err("hole >= len");
        }
        Ok(Self {
            vec: new_vec_none(len - 1),
            some_count: 0,
            hole,
        })
    }
    pub fn insert(&mut self, index: usize, value: T) -> Result<(), &'static str> {
        let safe_index = self.map_index(index)?;
        let stored = &mut self.vec[safe_index];
        if stored.is_some() {
            return Err("index already set");
        }
        *stored = Some(value);
        self.some_count += 1;
        Ok(())
    }
    // pub fn vec_ref(&self) -> &Vec<Option<T>> {
    //     &self.vec
    // }
    // pub fn into_vec(self) -> Vec<Option<T>> {
    //     self.vec
    // }
    // pub fn some_count(&self) -> usize {
    //     self.some_count
    // }
    // pub fn is_none(&self, index: usize) -> Result<bool, &'static str> {
    //     Ok(matches!(self.vec[self.map_index(index)?], None))
    // }
    /// Returns `true` if all items are `Some`
    pub fn is_full(&self) -> bool {
        assert!(self.some_count <= self.vec.len());
        self.some_count == self.vec.len()
    }

    pub fn into_hole_vec(self) -> Result<HoleVec<T>, &'static str> {
        if !self.is_full() {
            return Err("hole vec is not full");
        }
        Ok(HoleVec {
            vec: self.vec.into_iter().map(|opt| opt.unwrap()).collect(),
            hole: self.hole,
        })
    }

    pub fn map_index(&self, index: usize) -> Result<usize, &'static str> {
        map_index(index, self.hole, self.vec.len())
    }
}

pub fn new_vec_none<T>(len: usize) -> Vec<Option<T>> {
    (0..len).map(|_| None).collect() // can't use vec![None; capacity] https://users.rust-lang.org/t/how-to-initialize-vec-option-t-with-none/30580/2
}

fn map_index(index: usize, hole: usize, max: usize) -> Result<usize, &'static str> {
    match index {
        i if i < hole => Ok(i),
        i if i > hole && i <= max => Ok(i - 1),
        i if i == hole => Err("index == hole"),
        _ => Err("index out of range"),
    }
}

#[cfg(test)]
mod tests {
    use super::{FillVec2, HoleVec};
    // enable logs in tests
    use tracing_test::traced_test;

    #[test]
    #[traced_test]
    fn basic_correctness() {
        let hole_vec = init_hole_vec().unwrap();
        for c in hole_vec.iter() {
            println!("hole_vec item: {}", c);
        }
    }

    #[test]
    #[traced_test]
    #[should_panic]
    fn override_enumerate() {
        let hole_vec = init_hole_vec().unwrap();

        // should panic
        for (i, c) in hole_vec.iter().enumerate() {
            println!("(i,hole_vec[i]): ({},{})", i, c);
        }
    }

    fn init_hole_vec() -> Result<HoleVec<char>, &'static str> {
        let mut fill_vec = FillVec2::with_len(2, 5)?;
        fill_vec.insert(0, 'A')?;
        fill_vec.insert(1, 'B')?;
        fill_vec.insert(3, 'C')?;
        fill_vec.insert(4, 'D')?;
        assert!(fill_vec.is_full());
        fill_vec.into_hole_vec()
    }
}
