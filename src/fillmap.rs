//! A fillable HashMap
use std::{
    cmp::Eq,
    collections::HashMap,
    fmt::{self, Debug, Display},
    hash::Hash,
    iter::FromIterator
};

#[derive(Debug, Clone)]
pub struct FillMap<K,V> {
    map: HashMap<K,Option<V>>,
    len: usize,
}

#[derive(Debug)]
pub enum FillMapError<K> {
    KeyNotExists(K),
    ValueAlreadySet(K),
}

type Result<T,K> = std::result::Result<T, FillMapError<K>>;

impl<K,V> FromIterator<K> for FillMap<K,V>
where
    K: Hash + Eq
{
    fn from_iter<I: IntoIterator<Item=K>>(iter: I) -> Self {
        FillMap {
            map: iter.into_iter().map(|k| (k,None)).collect(),
            len: 0,
        }
    }
}

impl<K,V> FillMap<K,V>
where
    K: Hash + Eq + Clone
{
    pub fn insert(&mut self, k: K, v: V) -> Result<(),K> {
        let stored = self.map.get_mut(&k);
        let stored = match stored {
            None => return Err(FillMapError::KeyNotExists(k)),
            Some(o) => o,
        };
        if stored.is_some() {
            return Err(FillMapError::ValueAlreadySet(k));
        }
        *stored = Some(v);
        self.len += 1;
        Ok(())
    }
    pub fn into_hashmap(self) -> HashMap<K,V> {
        self.map.into_iter()
            .filter( |(_,v)| v.is_some() ) // remove unset entries
            .map( |(k,v)| (k,v.unwrap()) )
            .collect()
    }
    pub fn len(&self) -> usize { self.len }
    pub fn is_empty(&self) -> bool { self.len == 0 }
    pub fn is_full(&self) -> bool { self.len == self.map.len() }
}

impl<K: Debug> std::error::Error for FillMapError<K> {}
impl<K: Debug> Display for FillMapError<K> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
          FillMapError::KeyNotExists(k) => write!(f, "key {:?} does not exist", k),
          FillMapError::ValueAlreadySet(k) => write!(f, "value already set for key {:?}", k)
        }
      }
}