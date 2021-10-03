use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::marker::PhantomData;
use zeroize::Zeroize;

pub struct TypedUsize<K>(usize, PhantomData<K>);

impl<K> TypedUsize<K> {
    pub fn from_usize(index: usize) -> Self {
        TypedUsize(index, PhantomData)
    }

    pub fn as_usize(&self) -> usize {
        self.0
    }

    // Platform-independent byte conversion
    pub fn to_bytes(&self) -> [u8; 8] {
        (self.0 as u64).to_be_bytes()
    }
}

impl<K> Zeroize for TypedUsize<K> {
    fn zeroize(&mut self) {
        self.0.zeroize()
    }
}

// Manual blanket impls for common traits.
// `#[derive(...)]` doesn't work for all `K`:
// * https://stackoverflow.com/a/31371094
// * https://github.com/serde-rs/serde/issues/183#issuecomment-157348366

impl<K> Copy for TypedUsize<K> {}

impl<K> Clone for TypedUsize<K> {
    fn clone(&self) -> Self {
        Self::from_usize(self.0)
    }
}

impl<K> std::fmt::Debug for TypedUsize<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<K> std::fmt::Display for TypedUsize<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl<K> PartialEq for TypedUsize<K> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<K> Serialize for TypedUsize<K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, K> Deserialize<'de> for TypedUsize<K> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Self::from_usize(usize::deserialize(deserializer)?))
    }
}

#[cfg(test)]
mod tests {
    use super::TypedUsize;
    use crate::sdk::implementer_api::{deserialize, serialize};

    struct TestMarker;

    #[test]
    fn serde_bincode() {
        // test: `TypedUsize` and `usize` serialize to the same bytes
        let untyped: usize = 12345678;
        let typed = TypedUsize::<TestMarker>::from_usize(untyped);
        let untyped_bytes = serialize(&untyped).unwrap();
        let typed_bytes = serialize(&typed).unwrap();
        assert_eq!(typed_bytes, untyped_bytes);
        let typed_deserialized: TypedUsize<TestMarker> = deserialize(&typed_bytes).unwrap();
        assert_eq!(typed_deserialized, typed);
        assert_eq!(typed_deserialized.as_usize(), untyped);
    }
}
