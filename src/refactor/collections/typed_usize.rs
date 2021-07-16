use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct TypedUsize<K>(usize, SerdePhantom<K>);
// where
//     K: Behave;

/// Alias for all the trait bounds on `K` in order to work around https://stackoverflow.com/a/31371094
pub trait Behave: std::fmt::Debug + Clone + Copy + PartialEq + Send + Sync {}

impl<K> TypedUsize<K>
// where
//     K: Behave,
{
    pub fn from_usize(index: usize) -> Self {
        TypedUsize(index, SerdePhantom(PhantomData))
    }
    pub fn as_usize(&self) -> usize {
        self.0
    }
}

impl<K> std::fmt::Display for TypedUsize<K>
// where
//     K: Behave,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// `PhantomData` does not impl `Serialize`, `Deserialize`
/// https://github.com/serde-rs/serde/issues/183
/// The solution is to wrap `PhantomData` in a newtype `SerdePhantom`
/// and manually impl these traits for `SerdePhantom`.
use serde::{de, de::Visitor, Deserializer, Serializer};

// `PhantomData` derives the following traits, so we can, too.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    Eq,
    Hash,
    Ord,
    PartialEq,
    PartialOrd,
    // StructuralEq,        // unstable
    // StructuralPartialEq, // unstable
)]
pub struct SerdePhantom<K>(PhantomData<K>);

impl<K> Serialize for SerdePhantom<K> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_unit()
    }
}

impl<'de, K> Deserialize<'de> for SerdePhantom<K> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_unit(MyPhantomVisitor(PhantomData))
    }
}

struct MyPhantomVisitor<K>(PhantomData<K>); // need to use `K` somewhere

impl<'de, K> Visitor<'de> for MyPhantomVisitor<K> {
    type Value = SerdePhantom<K>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("unit type `()`")
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(SerdePhantom(PhantomData))
    }
}

#[cfg(test)]
mod tests {
    use super::{Behave, SerdePhantom, TypedUsize};
    use serde::{Deserialize, Serialize};
    use std::marker::PhantomData;

    #[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
    struct TestMarker;
    impl Behave for TestMarker {}

    #[test]
    fn serde_bincode() {
        // test: `MyPhantom` serializes to a zero-length byte vec
        let phantom = SerdePhantom::<TestMarker>(PhantomData);
        let bytes = bincode::serialize(&phantom).unwrap();
        assert_eq!(bytes, Vec::<u8>::new());
        let phantom_deserialized: SerdePhantom<TestMarker> = bincode::deserialize(&bytes).unwrap();
        assert_eq!(phantom_deserialized, phantom);

        // test: `TypedUsize` and `usize` serialize to the same bytes
        let untyped: usize = 12345678;
        let typed = TypedUsize::<TestMarker>::from_usize(untyped);
        let untyped_bytes = bincode::serialize(&untyped).unwrap();
        let typed_bytes = bincode::serialize(&typed).unwrap();
        assert_eq!(typed_bytes, untyped_bytes);
        let typed_deserialized: TypedUsize<TestMarker> =
            bincode::deserialize(&typed_bytes).unwrap();
        assert_eq!(typed_deserialized, typed);
        assert_eq!(typed_deserialized.as_usize(), untyped);
    }
}
