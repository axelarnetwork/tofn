//! serde support for k256
//!
//! ## References
//!
//! [Implementing Serialize · Serde](https://serde.rs/impl-serialize.html)
//! [Implementing Deserialize · Serde](https://serde.rs/impl-deserialize.html)

use ecdsa::elliptic_curve::Field;
use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use serde::{de, de::Error, de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

use crate::sdk::api::BytesVec;

/// A wrapper for a random scalar value that is zeroized on drop
/// TODO why not just do this for Scalar below?
#[derive(Debug, Zeroize)]
#[zeroize(drop)]
pub struct RandomScalar(k256::Scalar);

impl AsRef<k256::Scalar> for RandomScalar {
    fn as_ref(&self) -> &k256::Scalar {
        &self.0
    }
}

impl RandomScalar {
    /// Generate a random k256 Scalar
    pub fn generate() -> Self {
        Self(k256::Scalar::random(rand::thread_rng()))
    }
}

#[derive(Clone, Debug, PartialEq, Zeroize)]
pub struct Scalar(k256::Scalar);

impl AsRef<k256::Scalar> for Scalar {
    fn as_ref(&self) -> &k256::Scalar {
        &self.0
    }
}

#[cfg(feature = "malicious")]
impl AsMut<k256::Scalar> for Scalar {
    fn as_mut(&mut self) -> &mut k256::Scalar {
        &mut self.0
    }
}

impl From<k256::Scalar> for Scalar {
    fn from(s: k256::Scalar) -> Self {
        Scalar(s)
    }
}

impl Serialize for Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let bytes: [u8; 32] = self.0.to_bytes().into();
        bytes.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes: [u8; 32] = Deserialize::deserialize(deserializer)?;
        let field_bytes = k256::FieldBytes::from(bytes);
        let scalar = k256::Scalar::from_bytes_reduced(&field_bytes);

        // ensure bytes encodes an integer less than the secp256k1 modulus
        // if not then scalar.to_bytes() will differ from bytes
        if field_bytes != scalar.to_bytes() {
            return Err(D::Error::custom("integer exceeds secp256k1 modulus"));
        }

        Ok(Scalar(scalar))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Signature(k256::ecdsa::Signature);

impl AsRef<k256::ecdsa::Signature> for Signature {
    fn as_ref(&self) -> &k256::ecdsa::Signature {
        &self.0
    }
}

impl From<k256::ecdsa::Signature> for Signature {
    fn from(s: k256::ecdsa::Signature) -> Self {
        Signature(s)
    }
}

impl Serialize for Signature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.as_ref().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Signature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(Signature(
            <k256::ecdsa::Signature as ecdsa::signature::Signature>::from_bytes(
                Deserialize::deserialize(deserializer)?,
            )
            .map_err(D::Error::custom)?,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Zeroize)]
struct EncodedPoint(k256::EncodedPoint);

impl Serialize for EncodedPoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.0.as_bytes())
    }
}

impl<'de> Deserialize<'de> for EncodedPoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(EncodedPointVisitor)
    }
}

struct EncodedPointVisitor;

impl<'de> Visitor<'de> for EncodedPointVisitor {
    type Value = EncodedPoint;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("SEC1-encoded secp256k1 (K-256) curve point")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(EncodedPoint(
            k256::EncodedPoint::from_bytes(v).map_err(E::custom)?,
        ))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProjectivePoint(k256::ProjectivePoint);

// TODO delete bytes, from_bytes and prefer our bincode wrapper
impl ProjectivePoint {
    /// Trying to make this look like a method of k256::ProjectivePoint
    /// Unfortunately, `p.into().bytes()` needs type annotations
    pub fn bytes(&self) -> BytesVec {
        self.0
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Some(Self(k256::ProjectivePoint::from_encoded_point(
            &k256::EncodedPoint::from_bytes(bytes).ok()?,
        )?))
    }
}

impl AsRef<k256::ProjectivePoint> for ProjectivePoint {
    fn as_ref(&self) -> &k256::ProjectivePoint {
        &self.0
    }
}

#[cfg(feature = "malicious")]
impl AsMut<k256::ProjectivePoint> for ProjectivePoint {
    fn as_mut(&mut self) -> &mut k256::ProjectivePoint {
        &mut self.0
    }
}

pub fn to_bytes(p: &k256::ProjectivePoint) -> BytesVec {
    p.to_affine().to_encoded_point(true).as_bytes().to_vec()
}

impl From<k256::ProjectivePoint> for ProjectivePoint {
    fn from(p: k256::ProjectivePoint) -> Self {
        ProjectivePoint(p)
    }
}

impl From<&k256::ProjectivePoint> for ProjectivePoint {
    fn from(p: &k256::ProjectivePoint) -> Self {
        ProjectivePoint(*p)
    }
}

impl Serialize for ProjectivePoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        EncodedPoint(self.0.to_encoded_point(true)).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProjectivePoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(ProjectivePoint(
            k256::ProjectivePoint::from_encoded_point(&EncodedPoint::deserialize(deserializer)?.0)
                .ok_or_else(|| {
                    D::Error::custom("SEC1-encoded point is not on curve secp256k (K-256)")
                })?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use super::*;
    use bincode::Options;
    use k256::elliptic_curve::Field;
    use serde::de::DeserializeOwned;

    #[test]
    fn basic_round_trip() {
        let s = k256::Scalar::random(rand::thread_rng());
        basic_round_trip_impl::<_, Scalar>(s, Some(32));

        let p = k256::ProjectivePoint::generator() * s;
        basic_round_trip_impl::<_, ProjectivePoint>(p, None);
    }

    fn basic_round_trip_impl<T, U>(val: T, size: Option<usize>)
    where
        U: From<T> + Serialize + DeserializeOwned + PartialEq + Debug,
    {
        let bincode = bincode::DefaultOptions::new();

        let v = U::from(val);
        let v_serialized = bincode.serialize(&v).unwrap();
        if let Some(size) = size {
            assert_eq!(v_serialized.len(), size);
        }
        let v_deserialized = bincode.deserialize(&v_serialized).unwrap();
        assert_eq!(v, v_deserialized);
    }

    #[test]
    fn scalar_deserialization_fail() {
        let s = Scalar(k256::Scalar::random(rand::thread_rng()));
        scalar_deserialization_fail_impl(s);
    }

    fn scalar_deserialization_fail_impl<S>(scalar: S)
    where
        S: Serialize + DeserializeOwned + Debug,
    {
        let bincode = bincode::DefaultOptions::new();

        // test too few bytes
        let mut too_few_bytes = bincode.serialize(&scalar).unwrap();
        too_few_bytes.pop();
        bincode.deserialize::<S>(&too_few_bytes).unwrap_err();

        // test too many bytes
        let mut too_many_bytes = bincode.serialize(&scalar).unwrap();
        too_many_bytes.push(42);
        bincode.deserialize::<S>(&too_many_bytes).unwrap_err();

        let mut modulus: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ]; // secp256k1 modulus

        // test edge case: integer too large
        bincode.deserialize::<S>(&modulus).unwrap_err();

        // test edge case: integer not too large
        modulus[31] -= 1;
        bincode.deserialize::<S>(&modulus).unwrap();
    }
}
