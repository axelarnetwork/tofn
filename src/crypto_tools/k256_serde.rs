//! serde support for k256
//!
//! ## References
//!
//! [Implementing Serialize · Serde](https://serde.rs/impl-serialize.html)
//! [Implementing Deserialize · Serde](https://serde.rs/impl-deserialize.html)

use ecdsa::elliptic_curve::Field;
use k256::{
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    EncodedPoint,
};
use serde::{de, de::Error, de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroize;

use crate::sdk::api::BytesVec;

/// A wrapper for a random scalar value that is zeroized on drop
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

#[derive(Clone, Debug, PartialEq, Zeroize)]
struct AffinePoint(k256::AffinePoint);

impl Serialize for AffinePoint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(k256::EncodedPoint::from(self.0).as_bytes())
    }
}

impl<'de> Deserialize<'de> for AffinePoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(AffinePointVisitor)
    }
}

struct AffinePointVisitor;

impl<'de> Visitor<'de> for AffinePointVisitor {
    type Value = AffinePoint;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("SEC1-encoded secp256k1 (K-256) curve point")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(AffinePoint(
            k256::AffinePoint::from_encoded_point(
                &k256::EncodedPoint::from_bytes(v).map_err(E::custom)?,
            )
            .ok_or_else(|| E::custom("SEC1-encoded point is not on curve secp256k (K-256)"))?,
        ))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct ProjectivePoint(k256::ProjectivePoint);

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
            &EncodedPoint::from_bytes(bytes).ok()?,
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
        AffinePoint(self.0.to_affine()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProjectivePoint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(ProjectivePoint(
            AffinePoint::deserialize(deserializer)?.0.into(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct VerifyingKey(k256::ecdsa::VerifyingKey);

impl VerifyingKey {
    /// Trying to make this look like a method of k256::ProjectivePoint
    /// Unfortunately, `p.into().bytes()` needs type annotations
    pub fn bytes(&self) -> BytesVec {
        self.0.to_encoded_point(true).as_bytes().to_vec()
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        Some(Self(
            k256::ecdsa::VerifyingKey::from_encoded_point(&EncodedPoint::from_bytes(bytes).ok()?)
                .ok()?,
        ))
    }
}

impl AsRef<k256::ecdsa::VerifyingKey> for VerifyingKey {
    fn as_ref(&self) -> &k256::ecdsa::VerifyingKey {
        &self.0
    }
}

impl From<k256::ecdsa::VerifyingKey> for VerifyingKey {
    fn from(p: k256::ecdsa::VerifyingKey) -> Self {
        VerifyingKey(p)
    }
}

impl From<&k256::ecdsa::VerifyingKey> for VerifyingKey {
    fn from(p: &k256::ecdsa::VerifyingKey) -> Self {
        VerifyingKey(*p)
    }
}

impl Serialize for VerifyingKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(self.0.to_encoded_point(true).as_bytes())
    }
}

impl<'de> Deserialize<'de> for VerifyingKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // TODO this is a mess.  need to go through AffinePoint to check curve equation (I think?).
        Ok(VerifyingKey(
            k256::ecdsa::VerifyingKey::from_encoded_point(
                &AffinePoint::deserialize(deserializer)?
                    .0
                    .to_encoded_point(false),
            )
            .map_err(D::Error::custom)?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bincode::Options;
    use ecdsa::elliptic_curve::group::prime::PrimeCurveAffine;
    use k256::elliptic_curve::Field;

    #[test]
    fn basic_round_trip() {
        let bincode = bincode::DefaultOptions::new();

        // scalar
        let s = Scalar(k256::Scalar::random(rand::thread_rng()));
        let s_serialized = bincode.serialize(&s).unwrap();
        assert_eq!(s_serialized.len(), 32);
        let s_deserialized = bincode.deserialize(&s_serialized).unwrap();
        assert_eq!(s, s_deserialized);

        // affine point
        let a = AffinePoint(
            (k256::AffinePoint::generator() * k256::Scalar::random(rand::thread_rng())).to_affine(),
        );
        let a_serialized = bincode.serialize(&a).unwrap();
        let a_deserialized = bincode.deserialize(&a_serialized).unwrap();
        assert_eq!(a, a_deserialized);

        // projective point
        let p = ProjectivePoint(
            k256::ProjectivePoint::generator() * k256::Scalar::random(rand::thread_rng()),
        );
        let p_serialized = bincode.serialize(&p).unwrap();
        let p_deserialized = bincode.deserialize(&p_serialized).unwrap();
        assert_eq!(p, p_deserialized);

        // verifying key
        let s = k256::ecdsa::SigningKey::random(rand::thread_rng());
        let v = VerifyingKey(k256::ecdsa::VerifyingKey::from(s));
        let v_serialized = bincode.serialize(&v).unwrap();
        let v_deserialized = bincode.deserialize(&v_serialized).unwrap();
        assert_eq!(v, v_deserialized);
    }

    #[test]
    fn scalar_deserialization_fail() {
        let bincode = bincode::DefaultOptions::new();
        let s = Scalar(k256::Scalar::random(rand::thread_rng()));

        // test too few bytes
        let mut too_few_bytes = bincode.serialize(&s).unwrap();
        too_few_bytes.pop();
        bincode.deserialize::<Scalar>(&too_few_bytes).unwrap_err();

        // test too many bytes
        let mut too_many_bytes = bincode.serialize(&s).unwrap();
        too_many_bytes.push(42);
        bincode.deserialize::<Scalar>(&too_many_bytes).unwrap_err();

        let mut modulus: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ]; // secp256k1 modulus

        // test edge case: integer too large
        bincode.deserialize::<Scalar>(&modulus).unwrap_err();

        // test edge case: integer not too large
        modulus[31] -= 1;
        bincode.deserialize::<Scalar>(&modulus).unwrap();
    }
}
