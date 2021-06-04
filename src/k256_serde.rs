//! serde support for k256
//!
//! ## References
//!
//! [Implementing Serialize · Serde](https://serde.rs/impl-serialize.html)
//! [Implementing Deserialize · Serde](https://serde.rs/impl-deserialize.html)

use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use serde::{de, de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

#[derive(Clone, Debug, PartialEq)]
pub struct Scalar(k256::Scalar);

impl Scalar {
    pub fn unwrap(&self) -> &k256::Scalar {
        &self.0
    }

    // clippy appeasement: unwrap_mut currently used only in malicious mode
    #[cfg(feature = "malicious")]
    pub fn unwrap_mut(&mut self) -> &mut k256::Scalar {
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
        serializer.serialize_bytes(self.0.to_bytes().as_slice())
    }
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_bytes(ScalarVisitor)
    }
}

struct ScalarVisitor;

impl<'de> Visitor<'de> for ScalarVisitor {
    type Value = Scalar;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("SEC1-encoded secp256k1 (K-256) scalar")
    }

    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if v.len() != 32 {
            return Err(E::custom(format!(
                "invalid bytes length; expect 32, got {}",
                v.len()
            )));
        }
        Ok(Scalar(k256::Scalar::from_bytes_reduced(
            k256::FieldBytes::from_slice(v),
        )))
    }
}

#[derive(Clone, Debug, PartialEq)]
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
    pub fn unwrap(&self) -> &k256::ProjectivePoint {
        &self.0
    }

    /// Trying to make this look like a method of k256::ProjectivePoint
    /// Unfortunately, `p.into().bytes()` needs type annotations
    pub fn bytes(&self) -> Vec<u8> {
        self.0
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }
}

pub fn to_bytes(p: &k256::ProjectivePoint) -> Vec<u8> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::Field;

    #[test]
    fn basic_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let s = Scalar(k256::Scalar::random(rand::thread_rng()));
        let s_serialized = bincode::serialize(&s)?;
        let s_deserialized = bincode::deserialize(&s_serialized)?;
        assert_eq!(s, s_deserialized);

        let a = AffinePoint(
            k256::AffinePoint::generator() * k256::NonZeroScalar::random(rand::thread_rng()),
        );
        let a_serialized = bincode::serialize(&a)?;
        let a_deserialized = bincode::deserialize(&a_serialized)?;
        assert_eq!(a, a_deserialized);

        let p = ProjectivePoint(
            k256::ProjectivePoint::generator() * k256::Scalar::random(rand::thread_rng()),
        );
        let p_serialized = bincode::serialize(&p)?;
        let p_deserialized = bincode::deserialize(&p_serialized)?;
        assert_eq!(p, p_deserialized);

        Ok(())
    }
}
