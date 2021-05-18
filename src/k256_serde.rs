//! serde support for k256
//!
//! ## References
//!
//! [Implementing Serialize · Serde](https://serde.rs/impl-serialize.html)
//! [Implementing Deserialize · Serde](https://serde.rs/impl-deserialize.html)

use k256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use serde::{de, de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

/// newtype wrapper for k256::AffinePoint
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct AffinePoint(k256::AffinePoint);

/// impl `Deref` as a workaround for lack of delegation in Rust
impl std::ops::Deref for AffinePoint {
    type Target = k256::AffinePoint;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

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
            .ok_or(E::custom(
                "SEC1-encoded point is not on curve secp256k (K-256)",
            ))?,
        ))
    }
}

/// newtype wrapper for k256::ProjectivePoint
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct ProjectivePoint(k256::ProjectivePoint);

/// impl `Deref` as a workaround for lack of delegation in Rust
impl std::ops::Deref for ProjectivePoint {
    type Target = k256::ProjectivePoint;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<k256::ProjectivePoint> for ProjectivePoint {
    fn from(s: k256::ProjectivePoint) -> Self {
        ProjectivePoint(s)
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

/// Trying to make this look like a method of k256::ProjectivePoint
/// Unfortunately, `p.into().bytes()` needs type annotations
impl ProjectivePoint {
    pub(crate) fn bytes(&self) -> Vec<u8> {
        self.0
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }
}

pub(crate) fn to_bytes(p: &k256::ProjectivePoint) -> Vec<u8> {
    p.to_affine().to_encoded_point(true).as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use k256::elliptic_curve::Field;

    #[test]
    fn basic_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let a = super::AffinePoint(
            k256::AffinePoint::generator() * k256::NonZeroScalar::random(rand::thread_rng()),
        );
        let a_serialized = bincode::serialize(&a)?;
        let a_deserialized = bincode::deserialize(&a_serialized)?;
        assert_eq!(a, a_deserialized);

        let p = super::ProjectivePoint(
            k256::ProjectivePoint::generator() * k256::Scalar::random(rand::thread_rng()),
        );
        let p_serialized = bincode::serialize(&p)?;
        let p_deserialized = bincode::deserialize(&p_serialized)?;
        assert_eq!(p, p_deserialized);
        Ok(())
    }
}
