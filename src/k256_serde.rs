//! serde support for k256
//!
//! ## References
//!
//! [Implementing Serialize · Serde](https://serde.rs/impl-serialize.html)
//! [Implementing Deserialize · Serde](https://serde.rs/impl-deserialize.html)

use k256::elliptic_curve::sec1::FromEncodedPoint;
use serde::{de, de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

/// newtype wrapper for k256::AffinePoint
#[derive(Debug, PartialEq)]
struct AffinePoint(k256::AffinePoint);

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

#[cfg(test)]
mod tests {
    #[test]
    fn basic_round_trip() -> Result<(), Box<dyn std::error::Error>> {
        let random_point = super::AffinePoint(
            k256::AffinePoint::generator() * k256::NonZeroScalar::random(rand::thread_rng()),
        );
        let random_point_serialized = bincode::serialize(&random_point)?;
        let random_point_deserialized = bincode::deserialize(&random_point_serialized)?;
        assert_eq!(random_point, random_point_deserialized);
        Ok(())
    }
}
