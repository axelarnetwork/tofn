use crate::{collections::TypedUsize, sdk::api::TofnFatal};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tracing::{error, warn};

use super::api::{BytesVec, TofnResult};
use bincode::{
    config::{
        BigEndian, Bounded, RejectTrailing, VarintEncoding, WithOtherEndian, WithOtherIntEncoding,
        WithOtherLimit, WithOtherTrailing,
    },
    DefaultOptions, Options,
};

/// Max message length allowed to be (de)serialized
const MAX_MSG_LEN: u64 = 1000 * 1000; // 1 MB

/// Tofn version for serialized data.
const TOFN_SERIALIZATION_VERSION: u16 = 0;

pub fn encode_message<K>(
    payload: BytesVec,
    from: TypedUsize<K>,
    msg_type: MsgType<K>,
    expected_msg_types: ExpectedMsgTypes,
) -> TofnResult<BytesVec> {
    encode(&WireBytes {
        msg_type,
        from,
        payload,
        expected_msg_types,
    })
}

/// Encode a value of generic type `T` with versioning
pub fn encode<T: Serialize>(payload: &T) -> TofnResult<BytesVec> {
    serialize(&BytesVecVersioned {
        version: TOFN_SERIALIZATION_VERSION,
        payload: serialize(payload)?,
    })
}

/// Serialize a value using bincode and log errors
pub fn serialize<T: ?Sized>(value: &T) -> TofnResult<BytesVec>
where
    T: serde::Serialize,
{
    let bincode = bincoder();

    bincode.serialize(value).map_err(|err| {
        error!("serialization failure: {}", err.to_string());
        TofnFatal
    })
}

/// Deserialize bytes to a type using bincode and log errors.
/// Return an Option type since deserialization isn't treated as a Fatal error
/// in tofn (for the purposes of fault identification).
pub fn deserialize<T: DeserializeOwned>(bytes: &[u8]) -> Option<T> {
    let bincode = bincoder();

    bincode
        .deserialize(bytes)
        .map_err(|err| {
            warn!("deserialization failure: {}", err.to_string());
        })
        .ok()
}

/// Decode a versioned byte array to a value of generic type `T`
/// Note that deserialization failures are non-fatal: do not return TofnResult
pub fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Option<T> {
    let bytes_versioned: BytesVecVersioned = deserialize(bytes).or_else(|| {
        warn!("outer deserialization failure");
        None
    })?;

    if bytes_versioned.version != TOFN_SERIALIZATION_VERSION {
        warn!(
            "encoding version {}, expected {}",
            bytes_versioned.version, TOFN_SERIALIZATION_VERSION
        );
        return None;
    }

    deserialize(&bytes_versioned.payload).or_else(|| {
        warn!("inner deserialization failure");
        None
    })
}

pub fn decode_message<K>(bytes: &[u8]) -> Option<WireBytes<K>> {
    decode(bytes)
}

/// Prepare a `bincode` serde backend with our preferred config
/// (wow, that return type is ugly)
#[allow(clippy::type_complexity)]
fn bincoder() -> WithOtherTrailing<
    WithOtherIntEncoding<
        WithOtherEndian<WithOtherLimit<DefaultOptions, Bounded>, BigEndian>,
        VarintEncoding,
    >,
    RejectTrailing,
> {
    DefaultOptions::new()
        .with_limit(MAX_MSG_LEN)
        .with_big_endian() // do not ignore extra bytes at the end of the buffer
        .with_varint_encoding() // saves a lot of space in smaller messages
        .reject_trailing_bytes() // do not ignore extra bytes at the end of the buffer
}

#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))] // disable serde trait bounds on `K`: https://serde.rs/attr-bound.html
pub struct WireBytes<K> {
    pub msg_type: MsgType<K>,
    pub from: TypedUsize<K>,
    pub payload: BytesVec,
    pub expected_msg_types: ExpectedMsgTypes,
}

// TODO serde can derive Serialize for structs with a type parameter.
// But I cannot derive Debug for these types unless `K: Debug`. How does serde do it?
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(bound(serialize = "", deserialize = ""))] // disable serde trait bounds on `K`: https://serde.rs/attr-bound.html
pub enum MsgType<K> {
    Bcast,
    P2p { to: TypedUsize<K> },
    TotalShareCount1P2pOnly, // special case: used only when total_share_count is 1
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ExpectedMsgTypes {
    BcastAndP2p,
    BcastOnly,
    P2pOnly,
}

#[derive(Serialize, Deserialize)]
struct BytesVecVersioned {
    version: u16,
    payload: BytesVec,
}

#[cfg(test)]
mod tests {
    use bincode::{DefaultOptions, Options};

    use crate::sdk::wire_bytes::{decode, deserialize, encode, serialize, MAX_MSG_LEN};

    #[test]
    fn basic_correctness() {
        let msg = 255u8;
        let encoded_msg = encode(&msg).unwrap();
        assert_eq!(msg, decode::<u8>(&encoded_msg).unwrap());

        let msg = 0xFFFFFFFF_usize;
        let encoded_msg = encode(&msg).unwrap();
        assert_eq!(msg, decode::<usize>(&encoded_msg).unwrap());

        let msg = vec![42u64; 10];
        let encoded_msg = encode(&msg).unwrap();
        assert_eq!(msg, decode::<Vec<u64>>(&encoded_msg).unwrap());
    }

    #[test]
    fn large_message() {
        // 5 bytes for length, and 1 byte for each int
        let msg = vec![42u64; (MAX_MSG_LEN as usize) - 5];
        let encoded_msg = serialize(&msg).unwrap();
        assert_eq!(msg, deserialize::<Vec<u64>>(&encoded_msg).unwrap());

        // 5 bytes for length, 1 byte for version, and 1 byte for each int
        let msg = vec![42u64; (MAX_MSG_LEN as usize) - 11];
        let encoded_msg = encode(&msg).unwrap();
        assert_eq!(msg, decode::<Vec<u64>>(&encoded_msg).unwrap());
    }

    #[test]
    fn serialization_checks() {
        // Fail to serialize a large message
        let msg = vec![0; (MAX_MSG_LEN - 2) as usize]; // 2 bytes for length
        assert!(serialize(&msg).is_err());

        // Fail to deserialize a buffer with extra bytes
        let mut encoded_msg = serialize(&2_u8).unwrap();
        encoded_msg.extend_from_slice(&[42u8]);
        let res: Option<u8> = deserialize(&encoded_msg);
        assert!(res.is_none());

        // Fail to deserialize a large buffer
        let options = DefaultOptions::new()
            .with_big_endian()
            .with_varint_encoding();
        let encoded_msg = options
            .serialize(&[42; (MAX_MSG_LEN as usize) + 1][..])
            .unwrap();
        let res: Option<u8> = deserialize(&encoded_msg);
        assert!(res.is_none());
    }
}

#[cfg(feature = "malicious")]
pub mod malicious {
    use tracing::error;

    use crate::sdk::api::{BytesVec, TofnFatal, TofnResult};

    use super::{decode_message, encode_message, WireBytes};

    pub fn corrupt_payload<K>(bytes: &[u8]) -> TofnResult<BytesVec> {
        // for simplicity, deserialization error is treated as fatal
        // (we're in a malicious module so who cares?)
        let wire_bytes: WireBytes<K> = decode_message(bytes).ok_or_else(|| {
            error!("can't corrupt payload: deserialization failure");
            TofnFatal
        })?;

        encode_message(
            b"these bytes are corrupted 1234".to_vec(),
            wire_bytes.from,
            wire_bytes.msg_type,
            wire_bytes.expected_msg_types,
        )
    }
}
