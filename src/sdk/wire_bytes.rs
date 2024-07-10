use crate::sdk::api::TofnFatal;
use serde::{de::DeserializeOwned, Serialize};
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

/// Serialize a value using bincode and log errors
pub fn serialize<T: ?Sized + Serialize>(value: &T) -> TofnResult<BytesVec> {
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

#[cfg(test)]
mod tests {
    use bincode::{DefaultOptions, Options};

    use crate::sdk::wire_bytes::{deserialize, serialize, MAX_MSG_LEN};

    #[test]
    fn basic_correctness() {
        let msg = 255u8;
        let encoded_msg = serialize(&msg).unwrap();
        assert_eq!(msg, deserialize::<u8>(&encoded_msg).unwrap());

        let msg = 0xFFFFFFFF_usize;
        let encoded_msg = serialize(&msg).unwrap();
        assert_eq!(msg, deserialize::<usize>(&encoded_msg).unwrap());

        let msg = vec![42u64; 10];
        let encoded_msg = serialize(&msg).unwrap();
        assert_eq!(msg, deserialize::<Vec<u64>>(&encoded_msg).unwrap());
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
