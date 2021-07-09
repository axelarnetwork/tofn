pub type TofnResult<T> = Result<T, String>;
pub type BytesVec = Vec<u8>;
pub mod keygen;
pub mod protocol;
pub mod protocol_round;
