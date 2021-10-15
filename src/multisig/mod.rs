pub mod keygen;
pub mod sign;

// Domain separation for seeding the RNG
const KEYGEN_TAG: u8 = 0x00;
const SIGN_TAG: u8 = 0x01;
