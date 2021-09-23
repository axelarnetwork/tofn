// Domain separation constants for hash function calls
pub const Y_I_COMMIT_TAG: u8 = 0x00;
pub const MTA_PROOF_TAG: u8 = 0x01;
pub const MTA_PROOF_WC_TAG: u8 = 0x02;
pub const RANGE_PROOF_TAG: u8 = 0x03;
pub const RANGE_PROOF_WC_TAG: u8 = 0x04;
pub const CHAUM_PEDERSEN_PROOF_TAG: u8 = 0x05;
pub const PEDERSEN_PROOF_TAG: u8 = 0x06;
pub const SCHNORR_PROOF_TAG: u8 = 0x07;
pub const GAMMA_I_COMMIT_TAG: u8 = 0x08;

#[cfg(test)]
pub const PEDERSEN_SECP256K1_ALTERNATE_GENERATOR_TAG: u8 = 0x09;

pub(crate) const COMPOSITE_DLOG_PROOF_TAG: u8 = 0x0A;
pub(crate) const PAILLIER_KEY_PROOF_TAG: u8 = 0x0B;

// Domain separation for seeding the RNG
pub const KEYPAIR_TAG: u8 = 0x00;
pub const ZKSETUP_TAG: u8 = 0x01;

/// The max size of each prime is 1024 bits.
pub const MODULUS_MAX_SIZE: usize = 2048;

/// The min size of each prime is 1023 bits.
pub const MODULUS_MIN_SIZE: usize = 2046;
