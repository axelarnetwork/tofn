// Domain separation constants for hash function calls
pub(crate) const Y_I_COMMIT_TAG: u8 = 0x00;
pub(crate) const MTA_PROOF_TAG: u8 = 0x01;
pub(crate) const MTA_PROOF_WC_TAG: u8 = 0x02;
pub(crate) const RANGE_PROOF_TAG: u8 = 0x03;
pub(crate) const RANGE_PROOF_WC_TAG: u8 = 0x04;
pub(crate) const CHAUM_PEDERSEN_PROOF_TAG: u8 = 0x05;
pub(crate) const PEDERSEN_PROOF_TAG: u8 = 0x06;
pub(crate) const SCHNORR_PROOF_TAG: u8 = 0x07;
pub(crate) const GAMMA_I_COMMIT_TAG: u8 = 0x08;

#[cfg(test)]
pub(crate) const PEDERSEN_SECP256K1_ALTERNATE_GENERATOR_TAG: u8 = 0x09;

// Domain separation for seeding the RNG
pub(crate) const KEYPAIR_TAG: u8 = 0x00;
pub(crate) const ZKSETUP_TAG: u8 = 0x01;
