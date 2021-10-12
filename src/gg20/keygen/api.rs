use super::r1;
use crate::{
    collections::TypedUsize,
    crypto_tools::{
        paillier::{
            self,
            zk::{EncryptionKeyProof, ZkSetup, ZkSetupProof},
            DecryptionKey, EncryptionKey,
        },
        rng,
    },
    gg20::constants::{KEYPAIR_TAG, ZKSETUP_TAG},
    sdk::{
        api::{PartyShareCounts, Protocol, TofnFatal, TofnResult},
        implementer_api::{new_protocol, ProtocolBuilder},
    },
};
use serde::{Deserialize, Serialize};
use tracing::error;
use zeroize::Zeroize;

#[cfg(feature = "malicious")]
use super::malicious;

/// Maximum byte length of messages exchanged during keygen.
/// The sender of a message larger than this maximum will be accused as a faulter.
/// View all message sizes in the logs of the integration test `single_thred::basic_correctness`.
/// The largest keygen message is r1::Bcast with size ~4833 bytes on the wire.
/// There is also a variable-sized message in r2::Bcast that depends on the
/// threshold: 34t + 73. For t = 100, this is still smaller than the limit.
/// See https://github.com/axelarnetwork/tofn/issues/171
pub const MAX_MSG_LEN: usize = 5500;

pub use super::secret_key_share::*;
pub use rng::SecretRecoveryKey;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct KeygenShareId;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct KeygenPartyId;

pub type KeygenProtocol = Protocol<SecretKeyShare, KeygenShareId, KeygenPartyId, MAX_MSG_LEN>;
pub type KeygenProtocolBuilder = ProtocolBuilder<SecretKeyShare, KeygenShareId>;
pub type KeygenPartyShareCounts = PartyShareCounts<KeygenPartyId>;

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct PartyKeyPair {
    pub(super) ek: EncryptionKey,
    pub(super) dk: DecryptionKey,
}

#[derive(Debug, Clone)]
pub struct PartyKeygenData {
    pub(super) encryption_keypair: PartyKeyPair,
    pub(super) encryption_keypair_proof: EncryptionKeyProof,
    pub(super) zk_setup: ZkSetup,
    pub(super) zk_setup_proof: ZkSetupProof,
}

// Since safe prime generation is expensive, a party is expected to generate
// a keypair once for all it's shares and provide it to new_keygen
pub fn create_party_keypair_and_zksetup(
    my_party_id: TypedUsize<KeygenPartyId>,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<PartyKeygenData> {
    let encryption_keypair =
        recover_party_keypair(my_party_id, secret_recovery_key, session_nonce)?;

    let encryption_keypair_proof = encryption_keypair
        .ek
        .correctness_proof(&encryption_keypair.dk, &my_party_id.to_bytes());

    let mut zksetup_rng =
        rng::rng_seed(ZKSETUP_TAG, my_party_id, secret_recovery_key, session_nonce)?;
    let (zk_setup, zk_setup_proof) = ZkSetup::new(&mut zksetup_rng, &my_party_id.to_bytes())?;

    Ok(PartyKeygenData {
        encryption_keypair,
        encryption_keypair_proof,
        zk_setup,
        zk_setup_proof,
    })
}

pub fn recover_party_keypair(
    my_party_id: TypedUsize<KeygenPartyId>,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<PartyKeyPair> {
    let mut rng = rng::rng_seed(KEYPAIR_TAG, my_party_id, secret_recovery_key, session_nonce)?;

    let (ek, dk) = paillier::keygen(&mut rng)?;

    Ok(PartyKeyPair { ek, dk })
}

// BEWARE: This is only made visible for faster integration testing
pub fn create_party_keypair_and_zksetup_unsafe(
    my_party_id: TypedUsize<KeygenPartyId>,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<PartyKeygenData> {
    let encryption_keypair =
        recover_party_keypair_unsafe(my_party_id, secret_recovery_key, session_nonce)?;

    let encryption_keypair_proof = encryption_keypair
        .ek
        .correctness_proof(&encryption_keypair.dk, &my_party_id.to_bytes());

    let mut zksetup_rng =
        rng::rng_seed(ZKSETUP_TAG, my_party_id, secret_recovery_key, session_nonce)?;
    let (zk_setup, zk_setup_proof) =
        ZkSetup::new_unsafe(&mut zksetup_rng, &my_party_id.to_bytes())?;

    Ok(PartyKeygenData {
        encryption_keypair,
        encryption_keypair_proof,
        zk_setup,
        zk_setup_proof,
    })
}

// BEWARE: This is only made visible for faster integration testing
pub fn recover_party_keypair_unsafe(
    my_party_id: TypedUsize<KeygenPartyId>,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<PartyKeyPair> {
    let mut rng = rng::rng_seed(KEYPAIR_TAG, my_party_id, secret_recovery_key, session_nonce)?;

    let (ek, dk) = paillier::keygen_unsafe(&mut rng)?;

    Ok(PartyKeyPair { ek, dk })
}

// Can't define a keygen-specific alias for `RoundExecuter` that sets
// `FinalOutputTyped = KeygenOutput` and `Index = KeygenPartyIndex`
// because https://github.com/rust-lang/rust/issues/41517

// TODO use const generics for these bounds
pub const MAX_TOTAL_SHARE_COUNT: usize = 1000;
pub const MAX_PARTY_SHARE_COUNT: usize = MAX_TOTAL_SHARE_COUNT;

// BEWARE: This is only made visible for faster integration testing
// TODO: Use a better way to hide this from the API, while allowing it for integration tests
// since #[cfg(tests)] only works for unit tests

/// Initialize a new keygen protocol
#[allow(clippy::too_many_arguments)]
pub fn new_keygen(
    party_share_counts: KeygenPartyShareCounts,
    threshold: usize,
    my_party_id: TypedUsize<KeygenPartyId>,
    my_subshare_id: usize, // in 0..party_share_counts[my_party_id]
    party_keygen_data: &PartyKeygenData,
    #[cfg(feature = "malicious")] behaviour: malicious::Behaviour,
) -> TofnResult<KeygenProtocol> {
    // validate args
    if party_share_counts
        .iter()
        .any(|(_, &c)| c > MAX_PARTY_SHARE_COUNT)
    {
        error!(
            "detected a party with share count exceeding {}",
            MAX_PARTY_SHARE_COUNT
        );
        return Err(TofnFatal);
    }
    let total_share_count: usize = party_share_counts.total_share_count();
    let my_keygen_id = party_share_counts.party_to_share_id(my_party_id, my_subshare_id)?;

    #[allow(clippy::suspicious_operation_groupings)]
    if total_share_count <= threshold
        || total_share_count > MAX_TOTAL_SHARE_COUNT
        || my_party_id.as_usize() >= party_share_counts.party_count()
    {
        error!(
            "invalid (total_share_count, threshold, my_party_id, my_subshare_id, max_share_count): ({},{},{},{},{})",
            total_share_count, threshold, my_party_id, my_subshare_id, MAX_TOTAL_SHARE_COUNT
        );
        return Err(TofnFatal);
    }

    let round2 = r1::start(
        my_keygen_id,
        threshold,
        party_share_counts.clone(),
        party_keygen_data,
        #[cfg(feature = "malicious")]
        behaviour,
    )?;

    new_protocol(party_share_counts, my_keygen_id, round2)
}
