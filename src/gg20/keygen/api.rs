use std::{
    array::TryFromSliceError,
    convert::{TryFrom, TryInto},
};

use super::{r1, rng, SecretKeyShare};
use crate::{
    collections::TypedUsize,
    gg20::{
        constants::{KEYPAIR_TAG, ZKSETUP_TAG},
        crypto_tools::paillier::{
            self,
            zk::{ZkSetup, ZkSetupProof},
            DecryptionKey, EncryptionKey,
        },
    },
    sdk::{
        api::{PartyShareCounts, Protocol, TofnFatal, TofnResult, XProtocol},
        implementer_api::{new_protocol, xnew_protocol, ProtocolBuilder, XProtocolBuilder},
    },
};
use serde::{Deserialize, Serialize};
use tracing::error;
use zeroize::Zeroize;

#[cfg(feature = "malicious")]
use super::malicious;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct KeygenShareId;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct KeygenPartyId;

pub type XKeygenProtocol = XProtocol<SecretKeyShare, KeygenShareId, KeygenPartyId>;
pub type KeygenProtocol = Protocol<SecretKeyShare, KeygenShareId, KeygenPartyId>;
pub type XKeygenProtocolBuilder = XProtocolBuilder<SecretKeyShare, KeygenShareId>;
pub type KeygenProtocolBuilder = ProtocolBuilder<SecretKeyShare, KeygenShareId>;
pub type KeygenPartyShareCounts = PartyShareCounts<KeygenPartyId>;

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretRecoveryKey(pub(crate) [u8; 64]);

impl TryFrom<&[u8]> for SecretRecoveryKey {
    type Error = TryFromSliceError;
    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(v.try_into()?))
    }
}

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct PartyKeyPair {
    pub(crate) ek: EncryptionKey,
    pub(crate) dk: DecryptionKey,
}

#[derive(Debug, Clone)]
pub struct PartyZkSetup {
    pub(crate) zkp: ZkSetup,
    pub(crate) zkp_proof: ZkSetupProof,
}

// Since safe prime generation is expensive, a party is expected to generate
// a keypair once for all it's shares and provide it to new_keygen
pub fn create_party_keypair_and_zksetup(
    my_party_id: TypedUsize<KeygenPartyId>,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<(PartyKeyPair, PartyZkSetup)> {
    let keypair = recover_party_keypair(my_party_id, secret_recovery_key, session_nonce)?;

    let mut zksetup_rng =
        rng::rng_seed(ZKSETUP_TAG, my_party_id, secret_recovery_key, session_nonce)?;
    let (zkp, zkp_proof) = ZkSetup::new(&mut zksetup_rng);

    Ok((keypair, PartyZkSetup { zkp, zkp_proof }))
}

pub fn recover_party_keypair(
    my_party_id: TypedUsize<KeygenPartyId>,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<PartyKeyPair> {
    let mut rng = rng::rng_seed(KEYPAIR_TAG, my_party_id, secret_recovery_key, session_nonce)?;

    let (ek, dk) = paillier::keygen(&mut rng);

    Ok(PartyKeyPair { ek, dk })
}

// BEWARE: This is only made visible for faster integration testing
pub fn create_party_keypair_and_zksetup_unsafe(
    my_party_id: TypedUsize<KeygenPartyId>,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<(PartyKeyPair, PartyZkSetup)> {
    let keypair = recover_party_keypair_unsafe(my_party_id, secret_recovery_key, session_nonce)?;

    let mut zksetup_rng =
        rng::rng_seed(ZKSETUP_TAG, my_party_id, secret_recovery_key, session_nonce)?;
    let (zkp, zkp_proof) = ZkSetup::new_unsafe(&mut zksetup_rng);

    Ok((keypair, PartyZkSetup { zkp, zkp_proof }))
}

// BEWARE: This is only made visible for faster integration testing
pub fn recover_party_keypair_unsafe(
    my_party_id: TypedUsize<KeygenPartyId>,
    secret_recovery_key: &SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<PartyKeyPair> {
    let mut rng = rng::rng_seed(KEYPAIR_TAG, my_party_id, secret_recovery_key, session_nonce)?;

    let (ek, dk) = paillier::keygen_unsafe(&mut rng);

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
    party_keypair: &PartyKeyPair,
    party_zksetup: &PartyZkSetup,
    #[cfg(feature = "malicious")] behaviour: malicious::Behaviour,
) -> TofnResult<XKeygenProtocol> {
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
    let my_share_id = party_share_counts.party_to_share_id(my_party_id, my_subshare_id)?;

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

    // TODO ugly way to start the protocol
    let round2 = r1::R1 {
        threshold,
        party_share_counts,
        ek: party_keypair.ek.clone(),
        dk: party_keypair.dk.clone(),
        zkp: party_zksetup.zkp.clone(),
        zkp_proof: party_zksetup.zkp_proof.clone(),

        #[cfg(feature = "malicious")]
        behaviour,
    }
    .start(my_share_id)?;

    xnew_protocol(party_share_counts.clone(), my_share_id, round2)
}
