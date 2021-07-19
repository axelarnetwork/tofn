use std::{
    array::TryFromSliceError,
    convert::{TryFrom, TryInto},
};

use crate::refactor::{
    collections::{Subset, TypedUsize, VecMap},
    keygen::{
        GroupPublicInfo, KeygenPartyIndex, RealKeygenPartyIndex, SecretKeyShare, ShareSecretInfo,
    },
    sdk::{
        api::{BytesVec, PartyShareCounts, Protocol, TofnFatal, TofnResult},
        implementer_api::{new_protocol, ProtocolBuilder},
    },
};
use serde::{Deserialize, Serialize};
use tracing::error;

use super::r1;

#[cfg(feature = "malicious")]
use super::malicious;

pub type SignProtocol = Protocol<BytesVec, SignParticipantIndex, RealSignParticipantIndex>;
pub type SignProtocolBuilder = ProtocolBuilder<BytesVec, SignParticipantIndex>;
pub type ParticipantsList = VecMap<SignParticipantIndex, TypedUsize<KeygenPartyIndex>>;
pub type SignParties = Subset<RealKeygenPartyIndex>;
// TODO: pub type Peers = HoleVecMap<SignParticipantIndex, TypedUsize<KeygenPartyIndex>>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignParticipantIndex;
pub struct RealSignParticipantIndex;

/// sign only 32-byte hash digests
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageDigest([u8; 32]);

impl TryFrom<&[u8]> for MessageDigest {
    type Error = TryFromSliceError;
    fn try_from(v: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(v.try_into()?))
    }
}

impl From<&MessageDigest> for k256::Scalar {
    fn from(v: &MessageDigest) -> Self {
        k256::Scalar::from_bytes_reduced(k256::FieldBytes::from_slice(&v.0[..]))
    }
}

/// Initialize a new sign protocol
/// Assume `group`, `share` are valid and check `sign_parties` against it.
pub fn new_sign(
    group: &GroupPublicInfo,
    share: &ShareSecretInfo,
    sign_parties: &SignParties,
    msg_to_sign: &MessageDigest,
    #[cfg(feature = "malicious")] behaviour: malicious::Behaviour,
) -> TofnResult<SignProtocol> {
    let participants = VecMap::from_vec(group.party_share_counts().share_id_subset(sign_parties)?);

    // participant share count must be at least threshold + 1
    if participants.len() <= group.threshold() {
        error!(
            "not enough participant shares: threshold [{}], participants [{}]",
            group.threshold(),
            participants.len(),
        );
        return Err(TofnFatal);
    }

    // find my keygen share_id
    let index = participants
        .iter()
        .find(|(_, &k)| k == share.index())
        .map(|(s, _)| s)
        .ok_or_else(|| {
            error!("my keygen share_id {} is not a participant", share.index());
            TofnFatal
        })?;

    let sign_party_share_counts =
        PartyShareCounts::from_vec(group.party_share_counts().subset(sign_parties)?)?;

    new_protocol(
        sign_party_share_counts,
        index,
        Box::new(r1::R1 {
            secret_key_share: SecretKeyShare::new(group.clone(), share.clone()),
            msg_to_sign: msg_to_sign.into(),
            keygen_id: participants[index],
            sign_parties,
            #[cfg(feature = "malicious")]
            behaviour,
        }),
    )
}
