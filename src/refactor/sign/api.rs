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

pub type SignProtocol = Protocol<BytesVec, SignParticipantIndex, RealSignParticipantIndex>;
pub type SignProtocolBuilder = ProtocolBuilder<BytesVec, SignParticipantIndex>;
pub type ParticipantsList = VecMap<SignParticipantIndex, TypedUsize<KeygenPartyIndex>>;
pub type SignParties = Subset<RealKeygenPartyIndex>;

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
) -> TofnResult<SignProtocol> {
    if sign_parties.max_size() != group.party_share_counts().party_count() {
        error!(
            "sign_parties max size {} disagrees with keygen group party count {}",
            sign_parties.max_size(),
            group.party_share_counts().party_count()
        );
        return Err(TofnFatal);
    }

    // `participants` map sign_share_id -> keygen_share_id
    // Example:
    // input:
    //   keygen_party_ids: [a, b, c]
    //   share_counts:     [1, 2, 3]
    //   keygen_share_ids: [0, 1, 2, 3, 4, 5] <- always count from 0
    //                      ^  ^  ^  ^  ^  ^
    //                      a  b  b  c  c  c
    //   sign_party_ids:   [a, c] <- subset of keygen_party_ids
    // output:
    //   sign_share_ids:   [0, 1, 2, 3] <- always count from 0
    //   keygen_share_ids: [0, 3, 4, 5] <- ids of a's 1 share + c's 3 shares
    let participants = {
        let mut participants = Vec::new();
        let mut sum = 0;
        for (keygen_party_id, &party_share_count) in group.party_share_counts().iter() {
            if sign_parties.is_member(keygen_party_id)? {
                for j in 0..party_share_count {
                    participants.push(TypedUsize::from_usize(sum + j));
                }
            }
            sum += party_share_count;
        }
        VecMap::from_vec(participants)
    };

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

    let sign_party_share_counts = PartyShareCounts::<RealSignParticipantIndex>::from_vec(
        sign_parties
            .iter()
            .map(|i| group.party_share_counts().party_share_count(i))
            .collect::<TofnResult<Vec<_>>>()?,
    )?;

    new_protocol(
        sign_party_share_counts,
        index,
        Box::new(r1::R1 {
            secret_key_share: SecretKeyShare::new(group.clone(), share.clone()),
            msg_to_sign: msg_to_sign.into(),
            participants,
        }),
    )
}
