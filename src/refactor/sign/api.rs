use std::{
    array::TryFromSliceError,
    convert::{TryFrom, TryInto},
};

use crate::refactor::{
    api::{BytesVec, Protocol, TofnResult},
    collections::{Behave, TypedUsize, VecMap},
    implementer_api::{ProtocolBuilder, Round},
    keygen::{GroupPublicInfo, KeygenPartyIndex, SecretKeyShare, ShareSecretInfo},
};
use serde::{Deserialize, Serialize};
use tracing::error;

use super::r1;

pub type SignProtocol = Protocol<BytesVec, SignParticipantIndex>;
pub type SignProtocolBuilder = ProtocolBuilder<BytesVec, SignParticipantIndex>;
pub type ParticipantsList = VecMap<SignParticipantIndex, TypedUsize<KeygenPartyIndex>>;

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct SignParticipantIndex;
impl Behave for SignParticipantIndex {}

/// sign only 32-byte hash digests
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MessageDigest([u8; 32]);

/// Initialize a new sign protocol
pub fn new_sign(
    group: &GroupPublicInfo,
    share: &ShareSecretInfo,
    participants: &ParticipantsList,
    msg_to_sign: &MessageDigest,
) -> TofnResult<SignProtocol> {
    let index = validate_args(group, share, participants)?;

    Ok(Protocol::NotDone(Round::new_no_messages(
        Box::new(r1::R1 {
            secret_key_share: SecretKeyShare {
                group: group.clone(),
                share: share.clone(),
            },
            msg_to_sign: msg_to_sign.into(),
            participants: participants.clone(),
        }),
        participants.len(),
        index,
    )?))
}

/// Assume `group`, `share` are valid and check `participants` against it.
/// Returns my index in `participants`.
/// TODO either make this pub or move it out of api.rs
fn validate_args(
    group: &GroupPublicInfo,
    share: &ShareSecretInfo,
    participants: &ParticipantsList,
) -> TofnResult<TypedUsize<SignParticipantIndex>> {
    // participant count must be at least threshold + 1
    if participants.len() <= group.threshold || participants.len() > group.share_count() {
        error!(
            "invalid (participant_count,threshold,share_count): ({},{},{})",
            participants.len(),
            group.threshold,
            group.share_count()
        );
        return Err(());
    }

    // check that my index is in the list
    let my_participant_index = participants
        .iter()
        .find(|(_, &k)| k == share.index)
        .map(|(s, _)| s);
    if my_participant_index.is_none() {
        error!(
            "my keygen party index {} not found in `participants`",
            share.index
        );
        return Err(());
    }

    // check for duplicate party ids, indices out of bounds
    // just do a dumb quadratic-time check
    for (_, k) in participants.iter() {
        if k.as_usize() >= group.share_count() {
            error!(
                "keygen party index {} out of bounds {}",
                k,
                group.share_count()
            );
            return Err(());
        }
        if participants.iter().filter(|(_, kk)| k == *kk).count() > 1 {
            error!("duplicate keygen party index {} detected", k);
            return Err(());
        }
    }

    Ok(my_participant_index.unwrap())
}

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
