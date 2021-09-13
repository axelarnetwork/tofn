use tracing::info;

use crate::{
    collections::{HoleVecMap, TypedUsize, VecMap},
    gg20::sign::r3,
    sdk::{
        api::{BytesVec, MsgType},
        implementer_api::{decode_message, encode_message, serialize, ExpectedMsgTypes},
    },
};

use super::{r4, r6, SignShareId};

// all malicious behaviours
// names have the form <round><fault> where
// <round> indicates round where the first malicious tampering occurs, and
// <fault> is a description
// example: R1BadProof -> fault injected to the output of r1
#[derive(Clone, Debug)]
pub enum Behaviour {
    Honest,
    R1BadProof { victim: TypedUsize<SignShareId> },
    R1BadGammaI, // triggers r6::Output::FailType5
    R2FalseAccusation { victim: TypedUsize<SignShareId> },
    R2BadMta { victim: TypedUsize<SignShareId> },
    R2BadMtaWc { victim: TypedUsize<SignShareId> },
    R3BadSigmaI, // triggers r7::Output::FailType7
    R3FalseAccusationMta { victim: TypedUsize<SignShareId> },
    R3FalseAccusationMtaWc { victim: TypedUsize<SignShareId> },
    R3BadProof,
    R3BadDeltaI,                                    // triggers r6::Output::FailType5
    R3BadKI,                                        // triggers r6::Output::FailType5
    R3BadAlpha { victim: TypedUsize<SignShareId> }, // triggers r6::Output::FailType5
    R3BadBeta { victim: TypedUsize<SignShareId> },  // triggers r6::Output::FailType5
    R4BadReveal,
    R5BadProof { victim: TypedUsize<SignShareId> },
    R6FalseAccusation { victim: TypedUsize<SignShareId> },
    R6BadProof,
    R6FalseType5Claim,
    R7BadSI,
    R7FalseType7Claim,
}

impl Behaviour {
    pub fn is_honest(&self) -> bool {
        matches!(self, Self::Honest)
    }
}

pub(crate) fn log_confess_info<K>(sign_id: TypedUsize<K>, behaviour: &Behaviour, msg: &str) {
    if msg.is_empty() {
        info!("malicious peer {} does {:?}", sign_id, behaviour);
    } else {
        info!("malicious peer {} does {:?} [{}]", sign_id, behaviour, msg);
    }
}

pub fn delta_inverse_r3(
    faulter_share_id: TypedUsize<SignShareId>,
    all_bcasts: VecMap<SignShareId, Option<BytesVec>>,
) -> (VecMap<SignShareId, Option<BytesVec>>, k256::Scalar) {
    let mut all_bcasts_deserialized: Vec<r3::BcastHappy> = all_bcasts
        .map(|bytes_option| {
            bincode::deserialize(
                &decode_message::<SignShareId>(&bytes_option.unwrap())
                    .unwrap()
                    .payload,
            )
            .unwrap()
        })
        .into_vec();

    let mut faulter_bcast = all_bcasts_deserialized.remove(faulter_share_id.as_usize());

    let delta_i_sum_except_faulter = all_bcasts_deserialized
        .iter()
        .map(|bcast| bcast.delta_i.as_ref())
        .fold(k256::Scalar::zero(), |acc, delta_i| acc + delta_i);

    let faulter_delta_i_change = faulter_bcast.delta_i.as_ref() - &delta_i_sum_except_faulter;

    faulter_bcast.delta_i = delta_i_sum_except_faulter.negate().into();

    all_bcasts_deserialized.insert(faulter_share_id.as_usize(), faulter_bcast);

    (
        VecMap::from_vec(all_bcasts_deserialized).map2(|(from, bcast)| {
            Some(
                encode_message::<SignShareId>(
                    serialize(&bcast).unwrap(),
                    from,
                    MsgType::Bcast,
                    ExpectedMsgTypes::BcastOnly,
                )
                .unwrap(),
            )
        }),
        faulter_delta_i_change,
    )
}

// which scalar to corrupt in a delta-inverse attack
#[allow(non_camel_case_types)]
pub enum DeltaInvFaultType {
    delta_i,
    alpha_ij,
    beta_ij,
    k_i,
}

pub fn delta_inverse_r4(
    fault_type: &DeltaInvFaultType,
    delta_i_change: k256::Scalar,
    faulter_share_id: TypedUsize<SignShareId>,
    faulter_bcast: &mut BytesVec,
    faulter_p2ps: &mut HoleVecMap<SignShareId, BytesVec>,
) {
    let faulter_bcast_deserialized: r4::Bcast = bincode::deserialize(
        &decode_message::<SignShareId>(&faulter_bcast)
            .unwrap()
            .payload,
    )
    .unwrap();

    let faulter_p2ps_deserialized: HoleVecMap<_, r6::P2pSadType5> = faulter_p2ps
        .clone_map2_result(|(_, bytes)| {
            Ok(
                bincode::deserialize(&decode_message::<SignShareId>(bytes).unwrap().payload)
                    .unwrap(),
            )
        })
        .unwrap();

    match fault_type {
        DeltaInvFaultType::delta_i => {} // nothing to do here
        DeltaInvFaultType::alpha_ij => todo!(),
        DeltaInvFaultType::beta_ij => todo!(),
        DeltaInvFaultType::k_i => todo!(),
    }

    *faulter_bcast = encode_message::<SignShareId>(
        serialize(&faulter_bcast_deserialized).unwrap(),
        faulter_share_id,
        MsgType::Bcast,
        ExpectedMsgTypes::BcastAndP2p,
    )
    .unwrap();

    *faulter_p2ps = faulter_p2ps_deserialized
        .map2_result(|(to, p2p)| {
            encode_message::<SignShareId>(
                serialize(&p2p).unwrap(),
                faulter_share_id,
                MsgType::P2p { to },
                ExpectedMsgTypes::BcastAndP2p,
            )
        })
        .unwrap();
}
