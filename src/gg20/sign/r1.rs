use crate::{
    collections::TypedUsize,
    corrupt,
    gg20::{
        constants,
        crypto_tools::{hash, k256_serde::to_bytes, paillier, vss},
        keygen::SecretKeyShare,
    },
    sdk::{
        api::TofnResult,
        implementer_api::{serialize, XRoundBuilder},
    },
};
use ecdsa::elliptic_curve::Field;
use k256::Scalar;
use serde::{Deserialize, Serialize};

use super::{r2, Participants, SignShareId, XSignProtocolBuilder};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub(super) struct Bcast {
    pub(super) Gamma_i_commit: hash::Output,
    pub(super) k_i_ciphertext: paillier::Ciphertext,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct P2p {
    pub(super) range_proof: paillier::zk::range::Proof,
}

#[allow(non_snake_case)]
pub(super) fn start(
    my_share_id: TypedUsize<SignShareId>,
    my_secret_key_share: SecretKeyShare,
    msg_to_sign: Scalar,
    participants: Participants,
    #[cfg(feature = "malicious")] my_behaviour: Behaviour,
) -> TofnResult<XSignProtocolBuilder> {
    #[cfg(feature = "malicious")]
    use malicious::*;

    // TODO don't store `peers` with the round struct; it is a function of `participants` and `my_share_id`
    // TODO add a `iter_with_hole` method to `VecMap` for this purpose?
    let (peers, my_keygen_share_id) = participants.clone().puncture_hole(my_share_id)?;

    let lambda_i_S = &vss::lagrange_coefficient(
        my_share_id.as_usize(),
        &participants
            .iter()
            .map(|(_, keygen_peer_id)| keygen_peer_id.as_usize())
            .collect::<Vec<_>>(),
    )?;

    let w_i = my_secret_key_share.share().x_i().as_ref() * lambda_i_S;

    let k_i = k256::Scalar::random(rand::thread_rng());
    let gamma_i = k256::Scalar::random(rand::thread_rng());
    let Gamma_i = k256::ProjectivePoint::generator() * gamma_i;
    let (Gamma_i_commit, Gamma_i_reveal) = hash::commit(
        constants::GAMMA_I_COMMIT_TAG,
        my_share_id,
        to_bytes(&Gamma_i),
    );

    corrupt!(
        gamma_i,
        corrupt_gamma_i(my_share_id, &my_behaviour, gamma_i)
    );

    // initiate MtA protocols for
    // 1. k_i (me) * gamma_j (other)
    // 2. k_i (me) * w_j (other)
    // both MtAs use k_i, so my message k_i_ciphertext can be used in both MtA protocols
    // range proof must be custom for each other party
    // but k_i_ciphertext can be broadcast to all parties

    let ek = my_secret_key_share
        .group()
        .all_shares()
        .get(my_keygen_share_id)?
        .ek();
    let (k_i_ciphertext, k_i_randomness) = ek.encrypt(&(&k_i).into());

    let p2ps_out = Some(peers.map_ref(|(_sign_peer_id, &keygen_peer_id)| {
        let peer_zkp = my_secret_key_share
            .group()
            .all_shares()
            .get(keygen_peer_id)?
            .zkp();

        let range_proof = peer_zkp.range_proof(
            &paillier::zk::range::Statement {
                ciphertext: &k_i_ciphertext,
                ek,
            },
            &paillier::zk::range::Witness {
                msg: &k_i,
                randomness: &k_i_randomness,
            },
        );

        corrupt!(
            range_proof,
            corrupt_range_proof(my_share_id, &my_behaviour, _sign_peer_id, range_proof)
        );

        serialize(&P2p { range_proof })
    })?);

    let bcast_out = Some(serialize(&Bcast {
        Gamma_i_commit,
        k_i_ciphertext,
    })?);

    Ok(XSignProtocolBuilder::NotDone(XRoundBuilder::new(
        Box::new(r2::R2 {
            secret_key_share: my_secret_key_share,
            msg_to_sign: msg_to_sign,
            peers: peers,
            participants: participants,
            keygen_id: my_keygen_share_id,
            gamma_i,
            Gamma_i,
            Gamma_i_reveal,
            w_i,
            k_i,
            k_i_randomness,

            #[cfg(feature = "malicious")]
            behaviour: my_behaviour,
        }),
        bcast_out,
        p2ps_out,
    )))

    // Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastAndP2p {
    //     round: Box::new(r2::R2 {
    //         secret_key_share: self.secret_key_share,
    //         msg_to_sign: self.msg_to_sign,
    //         peers: self.peers,
    //         participants: self.participants,
    //         keygen_id: self.keygen_id,
    //         gamma_i,
    //         Gamma_i,
    //         Gamma_i_reveal,
    //         w_i,
    //         k_i,
    //         k_i_randomness,

    //         #[cfg(feature = "malicious")]
    //         behaviour: self.behaviour,
    //     }),
    //     bcast_out,
    //     p2ps_out,
    // }))
}

// impl no_messages::Executer for R1 {
//     type FinalOutput = BytesVec;
//     type Index = SignShareId;

//     #[allow(non_snake_case)]
//     fn execute(
//         self: Box<Self>,
//         info: &ProtocolInfo<Self::Index>,
//     ) -> TofnResult<SignProtocolBuilder> {
//         let sign_id = info.share_id();

//         let lambda_i_S = &vss::lagrange_coefficient(
//             sign_id.as_usize(),
//             &self
//                 .participants
//                 .iter()
//                 .map(|(_, keygen_peer_id)| keygen_peer_id.as_usize())
//                 .collect::<Vec<_>>(),
//         )?;

//         let w_i = self.secret_key_share.share().x_i().as_ref() * lambda_i_S;

//         let k_i = k256::Scalar::random(rand::thread_rng());
//         let gamma_i = k256::Scalar::random(rand::thread_rng());
//         let Gamma_i = k256::ProjectivePoint::generator() * gamma_i;
//         let (Gamma_i_commit, Gamma_i_reveal) =
//             hash::commit(constants::GAMMA_I_COMMIT_TAG, sign_id, to_bytes(&Gamma_i));

//         corrupt!(gamma_i, self.corrupt_gamma_i(sign_id, gamma_i));

//         // initiate MtA protocols for
//         // 1. k_i (me) * gamma_j (other)
//         // 2. k_i (me) * w_j (other)
//         // both MtAs use k_i, so my message k_i_ciphertext can be used in both MtA protocols
//         // range proof must be custom for each other party
//         // but k_i_ciphertext can be broadcast to all parties

//         let ek = &self
//             .secret_key_share
//             .group()
//             .all_shares()
//             .get(self.keygen_id)?
//             .ek();
//         let (k_i_ciphertext, k_i_randomness) = ek.encrypt(&(&k_i).into());

//         let p2ps_out = self.peers.map_ref(|(_sign_peer_id, &keygen_peer_id)| {
//             let peer_zkp = &self
//                 .secret_key_share
//                 .group()
//                 .all_shares()
//                 .get(keygen_peer_id)?
//                 .zkp();

//             let range_proof = peer_zkp.range_proof(
//                 &paillier::zk::range::Statement {
//                     ciphertext: &k_i_ciphertext,
//                     ek,
//                 },
//                 &paillier::zk::range::Witness {
//                     msg: &k_i,
//                     randomness: &k_i_randomness,
//                 },
//             );

//             corrupt!(
//                 range_proof,
//                 self.corrupt_range_proof(sign_id, _sign_peer_id, range_proof)
//             );

//             serialize(&P2p { range_proof })
//         })?;

//         let bcast_out = serialize(&Bcast {
//             Gamma_i_commit,
//             k_i_ciphertext,
//         })?;

//         Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastAndP2p {
//             round: Box::new(r2::R2 {
//                 secret_key_share: self.secret_key_share,
//                 msg_to_sign: self.msg_to_sign,
//                 peers: self.peers,
//                 participants: self.participants,
//                 keygen_id: self.keygen_id,
//                 gamma_i,
//                 Gamma_i,
//                 Gamma_i_reveal,
//                 w_i,
//                 k_i,
//                 k_i_randomness,

//                 #[cfg(feature = "malicious")]
//                 behaviour: self.behaviour,
//             }),
//             bcast_out,
//             p2ps_out,
//         }))
//     }

//     #[cfg(test)]
//     fn as_any(&self) -> &dyn std::any::Any {
//         self
//     }
// }

#[cfg(feature = "malicious")]
mod malicious {
    use crate::{
        collections::TypedUsize,
        gg20::{
            crypto_tools::paillier::{self, zk::range},
            sign::{
                malicious::{log_confess_info, Behaviour},
                SignShareId,
            },
        },
    };

    pub fn corrupt_gamma_i(
        my_share_id: TypedUsize<SignShareId>,
        my_behaviour: &Behaviour,
        mut gamma_i: k256::Scalar,
    ) -> k256::Scalar {
        if let Behaviour::R1BadGammaI = my_behaviour {
            log_confess_info(my_share_id, &my_behaviour, "");
            gamma_i += k256::Scalar::one();
        }
        gamma_i
    }

    pub fn corrupt_range_proof(
        my_share_id: TypedUsize<SignShareId>,
        my_behaviour: &Behaviour,
        peer_share_id: TypedUsize<SignShareId>,
        range_proof: range::Proof,
    ) -> range::Proof {
        if let Behaviour::R1BadProof { victim } = my_behaviour {
            if *victim == peer_share_id {
                log_confess_info(my_share_id, &my_behaviour, "");
                return paillier::zk::range::malicious::corrupt_proof(&range_proof);
            }
        }
        range_proof
    }
}
