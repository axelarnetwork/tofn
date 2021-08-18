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
        implementer_api::{serialize, RoundBuilder},
    },
};
use ecdsa::elliptic_curve::Field;
use k256::Scalar;
use serde::{Deserialize, Serialize};

use super::{r2, KeygenShareIds, SignProtocolBuilder, SignShareId};

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
    my_sign_id: TypedUsize<SignShareId>,
    my_secret_key_share: SecretKeyShare,
    msg_to_sign: Scalar,
    all_keygen_ids: KeygenShareIds,
    #[cfg(feature = "malicious")] my_behaviour: Behaviour,
) -> TofnResult<SignProtocolBuilder> {
    #[cfg(feature = "malicious")]
    use malicious::*;

    // Store a separate `peer_keygen_ids` as a `HoleVecMap` for future iteration.
    // It would be idiomatic to instead get a punctured iterator over `all_keygen_ids`,
    // but `HoleVecMap` does not impl `FromIterator` so we cannot use `collect`.
    let (peer_keygen_ids, my_keygen_id) = all_keygen_ids.clone().puncture_hole(my_sign_id)?;

    let lambda_i_S = &vss::lagrange_coefficient(
        my_sign_id.as_usize(),
        &all_keygen_ids
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
        my_sign_id,
        to_bytes(&Gamma_i),
    );

    corrupt!(gamma_i, corrupt_gamma_i(my_sign_id, &my_behaviour, gamma_i));

    // initiate MtA protocols for
    // 1. k_i (me) * gamma_j (other)
    // 2. k_i (me) * w_j (other)
    // both MtAs use k_i, so my message k_i_ciphertext can be used in both MtA protocols
    // range proof must be custom for each other party
    // but k_i_ciphertext can be broadcast to all parties

    let ek = my_secret_key_share
        .group()
        .all_shares()
        .get(my_keygen_id)?
        .ek();
    let (k_i_ciphertext, k_i_randomness) = ek.encrypt(&(&k_i).into());

    let p2ps_out = Some(peer_keygen_ids.clone_map2_result(
        |(_sign_peer_id, &keygen_peer_id)| {
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
                corrupt_range_proof(my_sign_id, &my_behaviour, _sign_peer_id, range_proof)
            );

            serialize(&P2p { range_proof })
        },
    )?);

    let bcast_out = Some(serialize(&Bcast {
        Gamma_i_commit,
        k_i_ciphertext,
    })?);

    Ok(SignProtocolBuilder::NotDone(RoundBuilder::new(
        Box::new(r2::R2 {
            secret_key_share: my_secret_key_share,
            msg_to_sign,
            peers: peer_keygen_ids,
            participants: all_keygen_ids,
            keygen_id: my_keygen_id,
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
}

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
            log_confess_info(my_share_id, my_behaviour, "");
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
                log_confess_info(my_share_id, my_behaviour, "");
                return paillier::zk::range::malicious::corrupt_proof(&range_proof);
            }
        }
        range_proof
    }
}
