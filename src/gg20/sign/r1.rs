use crate::{
    collections::TypedUsize,
    crypto_tools::{constants, hash, k256_serde::point_to_bytes, paillier, vss},
    gg20::keygen::SecretKeyShare,
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
pub struct Bcast {
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
    secret_key_share: SecretKeyShare,
    msg_to_sign: Scalar,
    all_keygen_ids: KeygenShareIds,
    #[cfg(feature = "malicious")] behaviour: Behaviour,
) -> TofnResult<SignProtocolBuilder> {
    // `HoleVecMap` has limited options for construction,
    // so we store a separate `peer_keygen_ids` to generate future `HoleVecMap`s.
    let (peer_keygen_ids, my_keygen_id) = all_keygen_ids.clone().puncture_hole(my_sign_id)?;

    let lambda_i_S = &vss::lagrange_coefficient(
        my_sign_id.as_usize(),
        &all_keygen_ids
            .iter()
            .map(|(_, peer_keygen_id)| peer_keygen_id.as_usize())
            .collect::<Vec<_>>(),
    )?;

    let w_i = secret_key_share.share().x_i().as_ref() * lambda_i_S;

    let k_i = k256::Scalar::random(rand::thread_rng());
    let gamma_i = k256::Scalar::random(rand::thread_rng());
    let Gamma_i = k256::ProjectivePoint::generator() * gamma_i;
    let (Gamma_i_commit, Gamma_i_reveal) = hash::commit(
        constants::GAMMA_I_COMMIT_TAG,
        my_sign_id,
        point_to_bytes(&Gamma_i),
    );

    corrupt!(
        gamma_i,
        malicious::corrupt_gamma_i(my_sign_id, &behaviour, gamma_i)
    );

    // initiate MtA protocols for
    // 1. k_i (me) * gamma_j (other)
    // 2. k_i (me) * w_j (other)
    // both MtAs use k_i, so my message k_i_ciphertext can be used in both MtA protocols
    // range proof must be custom for each other party
    // but k_i_ciphertext can be broadcast to all parties

    let ek = secret_key_share
        .group()
        .all_shares()
        .get(my_keygen_id)?
        .ek();
    let (k_i_ciphertext, k_i_randomness) = ek.encrypt(&(&k_i).into());

    let p2ps_out = Some(
        peer_keygen_ids.ref_map2_result(|(peer_sign_id, &peer_keygen_id)| {
            let peer_zkp = secret_key_share
                .group()
                .all_shares()
                .get(peer_keygen_id)?
                .zkp();

            let range_proof = peer_zkp.range_proof(
                &paillier::zk::range::Statement {
                    prover_id: my_sign_id,
                    verifier_id: peer_sign_id,
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
                malicious::corrupt_range_proof(my_sign_id, &behaviour, peer_sign_id, range_proof)
            );

            serialize(&P2p { range_proof })
        })?,
    );

    let bcast_out = Some(serialize(&Bcast {
        Gamma_i_commit,
        k_i_ciphertext,
    })?);

    Ok(SignProtocolBuilder::NotDone(RoundBuilder::new(
        Box::new(r2::R2 {
            secret_key_share,
            msg_to_sign,
            peer_keygen_ids,
            all_keygen_ids,
            my_keygen_id,
            gamma_i,
            Gamma_i,
            Gamma_i_reveal,
            w_i,
            k_i,
            k_i_randomness,

            #[cfg(feature = "malicious")]
            behaviour,
        }),
        bcast_out,
        p2ps_out,
    )))
}

#[cfg(feature = "malicious")]
mod malicious {
    use crate::{
        collections::TypedUsize,
        crypto_tools::paillier::{self, zk::range},
        gg20::sign::{
            malicious::{log_confess_info, Behaviour},
            SignShareId,
        },
    };

    pub fn corrupt_gamma_i(
        my_sign_id: TypedUsize<SignShareId>,
        behaviour: &Behaviour,
        mut gamma_i: k256::Scalar,
    ) -> k256::Scalar {
        if let Behaviour::R1BadGammaI = behaviour {
            log_confess_info(my_sign_id, behaviour, "");
            gamma_i += k256::Scalar::one();
        }
        gamma_i
    }

    pub fn corrupt_range_proof(
        my_sign_id: TypedUsize<SignShareId>,
        behaviour: &Behaviour,
        peer_sign_id: TypedUsize<SignShareId>,
        range_proof: range::Proof,
    ) -> range::Proof {
        if let Behaviour::R1BadProof { victim } = behaviour {
            if *victim == peer_sign_id {
                log_confess_info(my_sign_id, behaviour, "");
                return paillier::zk::range::malicious::corrupt_proof(&range_proof);
            }
        }
        range_proof
    }
}
