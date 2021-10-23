use crate::{
    collections::{FillVecMap, FullP2ps, HoleVecMap, P2ps, TypedUsize, VecMap},
    crypto_tools::{hash::Randomness, k256_serde, mta::Secret, paillier, vss, zkp::pedersen},
    gg20::{
        keygen::{KeygenShareId, SecretKeyShare},
        sign::{
            r3::{
                self,
                common::{check_message_types, R3Path},
            },
            r4, KeygenShareIds,
        },
    },
    sdk::{
        api::{BytesVec, TofnFatal, TofnResult},
        implementer_api::{serialize, Executer, ProtocolBuilder, ProtocolInfo, RoundBuilder},
    },
};
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::super::{r1, r2, Peers, SignShareId};

#[cfg(feature = "malicious")]
use super::super::malicious::Behaviour;

#[allow(non_snake_case)]
pub(in super::super) struct R3Happy {
    pub(in super::super) secret_key_share: SecretKeyShare,
    pub(in super::super) msg_to_sign: Scalar,
    pub(in super::super) peer_keygen_ids: Peers,
    pub(in super::super) all_keygen_ids: KeygenShareIds,
    pub(in super::super) my_keygen_id: TypedUsize<KeygenShareId>,
    pub(in super::super) gamma_i: Scalar,
    pub(in super::super) Gamma_i: ProjectivePoint,
    pub(in super::super) Gamma_i_reveal: Randomness,
    pub(in super::super) w_i: Scalar,
    pub(in super::super) k_i: Scalar,
    pub(in super::super) k_i_randomness: paillier::Randomness,
    pub(in super::super) beta_secrets: HoleVecMap<SignShareId, Secret>,
    pub(in super::super) nu_secrets: HoleVecMap<SignShareId, Secret>,
    pub(in super::super) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(in super::super) r1p2ps: FullP2ps<SignShareId, r1::P2p>,

    #[cfg(feature = "malicious")]
    pub(in super::super) behaviour: Behaviour,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct BcastHappy {
    pub delta_i: k256_serde::Scalar,
    pub T_i: k256_serde::ProjectivePoint,
    pub T_i_proof: pedersen::Proof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in super::super) struct P2pSad {
    pub mta_complaint: Accusation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(in super::super) enum Accusation {
    None,
    MtA,
    MtAwc,
}

impl Executer for R3Happy {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = ();
    type P2p = r2::P2p;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let my_sign_id = info.my_id();
        let mut faulters = info.new_fillvecmap();

        let paths = check_message_types(info, &bcasts_in, &p2ps_in, &mut faulters)?;
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // if anyone complained then move to sad path
        if paths.iter().any(|(_, path)| matches!(path, R3Path::Sad)) {
            warn!(
                "peer {} says: received an R2 complaint from others--move to sad path",
                my_sign_id,
            );
            return Box::new(r3::R3Sad {
                secret_key_share: self.secret_key_share,
                all_keygen_ids: self.all_keygen_ids,
                r1bcasts: self.r1bcasts,
                r1p2ps: self.r1p2ps,
            })
            .execute(info, bcasts_in, p2ps_in);
        }

        // happy path: everyone sent happy p2ps--unwrap into happy p2ps
        // TODO combine the next 2 lines into a new P2ps::map2_result method?
        let p2ps_in = p2ps_in.to_fullp2ps()?;
        let p2ps_in = p2ps_in.map2_result(|(_, p2p)| match p2p {
            Self::P2p::Happy(p) => Ok(p),
            Self::P2p::Sad(_) => Err(TofnFatal),
        })?;

        // verify mta proofs
        let zkp = self
            .secret_key_share
            .group()
            .all_shares()
            .get(self.my_keygen_id)?
            .zkp();

        let ek = self
            .secret_key_share
            .group()
            .all_shares()
            .get(self.my_keygen_id)?
            .ek();

        let mta_complaints =
            self.peer_keygen_ids
                .ref_map2_result(|(peer_sign_id, &peer_keygen_id)| {
                    let p2p_in = p2ps_in.get(peer_sign_id, my_sign_id)?;

                    let peer_stmt = paillier::zk::mta::Statement {
                        prover_id: peer_sign_id,
                        verifier_id: my_sign_id,
                        ciphertext1: &self.r1bcasts.get(my_sign_id)?.k_i_ciphertext,
                        ciphertext2: &p2p_in.alpha_ciphertext,
                        ek,
                    };

                    // verify zk proof for step 2 of MtA k_i * gamma_j
                    // (peer is the prover and we are the verifier)
                    if !zkp.verify_mta_proof(&peer_stmt, &p2p_in.alpha_proof) {
                        warn!(
                            "peer {} says: mta proof failed to verify for peer {}",
                            my_sign_id, peer_sign_id,
                        );
                        return Ok(Accusation::MtA);
                    }

                    // verify zk proof for step 2 of MtAwc k_i * w_j
                    let peer_lambda_i_S = &vss::lagrange_coefficient(
                        peer_sign_id.as_usize(),
                        &self
                            .all_keygen_ids
                            .iter()
                            .map(|(_, peer_keygen_id)| peer_keygen_id.as_usize())
                            .collect::<Vec<_>>(),
                    )?;

                    let peer_W_i = self
                        .secret_key_share
                        .group()
                        .all_shares()
                        .get(peer_keygen_id)?
                        .X_i()
                        .as_ref()
                        * peer_lambda_i_S;

                    let peer_stmt = paillier::zk::mta::StatementWc {
                        stmt: paillier::zk::mta::Statement {
                            prover_id: peer_sign_id,
                            verifier_id: my_sign_id,
                            ciphertext1: &self.r1bcasts.get(my_sign_id)?.k_i_ciphertext,
                            ciphertext2: &p2p_in.mu_ciphertext,
                            ek,
                        },
                        x_g: &peer_W_i,
                    };

                    // (peer is the prover and we are the verifier)
                    if !zkp.verify_mta_proof_wc(&peer_stmt, &p2p_in.mu_proof) {
                        warn!(
                            "peer {} says: mta_wc proof failed to verify for peer {}",
                            my_sign_id, peer_sign_id,
                        );
                        return Ok(Accusation::MtAwc);
                    }

                    Ok(Accusation::None)
                })?;

        corrupt!(
            mta_complaints,
            self.corrupt_complaint(my_sign_id, mta_complaints)?
        );

        if mta_complaints
            .iter()
            .any(|(_, complaint)| !matches!(complaint, Accusation::None))
        {
            let p2ps_out = Some(
                mta_complaints
                    .map2_result(|(_, mta_complaint)| serialize(&P2pSad { mta_complaint }))?,
            );

            return Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
                Box::new(r4::R4Sad {
                    secret_key_share: self.secret_key_share,
                    all_keygen_ids: self.all_keygen_ids,
                    r1bcasts: self.r1bcasts,
                    r2p2ps: p2ps_in,
                }),
                None,
                p2ps_out,
            )));
        }

        let alphas = self.peer_keygen_ids.ref_map2_result(|(peer_sign_id, _)| {
            let p2p_in = p2ps_in.get(peer_sign_id, my_sign_id)?;

            let alpha = self
                .secret_key_share
                .share()
                .dk()
                .decrypt(&p2p_in.alpha_ciphertext)
                .to_scalar();

            Ok(alpha)
        })?;

        let mus = self.peer_keygen_ids.ref_map2_result(|(peer_sign_id, _)| {
            let p2p_in = p2ps_in.get(peer_sign_id, my_sign_id)?;

            let mu = self
                .secret_key_share
                .share()
                .dk()
                .decrypt(&p2p_in.mu_ciphertext)
                .to_scalar();

            Ok(mu)
        })?;

        // compute delta_i = k_i * gamma_i + sum_{j != i} alpha_ij + beta_ji
        let delta_i = alphas
            .into_iter()
            .zip(self.beta_secrets.iter())
            .fold(self.k_i * self.gamma_i, |acc, ((_, alpha), (_, beta))| {
                acc + alpha + beta.beta.as_ref()
            });

        // many malicious behaviours require corrupt delta_i to prepare
        corrupt!(delta_i, self.corrupt_delta_i(my_sign_id, delta_i));
        corrupt!(delta_i, self.corrupt_k_i(my_sign_id, delta_i, self.gamma_i));
        corrupt!(delta_i, self.corrupt_alpha(my_sign_id, delta_i));
        corrupt!(delta_i, self.corrupt_beta(my_sign_id, delta_i));

        // compute sigma_i = k_i * w_i + sum_{j != i} mu_ij + nu_ji
        let sigma_i = mus
            .into_iter()
            .zip(self.nu_secrets.iter())
            .fold(self.k_i * self.w_i, |acc, ((_, mu), (_, nu))| {
                acc + mu + nu.beta.as_ref()
            });

        corrupt!(sigma_i, self.corrupt_sigma(my_sign_id, sigma_i));

        let (T_i, l_i) = pedersen::commit(&sigma_i);
        let T_i_proof = pedersen::prove(
            &pedersen::Statement {
                prover_id: my_sign_id,
                commit: &T_i,
            },
            &pedersen::Witness {
                msg: &sigma_i,
                randomness: &l_i,
            },
        );

        corrupt!(T_i_proof, self.corrupt_T_i_proof(my_sign_id, T_i_proof));

        let bcast_out = Some(serialize(&BcastHappy {
            delta_i: delta_i.into(),
            T_i: T_i.into(),
            T_i_proof,
        })?);

        Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
            Box::new(r4::R4Happy {
                secret_key_share: self.secret_key_share,
                msg_to_sign: self.msg_to_sign,
                peer_keygen_ids: self.peer_keygen_ids,
                all_keygen_ids: self.all_keygen_ids,
                my_keygen_id: self.my_keygen_id,
                gamma_i: self.gamma_i,
                Gamma_i: self.Gamma_i,
                Gamma_i_reveal: self.Gamma_i_reveal,
                k_i: self.k_i,
                k_i_randomness: self.k_i_randomness,
                sigma_i,
                l_i,
                beta_secrets: self.beta_secrets,
                r1bcasts: self.r1bcasts,
                r2p2ps: p2ps_in,

                #[cfg(feature = "malicious")]
                behaviour: self.behaviour,
            }),
            bcast_out,
            None,
        )))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(feature = "malicious")]
mod malicious {
    use super::{Accusation, R3Happy};
    use crate::{
        collections::{HoleVecMap, TypedUsize},
        crypto_tools::zkp::pedersen,
        gg20::sign::SignShareId,
        sdk::api::TofnResult,
    };
    use k256::Scalar;

    use super::super::super::malicious::{log_confess_info, Behaviour::*};

    impl R3Happy {
        pub fn corrupt_complaint(
            &self,
            my_sign_id: TypedUsize<SignShareId>,
            mut mta_complaints: HoleVecMap<SignShareId, Accusation>,
        ) -> TofnResult<HoleVecMap<SignShareId, Accusation>> {
            let (victim_sign_id, false_accusation) = match self.behaviour {
                R3FalseAccusationMta { victim } => (victim, Accusation::MtA),
                R3FalseAccusationMtaWc { victim } => (victim, Accusation::MtAwc),
                _ => return Ok(mta_complaints),
            };
            let accusation = mta_complaints.get_mut(victim_sign_id)?;
            if *accusation == false_accusation {
                log_confess_info(my_sign_id, &self.behaviour, "but the accusation is true");
            } else {
                log_confess_info(my_sign_id, &self.behaviour, "");
                *accusation = false_accusation;
            }
            Ok(mta_complaints)
        }

        #[allow(non_snake_case)]
        pub fn corrupt_T_i_proof(
            &self,
            my_sign_id: TypedUsize<SignShareId>,
            T_i_proof: pedersen::Proof,
        ) -> pedersen::Proof {
            if let R3BadProof = self.behaviour {
                log_confess_info(my_sign_id, &self.behaviour, "");
                return pedersen::malicious::corrupt_proof(&T_i_proof);
            }
            T_i_proof
        }

        pub fn corrupt_delta_i(
            &self,
            my_sign_id: TypedUsize<SignShareId>,
            mut delta_i: k256::Scalar,
        ) -> k256::Scalar {
            if let R3BadDeltaI = self.behaviour {
                log_confess_info(my_sign_id, &self.behaviour, "");
                delta_i += k256::Scalar::one();
            }
            delta_i
        }

        /// later we will corrupt k_i by adding 1
        /// => need to add gamma_i to delta_i to maintain consistency
        pub fn corrupt_k_i(
            &self,
            my_sign_id: TypedUsize<SignShareId>,
            mut delta_i: k256::Scalar,
            gamma_i: k256::Scalar,
        ) -> k256::Scalar {
            if let R3BadKI = self.behaviour {
                log_confess_info(my_sign_id, &self.behaviour, "step 1/2: delta_i");
                delta_i += gamma_i;
            }
            delta_i
        }

        /// later we will corrupt alpha_ij by adding 1
        /// => need to add 1 delta_i to maintain consistency
        pub fn corrupt_alpha(
            &self,
            my_sign_id: TypedUsize<SignShareId>,
            mut delta_i: k256::Scalar,
        ) -> k256::Scalar {
            if let R3BadAlpha { victim: _ } = self.behaviour {
                log_confess_info(my_sign_id, &self.behaviour, "step 1/2: delta_i");
                delta_i += k256::Scalar::one();
            }
            delta_i
        }

        /// later we will corrupt beta_ij by adding 1
        /// => need to add 1 delta_i to maintain consistency
        pub fn corrupt_beta(
            &self,
            my_sign_id: TypedUsize<SignShareId>,
            mut delta_i: k256::Scalar,
        ) -> k256::Scalar {
            if let R3BadBeta { victim: _ } = self.behaviour {
                log_confess_info(my_sign_id, &self.behaviour, "step 1/2: delta_i");
                delta_i += k256::Scalar::one();
            }
            delta_i
        }

        pub fn corrupt_sigma(
            &self,
            my_sign_id: TypedUsize<SignShareId>,
            mut sigma_i: Scalar,
        ) -> Scalar {
            if let R3BadSigmaI = self.behaviour {
                log_confess_info(my_sign_id, &self.behaviour, "");
                sigma_i += Scalar::one();
            }
            sigma_i
        }
    }
}
