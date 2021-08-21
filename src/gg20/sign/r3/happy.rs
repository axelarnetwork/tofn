use crate::{
    collections::{FillVecMap, FullP2ps, HoleVecMap, P2ps, TypedUsize, VecMap},
    corrupt,
    gg20::{
        crypto_tools::{hash::Randomness, k256_serde, mta::Secret, paillier, vss, zkp::pedersen},
        keygen::{KeygenShareId, SecretKeyShare},
        sign::{r3, r4, KeygenShareIds},
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnFatal, TofnResult},
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
    pub(in super::super) my_secret_key_share: SecretKeyShare,
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
    pub(in super::super) my_behaviour: Behaviour,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(in super::super) enum Bcast {
    Happy(BcastHappy),
    Sad(BcastSad),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub(in super::super) struct BcastHappy {
    pub delta_i: k256_serde::Scalar,
    pub T_i: k256_serde::ProjectivePoint,
    pub T_i_proof: pedersen::Proof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in super::super) struct BcastSad {
    pub mta_complaints: FillVecMap<SignShareId, Accusation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(in super::super) enum Accusation {
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
        let mut faulters = info.new_fillvecmap();

        // anyone who sent a bcast is a faulter
        for (from, bcast) in bcasts_in.iter() {
            if bcast.is_some() {
                warn!(
                    "peer {} says: unexpected bcast from peer {}",
                    info.my_id(),
                    from
                );
                faulters.set(from, ProtocolFault)?;
            }
        }
        // anyone who did not send p2ps is a faulter
        for (from, p2ps) in p2ps_in.iter() {
            if p2ps.is_none() {
                warn!(
                    "peer {} says: missing p2ps from peer {}",
                    info.my_id(),
                    from
                );
                faulters.set(from, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // everyone sent their bcast/p2ps---unwrap all bcasts/p2ps
        let p2ps_in = p2ps_in.to_fullp2ps()?;

        // anyone who sent conflicting p2ps is a faulter
        // quadratic work: https://github.com/axelarnetwork/tofn/issues/134
        for (from, p2ps) in p2ps_in.iter() {
            if !p2ps
                .iter()
                .all(|(_, p2p)| matches!(p2p, Self::P2p::Happy(_)))
                && !p2ps.iter().all(|(_, p2p)| matches!(p2p, Self::P2p::Sad(_)))
            {
                warn!(
                    "peer {} says: conflicting happy/sad p2ps from peer {}",
                    info.my_id(),
                    from
                );
                faulters.set(from, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // if anyone complained then move to sad path
        if p2ps_in.iter().any(|(_from, p2ps)| {
            p2ps.iter()
                .any(|(_to, p2p)| matches!(p2p, Self::P2p::Sad(_)))
        }) {
            warn!(
                "peer {} says: received an R2 complaint from others",
                info.my_id(),
            );

            let p2ps_in = p2ps_in.to_p2ps();

            return Box::new(r3::R3Sad {
                my_secret_key_share: self.my_secret_key_share,
                all_keygen_ids: self.all_keygen_ids,
                r1bcasts: self.r1bcasts,
                r1p2ps: self.r1p2ps,
            })
            .execute(info, bcasts_in, p2ps_in);
        }

        // everyone sent happy-path p2ps---unwrap into happy path
        let p2ps_in = p2ps_in.map2_result(|(_, p2p)| match p2p {
            Self::P2p::Happy(p) => Ok(p),
            Self::P2p::Sad(_) => Err(TofnFatal),
        })?;

        // DONE TO HERE

        let mut mta_complaints = info.new_fillvecmap();

        let zkp = self
            .my_secret_key_share
            .group()
            .all_shares()
            .get(self.my_keygen_id)?
            .zkp();

        let ek = self
            .my_secret_key_share
            .group()
            .all_shares()
            .get(self.my_keygen_id)?
            .ek();

        for (sign_peer_id, &keygen_peer_id) in &self.peer_keygen_ids {
            let p2p_in = p2ps_in.get(sign_peer_id, info.my_id())?;

            let peer_stmt = paillier::zk::mta::Statement {
                prover_id: sign_peer_id,
                verifier_id: info.my_id(),
                ciphertext1: &self.r1bcasts.get(info.my_id())?.k_i_ciphertext,
                ciphertext2: &p2p_in.alpha_ciphertext,
                ek,
            };

            // verify zk proof for step 2 of MtA k_i * gamma_j
            // Note that the peer is the prover and we are the verifier
            if !zkp.verify_mta_proof(&peer_stmt, &p2p_in.alpha_proof) {
                warn!(
                    "peer {} says: mta proof failed to verify for peer {}",
                    info.my_id(),
                    sign_peer_id,
                );

                mta_complaints.set(sign_peer_id, Accusation::MtA)?;

                continue;
            }

            // verify zk proof for step 2 of MtAwc k_i * w_j
            let peer_lambda_i_S = &vss::lagrange_coefficient(
                sign_peer_id.as_usize(),
                &self
                    .all_keygen_ids
                    .iter()
                    .map(|(_, keygen_peer_id)| keygen_peer_id.as_usize())
                    .collect::<Vec<_>>(),
            )?;

            let peer_W_i = self
                .my_secret_key_share
                .group()
                .all_shares()
                .get(keygen_peer_id)?
                .X_i()
                .as_ref()
                * peer_lambda_i_S;

            let peer_stmt = paillier::zk::mta::StatementWc {
                stmt: paillier::zk::mta::Statement {
                    prover_id: sign_peer_id,
                    verifier_id: info.my_id(),
                    ciphertext1: &self.r1bcasts.get(info.my_id())?.k_i_ciphertext,
                    ciphertext2: &p2p_in.mu_ciphertext,
                    ek,
                },
                x_g: &peer_W_i,
            };

            // Note that the peer is the prover and we are the verifier
            if !zkp.verify_mta_proof_wc(&peer_stmt, &p2p_in.mu_proof) {
                warn!(
                    "peer {} says: mta_wc proof failed to verify for peer {}",
                    info.my_id(),
                    sign_peer_id,
                );

                mta_complaints.set(sign_peer_id, Accusation::MtAwc)?;

                continue;
            }
        }

        corrupt!(
            mta_complaints,
            self.corrupt_complaint(info.my_id(), mta_complaints)?
        );

        if !mta_complaints.is_empty() {
            let bcast_out = Some(serialize(&Bcast::Sad(BcastSad { mta_complaints }))?);

            return Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
                Box::new(r4::R4Sad {
                    secret_key_share: self.my_secret_key_share,
                    participants: self.all_keygen_ids,
                    r1bcasts: self.r1bcasts,
                    r2p2ps: p2ps_in,
                }),
                bcast_out,
                None,
            )));
        }

        let alphas = self
            .peer_keygen_ids
            .clone_map2_result(|(sign_peer_id, _)| {
                let p2p_in = p2ps_in.get(sign_peer_id, info.my_id())?;

                let alpha = self
                    .my_secret_key_share
                    .share()
                    .dk()
                    .decrypt(&p2p_in.alpha_ciphertext)
                    .to_scalar();

                Ok(alpha)
            })?;

        let mus = self
            .peer_keygen_ids
            .clone_map2_result(|(sign_peer_id, _)| {
                let p2p_in = p2ps_in.get(sign_peer_id, info.my_id())?;

                let mu = self
                    .my_secret_key_share
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
        corrupt!(delta_i, self.corrupt_delta_i(info.my_id(), delta_i));
        corrupt!(
            delta_i,
            self.corrupt_k_i(info.my_id(), delta_i, self.gamma_i)
        );
        corrupt!(delta_i, self.corrupt_alpha(info.my_id(), delta_i));
        corrupt!(delta_i, self.corrupt_beta(info.my_id(), delta_i));

        // compute sigma_i = k_i * w_i + sum_{j != i} mu_ij + nu_ji
        let sigma_i = mus
            .into_iter()
            .zip(self.nu_secrets.iter())
            .fold(self.k_i * self.w_i, |acc, ((_, mu), (_, nu))| {
                acc + mu + nu.beta.as_ref()
            });

        corrupt!(sigma_i, self.corrupt_sigma(info.my_id(), sigma_i));

        let (T_i, l_i) = pedersen::commit(&sigma_i);
        let T_i_proof = pedersen::prove(
            &pedersen::Statement {
                prover_id: info.my_id(),
                commit: &T_i,
            },
            &pedersen::Witness {
                msg: &sigma_i,
                randomness: &l_i,
            },
        );

        corrupt!(T_i_proof, self.corrupt_T_i_proof(info.my_id(), T_i_proof));

        let bcast_out = Some(serialize(&Bcast::Happy(BcastHappy {
            delta_i: delta_i.into(),
            T_i: T_i.into(),
            T_i_proof,
        }))?);

        Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
            Box::new(r4::R4Happy {
                secret_key_share: self.my_secret_key_share,
                msg_to_sign: self.msg_to_sign,
                peers: self.peer_keygen_ids,
                participants: self.all_keygen_ids,
                keygen_id: self.my_keygen_id,
                gamma_i: self.gamma_i,
                Gamma_i: self.Gamma_i,
                Gamma_i_reveal: self.Gamma_i_reveal,
                k_i: self.k_i,
                k_i_randomness: self.k_i_randomness,
                sigma_i,
                l_i,
                beta_secrets: self.beta_secrets,
                r1bcasts: self.r1bcasts,
                _delta_i: delta_i,
                r2p2ps: p2ps_in,

                #[cfg(feature = "malicious")]
                behaviour: self.my_behaviour,
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
        collections::{FillVecMap, TypedUsize},
        gg20::{crypto_tools::zkp::pedersen, sign::SignShareId},
        sdk::api::TofnResult,
    };
    use k256::Scalar;

    use super::super::super::malicious::{log_confess_info, Behaviour::*};

    impl R3Happy {
        pub fn corrupt_complaint(
            &self,
            sign_id: TypedUsize<SignShareId>,
            mut mta_complaints: FillVecMap<SignShareId, Accusation>,
        ) -> TofnResult<FillVecMap<SignShareId, Accusation>> {
            let info = match self.my_behaviour {
                R3FalseAccusationMta { victim } => Some((victim, Accusation::MtA)),
                R3FalseAccusationMtaWc { victim } => Some((victim, Accusation::MtAwc)),
                _ => None,
            };
            if let Some((victim, accusation)) = info {
                if !mta_complaints.is_none(victim)? {
                    log_confess_info(sign_id, &self.my_behaviour, "but the accusation is true");
                } else if victim == sign_id {
                    log_confess_info(sign_id, &self.my_behaviour, "self accusation");
                    mta_complaints.set(sign_id, accusation)?;
                } else {
                    log_confess_info(sign_id, &self.my_behaviour, "");
                    mta_complaints.set(victim, accusation)?;
                }
            }
            Ok(mta_complaints)
        }

        #[allow(non_snake_case)]
        pub fn corrupt_T_i_proof(
            &self,
            sign_id: TypedUsize<SignShareId>,
            T_i_proof: pedersen::Proof,
        ) -> pedersen::Proof {
            if let R3BadProof = self.my_behaviour {
                log_confess_info(sign_id, &self.my_behaviour, "");
                return pedersen::malicious::corrupt_proof(&T_i_proof);
            }
            T_i_proof
        }

        pub fn corrupt_delta_i(
            &self,
            sign_id: TypedUsize<SignShareId>,
            mut delta_i: k256::Scalar,
        ) -> k256::Scalar {
            if let R3BadDeltaI = self.my_behaviour {
                log_confess_info(sign_id, &self.my_behaviour, "");
                delta_i += k256::Scalar::one();
            }
            delta_i
        }

        /// later we will corrupt k_i by adding 1
        /// => need to add gamma_i to delta_i to maintain consistency
        pub fn corrupt_k_i(
            &self,
            sign_id: TypedUsize<SignShareId>,
            mut delta_i: k256::Scalar,
            gamma_i: k256::Scalar,
        ) -> k256::Scalar {
            if let R3BadKI = self.my_behaviour {
                log_confess_info(sign_id, &self.my_behaviour, "step 1/2: delta_i");
                delta_i += gamma_i;
            }
            delta_i
        }

        /// later we will corrupt alpha_ij by adding 1
        /// => need to add 1 delta_i to maintain consistency
        pub fn corrupt_alpha(
            &self,
            sign_id: TypedUsize<SignShareId>,
            mut delta_i: k256::Scalar,
        ) -> k256::Scalar {
            if let R3BadAlpha { victim: _ } = self.my_behaviour {
                log_confess_info(sign_id, &self.my_behaviour, "step 1/2: delta_i");
                delta_i += k256::Scalar::one();
            }
            delta_i
        }

        /// later we will corrupt beta_ij by adding 1
        /// => need to add 1 delta_i to maintain consistency
        pub fn corrupt_beta(
            &self,
            sign_id: TypedUsize<SignShareId>,
            mut delta_i: k256::Scalar,
        ) -> k256::Scalar {
            if let R3BadBeta { victim: _ } = self.my_behaviour {
                log_confess_info(sign_id, &self.my_behaviour, "step 1/2: delta_i");
                delta_i += k256::Scalar::one();
            }
            delta_i
        }

        pub fn corrupt_sigma(
            &self,
            sign_id: TypedUsize<SignShareId>,
            mut sigma_i: Scalar,
        ) -> Scalar {
            if let R3BadSigmaI = self.my_behaviour {
                log_confess_info(sign_id, &self.my_behaviour, "");
                sigma_i += Scalar::one();
            }
            sigma_i
        }
    }
}
