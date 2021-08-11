use crate::{
    collections::{FillVecMap, HoleVecMap, P2ps, TypedUsize, VecMap},
    corrupt,
    gg20::{
        crypto_tools::{hash::Randomness, k256_serde, mta::Secret, paillier, vss, zkp::pedersen},
        keygen::{KeygenShareId, SecretKeyShare},
        sign::{r3, r4, Participants},
    },
    sdk::{
        api::{BytesVec, TofnFatal, TofnResult},
        implementer_api::{bcast_and_p2p, serialize, ProtocolBuilder, ProtocolInfo, RoundBuilder},
    },
};
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::super::{r1, r2, Peers, SignProtocolBuilder, SignShareId};

#[cfg(feature = "malicious")]
use super::super::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R3Happy {
    pub(crate) secret_key_share: SecretKeyShare,
    pub(crate) msg_to_sign: Scalar,
    pub(crate) peers: Peers,
    pub(crate) participants: Participants,
    pub(crate) keygen_id: TypedUsize<KeygenShareId>,
    pub(crate) gamma_i: Scalar,
    pub(crate) Gamma_i: ProjectivePoint,
    pub(crate) Gamma_i_reveal: Randomness,
    pub(crate) w_i: Scalar,
    pub(crate) k_i: Scalar,
    pub(crate) k_i_randomness: paillier::Randomness,
    pub(crate) beta_secrets: HoleVecMap<SignShareId, Secret>,
    pub(crate) nu_secrets: HoleVecMap<SignShareId, Secret>,
    pub(crate) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(crate) r1p2ps: P2ps<SignShareId, r1::P2p>,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Bcast {
    Happy(BcastHappy),
    Sad(BcastSad),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct BcastHappy {
    pub delta_i: k256_serde::Scalar,
    pub T_i: k256_serde::ProjectivePoint,
    pub T_i_proof: pedersen::Proof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BcastSad {
    pub mta_complaints: FillVecMap<SignShareId, Accusation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Accusation {
    MtA,
    MtAwc,
}

impl bcast_and_p2p::Executer for R3Happy {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r2::Bcast;
    type P2p = r2::P2p;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<SignProtocolBuilder> {
        let sign_id = info.share_id();
        let participants_count = info.share_count();

        // check for complaints
        if bcasts_in
            .iter()
            .any(|(_, bcast)| matches!(bcast, r2::Bcast::Sad(_)))
        {
            warn!(
                "peer {} says: received an R2 complaint from others",
                sign_id,
            );

            return Box::new(r3::R3Sad {
                secret_key_share: self.secret_key_share,
                participants: self.participants,
                r1bcasts: self.r1bcasts,
                r1p2ps: self.r1p2ps,

                #[cfg(feature = "malicious")]
                behaviour: self.behaviour,
            })
            .execute(info, bcasts_in, p2ps_in);
        }

        // TODO: This will be changed once we switch to using P2ps for complaints in R3
        let p2ps_in = p2ps_in.map2_result(|(_, p2p)| match p2p {
            r2::P2p::Happy(p) => Ok(p),
            r2::P2p::Sad => Err(TofnFatal),
        })?;

        let mut mta_complaints = FillVecMap::with_size(participants_count);

        let zkp = self
            .secret_key_share
            .group()
            .all_shares()
            .get(self.keygen_id)?
            .zkp();

        let ek = self
            .secret_key_share
            .group()
            .all_shares()
            .get(self.keygen_id)?
            .ek();

        for (sign_peer_id, &keygen_peer_id) in &self.peers {
            let p2p_in = p2ps_in.get(sign_peer_id, sign_id)?;

            let peer_stmt = paillier::zk::mta::Statement {
                prover_id: sign_peer_id,
                verifier_id: sign_id,
                ciphertext1: &self.r1bcasts.get(sign_id)?.k_i_ciphertext,
                ciphertext2: &p2p_in.alpha_ciphertext,
                ek,
            };

            // verify zk proof for step 2 of MtA k_i * gamma_j
            // Note that the peer is the prover and we are the verifier
            if !zkp.verify_mta_proof(&peer_stmt, &p2p_in.alpha_proof) {
                warn!(
                    "peer {} says: mta proof failed to verify for peer {}",
                    sign_id, sign_peer_id,
                );

                mta_complaints.set(sign_peer_id, Accusation::MtA)?;

                continue;
            }

            // verify zk proof for step 2 of MtAwc k_i * w_j
            let peer_lambda_i_S = &vss::lagrange_coefficient(
                sign_peer_id.as_usize(),
                &self
                    .participants
                    .iter()
                    .map(|(_, keygen_peer_id)| keygen_peer_id.as_usize())
                    .collect::<Vec<_>>(),
            )?;

            let peer_W_i = self
                .secret_key_share
                .group()
                .all_shares()
                .get(keygen_peer_id)?
                .X_i()
                .as_ref()
                * peer_lambda_i_S;

            let peer_stmt = paillier::zk::mta::StatementWc {
                stmt: paillier::zk::mta::Statement {
                    prover_id: sign_peer_id,
                    verifier_id: sign_id,
                    ciphertext1: &self.r1bcasts.get(sign_id)?.k_i_ciphertext,
                    ciphertext2: &p2p_in.mu_ciphertext,
                    ek,
                },
                x_g: &peer_W_i,
            };

            // Note that the peer is the prover and we are the verifier
            if !zkp.verify_mta_proof_wc(&peer_stmt, &p2p_in.mu_proof) {
                warn!(
                    "peer {} says: mta_wc proof failed to verify for peer {}",
                    sign_id, sign_peer_id,
                );

                mta_complaints.set(sign_peer_id, Accusation::MtAwc)?;

                continue;
            }
        }

        corrupt!(
            mta_complaints,
            self.corrupt_complaint(sign_id, mta_complaints)?
        );

        if !mta_complaints.is_empty() {
            let bcast_out = serialize(&Bcast::Sad(BcastSad { mta_complaints }))?;

            return Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastOnly {
                round: Box::new(r4::R4Sad {
                    secret_key_share: self.secret_key_share,
                    participants: self.participants,
                    r1bcasts: self.r1bcasts,
                    r2p2ps: p2ps_in,

                    #[cfg(feature = "malicious")]
                    behaviour: self.behaviour,
                }),
                bcast_out,
            }));
        }

        let alphas = self.peers.map_ref(|(sign_peer_id, _)| {
            let p2p_in = p2ps_in.get(sign_peer_id, sign_id)?;

            let alpha = self
                .secret_key_share
                .share()
                .dk()
                .decrypt(&p2p_in.alpha_ciphertext)
                .to_scalar();

            Ok(alpha)
        })?;

        let mus = self.peers.map_ref(|(sign_peer_id, _)| {
            let p2p_in = p2ps_in.get(sign_peer_id, sign_id)?;

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
        corrupt!(delta_i, self.corrupt_delta_i(sign_id, delta_i));
        corrupt!(delta_i, self.corrupt_k_i(sign_id, delta_i, self.gamma_i));
        corrupt!(delta_i, self.corrupt_alpha(sign_id, delta_i));
        corrupt!(delta_i, self.corrupt_beta(sign_id, delta_i));

        // compute sigma_i = k_i * w_i + sum_{j != i} mu_ij + nu_ji
        let sigma_i = mus
            .into_iter()
            .zip(self.nu_secrets.iter())
            .fold(self.k_i * self.w_i, |acc, ((_, mu), (_, nu))| {
                acc + mu + nu.beta.as_ref()
            });

        corrupt!(sigma_i, self.corrupt_sigma(sign_id, sigma_i));

        let (T_i, l_i) = pedersen::commit(&sigma_i);
        let T_i_proof = pedersen::prove(
            &pedersen::Statement {
                prover_id: sign_id,
                commit: &T_i,
            },
            &pedersen::Witness {
                msg: &sigma_i,
                randomness: &l_i,
            },
        );

        corrupt!(T_i_proof, self.corrupt_T_i_proof(sign_id, T_i_proof));

        let bcast_out = serialize(&Bcast::Happy(BcastHappy {
            delta_i: delta_i.into(),
            T_i: T_i.into(),
            T_i_proof,
        }))?;

        Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastOnly {
            round: Box::new(r4::R4Happy {
                secret_key_share: self.secret_key_share,
                msg_to_sign: self.msg_to_sign,
                peers: self.peers,
                participants: self.participants,
                keygen_id: self.keygen_id,
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
                behaviour: self.behaviour,
            }),
            bcast_out,
        }))
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
            let info = match self.behaviour {
                R3FalseAccusationMta { victim } => Some((victim, Accusation::MtA)),
                R3FalseAccusationMtaWc { victim } => Some((victim, Accusation::MtAwc)),
                _ => None,
            };
            if let Some((victim, accusation)) = info {
                if !mta_complaints.is_none(victim)? {
                    log_confess_info(sign_id, &self.behaviour, "but the accusation is true");
                } else if victim == sign_id {
                    log_confess_info(sign_id, &self.behaviour, "self accusation");
                    mta_complaints.set(sign_id, accusation)?;
                } else {
                    log_confess_info(sign_id, &self.behaviour, "");
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
            if let R3BadProof = self.behaviour {
                log_confess_info(sign_id, &self.behaviour, "");
                return pedersen::malicious::corrupt_proof(&T_i_proof);
            }
            T_i_proof
        }

        pub fn corrupt_delta_i(
            &self,
            sign_id: TypedUsize<SignShareId>,
            mut delta_i: k256::Scalar,
        ) -> k256::Scalar {
            if let R3BadDeltaI = self.behaviour {
                log_confess_info(sign_id, &self.behaviour, "");
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
            if let R3BadKI = self.behaviour {
                log_confess_info(sign_id, &self.behaviour, "step 1/2: delta_i");
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
            if let R3BadAlpha { victim: _ } = self.behaviour {
                log_confess_info(sign_id, &self.behaviour, "step 1/2: delta_i");
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
            if let R3BadBeta { victim: _ } = self.behaviour {
                log_confess_info(sign_id, &self.behaviour, "step 1/2: delta_i");
                delta_i += k256::Scalar::one();
            }
            delta_i
        }

        pub fn corrupt_sigma(
            &self,
            sign_id: TypedUsize<SignShareId>,
            mut sigma_i: Scalar,
        ) -> Scalar {
            if let R3BadSigmaI = self.behaviour {
                log_confess_info(sign_id, &self.behaviour, "");
                sigma_i += Scalar::one();
            }
            sigma_i
        }
    }
}
