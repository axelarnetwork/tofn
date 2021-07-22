use crate::{
    corrupt,
    hash::Randomness,
    k256_serde,
    mta::Secret,
    paillier_k256,
    protocol::gg20::vss_k256,
    refactor::{
        collections::{FillVecMap, HoleVecMap, P2ps, TypedUsize, VecMap},
        keygen::{KeygenPartyIndex, SecretKeyShare},
        sdk::{
            api::{BytesVec, TofnFatal, TofnResult},
            implementer_api::{
                bcast_and_p2p, serialize, ProtocolBuilder, ProtocolInfo, RoundBuilder,
            },
        },
        sign::{r3, r4, Participants},
    },
    zkp::pedersen_k256,
};
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::super::{r1, r2, Peers, SignParticipantIndex, SignProtocolBuilder};

#[cfg(feature = "malicious")]
use super::super::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R3 {
    pub secret_key_share: SecretKeyShare,
    pub msg_to_sign: Scalar,
    pub peers: Peers,
    pub participants: Participants,
    pub keygen_id: TypedUsize<KeygenPartyIndex>,
    pub gamma_i: Scalar,
    pub Gamma_i: ProjectivePoint,
    pub Gamma_i_reveal: Randomness,
    pub w_i: Scalar,
    pub k_i: Scalar,
    pub k_i_randomness: paillier_k256::Randomness,
    pub(crate) beta_secrets: HoleVecMap<SignParticipantIndex, Secret>,
    pub(crate) nu_secrets: HoleVecMap<SignParticipantIndex, Secret>,
    pub r1bcasts: VecMap<SignParticipantIndex, r1::Bcast>,
    pub r1p2ps: P2ps<SignParticipantIndex, r1::P2p>,

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
    pub T_i_proof: pedersen_k256::Proof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BcastSad {
    pub mta_complaints: FillVecMap<SignParticipantIndex, Accusation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Accusation {
    MtA,
    MtAwc,
}

impl bcast_and_p2p::Executer for R3 {
    type FinalOutput = BytesVec;
    type Index = SignParticipantIndex;
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
            // TODO: Should we check if this peer's P2p's are all Sad?
            warn!(
                "peer {} says: received an R2 complaint from others",
                sign_id,
            );

            return Box::new(r3::sad::R3 {
                secret_key_share: self.secret_key_share,
                msg_to_sign: self.msg_to_sign,
                peers: self.peers,
                participants: self.participants,
                keygen_id: self.keygen_id,
                gamma_i: self.gamma_i,
                Gamma_i: self.Gamma_i,
                Gamma_i_reveal: self.Gamma_i_reveal,
                w_i: self.w_i,
                k_i: self.k_i,
                k_i_randomness: self.k_i_randomness,
                r1bcasts: self.r1bcasts,
                r1p2ps: self.r1p2ps,

                #[cfg(feature = "malicious")]
                behaviour: self.behaviour,
            })
            .execute(info, bcasts_in, p2ps_in);
        }

        // TODO: Should faults be returned for bad P2ps?
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

            let peer_stmt = paillier_k256::zk::mta::Statement {
                ciphertext1: &self.r1bcasts.get(sign_id)?.k_i_ciphertext,
                ciphertext2: &p2p_in.alpha_ciphertext,
                ek,
            };

            // verify zk proof for step 2 of MtA k_i * gamma_j
            if let Err(err) = zkp.verify_mta_proof(&peer_stmt, &p2p_in.alpha_proof) {
                warn!(
                    "peer {} says: mta proof failed to verify for peer {} because [{}]",
                    sign_id, sign_peer_id, err
                );

                mta_complaints.set(sign_peer_id, Accusation::MtA)?;

                continue;
            }

            // verify zk proof for step 2 of MtAwc k_i * w_j
            let peer_lambda_i_S = &vss_k256::lagrange_coefficient(
                sign_peer_id.as_usize(),
                &self
                    .participants
                    .iter()
                    .map(|(_, keygen_peer_id)| keygen_peer_id.as_usize())
                    .collect::<Vec<_>>(),
            );

            let peer_W_i = self
                .secret_key_share
                .group()
                .all_shares()
                .get(keygen_peer_id)?
                .X_i()
                .unwrap()
                * peer_lambda_i_S;

            let peer_stmt = paillier_k256::zk::mta::StatementWc {
                stmt: paillier_k256::zk::mta::Statement {
                    ciphertext1: &self.r1bcasts.get(sign_id)?.k_i_ciphertext,
                    ciphertext2: &p2p_in.mu_ciphertext,
                    ek,
                },
                x_g: &peer_W_i,
            };

            if let Err(err) = zkp.verify_mta_proof_wc(&peer_stmt, &p2p_in.mu_proof) {
                warn!(
                    "peer {} says: mta_wc proof failed to verify for peer {} because [{}]",
                    sign_id, sign_peer_id, err
                );

                mta_complaints.set(sign_peer_id, Accusation::MtAwc)?;

                continue;
            }
        }

        if !mta_complaints.is_empty() {
            let bcast_out = serialize(&Bcast::Sad(BcastSad { mta_complaints }))?;

            return Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastOnly {
                round: Box::new(r4::sad::R4 {
                    secret_key_share: self.secret_key_share,
                    msg_to_sign: self.msg_to_sign,
                    peers: self.peers,
                    participants: self.participants,
                    keygen_id: self.keygen_id,
                    gamma_i: self.gamma_i,
                    Gamma_i: self.Gamma_i,
                    Gamma_i_reveal: self.Gamma_i_reveal,
                    w_i: self.w_i,
                    k_i: self.k_i,
                    k_i_randomness: self.k_i_randomness,
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
        let delta_i = alphas.into_iter().zip(self.beta_secrets.iter()).fold(
            self.k_i * self.gamma_i,
            |acc, ((_, alpha), (_, beta))| {
                acc + alpha + beta.beta.unwrap() // Why use k256_serde::Scalar here?
            },
        );

        // compute sigma_i = k_i * w_i + sum_{j != i} mu_ij + nu_ji
        let sigma_i = mus.into_iter().zip(self.nu_secrets.iter()).fold(
            self.k_i * self.w_i,
            |acc, ((_, mu), (_, nu))| {
                acc + mu + nu.beta.unwrap() // Why use k256_serde::Scalar here?
            },
        );

        corrupt!(sigma_i, self.corrupt_sigma(sign_id, sigma_i));

        let (T_i, l_i) = pedersen_k256::commit(&sigma_i);
        let T_i_proof = pedersen_k256::prove(
            &pedersen_k256::Statement { commit: &T_i },
            &pedersen_k256::Witness {
                msg: &sigma_i,
                randomness: &l_i,
            },
        );

        let bcast_out = serialize(&Bcast::Happy(BcastHappy {
            delta_i: k256_serde::Scalar::from(delta_i),
            T_i: k256_serde::ProjectivePoint::from(T_i),
            T_i_proof,
        }))?;

        Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastOnly {
            round: Box::new(r4::happy::R4 {
                secret_key_share: self.secret_key_share,
                msg_to_sign: self.msg_to_sign,
                peers: self.peers,
                participants: self.participants,
                keygen_id: self.keygen_id,
                gamma_i: self.gamma_i,
                Gamma_i: self.Gamma_i,
                Gamma_i_reveal: self.Gamma_i_reveal,
                w_i: self.w_i,
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
    use super::R3;
    use crate::refactor::{collections::TypedUsize, sign::SignParticipantIndex};
    use k256::Scalar;

    use super::super::super::malicious::{log_confess_info, Behaviour};

    impl R3 {
        pub fn corrupt_sigma(
            &self,
            sign_id: TypedUsize<SignParticipantIndex>,
            mut sigma_i: Scalar,
        ) -> Scalar {
            if let Behaviour::R3BadSigmaI = self.behaviour {
                log_confess_info(sign_id, &self.behaviour, "");
                sigma_i += Scalar::one();
            }
            sigma_i
        }
    }
}