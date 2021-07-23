use crate::{
    collections::{HoleVecMap, P2ps, Subset, TypedUsize, VecMap},
    corrupt,
    gg20::{
        crypto_tools::{
            hash::Randomness,
            k256_serde,
            mta::{self, Secret},
            paillier::{self, zk, Plaintext},
            zkp::pedersen_k256,
        },
        keygen::{KeygenPartyIndex, SecretKeyShare},
    },
    sdk::{
        api::{BytesVec, TofnResult},
        implementer_api::{bcast_and_p2p, serialize, ProtocolBuilder, ProtocolInfo, RoundBuilder},
    },
};
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{
    r1, r2, r3, r4, r5, r7, Participants, Peers, SignParticipantIndex, SignProtocolBuilder,
};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

#[allow(non_snake_case)]
pub struct R6 {
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
    pub k_i_randomness: paillier::Randomness,
    pub sigma_i: Scalar,
    pub l_i: Scalar,
    pub T_i: ProjectivePoint,
    pub(crate) beta_secrets: HoleVecMap<SignParticipantIndex, Secret>,
    pub r1bcasts: VecMap<SignParticipantIndex, r1::Bcast>,
    pub r2p2ps: P2ps<SignParticipantIndex, r2::P2pHappy>,
    pub r3bcasts: VecMap<SignParticipantIndex, r3::happy::BcastHappy>,
    pub r4bcasts: VecMap<SignParticipantIndex, r4::happy::Bcast>,
    pub delta_inv: Scalar,
    pub R: ProjectivePoint,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Bcast {
    Happy(BcastHappy),
    Sad(BcastSad),
    SadType5(BcastSadType5),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct BcastHappy {
    pub S_i: k256_serde::ProjectivePoint,
    pub S_i_proof_wc: pedersen_k256::ProofWc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BcastSad {
    pub zkp_complaints: Subset<SignParticipantIndex>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BcastSadType5 {
    pub k_i: k256_serde::Scalar,
    pub k_i_randomness: paillier::Randomness,
    pub gamma_i: k256_serde::Scalar,
    pub mta_plaintexts: HoleVecMap<SignParticipantIndex, MtaPlaintext>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MtaPlaintext {
    // need alpha_plaintext instead of alpha
    // because alpha_plaintext may differ from alpha
    // why? because the ciphertext was formed from homomorphic Paillier operations, not just encrypting alpha
    pub alpha_plaintext: Plaintext,
    pub alpha_randomness: paillier::Randomness,
    pub(crate) beta_secret: mta::Secret,
}

impl bcast_and_p2p::Executer for R6 {
    type FinalOutput = BytesVec;
    type Index = SignParticipantIndex;
    type Bcast = r5::Bcast;
    type P2p = r5::P2p;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<SignProtocolBuilder> {
        let sign_id = info.share_id();
        let participants_count = info.share_count();

        let mut zkp_complaints = Subset::with_max_size(participants_count);

        // verify proofs
        for (sign_peer_id, &keygen_peer_id) in &self.peers {
            let bcast = bcasts_in.get(sign_peer_id)?;
            let zkp = &self
                .secret_key_share
                .group()
                .all_shares()
                .get(self.keygen_id)?
                .zkp();
            let peer_k_i_ciphertext = &self.r1bcasts.get(sign_peer_id)?.k_i_ciphertext;
            let peer_ek = &self
                .secret_key_share
                .group()
                .all_shares()
                .get(keygen_peer_id)?
                .ek();
            let p2p_in = p2ps_in.get(sign_peer_id, sign_id)?;

            let peer_stmt = &zk::range::StatementWc {
                stmt: zk::range::Statement {
                    ciphertext: peer_k_i_ciphertext,
                    ek: peer_ek,
                },
                msg_g: bcast.R_i.unwrap(),
                g: &self.R,
            };

            if let Err(err) = zkp.verify_range_proof_wc(&peer_stmt, &p2p_in.k_i_range_proof_wc) {
                warn!(
                    "peer {} says: range proof wc failed to verify for peer {} because [{}]",
                    sign_id, sign_peer_id, err
                );

                zkp_complaints.add(sign_peer_id)?;
            }
        }

        corrupt!(
            zkp_complaints,
            self.corrupt_zkp_complaints(info.share_id(), zkp_complaints)?
        );

        if !zkp_complaints.is_empty() {
            let bcast_out = serialize(&Bcast::Sad(BcastSad { zkp_complaints }))?;

            return Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastOnly {
                round: Box::new(r7::sad::R7 {
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
                    sigma_i: self.sigma_i,
                    l_i: self.l_i,
                    T_i: self.T_i,
                    r1bcasts: self.r1bcasts,
                    r2p2ps: self.r2p2ps,
                    r3bcasts: self.r3bcasts,
                    r4bcasts: self.r4bcasts,
                    delta_inv: self.delta_inv,
                    R: self.R,
                    r5bcasts: bcasts_in,
                    r5p2ps: p2ps_in,

                    #[cfg(feature = "malicious")]
                    behaviour: self.behaviour,
                }),
                bcast_out,
            }));
        }

        // check for failure of type 5 from section 4.2 of https://eprint.iacr.org/2020/540.pdf
        let R_i_sum = bcasts_in
            .iter()
            .fold(ProjectivePoint::identity(), |acc, (_, bcast)| {
                acc + bcast.R_i.unwrap()
            });

        // malicious actor falsely claim type 5 fault by comparing against a corrupted curve generator
        let _curve_generator = ProjectivePoint::generator();
        corrupt!(
            _curve_generator,
            self.corrupt_curve_generator(info.share_id())
        );

        // check for type 5 fault
        if R_i_sum != _curve_generator {
            warn!("peer {} says: 'type 5' fault detected", sign_id);

            let mta_plaintexts = self.beta_secrets.map_ref(|(sign_peer_id, beta_secret)| {
                let r2p2p = self.r2p2ps.get(sign_peer_id, sign_id)?;

                let (alpha_plaintext, alpha_randomness) = self
                    .secret_key_share
                    .share()
                    .dk()
                    .decrypt_with_randomness(&r2p2p.alpha_ciphertext);

                corrupt!(
                    alpha_plaintext,
                    self.corrupt_alpha_plaintext(info.share_id(), sign_peer_id, alpha_plaintext)
                );

                let beta_secret = beta_secret.clone();

                corrupt!(
                    beta_secret,
                    self.corrupt_beta_secret(info.share_id(), sign_peer_id, beta_secret)
                );

                Ok(MtaPlaintext {
                    alpha_plaintext,
                    alpha_randomness,
                    beta_secret,
                })
            })?;

            let k_i = self.k_i;
            corrupt!(k_i, self.corrupt_k_i(info.share_id(), k_i));

            let bcast_out = serialize(&Bcast::SadType5(BcastSadType5 {
                k_i: k_i.into(),
                k_i_randomness: self.k_i_randomness.clone(),
                gamma_i: self.gamma_i.into(),
                mta_plaintexts,
            }))?;

            return Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastOnly {
                round: Box::new(r7::type5::R7 {
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
                    sigma_i: self.sigma_i,
                    l_i: self.l_i,
                    T_i: self.T_i,
                    r1bcasts: self.r1bcasts,
                    r2p2ps: self.r2p2ps,
                    r3bcasts: self.r3bcasts,
                    r4bcasts: self.r4bcasts,
                    delta_inv: self.delta_inv,
                    R: self.R,
                    r5bcasts: bcasts_in,
                    r5p2ps: p2ps_in,

                    #[cfg(feature = "malicious")]
                    behaviour: self.behaviour,
                }),
                bcast_out,
            }));
        }

        let S_i = self.R * self.sigma_i;
        let S_i_proof_wc = pedersen_k256::prove_wc(
            &pedersen_k256::StatementWc {
                stmt: pedersen_k256::Statement {
                    commit: &self.r3bcasts.get(sign_id)?.T_i.unwrap(),
                },
                msg_g: &S_i,
                g: &self.R,
            },
            &pedersen_k256::Witness {
                msg: &self.sigma_i,
                randomness: &self.l_i,
            },
        );

        corrupt!(
            S_i_proof_wc,
            self.corrupt_S_i_proof_wc(info.share_id(), S_i_proof_wc)
        );

        let bcast_out = serialize(&Bcast::Happy(BcastHappy {
            S_i: S_i.into(),
            S_i_proof_wc,
        }))?;

        Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastOnly {
            round: Box::new(r7::happy::R7 {
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
                sigma_i: self.sigma_i,
                l_i: self.l_i,
                T_i: self.T_i,
                r1bcasts: self.r1bcasts,
                r2p2ps: self.r2p2ps,
                r3bcasts: self.r3bcasts,
                r4bcasts: self.r4bcasts,
                delta_inv: self.delta_inv,
                R: self.R,
                r5bcasts: bcasts_in,
                r5p2ps: p2ps_in,

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
    use super::R6;
    use crate::{
        collections::{Subset, TypedUsize},
        gg20::{
            crypto_tools::{mta::Secret, paillier::Plaintext, zkp::pedersen_k256},
            sign::{
                malicious::{log_confess_info, Behaviour::*},
                SignParticipantIndex,
            },
        },
        sdk::api::TofnResult,
    };

    impl R6 {
        /// earlier we prepared to corrupt k_i by corrupting delta_i
        pub fn corrupt_k_i(
            &self,
            me: TypedUsize<SignParticipantIndex>,
            mut k_i: k256::Scalar,
        ) -> k256::Scalar {
            if let R3BadKI = self.behaviour {
                log_confess_info(me, &self.behaviour, "step 2/2: k_i");
                k_i += k256::Scalar::one();
            }
            k_i
        }
        /// earlier we prepared to corrupt alpha_plaintext by corrupting delta_i
        pub fn corrupt_alpha_plaintext(
            &self,
            me: TypedUsize<SignParticipantIndex>,
            recipient: TypedUsize<SignParticipantIndex>,
            mut alpha_plaintext: Plaintext,
        ) -> Plaintext {
            if let R3BadAlpha { victim } = self.behaviour {
                if victim == recipient {
                    log_confess_info(me, &self.behaviour, "step 2/2: alpha_plaintext");
                    alpha_plaintext.corrupt();
                }
            }
            alpha_plaintext
        }
        /// earlier we prepared to corrupt beta_secret by corrupting delta_i
        pub fn corrupt_beta_secret(
            &self,
            me: TypedUsize<SignParticipantIndex>,
            recipient: TypedUsize<SignParticipantIndex>,
            mut beta_secret: Secret,
        ) -> Secret {
            if let R3BadBeta { victim } = self.behaviour {
                if victim == recipient {
                    log_confess_info(me, &self.behaviour, "step 2/2: beta_secret");
                    *beta_secret.beta.unwrap_mut() += k256::Scalar::one();
                }
            }
            beta_secret
        }
        pub fn corrupt_zkp_complaints(
            &self,
            me: TypedUsize<SignParticipantIndex>,
            mut zkp_complaints: Subset<SignParticipantIndex>,
        ) -> TofnResult<Subset<SignParticipantIndex>> {
            if let R6FalseAccusation { victim } = self.behaviour {
                if zkp_complaints.is_member(victim)? {
                    log_confess_info(me, &self.behaviour, "but the accusation is true");
                } else if victim == me {
                    log_confess_info(me, &self.behaviour, "self accusation");
                    zkp_complaints.add(me)?;
                } else {
                    log_confess_info(me, &self.behaviour, "");
                    zkp_complaints.add(victim)?;
                }
            }
            Ok(zkp_complaints)
        }

        #[allow(non_snake_case)]
        pub fn corrupt_S_i_proof_wc(
            &self,
            me: TypedUsize<SignParticipantIndex>,
            range_proof: pedersen_k256::ProofWc,
        ) -> pedersen_k256::ProofWc {
            if let R6BadProof = self.behaviour {
                log_confess_info(me, &self.behaviour, "");
                return pedersen_k256::malicious::corrupt_proof_wc(&range_proof);
            }
            range_proof
        }

        pub fn corrupt_curve_generator(
            &self,
            me: TypedUsize<SignParticipantIndex>,
        ) -> k256::ProjectivePoint {
            if let R6FalseFailRandomizer = self.behaviour {
                log_confess_info(me, &self.behaviour, "");
                return k256::ProjectivePoint::identity();
            }
            k256::ProjectivePoint::generator()
        }
    }
}
