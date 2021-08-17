use crate::{
    collections::{FillVecMap, HoleVecMap, P2ps, Subset, TypedUsize, VecMap},
    corrupt,
    gg20::{
        crypto_tools::{
            k256_serde,
            mta::{self, Secret},
            paillier::{self, zk, Plaintext},
            zkp::pedersen,
        },
        keygen::{KeygenShareId, SecretKeyShare},
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnResult},
        implementer_api::{
            bcast_and_p2p, serialize, Executer, ProtocolBuilder, ProtocolInfo, RoundBuilder,
            XProtocolBuilder, XRoundBuilder,
        },
    },
};
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{r1, r2, r3, r4, r5, r7, Participants, Peers, SignProtocolBuilder, SignShareId};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

#[allow(non_snake_case)]
pub(super) struct R6 {
    pub(super) secret_key_share: SecretKeyShare,
    pub(super) msg_to_sign: Scalar,
    pub(super) peers: Peers,
    pub(super) participants: Participants,
    pub(super) keygen_id: TypedUsize<KeygenShareId>,
    pub(super) gamma_i: Scalar,
    pub(super) k_i: Scalar,
    pub(super) k_i_randomness: paillier::Randomness,
    pub(super) sigma_i: Scalar,
    pub(super) l_i: Scalar,
    pub(super) beta_secrets: HoleVecMap<SignShareId, Secret>,
    pub(super) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(super) r2p2ps: P2ps<SignShareId, r2::P2pHappy>,
    pub(super) r3bcasts: VecMap<SignShareId, r3::BcastHappy>,
    pub(super) r4bcasts: VecMap<SignShareId, r4::Bcast>,
    pub(super) R: ProjectivePoint,

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
    pub S_i_proof_wc: pedersen::ProofWc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BcastSad {
    pub zkp_complaints: Subset<SignShareId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BcastSadType5 {
    pub k_i: k256_serde::Scalar,
    pub k_i_randomness: paillier::Randomness,
    pub gamma_i: k256_serde::Scalar,
    // TODO: Switch away from serializing a HoleVecMap since it's an attack vector due to it's
    // internal hole being serialized: https://github.com/axelarnetwork/tofn/issues/105
    pub mta_plaintexts: HoleVecMap<SignShareId, MtaPlaintext>,
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

impl Executer for R6 {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r5::Bcast;
    type P2p = r5::P2p;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: crate::collections::FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: crate::collections::XP2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<crate::sdk::implementer_api::XProtocolBuilder<Self::FinalOutput, Self::Index>>
    {
        let my_share_id = info.share_id();
        let mut faulters = FillVecMap::with_size(info.share_count());

        // anyone who did not send a bcast is a faulter
        for (share_id, bcast) in bcasts_in.iter() {
            if bcast.is_none() {
                warn!(
                    "peer {} says: missing bcast from peer {}",
                    my_share_id, share_id
                );
                faulters.set(share_id, ProtocolFault)?;
            }
        }
        // anyone who did not send p2ps is a faulter
        for (share_id, p2ps) in p2ps_in.iter() {
            if p2ps.is_none() {
                warn!(
                    "peer {} says: missing p2ps from peer {}",
                    my_share_id, share_id
                );
                faulters.set(share_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(XProtocolBuilder::Done(Err(faulters)));
        }

        // everyone sent their bcast/p2ps---unwrap all bcasts/p2ps
        let bcasts_in = bcasts_in.to_vecmap()?;
        let p2ps_in = p2ps_in.to_p2ps()?;

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
            let p2p_in = p2ps_in.get(sign_peer_id, my_share_id)?;

            let peer_stmt = &zk::range::StatementWc {
                stmt: zk::range::Statement {
                    ciphertext: peer_k_i_ciphertext,
                    ek: peer_ek,
                },
                msg_g: bcast.R_i.as_ref(),
                g: &self.R,
            };

            if !zkp.verify_range_proof_wc(peer_stmt, &p2p_in.k_i_range_proof_wc) {
                warn!(
                    "peer {} says: range proof wc failed to verify for peer {}",
                    my_share_id, sign_peer_id,
                );

                zkp_complaints.add(sign_peer_id)?;
            }
        }

        corrupt!(
            zkp_complaints,
            self.corrupt_zkp_complaints(my_share_id, zkp_complaints)?
        );

        if !zkp_complaints.is_empty() {
            let bcast_out = Some(serialize(&Bcast::Sad(BcastSad { zkp_complaints }))?);

            return Ok(XProtocolBuilder::NotDone(XRoundBuilder::new(
                Box::new(r7::R7Sad {
                    secret_key_share: self.secret_key_share,
                    participants: self.participants,
                    r1bcasts: self.r1bcasts,
                    R: self.R,
                    r5bcasts: bcasts_in,
                    r5p2ps: p2ps_in,
                }),
                bcast_out,
                None,
            )));
        }

        // check for failure of type 5 from section 4.2 of https://eprint.iacr.org/2020/540.pdf
        let R_i_sum = bcasts_in
            .iter()
            .fold(ProjectivePoint::identity(), |acc, (_, bcast)| {
                acc + bcast.R_i.as_ref()
            });

        // malicious actor falsely claim type 5 fault by comparing against a corrupted curve generator
        let _curve_generator = ProjectivePoint::generator();
        corrupt!(
            _curve_generator,
            self.corrupt_curve_generator(info.share_id())
        );

        // check for type 5 fault
        if R_i_sum != _curve_generator {
            warn!("peer {} says: 'type 5' fault detected", my_share_id);

            let mta_plaintexts = self.beta_secrets.map_ref(|(sign_peer_id, beta_secret)| {
                let r2p2p = self.r2p2ps.get(sign_peer_id, my_share_id)?;

                let (alpha_plaintext, alpha_randomness) = self
                    .secret_key_share
                    .share()
                    .dk()
                    .decrypt_with_randomness(&r2p2p.alpha_ciphertext);

                corrupt!(
                    alpha_plaintext,
                    self.corrupt_alpha_plaintext(my_share_id, sign_peer_id, alpha_plaintext)
                );

                let beta_secret = beta_secret.clone();

                corrupt!(
                    beta_secret,
                    self.corrupt_beta_secret(my_share_id, sign_peer_id, beta_secret)
                );

                Ok(MtaPlaintext {
                    alpha_plaintext,
                    alpha_randomness,
                    beta_secret,
                })
            })?;

            let k_i = self.k_i;
            corrupt!(k_i, self.corrupt_k_i(my_share_id, k_i));

            let bcast_out = Some(serialize(&Bcast::SadType5(BcastSadType5 {
                k_i: k_i.into(),
                k_i_randomness: self.k_i_randomness.clone(),
                gamma_i: self.gamma_i.into(),
                mta_plaintexts,
            }))?);

            return Ok(XProtocolBuilder::NotDone(XRoundBuilder::new(
                Box::new(r7::R7Type5 {
                    secret_key_share: self.secret_key_share,
                    peers: self.peers,
                    participants: self.participants,
                    r1bcasts: self.r1bcasts,
                    r2p2ps: self.r2p2ps,
                    r3bcasts: self.r3bcasts,
                    r4bcasts: self.r4bcasts,
                    R: self.R,
                    r5bcasts: bcasts_in,
                    r5p2ps: p2ps_in,
                }),
                bcast_out,
                None,
            )));
        }

        let S_i = self.R * self.sigma_i;
        let S_i_proof_wc = pedersen::prove_wc(
            &pedersen::StatementWc {
                stmt: pedersen::Statement {
                    prover_id: my_share_id,
                    commit: self.r3bcasts.get(my_share_id)?.T_i.as_ref(),
                },
                msg_g: &S_i,
                g: &self.R,
            },
            &pedersen::Witness {
                msg: &self.sigma_i,
                randomness: &self.l_i,
            },
        )?;

        corrupt!(
            S_i_proof_wc,
            self.corrupt_S_i_proof_wc(my_share_id, S_i_proof_wc)
        );

        let bcast_out = Some(serialize(&Bcast::Happy(BcastHappy {
            S_i: S_i.into(),
            S_i_proof_wc,
        }))?);

        Ok(XProtocolBuilder::NotDone(XRoundBuilder::new(
            Box::new(r7::R7Happy {
                secret_key_share: self.secret_key_share,
                msg_to_sign: self.msg_to_sign,
                peers: self.peers,
                participants: self.participants,
                keygen_id: self.keygen_id,
                k_i: self.k_i,
                k_i_randomness: self.k_i_randomness,
                sigma_i: self.sigma_i,
                r1bcasts: self.r1bcasts,
                r2p2ps: self.r2p2ps,
                r3bcasts: self.r3bcasts,
                R: self.R,
                r5bcasts: bcasts_in,
                r5p2ps: p2ps_in,

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

impl bcast_and_p2p::Executer for R6 {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
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
                msg_g: bcast.R_i.as_ref(),
                g: &self.R,
            };

            if !zkp.verify_range_proof_wc(peer_stmt, &p2p_in.k_i_range_proof_wc) {
                warn!(
                    "peer {} says: range proof wc failed to verify for peer {}",
                    sign_id, sign_peer_id,
                );

                zkp_complaints.add(sign_peer_id)?;
            }
        }

        corrupt!(
            zkp_complaints,
            self.corrupt_zkp_complaints(sign_id, zkp_complaints)?
        );

        if !zkp_complaints.is_empty() {
            let bcast_out = serialize(&Bcast::Sad(BcastSad { zkp_complaints }))?;

            return Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastOnly {
                round: Box::new(r7::R7Sad {
                    secret_key_share: self.secret_key_share,
                    participants: self.participants,
                    r1bcasts: self.r1bcasts,
                    R: self.R,
                    r5bcasts: bcasts_in,
                    r5p2ps: p2ps_in,
                }),
                bcast_out,
            }));
        }

        // check for failure of type 5 from section 4.2 of https://eprint.iacr.org/2020/540.pdf
        let R_i_sum = bcasts_in
            .iter()
            .fold(ProjectivePoint::identity(), |acc, (_, bcast)| {
                acc + bcast.R_i.as_ref()
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
                    self.corrupt_alpha_plaintext(sign_id, sign_peer_id, alpha_plaintext)
                );

                let beta_secret = beta_secret.clone();

                corrupt!(
                    beta_secret,
                    self.corrupt_beta_secret(sign_id, sign_peer_id, beta_secret)
                );

                Ok(MtaPlaintext {
                    alpha_plaintext,
                    alpha_randomness,
                    beta_secret,
                })
            })?;

            let k_i = self.k_i;
            corrupt!(k_i, self.corrupt_k_i(sign_id, k_i));

            let bcast_out = serialize(&Bcast::SadType5(BcastSadType5 {
                k_i: k_i.into(),
                k_i_randomness: self.k_i_randomness.clone(),
                gamma_i: self.gamma_i.into(),
                mta_plaintexts,
            }))?;

            return Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastOnly {
                round: Box::new(r7::R7Type5 {
                    secret_key_share: self.secret_key_share,
                    peers: self.peers,
                    participants: self.participants,
                    r1bcasts: self.r1bcasts,
                    r2p2ps: self.r2p2ps,
                    r3bcasts: self.r3bcasts,
                    r4bcasts: self.r4bcasts,
                    R: self.R,
                    r5bcasts: bcasts_in,
                    r5p2ps: p2ps_in,
                }),
                bcast_out,
            }));
        }

        let S_i = self.R * self.sigma_i;
        let S_i_proof_wc = pedersen::prove_wc(
            &pedersen::StatementWc {
                stmt: pedersen::Statement {
                    prover_id: sign_id,
                    commit: self.r3bcasts.get(sign_id)?.T_i.as_ref(),
                },
                msg_g: &S_i,
                g: &self.R,
            },
            &pedersen::Witness {
                msg: &self.sigma_i,
                randomness: &self.l_i,
            },
        )?;

        corrupt!(
            S_i_proof_wc,
            self.corrupt_S_i_proof_wc(sign_id, S_i_proof_wc)
        );

        let bcast_out = serialize(&Bcast::Happy(BcastHappy {
            S_i: S_i.into(),
            S_i_proof_wc,
        }))?;

        Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastOnly {
            round: Box::new(r7::R7Happy {
                secret_key_share: self.secret_key_share,
                msg_to_sign: self.msg_to_sign,
                peers: self.peers,
                participants: self.participants,
                keygen_id: self.keygen_id,
                k_i: self.k_i,
                k_i_randomness: self.k_i_randomness,
                sigma_i: self.sigma_i,
                r1bcasts: self.r1bcasts,
                r2p2ps: self.r2p2ps,
                r3bcasts: self.r3bcasts,
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
            crypto_tools::{mta::Secret, paillier::Plaintext, zkp::pedersen},
            sign::{
                malicious::{log_confess_info, Behaviour::*},
                SignShareId,
            },
        },
        sdk::api::TofnResult,
    };

    impl R6 {
        /// earlier we prepared to corrupt k_i by corrupting delta_i
        pub fn corrupt_k_i(
            &self,
            sign_id: TypedUsize<SignShareId>,
            mut k_i: k256::Scalar,
        ) -> k256::Scalar {
            if let R3BadKI = self.behaviour {
                log_confess_info(sign_id, &self.behaviour, "step 2/2: k_i");
                k_i += k256::Scalar::one();
            }
            k_i
        }
        /// earlier we prepared to corrupt alpha_plaintext by corrupting delta_i
        pub fn corrupt_alpha_plaintext(
            &self,
            sign_id: TypedUsize<SignShareId>,
            recipient: TypedUsize<SignShareId>,
            mut alpha_plaintext: Plaintext,
        ) -> Plaintext {
            if let R3BadAlpha { victim } = self.behaviour {
                if victim == recipient {
                    log_confess_info(sign_id, &self.behaviour, "step 2/2: alpha_plaintext");
                    alpha_plaintext.corrupt();
                }
            }
            alpha_plaintext
        }
        /// earlier we prepared to corrupt beta_secret by corrupting delta_i
        pub fn corrupt_beta_secret(
            &self,
            sign_id: TypedUsize<SignShareId>,
            recipient: TypedUsize<SignShareId>,
            mut beta_secret: Secret,
        ) -> Secret {
            if let R3BadBeta { victim } = self.behaviour {
                if victim == recipient {
                    log_confess_info(sign_id, &self.behaviour, "step 2/2: beta_secret");
                    *beta_secret.beta.as_mut() += k256::Scalar::one();
                }
            }
            beta_secret
        }
        pub fn corrupt_zkp_complaints(
            &self,
            sign_id: TypedUsize<SignShareId>,
            mut zkp_complaints: Subset<SignShareId>,
        ) -> TofnResult<Subset<SignShareId>> {
            if let R6FalseAccusation { victim } = self.behaviour {
                if zkp_complaints.is_member(victim)? {
                    log_confess_info(sign_id, &self.behaviour, "but the accusation is true");
                } else if victim == sign_id {
                    log_confess_info(sign_id, &self.behaviour, "self accusation");
                    zkp_complaints.add(sign_id)?;
                } else {
                    log_confess_info(sign_id, &self.behaviour, "");
                    zkp_complaints.add(victim)?;
                }
            }
            Ok(zkp_complaints)
        }

        #[allow(non_snake_case)]
        pub fn corrupt_S_i_proof_wc(
            &self,
            sign_id: TypedUsize<SignShareId>,
            range_proof: pedersen::ProofWc,
        ) -> pedersen::ProofWc {
            if let R6BadProof = self.behaviour {
                log_confess_info(sign_id, &self.behaviour, "");
                return pedersen::malicious::corrupt_proof_wc(&range_proof);
            }
            range_proof
        }

        pub fn corrupt_curve_generator(
            &self,
            sign_id: TypedUsize<SignShareId>,
        ) -> k256::ProjectivePoint {
            if let R6FalseFailRandomizer = self.behaviour {
                log_confess_info(sign_id, &self.behaviour, "");
                return k256::ProjectivePoint::identity();
            }
            k256::ProjectivePoint::generator()
        }
    }
}
