use crate::{
    collections::{zip2, FillVecMap, FullP2ps, HoleVecMap, P2ps, TypedUsize, VecMap},
    crypto_tools::{hash::Randomness, k256_serde, mta::Secret, paillier, zkp::pedersen},
    gg20::{
        keygen::{KeygenShareId, SecretKeyShare},
        sign::{
            r4::{self, Bcast},
            type5_common::{BcastSadType5, MtaPlaintext, P2pSadType5},
            KeygenShareIds,
        },
    },
    sdk::{
        api::{BytesVec, Fault::ProtocolFault, TofnResult},
        implementer_api::{serialize, Executer, ProtocolBuilder, ProtocolInfo, RoundBuilder},
    },
};
use k256::{ProjectivePoint, Scalar};
use serde::{Deserialize, Serialize};
use tracing::warn;

use super::super::{r1, r2, r3, r5, Peers, SignShareId};

#[cfg(feature = "malicious")]
use super::super::malicious::Behaviour;

#[allow(non_snake_case)]
pub(in super::super) struct R4Happy {
    pub(in super::super) secret_key_share: SecretKeyShare,
    pub(in super::super) msg_to_sign: Scalar,
    pub(in super::super) peer_keygen_ids: Peers,
    pub(in super::super) all_keygen_ids: KeygenShareIds,
    pub(in super::super) my_keygen_id: TypedUsize<KeygenShareId>,
    pub(in super::super) gamma_i: Scalar,
    pub(in super::super) Gamma_i: ProjectivePoint,
    pub(in super::super) Gamma_i_reveal: Randomness,
    pub(in super::super) k_i: Scalar,
    pub(in super::super) k_i_randomness: paillier::Randomness,
    pub(in super::super) sigma_i: Scalar,
    pub(in super::super) l_i: Scalar,
    pub(in super::super) beta_secrets: HoleVecMap<SignShareId, Secret>,
    pub(in super::super) r1bcasts: VecMap<SignShareId, r1::Bcast>,
    pub(in super::super) r2p2ps: FullP2ps<SignShareId, r2::P2pHappy>,

    #[cfg(feature = "malicious")]
    pub(in super::super) behaviour: Behaviour,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct BcastHappy {
    pub(in super::super) Gamma_i: k256_serde::ProjectivePoint,
    pub(in super::super) Gamma_i_reveal: Randomness,
}

impl Executer for R4Happy {
    type FinalOutput = BytesVec;
    type Index = SignShareId;
    type Bcast = r3::BcastHappy;
    type P2p = r3::P2pSad;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let my_sign_id = info.my_id();
        let mut faulters = info.new_fillvecmap();

        // TODO make this round look like r3, r7

        // anyone who sent both bcast and p2p is a faulter
        for (peer_sign_id, bcast_option, p2ps_option) in zip2(&bcasts_in, &p2ps_in) {
            if bcast_option.is_some() && p2ps_option.is_some() {
                warn!(
                    "peer {} says: unexpected p2ps and bcast from peer {} in round 4 happy path",
                    my_sign_id, peer_sign_id
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // if anyone complained then move to sad path
        if p2ps_in.iter().any(|(_, p2ps_option)| p2ps_option.is_some()) {
            warn!(
                "peer {} says: received an R3 complaint from others--move to sad path",
                my_sign_id,
            );

            return Box::new(r4::R4Sad {
                secret_key_share: self.secret_key_share,
                all_keygen_ids: self.all_keygen_ids,
                r1bcasts: self.r1bcasts,
                r2p2ps: self.r2p2ps,
            })
            .execute(info, bcasts_in, p2ps_in);
        }

        // happy path: everyone sent bcast---unwrap all bcasts
        let bcasts_in = bcasts_in.to_vecmap()?;

        // verify zk proof for step 2 of MtA k_i * gamma_j
        for (peer_sign_id, bcast) in &bcasts_in {
            let peer_stmt = pedersen::Statement {
                prover_id: peer_sign_id,
                commit: bcast.T_i.as_ref(),
            };

            if !pedersen::verify(&peer_stmt, &bcast.T_i_proof) {
                warn!(
                    "peer {} says: pedersen proof failed to verify for peer {}",
                    my_sign_id, peer_sign_id,
                );
                faulters.set(peer_sign_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // prepare BcastHappy
        let Gamma_i_reveal = self.Gamma_i_reveal.clone();
        corrupt!(
            Gamma_i_reveal,
            self.corrupt_Gamma_i_reveal(my_sign_id, Gamma_i_reveal)
        );

        let bcast_happy = BcastHappy {
            Gamma_i: self.Gamma_i.into(),
            Gamma_i_reveal,
        };

        // compute delta_inv
        let delta_inv = bcasts_in
            .iter()
            .fold(Scalar::zero(), |acc, (_, bcast)| {
                acc + bcast.delta_i.as_ref()
            })
            .invert();

        // if delta_inv is undefined then move to 'type 5' sad path https://github.com/axelarnetwork/tofn/issues/110
        if bool::from(delta_inv.is_none()) {
            warn!(
                "peer {} says: delta inversion failure: switch to 'type 5' sad path",
                my_sign_id
            );

            let mta_plaintexts =
                self.beta_secrets
                    .ref_map2_result(|(peer_sign_id, beta_secret)| {
                        let r2p2p = self.r2p2ps.get(peer_sign_id, my_sign_id)?;
                        let (alpha_plaintext, alpha_randomness) = self
                            .secret_key_share
                            .share()
                            .dk()
                            .decrypt_with_randomness(&r2p2p.alpha_ciphertext);
                        Ok(MtaPlaintext {
                            alpha_plaintext,
                            alpha_randomness,
                            beta_secret: beta_secret.clone(),
                        })
                    })?;

            let bcast_out = Some(serialize(&Bcast::SadType5(
                bcast_happy,
                BcastSadType5 {
                    k_i: self.k_i.into(),
                    k_i_randomness: self.k_i_randomness.clone(),
                    gamma_i: self.gamma_i.into(),
                },
            ))?);

            let p2ps_out = Some(
                mta_plaintexts
                    .map2_result(|(_, mta_plaintext)| serialize(&P2pSadType5 { mta_plaintext }))?,
            );

            return Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
                Box::new(r5::R5Type5 {
                    secret_key_share: self.secret_key_share,
                    all_keygen_ids: self.all_keygen_ids,
                    r1bcasts: self.r1bcasts,
                    r2p2ps: self.r2p2ps,
                    r3bcasts: bcasts_in,
                }),
                bcast_out,
                p2ps_out,
            )));
        }

        let bcast_out = Some(serialize(&Bcast::Happy(bcast_happy))?);

        Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
            Box::new(r5::R5 {
                secret_key_share: self.secret_key_share,
                msg_to_sign: self.msg_to_sign,
                peer_keygen_ids: self.peer_keygen_ids,
                all_keygen_ids: self.all_keygen_ids,
                my_keygen_id: self.my_keygen_id,
                gamma_i: self.gamma_i,
                k_i: self.k_i,
                k_i_randomness: self.k_i_randomness,
                sigma_i: self.sigma_i,
                l_i: self.l_i,
                beta_secrets: self.beta_secrets,
                r1bcasts: self.r1bcasts,
                r2p2ps: self.r2p2ps,
                r3bcasts: bcasts_in,
                delta_inv: delta_inv.unwrap(),

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
    use super::R4Happy;
    use crate::{
        collections::TypedUsize,
        crypto_tools::hash::Randomness,
        gg20::sign::{
            malicious::{log_confess_info, Behaviour::*},
            SignShareId,
        },
    };

    impl R4Happy {
        #[allow(non_snake_case)]
        pub fn corrupt_Gamma_i_reveal(
            &self,
            sign_id: TypedUsize<SignShareId>,
            mut Gamma_i_reveal: Randomness,
        ) -> Randomness {
            if let R4BadReveal = self.behaviour {
                log_confess_info(sign_id, &self.behaviour, "");
                Gamma_i_reveal.corrupt();
            }
            Gamma_i_reveal
        }
    }
}
