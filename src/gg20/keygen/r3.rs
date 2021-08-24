use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    collections::{FillVecMap, P2ps, VecMap},
    corrupt,
    gg20::{
        constants,
        crypto_tools::{hash, k256_serde::to_bytes, paillier, vss, zkp::schnorr},
        keygen::{r4, SecretKeyShare},
    },
    sdk::{
        api::{Fault::ProtocolFault, TofnResult},
        implementer_api::{
            log_accuse_warn, serialize, Executer, ProtocolBuilder, ProtocolInfo, RoundBuilder,
        },
    },
};

use super::{r1, r2, KeygenPartyShareCounts, KeygenShareId};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) enum Bcast {
    Happy(BcastHappy),
    Sad(BcastSad),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct BcastHappy {
    pub(super) x_i_proof: schnorr::Proof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct BcastSad {
    pub(super) vss_complaints: FillVecMap<KeygenShareId, ShareInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct ShareInfo {
    pub(super) share: vss::Share,
    pub(super) randomness: paillier::Randomness,
}

pub(super) struct R3 {
    pub(super) threshold: usize,
    pub(super) party_share_counts: KeygenPartyShareCounts,
    pub(super) dk: paillier::DecryptionKey,
    pub(super) u_i_share: vss::Share,
    pub(super) r1bcasts: VecMap<KeygenShareId, r1::Bcast>,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

impl Executer for R3 {
    type FinalOutput = SecretKeyShare;
    type Index = KeygenShareId;
    type Bcast = r2::Bcast;
    type P2p = r2::P2p;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: FillVecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<ProtocolBuilder<Self::FinalOutput, Self::Index>> {
        let my_keygen_id = info.my_id();
        let mut faulters = FillVecMap::with_size(info.total_share_count());

        // anyone who did not send a bcast is a faulter
        for (peer_keygen_id, bcast) in bcasts_in.iter() {
            if bcast.is_none() {
                warn!(
                    "peer {} says: missing bcast from peer {}",
                    my_keygen_id, peer_keygen_id
                );
                faulters.set(peer_keygen_id, ProtocolFault)?;
            }
        }
        // anyone who did not send p2ps is a faulter
        for (peer_keygen_id, p2ps) in p2ps_in.iter() {
            if p2ps.is_none() {
                warn!(
                    "peer {} says: missing p2ps from peer {}",
                    my_keygen_id, peer_keygen_id
                );
                faulters.set(peer_keygen_id, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // everyone sent their bcast/p2ps---unwrap all bcasts/p2ps
        let bcasts_in = bcasts_in.to_vecmap()?;
        let p2ps_in = p2ps_in.to_fullp2ps()?;

        // check y_i commits
        for (peer_keygen_id, bcast) in bcasts_in.iter() {
            let peer_y_i = bcast.u_i_vss_commit.secret_commit();
            let peer_y_i_commit = hash::commit_with_randomness(
                constants::Y_I_COMMIT_TAG,
                peer_keygen_id,
                to_bytes(peer_y_i),
                &bcast.y_i_reveal,
            );

            if peer_y_i_commit != self.r1bcasts.get(peer_keygen_id)?.y_i_commit {
                warn!(
                    "peer {} says: invalid y_i reveal by peer {}",
                    my_keygen_id, peer_keygen_id
                );

                faulters.set(peer_keygen_id, ProtocolFault)?;
            }
        }

        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // decrypt shares
        let share_infos = p2ps_in.map_to_me(my_keygen_id, |p2p| {
            let (u_i_share_plaintext, u_i_share_randomness) =
                self.dk.decrypt_with_randomness(&p2p.u_i_share_ciphertext);

            let u_i_share =
                vss::Share::from_scalar(u_i_share_plaintext.to_scalar(), my_keygen_id.as_usize());

            ShareInfo {
                share: u_i_share,
                randomness: u_i_share_randomness,
            }
        })?;

        // validate shares
        let mut vss_complaints = FillVecMap::with_size(info.total_share_count());
        for (peer_keygen_id, share_info) in share_infos.iter() {
            if !bcasts_in
                .get(peer_keygen_id)?
                .u_i_vss_commit
                .validate_share(&share_info.share)
            {
                log_accuse_warn(my_keygen_id, peer_keygen_id, "invalid vss share");

                vss_complaints.set(
                    peer_keygen_id,
                    ShareInfo {
                        share: share_info.share.clone(),
                        randomness: share_info.randomness.clone(),
                    },
                )?;
            }
        }

        corrupt!(
            vss_complaints,
            self.corrupt_complaint(my_keygen_id, &share_infos, vss_complaints)?
        );

        if !vss_complaints.is_empty() {
            let bcast_out = Some(serialize(&Bcast::Sad(BcastSad { vss_complaints }))?);

            return Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
                Box::new(r4::R4Sad {
                    r1bcasts: self.r1bcasts,
                    r2bcasts: bcasts_in,
                    r2p2ps: p2ps_in,
                }),
                bcast_out,
                None,
            )));
        }

        // compute x_i
        let x_i = share_infos
            .into_iter()
            .fold(*self.u_i_share.get_scalar(), |acc, (_, share_info)| {
                acc + share_info.share.get_scalar()
            });

        // compute y
        let y = bcasts_in
            .iter()
            .fold(k256::ProjectivePoint::identity(), |acc, (_, r2bcast)| {
                acc + r2bcast.u_i_vss_commit.secret_commit()
            });

        // compute all_X_i
        let all_X_i: VecMap<KeygenShareId, k256::ProjectivePoint> = (0..info.total_share_count())
            .map(|i| {
                bcasts_in
                    .iter()
                    .fold(k256::ProjectivePoint::identity(), |acc, (_, x)| {
                        acc + x.u_i_vss_commit.share_commit(i)
                    })
            })
            .collect();

        corrupt!(x_i, self.corrupt_scalar(my_keygen_id, x_i));

        let x_i_proof = schnorr::prove(
            &schnorr::Statement {
                prover_id: my_keygen_id,
                base: &k256::ProjectivePoint::generator(),
                target: all_X_i.get(my_keygen_id)?,
            },
            &schnorr::Witness { scalar: &x_i },
        );

        let bcast_out = Some(serialize(&Bcast::Happy(BcastHappy { x_i_proof }))?);

        Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
            Box::new(r4::R4Happy {
                threshold: self.threshold,
                party_share_counts: self.party_share_counts,
                dk: self.dk,
                r1bcasts: self.r1bcasts,
                r2bcasts: bcasts_in,
                r2p2ps: p2ps_in,
                y,
                x_i,
                all_X_i,
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
    use super::{ShareInfo, R3};
    use crate::{
        collections::{FillVecMap, HoleVecMap, TypedUsize},
        gg20::{crypto_tools::vss, keygen::KeygenShareId},
        sdk::api::TofnResult,
    };

    use super::super::malicious::{log_confess_info, Behaviour};

    impl R3 {
        pub fn corrupt_scalar(
            &self,
            keygen_id: TypedUsize<KeygenShareId>,
            mut x_i: k256::Scalar,
        ) -> k256::Scalar {
            if let Behaviour::R3BadXIWitness = self.behaviour {
                log_confess_info(keygen_id, &self.behaviour, "");
                x_i += k256::Scalar::one();
            }
            x_i
        }

        pub fn corrupt_complaint(
            &self,
            keygen_id: TypedUsize<KeygenShareId>,
            share_infos: &HoleVecMap<KeygenShareId, ShareInfo>,
            mut vss_complaints: FillVecMap<KeygenShareId, ShareInfo>,
        ) -> TofnResult<FillVecMap<KeygenShareId, ShareInfo>> {
            if let Behaviour::R3FalseAccusation { victim } = self.behaviour {
                if !vss_complaints.is_none(victim)? {
                    log_confess_info(keygen_id, &self.behaviour, "but the accusation is true");
                } else if victim == keygen_id {
                    log_confess_info(keygen_id, &self.behaviour, "self accusation");

                    vss_complaints.set(
                        victim,
                        ShareInfo {
                            share: vss::Share::from_scalar(k256::Scalar::one(), 1), // junk data
                            randomness: self.r1bcasts.get(keygen_id)?.ek.sample_randomness(), // junk data
                        },
                    )?;
                } else {
                    log_confess_info(keygen_id, &self.behaviour, "");

                    vss_complaints.set(victim, share_infos.get(victim)?.clone())?;
                }
            }

            Ok(vss_complaints)
        }
    }
}
