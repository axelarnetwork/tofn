use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    corrupt, hash,
    k256_serde::to_bytes,
    paillier_k256,
    protocol::gg20::vss_k256,
    refactor::collections::{FillVecMap, P2ps, VecMap},
    refactor::{
        keygen::{r4, SecretKeyShare},
        sdk::{
            api::{Fault::ProtocolFault, TofnResult},
            implementer_api::{
                bcast_and_p2p, log_accuse_warn, serialize, ProtocolBuilder, ProtocolInfo,
                RoundBuilder,
            },
        },
    },
    zkp::schnorr_k256,
};

use super::{r1, r2, KeygenPartyIndex, KeygenPartyShareCounts, KeygenProtocolBuilder};

#[cfg(feature = "malicious")]
use super::malicious::Behaviour;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Bcast {
    Happy(BcastHappy),
    Sad(BcastSad),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BcastHappy {
    pub x_i_proof: schnorr_k256::Proof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BcastSad {
    pub vss_complaints: FillVecMap<KeygenPartyIndex, ShareInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShareInfo {
    pub share: vss_k256::Share,
    pub randomness: paillier_k256::Randomness,
}

pub struct R3 {
    pub threshold: usize,
    pub party_share_counts: KeygenPartyShareCounts,
    pub dk: paillier_k256::DecryptionKey,
    pub u_i_my_share: vss_k256::Share,
    pub r1bcasts: VecMap<KeygenPartyIndex, r1::Bcast>,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

impl bcast_and_p2p::Executer for R3 {
    type FinalOutput = SecretKeyShare;
    type Index = KeygenPartyIndex;
    type Bcast = r2::Bcast;
    type P2p = r2::P2p;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        info: &ProtocolInfo<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> TofnResult<KeygenProtocolBuilder> {
        let mut faulters = FillVecMap::with_size(info.share_count());

        // check y_i commits  // TODO: Why are we verifying our own bcast?
        for (from, bcast) in bcasts_in.iter() {
            let y_i = bcast.u_i_vss_commit.secret_commit();
            let y_i_commit = hash::commit_with_randomness(to_bytes(y_i), &bcast.y_i_reveal);
            if y_i_commit != self.r1bcasts.get(from)?.y_i_commit {
                warn!("party {} detect bad reveal by {}", info.share_id(), from);
                faulters.set(from, ProtocolFault)?;
            }
        }
        if !faulters.is_empty() {
            return Ok(ProtocolBuilder::Done(Err(faulters)));
        }

        // decrypt shares
        let share_infos = p2ps_in.map_to_me(info.share_id(), |p2p| {
            let (u_i_share_plaintext, u_i_share_randomness) =
                self.dk.decrypt_with_randomness(&p2p.u_i_share_ciphertext);
            let u_i_share = vss_k256::Share::from_scalar(
                u_i_share_plaintext.to_scalar(),
                info.share_id().as_usize(),
            );
            ShareInfo {
                share: u_i_share,
                randomness: u_i_share_randomness,
            }
        })?;

        // validate shares
        let mut vss_complaints = FillVecMap::with_size(info.share_count());
        for (from, share_info) in share_infos.iter() {
            if !bcasts_in
                .get(from)?
                .u_i_vss_commit
                .validate_share(&share_info.share)
            {
                log_accuse_warn(info.share_id(), from, "invalid vss share");
                vss_complaints.set(
                    from,
                    ShareInfo {
                        share: share_info.share.clone(),
                        randomness: share_info.randomness.clone(),
                    },
                )?;
            }
        }

        corrupt!(
            vss_complaints,
            self.corrupt_complaint(info.share_id(), &share_infos, vss_complaints)?
        );

        if !vss_complaints.is_empty() {
            return Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastOnly {
                round: Box::new(r4::sad::R4Sad {
                    r1bcasts: self.r1bcasts,
                    r2bcasts: bcasts_in,
                    r2p2ps: p2ps_in,
                }),
                bcast_out: serialize(&Bcast::Sad(BcastSad { vss_complaints }))?,
            }));
        }

        // compute x_i
        let x_i = share_infos
            .into_iter()
            .fold(*self.u_i_my_share.get_scalar(), |acc, (_, share_info)| {
                acc + share_info.share.get_scalar()
            });

        // compute y
        let y = bcasts_in
            .iter()
            .fold(k256::ProjectivePoint::identity(), |acc, (_, r2bcast)| {
                acc + r2bcast.u_i_vss_commit.secret_commit()
            });

        // compute all_X_i
        let all_X_i: VecMap<KeygenPartyIndex, k256::ProjectivePoint> = (0..info.share_count())
            .map(|i| {
                bcasts_in
                    .iter()
                    .fold(k256::ProjectivePoint::identity(), |acc, (_, x)| {
                        acc + x.u_i_vss_commit.share_commit(i)
                    })
            })
            .collect();

        corrupt!(x_i, self.corrupt_scalar(info.share_id(), x_i));

        let x_i_proof = schnorr_k256::prove(
            &schnorr_k256::Statement {
                base: &k256::ProjectivePoint::generator(),
                target: all_X_i.get(info.share_id())?,
            },
            &schnorr_k256::Witness { scalar: &x_i },
        );

        Ok(ProtocolBuilder::NotDone(RoundBuilder::BcastOnly {
            round: Box::new(r4::happy::R4 {
                threshold: self.threshold,
                party_share_counts: self.party_share_counts,
                dk: self.dk,
                r1bcasts: self.r1bcasts,
                r2bcasts: bcasts_in,
                r2p2ps: p2ps_in,
                y,
                x_i,
                all_X_i,
                #[cfg(feature = "malicious")]
                behaviour: self.behaviour,
            }),
            bcast_out: serialize(&Bcast::Happy(BcastHappy { x_i_proof }))?,
        }))
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
        protocol::gg20::vss_k256,
        refactor::{
            collections::{FillVecMap, HoleVecMap, TypedUsize},
            keygen::KeygenPartyIndex,
            sdk::api::TofnResult,
        },
    };

    use super::super::malicious::{log_confess_info, Behaviour};

    impl R3 {
        pub fn corrupt_scalar(
            &self,
            my_index: TypedUsize<KeygenPartyIndex>,
            mut x_i: k256::Scalar,
        ) -> k256::Scalar {
            if let Behaviour::R3BadXIWitness = self.behaviour {
                log_confess_info(my_index, &self.behaviour, "");
                x_i += k256::Scalar::one();
            }
            x_i
        }

        pub fn corrupt_complaint(
            &self,
            index: TypedUsize<KeygenPartyIndex>,
            share_infos: &HoleVecMap<KeygenPartyIndex, ShareInfo>,
            mut vss_complaints: FillVecMap<KeygenPartyIndex, ShareInfo>,
        ) -> TofnResult<FillVecMap<KeygenPartyIndex, ShareInfo>> {
            if let Behaviour::R3FalseAccusation { victim } = self.behaviour {
                if !vss_complaints.is_none(victim)? {
                    log_confess_info(index, &self.behaviour, "but the accusation is true");
                } else if victim == index {
                    log_confess_info(index, &self.behaviour, "self accusation");
                    vss_complaints.set(
                        victim,
                        ShareInfo {
                            share: vss_k256::Share::from_scalar(k256::Scalar::one(), 1), // junk data
                            randomness: self.r1bcasts.get(index)?.ek.sample_randomness(), // junk data
                        },
                    )?;
                } else {
                    log_confess_info(index, &self.behaviour, "");
                    vss_complaints.set(victim, share_infos.get(victim)?.clone())?;
                }
            }

            Ok(vss_complaints)
        }
    }
}
