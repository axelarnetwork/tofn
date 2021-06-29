use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    fillvec::FillVec,
    hash,
    k256_serde::to_bytes,
    paillier_k256,
    protocol::gg20::vss_k256,
    refactor::{
        keygen::r4,
        protocol::executer::{
            serialize_as_option, ProtocolBuilder, ProtocolRoundBuilder, RoundExecuterTyped,
        },
    },
    vecmap::VecMap,
    zkp::schnorr_k256,
};

use super::{r1, r2, Crime, KeygenOutput, KeygenPartyIndex};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Bcast {
    pub(super) x_i_proof: schnorr_k256::Proof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BcastFail {
    pub vss_complaints: Vec<VssComplaint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssComplaint {
    pub criminal_index: usize,
    pub share: vss_k256::Share,
    pub share_randomness: paillier_k256::Randomness,
}

pub(super) struct R3 {
    pub(super) threshold: usize,
    pub(super) dk: paillier_k256::DecryptionKey,
    pub(super) u_i_my_share: vss_k256::Share,
    pub(super) r1bcasts: Vec<r1::Bcast>, // TODO Vec<everything>
}

impl RoundExecuterTyped for R3 {
    type FinalOutputTyped = KeygenOutput;
    type Index = KeygenPartyIndex;
    type Bcast = r2::Bcast;
    type P2p = r2::P2p;

    #[allow(non_snake_case)]
    fn execute_typed(
        self: Box<Self>,
        party_count: usize,
        index: usize,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
        p2ps_in: Vec<FillVec<Self::P2p>>,
    ) -> ProtocolBuilder<Self::FinalOutputTyped, Self::Index> {
        // check y_i commits
        let criminals: Vec<Vec<Crime>> = bcasts_in
            .iter()
            .map(|(i, r2bcast)| {
                let r1bcast = &self.r1bcasts[i.as_usize()];
                let y_i = r2bcast.u_i_share_commits.secret_commit();
                let y_i_commit = hash::commit_with_randomness(to_bytes(y_i), &r2bcast.y_i_reveal);
                if y_i_commit != r1bcast.y_i_commit {
                    let crime = Crime::R3BadReveal;
                    warn!("party {} detect {:?} by {}", index, crime, i);
                    vec![crime]
                } else {
                    vec![]
                }
            })
            .collect();
        if !criminals.iter().all(Vec::is_empty) {
            return ProtocolBuilder::Done(Err(criminals));
        }

        // decrypt shares
        // TODO share_infos iterates only over _other_ parties
        // ie. iterate over p2p msgs from others to me
        let share_infos: FillVec<(vss_k256::Share, paillier_k256::Randomness)> = FillVec::from_vec(
            p2ps_in
                .iter()
                .map(|r2_p2ps| {
                    // return None if my_p2p is None
                    r2_p2ps.vec_ref()[index].as_ref().map(|my_p2p| {
                        let (u_i_share_plaintext, u_i_share_randomness) = self
                            .dk
                            .decrypt_with_randomness(&my_p2p.u_i_share_ciphertext);
                        let u_i_share =
                            vss_k256::Share::from_scalar(u_i_share_plaintext.to_scalar(), index);
                        (u_i_share, u_i_share_randomness)
                    })
                })
                .collect(),
        );

        // validate shares
        // TODO zip
        // - share_infos (which iterates only over _other_ parties)
        // - r2bcasts (which iterates over _all_ parties)
        let vss_failures: Vec<VssComplaint> = share_infos
            .vec_ref()
            .iter()
            .zip(bcasts_in.iter())
            .filter_map(|(share_info, (from, r2bcast))| {
                if let Some((u_i_share, u_i_share_randomness)) = share_info {
                    if !r2bcast.u_i_share_commits.validate_share(&u_i_share) {
                        warn!(
                            "party {} accuse {} of {:?}",
                            index,
                            from,
                            Crime::R4FailBadVss { victim: index },
                        );
                        Some(VssComplaint {
                            criminal_index: from.as_usize(),
                            share: u_i_share.clone(),
                            share_randomness: u_i_share_randomness.clone(),
                        })
                    } else {
                        None
                    }
                } else {
                    None // if share_info is none then I must be talking to myself
                }
            })
            .collect();
        // if !vss_failures.is_empty() {
        //     return RoundOutput::NotDone(RoundWaiter {
        //         round: Box::new(r4::R4 {
        //             share_count: party_count,
        //             threshold: self.threshold,
        //             index: index,
        //         }),
        //         msgs_out: SerializedMsgs {
        //             bcast: None,
        //             p2ps: None,
        //         },
        //         msgs_in: vec![
        //             SerializedMsgs {
        //                 bcast: None,
        //                 p2ps: None,
        //             };
        //             party_count
        //         ],
        //     })
        // }

        // compute x_i
        let x_i = share_infos
            .vec_ref()
            .iter()
            .filter_map(|share_info| {
                if let Some((share, _)) = share_info {
                    Some(share.get_scalar())
                } else {
                    None
                }
            })
            .fold(*self.u_i_my_share.get_scalar(), |acc, x| acc + x);

        // compute y
        let y = bcasts_in
            .iter()
            .fold(k256::ProjectivePoint::identity(), |acc, (_, r2bcast)| {
                acc + r2bcast.u_i_share_commits.secret_commit()
            });

        // compute all_X_i
        let all_X_i: Vec<k256::ProjectivePoint> = (0..party_count)
            .map(|i| {
                bcasts_in
                    .iter()
                    .fold(k256::ProjectivePoint::identity(), |acc, (_, x)| {
                        acc + x.u_i_share_commits.share_commit(i)
                    })
            })
            .collect();

        let x_i_proof = schnorr_k256::prove(
            &schnorr_k256::Statement {
                base: &k256::ProjectivePoint::generator(),
                target: &all_X_i[index],
            },
            &schnorr_k256::Witness { scalar: &x_i },
        );

        ProtocolBuilder::NotDone(ProtocolRoundBuilder {
            round: Box::new(r4::R4 {
                threshold: self.threshold,
                dk: self.dk,
                r1bcasts: self.r1bcasts,
                y,
                x_i,
                all_X_i,
            }),
            bcast_out: serialize_as_option(&Bcast { x_i_proof }),
            p2ps_out: None,
        })
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
