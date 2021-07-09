use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    hash,
    k256_serde::to_bytes,
    paillier_k256,
    protocol::gg20::{vss_k256, SecretKeyShare},
    refactor::{
        keygen::r4,
        protocol::{
            executer::{
                log_accuse_warn, serialize, ProtocolBuilder, ProtocolRoundBuilder, RoundExecuter,
            },
            Fault::ProtocolFault,
        },
    },
    vecmap::{FillVecMap, Index, P2ps, VecMap},
    zkp::schnorr_k256,
};

use super::{r1, r2, KeygenPartyIndex};

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
    pub vss_complaints: FillVecMap<KeygenPartyIndex, VssComplaint>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VssComplaint {
    pub share: vss_k256::Share,
    pub share_randomness: paillier_k256::Randomness,
}

pub struct R3 {
    pub threshold: usize,
    pub dk: paillier_k256::DecryptionKey,
    pub u_i_my_share: vss_k256::Share,
    pub r1bcasts: VecMap<KeygenPartyIndex, r1::Bcast>,

    #[cfg(feature = "malicious")]
    pub behaviour: Behaviour,
}

impl RoundExecuter for R3 {
    type FinalOutput = SecretKeyShare;
    type Index = KeygenPartyIndex;
    type Bcast = r2::Bcast;
    type P2p = r2::P2p;

    #[allow(non_snake_case)]
    fn execute(
        self: Box<Self>,
        party_count: usize,
        index: Index<Self::Index>,
        bcasts_in: VecMap<Self::Index, Self::Bcast>,
        p2ps_in: P2ps<Self::Index, Self::P2p>,
    ) -> ProtocolBuilder<Self::FinalOutput, Self::Index> {
        let mut faulters = FillVecMap::with_size(party_count);

        // check y_i commits
        for (from, bcast) in bcasts_in.iter() {
            let y_i = bcast.u_i_vss_commit.secret_commit();
            let y_i_commit = hash::commit_with_randomness(to_bytes(y_i), &bcast.y_i_reveal);
            if y_i_commit != self.r1bcasts.get(from).y_i_commit {
                warn!("party {} detect bad reveal by {}", index, from);
                faulters.set(from, ProtocolFault);
            }
        }
        if !faulters.is_empty() {
            return ProtocolBuilder::Done(Err(faulters));
        }

        // decrypt shares
        let share_infos = p2ps_in.map_to_me(index, |p2p| {
            let (u_i_share_plaintext, u_i_share_randomness) =
                self.dk.decrypt_with_randomness(&p2p.u_i_share_ciphertext);
            let u_i_share =
                vss_k256::Share::from_scalar(u_i_share_plaintext.to_scalar(), index.as_usize());
            (u_i_share, u_i_share_randomness)
        });

        // validate shares
        let mut vss_complaints = FillVecMap::with_size(party_count);
        for (from, (share, randomness)) in share_infos.iter() {
            if !bcasts_in.get(from).u_i_vss_commit.validate_share(share) {
                log_accuse_warn(index, from, "invalid vss share");
                vss_complaints.set(
                    from,
                    VssComplaint {
                        share: share.clone(),
                        share_randomness: randomness.clone(),
                    },
                );
            }
        }
        if !vss_complaints.is_empty() {
            return ProtocolBuilder::NotDone(ProtocolRoundBuilder {
                round: Box::new(r4::sad::R4Sad {
                    r1bcasts: self.r1bcasts,
                    r2bcasts: bcasts_in,
                    r2p2ps: p2ps_in,
                }),
                bcast_out: Some(serialize(&Bcast::Sad(BcastSad { vss_complaints }))),
                p2ps_out: None,
            });
        }

        // compute x_i
        let x_i = share_infos
            .into_iter()
            .fold(*self.u_i_my_share.get_scalar(), |acc, (_, (share, _))| {
                acc + share.get_scalar()
            });

        // compute y
        let y = bcasts_in
            .iter()
            .fold(k256::ProjectivePoint::identity(), |acc, (_, r2bcast)| {
                acc + r2bcast.u_i_vss_commit.secret_commit()
            });

        // compute all_X_i
        let all_X_i: VecMap<KeygenPartyIndex, k256::ProjectivePoint> = (0..party_count)
            .map(|i| {
                bcasts_in
                    .iter()
                    .fold(k256::ProjectivePoint::identity(), |acc, (_, x)| {
                        acc + x.u_i_vss_commit.share_commit(i)
                    })
            })
            .collect();

        let x_i = self.corrupt_scalar(index, x_i);

        let x_i_proof = schnorr_k256::prove(
            &schnorr_k256::Statement {
                base: &k256::ProjectivePoint::generator(),
                target: &all_X_i.get(index),
            },
            &schnorr_k256::Witness { scalar: &x_i },
        );

        ProtocolBuilder::NotDone(ProtocolRoundBuilder {
            round: Box::new(r4::happy::R4 {
                threshold: self.threshold,
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
            bcast_out: Some(serialize(&Bcast::Happy(BcastHappy { x_i_proof }))),
            p2ps_out: None,
        })
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

pub mod malicious {
    use tracing::info;

    use crate::{
        refactor::keygen::{self, KeygenPartyIndex},
        vecmap::Index,
    };

    use super::R3;

    impl R3 {
        pub fn corrupt_scalar(
            &self,
            my_index: Index<KeygenPartyIndex>,
            mut x_i: k256::Scalar,
        ) -> k256::Scalar {
            #[cfg(feature = "malicious")]
            if let keygen::Behaviour::R3BadXIWitness = self.behaviour {
                info!("malicious party {} do {:?}", my_index, self.behaviour);
                x_i += k256::Scalar::one();
            }
            x_i
        }
    }
}
