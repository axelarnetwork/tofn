use serde::{Deserialize, Serialize};

use super::{Keygen, Status};
use crate::{fillvec::FillVec, hash, paillier_k256, protocol::gg20::vss_k256};

#[cfg(feature = "malicious")]
use {super::malicious::Behaviour, tracing::info};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Bcast {
    pub(super) y_i_reveal_k256: hash::Randomness,
    pub(super) u_i_share_commits_k256: vss_k256::Commit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct P2p {
    pub(crate) u_i_share_ciphertext_k256: paillier_k256::Ciphertext,
}

#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub(super) struct State {
    pub(super) my_share_of_my_u_i_k256: vss_k256::Share,
}

impl Keygen {
    pub(super) fn r2(&self) -> (State, Bcast, FillVec<P2p>) {
        assert!(matches!(self.status, Status::R1));
        let r1state = self.r1state.as_ref().unwrap();

        // TODO check Paillier proofs?
        // for (i, in_r1bcast) in self.in_r1bcasts.vec_ref().iter().enumerate() {
        //     if i == self.my_index {
        //         continue;
        //     }
        //     let r1bcast = in_r1bcast.as_ref().unwrap();
        //     r1bcast
        //         .correct_key_proof
        //         .verify(&r1bcast.ek)
        //         .unwrap_or_else(|_| {
        //             panic!(
        //                 "party {} says: key proof failed to verify for party {}",
        //                 self.my_index, i
        //             )
        //         });
        //     if !r1bcast.zkp.verify_composite_dlog_proof() {
        //         panic!(
        //             "party {} says: dlog proof failed to verify for party {}",
        //             self.my_index, i
        //         );
        //     }
        // }

        // k256:: share my u_i
        let my_u_i_shares_k256 = r1state.my_u_i_vss_k256.shares(self.share_count);

        #[cfg(feature = "malicious")]
        let my_u_i_shares_k256 = if let Behaviour::R2BadShare { victim } = self.behaviour {
            info!(
                "(k256) malicious party {} do {:?}",
                self.my_index, self.behaviour
            );
            my_u_i_shares_k256
                .iter()
                .enumerate()
                .map(|(i, s)| {
                    if i == victim {
                        vss_k256::Share::from_scalar(
                            s.get_scalar() + k256::Scalar::one(),
                            s.get_index(),
                        )
                    } else {
                        s.clone()
                    }
                })
                .collect()
        } else {
            my_u_i_shares_k256
        };

        let mut out_p2ps = FillVec::with_len(self.share_count);
        for (i, my_u_i_share_k256) in my_u_i_shares_k256.iter().enumerate() {
            if i == self.my_index {
                continue;
            }

            // k256: encrypt the share for party i
            let ek_256 = &self.in_r1bcasts.vec_ref()[i].as_ref().unwrap().ek_k256;
            let (u_i_share_ciphertext_k256, _) =
                ek_256.encrypt(&my_u_i_share_k256.get_scalar().into());

            #[cfg(feature = "malicious")]
            let u_i_share_ciphertext_k256 = match self.behaviour {
                Behaviour::R2BadEncryption { victim } if victim == i => {
                    info!(
                        "(k256) malicious party {} do {:?}",
                        self.my_index, self.behaviour
                    );
                    u_i_share_ciphertext_k256.corrupt()
                }
                _ => u_i_share_ciphertext_k256,
            };

            out_p2ps
                .insert(
                    i,
                    P2p {
                        u_i_share_ciphertext_k256,
                    },
                )
                .unwrap();
        }

        let out_bcast = Bcast {
            y_i_reveal_k256: r1state.my_y_i_reveal_k256.clone(),
            u_i_share_commits_k256: r1state.my_u_i_vss_k256.commit(),
        };
        (
            State {
                my_share_of_my_u_i_k256: my_u_i_shares_k256[self.my_index].clone(),
            },
            out_bcast,
            out_p2ps,
        )
    }
}
