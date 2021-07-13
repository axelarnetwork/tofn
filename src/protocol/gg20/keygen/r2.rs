use serde::{Deserialize, Serialize};
use tracing::warn;

use super::{crimes::Crime, Keygen, Status};
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

pub(super) enum Output {
    Success {
        state: State,
        out_bcast: Bcast,
        out_p2ps: FillVec<P2p>,
    },
    Fail {
        criminals: Vec<Vec<Crime>>,
    },
}

impl Keygen {
    pub(super) fn r2(&self) -> Output {
        assert!(matches!(self.status, Status::R1));
        let r1state = self.r1state.as_ref().unwrap();

        // check Paillier proofs
        let mut criminals = vec![Vec::new(); self.share_count];
        for (i, in_r1bcast) in self.in_r1bcasts.vec_ref().iter().enumerate() {
            if i == self.my_index {
                continue;
            }
            let r1bcast = in_r1bcast.as_ref().unwrap();
            if !r1bcast.ek_k256.verify(&r1bcast.ek_proof) {
                let crime = Crime::R2BadEncryptionKeyProof;
                warn!("party {} detect {:?} by {}", self.my_index, crime, i);
                criminals[i].push(crime);
            }
            if !r1bcast.zkp_k256.verify(&r1bcast.zkp_proof) {
                let crime = Crime::R2BadZkSetupProof;
                warn!("party {} detect {:?} by {}", self.my_index, crime, i);
                criminals[i].push(crime);
            }
        }
        if !criminals.iter().all(Vec::is_empty) {
            return Output::Fail { criminals };
        }

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
                    u_i_share_ciphertext_k256.corrupt_owned()
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
        Output::Success {
            state: State {
                my_share_of_my_u_i_k256: my_u_i_shares_k256[self.my_index].clone(),
            },
            out_bcast,
            out_p2ps,
        }
    }
}
