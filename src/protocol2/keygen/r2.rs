use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    fillvec::FillVec,
    hash, paillier_k256,
    protocol::gg20::{keygen::crimes::Crime, vss_k256},
    protocol2::{
        keygen::r3, serialize_as_option, RoundExecuter, RoundOutput, RoundWaiter, SerializedMsgs,
    },
};

use super::{r1, KeygenOutput};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct OutMsg {
    pub(super) bcast: Bcast,
    pub(super) p2ps: FillVec<P2p>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct Bcast {
    pub(super) y_i_reveal: hash::Randomness,
    pub(super) u_i_share_commits: vss_k256::Commit,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct P2p {
    pub(super) u_i_share_ciphertext: paillier_k256::Ciphertext,
}

pub(super) struct State {
    pub(super) u_i_my_share: vss_k256::Share,
}

pub(super) struct R2 {
    pub(super) share_count: usize,
    pub(super) threshold: usize,
    pub(super) index: usize,
    pub(super) r1state: r1::State,
    pub(super) r1bcast: r1::Bcast,
}

impl RoundExecuter for R2 {
    type FinalOutput = KeygenOutput;

    fn execute(self: Box<Self>, msgs_in: Vec<SerializedMsgs>) -> RoundOutput<Self::FinalOutput> {
        // deserialize incoming messages
        let r1bcasts: Vec<r1::Bcast> = msgs_in
            .iter()
            .map(|msg| bincode::deserialize(&msg.bcast.as_ref().unwrap()).unwrap())
            .collect();

        // check Paillier proofs
        let mut criminals = vec![Vec::new(); self.share_count];
        for (i, r1bcast) in r1bcasts.iter().enumerate() {
            // if i == self.index {
            //     continue;
            // }
            if !r1bcast.ek.verify(&r1bcast.ek_proof) {
                let crime = Crime::R2BadEncryptionKeyProof;
                warn!("party {} detect {:?} by {}", self.index, crime, i);
                criminals[i].push(crime);
            }
            if !r1bcast.zkp.verify(&r1bcast.zkp_proof) {
                let crime = Crime::R2BadZkSetupProof;
                warn!("party {} detect {:?} by {}", self.index, crime, i);
                criminals[i].push(crime);
            }
        }
        if !criminals.iter().all(Vec::is_empty) {
            return RoundOutput::Done(Err(criminals));
        }

        let u_i_shares = self.r1state.u_i_vss.shares(self.share_count);

        // #[cfg(feature = "malicious")]
        // let my_u_i_shares_k256 = if let Behaviour::R2BadShare { victim } = self.behaviour {
        //     info!(
        //         "(k256) malicious party {} do {:?}",
        //         self.my_index, self.behaviour
        //     );
        //     my_u_i_shares_k256
        //         .iter()
        //         .enumerate()
        //         .map(|(i, s)| {
        //             if i == victim {
        //                 vss_k256::Share::from_scalar(
        //                     s.get_scalar() + k256::Scalar::one(),
        //                     s.get_index(),
        //                 )
        //             } else {
        //                 s.clone()
        //             }
        //         })
        //         .collect()
        // } else {
        //     my_u_i_shares_k256
        // };

        // TODO better pattern to get p2ps_out
        let p2ps_out = FillVec::from_vec(
            u_i_shares
                .iter()
                .enumerate()
                .map(|(i, u_i_share)| {
                    if i == self.index {
                        None
                    } else {
                        // encrypt the share for party i
                        let (u_i_share_ciphertext, _) =
                            r1bcasts[i].ek.encrypt(&u_i_share.get_scalar().into());

                        // #[cfg(feature = "malicious")]
                        // let u_i_share_ciphertext_k256 = match self.behaviour {
                        //     Behaviour::R2BadEncryption { victim } if victim == i => {
                        //         info!(
                        //             "(k256) malicious party {} do {:?}",
                        //             self.my_index, self.behaviour
                        //         );
                        //         u_i_share_ciphertext_k256.corrupt()
                        //     }
                        //     _ => u_i_share_ciphertext_k256,
                        // };

                        let p2p = P2p {
                            u_i_share_ciphertext,
                        };
                        serialize_as_option(&p2p)
                    }
                })
                .collect(),
        );

        let r2bcast = Bcast {
            y_i_reveal: self.r1state.y_i_reveal.clone(),
            u_i_share_commits: self.r1state.u_i_vss.commit(),
        };
        let bcast_out = serialize_as_option(&r2bcast);
        let r2state = State {
            u_i_my_share: u_i_shares[self.index].clone(),
        };

        RoundOutput::NotDone(RoundWaiter {
            round: Box::new(r3::R3 {
                share_count: self.share_count,
                threshold: self.threshold,
                index: self.index,
                r1state: self.r1state,
                r1bcast: self.r1bcast,
                r2state,
                r2bcast,
            }),
            msgs_out: SerializedMsgs {
                bcast: bcast_out,
                p2ps: Some(p2ps_out),
            },
            msgs_in: vec![
                SerializedMsgs {
                    bcast: None,
                    p2ps: Some(FillVec::with_len(self.share_count)),
                };
                self.share_count
            ],
        })
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
