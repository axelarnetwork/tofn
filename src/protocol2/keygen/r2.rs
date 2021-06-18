use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    fillvec::FillVec,
    hash, paillier_k256,
    protocol::gg20::{keygen::crimes::Crime, vss_k256},
    protocol2::{keygen::r3, RoundExecuter, RoundOutput, RoundWaiter},
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

pub(super) struct R2 {
    pub(super) share_count: usize,
    pub(super) threshold: usize,
    pub(super) index: usize,
    pub(super) dk: paillier_k256::DecryptionKey,
    pub(super) u_i_vss: vss_k256::Vss,
    pub(super) y_i_reveal: hash::Randomness,
    pub(super) msg: r1::Bcast,
}

impl RoundExecuter for R2 {
    type FinalOutput = KeygenOutput;

    fn execute(self: Box<Self>, all_in_msgs: FillVec<Vec<u8>>) -> RoundOutput<Self::FinalOutput> {
        // deserialize incoming messages
        let r1bcasts: Vec<r1::Bcast> = all_in_msgs
            .vec_ref()
            .iter()
            .map(|msg| bincode::deserialize(&msg.as_ref().unwrap()).unwrap())
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

        let u_i_shares = self.u_i_vss.shares(self.share_count);

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

        let mut out_p2ps = FillVec::with_len(self.share_count);
        for (i, u_i_share) in u_i_shares.iter().enumerate() {
            if i == self.index {
                continue;
            }

            // encrypt the share for party i
            let (u_i_share_ciphertext_k256, _) =
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

            out_p2ps
                .insert(
                    i,
                    P2p {
                        u_i_share_ciphertext: u_i_share_ciphertext_k256,
                    },
                )
                .unwrap();
        }

        let out_bcast = Bcast {
            y_i_reveal: self.y_i_reveal.clone(),
            u_i_share_commits: self.u_i_vss.commit(),
        };
        // Output::Success {
        //     state: State {
        //         my_share_of_my_u_i_k256: my_u_i_shares_k256[self.my_index].clone(),
        //     },
        //     out_bcast,
        //     out_p2ps,
        // }
        RoundOutput::NotDone(RoundWaiter {
            round: Box::new(r3::R3 {}),
            out_msg: None,
            all_in_msgs: FillVec::with_len(self.share_count),
        })
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
