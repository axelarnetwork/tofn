use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    fillvec::FillVec,
    hash, paillier_k256,
    protocol::gg20::{keygen::crimes::Crime, vss_k256},
    refactor::{
        keygen::r3,
        protocol::protocol::{
            serialize_as_option, Config, RoundExecuter, RoundOutput, RoundWaiter,
        },
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

pub(super) struct R2 {
    pub(super) share_count: usize,
    pub(super) threshold: usize,
    pub(super) index: usize,
    pub(super) dk: paillier_k256::DecryptionKey,
    pub(super) u_i_vss: vss_k256::Vss,
    pub(super) y_i_reveal: hash::Randomness,
}

impl RoundExecuter for R2 {
    type FinalOutput = KeygenOutput;

    fn execute(
        self: Box<Self>,
        bcasts_in: FillVec<Vec<u8>>,
        _p2ps_in: Vec<FillVec<Vec<u8>>>,
    ) -> RoundOutput<Self::FinalOutput> {
        // deserialize incoming messages
        let r1bcasts: Vec<r1::Bcast> = bcasts_in
            .vec_ref()
            .iter()
            .map(|bytes| bincode::deserialize(&bytes.as_ref().unwrap()).unwrap())
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

        // TODO better pattern to get p2ps_out
        let p2ps_out_bytes = FillVec::from_vec(
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

        let bcast_out = Bcast {
            y_i_reveal: self.y_i_reveal.clone(),
            u_i_share_commits: self.u_i_vss.commit(),
        };
        let bcast_out_bytes = serialize_as_option(&bcast_out);

        RoundOutput::NotDone(RoundWaiter::new(
            Config::BcastAndP2p {
                bcast_out_bytes,
                p2ps_out_bytes,
            },
            self.share_count,
            self.index,
            Box::new(r3::R3 {
                share_count: self.share_count,
                threshold: self.threshold,
                index: self.index,
                dk: self.dk,
                u_i_my_share: u_i_shares[self.index].clone(),
                r1bcasts,
            }),
        ))
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
