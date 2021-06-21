use tracing::warn;

use crate::{
    hash,
    k256_serde::to_bytes,
    protocol::gg20::keygen::crimes::Crime,
    protocol2::{RoundExecuter, RoundOutput, SerializedMsgs},
};

use super::{r1, r2, KeygenOutput};

pub(super) struct R3 {
    pub(super) share_count: usize,
    pub(super) threshold: usize,
    pub(super) index: usize,
    pub(super) r1state: r1::State,
    pub(super) my_r1bcast: r1::Bcast,
    pub(super) r1bcasts: Vec<r1::Bcast>, // TODO Vec<everything>
    pub(super) r2state: r2::State,
    pub(super) my_r2bcast: r2::Bcast,
}

impl RoundExecuter for R3 {
    type FinalOutput = KeygenOutput;

    fn execute(self: Box<Self>, msgs_in: Vec<SerializedMsgs>) -> RoundOutput<Self::FinalOutput> {
        // deserialize incoming messages
        let r2bcasts: Vec<r2::Bcast> = msgs_in
            .iter()
            .map(|msg| bincode::deserialize(&msg.bcast.as_ref().unwrap()).unwrap())
            .collect();

        // check y_i commits
        let criminals: Vec<Vec<Crime>> = r2bcasts
            .iter()
            .enumerate() // TODO unnecessary with Vec<everything>
            .map(|(i, r2bcast)| {
                let r1bcast = &self.r1bcasts[i];
                let y_i = r2bcast.u_i_share_commits.secret_commit();
                let y_i_commit = hash::commit_with_randomness(to_bytes(y_i), &r2bcast.y_i_reveal);
                if y_i_commit != r1bcast.y_i_commit {
                    let crime = Crime::R3BadReveal;
                    warn!("party {} detect {:?} by {}", self.index, crime, i);
                    vec![crime]
                } else {
                    vec![]
                }
            })
            .collect();

        // prioritize commit faiure path over vss failure path
        if !criminals.iter().all(Vec::is_empty) {
            return RoundOutput::Done(Err(criminals));
        }

        // k256: check y_i_commit

        // let mut criminals = vec![Vec::new(); self.share_count];
        // let mut vss_failures = Vec::new();

        // // check commitments
        // // compute x_i, y, all y_i
        // let my_vss_commit_k256 = &self.in_r2bcasts.vec_ref()[self.my_index]
        //     .as_ref()
        //     .unwrap()
        //     .u_i_share_commits_k256;
        // let mut y_k256 = *my_vss_commit_k256.secret_commit();
        // let mut my_x_i_k256 = *r2state.my_share_of_my_u_i_k256.get_scalar();
        // let mut all_X_i: Vec<k256::ProjectivePoint> = (0..self.share_count)
        //     // start each summation with my contribution
        //     .map(|i| my_vss_commit_k256.share_commit(i))
        //     .collect();

        // #[allow(clippy::needless_range_loop)]
        // for i in 0..self.share_count {
        //     if i == self.my_index {
        //         continue;
        //     }
        //     let r1bcast = self.in_r1bcasts.vec_ref()[i].as_ref().unwrap();
        //     let r2bcast = self.in_r2bcasts.vec_ref()[i].as_ref().unwrap();
        //     let my_r2p2p = self.in_all_r2p2ps[i].vec_ref()[self.my_index]
        //         .as_ref()
        //         .unwrap();

        //     // k256: check y_i_commit
        //     let y_i_k256 = r2bcast.u_i_share_commits_k256.secret_commit();
        //     let y_i_commit_k256 =
        //         hash::commit_with_randomness(to_bytes(y_i_k256), &r2bcast.y_i_reveal_k256);

        //     if y_i_commit_k256 != r1bcast.y_i_commit_k256 {
        //         let crime = Crime::R3BadReveal;
        //         warn!("(k256) party {} detect {:?} by {}", self.my_index, crime, i);
        //         criminals[i].push(crime);
        //     }

        //     // k256: decrypt share
        //     let (u_i_share_plaintext_k256, u_i_share_randomness_k256) = self
        //         .r1state
        //         .as_ref()
        //         .unwrap()
        //         .dk_k256
        //         .decrypt_with_randomness(&my_r2p2p.u_i_share_ciphertext_k256);
        //     let u_i_share_k256 =
        //         vss_k256::Share::from_scalar(u_i_share_plaintext_k256.to_scalar(), self.my_index);

        //     // k256: validate share
        //     let vss_valid = r2bcast
        //         .u_i_share_commits_k256
        //         .validate_share(&u_i_share_k256);

        //     // #[cfg(feature = "malicious")]
        //     // let vss_valid = match self.behaviour {
        //     //     Behaviour::R3FalseAccusation { victim } if victim == i && vss_valid => {
        //     //         info!(
        //     //             "(k256) malicious party {} do {:?}",
        //     //             self.my_index, self.behaviour
        //     //         );
        //     //         false
        //     //     }
        //     //     _ => vss_valid,
        //     // };

        //     if !vss_valid {
        //         warn!(
        //             "(k256) party {} accuse {} of {:?}",
        //             self.my_index,
        //             i,
        //             Crime::R4FailBadVss {
        //                 victim: self.my_index
        //             },
        //         );
        //         vss_failures.push(Complaint {
        //             criminal_index: i,
        //             vss_share_k256: u_i_share_k256.clone(),
        //             vss_share_randomness_k256: u_i_share_randomness_k256,
        //         });
        //     }

        //     y_k256 += y_i_k256;
        //     my_x_i_k256 += u_i_share_k256.get_scalar();

        //     for (j, X_i) in all_X_i.iter_mut().enumerate() {
        //         *X_i += r2bcast.u_i_share_commits_k256.share_commit(j);
        //     }
        // }

        // // #[cfg(feature = "malicious")]
        // // match self.behaviour {
        // //     Behaviour::R3FalseAccusation { victim } if victim == self.my_index => {
        // //         info!(
        // //             "malicious party {} do {:?} (self accusation)",
        // //             self.my_index, self.behaviour
        // //         );
        // //         vss_failures.push(Complaint {
        // //             criminal_index: self.my_index,
        // //             vss_share_k256: vss_k256::Share::from_scalar(k256::Scalar::one(), 1), // doesn't matter what we put here
        // //             vss_share_randomness_k256: self.in_r1bcasts.vec_ref()[self.my_index]
        // //                 .as_ref()
        // //                 .unwrap()
        // //                 .ek_k256
        // //                 .sample_randomness(), // doesn't matter what we put here
        // //         });
        // //     }
        // //     _ => (),
        // // };

        // // prioritize commit faiure path over vss failure path
        // if !criminals.iter().all(Vec::is_empty) {
        //     return Output::Fail { criminals };
        // }
        // if !vss_failures.is_empty() {
        //     return Output::FailVss {
        //         out_bcast: BcastFail { vss_failures },
        //     };
        // }

        // all_X_i[self.my_index] = k256::ProjectivePoint::generator() * my_x_i_k256;

        // // #[cfg(feature = "malicious")]
        // // if matches!(self.behaviour, Behaviour::R3BadXIWitness) {
        // //     info!("malicious party {} do {:?}", self.my_index, self.behaviour);
        // //     my_x_i_k256 += k256::Scalar::one();
        // // }

        // // Output::Success {
        // //     out_bcast: Bcast {
        // //         x_i_proof: schnorr_k256::prove(
        // //             &schnorr_k256::Statement {
        // //                 base: &k256::ProjectivePoint::generator(),
        // //                 target: &all_X_i[self.my_index],
        // //             },
        // //             &schnorr_k256::Witness {
        // //                 scalar: &my_x_i_k256,
        // //             },
        // //         ),
        // //     },
        // //     state: State {
        // //         y_k256,
        // //         my_x_i_k256,
        // //         all_X_i,
        // //     },
        // // }
        todo!()
    }

    #[cfg(test)]
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}
