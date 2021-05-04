use crate::zkp::pedersen;

use super::{crimes::Crime, Sign, Status};
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE,
};
use serde::{Deserialize, Serialize};
use tracing::warn;

// round 7

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    pub ecdsa_sig_summand: FE,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {
    pub(super) r: FE,
    pub(super) my_ecdsa_sig_summand: FE,
}

#[derive(Debug)]
pub(super) enum Output {
    Success { state: State, out_bcast: Bcast },
    Fail { criminals: Vec<Vec<Crime>> },
    FailType7 { out_bcast: BcastFailType7 },
}

impl Sign {
    pub(super) fn r7(&self) -> Output {
        assert!(matches!(self.status, Status::R6));
        let mut criminals = vec![Vec::new(); self.participant_indices.len()];

        // our check for 'type 5' failures succeeded in r6()
        // thus, anyone who sent us a r6::BcastRandomizer is a criminal
        if self.in_r6bcasts_fail_type5.some_count() > 0 {
            let complainers: Vec<usize> = self
                .in_r6bcasts_fail_type5
                .vec_ref()
                .iter()
                .enumerate()
                .filter_map(|x| if x.1.is_some() { Some(x.0) } else { None })
                .collect();
            let crime = Crime::R7FailType5FalseComplaint;
            warn!(
                "participant {} detect {:?} by {:?}",
                self.my_participant_index, crime, complainers
            );
            for c in complainers {
                criminals[c].push(crime.clone());
            }
            return Output::Fail { criminals };
        }

        let r5state = self.r5state.as_ref().unwrap();
        let r6state = self.r6state.as_ref().unwrap();

        // checks:
        // * sum of ecdsa_public_key_check (S_i) = ecdsa_public_key as per phase 6 of 2020/540
        // * verify zk proofs
        let mut ecdsa_public_key = r6state.my_ecdsa_public_key_check;

        for (i, participant_index) in self.participant_indices.iter().enumerate() {
            if *participant_index == self.my_secret_key_share.my_index {
                continue;
            }
            let in_r6bcast = self.in_r6bcasts.vec_ref()[i].as_ref().unwrap();
            let in_r3bcast = self.in_r3bcasts.vec_ref()[i].as_ref().unwrap();

            pedersen::verify_wc(
                &pedersen::StatementWc {
                    stmt: pedersen::Statement {
                        commit: &in_r3bcast.nonce_x_keyshare_summand_commit,
                    },
                    msg_g: &in_r6bcast.ecdsa_public_key_check,
                    g: &r5state.ecdsa_randomizer,
                },
                &in_r6bcast.ecdsa_public_key_check_proof_wc,
            )
            .unwrap_or_else(|e| {
                let crime = Crime::R7BadRangeProof;
                warn!(
                    "participant {} detect {:?} by {} because [{}]",
                    self.my_participant_index, crime, i, e
                );
                criminals[i].push(crime);
            });

            ecdsa_public_key = ecdsa_public_key + in_r6bcast.ecdsa_public_key_check;
        }

        if criminals.iter().map(|v| v.len()).sum::<usize>() > 0 {
            return Output::Fail { criminals };
        }

        // check for failure of type 7 from section 4.2 of https://eprint.iacr.org/2020/540.pdf
        if ecdsa_public_key != self.my_secret_key_share.ecdsa_public_key {
            warn!(
                "participant {} detect 'type 7' fault",
                self.my_participant_index
            );
            return Output::FailType7 {
                out_bcast: self.type7_fault_output(),
            };
        }

        // compute our sig share s_i (aka my_ecdsa_sig_summand) as per phase 7 of 2020/540
        let r1state = self.r1state.as_ref().unwrap();
        let r3state = self.r3state.as_ref().unwrap();
        let r: FE = ECScalar::from(
            &r5state
                .ecdsa_randomizer
                .x_coor()
                .unwrap()
                .mod_floor(&FE::q()),
        );
        let my_ecdsa_sig_summand = self.msg_to_sign * r1state.my_ecdsa_nonce_summand
            + r * r3state.my_nonce_x_keyshare_summand;

        Output::Success {
            state: State {
                r,
                my_ecdsa_sig_summand,
            },
            out_bcast: Bcast {
                ecdsa_sig_summand: my_ecdsa_sig_summand,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct BcastFailType7 {
    pub ecdsa_nonce_summand: FE, // k_i
    pub ecdsa_nonce_summand_randomness: BigInt, // k_i encryption randomness
                                 // pub mta_blind_summands: Vec<Option<MtaBlindSummandsData>>,
}

// #[derive(Debug, Clone, Serialize, Deserialize)]
// pub(super) struct MtaBlindSummandsData {
//     pub(super) rhs: FE,                           // beta_ji
//     pub(super) rhs_randomness: r2::RhsRandomness, // beta_ji encryption randomness
//     pub(super) lhs_plaintext: BigInt,             // alpha_ij Paillier plaintext
//     pub(super) lhs_randomness: BigInt,            // alpha_ij encryption randomness
// }

impl Sign {
    // execute blame protocol from section 4.3 of https://eprint.iacr.org/2020/540.pdf
    pub(super) fn type7_fault_output(&self) -> BcastFailType7 {
        todo!()
    }
}
