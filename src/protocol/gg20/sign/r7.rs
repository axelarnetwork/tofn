use super::{crimes::Crime, Sign, Status};
use crate::fillvec::FillVec;
use crate::zkp::pedersen;
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE,
};
use paillier::{Open, Paillier, RawCiphertext};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

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
    pub ecdsa_nonce_summand: FE,                // k_i
    pub ecdsa_nonce_summand_randomness: BigInt, // k_i encryption randomness
    pub mta_wc_keyshare_summands: Vec<Option<MtaWcKeyshareSummandsData>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct MtaWcKeyshareSummandsData {
    pub(super) lhs_plaintext: BigInt,  // mu_ij Paillier plaintext
    pub(super) lhs_randomness: BigInt, // mu_ij encryption randomness
}

impl Sign {
    // execute blame protocol from section 4.3 of https://eprint.iacr.org/2020/540.pdf
    pub(super) fn type7_fault_output(&self) -> BcastFailType7 {
        assert!(matches!(self.status, Status::R6));

        let r1state = self.r1state.as_ref().unwrap();
        let r3state = self.r3state.as_ref().unwrap();
        let mut mta_wc_keyshare_summands = FillVec::with_len(self.participant_indices.len());

        for i in 0..self.participant_indices.len() {
            if i == self.my_participant_index {
                continue;
            }

            // recover encryption randomness for my_mta_wc_keyshare_summands_lhs
            // need to decrypt again to do so
            let in_p2p = self.in_all_r2p2ps[i].vec_ref()[self.my_participant_index]
                .as_ref()
                .unwrap_or_else(|| {
                    // TODO these checks should not be necessary after refactoring
                    panic!(
                        "participant {} missing r2p2p from {}",
                        self.my_participant_index, i
                    )
                });
            let (
                my_mta_wc_keyshare_summand_lhs_plaintext,
                my_mta_wc_keyshare_summand_lhs_randomness,
            ) = Paillier::open(
                &self.my_secret_key_share.my_dk,
                &RawCiphertext::from(&in_p2p.mta_response_keyshare.c),
            );

            // sanity check: we should recover the value we computed in r3
            {
                let my_mta_wc_keyshare_summand_lhs_mod_q: FE =
                    ECScalar::from(&my_mta_wc_keyshare_summand_lhs_plaintext.0);
                if my_mta_wc_keyshare_summand_lhs_mod_q
                    != r3state.my_mta_wc_keyshare_summands_lhs[i].unwrap()
                {
                    error!("participant {} decryption of mta_wc_response_keyshare from {} in r6 differs from r3", self.my_participant_index, i);
                }

                // do not return my_mta_wc_keyshare_summand_lhs_mod_q
                // need my_mta_wc_keyshare_summand_lhs_plaintext because it may differ from my_mta_wc_keyshare_summand_lhs_mod_q
                // why? because the ciphertext was formed from homomorphic Paillier operations, not just encrypting my_mta_wc_keyshare_summand_lhs_mod_q
            }

            mta_wc_keyshare_summands
                .insert(
                    i,
                    MtaWcKeyshareSummandsData {
                        lhs_plaintext: (*my_mta_wc_keyshare_summand_lhs_plaintext.0).clone(),
                        lhs_randomness: my_mta_wc_keyshare_summand_lhs_randomness.0,
                    },
                )
                .unwrap();
        }

        BcastFailType7 {
            ecdsa_nonce_summand: r1state.my_ecdsa_nonce_summand,
            ecdsa_nonce_summand_randomness: r1state
                .my_encrypted_ecdsa_nonce_summand_randomness
                .clone(),
            mta_wc_keyshare_summands: mta_wc_keyshare_summands.into_vec(),
        }
    }
}
