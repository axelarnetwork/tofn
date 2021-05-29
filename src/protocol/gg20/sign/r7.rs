use super::{crimes::Crime, Sign, Status};
use crate::fillvec::FillVec;
use crate::zkp::{chaum_pedersen, pedersen, pedersen_k256};
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
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
    #[allow(non_snake_case)]
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

        // curv
        // checks:
        // * sum of ecdsa_public_key_check (S_i) = ecdsa_public_key as per phase 6 of 2020/540
        // * verify zk proofs
        let mut S_i_sum = r6state.s_i;

        for (i, participant_index) in self.participant_indices.iter().enumerate() {
            if *participant_index == self.my_secret_key_share.my_index {
                continue;
            }
            let in_r6bcast = self.in_r6bcasts.vec_ref()[i].as_ref().unwrap();
            let in_r3bcast = self.in_r3bcasts.vec_ref()[i].as_ref().unwrap();

            pedersen::verify_wc(
                &pedersen::StatementWc {
                    stmt: pedersen::Statement {
                        commit: &in_r3bcast.T_i,
                    },
                    msg_g: &in_r6bcast.S_i,
                    g: &r5state.R,
                },
                &in_r6bcast.S_i_proof_wc,
            )
            .unwrap_or_else(|e| {
                let crime = Crime::R7BadRangeProof;
                warn!(
                    "(curv) participant {} detect {:?} by {} because [{}]",
                    self.my_participant_index, crime, i, e
                );
                criminals[i].push(crime);
            });

            S_i_sum = S_i_sum + in_r6bcast.S_i;
        }

        // k256: verify proofs
        let criminals_k256: Vec<Vec<Crime>> = self
            .participant_indices
            .iter()
            .enumerate()
            .map(|(i, _participant_index)| {
                if i == self.my_participant_index {
                    return Vec::new(); // don't verify my own commit
                }
                let r3bcast = self.in_r3bcasts.vec_ref()[i].as_ref().unwrap();
                let r6bcast = self.in_r6bcasts.vec_ref()[i].as_ref().unwrap();

                if let Err(e) = pedersen_k256::verify_wc(
                    &pedersen_k256::StatementWc {
                        stmt: pedersen_k256::Statement {
                            commit: &r3bcast.T_i_k256.unwrap(),
                        },
                        msg_g: r6bcast.S_i_k256.unwrap(),
                        g: &r5state.R_k256,
                    },
                    &r6bcast.S_i_proof_wc_k256,
                ) {
                    let crime = Crime::R7BadRangeProof;
                    warn!(
                        "(k256) participant {} detect {:?} by {} because [{}]",
                        self.my_participant_index, crime, i, e
                    );
                    vec![crime]
                } else {
                    Vec::new()
                }
            })
            .collect();

        assert_eq!(criminals_k256, criminals);
        if !criminals.iter().all(Vec::is_empty) {
            return Output::Fail { criminals };
        }

        // curv: check for failure of type 7 from section 4.2 of https://eprint.iacr.org/2020/540.pdf
        if S_i_sum != self.my_secret_key_share.ecdsa_public_key {
            warn!(
                "participant {} detect 'type 7' fault",
                self.my_participant_index
            );
            return Output::FailType7 {
                out_bcast: self.type7_fault_output(),
            };
        }

        // k256: check for failure of type 7 from section 4.2 of https://eprint.iacr.org/2020/540.pdf
        let S_i_sum_k256 = self
            .in_r6bcasts
            .vec_ref()
            .iter()
            .map(|o| *o.as_ref().unwrap().S_i_k256.unwrap())
            .reduce(|acc, S_i| acc + S_i)
            .unwrap();
        if S_i_sum_k256 != *self.my_secret_key_share.y_k256.unwrap() {
            warn!(
                "participant {} detect 'type 7' fault",
                self.my_participant_index
            );
            return Output::FailType7 {
                out_bcast: self.type7_fault_output(),
            };
        }

        let r1state = self.r1state.as_ref().unwrap();
        let r3state = self.r3state.as_ref().unwrap();

        // curv: compute r, s_i
        let r: FE = ECScalar::from(&r5state.R.x_coor().unwrap().mod_floor(&FE::q()));
        let my_ecdsa_sig_summand = self.msg_to_sign * r1state.k_i + r * r3state.sigma_i;

        // k256: compute r, s_i
        // DONE TO HERE

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
    pub proof: chaum_pedersen::Proof,
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
                .unwrap();
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
                if my_mta_wc_keyshare_summand_lhs_mod_q != r3state.mus[i].unwrap() {
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

        let proof = chaum_pedersen::prove(
            &chaum_pedersen::Statement {
                base1: &GE::generator(),                       // G
                base2: &self.r5state.as_ref().unwrap().R,      // R
                target1: &(GE::generator() * r3state.sigma_i), // sigma_i * G
                target2: &self.r6state.as_ref().unwrap().s_i,  // sigma_i * R == S_i
            },
            &chaum_pedersen::Witness {
                scalar: &r3state.sigma_i,
            },
        );

        let r1state = self.r1state.as_ref().unwrap();

        BcastFailType7 {
            ecdsa_nonce_summand: r1state.k_i,
            ecdsa_nonce_summand_randomness: r1state.k_i_randomness.clone(),
            mta_wc_keyshare_summands: mta_wc_keyshare_summands.into_vec(),
            proof,
        }
    }
}
