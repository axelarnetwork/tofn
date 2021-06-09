use super::{crimes::Crime, Sign, Status};
use crate::fillvec::FillVec;
use crate::k256_serde;
use crate::paillier_k256::{Plaintext, Randomness};
use crate::zkp::{chaum_pedersen_k256, pedersen_k256};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

// round 7

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    pub s_i_k256: k256_serde::Scalar, // k256
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub(super) struct State {
    pub(super) r_k256: k256::Scalar, // k256
}

#[allow(clippy::large_enum_variant)]
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

        // our check for 'type 5' failures succeeded in r6()
        // thus, anyone who sent us a r6::BcastRandomizer is a criminal
        if self.in_r6bcasts_fail_type5.some_count() > 0 {
            let crime = Crime::R7FailType5FalseComplaint;
            let criminals: Vec<Vec<Crime>> = self
                .in_r6bcasts_fail_type5
                .vec_ref()
                .iter()
                .map(|b| {
                    if b.is_some() {
                        vec![crime.clone()]
                    } else {
                        vec![]
                    }
                })
                .collect();

            // pretty log message
            let complainers: Vec<usize> = self
                .in_r6bcasts_fail_type5
                .vec_ref()
                .iter()
                .enumerate()
                .filter_map(|x| if x.1.is_some() { Some(x.0) } else { None })
                .collect();
            warn!(
                "participant {} detect {:?} by {:?}",
                self.my_participant_index, crime, complainers
            );

            return Output::Fail { criminals };
        }

        let r5state = self.r5state.as_ref().unwrap();

        // verify proofs
        let criminals: Vec<Vec<Crime>> = self
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
        if !criminals.iter().all(Vec::is_empty) {
            return Output::Fail { criminals };
        }

        // k256: check for failure of type 7 from section 4.2 of https://eprint.iacr.org/2020/540.pdf
        let S_i_sum_k256 = self
            .in_r6bcasts
            .vec_ref()
            .iter()
            .map(|o| *o.as_ref().unwrap().S_i_k256.unwrap())
            .reduce(|acc, S_i| acc + S_i)
            .unwrap();
        if S_i_sum_k256 != *self.my_secret_key_share.group.y_k256.unwrap() {
            warn!(
                "(k256) participant {} detect 'type 7' fault",
                self.my_participant_index
            );
            return Output::FailType7 {
                out_bcast: self.type7_fault_output(),
            };
        }

        let r1state = self.r1state.as_ref().unwrap();
        let r3state = self.r3state.as_ref().unwrap();

        // k256: compute r, s_i
        // reference for r: https://docs.rs/k256/0.8.1/src/k256/ecdsa/sign.rs.html#223-225
        let r_k256 = k256::Scalar::from_bytes_reduced(
            self.r5state
                .as_ref()
                .unwrap()
                .R_k256
                .to_affine()
                .to_encoded_point(true)
                .x()
                .unwrap(),
        );
        let s_i_k256 = self.msg_to_sign_k256 * r1state.k_i_k256 + r_k256 * r3state.sigma_i_k256;

        Output::Success {
            state: State { r_k256 },
            out_bcast: Bcast {
                s_i_k256: s_i_k256.into(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct BcastFailType7 {
    pub mta_wc_plaintexts: Vec<Option<MtaWcPlaintext>>,
    pub k_i_k256: k256_serde::Scalar,
    pub k_i_randomness_k256: Randomness,
    pub proof_k256: chaum_pedersen_k256::Proof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct MtaWcPlaintext {
    // mu_plaintext instead of mu
    // because mu_plaintext may differ from mu
    // why? because the ciphertext was formed from homomorphic Paillier operations, not just encrypting mu
    pub(super) mu_plaintext_k256: Plaintext,
    pub(super) mu_randomness_k256: Randomness,
}

impl Sign {
    // execute blame protocol from section 4.3 of https://eprint.iacr.org/2020/540.pdf
    pub(super) fn type7_fault_output(&self) -> BcastFailType7 {
        assert!(matches!(self.status, Status::R6));
        let r3state = self.r3state.as_ref().unwrap();

        let mut mta_wc_plaintexts = FillVec::with_len(self.participant_indices.len());
        for i in 0..self.participant_indices.len() {
            if i == self.my_participant_index {
                continue;
            }

            // recover encryption randomness for mu; need to decrypt again to do so
            let in_p2p = self.in_all_r2p2ps[i].vec_ref()[self.my_participant_index]
                .as_ref()
                .unwrap();
            let (mu_plaintext_k256, mu_randomness_k256) = self
                .my_secret_key_share
                .share
                .dk_k256
                .decrypt_with_randomness(&in_p2p.mu_ciphertext_k256);

            // sanity check: we should recover the mu we computed in r3
            {
                let mu_k256 = mu_plaintext_k256.to_scalar();
                if mu_k256 != r3state.mus_k256.vec_ref()[i].unwrap() {
                    error!(
                        "participant {} decryption of mu from {} in r6 differs from r3",
                        self.my_participant_index, i
                    );
                }
            }

            mta_wc_plaintexts
                .insert(
                    i,
                    MtaWcPlaintext {
                        mu_plaintext_k256,
                        mu_randomness_k256,
                    },
                )
                .unwrap();
        }

        // k256
        let r6bcast = self.in_r6bcasts.vec_ref()[self.my_participant_index]
            .as_ref()
            .unwrap();
        let proof_k256 = chaum_pedersen_k256::prove(
            &chaum_pedersen_k256::Statement {
                base1: &k256::ProjectivePoint::generator(),
                base2: &self.r5state.as_ref().unwrap().R_k256,
                target1: &(k256::ProjectivePoint::generator() * r3state.sigma_i_k256),
                target2: r6bcast.S_i_k256.unwrap(),
            },
            &chaum_pedersen_k256::Witness {
                scalar: &r3state.sigma_i_k256,
            },
        );

        let r1state = self.r1state.as_ref().unwrap();
        BcastFailType7 {
            mta_wc_plaintexts: mta_wc_plaintexts.into_vec(),
            k_i_k256: r1state.k_i_k256.into(),
            k_i_randomness_k256: r1state.k_i_randomness_k256.clone(),
            proof_k256,
        }
    }
}
