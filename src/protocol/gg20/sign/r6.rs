use super::{r2, Sign, Status};
use crate::fillvec::FillVec;
use crate::{
    k256_serde,
    paillier_k256::zk,
    zkp::{paillier::range, pedersen, pedersen_k256},
};
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use paillier::{Open, Paillier, RawCiphertext};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

// round 6

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Bcast {
    // curv
    pub S_i: GE,
    pub S_i_proof_wc: pedersen::ProofWc,

    // k256
    pub S_i_k256: k256_serde::ProjectivePoint,
    pub S_i_proof_wc_k256: pedersen_k256::ProofWc,
}

#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub(super) struct State {
    pub(super) s_i: GE, // redundant
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Culprit {
    pub participant_index: usize,
    pub crime: Crime,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Crime {
    RangeProofWc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BcastFail {
    pub culprits: Vec<Culprit>,
}

#[derive(Debug)]
pub(super) enum Output {
    Success { state: State, out_bcast: Bcast },
    Fail { out_bcast: BcastFail },
    FailType5 { out_bcast: BcastFailType5 },
}

impl Sign {
    #[allow(non_snake_case)]
    pub(super) fn r6(&self) -> Output {
        assert!(matches!(self.status, Status::R5));
        let r5state = self.r5state.as_ref().unwrap();

        // curv
        // checks:
        // * sum of ecdsa_randomizer_x_nonce_summand (R_i) = G as per phase 5 of 2020/540
        // * verify zk proofs
        let mut R_i_sum = r5state.R_i;
        let mut culprits = Vec::new();

        for (i, participant_index) in self.participant_indices.iter().enumerate() {
            if i == self.my_participant_index {
                continue;
            }
            let in_r5bcast = self.in_r5bcasts.vec_ref()[i].as_ref().unwrap();
            R_i_sum = R_i_sum + in_r5bcast.R_i;

            let in_r5p2p = self.in_all_r5p2ps[i].vec_ref()[self.my_participant_index]
                .as_ref()
                .unwrap_or_else(|| {
                    panic!(
                        "sign r5 participant {}: missing p2p msg from participant {}",
                        self.my_participant_index, i
                    )
                });
            self.my_secret_key_share
                .my_zkp
                .verify_range_proof_wc(
                    &range::StatementWc {
                        stmt: range::Statement {
                            ciphertext: &self.in_r1bcasts.vec_ref()[i]
                                .as_ref()
                                .unwrap()
                                .k_i_ciphertext
                                .c,
                            ek: &self.my_secret_key_share.all_eks[*participant_index],
                        },
                        msg_g: &in_r5bcast.R_i,
                        g: &r5state.R,
                    },
                    &in_r5p2p.k_i_range_proof_wc,
                )
                .unwrap_or_else(|e| {
                    warn!(
                        "(curv) participant {} says: range proof wc failed to verify for participant {} because [{}]",
                        self.my_participant_index, i, e
                    );
                    culprits.push(Culprit {
                        participant_index: i,
                        crime: Crime::RangeProofWc,
                    });
                });
        }

        // k256: verify proofs
        let culprits_k256: Vec<Culprit> = self
            .participant_indices
            .iter()
            .enumerate()
            .filter_map(|(i, participant_index)| {
                if i == self.my_participant_index {
                    return None; // nothing from myself for me to verify
                }

                let r1bcast = self.in_r1bcasts.vec_ref()[i].as_ref().unwrap();
                let r5bcast = self.in_r5bcasts.vec_ref()[i].as_ref().unwrap();
                let r5p2p = self.in_all_r5p2ps[i].vec_ref()[self.my_participant_index]
                    .as_ref()
                    .unwrap();

                if let Err(e) = self.my_zkp_k256().verify_range_proof_wc(
                    &zk::range::StatementWc {
                        stmt: zk::range::Statement {
                            ciphertext: &r1bcast.k_i_ciphertext_k256,
                            ek: &self.my_secret_key_share.all_eks_k256[*participant_index],
                        },
                        msg_g: r5bcast.R_i_k256.unwrap(),
                        g: &r5state.R_k256,
                    },
                    &r5p2p.k_i_range_proof_wc_k256,
                ) {
                    let crime = Crime::RangeProofWc;
                    warn!(
                        "(k256) participant {} accuse {} of {:?} because [{}]",
                        self.my_participant_index, i, crime, e
                    );
                    Some(Culprit {
                        participant_index: i,
                        crime,
                    })
                } else {
                    None
                }
            })
            .collect();

        assert_eq!(culprits_k256, culprits);
        if !culprits.is_empty() {
            return Output::Fail {
                out_bcast: BcastFail { culprits },
            };
        }

        // curv: check for failure of type 5 from section 4.2 of https://eprint.iacr.org/2020/540.pdf
        if R_i_sum != GE::generator() {
            warn!(
                "(curv) participant {} detect 'type 5' fault",
                self.my_participant_index
            );
            return Output::FailType5 {
                out_bcast: self.type5_fault_output(),
            };
        }

        // k256: check for failure of type 5 from section 4.2 of https://eprint.iacr.org/2020/540.pdf
        let R_i_sum_k256 = self
            .in_r5bcasts
            .vec_ref()
            .iter()
            .map(|o| *o.as_ref().unwrap().R_i_k256.unwrap())
            .reduce(|acc, r_i| acc + r_i)
            .unwrap();
        if R_i_sum_k256 != k256::ProjectivePoint::generator() {
            warn!(
                "(k256) participant {} detect 'type 5' fault",
                self.my_participant_index
            );
            return Output::FailType5 {
                out_bcast: self.type5_fault_output(),
            };
        }

        let r3state = self.r3state.as_ref().unwrap();
        let r3bcast = self.in_r3bcasts.vec_ref()[self.my_participant_index]
            .as_ref()
            .unwrap();

        // curv: compute S_i
        let S_i = r5state.R * r3state.sigma_i;
        let S_i_proof_wc = pedersen::prove_wc(
            &pedersen::StatementWc {
                stmt: pedersen::Statement {
                    commit: &r3state.t_i,
                },
                msg_g: &S_i,
                g: &r5state.R,
            },
            &pedersen::Witness {
                msg: &r3state.sigma_i,
                randomness: &r3state.l_i,
            },
        );

        // k256: compute S_i
        let S_i_k256 = r5state.R_k256 * r3state.sigma_i_k256;
        let S_i_proof_wc_k256 = pedersen_k256::prove_wc(
            &pedersen_k256::StatementWc {
                stmt: pedersen_k256::Statement {
                    commit: r3bcast.t_i_k256.unwrap(),
                },
                msg_g: &S_i_k256,
                g: &r5state.R_k256,
            },
            &pedersen_k256::Witness {
                msg: &r3state.sigma_i_k256,
                randomness: &r3state.l_i_k256,
            },
        );

        Output::Success {
            state: State { s_i: S_i },
            out_bcast: Bcast {
                S_i,
                S_i_proof_wc,
                S_i_k256: S_i_k256.into(),
                S_i_proof_wc_k256,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct BcastFailType5 {
    pub ecdsa_nonce_summand: FE,                // k_i
    pub ecdsa_nonce_summand_randomness: BigInt, // k_i encryption randomness
    pub secret_blind_summand: FE,               // gamma_i
    pub mta_blind_summands: Vec<Option<MtaBlindSummandsData>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct MtaBlindSummandsData {
    pub(super) rhs: FE,                           // beta_ji
    pub(super) rhs_randomness: r2::RhsRandomness, // beta_ji encryption randomness
    pub(super) lhs_plaintext: BigInt,             // alpha_ij Paillier plaintext
    pub(super) lhs_randomness: BigInt,            // alpha_ij encryption randomness
}

impl Sign {
    // execute blame protocol from section 4.3 of https://eprint.iacr.org/2020/540.pdf
    pub(super) fn type5_fault_output(&self) -> BcastFailType5 {
        assert!(matches!(self.status, Status::R5));

        let r1state = self.r1state.as_ref().unwrap();
        let r2state = self.r2state.as_ref().unwrap();
        let r3state = self.r3state.as_ref().unwrap();
        let mut mta_blind_summands = FillVec::with_len(self.participant_indices.len());

        for i in 0..self.participant_indices.len() {
            if i == self.my_participant_index {
                continue;
            }

            // recover encryption randomness for my_mta_blind_summands_lhs
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
            let (my_mta_blind_summand_lhs_plaintext, my_mta_blind_summand_lhs_randomness) =
                Paillier::open(
                    &self.my_secret_key_share.my_dk,
                    &RawCiphertext::from(&in_p2p.mta_response_blind.c),
                );

            // sanity check: we should recover the value we computed in r3
            {
                let my_mta_blind_summand_lhs_mod_q: FE =
                    ECScalar::from(&my_mta_blind_summand_lhs_plaintext.0);
                if my_mta_blind_summand_lhs_mod_q != r3state.alphas[i].unwrap() {
                    error!("participant {} decryption of mta_response_blind from {} in r6 differs from r3", self.my_participant_index, i);
                }

                // do not return my_mta_blind_summand_lhs_mod_q
                // need my_mta_blind_summand_lhs_plaintext because it may differ from my_mta_blind_summand_lhs_mod_q
                // why? because the ciphertext was formed from homomorphic Paillier operations, not just encrypting my_mta_blind_summand_lhs_mod_q
            }

            mta_blind_summands
                .insert(
                    i,
                    MtaBlindSummandsData {
                        rhs: r2state.betas[i].unwrap(),
                        rhs_randomness: r2state.my_mta_blind_summands_rhs_randomness[i]
                            .as_ref()
                            .unwrap()
                            .clone(),
                        lhs_plaintext: (*my_mta_blind_summand_lhs_plaintext.0).clone(),
                        lhs_randomness: my_mta_blind_summand_lhs_randomness.0,
                    },
                )
                .unwrap();
        }

        BcastFailType5 {
            ecdsa_nonce_summand: r1state.k_i,
            ecdsa_nonce_summand_randomness: r1state.k_i_randomness.clone(),
            secret_blind_summand: r1state.gamma_i,
            mta_blind_summands: mta_blind_summands.into_vec(),
        }
    }
}
