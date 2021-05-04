use super::{r2, Sign, Status};
use crate::fillvec::FillVec;
use crate::zkp::{pedersen, range};
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use paillier::{
    // DecryptionKey, EncryptionKey, Open, Paillier, Randomness, RawCiphertext, RawPlaintext,
    Open,
    Paillier,
    RawCiphertext,
};
use serde::{Deserialize, Serialize};
use tracing::warn;

// round 6

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    pub ecdsa_public_key_check: GE,
    pub ecdsa_public_key_check_proof_wc: pedersen::ProofWc,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {
    pub(super) my_ecdsa_public_key_check: GE,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Culprit {
    pub participant_index: usize,
    pub crime: Crime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Crime {
    RangeProofWc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BcastFail {
    pub culprits: Vec<Culprit>,
}

pub(super) enum Output {
    Success { state: State, out_bcast: Bcast },
    Fail { out_bcast: BcastFail },
    FailType5 { out_bcast: BcastFailType5 },
}

impl Sign {
    pub(super) fn r6(&self) -> Output {
        assert!(matches!(self.status, Status::R5));
        let r5state = self.r5state.as_ref().unwrap();

        // checks:
        // * sum of ecdsa_randomizer_x_nonce_summand (R_i) = G as per phase 5 of 2020/540
        // * verify zk proofs
        let mut ecdsa_randomizer_x_nonce = r5state.my_ecdsa_randomizer_x_nonce_summand;
        let mut culprits = Vec::new();

        for (i, participant_index) in self.participant_indices.iter().enumerate() {
            if i == self.my_participant_index {
                continue;
            }
            let in_r5bcast = self.in_r5bcasts.vec_ref()[i].as_ref().unwrap();
            ecdsa_randomizer_x_nonce =
                ecdsa_randomizer_x_nonce + in_r5bcast.ecdsa_randomizer_x_nonce_summand;

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
                                .encrypted_ecdsa_nonce_summand
                                .c,
                            ek: &self.my_secret_key_share.all_eks[*participant_index],
                        },
                        msg_g: &in_r5bcast.ecdsa_randomizer_x_nonce_summand,
                        g: &r5state.ecdsa_randomizer,
                    },
                    &in_r5p2p.ecdsa_randomizer_x_nonce_summand_proof,
                )
                .unwrap_or_else(|e| {
                    warn!(
                        "participant {} says: range proof wc failed to verify for participant {} because [{}]",
                        self.my_participant_index, i, e
                    );
                    culprits.push(Culprit {
                        participant_index: i,
                        crime: Crime::RangeProofWc,
                    });
                });
        }

        if !culprits.is_empty() {
            return Output::Fail {
                out_bcast: BcastFail { culprits },
            };
        }

        // check for failure of type 5 from section 4.2 of https://eprint.iacr.org/2020/540.pdf
        if ecdsa_randomizer_x_nonce != GE::generator() {
            warn!(
                "participant {} detect 'type 5' fault",
                self.my_participant_index
            );
            return Output::FailType5 {
                out_bcast: self.type5_fault_output(),
            };
        }

        // compute S_i (aka ecdsa_public_key_check) and zk proof as per phase 6 of 2020/540
        let r3state = self.r3state.as_ref().unwrap();
        let my_ecdsa_public_key_check =
            r5state.ecdsa_randomizer * r3state.my_nonce_x_keyshare_summand;
        let proof_wc = pedersen::prove_wc(
            &pedersen::StatementWc {
                stmt: pedersen::Statement {
                    commit: &r3state.my_nonce_x_keyshare_summand_commit,
                },
                msg_g: &my_ecdsa_public_key_check,
                g: &r5state.ecdsa_randomizer,
            },
            &pedersen::Witness {
                msg: &r3state.my_nonce_x_keyshare_summand,
                randomness: &r3state.my_nonce_x_keyshare_summand_commit_randomness,
            },
        );

        Output::Success {
            state: State {
                my_ecdsa_public_key_check,
            },
            out_bcast: Bcast {
                ecdsa_public_key_check: my_ecdsa_public_key_check,
                ecdsa_public_key_check_proof_wc: proof_wc,
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
                        "r7_fail_randomizer participant {} says: missing r2p2p from {}",
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
                assert_eq!(
                    my_mta_blind_summand_lhs_mod_q,
                    r3state.my_mta_blind_summands_lhs[i].unwrap(),
                    "participant {}: decryption of mta_response_blind from {} in r7_fail_randomizer differs from r3", self.my_participant_index, i
                ); // TODO panic

                // do not return my_mta_blind_summand_lhs_mod_q
                // need my_mta_blind_summand_lhs_plaintext because it may differ from my_mta_blind_summand_lhs_mod_q
                // why? because the ciphertext was formed from homomorphic Paillier operations, not just encrypting my_mta_blind_summand_lhs_mod_q
            }

            mta_blind_summands
                .insert(
                    i,
                    MtaBlindSummandsData {
                        rhs: r2state.my_mta_blind_summands_rhs[i].unwrap(),
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
            ecdsa_nonce_summand: r1state.my_ecdsa_nonce_summand,
            ecdsa_nonce_summand_randomness: r1state
                .my_encrypted_ecdsa_nonce_summand_randomness
                .clone(),
            secret_blind_summand: r1state.my_secret_blind_summand,
            mta_blind_summands: mta_blind_summands.into_vec(),
        }
    }
}
