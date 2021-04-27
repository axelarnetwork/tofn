use super::{Sign, Status};
use crate::zkp::{pedersen, range};
use curv::{elliptic::curves::traits::ECPoint, BigInt, FE, GE};
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
pub struct BcastCulprits {
    pub culprits: Vec<Culprit>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BcastRandomizer {
    // TODO do I also need encryption randomness for alpha_ij ?  Yes.
    // get encryption randomness for alpha_ij from Paillier::open
    // how to verify integrity of alpha_ij, beta_ji:
    // 1. call MessageB::b_with_predefined_randomness to get enc(alpha_ji) and beta_ji
    // 2. call Paillier::encrypt_with_chosen_randomness to get enc(alpha_ji)
    pub ecdsa_nonce_summand: FE,                // k_i
    pub ecdsa_nonce_summand_randomness: BigInt, // k_i encryption randomness
    pub secret_blind_summand: FE,               // gamma_i

    // make this one vec of a struct
    pub mta_blind_summands_rhs: Vec<Option<FE>>, // beta_ji
    pub mta_blind_summands_rhs_randomness: Vec<Option<BigInt>>, // beta_ji encryption randomness
    pub mta_blind_summands_lhs: Vec<Option<FE>>, // alpha_ij
}
pub enum Output {
    Success { state: State, out_bcast: Bcast },
    FailRangeProofWc { out_bcast: BcastCulprits },
    FailRandomizer { out_bcast: BcastRandomizer },
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
            return Output::FailRangeProofWc {
                out_bcast: BcastCulprits { culprits },
            };
        }

        // check for failure of type 5 from section 4.2 of https://eprint.iacr.org/2020/540.pdf
        if ecdsa_randomizer_x_nonce != GE::generator() {
            // execute blame protocol from section 4.3 of https://eprint.iacr.org/2020/540.pdf
            warn!(
                "participant {} says: randomizer check failed, begin randomizer fault attribution",
                self.my_participant_index
            );
            let r1state = self.r1state.as_ref().unwrap();
            let r2state = self.r2state.as_ref().unwrap();
            let r3state = self.r3state.as_ref().unwrap();
            return Output::FailRandomizer {
                out_bcast: BcastRandomizer {
                    ecdsa_nonce_summand: r1state.my_ecdsa_nonce_summand,
                    ecdsa_nonce_summand_randomness: r1state
                        .my_encrypted_ecdsa_nonce_summand_randomness
                        .clone(),
                    secret_blind_summand: r1state.my_secret_blind_summand,
                    mta_blind_summands_rhs: r2state.my_mta_blind_summands_rhs.clone(),
                    mta_blind_summands_rhs_randomness: r2state
                        .my_mta_blind_summands_rhs_randomness
                        .clone(),
                    mta_blind_summands_lhs: r3state.my_mta_blind_summands_lhs.clone(),
                },
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
