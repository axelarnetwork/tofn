use super::{Sign, Status};
use crate::fillvec::FillVec;
use crate::protocol::gg20::vss;
use crate::zkp::{mta, pedersen};
use curv::{elliptic::curves::traits::ECScalar, FE, GE};
use serde::{Deserialize, Serialize};
use tracing::warn;

// round 3

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    pub nonce_x_blind_summand: FE,           // delta_i
    pub nonce_x_keyshare_summand_commit: GE, // a Pedersen commitment
    pub nonce_x_keyshare_summand_proof: pedersen::Proof,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {
    pub(super) my_nonce_x_blind_summand: FE,
    pub(super) my_nonce_x_keyshare_summand: FE,
    pub(super) my_nonce_x_keyshare_summand_commit: GE,
    pub(super) my_nonce_x_keyshare_summand_commit_randomness: FE,
    pub(super) my_mta_blind_summands_lhs: Vec<Option<FE>>, // alpha_ij, needed only in r6 fail mode
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Culprit {
    pub participant_index: usize,
    pub crime: Crime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Crime {
    Mta,
    MtaWc,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailBcast {
    pub culprits: Vec<Culprit>,
}

// TODO is it better to have `State` and `P2p` be enum types?
pub enum Output {
    Success { state: State, out_bcast: Bcast },
    Fail { out_bcast: FailBcast },
}

impl Sign {
    pub(super) fn r3(&self) -> Output {
        assert!(matches!(self.status, Status::R2));

        let (my_ek, my_dk) = (
            &self.my_secret_key_share.my_ek,
            &self.my_secret_key_share.my_dk,
        );
        let r1state = self.r1state.as_ref().unwrap();

        // complete the MtA protocols:
        // 1. my_ecdsa_nonce_summand * my_secret_blind_summand
        // 2. my_ecdsa_nonce_summand * my_secret_key_summand
        let mut my_mta_blind_summands_lhs = FillVec::with_len(self.participant_indices.len());
        let mut my_mta_keyshare_summands_lhs = FillVec::with_len(self.participant_indices.len());
        let mut culprits = Vec::new();

        for (i, participant_index) in self.participant_indices.iter().enumerate() {
            if *participant_index == self.my_secret_key_share.my_index {
                continue;
            }
            let in_p2p = self.in_all_r2p2ps[i].vec_ref()[self.my_participant_index]
                .as_ref()
                .unwrap_or_else(|| {
                    panic!(
                        "r3 participant {} says: missing r2p2p from {}",
                        self.my_participant_index, i
                    )
                });

            // verify zk proofs from MtA, MtAwc
            self.my_secret_key_share
                .my_zkp
                .verify_mta_proof(
                    &mta::Statement {
                        ciphertext1: &r1state.my_encrypted_ecdsa_nonce_summand,
                        ciphertext2: &in_p2p.mta_response_blind.c,
                        ek: my_ek,
                    },
                    &in_p2p.mta_proof,
                )
                .unwrap_or_else(|e| {
                    warn!(
                        "party {} says: mta proof failed to verify for party {} because [{}]",
                        self.my_secret_key_share.my_index, participant_index, e
                    );
                    culprits.push(Culprit {
                        participant_index: i,
                        crime: Crime::Mta,
                    });
                });
            let other_public_key_summand = self.my_secret_key_share.all_ecdsa_public_key_shares
                [*participant_index]
                * vss::lagrangian_coefficient(
                    self.my_secret_key_share.share_count,
                    *participant_index,
                    &self.participant_indices,
                );
            self.my_secret_key_share
                .my_zkp
                .verify_mta_proof_wc(
                    &mta::StatementWc {
                        stmt: mta::Statement {
                            ciphertext1: &r1state.my_encrypted_ecdsa_nonce_summand,
                            ciphertext2: &in_p2p.mta_response_keyshare.c,
                            ek: my_ek,
                        },
                        x_g: &other_public_key_summand,
                    },
                    &in_p2p.mta_proof_wc,
                )
                .unwrap_or_else(|e| {
                    warn!(
                        "party {} says: mta_wc proof failed to verify for party {} because [{}]",
                        self.my_secret_key_share.my_index, participant_index, e
                    );
                    culprits.push(Culprit {
                        participant_index: i,
                        crime: Crime::MtaWc,
                    });
                });

            // decrypt my portion of the additive share
            let (my_mta_blind_summand_lhs, _) = in_p2p
                .mta_response_blind
                .verify_proofs_get_alpha(my_dk, &r1state.my_ecdsa_nonce_summand)
                .unwrap(); // TODO panic

            let (my_mta_keyshare_summand_lhs, _) = in_p2p
                .mta_response_keyshare
                .verify_proofs_get_alpha(my_dk, &r1state.my_ecdsa_nonce_summand)
                .unwrap(); // TODO panic

            // TODO zengo does this extra check, but it requires more messages to be sent
            // if input.g_w_i_s[ind] != input.m_b_w_s[i].b_proof.pk {
            //     println!("MtAwc did not work i = {} ind ={}", i, ind);
            //     return Err(Error::InvalidCom);
            // }

            my_mta_blind_summands_lhs
                .insert(i, my_mta_blind_summand_lhs)
                .unwrap();
            my_mta_keyshare_summands_lhs
                .insert(i, my_mta_keyshare_summand_lhs)
                .unwrap();
        }

        if !culprits.is_empty() {
            return Output::Fail {
                out_bcast: FailBcast { culprits },
            };
        }

        // sum my additive shares to get (my_nonce_x_blind_summand, my_nonce_x_keyshare_summand)
        // GG20 notation:
        // (my_nonce_x_blind_summand, my_nonce_x_keyshare_summand) -> (delta_i, sigma_i)
        // my_ecdsa_nonce_summand -> k_i
        // my_secret_blind_summand -> gamma_i
        // my_secret_key_summand -> w_i
        // my_nonce_x_blind_summand -> ki_gamma_i -> delta_i
        // my_nonce_x_keyshare_summand -> ki_w_i -> sigma_i
        let r2state = self.r2state.as_ref().unwrap();
        let my_mta_blind_summands_lhs = my_mta_blind_summands_lhs.into_vec();
        let my_mta_keyshare_summands_lhs = my_mta_keyshare_summands_lhs.into_vec();

        // start the summation with my contribution
        let mut my_nonce_x_blind_summand = r1state
            .my_ecdsa_nonce_summand
            .mul(&r1state.my_secret_blind_summand.get_element());
        let mut my_nonce_x_keyshare_summand = r1state
            .my_ecdsa_nonce_summand
            .mul(&r1state.my_secret_key_summand.get_element());

        for i in 0..self.participant_indices.len() {
            if self.participant_indices[i] == self.my_secret_key_share.my_index {
                continue;
            }
            my_nonce_x_blind_summand = my_nonce_x_blind_summand
                + my_mta_blind_summands_lhs[i]
                    .unwrap()
                    .add(&r2state.my_mta_blind_summands_rhs[i].unwrap().get_element());
            my_nonce_x_keyshare_summand = my_nonce_x_keyshare_summand
                + my_mta_keyshare_summands_lhs[i].unwrap().add(
                    &r2state.my_mta_keyshare_summands_rhs[i]
                        .unwrap()
                        .get_element(),
                );
        }

        // commit to my_nonce_x_keyshare_summand and compute a zk proof for the commitment
        // GG20 notation:
        // commit -> T_i
        // randomness -> l
        let (commit, randomness) = &pedersen::commit(&my_nonce_x_keyshare_summand);
        let proof = pedersen::prove(
            &pedersen::Statement { commit },
            &pedersen::Witness {
                msg: &my_nonce_x_keyshare_summand,
                randomness,
            },
        );

        Output::Success {
            state: State {
                my_nonce_x_blind_summand,
                my_nonce_x_keyshare_summand,
                my_nonce_x_keyshare_summand_commit: *commit,
                my_nonce_x_keyshare_summand_commit_randomness: *randomness,
                my_mta_blind_summands_lhs,
            },
            out_bcast: Bcast {
                nonce_x_blind_summand: my_nonce_x_blind_summand,
                nonce_x_keyshare_summand_commit: *commit,
                nonce_x_keyshare_summand_proof: proof,
            },
        }
    }
}
