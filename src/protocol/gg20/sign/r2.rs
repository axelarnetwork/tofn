use super::{Sign, Status};
use crate::fillvec::FillVec;
use crate::zkp::{mta, range};
use curv::{elliptic::curves::traits::ECPoint, BigInt, FE, GE};
use multi_party_ecdsa::utilities::mta as mta_zengo;
use serde::{Deserialize, Serialize};
use tracing::info;

// round 2

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2p {
    pub mta_response_blind: mta_zengo::MessageB,
    pub mta_proof: mta::Proof,
    pub mta_response_keyshare: mta_zengo::MessageB,
    pub mta_proof_wc: mta::ProofWc,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {
    pub(super) my_mta_blind_summands_rhs: Vec<Option<FE>>,
    pub(super) my_mta_blind_summands_rhs_randomness: Vec<Option<BigInt>>, // needed only in r6 fail mode
    pub(super) my_mta_keyshare_summands_rhs: Vec<Option<FE>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Culprit {
    pub participant_index: usize,
    pub crime: Crime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Crime {
    RangeProof,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailBcast {
    pub culprits: Vec<Culprit>,
}

// TODO is it better to have `State` and `P2p` be enum types?
pub enum Output {
    Success {
        state: State,
        out_p2ps: FillVec<P2p>,
    },
    Fail {
        out_bcast: FailBcast,
    },
}

impl Sign {
    pub(super) fn r2(&self) -> Output {
        assert!(matches!(self.status, Status::R1));

        // response msg for MtA protocols:
        // 1. my_ecdsa_nonce_summand (other) * my_secret_blind_summand (me)
        // 2. my_ecdsa_nonce_summand (other) * my_secret_key_summand (me)
        // both MtAs use my_ecdsa_nonce_summand, so I use the same message for both

        let r1state = self.r1state.as_ref().unwrap();
        let my_public_key_summand = GE::generator() * r1state.my_secret_key_summand;

        let mut out_p2ps = FillVec::with_len(self.participant_indices.len());
        let mut my_mta_blind_summands_rhs = FillVec::with_len(self.participant_indices.len());
        let mut my_mta_blind_summands_rhs_randomness =
            FillVec::with_len(self.participant_indices.len());
        let mut my_mta_keyshare_summands_rhs = FillVec::with_len(self.participant_indices.len());
        let mut culprits = Vec::new();

        // verify zk proofs for first message of MtA
        for (i, participant_index) in self.participant_indices.iter().enumerate() {
            // TODO make a self.iter_others_enumerate method that automatically skips my index
            if *participant_index == self.my_secret_key_share.my_index {
                continue;
            }

            // TODO don't use mta!  It sucks!
            // 1. unused return values in MessageB::b()
            // 2. MessageA arg is passed by value
            let other_ek = &self.my_secret_key_share.all_eks[*participant_index];
            let other_encrypted_ecdsa_nonce_summand = &self.in_r1bcasts.vec_ref()[i]
                .as_ref()
                .unwrap()
                .encrypted_ecdsa_nonce_summand;

            // verify zk proof for first message of MtA
            let stmt = &range::Statement {
                ciphertext: &other_encrypted_ecdsa_nonce_summand.c,
                ek: other_ek,
            };
            let proof = &self.in_all_r1p2ps[i].vec_ref()[self.my_participant_index]
                .as_ref()
                .unwrap()
                .range_proof;
            self.my_secret_key_share
                .my_zkp
                .verify_range_proof(stmt, proof)
                .unwrap_or_else(|e| {
                    info!(
                        "participant {} says: range proof from {} failed to verify because [{}]",
                        self.my_participant_index, i, e
                    );
                    culprits.push(Culprit {
                        participant_index: i,
                        crime: Crime::RangeProof,
                    });
                });

            // MtA for nonce * blind
            // TODO tidy scoping: don't need randomness, beta_prime after these two statements
            let (mta_response_blind, my_mta_blind_summand_rhs, randomness, beta_prime) = // (m_b_gamma, beta_gamma)
                mta_zengo::MessageB::b(&r1state.my_secret_blind_summand, other_ek, other_encrypted_ecdsa_nonce_summand.clone());
            let other_zkp = &self.my_secret_key_share.all_zkps[*participant_index];
            let mta_proof = other_zkp.mta_proof(
                &mta::Statement {
                    ciphertext1: &other_encrypted_ecdsa_nonce_summand.c,
                    ciphertext2: &mta_response_blind.c,
                    ek: other_ek,
                },
                &mta::Witness {
                    x: &r1state.my_secret_blind_summand,
                    msg: &beta_prime,
                    randomness: &randomness,
                },
            );
            my_mta_blind_summands_rhs_randomness
                .insert(i, randomness)
                .unwrap();

            // MtAwc for nonce * keyshare
            let (mta_response_keyshare, my_mta_keyshare_summand_rhs, randomness_wc, beta_prime_wc) = // (m_b_w, beta_wi)
                mta_zengo::MessageB::b(&r1state.my_secret_key_summand, other_ek, other_encrypted_ecdsa_nonce_summand.clone());
            let mta_proof_wc = other_zkp.mta_proof_wc(
                &mta::StatementWc {
                    stmt: mta::Statement {
                        ciphertext1: &other_encrypted_ecdsa_nonce_summand.c,
                        ciphertext2: &mta_response_keyshare.c,
                        ek: other_ek,
                    },
                    x_g: &my_public_key_summand,
                },
                &mta::Witness {
                    x: &r1state.my_secret_key_summand,
                    msg: &beta_prime_wc,
                    randomness: &randomness_wc,
                },
            );

            // TODO I'm not sending my rhs summands even though zengo does https://github.com/axelarnetwork/tofn/issues/7#issuecomment-771379525

            out_p2ps
                .insert(
                    i,
                    P2p {
                        mta_response_blind,
                        mta_proof,
                        mta_response_keyshare,
                        mta_proof_wc,
                    },
                )
                .unwrap();
            my_mta_blind_summands_rhs
                .insert(i, my_mta_blind_summand_rhs)
                .unwrap();
            my_mta_keyshare_summands_rhs
                .insert(i, my_mta_keyshare_summand_rhs)
                .unwrap();
        }

        if culprits.is_empty() {
            Output::Success {
                state: State {
                    my_mta_blind_summands_rhs: my_mta_blind_summands_rhs.into_vec(),
                    my_mta_blind_summands_rhs_randomness: my_mta_blind_summands_rhs_randomness
                        .into_vec(),
                    my_mta_keyshare_summands_rhs: my_mta_keyshare_summands_rhs.into_vec(),
                },
                out_p2ps,
            }
        } else {
            Output::Fail {
                out_bcast: FailBcast { culprits },
            }
        }
    }
}
