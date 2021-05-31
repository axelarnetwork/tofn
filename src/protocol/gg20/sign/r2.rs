use super::{Sign, Status};
use crate::{fillvec::FillVec, paillier_k256};
use crate::{
    paillier_k256::Ciphertext,
    zkp::paillier::{mta, range},
};
use curv::{elliptic::curves::traits::ECPoint, BigInt, FE, GE};
use multi_party_ecdsa::utilities::mta as mta_zengo;
use serde::{Deserialize, Serialize};
use tracing::info;

// round 2

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2p {
    // curv
    pub mta_response_blind: mta_zengo::MessageB,
    pub mta_proof: mta::Proof,
    pub mta_response_keyshare: mta_zengo::MessageB,
    pub mta_proof_wc: mta::ProofWc,

    // k256
    pub alpha_ciphertext_k256: Ciphertext,
    pub alpha_proof_k256: crate::paillier_k256::zk::mta::Proof,
    pub mu_ciphertext_k256: Ciphertext,
    pub mu_proof_k256: crate::paillier_k256::zk::mta::ProofWc,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub(super) struct State {
    // curv
    pub(super) betas: Vec<Option<FE>>,
    pub(super) my_mta_blind_summands_rhs_randomness: Vec<Option<RhsRandomness>>, // needed only in r6 fail mode
    pub(super) nus: Vec<Option<FE>>,

    // k256
    pub(super) beta_secrets_k256: FillVec<crate::mta::Secret>,
    pub(super) nu_secrets_k256: FillVec<crate::mta::Secret>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RhsRandomness {
    pub(super) randomness: BigInt,
    pub(super) beta_prime: BigInt,
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
pub(super) enum Output {
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

        let r1state = self.r1state.as_ref().unwrap();
        let mut out_p2ps = FillVec::with_len(self.participant_indices.len());
        let mut culprits = Vec::new();

        // curv
        let my_public_key_summand = GE::generator() * r1state.w_i;
        let mut my_betas = FillVec::with_len(self.participant_indices.len());
        let mut my_beta_secrets = FillVec::with_len(self.participant_indices.len());
        let mut my_nus = FillVec::with_len(self.participant_indices.len());

        // k256
        let mut beta_secrets_k256 = FillVec::with_len(self.participant_indices.len());
        let mut nu_secrets_k256 = FillVec::with_len(self.participant_indices.len());

        // step 2 for MtA protocols:
        // 1. k_i (other) * gamma_j (me)
        // 2. k_i (other) * w_j (me)
        for (i, participant_index) in self.participant_indices.iter().enumerate() {
            // TODO make a self.iter_others_enumerate method that automatically skips my index
            if *participant_index == self.my_secret_key_share.my_index {
                continue;
            }

            // curv: verify zk proof for first message of MtA
            let other_ek = &self.my_secret_key_share.all_eks[*participant_index];
            let other_k_i_ciphertext = &self.in_r1bcasts.vec_ref()[i]
                .as_ref()
                .unwrap()
                .k_i_ciphertext;
            let stmt = &range::Statement {
                ciphertext: &other_k_i_ciphertext.c,
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
                    // do not accuse curv crimes
                    // culprits.push(Culprit {
                    //     participant_index: i,
                    //     crime: Crime::RangeProof,
                    // });
                });

            // k256: verify zk proof for first message of MtA
            let other_ek_k256 = &self.my_secret_key_share.all_eks_k256[*participant_index];
            let other_k_i_ciphertext_k256 = &self.in_r1bcasts.vec_ref()[i]
                .as_ref()
                .unwrap()
                .k_i_ciphertext_k256;
            let stmt = &paillier_k256::zk::range::Statement {
                ciphertext: other_k_i_ciphertext_k256,
                ek: other_ek_k256,
            };
            let proof = &self.in_all_r1p2ps[i].vec_ref()[self.my_participant_index]
                .as_ref()
                .unwrap()
                .range_proof_k256;
            self.my_zkp_k256()
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

            // curv: MtA step 2 for k_i * gamma_j
            let (alpha_ciphertext, beta, randomness, beta_prime) = // (m_b_gamma, beta_gamma)
                mta_zengo::MessageB::b(&r1state.gamma_i, other_ek, other_k_i_ciphertext.clone());
            let other_zkp = &self.my_secret_key_share.all_zkps[*participant_index];
            let mta_proof = other_zkp.mta_proof(
                &mta::Statement {
                    ciphertext1: &other_k_i_ciphertext.c,
                    ciphertext2: &alpha_ciphertext.c,
                    ek: other_ek,
                },
                &mta::Witness {
                    x: &r1state.gamma_i,
                    msg: &beta_prime,
                    randomness: &randomness,
                },
            );
            my_beta_secrets
                .insert(
                    i,
                    RhsRandomness {
                        randomness,
                        beta_prime,
                    },
                )
                .unwrap();

            // k256: MtA step 2 for k_i * gamma_j
            let other_zkp_k256 = &self.my_secret_key_share.all_zkps_k256[*participant_index];
            let (alpha_ciphertext_k256, alpha_proof_k256, beta_secret_k256) =
                crate::mta::mta_response_with_proof(
                    other_zkp_k256,
                    other_ek_k256,
                    other_k_i_ciphertext_k256,
                    &r1state.gamma_i_k256,
                );
            beta_secrets_k256.insert(i, beta_secret_k256).unwrap();

            // curv: MtAwc step 2 for k_i * w_j
            let (mu_ciphertext, nu, randomness_wc, beta_prime_wc) = // (m_b_w, beta_wi)
                mta_zengo::MessageB::b(&r1state.w_i, other_ek, other_k_i_ciphertext.clone());
            let mta_proof_wc = other_zkp.mta_proof_wc(
                &mta::StatementWc {
                    stmt: mta::Statement {
                        ciphertext1: &other_k_i_ciphertext.c,
                        ciphertext2: &mu_ciphertext.c,
                        ek: other_ek,
                    },
                    x_g: &my_public_key_summand,
                },
                &mta::Witness {
                    x: &r1state.w_i,
                    msg: &beta_prime_wc,
                    randomness: &randomness_wc,
                },
            );

            // k256: MtAwc step 2 for k_i * w_j
            let (mu_ciphertext_k256, mu_proof_k256, nu_secret_k256) =
                crate::mta::mta_response_with_proof_wc(
                    other_zkp_k256,
                    other_ek_k256,
                    other_k_i_ciphertext_k256,
                    &r1state.w_i_k256,
                );
            nu_secrets_k256.insert(i, nu_secret_k256).unwrap();

            out_p2ps
                .insert(
                    i,
                    P2p {
                        mta_response_blind: alpha_ciphertext,
                        mta_proof,
                        mta_response_keyshare: mu_ciphertext,
                        mta_proof_wc,
                        alpha_ciphertext_k256,
                        alpha_proof_k256,
                        mu_ciphertext_k256,
                        mu_proof_k256,
                    },
                )
                .unwrap();
            my_betas.insert(i, beta).unwrap();
            my_nus.insert(i, nu).unwrap();
        }

        if culprits.is_empty() {
            Output::Success {
                state: State {
                    betas: my_betas.into_vec(),
                    my_mta_blind_summands_rhs_randomness: my_beta_secrets.into_vec(),
                    nus: my_nus.into_vec(),
                    beta_secrets_k256,
                    nu_secrets_k256,
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
