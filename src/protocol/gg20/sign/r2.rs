use super::{Sign, Status};
use crate::paillier_k256::Ciphertext;
use crate::{fillvec::FillVec, paillier_k256};
use serde::{Deserialize, Serialize};
use tracing::info;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2p {
    pub alpha_ciphertext_k256: Ciphertext,
    pub alpha_proof_k256: crate::paillier_k256::zk::mta::Proof,
    pub mu_ciphertext_k256: Ciphertext,
    pub mu_proof_k256: crate::paillier_k256::zk::mta::ProofWc,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub(super) struct State {
    pub(super) beta_secrets_k256: FillVec<crate::mta::Secret>,
    pub(super) nu_secrets_k256: FillVec<crate::mta::Secret>,
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

        let mut beta_secrets_k256 = FillVec::with_len(self.participant_indices.len());
        let mut nu_secrets_k256 = FillVec::with_len(self.participant_indices.len());

        // step 2 for MtA protocols:
        // 1. k_i (other) * gamma_j (me)
        // 2. k_i (other) * w_j (me)
        for (i, participant_index) in self.participant_indices.iter().enumerate() {
            if *participant_index == self.my_secret_key_share.share.index {
                continue;
            }

            // k256: verify zk proof for first message of MtA
            let other_ek_k256 = &self.my_secret_key_share.group.all_shares[*participant_index].ek;
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

            // k256: MtA step 2 for k_i * gamma_j
            let other_zkp_k256 = &self.my_secret_key_share.group.all_shares[*participant_index].zkp;
            let (alpha_ciphertext_k256, alpha_proof_k256, beta_secret_k256) =
                crate::mta::mta_response_with_proof(
                    other_zkp_k256,
                    other_ek_k256,
                    other_k_i_ciphertext_k256,
                    &r1state.gamma_i_k256,
                );
            beta_secrets_k256.insert(i, beta_secret_k256).unwrap();

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
                        alpha_ciphertext_k256,
                        alpha_proof_k256,
                        mu_ciphertext_k256,
                        mu_proof_k256,
                    },
                )
                .unwrap();
        }

        if culprits.is_empty() {
            Output::Success {
                state: State {
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
