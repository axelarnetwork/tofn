use super::{Sign, Status};
use crate::fillvec::FillVec;
use crate::k256_serde;
use crate::paillier_k256;
use crate::protocol::gg20::vss_k256;
use crate::zkp::pedersen_k256;
use serde::{Deserialize, Serialize};
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Bcast {
    pub delta_i_k256: k256_serde::Scalar,
    pub T_i_k256: k256_serde::ProjectivePoint,
    pub T_i_proof_k256: pedersen_k256::Proof,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub(super) struct State {
    pub(super) sigma_i_k256: k256::Scalar,
    pub(super) l_i_k256: k256::Scalar,
    pub(super) alphas_k256: FillVec<k256::Scalar>,
    pub(super) mus_k256: FillVec<k256::Scalar>,
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

pub(super) enum Output {
    Success { state: State, out_bcast: Bcast },
    Fail { out_bcast: FailBcast },
}

impl Sign {
    pub(super) fn r3(&self) -> Output {
        assert!(matches!(self.status, Status::R2));

        let r1state = self.r1state.as_ref().unwrap();
        let r1bcast = self.in_r1bcasts.vec_ref()[self.my_participant_index]
            .as_ref()
            .unwrap();
        let mut culprits = Vec::new();

        let mut alphas_k256 = FillVec::with_len(self.participant_indices.len());
        let mut mus_k256 = FillVec::with_len(self.participant_indices.len());

        // step 3 for MtA protocols:
        // 1. k_i (me) * gamma_j (other)
        // 2. k_i (me) * w_j (other)
        for (i, participant_index) in self.participant_indices.iter().enumerate() {
            if *participant_index == self.my_secret_key_share.share.my_index {
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

            // k256: verify zk proof for step 2 of MtA k_i * gamma_j
            self.my_zkp_k256()
                .verify_mta_proof(
                    &paillier_k256::zk::mta::Statement {
                        ciphertext1: &r1bcast.k_i_ciphertext_k256,
                        ciphertext2: &in_p2p.alpha_ciphertext_k256,
                        ek: self.my_ek_k256(),
                    },
                    &in_p2p.alpha_proof_k256,
                )
                .unwrap_or_else(|e| {
                    warn!(
                        "party {} says: mta proof failed to verify for party {} because [{}]",
                        self.my_secret_key_share.share.my_index, participant_index, e
                    );
                    culprits.push(Culprit {
                        participant_index: i,
                        crime: Crime::Mta,
                    });
                });

            // k256: verify zk proof for step 2 of MtAwc k_i * w_j
            let other_g_w_i = self.my_secret_key_share.group.all_y_i_k256[*participant_index]
                .unwrap()
                * &vss_k256::lagrange_coefficient(i, &self.participant_indices);
            self.my_zkp_k256()
                .verify_mta_proof_wc(
                    &paillier_k256::zk::mta::StatementWc {
                        stmt: paillier_k256::zk::mta::Statement {
                            ciphertext1: &r1bcast.k_i_ciphertext_k256,
                            ciphertext2: &in_p2p.mu_ciphertext_k256,
                            ek: self.my_ek_k256(),
                        },
                        x_g: &other_g_w_i,
                    },
                    &in_p2p.mu_proof_k256,
                )
                .unwrap_or_else(|e| {
                    warn!(
                        "party {} says: mta_wc proof failed to verify for party {} because [{}]",
                        self.my_secret_key_share.share.my_index, participant_index, e
                    );
                    culprits.push(Culprit {
                        participant_index: i,
                        crime: Crime::MtaWc,
                    });
                });

            // k256: decrypt alpha for MtA k_i * gamma_j
            let alpha_k256 = self
                .my_secret_key_share
                .share
                .dk_k256
                .decrypt(&in_p2p.alpha_ciphertext_k256)
                .to_scalar();
            alphas_k256.insert(i, alpha_k256).unwrap();

            // k256: decrypt mu for MtA k_i * w_j
            let mu_k256 = self
                .my_secret_key_share
                .share
                .dk_k256
                .decrypt(&in_p2p.mu_ciphertext_k256)
                .to_scalar();
            mus_k256.insert(i, mu_k256).unwrap();
        }

        if !culprits.is_empty() {
            return Output::Fail {
                out_bcast: FailBcast { culprits },
            };
        }

        let r2state = self.r2state.as_ref().unwrap();

        // compute delta_i = k_i * gamma_i + sum_{j != i} alpha_ij + beta_ji
        let delta_i_k256 = {
            let mut sum = r1state.k_i_k256 * r1state.gamma_i_k256; // k_i * gamma_i
            for i in 0..self.participant_indices.len() {
                if self.participant_indices[i] == self.my_secret_key_share.share.my_index {
                    continue;
                }
                sum = sum
                    + alphas_k256.vec_ref()[i].as_ref().unwrap()
                    + r2state.beta_secrets_k256.vec_ref()[i]
                        .as_ref()
                        .unwrap()
                        .beta
                        .unwrap();
            }
            sum
        };

        // compute sigma_i = k_i * w_i + sum_{j != i} mu_ij + nu_ji
        let sigma_i_k256 = {
            let mut sum = r1state.k_i_k256 * r1state.w_i_k256; // k_i * w_i
            for i in 0..self.participant_indices.len() {
                if self.participant_indices[i] == self.my_secret_key_share.share.my_index {
                    continue;
                }
                sum = sum
                    + mus_k256.vec_ref()[i].as_ref().unwrap()
                    + r2state.nu_secrets_k256.vec_ref()[i]
                        .as_ref()
                        .unwrap()
                        .beta
                        .unwrap();
            }

            #[cfg(feature = "malicious")] // TODO hack type7 fault
            if matches!(self.behaviour, super::malicious::Behaviour::R3BadSigmaI) {
                sum += k256::Scalar::one();
            }

            sum
        };

        let (t_i_k256, l_i_k256) = pedersen_k256::commit(&sigma_i_k256);
        let t_i_proof_k256 = pedersen_k256::prove(
            &pedersen_k256::Statement { commit: &t_i_k256 },
            &pedersen_k256::Witness {
                msg: &sigma_i_k256,
                randomness: &l_i_k256,
            },
        );

        Output::Success {
            state: State {
                sigma_i_k256,
                l_i_k256,
                alphas_k256,
                mus_k256,
            },
            out_bcast: Bcast {
                delta_i_k256: k256_serde::Scalar::from(delta_i_k256),
                T_i_k256: k256_serde::ProjectivePoint::from(t_i_k256),
                T_i_proof_k256: t_i_proof_k256,
            },
        }
    }
}
