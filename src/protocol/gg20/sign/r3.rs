use super::{Sign, Status};
use crate::fillvec::FillVec;
use crate::k256_serde;
use crate::paillier_k256;
use crate::protocol::gg20::vss;
use crate::protocol::gg20::vss_k256;
use crate::zkp::{paillier::mta, pedersen, pedersen_k256};
use curv::{elliptic::curves::traits::ECScalar, FE, GE};
use serde::{Deserialize, Serialize};
use tracing::warn;

// round 3

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    // curv
    pub delta_i: FE,
    pub t_i: GE,
    pub t_i_proof: pedersen::Proof,

    // k256
    pub delta_i_k256: k256_serde::Scalar,
    pub t_i_k256: k256_serde::ProjectivePoint,
    pub t_i_proof_k256: pedersen_k256::Proof,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub(super) struct State {
    // curv
    pub(super) delta_i: FE, // redundant
    pub(super) sigma_i: FE,
    pub(super) t_i: GE, // redundant
    pub(super) l_i: FE,
    pub(super) alphas: Vec<Option<FE>>, // alpha_ij, needed only in r7_fail_type5
    pub(super) mus: Vec<Option<FE>>,    // mu_ij, needed only in r8_fail_type7

    // k256
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

// TODO is it better to have `State` and `P2p` be enum types?
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

        // curv
        let (my_ek, my_dk) = (
            &self.my_secret_key_share.my_ek,
            &self.my_secret_key_share.my_dk,
        );
        let mut alphas = FillVec::with_len(self.participant_indices.len());
        let mut mus = FillVec::with_len(self.participant_indices.len());

        // k256
        let mut alphas_k256 = FillVec::with_len(self.participant_indices.len());
        let mut mus_k256 = FillVec::with_len(self.participant_indices.len());

        // step 3 for MtA protocols:
        // 1. k_i (me) * gamma_j (other)
        // 2. k_i (me) * w_j (other)
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

            // curv: verify zk proof for step 2 of MtA k_i * gamma_j
            self.my_secret_key_share
                .my_zkp
                .verify_mta_proof(
                    &mta::Statement {
                        ciphertext1: &r1state.encrypted_k_i,
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
                        self.my_secret_key_share.my_index, participant_index, e
                    );
                    culprits.push(Culprit {
                        participant_index: i,
                        crime: Crime::Mta,
                    });
                });

            // curv: verify zk proof for step 2 of MtAwc k_i * w_j
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
                            ciphertext1: &r1state.encrypted_k_i,
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

            // k256: verify zk proof for step 2 of MtAwc k_i * w_j
            let other_g_w_i = self.my_secret_key_share.all_y_i_k256[*participant_index].unwrap()
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
                        self.my_secret_key_share.my_index, participant_index, e
                    );
                    culprits.push(Culprit {
                        participant_index: i,
                        crime: Crime::MtaWc,
                    });
                });

            // curv: decrypt alpha for MtA k_i * gamma_j
            let (alpha, _) = in_p2p
                .mta_response_blind
                .verify_proofs_get_alpha(my_dk, &r1state.k_i)
                .unwrap();
            alphas.insert(i, alpha).unwrap();

            // k256: decrypt alpha for MtA k_i * gamma_j
            let alpha_k256 = self
                .my_secret_key_share
                .dk_k256
                .decrypt(&in_p2p.alpha_ciphertext_k256)
                .to_scalar();
            alphas_k256.insert(i, alpha_k256).unwrap();

            // curv: decrypt mu for MtA k_i * w_j
            let (mu, _) = in_p2p
                .mta_response_keyshare
                .verify_proofs_get_alpha(my_dk, &r1state.k_i)
                .unwrap();
            mus.insert(i, mu).unwrap();

            // k256: decrypt mu for MtA k_i * w_j
            let mu_k256 = self
                .my_secret_key_share
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

        // curv
        let alphas = alphas.into_vec();
        let mut delta_i = r1state.k_i.mul(&r1state.gamma_i.get_element()); // k_i * gamma_i
        for i in 0..self.participant_indices.len() {
            if self.participant_indices[i] == self.my_secret_key_share.my_index {
                continue;
            }
            delta_i = delta_i
                + alphas[i]
                    .unwrap()
                    .add(&r2state.betas[i].unwrap().get_element());
        }

        // k256
        let delta_i_k256 = {
            let mut sum = r1state.k_i_k256 * r1state.gamma_i_k256; // k_i * gamma_i
            for i in 0..self.participant_indices.len() {
                if self.participant_indices[i] == self.my_secret_key_share.my_index {
                    continue;
                }
                sum = sum
                    + alphas_k256.vec_ref()[i].as_ref().unwrap()
                    + r2state.beta_secrets_k256.vec_ref()[i]
                        .as_ref()
                        .unwrap()
                        .beta;
            }
            sum
        };

        // compute sigma_i = k_i * w_i + sum_{j != i} mu_ij + nu_ji

        // curv
        let mus = mus.into_vec();
        let mut sigma_i = r1state.k_i.mul(&r1state.w_i.get_element());
        for i in 0..self.participant_indices.len() {
            if self.participant_indices[i] == self.my_secret_key_share.my_index {
                continue;
            }
            sigma_i = sigma_i + mus[i].unwrap().add(&r2state.nus[i].unwrap().get_element());
        }

        // k256
        let sigma_i_k256 = {
            let mut sum = r1state.k_i_k256 * r1state.w_i_k256; // k_i * w_i
            for i in 0..self.participant_indices.len() {
                if self.participant_indices[i] == self.my_secret_key_share.my_index {
                    continue;
                }
                sum = sum
                    + mus_k256.vec_ref()[i].as_ref().unwrap()
                    + r2state.nu_secrets_k256.vec_ref()[i].as_ref().unwrap().beta;
            }
            sum
        };

        #[cfg(feature = "malicious")] // TODO hack type7 fault
        if matches!(
            self.behaviour,
            super::malicious::MaliciousType::R3BadNonceXKeyshareSummand
        ) {
            use super::corrupt_scalar;
            sigma_i = corrupt_scalar(&sigma_i);
        }

        // curv
        let (t_i, l_i) = pedersen::commit(&sigma_i);
        let t_i_proof = pedersen::prove(
            &pedersen::Statement { commit: &t_i },
            &pedersen::Witness {
                msg: &sigma_i,
                randomness: &l_i,
            },
        );

        // k256
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
                delta_i,
                sigma_i,
                t_i,
                l_i,
                alphas,
                mus,
                sigma_i_k256,
                l_i_k256,
                alphas_k256,
                mus_k256,
            },
            out_bcast: Bcast {
                delta_i,
                t_i,
                t_i_proof,
                delta_i_k256: k256_serde::Scalar::from(delta_i_k256),
                t_i_k256: k256_serde::ProjectivePoint::from(t_i_k256),
                t_i_proof_k256,
            },
        }
    }
}
