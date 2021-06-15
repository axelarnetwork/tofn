use super::{Sign, Status};
use crate::fillvec::FillVec;
use crate::mta;
use crate::paillier_k256::{Plaintext, Randomness};
use crate::{k256_serde, paillier_k256::zk, zkp::pedersen_k256};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct Bcast {
    pub S_i_k256: k256_serde::ProjectivePoint,
    pub S_i_proof_wc_k256: pedersen_k256::ProofWc,
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
    Success { out_bcast: Bcast },
    Fail { out_bcast: BcastFail },
    FailType5 { out_bcast: BcastFailType5 },
}

impl Sign {
    #[allow(non_snake_case)]
    pub(super) fn r6(&self) -> Output {
        assert!(matches!(self.status, Status::R5));
        let r5state = self.r5state.as_ref().unwrap();

        // k256: verify proofs
        let culprits: Vec<Culprit> = self
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
                            ek: &self.my_secret_key_share.group.all_shares[*participant_index].ek,
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
        if !culprits.is_empty() {
            return Output::Fail {
                out_bcast: BcastFail { culprits },
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

        // k256: compute S_i
        let S_i_k256 = r5state.R_k256 * r3state.sigma_i_k256;
        let S_i_proof_wc_k256 = pedersen_k256::prove_wc(
            &pedersen_k256::StatementWc {
                stmt: pedersen_k256::Statement {
                    commit: r3bcast.T_i_k256.unwrap(),
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
            out_bcast: Bcast {
                S_i_k256: S_i_k256.into(),
                S_i_proof_wc_k256,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct BcastFailType5 {
    pub k_i_256: k256_serde::Scalar,
    pub k_i_randomness_k256: Randomness,
    pub gamma_i_k256: k256_serde::Scalar,
    pub mta_plaintexts: Vec<Option<MtaPlaintext>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct MtaPlaintext {
    // need alpha_plaintext instead of alpha
    // because alpha_plaintext may differ from alpha
    // why? because the ciphertext was formed from homomorphic Paillier operations, not just encrypting alpha
    pub(super) alpha_plaintext_k256: Plaintext,
    pub(super) alpha_randomness_k256: Randomness,
    pub(super) beta_secrets_k256: mta::Secret,
}

impl Sign {
    // execute blame protocol from section 4.3 of https://eprint.iacr.org/2020/540.pdf
    pub(super) fn type5_fault_output(&self) -> BcastFailType5 {
        assert!(matches!(self.status, Status::R5));

        let r1state = self.r1state.as_ref().unwrap();
        let r2state = self.r2state.as_ref().unwrap();
        let r3state = self.r3state.as_ref().unwrap();
        let mut mta_plaintexts = FillVec::with_len(self.participant_indices.len());

        for i in 0..self.participant_indices.len() {
            if i == self.my_participant_index {
                continue;
            }

            // k256
            // recover encryption randomness for alpha; need to decrypt again to do so
            let in_p2p = self.in_all_r2p2ps[i].vec_ref()[self.my_participant_index]
                .as_ref()
                .unwrap();
            let (alpha_plaintext_k256, alpha_randomness_k256) = self
                .my_secret_key_share
                .share
                .dk_k256
                .decrypt_with_randomness(&in_p2p.alpha_ciphertext_k256);

            // sanity check: we should recover the alpha we computed in r3
            {
                let alpha_k256 = alpha_plaintext_k256.to_scalar();
                if alpha_k256 != r3state.alphas_k256.vec_ref()[i].unwrap() {
                    error!(
                        "participant {} decryption of alpha from {} in r6 differs from r3",
                        self.my_participant_index, i
                    );
                }
            }

            mta_plaintexts
                .insert(
                    i,
                    MtaPlaintext {
                        beta_secrets_k256: r2state.beta_secrets_k256.vec_ref()[i]
                            .as_ref()
                            .unwrap()
                            .clone(),
                        alpha_plaintext_k256,
                        alpha_randomness_k256,
                    },
                )
                .unwrap();
        }

        BcastFailType5 {
            k_i_256: k256_serde::Scalar::from(r1state.k_i_k256),
            k_i_randomness_k256: r1state.k_i_randomness_k256.clone(),
            gamma_i_k256: k256_serde::Scalar::from(r1state.gamma_i_k256),
            mta_plaintexts: mta_plaintexts.into_vec(),
        }
    }
}
