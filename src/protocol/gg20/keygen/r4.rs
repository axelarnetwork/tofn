use super::{crimes::Crime, Keygen, SecretKeyShare, Status};
use crate::{k256_serde, zkp::schnorr_k256};
use tracing::warn;

pub(super) enum Output {
    Success { key_share: SecretKeyShare },
    Fail { criminals: Vec<Vec<Crime>> },
}

impl Keygen {
    pub(super) fn r4(&self) -> Output {
        assert!(matches!(self.status, Status::R3));
        let r1state = self.r1state.as_ref().unwrap();
        let r3state = self.r3state.as_ref().unwrap();

        // k256: verify proofs
        let criminals_k256: Vec<Vec<Crime>> = self
            .in_r3bcasts
            .vec_ref()
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if schnorr_k256::verify(
                    &schnorr_k256::Statement {
                        base: &k256::ProjectivePoint::generator(),
                        target: &self.r3state.as_ref().unwrap().all_y_i_k256[i],
                    },
                    &b.as_ref().unwrap().x_i_proof,
                )
                .is_err()
                {
                    let crime = Crime::R4BadDLProof;
                    warn!("(k256) party {} detect {:?} by {}", self.my_index, crime, i);
                    vec![crime]
                } else {
                    vec![]
                }
            })
            .collect();
        if !criminals_k256.iter().all(Vec::is_empty) {
            return Output::Fail {
                criminals: criminals_k256,
            };
        }

        // prepare data for final output
        let r1bcasts = self.in_r1bcasts.vec_ref();

        let all_eks_k256 = r1bcasts
            .iter()
            .map(|b| b.as_ref().unwrap().ek_k256.clone())
            .collect();
        let all_zkps_k256 = r1bcasts
            .iter()
            .map(|b| b.as_ref().unwrap().zkp_k256.clone())
            .collect();

        Output::Success {
            key_share: SecretKeyShare {
                share_count: self.share_count,
                threshold: self.threshold,
                my_index: self.my_index,
                dk_k256: r1state.dk_k256.clone(),
                y_k256: r3state.y_k256.into(),
                my_x_i_k256: r3state.my_x_i_k256.into(),
                all_y_i_k256: r3state
                    .all_y_i_k256
                    .iter()
                    .map(k256_serde::ProjectivePoint::from)
                    .collect(),
                all_eks_k256,
                all_zkps_k256,
            },
        }
    }
}
