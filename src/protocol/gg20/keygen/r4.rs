use super::{Keygen, SecretKeyShare, Status};
use crate::k256_serde;
use curv::cryptographic_primitives::proofs::sigma_dlog::{DLogProof, ProveDLog};

impl Keygen {
    pub(super) fn r4(&self) -> SecretKeyShare {
        assert!(matches!(self.status, Status::R3));
        let r1state = self.r1state.as_ref().unwrap();
        let r3state = self.r3state.as_ref().unwrap();

        // verify other parties' proofs
        for (i, bcast) in self.in_r3bcasts.vec_ref().iter().enumerate() {
            if i == self.my_index {
                continue;
            }
            let bcast = bcast.clone().unwrap_or_else(|| {
                panic!(
                    "party {} says: missing bcast input for party {}",
                    self.my_index, i
                )
            });
            DLogProof::verify(&bcast.dlog_proof).unwrap_or_else(|_| {
                panic!(
                    "party {} says: dlog proof failed to verify for party {}",
                    self.my_index, i
                )
            });
        }

        // prepare data for final output
        let r1bcasts = self.in_r1bcasts.vec_ref();

        // curv
        let all_eks = r1bcasts
            .iter()
            .map(|b| b.as_ref().unwrap().ek.clone())
            .collect();
        let all_zkps = r1bcasts
            .iter()
            .map(|b| b.as_ref().unwrap().zkp.clone())
            .collect();

        // k256
        let all_eks_k256 = r1bcasts
            .iter()
            .map(|b| b.as_ref().unwrap().ek_k256.clone())
            .collect();
        let all_zkps_k256 = r1bcasts
            .iter()
            .map(|b| b.as_ref().unwrap().zkp_k256.clone())
            .collect();

        SecretKeyShare {
            share_count: self.share_count,
            threshold: self.threshold,
            my_index: self.my_index,
            my_dk: r1state.my_dk.clone(),
            my_ek: r1state.my_ek.clone(),
            my_zkp: r1state.my_zkp.clone(),
            ecdsa_public_key: r3state.y,
            my_ecdsa_secret_key_share: r3state.my_x_i,
            all_ecdsa_public_key_shares: r3state.all_y_i.clone(),
            all_eks,
            all_zkps,

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
        }
    }
}
