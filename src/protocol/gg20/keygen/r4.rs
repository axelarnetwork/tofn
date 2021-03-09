use super::{Keygen, SecretKeyShare, Status};
use curv::cryptographic_primitives::proofs::sigma_dlog::{DLogProof, ProveDLog};

impl Keygen {
    pub(super) fn r4(&self) -> SecretKeyShare {
        assert!(matches!(self.status, Status::R3));
        let r1state = self.r1state.as_ref().unwrap();
        let r2state = self.r2state.as_ref().unwrap();
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
        SecretKeyShare {
            share_count: self.share_count,
            threshold: self.threshold,
            my_index: self.my_index,
            my_dk: r1state.my_dk.clone(),
            my_ek: r1state.my_ek.clone(),
            zkp: r1state.zkp.clone(),
            ecdsa_public_key: r3state.ecdsa_public_key,
            my_ecdsa_secret_key_share: r3state.my_ecdsa_secret_key_share,
            all_eks: r2state.all_eks.clone(),
        }
    }
}
