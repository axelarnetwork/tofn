use super::{R3Bcast, R3State, SecretKeyShare};
use curv::cryptographic_primitives::proofs::sigma_dlog::{DLogProof, ProveDLog};

pub fn execute(state: &R3State, in_bcasts: &[Option<R3Bcast>]) -> SecretKeyShare {
    assert_eq!(in_bcasts.len(), state.share_count);
    // verify other parties' proofs
    for (i, bcast) in in_bcasts.iter().enumerate() {
        if i == state.my_index {
            continue;
        }
        let bcast = bcast.clone().unwrap_or_else(|| {
            panic!(
                "party {} says: missing bcast input for party {}",
                state.my_index, i
            )
        });
        DLogProof::verify(&bcast.dlog_proof).unwrap_or_else(|_| {
            panic!(
                "party {} says: dlog proof failed to verify for party {}",
                state.my_index, i
            )
        });
    }
    SecretKeyShare {
        share_count: state.share_count,
        threshold: state.threshold,
        my_index: state.my_index,
        my_dk: state.my_dk.clone(),
        my_ek: state.my_ek.clone(),
        ecdsa_public_key: state.ecdsa_public_key,
        my_ecdsa_secret_key_share: state.my_ecdsa_secret_key_share,
        all_eks: state.all_eks.clone(),
    }
}
