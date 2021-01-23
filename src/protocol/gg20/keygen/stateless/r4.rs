use super::{FinalOutput, R3Bcast, R3State};
use curv::cryptographic_primitives::proofs::sigma_dlog::{DLogProof, ProveDLog};

pub fn execute(state: &R3State, in_bcasts: &[Option<R3Bcast>]) -> FinalOutput {
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
    FinalOutput {
        my_share_index: state.my_share_index,
        ecdsa_public_key: state.ecdsa_public_key,
        my_ecdsa_secret_key_share: state.my_ecdsa_secret_key_share,
    }
}
