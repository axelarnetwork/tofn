use super::{FinalOutput, R3Bcast, R3State};
use curv::cryptographic_primitives::proofs::sigma_dlog::{DLogProof, ProveDLog};

pub fn execute(state: R3State, in_bcasts: &[Option<R3Bcast>]) -> FinalOutput {
    assert_eq!(in_bcasts.len(), state.share_count);
    // verify other parties' proofs
    for i in 0..state.share_count {
        if i == state.my_index {
            continue;
        }
        let bcast = in_bcasts[i].clone().expect(&format!(
            "party {} says: missing bcast input for party {}",
            state.my_index, i
        ));
        DLogProof::verify(&bcast.dlog_proof).expect(&format!(
            "party {} says: dlog proof failed to verify for party {}",
            state.my_index, i
        ));
    }
    FinalOutput {
        my_share_index: state.my_share_index,
        ecdsa_public_key: state.ecdsa_public_key,
        my_ecdsa_secret_key_share: state.my_ecdsa_secret_key_share,
    }
}
