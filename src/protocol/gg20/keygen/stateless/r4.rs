use super::{FinalOutput, R3State, R4Input};
use curv::cryptographic_primitives::proofs::sigma_dlog::{DLogProof, ProveDLog};

pub fn execute(state: R3State, input: R4Input) -> FinalOutput {
    // TODO:
    // assert!(!msg.other_r2_msgs.contains_key(&msg.my_uid));
    // assert_eq!(
    //     msg.other_r2_msgs.keys().collect::<Vec<&ID>>().sort_unstable(),
    //     state.others.keys().collect::<Vec<&ID>>().sort_unstable()
    // );

    // verify other parties' proofs
    for other_r3_bcast in input.other_r3_bcasts.values() {
        DLogProof::verify(&other_r3_bcast.dlog_proof).unwrap(); // panic on error for now
    }

    FinalOutput {
        my_share_index: state.my_r2_state.my_share_index,
        ecdsa_public_key: state.ecdsa_public_key,
        my_ecdsa_secret_key_share: state.my_ecdsa_secret_key_share,
        // my_r3_state: state,
    }
}
