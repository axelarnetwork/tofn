use curv::{
    cryptographic_primitives::{
        proofs::sigma_dlog::{DLogProof, ProveDLog},
    },
};
use super::{R3State, R4Input, R4State};

pub fn execute(state: R3State, msg: R4Input) -> R4State {
    // TODO:
    // assert!(!msg.other_r2_msgs.contains_key(&msg.my_uid));
    // assert_eq!(
    //     msg.other_r2_msgs.keys().collect::<Vec<&ID>>().sort_unstable(),
    //     state.others.keys().collect::<Vec<&ID>>().sort_unstable()
    // );

    // verify other parties' proofs
    for other_r3_bcast in msg.other_r3_bcasts.values() {
        DLogProof::verify(&other_r3_bcast.dlog_proof).unwrap(); // panic on error for now
    }

    R4State{
        my_vss_index: state.my_vss_index,
        public_key: state.public_key,
        my_secret_key_share: state.my_secret_key_share,
    }
}