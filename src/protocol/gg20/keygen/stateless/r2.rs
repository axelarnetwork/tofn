use std::collections::HashMap;
use curv::{
    cryptographic_primitives::{
        secret_sharing::feldman_vss::{VerifiableSS},
    },
};
use super::{R1State, R2Input, R2Output, R2State, R2Bcast, R2P2p};

pub fn execute(state: R1State, msg: R2Input) -> (R2State, R2Output) {
    let share_count = msg.other_r1_bcasts.len() + 1;

    assert!(msg.threshold < share_count);
    assert!(!msg.other_r1_bcasts.contains_key(&msg.my_uid));

    // verify other parties' proofs
    for r1_msg_out in msg.other_r1_bcasts.values() {
        r1_msg_out.correct_key_proof.verify(&r1_msg_out.ek).unwrap(); // panic on error for now
        r1_msg_out.zkp.dlog_proof.verify(&r1_msg_out.zkp.dlog_statement).unwrap(); // panic on error for now
    }

    let (my_vss_scheme, all_secret_shares) = VerifiableSS::share(
        msg.threshold,
        share_count,
        &state.u
    );

    // ensure a deterministic distribution of unique shares among parties
    // TODO too much cloning
    let mut sorted_ids : Vec<&String> = msg.other_r1_bcasts.keys().collect();
    sorted_ids.push(&msg.my_uid);
    sorted_ids.sort_unstable();

    let mut p2p_msg = HashMap::<String,_>::with_capacity(msg.other_r1_bcasts.len());
    // let mut others = HashMap::<ID,_>::with_capacity(msg.other_r1_bcasts.len());
    let (mut my_share_of_u, mut my_vss_index) = (None,None);
    for i in 0..sorted_ids.len() {
        if *sorted_ids[i] == msg.my_uid {
            my_share_of_u = Some(all_secret_shares[i]);
            my_vss_index = Some(i+1); // TODO watch out! maybe I should select my own indices...
            continue;
        }
        p2p_msg.insert(
            sorted_ids[i].clone(),
            R2P2p{ secret_share: all_secret_shares[i] }
        );
        // others.insert(
        //     sorted_ids[i].clone(),
        //     ( msg.other_r1_bcasts.get(&sorted_ids[i]).unwrap().clone(), i )
        // );
    }

    // TODO sign and encrypt each p2p_msg

    assert_eq!(p2p_msg.len(), share_count-1);
    (
        R2State {
            // u: state.u,
            y: state.y,
            dk: state.dk,
            my_share_of_u: my_share_of_u.unwrap(),
            my_vss_index: my_vss_index.unwrap(),
            others: msg.other_r1_bcasts,
            threshold: msg.threshold,
        },
        R2Output {
            broadcast: R2Bcast {
                y: state.y,
                my_reveal: state.reveal,
                my_vss_commitments: my_vss_scheme.commitments,
                // my_vss_scheme,
            },
            p2p: p2p_msg,
        },
    )
}