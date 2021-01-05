use std::collections::HashMap;
use super::{R1State, R2Input, R2Output, R2State, R2Bcast, R2P2p, super::super::vss};

pub fn execute(state: R1State, input: R2Input) -> (R2State, R2Output) {
    let share_count = input.other_r1_bcasts.len() + 1;

    assert!(input.threshold < share_count);
    assert!(!input.other_r1_bcasts.contains_key(&input.my_uid));

    // verify other parties' proofs
    for r1_msg_out in input.other_r1_bcasts.values() {
        r1_msg_out.correct_key_proof.verify(&r1_msg_out.ek).unwrap(); // panic on error for now
        r1_msg_out.zkp.dlog_proof.verify(&r1_msg_out.zkp.dlog_statement).unwrap(); // panic on error for now
    }

    let (
        my_secret_share_commitments,
        my_ecdsa_secret_summand_shares,
    ) = vss::share(
        input.threshold,
        share_count,
        &state.my_ecdsa_secret_summand
    );

    // Assign a unique, deterministic share index to each party
    // To this end, each party is assigned its index in the vec of sorted ids
    let mut sorted_ids : Vec<&String> = input.other_r1_bcasts.keys().collect();
    sorted_ids.push(&input.my_uid);
    sorted_ids.sort_unstable();

    // prepare outgoing p2p messages: secret shares of my_ecdsa_secret_summand
    let mut p2p = HashMap::<String,_>::with_capacity(input.other_r1_bcasts.len());
    let (mut my_share_of_my_ecdsa_secret_summand, mut my_share_index) = (None,None);
    for i in 0..sorted_ids.len() {

        // keep my own share for myself
        if *sorted_ids[i] == input.my_uid {
            my_share_of_my_ecdsa_secret_summand = Some(my_ecdsa_secret_summand_shares[i]);
            my_share_index = Some(i+1); // TODO watch out! maybe I should select my own indices...
            continue;
        }

        p2p.insert(
            sorted_ids[i].clone(),
            R2P2p{ ecdsa_secret_summand_share: my_ecdsa_secret_summand_shares[i] }
        );
    }

    // TODO sign and encrypt each p2p_msg

    assert_eq!(p2p.len(), share_count-1);
    let my_output = R2Output {
        bcast: R2Bcast {
            reveal: state.my_reveal.clone(),
            secret_share_commitments: my_secret_share_commitments,
        },
        p2p,
    };
    (
        R2State {
            my_share_of_my_ecdsa_secret_summand: my_share_of_my_ecdsa_secret_summand.unwrap(),
            my_share_index: my_share_index.unwrap(),
            my_r1_state: state,
            input: input.clone(),
            my_output: my_output.clone(),
        },
        my_output,
    )
}