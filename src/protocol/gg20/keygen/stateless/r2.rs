use super::{super::super::vss, R1Bcast, R1State, R2Bcast, R2P2p, R2State};

pub fn execute(
    state: &R1State,
    in_bcasts: &[Option<R1Bcast>],
) -> (R2State, R2Bcast, Vec<Option<R2P2p>>) {
    assert_eq!(in_bcasts.len(), state.share_count);

    // verify other parties' proofs and build commits list
    let mut all_commits = Vec::with_capacity(state.share_count);
    for (i, bcast) in in_bcasts.iter().enumerate() {
        if i == state.my_index {
            all_commits.push(state.my_commit.clone());
            continue; // don't verify my own proof
        }
        let bcast = bcast.clone().unwrap_or_else(|| {
            panic!(
                "party {} says: missing input for party {}",
                state.my_index, i
            )
        });
        bcast
            .correct_key_proof
            .verify(&bcast.ek)
            .unwrap_or_else(|_| {
                panic!(
                    "party {} says: key proof failed to verify for party {}",
                    state.my_index, i
                )
            });
        bcast
            .zkp
            .dlog_proof
            .verify(&bcast.zkp.dlog_statement)
            .unwrap_or_else(|_| {
                panic!(
                    "party {} says: dlog proof failed to verify for party {}",
                    state.my_index, i
                )
            });
        all_commits.push(bcast.commit);
    }
    assert_eq!(all_commits.len(), state.share_count);

    let (secret_share_commitments, ecdsa_secret_summand_shares) = vss::share(
        state.threshold,
        state.share_count,
        &state.my_ecdsa_secret_summand,
    );
    assert_eq!(secret_share_commitments[0], state.my_ecdsa_public_summand);

    // Assign a unique, deterministic share index to each party
    // To this end, each party is assigned its index in the vec of sorted ids
    // let mut sorted_ids: Vec<&String> = input.in_r1bcast.keys().collect();
    // sorted_ids.push(&input.my_index);
    // sorted_ids.sort_unstable();

    // prepare outgoing p2p messages: secret shares of my_ecdsa_secret_summand
    let mut out_p2p: Vec<Option<R2P2p>> = ecdsa_secret_summand_shares
        .into_iter()
        .map(|x| {
            Some(R2P2p {
                ecdsa_secret_summand_share: x,
            })
        })
        .collect();
    let my_share_of_my_ecdsa_secret_summand = out_p2p[state.my_index]
        .take()
        .unwrap()
        .ecdsa_secret_summand_share;

    // TODO sign and encrypt each p2p_msg
    assert_eq!(out_p2p.len(), state.share_count);

    let out_bcast = R2Bcast {
        reveal: state.my_reveal.clone(),
        secret_share_commitments,
    };
    (
        R2State {
            share_count: state.share_count,
            threshold: state.threshold,
            my_index: state.my_index,
            my_share_of_my_ecdsa_secret_summand,
            my_ecdsa_public_summand: state.my_ecdsa_public_summand,
            all_commits,
        },
        out_bcast,
        out_p2p,
    )
}
