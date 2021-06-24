use rand::RngCore;
use tofn::{
    fillvec::FillVec,
    protocol::gg20::SecretKeyShare,
    refactor::{
        keygen::{new_keygen, KeygenOutput},
        protocol::protocol::{
            Protocol::{self, *},
            ProtocolRound,
        },
    },
};

/// TODO rename parent dir to `example`
/// TODO clean up
// TODO generic over final output F

#[test]
fn main() {
    let (share_count, threshold) = (5, 2);
    let session_nonce = b"foobar";

    let mut parties: Vec<Protocol<KeygenOutput>> = (0..share_count)
        .map(|index| {
            let mut secret_recovery_key = [0; 64];
            rand::thread_rng().fill_bytes(&mut secret_recovery_key);
            new_keygen(
                share_count,
                threshold,
                index,
                &secret_recovery_key,
                session_nonce,
            )
            .expect("`new_keygen` failure")
        })
        .collect();

    while nobody_done(&parties) {
        parties = next_round(parties);
    }

    let results: Vec<SecretKeyShare> = parties
        .into_iter()
        .enumerate()
        .map(|(i, party)| match party {
            NotDone(_) => panic!("party {} not done yet", i),
            Done(result) => result.expect("party finished with error"),
        })
        .collect();

    println!("group info: {:?}", results[0].group);
    for (i, result) in results.iter().enumerate() {
        println!("party {} secret info: {:?}", i, result.share);
    }
}

// TODO generic over final output F
fn nobody_done(parties: &[Protocol<KeygenOutput>]) -> bool {
    parties.iter().all(|party| matches!(party, NotDone(_)))
}

// TODO generic over final output F
fn next_round(parties: Vec<Protocol<KeygenOutput>>) -> Vec<Protocol<KeygenOutput>> {
    // extract current round from parties
    let mut rounds: Vec<ProtocolRound<KeygenOutput>> = parties
        .into_iter()
        .enumerate()
        .map(|(i, party)| match party {
            NotDone(round) => round,
            Done(_) => panic!("party {} done too early", i),
        })
        .collect();

    // deliver bcasts
    let bcasts: Vec<(usize, Vec<u8>)> = rounds
        .iter()
        .enumerate()
        .filter_map(|(i, round)| round.bcast_out().map(|bcast| (i, bcast.clone())))
        .collect();
    for (from, bcast) in bcasts.into_iter() {
        for round in rounds.iter_mut() {
            round.bcast_in(from, &bcast);
        }
    }

    // deliver p2ps
    let all_p2ps: Vec<FillVec<Vec<u8>>> = rounds
        .iter()
        .map(|round| round.p2ps_out().clone())
        .collect();
    for (from, p2ps) in all_p2ps.into_iter().enumerate() {
        for (to, p2p) in p2ps
            .into_vec()
            .into_iter()
            .enumerate()
            .filter_map(|(i, p2p)| p2p.map(|p| (i, p)))
        {
            for round in rounds.iter_mut() {
                round.p2p_in(from, to, &p2p);
            }
        }
    }

    // compute next round's parties
    rounds
        .into_iter()
        .enumerate()
        .map(|(i, round)| {
            assert!(
                !round.expecting_more_msgs_this_round(),
                "party {} should not be expecting more messages this round",
                i
            );
            round.execute_next_round()
        })
        .collect()
}
