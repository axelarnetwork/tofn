use super::*;

pub(crate) trait Spoofer {
    fn index(&self) -> usize;
    fn spoof(&self, original_msg: &[u8]) -> Vec<u8>;
    fn is_spoof_round(&self, msg: &[u8]) -> bool;
}

pub(crate) fn execute_protocol_vec(parties: &mut [&mut dyn Protocol]) {
    execute_protocol_vec_spoof(
        parties,
        &[], // create an empty slice of spoofers
    )
}

// check that all parties agree on expecting new messages
fn all_parties_expect_the_same(parties: &[&mut dyn Protocol]) -> bool {
    let expecting_more = parties[0].expecting_more_msgs_this_round();
    for (i, p) in parties.iter().enumerate() {
        if expecting_more != p.expecting_more_msgs_this_round() {
            println!("Party {} disagree", i);
            return false;
        }
    }
    true
}

pub(crate) fn execute_protocol_vec_spoof(
    parties: &mut [&mut dyn Protocol],
    spoofers: &[&dyn Spoofer],
) {
    #[allow(clippy::needless_range_loop)] // see explanation below
    while nobody_done(parties) {
        // #[allow(clippy::needless_range_loop)]
        // need to iterate over indices 0..n instead of parties.iter()
        // to satisfy the borrow checker
        for i in 0..parties.len() {
            // set up index range. We check if 'from' index is the current share
            let from_index_range = IndexRange { first: i, last: i };

            // pick spoofer if exists and acts in the current round
            let spoofer = spoofers.iter().find(|s| s.index() == i);

            // deliver bcast message to all other parties
            if let Some(bcast) = parties[i].get_bcast_out() {
                let bcast = bcast.clone();
                for j in 0..parties.len() {
                    parties[j].set_msg_in(&bcast, &from_index_range).unwrap();

                    // if I am a spoofer, create a *duplicate* message and change
                    // the 'from' field of the new message into 'victim'
                    if let Some(spoofer) = spoofer {
                        if spoofer.is_spoof_round(&bcast) {
                            parties[j]
                                .set_msg_in(&spoofer.spoof(&bcast), &from_index_range)
                                .unwrap();
                        }
                    }
                }
            }

            // deliver p2p messages
            if let Some(p2ps) = parties[i].get_p2p_out() {
                let p2ps = p2ps.clone(); // fighting the borrow checker
                for j in 0..parties.len() {
                    for opt in &p2ps {
                        if let Some(p2p) = opt {
                            parties[j].set_msg_in(&p2p, &from_index_range).unwrap();
                            // if I am a spoofer, create a *duplicate* message and change
                            // the 'from' field of the new message into 'victim'
                            if let Some(spoofer) = spoofer {
                                if spoofer.is_spoof_round(&p2p) {
                                    parties[j]
                                        .set_msg_in(&spoofer.spoof(&p2p), &from_index_range)
                                        .unwrap();
                                }
                            }
                        }
                    }
                }
            }

            // check that all parties agree on expecting more messages after the end of every party's round
            assert!(all_parties_expect_the_same(parties));
        }

        // proceed to next round for each party
        for i in 0..parties.len() {
            parties[i].next_round().unwrap();
        }
    }
}

use tracing::warn;
fn nobody_done(parties: &[&mut dyn Protocol]) -> bool {
    // warn if there's disagreement
    let (mut done, mut not_done) = (
        Vec::with_capacity(parties.len()),
        Vec::with_capacity(parties.len()),
    );
    for (i, p) in parties.iter().enumerate() {
        if p.done() {
            done.push(i);
        } else {
            not_done.push(i);
        }
    }
    if !done.is_empty() && !not_done.is_empty() {
        warn!(
            "disagreement: done parties {:?}, not done parties {:?}",
            done, not_done
        );
    }
    done.is_empty()
}
