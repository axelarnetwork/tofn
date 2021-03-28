use super::*;

// TODO temporary: used only by keygen because keygen parties do not yet store _all_ p2p messages
pub fn execute_protocol_vec_no_p2p(parties: &mut [&mut dyn Protocol]) {
    #[allow(clippy::needless_range_loop)] // see explanation below
    while !all_done(parties) {
        // #[allow(clippy::needless_range_loop)]
        // need to iterate over indices 0..n instead of parties.iter()
        // to satisfy the borrow checker
        for i in 0..parties.len() {
            assert!(!parties[i].expecting_more_msgs_this_round());
            parties[i].next_round().unwrap();

            // deliver bcast message to all other parties
            if let Some(bcast) = parties[i].get_bcast_out() {
                let bcast = bcast.clone();
                for j in 0..parties.len() {
                    if j == i {
                        continue; // don't broadcast to myself
                    }
                    parties[j].set_msg_in(&bcast).unwrap();
                }
            }

            // deliver p2p messages
            // only deliver to party j messages addressed to j
            if let Some(p2ps) = parties[i].get_p2p_out() {
                let p2ps = p2ps.clone();
                for (j, opt) in p2ps.iter().enumerate() {
                    if let Some(p2p) = opt {
                        parties[j].set_msg_in(&p2p).unwrap();
                    }
                }
            }
        }
    }
}

pub fn execute_protocol_vec(parties: &mut [&mut dyn Protocol], allow_self_delivery: bool) {
    #[allow(clippy::needless_range_loop)] // see explanation below
    while !all_done(parties) {
        // #[allow(clippy::needless_range_loop)]
        // need to iterate over indices 0..n instead of parties.iter()
        // to satisfy the borrow checker
        for i in 0..parties.len() {
            assert!(!parties[i].expecting_more_msgs_this_round());
            parties[i].next_round().unwrap();

            // deliver bcast message to all other parties
            if let Some(bcast) = parties[i].get_bcast_out() {
                let bcast = bcast.clone();
                for j in 0..parties.len() {
                    if !allow_self_delivery && j == i {
                        continue; // don't broadcast to myself
                    }
                    parties[j].set_msg_in(&bcast).unwrap();
                }
            }

            // deliver p2p messages
            if let Some(p2ps) = parties[i].get_p2p_out() {
                let p2ps = p2ps.clone(); // fighting the borrow checker
                for j in 0..parties.len() {
                    if !allow_self_delivery && j == i {
                        continue; // don't deliver to myself
                    }
                    for opt in &p2ps {
                        if let Some(p2p) = opt {
                            parties[j].set_msg_in(&p2p).unwrap();
                        }
                    }
                }
            }
        }
    }
}

fn all_done(parties: &[&mut dyn Protocol]) -> bool {
    // panic if there's disagreement
    let done = parties[0].done();
    let parties = parties.iter().skip(1);
    for (i, p) in parties.enumerate() {
        if p.done() != done {
            panic!(
                "party 0 done? [{}], but party {} done? [{}]",
                done,
                i,
                p.done()
            );
        }
    }
    done
}
