use super::*;

pub const TEST_CASES: [(usize, usize); 4] // (share_count, threshold)
    = [(5, 0), (5, 1), (5, 3), (5, 4)];

pub fn execute_protocol_vec<R>(parties: &mut Vec<Protocol<R>>) {
    #[allow(clippy::needless_range_loop)] // see explanation below
    while !all_done(parties) {
        // #[allow(clippy::needless_range_loop)]
        // need to iterate over indices 0..n instead of parties.iter()
        // because otherwise the borrow checker complains
        // TODO a better way? https://ryhl.io/blog/temporary-shared-mutation/
        for i in 0..parties.len() {
            let (bcast, p2ps) = parties[i].get_messages_out();
            let sender_id = parties[i].get_id().to_string(); // clone to satisfy the borrow checker

            // deliver bcast message to all other parties
            if let Some(bcast) = bcast {
                // #[allow(clippy::needless_range_loop)]
                for j in 0..parties.len() {
                    if j == i {
                        continue;
                    } // don't broadcast to myself
                    parties[j].add_message_in(&sender_id, &bcast);
                }
            }

            // deliver p2p messages
            for (receiver_id, p2p) in p2ps {
                // quadratic complexity :(
                parties
                    .iter_mut()
                    .find(|p| *p.get_id() == receiver_id)
                    .unwrap() // linear search
                    .add_message_in(&sender_id, &p2p);
            }
        }

        // all messages delivered -- all parties should now be able to proceed
        for p in parties.iter() {
            if !p.can_proceed() {
                panic!("party {:?} cannot proceed", p.get_id());
            }
        }

        // advance all parties to next round
        // iterate over indices 0..n to satisfy the borrow checker
        for i in 0..parties.len() {
            parties[i].next();
        }
    }
}

// TODO can't satisfy the borrow checker with HashMap
// pub fn execute_protocol_map<ID>(parties: &mut HashMap<ID,Protocol<ID>>)
//     where ID: Eq + Clone
// {
//     // lots of fighting the borrow checker here
//     for (id,p) in parties.iter() {
//         let (bcast, p2ps) = p.get_messages_out();
//         let sender_id = p.get_id().clone(); // clone to satisfy the borrow checker
//         if let Some(bcast) = bcast {
//             for (id2,p2) in parties { // <-- borrow checker complains
//                 if id2==id {continue} // don't broadcast to myself
//                 p2.add_message_in(&sender_id, &bcast);
//             }
//         }
//         for (receiver_id, p2p) in p2ps {
//         }
//     }
// }

fn all_done<R>(parties: &[Protocol<R>]) -> bool {
    // panic if there's disagreement
    let done = parties[0].done();
    let parties = parties.iter().skip(1);
    for p in parties {
        if p.done() != done {
            panic!(
                "party {:?} done? [{}], party 0 done? [{}]",
                p.get_id(),
                p.done(),
                done
            );
        }
    }
    done
}

#[cfg(test)]
pub mod mock; // abandoned
