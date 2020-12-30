use super::*;

pub fn execute_protocol_vec<ID>(parties: &mut Vec<Protocol<ID>>)
    where ID: Eq + Clone
{
    // need to iterate over indices 0..n instead of parties.iter()
    // because otherwise the borrow checker complains
    // that's why we use Vec instead of HashMap :(
    for i in 0..parties.len() {
        let (bcast, p2ps) = parties[i].get_messages_out();
        let sender_id = parties[i].get_id().clone(); // clone to satisfy the borrow checker

        // broadcast message to all other parties
        if let Some(bcast) = bcast {
            for j in 0..parties.len() {
                if j==i {continue} // don't broadcast to myself
                parties[j].add_message_in(&sender_id, &bcast);
            }
        }

        // deliver p2p messages
        for (receiver_id, p2p) in p2ps { // quadratic complexity :(
            parties.iter_mut()
                .find(|p| *p.get_id()==receiver_id).unwrap() // linear search
                .add_message_in(&sender_id, &p2p);
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

#[cfg(test)]
pub mod mock; // abandoned