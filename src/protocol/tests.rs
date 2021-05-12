use super::{
    gg20::sign::{MsgMeta, Status},
    *,
};

pub(crate) struct Spoofer {
    pub(crate) my_index: usize,
    pub(crate) victim: usize,
    pub(crate) status: Status,
}

impl Spoofer {
    pub(crate) fn spoof(&self, original_msg: &[u8]) -> Vec<u8> {
        let mut msg: MsgMeta = bincode::deserialize(original_msg).unwrap();
        msg.set_from(self.victim);
        bincode::serialize(&msg).unwrap()
    }

    pub(crate) fn is_spoof_round(&self, msg: &[u8]) -> bool {
        let msg: MsgMeta = bincode::deserialize(msg).unwrap();
        msg.get_msg_type() == self.status
    }
}

pub fn execute_protocol_vec(parties: &mut [&mut dyn Protocol], allow_self_delivery: bool) {
    #[allow(clippy::needless_range_loop)] // see explanation below
    while nobody_done(parties) {
        // #[allow(clippy::needless_range_loop)]
        // need to iterate over indices 0..n instead of parties.iter()
        // to satisfy the borrow checker
        for i in 0..parties.len() {
            assert!(!parties[i].expecting_more_msgs_this_round());
            parties[i].next_round().unwrap();

            let from_index_range = IndexRange { first: i, last: i };

            // deliver bcast message to all other parties
            if let Some(bcast) = parties[i].get_bcast_out() {
                let bcast = bcast.clone();
                for j in 0..parties.len() {
                    if !allow_self_delivery && j == i {
                        continue; // don't broadcast to myself
                    }
                    parties[j].set_msg_in(&bcast, &from_index_range).unwrap();
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
                            parties[j].set_msg_in(&p2p, &from_index_range).unwrap();
                        }
                    }
                }
            }
        }
    }
}

pub(crate) fn execute_protocol_vec_spoof(
    parties: &mut [&mut dyn Protocol],
    allow_self_delivery: bool,
    spoofers: &[Spoofer],
) {
    #[allow(clippy::needless_range_loop)] // see explanation below
    while nobody_done(parties) {
        // #[allow(clippy::needless_range_loop)]
        // need to iterate over indices 0..n instead of parties.iter()
        // to satisfy the borrow checker
        for i in 0..parties.len() {
            assert!(!parties[i].expecting_more_msgs_this_round());
            parties[i].next_round().unwrap();

            let from_index_range = IndexRange { first: i, last: i };

            // deliver bcast message to all other parties
            if let Some(bcast) = parties[i].get_bcast_out() {
                let bcast = bcast.clone();
                for j in 0..parties.len() {
                    if !allow_self_delivery && j == i {
                        continue; // don't broadcast to myself
                    }
                    parties[j].set_msg_in(&bcast, &from_index_range).unwrap();

                    // create index range with incorrect 'from' field if i am a spoofer
                    if let Some(spoofer) = spoofers.iter().find(|s| s.my_index == i) {
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
                    if !allow_self_delivery && j == i {
                        continue; // don't deliver to myself
                    }
                    for opt in &p2ps {
                        if let Some(p2p) = opt {
                            parties[j].set_msg_in(&p2p, &from_index_range).unwrap();
                            // create index range with incorrect 'from' field if i am a spoofer
                            if let Some(spoofer) = spoofers.iter().find(|s| s.my_index == i) {
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
