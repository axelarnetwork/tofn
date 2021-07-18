use crate::common::keygen;
use broadcaster::Broadcaster;
use std::{sync::mpsc, thread};
use tofn::refactor::{collections::VecMap, keygen::SecretKeyShare};

#[test]
fn basic_correctness() {
    let party_share_counts = VecMap::from_vec(vec![1, 2, 3, 4]); // 10 total shares
    let share_count = party_share_counts.iter().map(|(_, c)| c).sum();
    let threshold = 5;

    let shares = keygen::initialize_honest_parties(&party_share_counts, threshold);

    let (broadcaster, receivers) = Broadcaster::new(share_count);
    let (result_sender, result_receiver) = mpsc::channel();

    for ((_, share), receiver) in shares.into_iter().zip(receivers.into_iter()) {
        let broadcaster = broadcaster.clone();
        let result_sender = result_sender.clone();
        thread::spawn(move || {
            result_sender.send(party::execute_protocol(share, receiver, broadcaster))
        });
    }

    drop(result_sender); // so that result_receiver can close

    let results: Vec<SecretKeyShare> = result_receiver
        .into_iter()
        .map(|res| {
            res.expect("internal tofn error")
                .expect("party finished in sad path")
        })
        .collect();

    println!("group info: {:?}", results[0].group);
    for (i, result) in results.iter().enumerate() {
        println!("party {} secret info: {:?}", i, result.share);
    }
}

mod broadcaster {
    use std::sync::mpsc::{self, Receiver, Sender};

    #[derive(Clone)]
    pub struct Broadcaster<T> {
        senders: Vec<Sender<T>>,
    }

    impl<T> Broadcaster<T>
    where
        T: Clone,
    {
        pub fn new(party_count: usize) -> (Self, Vec<Receiver<T>>) {
            // can't build two vecs from one iterator
            // so we need to do it the old-fashioned way
            let mut senders = Vec::with_capacity(party_count);
            let mut receivers = Vec::with_capacity(party_count);
            for _ in 0..party_count {
                let (sender, receiver) = mpsc::channel();
                senders.push(sender);
                receivers.push(receiver);
            }
            (Self { senders }, receivers)
        }
        pub fn send(&self, msg: T) {
            for sender in self.senders.iter() {
                sender.send(msg.clone()).expect("broadcast fail");
            }
        }
    }
}
mod party;
