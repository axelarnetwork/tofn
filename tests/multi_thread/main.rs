use broadcaster::Broadcaster;
use rand::RngCore;
use std::{sync::mpsc, thread};
use tofn::{
    protocol::gg20::SecretKeyShare,
    refactor::{
        keygen::{new_keygen, KeygenOutput, KeygenPartyIndex},
        protocol::Protocol,
    },
    vecmap::Index,
};

/// TODO rename parent dir to `example`
/// TODO clean up
// TODO generic over final output F

#[test]
fn main() {
    let (share_count, threshold) = (5, 2);
    let session_nonce = b"foobar";

    let parties: Vec<Protocol<KeygenOutput, KeygenPartyIndex>> = (0..share_count)
        .map(|index| {
            let mut secret_recovery_key = [0; 64];
            rand::thread_rng().fill_bytes(&mut secret_recovery_key);
            new_keygen(
                share_count,
                threshold,
                Index::from_usize(index),
                &secret_recovery_key,
                session_nonce,
            )
            .expect("`new_keygen` failure")
        })
        .collect();

    let (broadcaster, receivers) = Broadcaster::new(share_count);
    let (result_sender, result_receiver) = mpsc::channel();

    for (party, receiver) in parties.into_iter().zip(receivers.into_iter()) {
        let broadcaster = broadcaster.clone();
        let result_sender = result_sender.clone();
        thread::spawn(move || {
            result_sender.send(party::execute_protocol(party, receiver, broadcaster))
        });
    }

    drop(result_sender); // so that result_receiver can close

    let results: Vec<SecretKeyShare> = result_receiver
        .into_iter()
        .map(|res| res.expect("party finished with error"))
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
