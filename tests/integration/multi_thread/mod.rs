use crate::common::keygen;
use broadcaster::Broadcaster;
use ecdsa::{elliptic_curve::sec1::FromEncodedPoint, hazmat::VerifyPrimitive};
use std::{convert::TryFrom, sync::mpsc, thread};
use tofn::{
    collections::{TypedUsize, VecMap},
    gg20::{
        keygen::{KeygenShareId, SecretKeyShare},
        sign::{new_sign, MessageDigest, SignParties, SignShareId},
    },
    sdk::api::PartyShareCounts,
};
use tracing::debug;

#[cfg(feature = "malicious")]
use tofn::gg20::sign;

#[test]
fn basic_correctness() {
    set_up_logs();

    let party_share_counts = PartyShareCounts::from_vec(vec![1, 2, 3, 4]).unwrap(); // 10 total shares
    let threshold = 5;

    // keygen
    debug!("start keygen");
    let keygen_shares = keygen::initialize_honest_parties(&party_share_counts, threshold);
    let (keygen_broadcaster, keygen_receivers) =
        Broadcaster::new(party_share_counts.total_share_count());
    let (keygen_result_sender, keygen_result_receiver) = mpsc::channel();
    for ((_, keygen_share), keygen_receiver) in
        keygen_shares.into_iter().zip(keygen_receivers.into_iter())
    {
        let keygen_broadcaster = keygen_broadcaster.clone();
        let keygen_result_sender = keygen_result_sender.clone();
        thread::spawn(move || {
            keygen_result_sender.send(party::execute_protocol(
                keygen_share,
                keygen_receiver,
                keygen_broadcaster,
            ))
        });
    }
    drop(keygen_result_sender); // so that result_receiver can close

    // collect keygen output
    let mut secret_key_shares_unsorted: Vec<SecretKeyShare> = keygen_result_receiver
        .into_iter()
        .map(|output| {
            output
                .expect("keygen internal tofn error")
                .expect("keygen party finished in sad path")
        })
        .collect();
    debug!("end keygen");
    secret_key_shares_unsorted.sort_by(|a, b| {
        a.share()
            .index()
            .as_usize()
            .cmp(&b.share().index().as_usize())
    });
    let secret_key_shares = VecMap::<KeygenShareId, _>::from_vec(secret_key_shares_unsorted);

    // sign participants: 0,1,3 out of 0,1,2,3
    let sign_parties = {
        let mut sign_parties = SignParties::with_max_size(party_share_counts.party_count());
        sign_parties.add(TypedUsize::from_usize(0)).unwrap();
        sign_parties.add(TypedUsize::from_usize(1)).unwrap();
        sign_parties.add(TypedUsize::from_usize(3)).unwrap();
        sign_parties
    };
    let keygen_share_ids = VecMap::<SignShareId, _>::from_vec(
        party_share_counts.share_id_subset(&sign_parties).unwrap(),
    );

    // sign
    debug!("start sign");
    let msg_to_sign = MessageDigest::try_from(&[42; 32][..]).unwrap();
    let sign_shares = keygen_share_ids.map(|keygen_share_id| {
        let secret_key_share = secret_key_shares.get(keygen_share_id).unwrap();
        new_sign(
            secret_key_share.group(),
            secret_key_share.share(),
            &sign_parties,
            &msg_to_sign,
            #[cfg(feature = "malicious")]
            sign::malicious::Behaviour::Honest,
        )
        .unwrap()
    });

    let (sign_broadcaster, sign_receivers) = Broadcaster::new(sign_shares.len());
    let (sign_result_sender, sign_result_receiver) = mpsc::channel();
    for ((_, sign_share), sign_receiver) in sign_shares.into_iter().zip(sign_receivers.into_iter())
    {
        let sign_broadcaster = sign_broadcaster.clone();
        let sign_result_sender = sign_result_sender.clone();
        thread::spawn(move || {
            sign_result_sender.send(party::execute_protocol(
                sign_share,
                sign_receiver,
                sign_broadcaster,
            ))
        });
    }
    drop(sign_result_sender); // so that result_receiver can close

    // collect sign output
    let signatures: VecMap<SignShareId, _> = sign_result_receiver
        .into_iter()
        .map(|output| {
            output
                .expect("sign internal tofn error")
                .expect("sign party finished in sad path")
        })
        .collect();
    debug!("end sign");

    // grab pubkey bytes from one of the shares
    let pubkey_bytes = secret_key_shares
        .get(TypedUsize::from_usize(0))
        .unwrap()
        .group()
        .encoded_pubkey();

    // verify a signature
    let pubkey = k256::AffinePoint::from_encoded_point(
        &k256::EncodedPoint::from_bytes(pubkey_bytes).unwrap(),
    )
    .unwrap();
    let sig = k256::ecdsa::Signature::from_der(signatures.get(TypedUsize::from_usize(0)).unwrap())
        .unwrap();
    assert!(pubkey
        .verify_prehashed(&k256::Scalar::from(&msg_to_sign), &sig)
        .is_ok());
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
        pub fn new(share_count: usize) -> (Self, Vec<Receiver<T>>) {
            // can't build two vecs from one iterator
            // so we need to do it the old-fashioned way
            let mut senders = Vec::with_capacity(share_count);
            let mut receivers = Vec::with_capacity(share_count);
            for _ in 0..share_count {
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

fn set_up_logs() {
    // set up environment variable for log level
    // set up an event subscriber for logs
    let _ = tracing_subscriber::fmt()
        // .with_env_filter("tofnd=info,[Keygen]=info")
        .with_max_level(tracing::Level::DEBUG)
        // .json()
        // .with_ansi(atty::is(atty::Stream::Stdout))
        // .without_time()
        // .with_target(false)
        // .with_current_span(false)
        .try_init();
}
