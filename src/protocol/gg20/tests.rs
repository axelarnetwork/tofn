pub mod keygen {
    use crate::protocol::{gg20::keygen::Keygen, tests::execute_protocol_vec, Protocol};

    lazy_static::lazy_static! {
        pub static ref TEST_CASES: Vec<(usize,usize)> // (share_count, threshold)
        // = vec![(5,3)];
        = vec![(5, 0), (5, 1), (5, 3), (5, 4)];
        pub static ref TEST_CASES_INVALID: Vec<(usize,usize)> = vec![(5, 5), (5, 6), (2, 4)];
    }
    use rand::RngCore;
    use tracing_test::traced_test; // enable logs in tests

    #[test]
    #[traced_test]
    fn protocol_basic_correctness() {
        for &(share_count, threshold) in TEST_CASES.iter() {
            let mut prf_secret_key = [0; 64];
            rand::thread_rng().fill_bytes(&mut prf_secret_key);

            // just for fun: keep it on the stack: avoid use of Box<dyn Protocol> https://doc.rust-lang.org/book/ch17-02-trait-objects.html
            let mut parties: Vec<Keygen> = (0..share_count)
                .map(|i| {
                    Keygen::new(share_count, threshold, i, &prf_secret_key, &i.to_be_bytes())
                        .unwrap()
                })
                .collect();
            let mut protocols: Vec<&mut dyn Protocol> =
                parties.iter_mut().map(|p| p as &mut dyn Protocol).collect();
            execute_protocol_vec(&mut protocols);

            // TEST: everyone computed the same pubkey
            let key_share = parties[0].clone_output().unwrap().unwrap();
            for p in parties.iter() {
                let cur_key = p.clone_output().unwrap().unwrap();
                assert_eq!(cur_key.group.y_k256, key_share.group.y_k256);
            }
        }

        for (i, &(share_count, threshold)) in TEST_CASES_INVALID.iter().enumerate() {
            assert!(Keygen::new(share_count, threshold, i, &[7; 64], &i.to_be_bytes()).is_err());
        }
    }
}

pub mod sign {
    use crate::protocol::{
        gg20::{keygen::tests_k256::execute_keygen, sign::Sign, MessageDigest},
        tests::execute_protocol_vec,
        Protocol,
    };
    use tracing_test::traced_test; // enable logs in tests

    pub const MSG_TO_SIGN: MessageDigest = MessageDigest([
        42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ]);

    lazy_static::lazy_static! {
        pub static ref TEST_CASES: Vec<(usize, usize, Vec<usize>)> = vec![ // (share_count, threshold, participant_indices)
            // (5, 2, vec![1,2,4]),
            (5, 2, vec![4,1,2]),
            // (5, 2, vec![0,1,2,3]),
            (5, 2, vec![4,2,3,1,0]),
            (1,0,vec![0]),
        ];
        // TODO add TEST_CASES_INVALID
    }

    #[test]
    #[traced_test]
    fn protocol_basic_correctness() {
        for (share_count, threshold, participant_indices) in TEST_CASES.iter() {
            let key_shares = execute_keygen(*share_count, *threshold);

            // keep it on the stack: avoid use of Box<dyn Protocol> https://doc.rust-lang.org/book/ch17-02-trait-objects.html
            let mut participants: Vec<Sign> = participant_indices
                .iter()
                .map(|i| {
                    Sign::new(
                        &key_shares[*i].group,
                        &key_shares[*i].share,
                        &participant_indices,
                        &MSG_TO_SIGN,
                    )
                    .unwrap()
                })
                .collect();
            let mut protocols: Vec<&mut dyn Protocol> = participants
                .iter_mut()
                .map(|p| p as &mut dyn Protocol)
                .collect();
            execute_protocol_vec(&mut protocols);

            // TEST: everyone computed the same signature
            let sig = participants[0].clone_output().unwrap().unwrap();
            for p in participants.iter() {
                let cur_sig = p.clone_output().unwrap().unwrap();
                assert_eq!(cur_sig, sig);
            }
        }
    }
}
