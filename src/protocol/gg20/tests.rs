pub mod keygen {
    use crate::protocol::{
        gg20::keygen::Keygen,
        tests::{execute_protocol_vec, execute_protocol_vec_stall},
        Protocol,
    };

    lazy_static::lazy_static! {
        pub static ref TEST_CASES: Vec<(usize,usize)> // (share_count, threshold)
        // = vec![(5,3)];
        = vec![(5, 0), (5, 1), (5, 3), (5, 4)];
        pub static ref TEST_CASES_INVALID: Vec<(usize,usize)> = vec![(5, 5), (5, 6), (2, 4)];
    }
    use tracing_test::traced_test; // enable logs in tests

    #[test]
    #[traced_test]
    fn protocol_basic_correctness() {
        for &(share_count, threshold) in TEST_CASES.iter() {
            // keep it on the stack: avoid use of Box<dyn Protocol> https://doc.rust-lang.org/book/ch17-02-trait-objects.html
            let mut parties: Vec<Keygen> = (0..share_count)
                .map(|i| Keygen::new(share_count, threshold, i).unwrap())
                .collect();
            let mut protocols: Vec<&mut dyn Protocol> =
                parties.iter_mut().map(|p| p as &mut dyn Protocol).collect();
            execute_protocol_vec(&mut protocols);

            // TEST: everyone computed the same pubkey
            let key_share = parties[0].clone_output().unwrap().unwrap();
            for p in parties.iter() {
                let cur_key = p.clone_output().unwrap().unwrap();
                assert_eq!(cur_key.ecdsa_public_key, key_share.ecdsa_public_key);
            }
        }

        for (i, &(share_count, threshold)) in TEST_CASES_INVALID.iter().enumerate() {
            assert!(Keygen::new(share_count, threshold, i).is_err());
        }
    }
}

pub mod sign {
    use crate::protocol::{
        gg20::{keygen::tests::execute_keygen, sign::Sign},
        tests::execute_protocol_vec,
        Protocol,
    };
    use tracing_test::traced_test; // enable logs in tests

    lazy_static::lazy_static! {
        pub static ref MSG_TO_SIGN: Vec<u8> = vec![42];
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
                .map(|i| Sign::new(&key_shares[*i], &participant_indices, &MSG_TO_SIGN).unwrap())
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
