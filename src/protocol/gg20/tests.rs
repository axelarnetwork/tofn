pub mod sign {
    use crate::protocol::{
        gg20::{
            keygen::tests::execute_keygen,
            sign::{tests::equal_sigs, Sign},
        },
        tests::execute_protocol_vec,
        Protocol,
    };

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
        pub static ref ONE_CRIMINAL_TEST_CASES: Vec<OneCrimeTestCase> = vec![
            OneCrimeTestCase{
                share_count: 5,
                threshold: 2,
                participant_indices: vec![4,1,2],
                criminal: 1,
                victim: 0,
            },
            OneCrimeTestCase{
                share_count: 7,
                threshold: 4,
                participant_indices: vec![6,4,2,0,3],
                criminal: 2,
                victim: 4,
            },
        ];
    }

    pub struct OneCrimeTestCase {
        pub share_count: usize,
        pub threshold: usize,
        pub participant_indices: Vec<usize>,
        pub criminal: usize,
        pub victim: usize,
    }

    #[test]
    fn protocol_basic_correctness() {
        protocol_basic_correctness_inner(false)
    }

    #[test]
    fn protocol_basic_correctness_with_self_delivery() {
        protocol_basic_correctness_inner(true)
    }

    fn protocol_basic_correctness_inner(allow_self_delivery: bool) {
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
            execute_protocol_vec(&mut protocols, allow_self_delivery);

            // TEST: everyone computed the same signature
            let sig = participants[0].get_result().unwrap().unwrap();
            for p in participants.iter() {
                let cur_sig = p.get_result().unwrap().unwrap();
                assert!(equal_sigs(cur_sig, sig));
            }
        }
    }
}
