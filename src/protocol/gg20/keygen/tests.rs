use super::*;
use crate::protocol::tests::{execute_protocol_vec, TEST_CASES};

#[test]
fn keygen() {
    for test_case in &TEST_CASES {
        let ids: Vec<String> = (0..test_case.0).map(|i| i.to_string()).collect();
        let mut protocols_vec: Vec<Protocol<FinalOutput>> = ids
            .iter()
            .enumerate()
            .map(|(i, _)| new_protocol(&ids, i, test_case.1))
            .collect();
        execute_protocol_vec(&mut protocols_vec);
    }
}

pub mod mock; // abandoned
