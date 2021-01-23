use super::*;
use crate::protocol::tests::{execute_protocol_vec, TEST_CASES};

#[test]
fn keygen() {
    for &(share_count, threshold) in TEST_CASES.iter() {
        // keep it on the stack: avoid use of Box<dyn Protocol> https://doc.rust-lang.org/book/ch17-02-trait-objects.html
        let mut keygen_protocols: Vec<KeygenProtocol> = (0..share_count)
            .map(|i| KeygenProtocol::new(share_count, threshold, i))
            .collect();
        let mut protocols: Vec<&mut dyn Protocol2> = keygen_protocols
            .iter_mut()
            .map(|p| p as &mut dyn Protocol2)
            .collect();
        execute_protocol_vec(&mut protocols);
    }
}
