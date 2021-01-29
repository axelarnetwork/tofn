use super::*;
use crate::protocol::tests::{execute_protocol_vec, TEST_CASES, TEST_CASES_INVALID};

#[test]
fn keygen() {
    for &(share_count, threshold) in TEST_CASES.iter() {
        // keep it on the stack: avoid use of Box<dyn Protocol> https://doc.rust-lang.org/book/ch17-02-trait-objects.html
        let mut keygen_protocols: Vec<Keygen> = (0..share_count)
            .map(|i| Keygen::new(share_count, threshold, i))
            .collect();
        let mut protocols: Vec<&mut dyn Protocol> = keygen_protocols
            .iter_mut()
            .map(|p| p as &mut dyn Protocol)
            .collect();
        execute_protocol_vec(&mut protocols);
    }

    // silence terminal output from catch_unwind https://stackoverflow.com/questions/35559267/suppress-panic-output-in-rust-when-using-paniccatch-unwind/35559417#35559417
    std::panic::set_hook(Box::new(|_| {}));

    for (i, &(share_count, threshold)) in TEST_CASES_INVALID.iter().enumerate() {
        assert!(std::panic::catch_unwind(|| Keygen::new(share_count, threshold, i)).is_err());
    }
}
