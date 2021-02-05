use super::Keygen;
use crate::protocol::{tests::execute_protocol_vec, Protocol};

lazy_static::lazy_static! {
    pub static ref TEST_CASES: Vec<(usize,usize)> // (share_count, threshold)
    = vec![(5,3)];
    // = vec![(5, 0), (5, 1), (5, 3), (5, 4), (20,10)];
    pub static ref TEST_CASES_INVALID: Vec<(usize,usize)> = vec![(5, 5), (5, 6), (2, 4)];
}

#[test]
fn keygen() {
    for &(share_count, threshold) in TEST_CASES.iter() {
        // keep it on the stack: avoid use of Box<dyn Protocol> https://doc.rust-lang.org/book/ch17-02-trait-objects.html
        let mut keygen_protocols: Vec<Keygen> = (0..share_count)
            .map(|i| Keygen::new(share_count, threshold, i).unwrap())
            .collect();
        let mut protocols: Vec<&mut dyn Protocol> = keygen_protocols
            .iter_mut()
            .map(|p| p as &mut dyn Protocol)
            .collect();
        execute_protocol_vec(&mut protocols);
    }

    for (i, &(share_count, threshold)) in TEST_CASES_INVALID.iter().enumerate() {
        assert!(Keygen::new(share_count, threshold, i).is_err());
    }
}
