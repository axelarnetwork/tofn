use rand::prelude::SliceRandom;

use super::{tests_k256::*, *};

#[test]
fn basic_correctness() {
    use rand::RngCore;

    let (share_count, threshold) = (7, 4);
    let mut secret_recovery_keys = vec![[0u8; 64]; share_count];

    // repeat some secret_recovery_keys:
    // fill secret_recovery_keys with random data, copying each entry once
    // eg: [r1, r1, r2, r2, r3, r3, r4]
    // use `while let` instead of `for` so as to enable use of iterator inside loop: https://stackoverflow.com/a/59045627
    let mut iter_mut = secret_recovery_keys.iter_mut();
    while let Some(s) = iter_mut.next() {
        rand::thread_rng().fill_bytes(s);
        if let Some(t) = iter_mut.next() {
            *t = *s;
        }
    }
    let session_nonce = b"foobar";
    let shares = execute_keygen_from_recovery(threshold, &secret_recovery_keys, session_nonce);

    let recovery_infos = {
        let mut recovery_infos: Vec<_> = shares.iter().map(|s| s.recovery_info()).collect();
        recovery_infos.shuffle(&mut rand::thread_rng()); // simulate nondeterministic message receipt
        recovery_infos
    };
    let recovered_shares: Vec<SecretKeyShare> = secret_recovery_keys
        .iter()
        .enumerate()
        .map(|(i, r)| {
            SecretKeyShare::recover(r, session_nonce, &recovery_infos, i, threshold).unwrap()
        })
        .collect();

    assert_eq!(
        recovered_shares, shares,
        "comment-out this assert and use the following code to narrow down the discrepancy"
    );

    for (i, (s, r)) in shares.iter().zip(recovered_shares.iter()).enumerate() {
        assert_eq!(s.share, r.share, "party {}", i);
        for (j, (ss, rr)) in s
            .group
            .all_shares
            .iter()
            .zip(r.group.all_shares.iter())
            .enumerate()
        {
            assert_eq!(ss.X_i, rr.X_i, "party {} public info on party {}", i, j);
            assert_eq!(ss.ek, rr.ek, "party {} public info on party {}", i, j);
            assert_eq!(ss.zkp, rr.zkp, "party {} public info on party {}", i, j);
        }
        assert_eq!(s.group.threshold, r.group.threshold, "party {}", i);
        assert_eq!(s.group.y, r.group.y, "party {}", i);
    }
}
