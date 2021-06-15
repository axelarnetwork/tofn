use super::{tests_k256::*, *};

#[test]
fn basic_correctness() {
    let (share_count, threshold) = (3, 1);
    let KeySharesWithRecovery {
        shares,
        secret_recovery_keys,
        session_nonce,
    } = execute_keygen_with_recovery(share_count, threshold);
    let recovery_infos: Vec<KeyShareRecoveryInfo> =
        shares.iter().map(|s| s.recovery_info()).collect();
    let recovered_shares: Vec<SecretKeyShare> = secret_recovery_keys
        .iter()
        .map(|r| SecretKeyShare::recover(r, &session_nonce, &recovery_infos, threshold).unwrap())
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
        assert_eq!(s.group.y_k256, r.group.y_k256, "party {}", i);
    }
}
