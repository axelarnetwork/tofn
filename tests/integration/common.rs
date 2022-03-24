use std::convert::TryInto;

use tofn::{collections::TypedUsize, gg20::keygen::SecretRecoveryKey};

pub mod integration_keygen {
    use tofn::{
        collections::VecMap,
        gg20::keygen::{
            create_party_keypair_and_zksetup_unsafe, new_keygen, KeygenPartyId, KeygenProtocol,
            KeygenShareId,
        },
        sdk::api::PartyShareCounts,
    };

    #[cfg(feature = "malicious")]
    use tofn::gg20::keygen::malicious::Behaviour;

    pub fn initialize_honest_parties(
        party_share_counts: &PartyShareCounts<KeygenPartyId>,
        threshold: usize,
    ) -> VecMap<KeygenShareId, KeygenProtocol> {
        let session_nonce = b"foobar";

        party_share_counts
            .iter()
            .map(|(party_id, &party_share_count)| {
                // each party use the same secret recovery key for all its subshares
                let secret_recovery_key = super::dummy_secret_recovery_key(party_id);

                let party_keygen_data = create_party_keypair_and_zksetup_unsafe(
                    party_id,
                    &secret_recovery_key,
                    session_nonce,
                )
                .unwrap();

                (0..party_share_count).map(move |subshare_id| {
                    new_keygen(
                        party_share_counts.clone(),
                        threshold,
                        party_id,
                        subshare_id,
                        &party_keygen_data,
                        #[cfg(feature = "malicious")]
                        Behaviour::Honest,
                    )
                    .unwrap()
                })
            })
            .flatten()
            .collect()
    }
}

pub mod integration_ceygen {
    use std::ops::Mul;

    #[cfg(feature = "malicious")]
    use tofn::gg20::keygen::malicious::Behaviour;
    use tofn::{
        collections::VecMap,
        gg20::ceygen::{
            create_party_keypair_and_zksetup_unsafe, new_ceygen, Coefficients, GroupPublicInfo,
            KeygenPartyId, KeygenProtocol, KeygenShareId, SecretKeyShare, ShareSecretInfo,
        },
        sdk::api::PartyShareCounts,
    };

    pub fn initialize_honest_parties(
        party_share_counts: &PartyShareCounts<KeygenPartyId>,
        threshold: usize,
        alice_key: k256::Scalar,
    ) -> VecMap<KeygenShareId, SecretKeyShare> {
        let session_nonce = b"foobar";
        let shares =
            tofn::gg20::ceygen::Ss::new_byok(threshold, alice_key)
                .shares(party_share_counts.party_count())
                .into_iter();

        let ceygen_share_info: Vec<CeygenShareInfo> = party_share_counts
            .iter()
            .map(|(party_id, &party_share_count)| {
                // each party use the same secret recovery key for all its subshares
                let secret_recovery_key = super::dummy_secret_recovery_key(party_id);

                let party_keygen_data = create_party_keypair_and_zksetup_unsafe(
                    party_id,
                    &secret_recovery_key,
                    session_nonce,
                )
                .unwrap();

                (0..party_share_count).map(move |subshare_id| {
                    new_ceygen(
                        party_share_counts.clone(),
                        threshold,
                        party_id,
                        subshare_id,
                        shares
                            .next()
                            .expect("{party_id}, {share_id} out of range for ceygen"),
                        &party_keygen_data,
                        #[cfg(feature = "malicious")]
                        Behaviour::Honest,
                    )
                    .unwrap()
                })
            })
            .flatten()
            .collect();

        let y = k256::ProjectivePoint::generator().mul(alice_key);

        ceygen_share_info
            .into_iter()
            .map(|(share_public_info, share_secret_info)| {
                (SecretKeyShare::new(
                    GroupPublicInfo::new(party_share_counts, threshold, y, share_public_info),
                    share_secret_info,
                ))
            })
            .collect();
    }
}

/// return the all-zero array with the first bytes set to the bytes of `index`
pub fn dummy_secret_recovery_key<K>(index: TypedUsize<K>) -> SecretRecoveryKey {
    let index_bytes = index.as_usize().to_be_bytes();
    let mut result = [0; 64];
    for (i, &b) in index_bytes.iter().enumerate() {
        result[i] = b;
    }
    result[..].try_into().unwrap()
}
