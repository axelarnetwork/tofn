pub mod keygen {
    use rand::RngCore;
    use tofn::{
        refactor::collections::{TypedUsize, VecMap},
        refactor::{
            keygen::{
                new_keygen, KeygenPartyIndex, KeygenProtocol, RealKeygenPartyIndex,
                SecretRecoveryKey,
            },
            sdk::api::PartyShareCounts,
        },
    };

    #[cfg(feature = "malicious")]
    use tofn::refactor::keygen::malicious::Behaviour;

    pub fn initialize_honest_parties(
        party_share_counts: &PartyShareCounts<RealKeygenPartyIndex>,
        threshold: usize,
    ) -> VecMap<KeygenPartyIndex, KeygenProtocol> {
        let session_nonce = b"foobar";

        party_share_counts
            .iter()
            .map(|(party_id, &party_share_count)| {
                // each party use the same secret recovery key for all its subshares
                let mut secret_recovery_key = [0u8; 64];
                rand::thread_rng().fill_bytes(&mut secret_recovery_key);

                (0..party_share_count).map(move |subshare_id| {
                    new_keygen(
                        party_share_counts.clone(),
                        threshold,
                        party_id,
                        subshare_id,
                        &secret_recovery_key,
                        session_nonce,
                        #[cfg(feature = "malicious")]
                        Behaviour::Honest,
                    )
                    .unwrap()
                })
            })
            .flatten()
            .collect()
    }

    /// return the all-zero array with the first bytes set to the bytes of `index`
    pub fn dummy_secret_recovery_key<K>(index: TypedUsize<K>) -> SecretRecoveryKey {
        let index_bytes = index.as_usize().to_be_bytes();
        let mut result = [0; 64];
        for (i, &b) in index_bytes.iter().enumerate() {
            result[i] = b;
        }
        result
    }
}
