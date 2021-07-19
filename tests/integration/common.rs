pub mod keygen {
    use tofn::{
        refactor::collections::{TypedUsize, VecMap},
        refactor::{
            keygen::{
                new_keygen, KeygenPartyIndex, KeygenProtocol, RealKeygenPartyIndex,
                SecretRecoveryKey,
            },
            sdk::implementer_api::PartyShareCounts,
        },
    };

    #[cfg(feature = "malicious")]
    use tofn::refactor::keygen::malicious::Behaviour;

    pub fn initialize_honest_parties(
        party_share_counts: &PartyShareCounts<RealKeygenPartyIndex>,
        threshold: usize,
    ) -> VecMap<KeygenPartyIndex, KeygenProtocol> {
        let session_nonce = b"foobar";
        (0..party_share_counts.total_share_count())
            .map(|index| {
                let index = TypedUsize::from_usize(index);
                new_keygen(
                    party_share_counts.clone(),
                    threshold,
                    index,
                    &dummy_secret_recovery_key(index),
                    session_nonce,
                    #[cfg(feature = "malicious")]
                    Behaviour::Honest,
                )
                .expect("`new_keygen` failure")
            })
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
