use crate::{
    collections::TypedUsize,
    crypto_tools::{k256_serde, rng},
    multisig,
    sdk::{
        api::TofnResult,
        implementer_api::{serialize, ProtocolBuilder, RoundBuilder},
    },
};
use ecdsa::elliptic_curve::Field;
use serde::{Deserialize, Serialize};

use super::{r2, KeygenPartyShareCounts, KeygenProtocolBuilder, KeygenShareId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    pub(super) verifying_key: k256_serde::ProjectivePoint,
}

pub fn start(
    my_keygen_id: TypedUsize<KeygenShareId>,
    threshold: usize,
    party_share_counts: KeygenPartyShareCounts,
    secret_recovery_key: &rng::SecretRecoveryKey,
    session_nonce: &[u8],
) -> TofnResult<KeygenProtocolBuilder> {
    let rng = rng::rng_seed(
        multisig::KEYGEN_TAG,
        my_keygen_id,
        secret_recovery_key,
        session_nonce,
    )?;

    let signing_key = k256::Scalar::random(rng);
    let verifying_key = k256::ProjectivePoint::generator() * signing_key;

    let bcast_out = Some(serialize(&Bcast {
        verifying_key: verifying_key.into(),
    })?);

    Ok(ProtocolBuilder::NotDone(RoundBuilder::new(
        Box::new(r2::R2 {
            threshold,
            party_share_counts,
            signing_key,
        }),
        bcast_out,
        None,
    )))
}
