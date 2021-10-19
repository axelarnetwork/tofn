use crate::{
    collections::TypedUsize,
    crypto_tools::{k256_serde, rng},
    multisig::{self, keygen::SecretKeyShare},
    sdk::{
        api::{TofnFatal, TofnResult},
        implementer_api::{serialize, RoundBuilder},
    },
};
use ecdsa::{elliptic_curve::Field, hazmat::SignPrimitive};
use serde::{Deserialize, Serialize};

use super::{r2, KeygenShareIds, MessageDigest, SignProtocolBuilder, SignShareId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    pub(super) signature: k256_serde::Signature,
}

pub(super) fn start(
    my_sign_id: TypedUsize<SignShareId>,
    secret_key_share: SecretKeyShare,
    msg_to_sign: &MessageDigest,
    all_keygen_ids: KeygenShareIds,
) -> TofnResult<SignProtocolBuilder> {
    let msg_to_sign = k256::Scalar::from(msg_to_sign);
    let signing_key = secret_key_share.share().signing_key().as_ref();

    let rng = rng::rng_seed_ecdsa_ephemeral_scalar_with_party_id(
        multisig::SIGN_TAG,
        my_sign_id,
        signing_key,
        &msg_to_sign,
    )?;
    let ephemeral_scalar = k256::Scalar::random(rng);

    let signature = signing_key
        .try_sign_prehashed(&ephemeral_scalar, &msg_to_sign)
        .map_err(|_| TofnFatal)?;

    let bcast_out = Some(serialize(&Bcast {
        signature: signature.into(),
    })?);

    Ok(SignProtocolBuilder::NotDone(RoundBuilder::new(
        Box::new(r2::R2 {
            secret_key_share,
            msg_to_sign,
            all_keygen_ids,
        }),
        bcast_out,
        None,
    )))
}
