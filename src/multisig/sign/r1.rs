use crate::{
    collections::TypedUsize,
    crypto_tools::k256_serde,
    multisig::{keygen::SecretKeyShare, sign::digest::DigestWrapper},
    sdk::{
        api::{TofnFatal, TofnResult},
        implementer_api::{serialize, RoundBuilder},
    },
};
use ecdsa::{elliptic_curve::Field, hazmat::DigestPrimitive, signature::DigestSigner};
use k256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    Scalar,
};
use serde::{Deserialize, Serialize};

use super::{KeygenShareIds, MessageDigest, SignProtocolBuilder, SignShareId};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    pub(super) signature: k256_serde::Signature,
}

// #[allow(non_snake_case)]
pub(super) fn start(
    my_sign_id: TypedUsize<SignShareId>,
    secret_key_share: SecretKeyShare,
    msg_to_sign: &MessageDigest,
    // msg_to_sign: k256::ecdsa::digest::Output,
    // msg_to_sign: <k256::Secp256k1 as DigestPrimitive>::Digest,
    all_keygen_ids: KeygenShareIds,
) -> TofnResult<SignProtocolBuilder> {
    // let msg_to_sign = b"foobar";
    // let msg_to_sign;
    let digest = DigestWrapper::from(msg_to_sign);
    let signature: Signature = secret_key_share
        .share()
        .signing_key()
        .as_ref()
        // .sign(msg_to_sign);
        .sign_digest(digest);
    // .map_err(|_| TofnFatal)?
    // .into();

    let bcast_out = Some(serialize(&Bcast {
        signature: signature.into(),
    })?);

    // Ok(SignProtocolBuilder::NotDone(RoundBuilder::new(
    //     Box::new(r2::R2 {
    //         secret_key_share,
    //         msg_to_sign,
    //         peer_keygen_ids,
    //         all_keygen_ids,
    //         my_keygen_id,
    //         gamma_i,
    //         Gamma_i,
    //         Gamma_i_reveal,
    //         w_i,
    //         k_i,
    //         k_i_randomness,

    //         #[cfg(feature = "malicious")]
    //         behaviour,
    //     }),
    //     bcast_out,
    //     p2ps_out,
    // )))
    todo!()
}
