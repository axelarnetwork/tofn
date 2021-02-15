use super::EcdsaSig;
use curv::{
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
/// Experimenting with k256 crate
// use k256::{
//     ecdsa::{
//         signature::{DigestSigner, Signer},
//         Signature, SigningKey,
//     },
//     FieldBytes, PublicKey, SecretKey,
// };
use k256::{
    ecdsa::{
        // recoverable::Signature,
        signature::{DigestSigner, RandomizedDigestSigner, Signer},
        Signature,
        SigningKey,
    },
    FieldBytes, SecretKey,
};
// use k256::ecdsa::Signature;

#[test]
fn k256() -> Result<(), Box<(dyn std::error::Error + Send + Sync + 'static)>> {
    // make a signature using curv
    let msg: [u8; 1] = [42];
    let msg = &msg[..];
    let msg_fe: FE = ECScalar::from(&BigInt::from(msg));
    let sk = FE::new_random();
    let pk = GE::generator() * sk;
    let k = FE::new_random();
    let randomizer = GE::generator() * k.invert();
    let r: FE = ECScalar::from(&randomizer.x_coor().unwrap().mod_floor(&FE::q()));
    let s = k * (msg_fe + sk * r);
    let sig = EcdsaSig { r, s };
    assert!(sig.verify(&pk, &msg_fe));

    // import the signature using k256 and check round-trip
    let (r, s) = (&sig.r.to_big_int(), &sig.s.to_big_int());
    let (r_old, s_old) = (r.clone(), s.clone());
    let (r, s): (Vec<u8>, Vec<u8>) = (r.into(), s.into());
    let (r, s): (&[u8], &[u8]) = (&r, &s);
    let (r, s): (FieldBytes, FieldBytes) = (*FieldBytes::from_slice(r), *FieldBytes::from_slice(s));
    let ksig = Signature::from_scalars(r, s)?;
    let der_sig = ksig.to_asn1();
    let der_bytes = der_sig.as_bytes();
    println!("serialized sig: {:?}", der_bytes);
    let (r, s) = (ksig.r(), ksig.s());
    let (r, s): (FieldBytes, FieldBytes) = (From::from(r), From::from(s));
    let (r, s) = (r.as_slice(), s.as_slice());
    let (r, s): (BigInt, BigInt) = (BigInt::from(r), BigInt::from(s));
    assert_eq!(r, r_old);
    assert_eq!(s, s_old);

    // recreate the curv sig using k256
    let sk = &sk.to_big_int();
    let sk_old = sk.clone();
    let sk: Vec<u8> = sk.into();
    let sk = SigningKey::from_bytes(&sk)?;
    // TODO how to get k256 to use my k nonce?
    // TODO how to get k256 to convert msg bytes into a digest?
    // let sig: Signature = sk.sign_digest_with_rng(rng, digest);

    Ok(())
}
