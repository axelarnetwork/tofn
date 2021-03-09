use curv::{
    cryptographic_primitives::commitments::{hash_commitment::HashCommitment, traits::Commitment},
    elliptic::curves::traits::{ECPoint, ECScalar},
    BigInt, FE, GE,
};
use paillier::{DecryptionKey, EncryptionKey};
use paillier::{KeyGeneration, Paillier};
use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::NICorrectKeyProof;

use super::{Keygen, Status};
use crate::zkp::Zkp;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bcast {
    pub commit: BigInt,
    pub ek: EncryptionKey, // homomorphic encryption (Paillier)
    pub zkp: Zkp,          // TODO need a better name
    pub correct_key_proof: NICorrectKeyProof,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct State {
    pub(super) my_ecdsa_secret_summand: FE, // final ecdsa secret key is the sum over all parties
    pub(super) my_ecdsa_public_summand: GE, // final ecdsa public key is the sum over all parties
    pub(super) my_dk: DecryptionKey,        // homomorphic decryption (Paillier)
    pub(super) my_ek: EncryptionKey,        // a copy of Bcast.ek
    pub(super) zkp: Zkp,
    pub(super) my_commit: BigInt, // a copy of Bcast.commit
    pub(super) my_reveal: BigInt, // decommit---to be released later
}

impl Keygen {
    // immutable &self: do not modify existing self state, only add more
    pub(super) fn r1(&self) -> (State, Bcast) {
        assert!(matches!(self.status, Status::New));
        let my_ecdsa_secret_summand = FE::new_random();
        let my_ecdsa_public_summand = GE::generator() * my_ecdsa_secret_summand;

        // TODO use safe primes in production
        // let (ek, dk) = Paillier::keypair_safe_primes().keys();
        let (ek, my_dk) = Paillier::keypair().keys();

        let correct_key_proof = NICorrectKeyProof::proof(&my_dk);
        let zkp = Zkp::new_unsafe();
        let (commit, my_reveal) = HashCommitment::create_commitment(
            &my_ecdsa_public_summand.bytes_compressed_to_big_int(),
        );
        (
            State {
                my_ecdsa_secret_summand,
                my_dk,
                my_ek: ek.clone(),
                zkp: zkp.clone(),
                my_commit: commit.clone(),
                my_reveal,
                my_ecdsa_public_summand,
            },
            Bcast {
                commit,
                ek,
                zkp,
                correct_key_proof,
            },
        )
    }
}
