pub mod r1;
pub mod r2;
pub mod r3;
pub mod r4;

use curv::{cryptographic_primitives::proofs::sigma_dlog::DLogProof, BigInt, FE, GE, PK};
use paillier::{DecryptionKey, EncryptionKey};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use zk_paillier::zkproofs::NICorrectKeyProof;

use super::super::zkp::Zkp;

// TODO curv types FE, GE add a bunch of cruft on top of secp256k1 types SK=SecretKey, PK=PublicKey
// prefer SK, PK to FE, GE where possible

// TODO 2020/540 calls for the Paillier zk proofs only at the end in round 4
// By contrast, most implementations do it much earlier
// I presume 2020/540 suggest to do it later to avoid unneccessary work in the event of a fault
// Perhaps we should do that

// TODO lots of cloning from RXState to R(X+1)State
// Shall we abandon the stateless-first pattern?

// round 1

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R1Bcast {
    commit: BigInt,
    ek: EncryptionKey, // homomorphic encryption (Paillier)
    zkp: Zkp,          // TODO need a better name
    correct_key_proof: NICorrectKeyProof,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct R1State {
    pub share_count: usize,
    pub threshold: usize,
    pub my_index: usize,
    pub my_ecdsa_secret_summand: FE, // final ecdsa secret key is the sum over all parties
    pub my_ecdsa_public_summand: GE, // final ecdsa public key is the sum over all parties
    pub my_dk: DecryptionKey,        // homomorphic decryption (Paillier)
    pub my_ek: EncryptionKey,        // homomorphic encryption (Paillier)
    pub my_commit: BigInt,           // for convenience: a copy of R1Bcast.commit
    pub my_reveal: BigInt,           // decommit---to be released later
}

// round 2

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct R2Bcast {
    pub reveal: BigInt,
    pub secret_share_commitments: Vec<GE>,
}

// impl R2Bcast {
//     // helper getters
//     pub fn get_ecdsa_public_summand(&self) -> GE {
//         self.secret_share_commitments[0]
//     }
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct R2P2p {
    pub ecdsa_secret_summand_share: FE, // threshold share of my_ecdsa_secret_summand
}

#[derive(Debug)]
pub struct R2State {
    pub share_count: usize,
    pub threshold: usize,
    pub my_index: usize,
    pub my_dk: DecryptionKey,
    pub my_ek: EncryptionKey,
    pub my_share_of_my_ecdsa_secret_summand: FE,
    pub my_ecdsa_public_summand: GE, // used only to compute the final ecdsa_public_key
    pub all_commits: Vec<BigInt>,
    pub all_eks: Vec<EncryptionKey>,
}

// round 3

// #[derive(Debug, Clone)]
// pub struct R3Input {
//     pub other_r2_msgs: HashMap<String, (R2Bcast, R2P2p)>,
// }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct R3Bcast {
    dlog_proof: DLogProof,
}
#[derive(Debug)]
pub struct R3State {
    pub share_count: usize,
    pub threshold: usize,
    pub my_index: usize,
    pub my_dk: DecryptionKey,
    pub my_ek: EncryptionKey,
    pub ecdsa_public_key: GE,          // the final pub key
    pub my_ecdsa_secret_key_share: FE, // my final secret key share
    pub all_eks: Vec<EncryptionKey>,
}

// round 4

// #[derive(Debug)]
// pub struct R4Input {
//     pub other_r3_bcasts: HashMap<String, R3Bcast>,
// }

// FinalOutput discards unneeded intermediate info from the protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretKeyShare {
    pub share_count: usize,
    pub threshold: usize,
    pub my_index: usize,
    pub my_dk: DecryptionKey,
    pub my_ek: EncryptionKey,
    pub my_ecdsa_secret_key_share: FE,
    pub ecdsa_public_key: GE,
    pub all_eks: Vec<EncryptionKey>,
}

// impl SecretKeyShare {
//     pub fn get_ecdsa_public_key(&self) -> &PK {
//         &self.ecdsa_public_key
//     }
// }

#[cfg(test)]
pub mod tests; // TODO not pub
