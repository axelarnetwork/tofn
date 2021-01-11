pub mod r1;
pub mod r2;
pub mod r3;
pub mod r4;

use curv::{cryptographic_primitives::proofs::sigma_dlog::DLogProof, BigInt, FE, GE};
use paillier::{DecryptionKey, EncryptionKey};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Debug};
use zk_paillier::zkproofs::NICorrectKeyProof;

use super::super::zkp::Zkp;

// TODO explain: why not use Vec and let party ids be implicit 0..vec.len?
// Because each party would have awkward book keeping, and the user of these stateless functions would need to put messages in sorted order
// So instead we use HashMap and let IDs be generic
// We need ID to be Ord because we need a way to map each ID to a unique ECScalar for evaluation in VSS polynomials
// The easiest way to do that is to sort all the IDs and assign scalars 1..n to the sorted list
// It would be nice if each party's VSS scalar were independent of other party's IDs
// One way to achieve this is to hash each ID into a ECScalar
// but that requires IDs to be hashable and it requires a hash-to-ECScalar implementation

// TODO 2020/540 calls for the Paillier zk proofs only at the end in round 4
// By contrast, most implementations do it much earlier
// I presume 2020/540 suggest to do it later to avoid unneccessary work in the event of a fault
// Perhaps we should do that

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
    my_ecdsa_secret_summand: FE, // final ecdsa secret key is the sum over all parties
    my_ecdsa_public_summand: GE, // final ecdsa public key is the sum over all parties
    my_dk: DecryptionKey,        // homomorphic decryption (Paillier)
    my_reveal: BigInt,           // decommit---to be released later
    my_output: R1Bcast,
}

// round 2

#[derive(Debug, Clone)]
pub struct R2Input {
    pub threshold: usize,
    pub other_r1_bcasts: HashMap<String, R1Bcast>,
    pub my_uid: String,
}
#[derive(Debug, Clone)]
pub struct R2Output {
    pub bcast: R2Bcast,
    pub p2p: HashMap<String, R2P2p>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct R2Bcast {
    pub reveal: BigInt,
    pub secret_share_commitments: Vec<GE>,
}

impl R2Bcast {
    // helper getters
    pub fn get_ecdsa_public_summand(&self) -> GE {
        self.secret_share_commitments[0]
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct R2P2p {
    pub ecdsa_secret_summand_share: FE, // threshold share of my_ecdsa_secret_summand
}

#[derive(Debug)]
pub struct R2State {
    my_share_of_my_ecdsa_secret_summand: FE,
    my_share_index: usize,
    my_r1_state: R1State,
    input: R2Input,
    my_output: R2Output,
}

impl R2State {
    // helper getters
    fn get_ecdsa_public_summand(&self) -> GE {
        self.my_output.bcast.get_ecdsa_public_summand()
    }
}

// round 3

#[derive(Debug, Clone)]
pub struct R3Input {
    pub other_r2_msgs: HashMap<String, (R2Bcast, R2P2p)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct R3Bcast {
    dlog_proof: DLogProof,
}
#[derive(Debug)]
pub struct R3State {
    // my_vss_index: usize, // delete me
    ecdsa_public_key: GE,          // the final pub key
    my_ecdsa_secret_key_share: FE, // my final secret key share
    my_r2_state: R2State,
    input: R3Input,
    my_output: R3Bcast,
}

// round 4

#[derive(Debug)]
pub struct R4Input {
    pub other_r3_bcasts: HashMap<String, R3Bcast>,
}

// FinalOutput discards unneeded intermediate info from the protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalOutput {
    ecdsa_public_key: GE,
    my_share_index: usize,
    my_ecdsa_secret_key_share: FE,
}

#[cfg(test)]
mod tests;
