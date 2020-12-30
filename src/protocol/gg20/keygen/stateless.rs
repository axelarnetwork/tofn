pub mod r1;
pub mod r2;
pub mod r3;
pub mod r4;


use std::{
    fmt::Debug,
    collections::HashMap,
};
use serde::{Deserialize, Serialize};
use curv::{
    BigInt, FE, GE,
    cryptographic_primitives::{
        proofs::sigma_dlog::{DLogProof},
    },
};
use paillier::{EncryptionKey, DecryptionKey};
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

#[derive(Clone, Debug, Serialize, Deserialize)]
// #[derive(Debug)]
pub struct R1Bcast {
    commit: BigInt,
    ek: EncryptionKey,
    zkp: Zkp,
    correct_key_proof: NICorrectKeyProof,
}
#[derive(Debug)] // do not derive Clone, Serialize, Deserialize
pub struct R1State {
    // secrets
    u: FE,
    dk: DecryptionKey,
    // decommit - to be released later
    reveal: BigInt,
    y: GE,

    msg_out: R1Bcast,
}

// round 2

#[derive(Debug)]
pub struct R2Input<ID>
    // where ID: Eq + Hash + Ord // TODO how best to avoid repeating this where clause?
{
    pub threshold: usize,
    pub other_r1_bcasts: HashMap<ID, R1Bcast>,
    pub my_uid: ID,
}
#[derive(Debug)]
pub struct R2Output<ID>
{
    pub broadcast: R2Bcast,
    pub p2p: HashMap<ID, R2P2p>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct R2Bcast {
    pub y: GE, // TODO redundant: equals my_vss_commitments[0]
    pub my_reveal: BigInt,
    pub my_vss_commitments: Vec<GE>,
    // pub my_vss_scheme: VerifiableSS,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct R2P2p {
    pub secret_share: FE,
}

#[derive(Debug)]
pub struct R2State<ID> {
    // u: FE,
    y: GE, // TODO redundant
    dk: DecryptionKey,
    my_share_of_u: FE,
    my_vss_index: usize,
    // others: HashMap<ID, (R1Bcast, usize)>, // (msg, share_index)
    others: HashMap<ID, R1Bcast>,
    threshold: usize,
}

// round 3

#[derive(Debug)]
pub struct R3Input<ID> {
    pub other_r2_msgs: HashMap<ID, (R2Bcast, R2P2p)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct R3Bcast {
    dlog_proof: DLogProof,
}
#[derive(Debug)]
pub struct R3State {
    my_vss_index: usize,
    public_key: GE,
    my_secret_key_share: FE,
}

// round 4

#[derive(Debug)]
pub struct R4Input<ID> {
    pub other_r3_bcasts: HashMap<ID, R3Bcast>,
}

#[derive(Debug)]
pub struct R4State {
    my_vss_index: usize,
    public_key: GE,
    my_secret_key_share: FE,
}

#[cfg(test)]
mod tests;