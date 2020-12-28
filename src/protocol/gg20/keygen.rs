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

use super::zkp::Zkp;

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
    threshold: usize,
    other_r1_bcasts: HashMap<ID, R1Bcast>,
    my_uid: ID,
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
    other_r2_msgs: HashMap<ID, (R2Bcast, R2P2p)>,
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
    other_r3_bcasts: HashMap<ID, R3Bcast>,
}

#[derive(Debug)]
pub struct R4State {
    my_vss_index: usize,
    public_key: GE,
    my_secret_key_share: FE,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{hash::Hash};
    use curv::{
        // FE, // rustc does not warn of unused imports for FE
        cryptographic_primitives::{
            secret_sharing::feldman_vss::{VerifiableSS, ShamirSecretSharing},
        },
        elliptic::curves::traits::{ECScalar},
    };

    const SHARE_COUNT: usize = 5;
    const THRESHOLD: usize = 3;

    #[test]
    fn stateless_keygen_usize_ids() {
        // party ids: 0,...,n 
        stateless_keygen::<usize>((0..SHARE_COUNT).collect(), THRESHOLD);
    }

    #[test]
    fn stateless_keygen_string_ids() {
        // party ids: "0",...,"n" 
        stateless_keygen::<String>((0..SHARE_COUNT).map(|i| i.to_string()).collect(), THRESHOLD);
    }

    fn stateless_keygen<ID>(ids: Vec<ID>, threshold: usize)
        where ID: Eq + Hash + Ord + Clone + Debug
    {
        let share_count = ids.len();
        assert!(threshold < share_count);

        // execute round 1 all parties and store their outputs
        let mut all_r1_bcasts = HashMap::with_capacity(share_count);
        let mut all_r1_states = HashMap::with_capacity(share_count);
        for id in ids.iter() {
            let (state, msg) = r1::start();
            all_r1_bcasts.insert(id.clone(), msg);
            all_r1_states.insert(id, state);
        }
        let all_r1_bcasts = all_r1_bcasts; // make read-only

        // save each u for later tests
        let all_u_secrets : Vec<FE> = all_r1_states.values().map(|v| v.u).collect();

        // execute round 2 all parties and store their outputs
        let mut all_r2_states = HashMap::with_capacity(share_count);
        let mut all_r2_bcasts = HashMap::with_capacity(share_count);
        let mut all_r2_p2ps = HashMap::with_capacity(share_count);
        for id in ids.iter() {
            let mut other_r1_bcasts = all_r1_bcasts.clone();
            other_r1_bcasts.remove(id).unwrap();
            let my_r1_state = all_r1_states.remove(id).unwrap();
            let input = R2Input {
                my_uid: id.clone(),
                other_r1_bcasts,
                threshold,
            };
            let (state, msg) = r2::execute::<ID>(my_r1_state, input);
            all_r2_states.insert(id, state);
            all_r2_bcasts.insert(id.clone(), msg.broadcast);
            all_r2_p2ps.insert(id, msg.p2p);
        }
        let all_r2_bcasts = all_r2_bcasts; // make read-only
        let all_r2_p2ps = all_r2_p2ps; // make read-only

        // route p2p msgs and build round 3 inputs
        let all_r3_inputs = ids.iter().map(|id| {
            let mut other_r2_bcasts = all_r2_bcasts.clone();
            other_r2_bcasts.remove(id).unwrap();
            (
                id,
                R3Input {
                    other_r2_msgs: all_r2_p2ps.iter()
                    .filter(|(k,_)| **k != id)
                    .map(|(k,v)| {
                        (
                            (*k).clone(),
                            ( other_r2_bcasts.remove(*k).unwrap(), v.get(id).unwrap().clone() )
                        )
                    }).collect::<HashMap<_,_>>()
                }
            )
        }).collect::<HashMap<_,_>>();

        // execute round 3 all parties and store their outputs
        let mut all_r3_states = HashMap::with_capacity(share_count);
        let mut all_r3_bcasts = HashMap::with_capacity(share_count);
        for (id, input) in all_r3_inputs {
            let my_r2_state = all_r2_states.remove(id).unwrap();
            let (state,msg) = r3::execute::<ID>(my_r2_state, input);
            all_r3_states.insert(id, state);
            all_r3_bcasts.insert(id.clone(), msg);
        }
        let all_r3_bcasts = all_r3_bcasts; // make read-only

        // execute round 4 all parties and store their outputs
        let mut all_r4_states = HashMap::with_capacity(share_count);
        for id in ids.iter() {
            let mut other_r3_bcasts = all_r3_bcasts.clone();
            other_r3_bcasts.remove(id).unwrap();
            let my_r3_state = all_r3_states.remove(id).unwrap();
            let input = R4Input {
                other_r3_bcasts,
            };
            let result = r4::execute::<ID>(my_r3_state, input);
            all_r4_states.insert(id, result);
        }
        let all_r4_states = all_r4_states; // make read-only

        // test: reconstruct the secret key in two ways:
        // 1. from all the u secrets of round 1
        // 2. from the first t+1 shares
        let secret_key_sum_u = all_u_secrets.iter()
            .fold(FE::zero(), |acc, x| acc + x);

        let mut all_vss_indices = Vec::<usize>::with_capacity(share_count);
        let mut all_secret_shares = Vec::<FE>::with_capacity(share_count);
        for state in all_r4_states.values() {
            all_vss_indices.push(state.my_vss_index - 1); // careful! curv library adds 1 to indices
            all_secret_shares.push(state.my_secret_key_share);
        }
        let test_vss_scheme = VerifiableSS{ // cruft: needed for curv library
            parameters: ShamirSecretSharing{
                share_count,
                threshold,
            },
            commitments: Vec::new(),
        };
        let secret_key_reconstructed = test_vss_scheme.reconstruct(
            &all_vss_indices[0..=threshold],
            &all_secret_shares[0..=threshold]
        );

        assert_eq!(secret_key_reconstructed, secret_key_sum_u);
    }
}
