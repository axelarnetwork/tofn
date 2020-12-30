use super::*;
use crate::protocol::tests::{
    // execute_protocol_map,
    execute_protocol_vec
};

pub const SHARE_COUNT: usize = 5;
pub const THRESHOLD: usize = 3;

#[test]
fn stateful_keygen_usize_ids() {
    // party ids: 0,...,n 
    stateful_keygen::<usize>((0..SHARE_COUNT).collect(), THRESHOLD);
}

#[test]
fn stateful_keygen_string_ids() {
    // party ids: "0",...,"n" 
    stateful_keygen::<String>((0..SHARE_COUNT).map(|i| i.to_string()).collect(), THRESHOLD);
}

// TODO 'static needed due to use of Box<dyn State<ID>>
// is there a better way? can I eliminate the 'static?
fn stateful_keygen<ID: 'static>(ids: Vec<ID>, threshold: usize)
    where ID: Eq + Hash + Ord + Clone + Debug
{
    let mut protocols_vec: Vec<Protocol<ID>> = ids.iter().enumerate()
        .map(|(i,_)| new_protocol(&ids, i, threshold)).collect();
    execute_protocol_vec(&mut protocols_vec);

    // TODO execute_protocol_map won't compile
    // let mut protocols: HashMap<ID,Protocol<ID>> = ids.iter().enumerate()
    //     .map(|(i,id)| (id.clone(), new_protocol(&ids, i, threshold))).collect();
    // execute_protocol_map(&mut protocols);
    
}

pub mod mock; // abandoned
