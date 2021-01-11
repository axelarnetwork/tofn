use super::*;
use crate::protocol::tests::execute_protocol_vec;

pub const SHARE_COUNT: usize = 5;
pub const THRESHOLD: usize = 3;

#[test]
fn keygen() {
    let ids: Vec<String> = (0..SHARE_COUNT).map(|i| i.to_string()).collect();
    let mut protocols_vec: Vec<Protocol<FinalOutput>> = ids
        .iter()
        .enumerate()
        .map(|(i, _)| new_protocol(&ids, i, THRESHOLD))
        .collect();
    execute_protocol_vec(&mut protocols_vec);

    // TODO execute_protocol_map won't compile
    // let mut protocols: HashMap<ID,Protocol<ID>> = ids.iter().enumerate()
    //     .map(|(i,id)| (id.clone(), new_protocol(&ids, i, threshold))).collect();
    // execute_protocol_map(&mut protocols);
}

pub mod mock; // abandoned
