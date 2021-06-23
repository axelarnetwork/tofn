use super::protocol::*;

pub fn execute_protocol_vec<F>(parties: &[RoundWaiter<F>]) -> Vec<F> {
    // while nobody_done(parties) {
    //     let parties: Vec<RoundWaiter<F>> = parties.iter().map(|p| p.execute_next_round()).collect();
    // }
    // TODO if somebody's not done then we can't get a `F` from him!  Maybe just return `F` instead of `Vec<F>`??
    todo!()
}

fn nobody_done<F>(parties: &[RoundWaiter<F>]) -> bool {
    parties.iter().all(|p| p.expecting_more_msgs_this_round())
}
