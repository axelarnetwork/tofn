use serde::{Deserialize, Serialize};

use super::r6::BcastSadType5; // TODO reuse BcastSadType5 from r6??

mod happy;
pub(super) use happy::{BcastHappy, R4Happy};
mod sad;
pub(super) use sad::R4Sad;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Bcast {
    Happy(BcastHappy),
    SadType5(BcastSadType5),
}
