use serde::{Deserialize, Serialize};

use super::type5_common::BcastSadType5;

mod happy;
pub(super) use happy::{BcastHappy, R4Happy};
mod sad;
pub(super) use sad::R4Sad;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Bcast {
    Happy(BcastHappy),
    SadType5(BcastHappy, BcastSadType5),
}
