mod api;
pub use api::*;

mod r1;
mod r2;
mod r3;
mod r4;
mod r5;
mod r6;
mod r7;
mod r8;

mod type5_common;

#[cfg(test)]
mod tests;

#[cfg(feature = "malicious")]
pub mod malicious;
