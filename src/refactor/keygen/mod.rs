// TODO: Rust 2018 doesn't allow importing a macro from another module
// in the same crate without a crate level export.
#[macro_export]
macro_rules! corrupt {
    ($sym:ident, $e:expr) => {
        #[cfg(feature = "malicious")]
        let $sym = $e;
    };
}

mod api;
pub use api::*;
mod secret_key_share;
pub use secret_key_share::*;

mod r1;
mod r2;
mod r3;
mod r4;
mod rng;

#[cfg(test)]
pub(super) mod tests; // pub(super) so that sign module can see tests::execute_keygen

#[cfg(feature = "malicious")]
pub mod malicious;
