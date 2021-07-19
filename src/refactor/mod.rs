pub mod collections;
pub mod keygen;
pub mod sdk;
pub mod sign;

// TODO: Rust 2018 doesn't allow importing a macro from another module
// in the same crate without a crate level export.
#[macro_export]
macro_rules! corrupt {
    ($sym:ident, $e:expr) => {
        #[cfg(feature = "malicious")]
        let $sym = $e;
    };
}
