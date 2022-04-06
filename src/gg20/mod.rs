mod constants;

/// corrupt! should be visible only within modules [keygen], [sign]
/// Thus, we must define it here in accordance with the bizarre rules for macro visibility:
/// <https://danielkeep.github.io/tlborm/book/mbe-min-scoping.html>
macro_rules! corrupt {
    ($sym:ident, $e:expr) => {
        #[cfg(feature = "malicious")]
        let $sym = $e;
    };
}

pub mod keygen;
pub mod sign;
