#![deny(missing_docs)]
//! Crate for examples for the covenants in Bitcoin script.

use hex;
use once_cell::sync::Lazy;

/// The "Nothing Up My Sleeve" (NUMS) point.
pub static SECP256K1_GENERATOR: Lazy<Vec<u8>> = Lazy::new(|| {
    hex::decode("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap()
});

pub(crate) mod treepp {
    pub use bitcoin_script::{define_pushable, script};

    define_pushable!();

    pub use bitcoin::ScriptBuf as Script;
}

/// The counter example.
pub mod counter;
