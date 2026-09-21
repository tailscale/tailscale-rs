//! String formatting utilities.

mod hex;
mod iter;

pub use hex::{AsHexExt, Case as HexCase, HexIter, HexdumpIter, hex_fmt};
pub use iter::IterFmt;
