//! Standard DEX header/map/fixed-reference validation over caller-owned bytes.
//! This is a bounded M1 reader, not an ART verifier or complete facts builder.

pub mod checked_reader;
pub mod header;
pub mod strings;
pub mod types;
pub mod definitions;
pub mod instructions;

pub use header::{DexHeader, DexRange, MapItem, TableInfo, validate_header};
