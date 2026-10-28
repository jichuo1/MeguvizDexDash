//! Standard DEX header/map/fixed-reference validation over caller-owned bytes.
//! This is a bounded M1 reader, not an ART verifier or complete facts builder.

pub mod annotations;
pub mod checked_reader;
pub mod definitions;
pub mod header;
pub mod instructions;
pub mod strings;
pub mod types;

pub use header::{DexHeader, DexRange, MapItem, TableInfo, validate_header};
