//! Snapshot-scoped exact facts. Metadata completion never implies complete audit facts.
pub mod metadata;
pub mod definitions;
pub mod code;

pub use metadata::{
    EntityKind, EntityRef, MetadataFacts, MetadataSource, PrototypeFact, StringFact,
    StringPoolIdentity, TypeFact,
};
