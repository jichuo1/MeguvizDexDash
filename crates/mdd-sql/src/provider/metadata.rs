//! Minimal real native fact provider. Strings are read by source occurrence
//! and ordinal, with the original MetadataFacts lease; no row-table ETL.
use super::*;
use crate::{quota, values::SqlText};
use mdd_facts::MetadataFacts;
use mdd_types::{Completeness, ErrorCode, MddError, opaque_id};
use std::collections::BTreeSet;

pub struct MetadataSqlProvider {
    binding: SqlBinding,
    occurrences: Vec<Arc<MetadataFacts>>,
}
impl MetadataSqlProvider {
    pub fn new(occurrences: Vec<Arc<MetadataFacts>>, epoch: DecimalU64) -> MddResult<Self> {
        let snapshot = occurrences
            .first()
            .ok_or_else(|| invalid("METADATA_SCOPE_MUST_BE_EXPLICIT"))?
            .source()
            .snapshot_id
            .clone();
        let mut seen = BTreeSet::new();
        for facts in &occurrences {
            if facts.source().snapshot_id != snapshot
                || !seen.insert(facts.source().dex_occurrence_id.clone())
                || facts.metadata_coverage() != Completeness::Complete
            {
                return Err(invalid("METADATA_PROVIDER_SOURCE_OR_COVERAGE"));
            }
        }
        Ok(Self {
            binding: SqlBinding {
                provider_identity: opaque_id("sql-metadata-provider")?,
                snapshot_id: snapshot,
                catalog_epoch: epoch,
            },
            occurrences,
        })
    }
    pub fn occurrence_count(&self) -> usize {
        self.occurrences.len()
    }
}
struct MetadataCursor {
    provider: Arc<MetadataSqlProvider>,
    occurrence: usize,
    string: usize,
    control: SqlControl,
}
impl SqlFactCursor for MetadataCursor {
    fn next_row(&mut self) -> MddResult<Option<SqlRow>> {
        while let Some(facts) = self.provider.occurrences.get(self.occurrence) {
            self.control.checkpoint(1, false)?;
            if let Some(string) = facts.strings().get(self.string) {
                let text_bytes = (string.data.text.utf16_units.len() as u64)
                    .checked_mul(2)
                    .and_then(|v| v.checked_add(string.data.text.raw_mutf8.len() as u64))
                    .ok_or_else(|| quota("METADATA_SQL_CELL_OVERFLOW"))?;
                if text_bytes > self.control.inner.limits.max_cell_bytes {
                    return Err(quota("METADATA_SQL_CELL_BYTES_BEFORE_CLONE"));
                }
                // Account for both copies of raw MUTF-8, UTF-16 and the two
                // source identifiers before constructing the owned row.
                let id_bytes = facts
                    .source()
                    .dex_occurrence_id
                    .len()
                    .checked_add(string.string_pool_id.len())
                    .and_then(|v| v.checked_mul(2))
                    .and_then(|v| u64::try_from(v).ok())
                    .ok_or_else(|| quota("METADATA_SQL_ROW_BYTES_OVERFLOW"))?;
                let work_bytes = text_bytes
                    .checked_add(string.data.text.raw_mutf8.len() as u64)
                    .and_then(|v| v.checked_add(id_bytes))
                    .and_then(|v| v.checked_add(16))
                    .ok_or_else(|| quota("METADATA_SQL_ROW_BYTES_OVERFLOW"))?;
                self.control.work(work_bytes)?;
                self.string += 1;
                return Ok(Some(vec![
                    SqlValue::text(&facts.source().dex_occurrence_id),
                    SqlValue::text(&string.string_pool_id),
                    SqlValue::U64(DecimalU64(u64::from(string.data.string_idx))),
                    SqlValue::Text(SqlText {
                        utf16: string.data.text.utf16_units.clone(),
                        original_mutf8: Some(string.data.text.raw_mutf8.clone()),
                    }),
                    SqlValue::DexMutf8 {
                        bytes: string.data.text.raw_mutf8.clone(),
                        utf16_code_units: DecimalU64(string.data.text.utf16_units.len() as u64),
                    },
                ]));
            }
            self.occurrence += 1;
            self.string = 0;
        }
        Ok(None)
    }
}
impl SqlFactProvider for MetadataSqlProvider {
    fn binding(&self) -> &SqlBinding {
        &self.binding
    }
    fn relations(&self) -> MddResult<Vec<SqlRelation>> {
        let columns = [
            ("dex_occurrence_id", SqlType::Text),
            ("string_pool_id", SqlType::Text),
            ("string_idx", SqlType::U64),
            ("value", SqlType::Text),
            ("raw_mutf8", SqlType::Bytes),
        ]
        .into_iter()
        .map(|(name, data_type)| SqlColumn {
            id: name.into(),
            name: name.into(),
            data_type,
            nullable: false,
        })
        .collect();
        let count = self
            .occurrences
            .iter()
            .try_fold(0u64, |count, facts| {
                count.checked_add(facts.strings().len() as u64)
            })
            .ok_or_else(|| quota("METADATA_SQL_ROWS_OVERFLOW"))?;
        Ok(vec![SqlRelation {
            name: "native_strings".into(),
            columns,
            required_layers: vec![FactLayer::Metadata],
            estimated_rows: Some(DecimalU64(count)),
        }])
    }
    fn require_relation(&self, relation: &str) -> MddResult<()> {
        if relation.eq_ignore_ascii_case("native_strings") {
            Ok(())
        } else {
            Err(MddError::new(
                ErrorCode::InvalidArgument,
                "sql.metadata",
                "unknown relation",
            ))
        }
    }
    fn open_cursor(
        self: Arc<Self>,
        relation: &str,
        control: SqlControl,
    ) -> MddResult<Box<dyn SqlFactCursor>> {
        self.require_relation(relation)?;
        Ok(Box::new(MetadataCursor {
            provider: self,
            occurrence: 0,
            string: 0,
            control,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SqlBridge, control::SqlLimits, dialects::SqlDialect};
    use mdd_dex::strings::StringLimits;
    use mdd_input::{
        archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy},
        snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot},
    };
    #[test]
    fn real_metadata_same_snapshot_duplicates_and_lossless_values() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/references/generated/nonscalar-string-035.dex");
        let input = InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        };
        let snapshot =
            Snapshot::capture(&[input.clone(), input], CaptureLimits::default()).unwrap();
        let mut facts = Vec::new();
        for source in snapshot.sources() {
            let inventory = ArchiveInventory::build(
                source,
                InventoryPolicy::default(),
                ArchiveLimits::default(),
            )
            .unwrap();
            facts.push(Arc::new(
                MetadataFacts::build(&snapshot, &inventory, 0, StringLimits::default()).unwrap(),
            ));
        }
        let strings = facts[0].strings().len();
        let source_id = snapshot.manifest().snapshot_id.clone();
        let provider = Arc::new(MetadataSqlProvider::new(facts, DecimalU64(0)).unwrap());
        assert_eq!(provider.occurrence_count(), 2);
        drop(snapshot);
        let bridge = SqlBridge::new(provider, SqlDialect::NativeV1, SqlLimits::default()).unwrap();
        let result=bridge.query("SELECT dex_occurrence_id,string_idx,value,raw_mutf8 FROM native_strings ORDER BY dex_occurrence_id,string_idx").unwrap();
        assert_eq!(result.binding().snapshot_id, source_id);
        assert_eq!(result.rows().len(), strings * 2);
        assert_ne!(result.rows()[0][0], result.rows()[strings][0]);
        assert!(
            result
                .rows()
                .iter()
                .any(|row| matches!(&row[2],SqlValue::Text(text) if text.strict_utf8().is_err()))
        );
        let count = bridge.query("SELECT COUNT(*) AS n FROM native_strings WHERE value = ?");
        assert!(count.is_err());
    }
}
