//! Versioned execution ownership, separate from shareable source/data bindings.
use crate::{invalid, provider::SqlBinding};
use mdd_query::budget::RuntimeBudget;
use mdd_session::QueryBinding;
use mdd_types::{DecimalU64, MddResult};
use serde::Serialize;

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SqlExecutionBinding {
    pub schema_version: String,
    pub worker_owner_id: String,
    pub session_id: String,
    pub query_id: String,
    pub snapshot_id: String,
    pub catalog_epoch: DecimalU64,
    pub provider_identity: String,
    pub request_key: String,
    pub schema_id: String,
    pub semantic_version: String,
}
impl SqlExecutionBinding {
    pub(crate) fn capture(
        runtime: &RuntimeBudget,
        source: &SqlBinding,
        expected: &QueryBinding,
    ) -> MddResult<Self> {
        let token = runtime.cancellation();
        let actual = token.binding()?;
        let status = token.status()?;
        if token.snapshot_id()? != source.snapshot_id
            || status.catalog_epoch != source.catalog_epoch
            || actual.request_key != expected.request_key
            || actual.schema_id != expected.schema_id
            || actual.semantic_version != expected.semantic_version
        {
            return Err(invalid("SQL_RUNTIME_SNAPSHOT_EPOCH_OR_FINGERPRINT"));
        }
        if let Some(error) = status.error {
            return Err(error);
        }
        Ok(Self {
            schema_version: "mdd.sql.execution-binding.v1".into(),
            worker_owner_id: token.worker_owner_id()?,
            session_id: token.session_id()?,
            query_id: token.query_handle().id().into(),
            snapshot_id: source.snapshot_id.clone(),
            catalog_epoch: source.catalog_epoch,
            provider_identity: source.provider_identity.clone(),
            request_key: actual.request_key,
            schema_id: actual.schema_id,
            semantic_version: actual.semantic_version,
        })
    }
}
