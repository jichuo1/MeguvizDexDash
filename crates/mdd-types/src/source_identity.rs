use crate::DecimalU64;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    pub occurrence_id: String,
    pub input_ordinal: DecimalU64,
    pub content_id: String,
    pub byte_length: DecimalU64,
    pub input_kind: String,
    pub origin_display: Option<String>,
}
