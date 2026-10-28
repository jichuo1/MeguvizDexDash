use mdd_types::source_identity::SourceIdentity;
use mdd_types::{DecimalU64, ErrorCode, MddError, MddResult, content_id, opaque_id, sha256};
use serde::Serialize;
use std::{collections::BTreeMap, fs::File, io::Read, path::PathBuf, sync::Arc};

#[derive(Clone, Copy, Debug)]
pub enum InputKind {
    RawDex,
    Apk,
}

impl InputKind {
    fn name(self) -> &'static str {
        match self {
            Self::RawDex => "raw-dex",
            Self::Apk => "apk-zip",
        }
    }
}

#[derive(Clone, Debug)]
pub struct InputSpec {
    pub path: PathBuf,
    pub kind: InputKind,
    pub expected_sha256: Option<String>,
}

#[derive(Clone, Copy, Debug)]
pub struct CaptureLimits {
    pub max_input_bytes: u64,
    pub max_sources: usize,
}

impl Default for CaptureLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 1024 * 1024 * 1024,
            max_sources: 256,
        }
    }
}

#[derive(Clone)]
pub struct CapturedSource {
    identity: SourceIdentity,
    kind: InputKind,
    bytes: Arc<[u8]>,
}

impl CapturedSource {
    pub fn identity(&self) -> &SourceIdentity {
        &self.identity
    }
    pub fn kind(&self) -> InputKind {
        self.kind
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn lease(&self) -> Arc<[u8]> {
        Arc::clone(&self.bytes)
    }
}

#[derive(Clone, Serialize)]
pub struct SnapshotManifest {
    pub schema_version: String,
    pub snapshot_id: String,
    pub snapshot_content_key: String,
    pub capture_policy: String,
    pub sources: Vec<SourceIdentity>,
    pub captured_input_bytes: DecimalU64,
    pub scope: String,
}

pub struct Snapshot {
    manifest: SnapshotManifest,
    sources: Vec<CapturedSource>,
}

impl Snapshot {
    pub fn capture(inputs: &[InputSpec], limits: CaptureLimits) -> MddResult<Self> {
        if inputs.is_empty() {
            return Err(MddError::new(
                ErrorCode::InvalidArgument,
                "capture",
                "input list is empty",
            ));
        }
        if inputs.len() > limits.max_sources {
            return Err(MddError::new(
                ErrorCode::QuotaExceeded,
                "capture",
                "source count exceeds budget",
            )
            .detail("budget", "max_sources")
            .detail("limit", limits.max_sources.to_string()));
        }
        let snapshot_id = opaque_id("snapshot")?;
        let mut sources = Vec::new();
        let mut content: BTreeMap<String, Arc<[u8]>> = BTreeMap::new();
        let mut total = 0u64;
        for (ordinal, input) in inputs.iter().enumerate() {
            if let Some(expected) = &input.expected_sha256
                && (expected.len() != 64
                    || !expected
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
            {
                return Err(MddError::new(
                    ErrorCode::InvalidArgument,
                    "capture",
                    "expected SHA-256 must be lowercase 64-digit hex",
                ));
            }
            let io_error = |error: std::io::Error| {
                MddError::new(ErrorCode::InvalidInput, "capture", error.to_string())
                    .detail("input_ordinal", ordinal.to_string())
            };
            let mut file = File::open(&input.path).map_err(io_error)?;
            let mut bytes = Vec::new();
            let mut buffer = [0u8; 65536];
            loop {
                let count = file.read(&mut buffer).map_err(io_error)?;
                if count == 0 {
                    break;
                }
                total = total.checked_add(count as u64).ok_or_else(|| {
                    MddError::new(ErrorCode::QuotaExceeded, "capture", "input length overflow")
                })?;
                if total > limits.max_input_bytes {
                    return Err(MddError::new(
                        ErrorCode::QuotaExceeded,
                        "capture",
                        "input byte budget exceeded",
                    )
                    .detail("budget", "max_input_bytes")
                    .detail("limit", limits.max_input_bytes.to_string())
                    .detail("observed", total.to_string())
                    .detail("input_ordinal", ordinal.to_string()));
                }
                bytes.try_reserve(count).map_err(|error| {
                    MddError::new(ErrorCode::QuotaExceeded, "capture", error.to_string())
                })?;
                bytes.extend_from_slice(&buffer[..count]);
            }
            let correct_magic = match input.kind {
                InputKind::RawDex => bytes.starts_with(b"dex\n"),
                InputKind::Apk => {
                    bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06")
                }
            };
            if !correct_magic {
                return Err(MddError::new(
                    ErrorCode::InvalidInput,
                    "capture",
                    "input magic does not match declared kind",
                )
                .detail("input_ordinal", ordinal.to_string()));
            }
            let digest = sha256(&bytes);
            if input
                .expected_sha256
                .as_ref()
                .is_some_and(|expected| *expected != digest)
            {
                return Err(MddError::new(
                    ErrorCode::SourceChanged,
                    "capture",
                    "captured content differs from expected SHA-256",
                )
                .detail("actual_sha256", digest)
                .detail("input_ordinal", ordinal.to_string()));
            }
            let id = content_id(&bytes);
            let byte_length = bytes.len() as u64;
            let blob = content
                .entry(id.clone())
                .or_insert_with(|| Arc::from(bytes))
                .clone();
            sources.push(CapturedSource {
                identity: SourceIdentity {
                    occurrence_id: format!("{snapshot_id}:source:{ordinal}"),
                    input_ordinal: DecimalU64(ordinal as u64),
                    content_id: id,
                    byte_length: DecimalU64(byte_length),
                    input_kind: input.kind.name().to_owned(),
                    origin_display: input.path.to_str().map(str::to_owned),
                },
                kind: input.kind,
                bytes: blob,
            });
        }
        let identities: Vec<_> = sources.iter().map(|s| s.identity.clone()).collect();
        let key_items: Vec<_> = identities
            .iter()
            .map(|s| (&s.content_id, &s.input_kind))
            .collect();
        let key = serde_json::to_vec(&("capture-owned-v1", &key_items)).map_err(|error| {
            MddError::new(ErrorCode::InternalFault, "capture", error.to_string())
        })?;
        Ok(Self {
            manifest: SnapshotManifest {
                schema_version: "mdd.snapshot.capture.v1".to_owned(), snapshot_id,
                snapshot_content_key: content_id(&key), capture_policy: "owned-captured-bytes-v1".to_owned(),
                sources: identities, captured_input_bytes: DecimalU64(total),
                scope: "owned source capture only; member inventory and DEX facts require separate validation".to_owned(),
            }, sources,
        })
    }

    pub fn manifest(&self) -> &SnapshotManifest {
        &self.manifest
    }
    pub fn sources(&self) -> &[CapturedSource] {
        &self.sources
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn directory() -> PathBuf {
        let path = std::env::temp_dir().join(opaque_id("mdd-test").unwrap());
        fs::create_dir(&path).unwrap();
        path
    }

    fn spec(path: PathBuf) -> InputSpec {
        InputSpec {
            path,
            kind: InputKind::RawDex,
            expected_sha256: None,
        }
    }

    #[test]
    fn capture_retains_generation_and_occurrences() {
        let dir = directory();
        let path = dir.join("source.dex");
        let original = include_bytes!("../../../../tests/fixtures/generated/minimal-035.dex");
        fs::write(&path, original).unwrap();
        let snapshot = Snapshot::capture(
            &[spec(path.clone()), spec(path.clone())],
            CaptureLimits::default(),
        )
        .unwrap();
        assert_eq!(snapshot.sources().len(), 2);
        assert_ne!(
            snapshot.sources()[0].identity().occurrence_id,
            snapshot.sources()[1].identity().occurrence_id
        );
        assert!(Arc::ptr_eq(
            &snapshot.sources()[0].lease(),
            &snapshot.sources()[1].lease()
        ));
        let lease = snapshot.sources()[0].lease();
        let modified = vec![b'x'; original.len()];
        let times = fs::metadata(&path).unwrap();
        fs::write(&path, modified).unwrap();
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(times.modified().unwrap()))
            .unwrap();
        fs::rename(&path, dir.join("renamed.dex")).unwrap();
        fs::remove_file(dir.join("renamed.dex")).unwrap();
        fs::write(&path, b"replacement").unwrap();
        assert_eq!(snapshot.sources()[0].bytes(), original);
        assert_eq!(snapshot.sources()[1].bytes(), original);
        assert_eq!(lease.as_ref(), original);
        drop(snapshot);
        assert_eq!(lease.as_ref(), original);
    }

    #[test]
    fn source_expected_hash_and_zero_budget_fail_closed() {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/generated/minimal-035.dex");
        let mut input = spec(path);
        input.expected_sha256 = Some("0".repeat(64));
        assert_eq!(
            Snapshot::capture(&[input.clone()], CaptureLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::SourceChanged
        );
        input.expected_sha256 = None;
        assert_eq!(
            Snapshot::capture(
                &[input],
                CaptureLimits {
                    max_input_bytes: 0,
                    max_sources: 1
                }
            )
            .err()
            .unwrap()
            .code,
            ErrorCode::QuotaExceeded
        );
        assert_eq!(
            Snapshot::capture(&[], CaptureLimits::default())
                .err()
                .unwrap()
                .code,
            ErrorCode::InvalidArgument
        );
    }
}
