use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Cursor, Read, Write};

mod sql;

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct ProbeValue {
    decimal_u64: String,
    utf16: Vec<u16>,
    nullable: Option<String>,
}

fn probe() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let value = ProbeValue {
        decimal_u64: u64::MAX.to_string(),
        utf16: vec![0, 0xd800, 0xdc00],
        nullable: None,
    };
    let encoded = serde_json::to_vec(&value)?;
    let decoded: ProbeValue = serde_json::from_slice(&encoded)?;
    if decoded != value {
        return Err("JSON lossless representation failed".into());
    }
    let digest: String = Sha256::digest(b"abc")
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    if digest != "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" {
        return Err("SHA-256 known vector failed".into());
    }
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    writer.start_file("classes.dex", options)?;
    writer.write_all(b"build-probe bytes, not a valid DEX")?;
    let mut archive = zip::ZipArchive::new(writer.finish()?)?;
    let mut bytes = Vec::new();
    archive.by_index(0)?.read_to_end(&mut bytes)?;
    if bytes != b"build-probe bytes, not a valid DEX" {
        return Err("ZIP DEFLATE round trip failed".into());
    }
    let db = rusqlite::Connection::open_in_memory()?;
    let source_id: String = db.query_row("SELECT sqlite_source_id()", [], |r| r.get(0))?;
    let mut options = db.prepare("PRAGMA compile_options")?;
    let compile_options = options
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let mut entropy = [0u8; 32];
    getrandom::fill(&mut entropy)?;
    if entropy.iter().all(|byte| *byte == 0) {
        return Err("OS randomness returned all zero bytes".into());
    }
    Ok(serde_json::json!({
        "schema_version": "mdd.build-probe.v1",
        "scope": "M0 dependency build and API probes only; no engine qualification",
        "target_os": std::env::consts::OS,
        "target_arch": std::env::consts::ARCH,
        "sqlite_version": rusqlite::version(),
        "sqlite_source_id": source_id,
        "sqlite_compile_options": compile_options,
        "sql_bridge_probe": sql::probe()?,
        "checks": {"json_lossless": true, "sha256_known_vector": true,
                   "zip_deflate_roundtrip": true, "os_randomness": true}
    }))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", serde_json::to_string_pretty(&probe()?)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn dependency_apis_are_usable() {
        super::probe().unwrap();
    }
}
