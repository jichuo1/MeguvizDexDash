use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::{Path, PathBuf},
};

fn collect(directory: &Path, files: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(directory).expect("read source directory") {
        let path = entry.expect("read source entry").path();
        if path.is_dir() {
            collect(&path, files);
        } else if path.extension().is_some_and(|s| s == "rs")
            || path.file_name().is_some_and(|s| s == "Cargo.toml")
        {
            files.push(path);
        }
    }
}

fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap())
        .join("../..")
        .canonicalize()
        .unwrap();
    let mut files = Vec::new();
    collect(&root.join("crates"), &mut files);
    for name in ["Cargo.toml", "Cargo.lock", "rust-toolchain.toml"] {
        files.push(root.join(name));
    }
    files.sort();
    let mut hash = Sha256::new();
    for path in files {
        println!("cargo:rerun-if-changed={}", path.display());
        let relative = path
            .strip_prefix(&root)
            .unwrap()
            .components()
            .map(|c| {
                c.as_os_str()
                    .to_str()
                    .expect("project source paths are Unicode")
            })
            .collect::<Vec<_>>()
            .join("/");
        let bytes = fs::read(&path).expect("read source identity bytes");
        hash.update((relative.len() as u64).to_le_bytes());
        hash.update(relative.as_bytes());
        hash.update((bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
    }
    hash.update(env::var("TARGET").unwrap().as_bytes());
    hash.update(env::var("PROFILE").unwrap().as_bytes());
    let digest = hash
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    println!("cargo:rustc-env=MDD_SOURCE_SHA256={digest}");
}
