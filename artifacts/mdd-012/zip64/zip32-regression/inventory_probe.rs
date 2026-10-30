use mdd_input::{archive::{ArchiveInventory, ArchiveLimits, InventoryPolicy}, snapshot::{CaptureLimits, InputKind, InputSpec, Snapshot}};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let snapshot = Snapshot::capture(&[InputSpec { path: args[0].clone().into(), kind: InputKind::Apk,
        expected_sha256: Some(args[1].to_str().unwrap().to_owned()) }], CaptureLimits::default())?;
    let source = &snapshot.sources()[0];
    let inventory = ArchiveInventory::build(source, InventoryPolicy::default(), ArchiveLimits::default())?;
    println!("{{\"source_content_id\":\"{}\",\"members\":{},\"selected_dexes\":{},\"directory_complete\":{},\"selected_dex_bytes_complete\":{}}}",
        source.identity().content_id, inventory.manifest().members.len(), inventory.selected_dexes().len(),
        inventory.manifest().directory_complete, inventory.manifest().selected_dex_bytes_complete);
    Ok(())
}
