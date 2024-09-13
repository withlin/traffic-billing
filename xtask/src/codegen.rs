use aya_tool::generate::InputFile;
use std::process::Command;
use std::{fs::File, io::Write, path::PathBuf};

pub fn generate() -> Result<(), anyhow::Error> {
    let dir = PathBuf::from("traffic-billing-ebpf/src");
    let names = vec!["task_struct", "ipv6hdr", "sk_buff", "udphdr", "tcp_hdr"];
    let bindings = aya_tool::generate(
        InputFile::Btf(PathBuf::from("/sys/kernel/btf/vmlinux")),
        &names,
        &[],
    )?;
    let mut vmlinux = File::create(dir.join("vmlinux.rs"))?;
    vmlinux.write_all(bindings.as_bytes())?;
    vmlinux.flush()?;
    let status = Command::new("rustfmt")
        .args(&vec![dir.join("vmlinux.rs")])
        .status()?;

    assert!(status.success());
    Ok(())
}