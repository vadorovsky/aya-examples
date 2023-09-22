use std::process::Command;

use anyhow::{bail, Result};

fn main() -> Result<()> {
    let out_dir = std::env::var("OUT_DIR").unwrap();

    let status = Command::new("clang")
        .arg("-I")
        .arg("src/")
        .arg("-O2")
        .arg("-emit-llvm")
        .arg("-target")
        .arg("bpf")
        .arg("-c")
        .arg("-gdwarf-4")
        .arg("src/vmlinux_access.c")
        .arg("-o")
        .arg(format!("{out_dir}/vmlinux_access.o"))
        .status()
        .expect("Failed to compile the C-shim");
    if !status.success() {
        bail!("Failed to compile eBPF program");
    }

    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-lib=link-arg={out_dir}/vmlinux_access.o");
    println!("cargo:rerun-if-changed=src/vmlinux_access.c");
    println!("cargo:rerun-if-changed=src/vmlinux_access.h");
    println!("cargo:rerun-if-changed=src/vmlinux.h");

    Ok(())
}
