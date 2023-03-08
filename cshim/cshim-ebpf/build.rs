use std::process::Command;

fn main() {
    let out_dir = std::env::var("OUT_DIR").unwrap();

    let _ = Command::new("clang")
        .arg("-I")
        .arg("src/")
        .arg("-O2")
        .arg("-target")
        .arg("bpf")
        .arg("-emit-llvm")
        .arg("-c")
        .arg("-g")
        .arg("src/vmlinux_access.c")
        .arg("-o")
        .arg(format!("{out_dir}/vmlinux_access.ll"))
        .status()
        .expect("Failed to compile the C-shim");

    let _ = Command::new("llc")
        .arg("-march=bpf")
        .arg("-filetype=obj")
        .arg(format!("{out_dir}/vmlinux_access.ll"))
        .arg("-o")
        .arg(format!("{out_dir}/vmlinux_access.o"))
        .status()
        .expect("Failed to compile the C-shim");

    println!("cargo:rustc-link-search=native={out_dir}");
    println!("cargo:rustc-link-lib=link-arg={out_dir}/vmlinux_access.o");
    // println!("cargo:rustc-link-arg-bin=cshim={out_dir}/vmlinux_access.o");
    println!("cargo:rerun-if-changed=src/vmlinux_access.c");
    println!("cargo:rerun-if-changed=src/vmlinux_access.h");
    println!("cargo:rerun-if-changed=src/vmlinux.h");
}
