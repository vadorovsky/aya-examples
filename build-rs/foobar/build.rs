use std::{path::PathBuf, process::Command};

fn main() -> Result<(), anyhow::Error> {
    println!("cargo:rerun-if-changed=../foobar-ebpf");

    let dir = PathBuf::from("../foobar-ebpf");
    let target = "--target=bpfel-unknown-none";
    let args = vec!["build", target, "-Z", "build-std=core", "--release"];

    let status = Command::new("cargo")
        .current_dir(dir)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap())
        .args(&args)
        .status()
        .expect("failed to build bpf program");
    assert!(status.success());
    Ok(())
}
