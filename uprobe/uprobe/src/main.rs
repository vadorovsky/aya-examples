use aya::programs::UProbe;
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use log::{info, warn};
use procfs::process::Process;
use tokio::signal;

#[no_mangle]
#[inline(never)]
pub extern "C" fn uprobed_function(_val: u32) {}

fn get_base_addr() -> Result<usize, anyhow::Error> {
    let me = Process::myself()?;
    let maps = me.maps()?;

    for entry in maps {
        if entry.perms.contains("r-xp") {
            return Ok((entry.address.0 - entry.offset) as usize);
        }
    }

    anyhow::bail!("Failed to find executable region")
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/uprobe"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/uprobe"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut UProbe = bpf.program_mut("uprobe").unwrap().try_into()?;
    program.load()?;

    let fn_addr = uprobed_function as *const () as usize;
    let offset = fn_addr - get_base_addr()?;

    program.attach(None, offset as u64, "/proc/self/exe", None)?;

    uprobed_function(69);
    uprobed_function(420);

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
