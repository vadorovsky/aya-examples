use aya::{
    include_bytes_aligned, maps::perf::AsyncPerfEventArray, programs::Lsm, util::online_cpus, Bpf,
    Btf,
};
use bytes::BytesMut;
use log::info;
use tokio::{signal, task};

use cshim_common::Event;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/cshim"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/cshim"
    ))?;
    let btf = Btf::from_sys_fs()?;
    let program: &mut Lsm = bpf.program_mut("task_alloc").unwrap().try_into()?;
    program.load("task_alloc", &btf)?;
    program.attach()?;

    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;

    let cpus = online_cpus()?;
    for cpu_id in cpus {
        let mut buf = perf_array.open(cpu_id, None)?;

        task::spawn(async move {
            let mut buffers = (0..10)
                .map(|_| BytesMut::with_capacity(1024))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const Event;

                    let data = unsafe { ptr.read_unaligned() };
                    info!("PID: {}, TGID: {}", data.pid, data.tgid);
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
