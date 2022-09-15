#![no_std]
#![no_main]

use aya_bpf::{
    cty::c_char,
    helpers::bpf_probe_read_kernel_str,
    macros::{btf_tracepoint, map},
    maps::PerCpuArray,
    programs::BtfTracePointContext,
};
use aya_log_ebpf::info;

const LOG_BUF_CAPACITY: usize = 64;

#[repr(C)]
pub struct Buf {
    pub buf: [u8; LOG_BUF_CAPACITY],
}

#[map]
pub static BUF: PerCpuArray<Buf> = PerCpuArray::with_max_entries(1, 0);

#[btf_tracepoint(name = "cgroup_mkdir")]
pub fn cgroup_mkdir(ctx: BtfTracePointContext) -> i32 {
    match { try_cgroup_mkdir(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_cgroup_mkdir(ctx: BtfTracePointContext) -> Result<i32, i32> {
    let path = unsafe {
        let path: *const c_char = ctx.arg(1);
        let buf = BUF.get_mut(0).ok_or(0)?;
        let len =
            bpf_probe_read_kernel_str(path as *const u8, &mut buf.buf).map_err(|e| e as i32)?;
        core::str::from_utf8_unchecked(&buf.buf[..len])
    };

    info!(&ctx, "tracepoint cgroup_mkdir called: {}", path);

    if path.starts_with("/sys/fs/cgroup") {
        info!(&ctx, "cgroup");
    }
    if path.starts_with("/system.slice/docker") {
        info!(&ctx, "docker cgroup");
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
