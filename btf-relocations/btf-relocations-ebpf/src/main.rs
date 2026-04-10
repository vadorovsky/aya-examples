#![no_std]
#![no_main]
#![feature(btf_preserve_access)]

use aya_ebpf::{
    EbpfContext, Global, helpers::bpf_probe_read_kernel, macros::kprobe, programs::ProbeContext,
};
use aya_log_ebpf::info;

#[unsafe(no_mangle)]
static TARGET_TGID: Global<u32> = Global::new(0);

#[btf_preserve_access]
#[expect(non_camel_case_types, reason = "kernel type")]
struct task_struct {
    pid: u32,
    tgid: u32,
}

#[kprobe]
pub fn btf_relocations(ctx: ProbeContext) -> u32 {
    match try_btf_relocations(ctx) {
        Ok(ret) => ret,
        Err(_) => 0,
    }
}

fn try_btf_relocations(ctx: ProbeContext) -> Result<u32, i32> {
    if ctx.tgid() != TARGET_TGID.load() {
        return Ok(0);
    }

    let task: *const task_struct = ctx.arg(0).ok_or(-1)?;
    let pid = unsafe { bpf_probe_read_kernel(&(*task).pid)? };
    let tgid = unsafe { bpf_probe_read_kernel(&(*task).tgid)? };
    info!(&ctx, "kprobe called: pid: {}, tgid: {}", pid, tgid);
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
