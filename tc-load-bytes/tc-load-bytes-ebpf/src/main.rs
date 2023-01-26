#![no_std]
#![no_main]

use aya_bpf::{
    bindings::TC_ACT_PIPE,
    macros::{classifier, map},
    maps::PerCpuArray,
    programs::TcContext,
};

use tc_load_bytes_common::{PacketBuffer, MAX_MTU};

#[map]
static BUF: PerCpuArray<PacketBuffer> = PerCpuArray::with_max_entries(1, 0);

#[classifier(name = "tc_load_bytes")]
pub fn tc_load_bytes(ctx: TcContext) -> i32 {
    match try_tc_load_bytes(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_tc_load_bytes(ctx: TcContext) -> Result<i32, i32> {
    let buf = unsafe {
        let ptr = BUF.get_ptr_mut(0).ok_or(0)?;
        &mut *ptr
    };
    if ctx.data() + MAX_MTU > ctx.data_end() {
        return Err(TC_ACT_PIPE);
    }
    ctx.load_bytes(0, &mut buf.buf[..MAX_MTU])
        .map_err(|_| TC_ACT_PIPE)?;

    Ok(TC_ACT_PIPE)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
