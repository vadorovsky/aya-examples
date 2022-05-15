#![no_std]
#![no_main]

use aya_bpf::{
    bindings::path,
    cty::{c_char, c_long},
    helpers::bpf_d_path,
    macros::{lsm, map},
    maps::PerCpuArray,
    programs::LsmContext,
};
use aya_log_ebpf::info;

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use vmlinux::file;

pub const PATH_LEN: usize = 512;

#[derive(Copy, Clone)]
#[repr(C)]
pub struct Path {
    pub path: [u8; PATH_LEN],
}

#[map]
pub(crate) static mut PATH_BUF: PerCpuArray<Path> = PerCpuArray::with_max_entries(1, 0);

#[inline(always)]
pub fn my_bpf_d_path(path: *mut path, buf: &mut [u8]) -> Result<usize, c_long> {
    let ret = unsafe { bpf_d_path(path, buf.as_mut_ptr() as *mut c_char, buf.len() as u32) };
    if ret < 0 {
        return Err(ret);
    }

    Ok(ret as usize)
}

#[lsm(name = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match { try_file_open(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    let buf = unsafe { PATH_BUF.get_mut(0).ok_or(0)? };

    let p = unsafe {
        let f: *const file = ctx.arg(0);
        let p = &(*f).f_path as *const _ as *mut path;
        let len = my_bpf_d_path(p, &mut buf.path).map_err(|e| e as i32)?;
        if len >= PATH_LEN {
            return Err(0);
        }
        core::str::from_utf8_unchecked(&buf.path[..len])
    };
    info!(&ctx, "file_open: path: {}", p);

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
