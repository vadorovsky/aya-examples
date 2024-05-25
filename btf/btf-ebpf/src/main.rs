#![no_std]
#![no_main]

use aya_ebpf::{macros::lsm, programs::LsmContext};
use aya_log_ebpf::info;

#[repr(C)]
pub struct Foo {
    a: i32,
    b: i64,
}

pub fn get_a(foo: &Foo) -> i32 {
    foo.a
}

pub fn get_b(foo: &Foo) -> i64 {
    foo.b
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    match try_file_open(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_file_open(ctx: LsmContext) -> Result<i32, i32> {
    info!(&ctx, "lsm hook file_open called");

    let foo = Foo { a: 34, b: 75 };
    info!(&ctx, "a: {}", get_a(&foo));
    info!(&ctx, "b: {}", get_b(&foo));

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
