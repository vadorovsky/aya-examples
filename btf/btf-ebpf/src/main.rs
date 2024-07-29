#![no_std]
#![no_main]

use aya_ebpf::{bpf_printk, macros::lsm, programs::LsmContext};

#[repr(C)]
pub struct Foo {
    field_a: i32,
    field_b: i64,
    field_c: u32,
    field_d: u64,
    field_e: u128,
}

#[inline(never)]
pub fn get_field_a(foo: &Foo) -> i32 {
    foo.field_a
}

#[inline(never)]
pub fn get_field_b(foo: &Foo) -> i64 {
    foo.field_b
}

#[inline(never)]
pub fn get_field_c(foo: &Foo) -> u32 {
    foo.field_c
}

#[inline(never)]
pub fn get_field_d(foo: &Foo) -> u64 {
    foo.field_d
}

#[inline(never)]
pub fn get_field_e(foo: &Foo) -> u128 {
    foo.field_e
}

#[lsm(hook = "file_open")]
pub fn file_open(ctx: LsmContext) -> i32 {
    unsafe {
        let foo: *const Foo = ctx.arg(0);

        let field_a_var = get_field_a(&*foo);
        // let field_b_var = get_field_b(&*foo);
        // let field_c_var = get_field_c(&*foo);
        // let field_d_var = get_field_d(&*foo);
        // let field_e_var = get_field_e(&*foo);
        bpf_printk!(b"a: {}", field_a_var);
        // bpf_printk!(b"b: {}", field_b_var);
        // bpf_printk!(b"c: {}", field_c_var);
        // bpf_printk!(b"d: {}", field_d_var);
        // bpf_printk!(b"e: {}", field_e_var as u64);
    }

    0
}

#[lsm(hook = "sb_mount")]
pub fn sb_mount(ctx: LsmContext) -> i32 {
    unsafe {    
        let foo: *const Foo = ctx.arg(0);

        bpf_printk!(b"a: {}", (*foo).field_a);
        bpf_printk!(b"b: {}", (*foo).field_b);
        bpf_printk!(b"c: {}", (*foo).field_c);
        bpf_printk!(b"d: {}", (*foo).field_d);
        bpf_printk!(b"e: {}", (*foo).field_e as u64);
    }

    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
