#![no_std]
#![no_main]

use core::sync::atomic::{AtomicU64, Ordering};

use aya_bpf::{
    macros::tracepoint,
    programs::TracePointContext,
};  
use aya_log_ebpf::info;

#[tracepoint(name="atomic")]
pub fn atomic(ctx: TracePointContext) -> u32 {
    match try_atomic(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_atomic(ctx: TracePointContext) -> Result<u32, u32> {
    let mut au64 = AtomicU64::new(100);
    info!(&ctx, "au64: {}", au64.load(Ordering::Relaxed));

    *au64.get_mut() = 50;
    info!(&ctx, "au64: {}", au64.load(Ordering::Relaxed));

    au64.store(120, Ordering::Relaxed);
    info!(&ctx, "au64: {}", au64.load(Ordering::Relaxed));

    au64.swap(140, Ordering::Relaxed);
    info!(&ctx, "au64: {}", au64.load(Ordering::Relaxed));

    // The following ones fail with:
    // error: linking with `bpf-linker` failed: signal: 6 (SIGABRT) (core dumped)
    //  |
    //  = note: LC_ALL="C" PATH="/home/vadorovsky/repos/rust/build/x86_64-unknown-linux-gnu/stage1/lib/rustlib/x86_64-unknown-linux-gnu/bin:/home/vadorovsky/.npm-global/bin:/home/vadorovsky/solana/bin:/home/vadorovsky/.local/share/solana/install/active_release/bin:/home/vadorovsky/.local/llvm/bin:/home/vadorovsky/go/bin:/home/vadorovsky/.cargo/bin:/home/vadorovsky/miniconda3/bin:/home/vadorovsky/miniconda3/condabin:/home/vadorovsky/.cargo/bin:/home/vadorovsky/.local/bin:/home/vadorovsky/bin:/usr/local/bin:/usr/bin:/usr/bin" VSLANG="1033" "bpf-linker" "--export-symbols" "/tmp/rustc6xzwse/symbols" "/tmp/rustc6xzwse/symbols.o" "/home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/bpfel-unknown-none/debug/deps/atomic-0df4b88cd767cdfe.atomic.9f2f50cf-cgu.0.rcgu.o" "-L" "/home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/bpfel-unknown-none/debug/deps" "-L" "/home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/debug/deps" "-L" "/home/vadorovsky/repos/rust/build/x86_64-unknown-linux-gnu/stage1/lib/rustlib/bpfel-unknown-none/lib" "--cpu" "generic" "--cpu-features" "" "-L" "/home/vadorovsky/repos/rust/build/x86_64-unknown-linux-gnu/stage1/lib/rustlib/bpfel-unknown-none/lib" "-o" "/home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/bpfel-unknown-none/debug/deps/atomic-0df4b88cd767cdfe" "-O3" "--debug"
    //  = note: 03:27:44 [ERROR] fatal error: "Cannot select: 0x5576d21afe28: i64,ch = AtomicLoad<(dereferenceable load monotonic (s64) from %ir.7)> 0x5576d21b2b28, FrameIndex:i64<5>\n  0x5576d21afdc0: i64 = FrameIndex<5>\nIn function: atomic"
    //          PLEASE submit a bug report to https://github.com/llvm/llvm-project/issues/ and include the crash backtrace.
    //          Stack dump:
    //          1.    Running pass 'BPF DAG->DAG Pattern Instruction Selection' on function '@atomic'
    //          03:27:44 [ INFO] command line: "bpf-linker --export-symbols /tmp/rustc6xzwse/symbols /tmp/rustc6xzwse/symbols.o /home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/bpfel-unknown-none/debug/deps/atomic-0df4b88cd767cdfe.atomic.9f2f50cf-cgu.0.rcgu.o -L /home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/bpfel-unknown-none/debug/deps -L /home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/debug/deps -L /home/vadorovsky/repos/rust/build/x86_64-unknown-linux-gnu/stage1/lib/rustlib/bpfel-unknown-none/lib --cpu generic --cpu-features  -L /home/vadorovsky/repos/rust/build/x86_64-unknown-linux-gnu/stage1/lib/rustlib/bpfel-unknown-none/lib -o /home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/bpfel-unknown-none/debug/deps/atomic-0df4b88cd767cdfe -O3 --debug"
    //          03:27:44 [ INFO] LLVM command line: ["bpf-linker", "--bpf-expand-memcpy-in-order"]
    //          03:27:44 [ INFO] linking file "/tmp/rustc6xzwse/symbols.o" type elf
    //          03:27:44 [ WARN] ignoring file "/tmp/rustc6xzwse/symbols.o": no embedded bitcode
    //          03:27:44 [ INFO] linking file "/home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/bpfel-unknown-none/debug/deps/atomic-0df4b88cd767cdfe.atomic.9f2f50cf-cgu.0.rcgu.o" type bitcode
    //          03:27:44 [ INFO] emitting LLVMObjectFile to "/home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/bpfel-unknown-none/debug/deps/atomic-0df4b88cd767cdfe"

    // au64.compare_and_swap(222, 333, Ordering::Relaxed);
    // info!(&ctx, "au64: {}", au64.load(Ordering::Relaxed));

    // au64.compare_and_swap(0, 444, Ordering::Relaxed);
    // info!(&ctx, "au64: {}", au64.load(Ordering::Relaxed));

    // The following ones fail with:
    // error: linking with `bpf-linker` failed: signal: 6 (SIGABRT) (core dumped)
    // |
    // = note: LC_ALL="C" PATH="/home/vadorovsky/repos/rust/build/x86_64-unknown-linux-gnu/stage1/lib/rustlib/x86_64-unknown-linux-gnu/bin:/home/vadorovsky/.npm-global/bin:/home/vadorovsky/solana/bin:/home/vadorovsky/.local/share/solana/install/active_release/bin:/home/vadorovsky/.local/llvm/bin:/home/vadorovsky/go/bin:/home/vadorovsky/.cargo/bin:/home/vadorovsky/miniconda3/bin:/home/vadorovsky/miniconda3/condabin:/home/vadorovsky/.cargo/bin:/home/vadorovsky/.local/bin:/home/vadorovsky/bin:/usr/local/bin:/usr/bin:/usr/bin" VSLANG="1033" "bpf-linker" "--export-symbols" "/tmp/rustcOZPmMX/symbols" "/tmp/rustcOZPmMX/symbols.o" "/home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/bpfel-unknown-none/debug/deps/atomic-0df4b88cd767cdfe.atomic.9f2f50cf-cgu.0.rcgu.o" "-L" "/home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/bpfel-unknown-none/debug/deps" "-L" "/home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/debug/deps" "-L" "/home/vadorovsky/repos/rust/build/x86_64-unknown-linux-gnu/stage1/lib/rustlib/bpfel-unknown-none/lib" "--cpu" "generic" "--cpu-features" "" "-L" "/home/vadorovsky/repos/rust/build/x86_64-unknown-linux-gnu/stage1/lib/rustlib/bpfel-unknown-none/lib" "-o" "/home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/bpfel-unknown-none/debug/deps/atomic-0df4b88cd767cdfe" "-O3" "--debug"
    //         PLEASE submit a bug report to https://github.com/llvm/llvm-project/issues/ and include the crash backtrace.
    //         Stack dump:
    //         0.    Running pass 'Function Pass Manager' on module 'atomic-0df4b88cd767cdfe'.
    //         1.    Running pass 'BPF DAG->DAG Pattern Instruction Selection' on function '@atomic'
    //         03:37:58 [ INFO] command line: "bpf-linker --export-symbols /tmp/rustcOZPmMX/symbols /tmp/rustcOZPmMX/symbols.o /home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/bpfel-unknown-none/debug/deps/atomic-0df4b88cd767cdfe.atomic.9f2f50cf-cgu.0.rcgu.o -L /home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/bpfel-unknown-none/debug/deps -L /home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/debug/deps -L /home/vadorovsky/repos/rust/build/x86_64-unknown-linux-gnu/stage1/lib/rustlib/bpfel-unknown-none/lib --cpu generic --cpu-features  -L /home/vadorovsky/repos/rust/build/x86_64-unknown-linux-gnu/stage1/lib/rustlib/bpfel-unknown-none/lib -o /home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/bpfel-unknown-none/debug/deps/atomic-0df4b88cd767cdfe -O3 --debug"
    //         03:37:58 [ INFO] LLVM command line: ["bpf-linker", "--bpf-expand-memcpy-in-order"]
    //         03:37:58 [ INFO] linking file "/tmp/rustcOZPmMX/symbols.o" type elf
    //         03:37:58 [ WARN] ignoring file "/tmp/rustcOZPmMX/symbols.o": no embedded bitcode
    //         03:37:58 [ INFO] linking file "/home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/bpfel-unknown-none/debug/deps/atomic-0df4b88cd767cdfe.atomic.9f2f50cf-cgu.0.rcgu.o" type bitcode
    //         03:37:58 [ INFO] emitting LLVMObjectFile to "/home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/bpfel-unknown-none/debug/deps/atomic-0df4b88cd767cdfe"

    // au64.compare_exchange(222, 333, Ordering::Relaxed, Ordering::Relaxed).map_err(|_| 1u32)?;
    // info!(&ctx, "au64: {}", au64.load(Ordering::Relaxed));

    // au64.compare_exchange_weak(222, 333, Ordering::Relaxed, Ordering::Relaxed).map_err(|_| 1u32)?;
    // info!(&ctx, "au64: {}", au64.load(Ordering::Relaxed));

    // The following ones fail with errors similar to:
    // = note: 04:03:23 [ERROR] fatal error: "Cannot select: 0x557ddf0cace8: i64,ch = AtomicLoad<(dereferenceable load monotonic (s64) from %ir.7)> 0x557ddf0cf320, FrameIndex:i64<5>\n  0x557ddf0cac80: i64 = FrameIndex<5>\nIn function: atomic"
    //         PLEASE submit a bug report to https://github.com/llvm/llvm-project/issues/ and include the crash backtrace.
    //         Stack dump:
    //         0.    Running pass 'Function Pass Manager' on module 'atomic-0df4b88cd767cdfe'.
    //         1.    Running pass 'BPF DAG->DAG Pattern Instruction Selection' on function '@atomic'
    //         04:03:23 [ INFO] command line: "bpf-linker --export-symbols /tmp/rustcW0LXTz/symbols /tmp/rustcW0LXTz/symbols.o /home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/bpfel-unknown-none/debug/deps/atomic-0df4b88cd767cdfe.atomic.9f2f50cf-cgu.0.rcgu.o -L /home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/bpfel-unknown-none/debug/deps -L /home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/debug/deps -L /home/vadorovsky/repos/rust/build/x86_64-unknown-linux-gnu/stage1/lib/rustlib/bpfel-unknown-none/lib --cpu generic --cpu-features  -L /home/vadorovsky/repos/rust/build/x86_64-unknown-linux-gnu/stage1/lib/rustlib/bpfel-unknown-none/lib -o /home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/bpfel-unknown-none/debug/deps/atomic-0df4b88cd767cdfe -O3 --debug"
    //         04:03:23 [ INFO] LLVM command line: ["bpf-linker", "--bpf-expand-memcpy-in-order"]
    //         04:03:23 [ INFO] linking file "/tmp/rustcW0LXTz/symbols.o" type elf
    //         04:03:23 [ WARN] ignoring file "/tmp/rustcW0LXTz/symbols.o": no embedded bitcode
    //         04:03:23 [ INFO] linking file "/home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/bpfel-unknown-none/debug/deps/atomic-0df4b88cd767cdfe.atomic.9f2f50cf-cgu.0.rcgu.o" type bitcode
    //         04:03:23 [ INFO] emitting LLVMObjectFile to "/home/vadorovsky/repos/aya-examples/atomic/atomic-ebpf/../target/bpfel-unknown-none/debug/deps/atomic-0df4b88cd767cdfe"

    // au64.fetch_add(10, Ordering::Relaxed);
    // info!(&ctx, "au64: {}", au64.load(Ordering::Relaxed));

    // au64.fetch_sub(10, Ordering::Relaxed);
    // info!(&ctx, "au64: {}", au64.load(Ordering::Relaxed));

    // au64.fetch_and(10, Ordering::Relaxed);
    // info!(&ctx, "au64: {}", au64.load(Ordering::Relaxed));

    // au64.fetch_min(23, Ordering::Relaxed);
    // info!(&ctx, "au64: {}", au64.load(Ordering::Relaxed));

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
