use std::{mem, net::Ipv4Addr, ptr};

use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::perf::AsyncPerfEventArray,
    programs::{Xdp, XdpFlags},
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use clap::Parser;
use log::info;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use tokio::signal;

use xdp_perfbuf_common::PacketBuffer;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/xdp-perfbuf"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/xdp-perfbuf"
    ))?;
    let program: &mut Xdp = bpf.program_mut("xdp_perfbuf").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    let mut events = AsyncPerfEventArray::try_from(bpf.map_mut("DATA")?)?;
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;

        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(9000))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    let buf = &mut buffers[i];

                    let hdr = unsafe { ptr::read_unaligned(buf.as_ptr() as *const PacketBuffer) };
                    let pkt_buf = buf.split().freeze().slice(
                        mem::size_of::<PacketBuffer>()..mem::size_of::<PacketBuffer>() + hdr.size,
                    );
                    info!("Received packet of size {}", hdr.size);

                    let ethhdr = pkt_buf.slice(..EthHdr::LEN);
                    let ethhdr = unsafe { ptr::read_unaligned(ethhdr.as_ptr() as *const EthHdr) };
                    match ethhdr.ether_type {
                        EtherType::Ipv4 => {}
                        _ => continue,
                    }

                    let ipv4hdr = pkt_buf.slice(EthHdr::LEN..EthHdr::LEN + Ipv4Hdr::LEN);
                    let ipv4hdr =
                        unsafe { ptr::read_unaligned(ipv4hdr.as_ptr() as *const Ipv4Hdr) };

                    let src_addr = u32::from_be(ipv4hdr.src_addr);
                    let src_addr = Ipv4Addr::from(src_addr);

                    let src_port = match ipv4hdr.proto {
                        IpProto::Tcp => {
                            let tcphdr = pkt_buf.slice(
                                EthHdr::LEN + Ipv4Hdr::LEN
                                    ..EthHdr::LEN + Ipv4Hdr::LEN + TcpHdr::LEN,
                            );
                            let tcphdr =
                                unsafe { ptr::read_unaligned(tcphdr.as_ptr() as *const TcpHdr) };
                            u16::from_be(tcphdr.source)
                        }
                        IpProto::Udp => {
                            let udphdr = pkt_buf.slice(
                                EthHdr::LEN + Ipv4Hdr::LEN
                                    ..EthHdr::LEN + Ipv4Hdr::LEN + UdpHdr::LEN,
                            );
                            let udphdr =
                                unsafe { ptr::read_unaligned(udphdr.as_ptr() as *const UdpHdr) };
                            u16::from_be(udphdr.source)
                        }
                        _ => continue,
                    };

                    info!("source address: {:?}, source port: {}", src_addr, src_port);
                }
            }
        });
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
