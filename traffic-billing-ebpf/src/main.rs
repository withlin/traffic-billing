#![no_std]
#![no_main]
#[warn(unused_imports)]
#[no_mangle]
#[link_section = "license"]
pub static LICENSE: [u8; 4] = *b"GPL\0";

use aya_bpf::cty::{c_long, c_uchar, c_ushort};
use aya_bpf::helpers::{
    bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_task, bpf_probe_read,
};
use aya_bpf::{
    macros::{kprobe, map},
    maps::{
        lpm_trie::{Key, LpmTrie},
        PerfEventArray,
    },
    programs::ProbeContext,
};

use aya_log_ebpf::warn;
#[allow(warnings)]
mod vmlinux;
use traffic_billing_common::PacketLog;
use vmlinux::{iphdr, sk_buff, sock, task_struct, udphdr};

#[map(name = "LANCIDRS")]
static mut LANLANCIDRS: LpmTrie<u32, u32> = LpmTrie::<u32, u32>::with_max_entries(1024, 1);

#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketLog> =
    PerfEventArray::<PacketLog>::with_max_entries(1024, 0);

const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const AF_INET: c_ushort = 2;
const AF_INET6: c_ushort = 10;
const IPPROTO_UDP: u8 = 17;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(C)]
pub enum EthProtocol {
    IP,
    IPv6,
    Other,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    Inbound = b'I',
    Outbound = b'O',
}

impl Direction {
    pub fn as_char(self) -> char {
        self as u8 as char
    }
}

impl EthProtocol {
    pub fn from_eth(proto: u16) -> Self {
        match proto {
            ETH_P_IP => Self::IP,
            ETH_P_IPV6 => Self::IPv6,
            _ => Self::Other,
        }
    }

    pub fn from_family(proto: c_ushort) -> Self {
        match proto {
            AF_INET => Self::IP,
            AF_INET6 => Self::IPv6,
            _ => Self::Other,
        }
    }

    pub fn is_ip(&self) -> bool {
        matches!(self, Self::IP)
    }

    pub fn is_ipv6(&self) -> bool {
        matches!(self, Self::IPv6)
    }

    pub fn is_other(&self) -> bool {
        matches!(self, Self::Other)
    }

    pub fn to_string(&self) -> &'static str {
        match self {
            Self::IP => "IP",
            Self::IPv6 => "IPv6",
            Self::Other => "UNK",
        }
    }
}

#[inline]
fn ntohs(value: u16) -> u16 {
    u16::from_be(value)
}

#[inline]
fn ntohl(value: u32) -> u32 {
    u32::from_be(value)
}

#[inline]
unsafe fn is_container_process() -> Result<bool, c_long> {
    let task = bpf_get_current_task() as *const task_struct;
    let nsproxy = bpf_probe_read(&(*task).nsproxy)?;
    let pidns = bpf_probe_read(&(*nsproxy).pid_ns_for_children)?;
    Ok(bpf_probe_read(&(*pidns).level)? > 0)
}

// struct sock with udp_sendmsg may not miss ip addresses on listening socket.
// Addresses are retrieved from struct flowi4 with ip_make_skb.
#[kprobe(name = "ip_send_skb")]
pub fn ip_send_skb(ctx: ProbeContext) -> u32 {
    match unsafe { try_ip_send_skb(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => {
            if ret != 0 {
                warn!(&ctx, "ip_send_skb failed in kernel: {}", ret);
            }
            ret as u32
        }
    }
}

#[kprobe(name = "skb_consume_udp")]
pub fn skb_consume_udp(ctx: ProbeContext) -> u32 {
    match unsafe { try_skb_consume_udp(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => {
            if ret != 0 {
                warn!(&ctx, "skb_consume_udp failed in kernel: {}", ret);
            }
            ret as u32
        }
    }
}

#[kprobe(name = "tcp_cleanup_rbuf")]
pub fn tcp_cleanup_rbuf(ctx: ProbeContext) -> u32 {
    match unsafe { try_tcp_cleanup_rbuf(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => {
            if ret != 0 {
                warn!(&ctx, "tcp_cleanup_rbuf failed in kernel: {}", ret);
            }
            ret as u32
        }
    }
}

#[kprobe(name = "tcp_sendmsg")]
pub fn tcp_sendmsg(ctx: ProbeContext) -> u32 {
    match unsafe { try_tcp_sendmsg(&ctx) } {
        Ok(ret) => ret,
        Err(ret) => {
            if ret != 0 {
                warn!(&ctx, "tcp_sendmsg failed in kernel: {}", ret);
            }
            ret as u32
        }
    }
}



unsafe fn log_packet(
    ctx: &ProbeContext,
    saddr: u32,
    daddr: u32,
    pid: u32,
    direction: Direction,
    len: u32,
) -> Result<(), c_long> {
    let comm = bpf_get_current_comm()?;
    let comm = core::mem::transmute::<_, [u8; 16]>(comm);

    let log_entry = PacketLog {
        saddr,
        daddr,
        pid,
        direction: direction.as_char(),
        len,
        command: comm,
    };
    EVENTS.output(ctx, &log_entry, 0);
    Ok(())
}

unsafe fn try_tcp_sendmsg(ctx: &ProbeContext) -> Result<u32, c_long> {
    if !is_container_process()? {
        return Ok(0);
    }

    let pid = bpf_get_current_pid_tgid() as u32;
    let sk = &*bpf_probe_read(&ctx.arg::<*const sock>(0).ok_or(1)?)?;

    let saddr = u32::from_be(bpf_probe_read(
        &sk.__sk_common
            .__bindgen_anon_1
            .__bindgen_anon_1
            .skc_rcv_saddr,
    )?);
    let daddr = u32::from_be(bpf_probe_read(
        &sk.__sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr,
    )?);
    let len = ntohs(ctx.arg(2).ok_or(1u32)?);

    let family = EthProtocol::from_family(bpf_probe_read(&sk.__sk_common.skc_family)?);
    if family.is_other() || family.is_ipv6() {
        return Ok(0);
    }

    let daddr_lookup = Key::new(32, u32::from(daddr).to_be());
    if LANCIDRS.get(&daddr_lookup).is_some() {
        return Ok(0);
    }

    log_packet(ctx, saddr, daddr, pid, Direction::Outbound, len as u32)?;
    Ok(0)
}




unsafe fn try_tcp_cleanup_rbuf(ctx: &ProbeContext) -> Result<u32, c_long> {
    if !is_container_process()? {
        return Ok(0);
    }

    let pid = bpf_get_current_pid_tgid() as u32;
    let sk = &*bpf_probe_read(&ctx.arg::<*const sock>(0).ok_or(1)?)?;

    let saddr = u32::from_be(bpf_probe_read(
        &sk.__sk_common
            .__bindgen_anon_1
            .__bindgen_anon_1
            .skc_rcv_saddr,
    )?);
    let daddr = u32::from_be(bpf_probe_read(
        &sk.__sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr,
    )?);
    let len = ntohs(ctx.arg(1).ok_or(1u32)?);

    let family = EthProtocol::from_family(bpf_probe_read(&sk.__sk_common.skc_family)?);
    if family.is_other() || family.is_ipv6() {
        return Ok(0);
    }

    let daddr_lookup = Key::new(32, u32::from(daddr).to_be());
    if LANCIDRS.get(&daddr_lookup).is_some() {
        return Ok(0);
    }

    log_packet(ctx, daddr, saddr, pid, Direction::Inbound, len as u32)?;
    Ok(0)
}

unsafe fn try_ip_send_skb(ctx: &ProbeContext) -> Result<u32, c_long> {
    if !is_container_process()? {
        return Ok(0);
    }

    let pid = bpf_get_current_pid_tgid() as u32;
    let sb: *const sk_buff = ctx.arg(1).ok_or(1u32)?;
    let protocol = bpf_probe_read(&(*sb).protocol as *const u16).map_err(|_| 100u32)?;
    if protocol as u8 != IPPROTO_UDP {
        return Ok(0);
    }

    let head = bpf_probe_read(&(*sb).head as *const *mut c_uchar).map_err(|_| 100u8)?;
    let ip_header_offset =
        bpf_probe_read(&(*sb).network_header as *const u16).map_err(|_| 100u16)?;

    let ip_hdr_ptr = head.add(ip_header_offset.into());
    let ip_hdr_new = bpf_probe_read(ip_hdr_ptr as *const iphdr).map_err(|_| 101u8)?;

    let transport_header_offset =
        bpf_probe_read(&(*sb).transport_header as *const u16).map_err(|_| 100u16)?;
    let trans_hdr_ptr = head.add(transport_header_offset as usize);
    let trans_hdr = bpf_probe_read(trans_hdr_ptr as *const udphdr).map_err(|_| 101u8)?;

    let len = ntohs(bpf_probe_read(&trans_hdr.len)?);
    let daddr_lookup = Key::new(32, u32::from(ip_hdr_new.daddr as u32).to_be());
    if LANCIDRS.get(&daddr_lookup).is_some() {
        return Ok(0);
    }

    let saddr = u32::from_be(ip_hdr_new.saddr);
    let daddr = u32::from_be(ip_hdr_new.daddr);
    log_packet(ctx, saddr, daddr, pid, Direction::Outbound, len as u32)?;
    Ok(0)
}

unsafe fn try_skb_consume_udp(ctx: &ProbeContext) -> Result<u32, c_long> {
    if !is_container_process()? {
        return Ok(0);
    }

    let pid = bpf_get_current_pid_tgid() as u32;
    let sk = &*bpf_probe_read(&ctx.arg::<*const sock>(0).ok_or(1)?)?;

    let saddr = ntohl(bpf_probe_read(
        &sk.__sk_common
            .__bindgen_anon_1
            .__bindgen_anon_1
            .skc_rcv_saddr,
    )?);
    let daddr = ntohl(bpf_probe_read(
        &sk.__sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr,
    )?);
    let len = ntohs(ctx.arg(2).ok_or(1u32)?);

    let family = EthProtocol::from_family(bpf_probe_read(&sk.__sk_common.skc_family)?);
    if family.is_other() || family.is_ipv6() {
        return Ok(0);
    }

    let saddr_lookup = Key::new(32, u32::from(daddr).to_be());
    if LANCIDRS.get(&saddr_lookup).is_some() {
        return Ok(0);
    }

    log_packet(ctx, daddr, saddr, pid, Direction::Inbound, len as u32)?;
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
