#![no_std]
#![no_main]
#![feature(const_ptr_offset_from, const_refs_to_cell)]

use core::mem;

use aya_bpf::{bindings::xdp_action, helpers::bpf_ktime_get_ns, macros::map, macros::xdp, memset, programs::XdpContext};
use aya_bpf::cty::{c_int};
use aya_bpf::maps::PerfEventArray;
use aya_log_ebpf::{info};
use crc::*;
use memoffset::offset_of;

use bindings::*;
use constants::*;
use syncookies_common::PacketLog;

#[allow(dead_code)]
#[allow(non_camel_case_types)]
mod bindings;

#[allow(dead_code)]
#[allow(non_camel_case_types)]
mod constants;


#[map(name = "EVENTS")]
static mut EVENTS: PerfEventArray<PacketLog> = PerfEventArray::<PacketLog>::with_max_entries(1024, 0);

#[xdp(name = "syncookies")]
pub fn syncookies(ctx: XdpContext) -> u32 {
    match try_syncookies(&ctx) {
        Ok(ret) => ret,
        Err(_) => {
            info!(&ctx, "abort");
            xdp_action::XDP_ABORTED
        }
    }
}

/// Return a Counter that increases every so often.
/// Currently its around 8.6 sec
#[inline(always)]
fn cookie_counter() -> u32 {
    (unsafe { bpf_ktime_get_ns() } >> 33) as u32
}

#[inline(always)]
fn process_tcp_syn<T: EthernetProtocol>(ctx: &XdpContext, t: &FourTuple<T>) -> Result<u32, ()> {
    let tcp: *mut tcphdr = unsafe { mut_ptr_at(ctx, ETH_HDR_LEN + T::HEADER_LENGTH)? };

    info!(ctx, "before: cookie {}", u32::from_be(unsafe { *ptr_at(ctx, ETH_HDR_LEN + T::HEADER_LENGTH + offset_of!(tcphdr, seq))? }));

    /* Create SYN-ACK with cookie */
    // let cookie = t.crc32();
    let cookie = 0; //TODO: FIX CRC32 to work with ebpf
    unsafe {
        (*tcp).ack_seq = (u32::from_be((*tcp).seq) + 1).to_be();
        (*tcp).seq = cookie;
        (*tcp).set_ack(1);
    }

    info!(ctx, "after: cookie {}", u32::from_be(unsafe { *ptr_at(ctx, ETH_HDR_LEN + T::HEADER_LENGTH + offset_of!(tcphdr, seq))? }));

    unsafe { swap_addresses::<T>(ctx)?; }

    Ok(xdp_action::XDP_TX)
}

#[inline(always)]
unsafe fn swap_addresses<T: EthernetProtocol>(ctx: &XdpContext) -> Result<(), ()> {
    let eth: *mut ethhdr = mut_ptr_at(ctx, 0)?;
    let ip: *mut iphdr = mut_ptr_at(ctx, ETH_HDR_LEN)?;
    let tcp: *mut tcphdr = mut_ptr_at(ctx, ETH_HDR_LEN + T::HEADER_LENGTH)?;

    let ip_len = ((*ip).ihl() * 4) as u32;
    if ip_len > MAX_CSUM_BYTES {
        return Err(())
    }

    let tcp_len = ((*tcp).doff() * 4) as u32;
    if tcp_len > MAX_CSUM_BYTES {
        return Err(())
    }

    let tmp_source = (*tcp).source;
    (*tcp).source = (*tcp).dest;
    (*tcp).dest = tmp_source;

    /* Reverse IP direction */
    let tmp_source = (*ip).saddr;
    (*ip).saddr = (*ip).daddr;
    (*ip).daddr = tmp_source;

    /* Reverse Ethernet direction */
    let tmp_source = (*eth).h_source;
    (*eth).h_source = (*eth).h_dest;
    (*eth).h_dest = tmp_source;

    /* Clear IP options */
    memset(mut_ptr_at(ctx, ETH_HDR_LEN + 1)?, (ip_len as usize - IP_HDR_LEN) as c_int, 0);

    /* Update IP checksum */
    (*ip).check = 0;
    (*ip).check = carry(sum16(ctx, ETH_HDR_LEN, ip_len as usize));

    /* Update TCP checksum */
    (*tcp).check = 0;
    let mut tcp_csum: u32 = 0;
    tcp_csum += sum16_32((*ip).saddr);
    tcp_csum += sum16_32((*ip).daddr);
    tcp_csum += 0x0600;
    tcp_csum += tcp_len << 8;
    tcp_csum += sum16(ctx, ETH_HDR_LEN + T::HEADER_LENGTH, tcp_len as usize);
    (*tcp).check = carry(tcp_csum);

    Ok(())
}

const MAX_CSUM_WORDS: u32 = 32;
const MAX_CSUM_BYTES: u32 = MAX_CSUM_WORDS * 2;

/// Calculate sum of 16-bit words from `data` of `size` bytes,
/// Size is assumed to be even, from 0 to MAX_CSUM_BYTES.
#[inline(always)]
fn sum16(ctx: &XdpContext, offset: usize, size: usize) -> u32 {
    let start = ctx.data();
    let end = ctx.data_end();

    let mut s: u32 = 0;
    for i in 0..MAX_CSUM_WORDS {
        let pos = start + offset + 2 * i as usize;
        if 2 * i as usize >= size {
            /* normal exit */
            return s;
        }

        if pos + 1 + 1 > end {
            return 0; /* should be unreachable */
        }

        s += unsafe { *(pos as *const u16) } as u32;
    }

    s
}

/// A handy version of `sum16()` for 32-bit words.
/// Does not actually conserve any instructions.
#[inline(always)]
fn sum16_32(v: u32) -> u32 {
    (v >> 16) + (v & 0xffff)
}

/// Carry upper bits and compute one's complement for a checksum.
#[inline(always)]
fn carry(csum: u32) -> u16 {
    let csum = (csum & 0xffff) + (csum >> 16);
    let csum = (csum & 0xffff) + (csum >> 16);
    !csum as u16
}

#[inline(always)]
fn process_tcp_ack<T: EthernetProtocol>(ctx: &XdpContext, x: &FourTuple<T>) -> Result<u32, ()> {
    //TODO: Handle ACK
    Ok(xdp_action::XDP_PASS)
}

fn read_ip<T: EthernetProtocol>(ctx: &XdpContext) -> Result<u32, ()> {
    let ip_proto = u8::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + T::PROTOCOL_OFFSET)? });

    // We only care about TCP
    if ip_proto != IPPROTO_TCP {
        return Ok(xdp_action::XDP_PASS);
    }

    let tuple = FourTuple {
        src_address: T::read_source_address(&ctx)?,
        dst_address: T::read_destination_address(&ctx)?,
        src_port: u16::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, source))? }),
        dst_port: u16::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + IP_HDR_LEN + offset_of!(tcphdr, dest))? }),
    };
    // info!(&ctx, "tuple {} {} {} {}", tuple.src_port, tuple.dst_port, tuple.src_address, tuple.dst_address);

    let flags = u16::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + T::HEADER_LENGTH + offset_of!(tcphdr, _bitfield_1))? });
    match flags & (TH_SYN | TH_ACK) {
        TH_SYN => process_tcp_syn::<T>(&ctx, &tuple),
        TH_ACK => process_tcp_ack::<T>(&ctx, &tuple),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

fn try_syncookies(ctx: &XdpContext) -> Result<u32, ()> {
    let eth_proto = u16::from_be(unsafe { *ptr_at(ctx, offset_of!(ethhdr, h_proto))? });

    let action = match eth_proto {
        ETH_P_IP => read_ip::<V4>(ctx)?,
        ETH_P_IPV6 => read_ip::<V6>(ctx)?,
        _ => return Ok(xdp_action::XDP_PASS)
    };

    // let log_entry = PacketLog {
    //     protocol: u32::from(eth_proto),
    //     action,
    // };

    // unsafe {
    //     EVENTS.output(ctx, &log_entry, 0);
    // }

    Ok(action)
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
unsafe fn mut_ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

trait EthernetProtocol {
    const PROTOCOL_OFFSET: usize;
    const HEADER_LENGTH: usize;
    type AddressSize: Copy;
    fn read_source_address(ctx: &XdpContext) -> Result<Self::AddressSize, ()>;
    fn read_destination_address(ctx: &XdpContext) -> Result<Self::AddressSize, ()>;
    fn crc32(digest: &mut Digest<u32>, address: Self::AddressSize);
}

struct V4;

struct V6;

impl EthernetProtocol for V4 {
    const PROTOCOL_OFFSET: usize = offset_of!(iphdr, protocol);
    const HEADER_LENGTH: usize = IP_HDR_LEN;
    type AddressSize = u32;

    #[inline(always)]
    fn read_source_address(ctx: &XdpContext) -> Result<Self::AddressSize, ()> {
        Ok(u32::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, saddr))? }))
    }

    #[inline(always)]
    fn read_destination_address(ctx: &XdpContext) -> Result<Self::AddressSize, ()> {
        Ok(u32::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(iphdr, daddr))? }))
    }

    fn crc32(digest: &mut Digest<u32>, address: Self::AddressSize) {
        digest.update(&address.to_be_bytes())
    }
}

impl EthernetProtocol for V6 {
    const PROTOCOL_OFFSET: usize = offset_of!(ipv6hdr, nexthdr);
    const HEADER_LENGTH: usize = IPV6_HDR_LEN;
    type AddressSize = u128;

    #[inline(always)]
    fn read_source_address(ctx: &XdpContext) -> Result<Self::AddressSize, ()> {
        Ok(u128::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(ipv6hdr, saddr))? }))
    }

    #[inline(always)]
    fn read_destination_address(ctx: &XdpContext) -> Result<Self::AddressSize, ()> {
        Ok(u128::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + offset_of!(ipv6hdr, daddr))? }))
    }

    fn crc32(digest: &mut Digest<u32>, address: Self::AddressSize) {
        digest.update(&address.to_be_bytes())
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct FourTuple<T: EthernetProtocol> {
    pub src_address: T::AddressSize,
    pub dst_address: T::AddressSize,
    pub src_port: u16,
    pub dst_port: u16,
}

const CRC32: Crc<u32> = Crc::<u32>::new(&crc::CRC_32_CKSUM);
const COOKIE_SEED: u32 = 42;

impl<T: EthernetProtocol> FourTuple<T> {
    #[inline(always)]
    fn crc32(&self) -> u32 {
        let mut digest = CRC32.digest();
        T::crc32(&mut digest, self.src_address);
        T::crc32(&mut digest, self.dst_address);
        digest.update(&self.src_port.to_be_bytes());
        digest.update(&self.dst_port.to_be_bytes());
        digest.finalize()
    }
}

