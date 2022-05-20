#![no_std]
#![no_main]
#![feature(const_ptr_offset_from, const_refs_to_cell)]

use core::mem;

use aya_bpf::{
    bindings::xdp_action, helpers::bpf_ktime_get_ns, macros::map, macros::xdp, memset,
    programs::XdpContext,
};
use aya_bpf::cty::c_int;
use aya_bpf::maps::PerfEventArray;
use aya_log_ebpf::info;
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
static mut EVENTS: PerfEventArray<PacketLog> =
    PerfEventArray::<PacketLog>::with_max_entries(1024, 0);

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
fn process_tcp_syn<T: IPProtocol>(ctx: &XdpContext, t: &FourTuple<T>) -> Result<u32, ()> {
    let tcp: *mut tcphdr = T::tcp(ctx)?;

    info!(
        ctx,
        "before: cookie {}",
        u32::from_be(unsafe {
            *ptr_at(
                ctx,
                ETH_HDR_LEN + T::HEADER_LENGTH + offset_of!(tcphdr, seq),
            )?
        })
    );

    /* Create SYN-ACK with cookie */
    let cookie = t.crc32();
    unsafe {
        (*tcp).ack_seq = (u32::from_be((*tcp).seq) + 1).to_be();
        (*tcp).seq = cookie;
        (*tcp).set_ack(1);
    }

    info!(
        ctx,
        "after: cookie {}",
        u32::from_be(unsafe {
            *ptr_at(
                ctx,
                ETH_HDR_LEN + T::HEADER_LENGTH + offset_of!(tcphdr, seq),
            )?
        })
    );

    unsafe {
        swap_addresses::<T>(ctx)?;
    }

    info!(ctx, "OK TX");
    Ok(xdp_action::XDP_TX)
}

#[inline(always)]
unsafe fn swap_addresses<T: IPProtocol>(ctx: &XdpContext) -> Result<(), ()> {
    let eth = T::eth(ctx)?;
    let ip = T::ip(ctx)?;
    let tcp = T::tcp(ctx)?;

    if (*ip).header_length() > MAX_CSUM_BYTES {
        return Err(());
    }

    let tcp_len = ((*tcp).doff() * 4) as u32;
    if tcp_len > MAX_CSUM_BYTES {
        return Err(());
    }

    let tmp_source = (*tcp).source;
    (*tcp).source = (*tcp).dest;
    (*tcp).dest = tmp_source;

    /* Reverse IP direction */
    (*ip).swap_address();

    /* Reverse Ethernet direction */
    (*eth).swap_address();

    /* Update IP checksum */
    (*ip).update_checksum(ctx);

    /* Update TCP checksum */
    (*tcp).check = 0;
    let mut tcp_csum: u32 = 0;
    tcp_csum += T::IPHeader::sum16((*ip).source_address());
    tcp_csum += T::IPHeader::sum16((*ip).destination_address());
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

/// Carry upper bits and compute one's complement for a checksum.
#[inline(always)]
fn carry(csum: u32) -> u16 {
    let csum = (csum & 0xffff) + (csum >> 16);
    let csum = (csum & 0xffff) + (csum >> 16);
    !csum as u16
}

#[inline(always)]
fn process_tcp_ack<T: IPProtocol>(ctx: &XdpContext, x: &FourTuple<T>) -> Result<u32, ()> {
    //TODO: Handle ACK
    Ok(xdp_action::XDP_PASS)
}

fn read_ip<T: IPProtocol<IPHeader=T>>(ctx: &XdpContext) -> Result<u32, ()> {
    let ip_proto = u8::from_be(unsafe { *ptr_at(&ctx, ETH_HDR_LEN + T::PROTOCOL_OFFSET)? });

    // We only care about TCP
    if ip_proto != IPPROTO_TCP {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip = T::ip(&ctx)?;
    let tuple = FourTuple {
        src_address: unsafe { (*ip).source_address() },
        dst_address: unsafe { (*ip).destination_address() },
        src_port: u16::from_be(unsafe {
            *ptr_at(&ctx, ETH_HDR_LEN + T::HEADER_LENGTH + offset_of!(tcphdr, source))?
        }),
        dst_port: u16::from_be(unsafe {
            *ptr_at(&ctx, ETH_HDR_LEN + T::HEADER_LENGTH + offset_of!(tcphdr, dest))?
        }),
    };
    // info!(&ctx, "tuple {} {} {} {}", tuple.src_port, tuple.dst_port, tuple.src_address, tuple.dst_address);

    let flags = u16::from_be(unsafe {
        *ptr_at(
            &ctx,
            ETH_HDR_LEN + T::HEADER_LENGTH + offset_of!(tcphdr, _bitfield_1),
        )?
    });
    match flags & (TH_SYN | TH_ACK) {
        TH_SYN => process_tcp_syn::<T>(&ctx, &tuple),
        TH_ACK => process_tcp_ack::<T>(&ctx, &tuple),
        _ => Ok(xdp_action::XDP_PASS),
    }
}

fn try_syncookies(ctx: &XdpContext) -> Result<u32, ()> {
    let eth_proto = u16::from_be(unsafe { *ptr_at(ctx, offset_of!(ethhdr, h_proto))? });

    let action = match eth_proto {
        ETH_P_IP => read_ip::<iphdr>(ctx)?,
        ETH_P_IPV6 => read_ip::<ipv6hdr>(ctx)?,
        _ => return Ok(xdp_action::XDP_PASS),
    };

    // let log_entry = PacketLog {
    //     protocol: u32::from(eth_proto),
    //     action,
    // };
    //
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

trait IPProtocol {
    const PROTOCOL_OFFSET: usize;
    const HEADER_LENGTH: usize = mem::size_of::<Self::IPHeader>();
    type AddressSize: Copy;
    type IPHeader: IPProtocol + UpdateChecksum + Swappable;

    fn source_address(&self) -> Self::AddressSize;
    fn destination_address(&self) -> Self::AddressSize;
    fn header_length(&self) -> u32;

    /// A handy version of `sum16()` for Self::AddressSize-bit words.
    /// Does not actually conserve any instructions.
    fn sum16(v: Self::AddressSize) -> u32;

    fn crc32(digest: &mut Digest<u32>, address: Self::AddressSize);

    fn eth(ctx: &XdpContext) -> Result<*mut ethhdr, ()> {
        unsafe { mut_ptr_at(ctx, 0) }
    }
    fn ip(ctx: &XdpContext) -> Result<*mut Self::IPHeader, ()> {
        unsafe { mut_ptr_at(ctx, ETH_HDR_LEN) }
    }
    fn tcp(ctx: &XdpContext) -> Result<*mut tcphdr, ()> {
        unsafe { mut_ptr_at(ctx, ETH_HDR_LEN + Self::HEADER_LENGTH) }
    }
}

impl IPProtocol for iphdr {
    const PROTOCOL_OFFSET: usize = offset_of!(iphdr, protocol);
    type AddressSize = u32;
    type IPHeader = iphdr;

    fn source_address(&self) -> Self::AddressSize {
        self.saddr
    }

    fn destination_address(&self) -> Self::AddressSize {
        self.daddr
    }

    fn header_length(&self) -> u32 {
        self.ihl() as u32 * 4
    }

    fn sum16(v: Self::AddressSize) -> u32 {
        (v >> 16) + (v & 0xffff)
    }

    fn crc32(digest: &mut Digest<u32>, address: Self::AddressSize) {
        digest.update(&address.to_be_bytes())
    }
}

impl IPProtocol for ipv6hdr {
    const PROTOCOL_OFFSET: usize = offset_of!(ipv6hdr, nexthdr);
    type AddressSize = u128;
    type IPHeader = ipv6hdr;

    fn source_address(&self) -> Self::AddressSize {
        unsafe { u128::from_be_bytes(self.saddr.in6_u.u6_addr8) }
    }

    fn destination_address(&self) -> Self::AddressSize {
        unsafe { u128::from_be_bytes(self.daddr.in6_u.u6_addr8) }
    }

    fn header_length(&self) -> u32 {
        mem::size_of::<Self::IPHeader>() as u32
    }

    fn sum16(v: Self::AddressSize) -> u32 {
        ((v >> 32) + (v & 0xffffffff) + (v >> 16) + (v & 0xffff)) as u32
    }

    fn crc32(digest: &mut Digest<u32>, address: Self::AddressSize) {
        digest.update(&address.to_be_bytes())
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
struct FourTuple<T: IPProtocol> {
    pub src_address: T::AddressSize,
    pub dst_address: T::AddressSize,
    pub src_port: u16,
    pub dst_port: u16,
}

const CRC32: Crc<u32> = Crc::<u32>::new(&crc::CRC_32_CKSUM);
const COOKIE_SEED: u32 = 42;

impl<T: IPProtocol> FourTuple<T> {
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


// -----------------------------

trait UpdateChecksum {
    fn update_checksum(&mut self, ctx: &XdpContext) {}
}

impl UpdateChecksum for iphdr {
    fn update_checksum(&mut self, ctx: &XdpContext) {
        /* Clear IP options */
        unsafe {
            memset(
                mut_ptr_at(ctx, ETH_HDR_LEN + 1).unwrap(),
                (self.header_length() as usize - mem::size_of::<iphdr>()) as c_int,
                0,
            )
        };

        self.check = 0;

        let check = sum16(ctx, ETH_HDR_LEN, self.header_length() as usize);
        let check = carry(check);
        self.check = check;
    }
}

impl UpdateChecksum for ipv6hdr {}

// -----------------------------

trait Swappable {
    fn swap_address(&mut self);
}

impl Swappable for iphdr {
    fn swap_address(&mut self) {
        unsafe {
            let tmp_source = self.saddr;
            self.saddr = self.daddr;
            self.daddr = tmp_source;
        }
    }
}

impl Swappable for ipv6hdr {
    fn swap_address(&mut self) {
        unsafe {
            let tmp_source = self.saddr;
            self.saddr = self.daddr;
            self.daddr = tmp_source;
        }
    }
}

impl Swappable for ethhdr {
    fn swap_address(&mut self) {
        unsafe {
            let tmp_source = self.h_source;
            self.h_source = self.h_dest;
            self.h_dest = tmp_source;
        }
    }
}
