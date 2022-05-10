use core::mem;
use crate::{ethhdr, iphdr, ipv6hdr, tcphdr};

pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_IPV6: u16 = 0x86DD;
pub const ETH_HDR_LEN: usize = mem::size_of::<ethhdr>();
pub const IP_HDR_LEN: usize = mem::size_of::<iphdr>();
pub const IPV6_HDR_LEN: usize = mem::size_of::<ipv6hdr>();
pub const TCP_HDR_LEN: usize = mem::size_of::<tcphdr>();
pub const IPPROTO_TCP: u8 = 6;


pub const TH_FIN: u16 =  0x01;
pub const TH_SYN: u16 =  0x02;
pub const TH_RST: u16 =  0x04;
pub const TH_PUSH: u16 = 0x08;
pub const TH_ACK: u16 =  0x10;
pub const TH_URG: u16 =  0x20;
pub const TH_ECE: u16 =  0x40;
pub const TH_CWR: u16 =  0x80;
