#![no_std]

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PacketLog {
    pub protocol: u32,
    pub action: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
