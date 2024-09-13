#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PacketLog {
    pub saddr: u32,
    pub daddr: u32,
    pub len: u32,
    pub pid: u32,
    pub direction: char,
    pub command: [u8; 16],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
