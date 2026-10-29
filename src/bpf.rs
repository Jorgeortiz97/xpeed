//! Embedded BPF objects and the userspace mirrors of `src/bpf/common.h`.

use std::{io, os::fd::RawFd};

use anyhow::{Context, Result};
use aya::{
    Ebpf, Pod,
    programs::{Xdp, XdpFlags},
};
use clap::ValueEnum;

pub static TX_OBJ: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/tx.bpf.o"));
pub static RX_OBJ: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/rx.bpf.o"));

pub const MAX_STREAMS: usize = 256;
pub const MAX_VLANS: usize = 2;
pub const HDR_LEN: usize = 18;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TxStream {
    pub packets: u64,
    _pad: [u64; 7],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TxXmit {
    pub sent: u64,
    pub drops: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RxStream {
    pub packets: u64,
    pub next_seq: u64,
    pub out_of_order: u64,
    pub jitter: u64,
    pub last_transit: i64,
}

impl RxStream {
    pub fn jitter_ns(&self) -> f64 {
        self.jitter as f64 / 16.0
    }
}

unsafe impl Pod for TxStream {}
unsafe impl Pod for TxXmit {}
unsafe impl Pod for RxStream {}

pub fn load_xdp<'a>(ebpf: &'a mut Ebpf, name: &str) -> Result<&'a mut Xdp> {
    let prog: &mut Xdp = ebpf.program_mut(name).unwrap().try_into()?;
    prog.load().with_context(|| format!("loading {name}"))?;
    Ok(prog)
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Mode {
    /// Native if the driver supports it, generic otherwise
    Auto,
    /// In the driver
    Native,
    /// Generic, in the network stack (slow; testing only)
    Skb,
}

impl Mode {
    pub fn flags(self) -> XdpFlags {
        match self {
            Mode::Auto => XdpFlags::default(),
            Mode::Native => XdpFlags::DRV_MODE,
            Mode::Skb => XdpFlags::SKB_MODE,
        }
    }
}

/// `union bpf_attr` as used by BPF_PROG_TEST_RUN. The kernel rejects nonzero
/// bytes past `batch_size`, so the tail padding is an explicit, zeroed field.
#[repr(C)]
#[derive(Default)]
struct TestRunAttr {
    prog_fd: u32,
    retval: u32,
    data_size_in: u32,
    data_size_out: u32,
    data_in: u64,
    data_out: u64,
    repeat: u32,
    duration: u32,
    ctx_size_in: u32,
    ctx_size_out: u32,
    ctx_in: u64,
    ctx_out: u64,
    flags: u32,
    cpu: u32,
    batch_size: u32,
    _pad: u32,
}

const BPF_PROG_TEST_RUN: libc::c_long = 10;
const BPF_F_TEST_XDP_LIVE_FRAMES: u32 = 1 << 1;

/// Runs an XDP program `repeat` times over `frame` in live-frames mode, so its
/// redirects really transmit (Linux >= 5.18).
pub fn xdp_run_live(prog: RawFd, frame: &[u8], repeat: u32) -> io::Result<()> {
    let mut attr = TestRunAttr {
        prog_fd: prog as u32,
        data_size_in: frame.len() as u32,
        data_in: frame.as_ptr() as u64,
        repeat,
        flags: BPF_F_TEST_XDP_LIVE_FRAMES,
        ..Default::default()
    };
    let size = size_of::<TestRunAttr>();
    // The kernel writes retval and duration back.
    match unsafe { libc::syscall(libc::SYS_bpf, BPF_PROG_TEST_RUN, &mut attr as *mut TestRunAttr, size) } {
        0 => Ok(()),
        _ => Err(io::Error::last_os_error()),
    }
}
