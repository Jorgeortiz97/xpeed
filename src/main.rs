mod bpf;
mod client;
mod net;
mod packet;
mod proto;
mod report;
mod server;

use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

use clap::{Parser, Subcommand};
use nix::sys::{
    resource::{RLIM_INFINITY, Resource, setrlimit},
    signal::{SigHandler, Signal, signal},
};

use crate::bpf::Mode;

/// High-performance network benchmarking powered by XDP
#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Receive: count and drop test traffic in an XDP program
    Server {
        #[command(flatten)]
        args: server::Args,
        #[command(flatten)]
        common: Common,
    },
    /// Send: generate UDP test traffic with XDP live frames
    Client {
        #[command(flatten)]
        args: client::Args,
        #[command(flatten)]
        common: Common,
    },
}

#[derive(clap::Args)]
pub struct Common {
    /// TCP control and UDP data port
    #[arg(short, long, default_value_t = 5301)]
    pub port: u16,
    /// XDP attach mode (on the client: of the helper program on the egress interface)
    #[arg(short, long, value_enum, default_value_t = Mode::Auto)]
    pub mode: Mode,
    /// Seconds between periodic reports
    #[arg(short, long, default_value_t = 1.0, value_parser = seconds)]
    pub interval: f64,
}

/// Longest test or report interval, as in iperf3.
pub const MAX_SECONDS: f64 = 86400.0;

/// Set by SIGINT/SIGTERM while `catch_signals(true)` is in effect.
pub static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Relaxed);
}

/// Makes SIGINT and SIGTERM set `STOP`, or restores their default action.
pub fn catch_signals(catch: bool) -> anyhow::Result<()> {
    let handler = if catch { SigHandler::Handler(on_signal) } else { SigHandler::SigDfl };
    for sig in [Signal::SIGINT, Signal::SIGTERM] {
        unsafe { signal(sig, handler) }?;
    }
    Ok(())
}

fn positive(s: &str) -> Result<f64, String> {
    s.parse()
        .ok()
        .filter(|v: &f64| v.is_finite() && *v > 0.0)
        .ok_or_else(|| format!("'{s}' is not a positive number"))
}

fn seconds(s: &str) -> Result<f64, String> {
    positive(s).and_then(|v| if v <= MAX_SECONDS { Ok(v) } else { Err(format!("'{s}' is more than a day")) })
}

fn main() -> anyhow::Result<()> {
    // Kernels before 5.11 charge BPF maps against RLIMIT_MEMLOCK.
    let _ = setrlimit(Resource::RLIMIT_MEMLOCK, RLIM_INFINITY, RLIM_INFINITY);
    match Cli::parse().cmd {
        Cmd::Server { args, common } => server::run(args, common),
        Cmd::Client { args, common } => client::run(args, common),
    }
}
