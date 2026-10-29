//! Sender: replays one template frame per stream through xpeed_tx with
//! BPF_PROG_RUN live frames, from a pinned thread per stream.

use std::{
    fs, io,
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    os::{
        fd::{AsFd, AsRawFd, RawFd},
        unix::fs::MetadataExt,
    },
    str::FromStr,
    sync::atomic::{AtomicUsize, Ordering::Relaxed},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use aya::{
    Btf, Ebpf, EbpfLoader,
    maps::{Array, MapData, PerCpuArray},
    programs::BtfTracePoint,
};
use nix::{
    sched::{CpuSet, sched_getaffinity, sched_setaffinity},
    sys::signal::{SigHandler, Signal, signal},
    unistd::Pid,
};
use socket2::{Domain, Socket, Type};

use crate::{
    Common, STOP,
    bpf::{self, MAX_STREAMS, MAX_VLANS, Mode, TX_OBJ, TxStream, TxXmit},
    catch_signals,
    net::{self, Bind, Mac, parse_mac},
    packet::{self, Flow, VlanProto},
    proto::{Conn, Hello, Msg, VERSION},
    report::{Report, SI, StreamReport, si, tx_header, tx_line},
};

/// Packets per BPF_PROG_RUN call when not rate limited: a few ms of work.
const CHUNK: u64 = 1 << 16;
/// Rate-limited calls carry at least this much traffic: each call sets up a
/// page pool, too costly for a handful of frames.
const MIN_BATCH_SECS: f64 = 1e-3;
/// Longest sleep between checks for the deadline and Ctrl-C.
const MAX_SLEEP: Duration = Duration::from_millis(50);

#[derive(clap::Args)]
pub struct Args {
    /// Server address or hostname
    target: String,
    /// Local address or interface to send from
    #[arg(short = 'B', long)]
    bind: Option<Bind>,
    /// Test duration in seconds
    #[arg(short = 't', long = "time", default_value_t = 10.0, value_parser = crate::seconds)]
    duration: f64,
    /// Ethernet frame size in bytes, FCS included [default: the minimum, 64 for IPv4 and 84 for IPv6, +4 per VLAN tag]
    #[arg(short, long)]
    size: Option<usize>,
    /// Total target bitrate in bit/s, frames with FCS (k/M/G/T suffixes) [default: the line rate]
    #[arg(short, long, value_parser = parse_rate, conflicts_with = "pps")]
    bitrate: Option<f64>,
    /// Total target packet rate (k/M/G/T suffixes)
    #[arg(long, value_parser = parse_rate)]
    pps: Option<f64>,
    /// Number of parallel streams, each sent by its own thread and CPU
    #[arg(short = 'P', long, default_value_t = 1, conflicts_with = "cpus")]
    parallel: usize,
    /// CPUs to send from, one stream each (e.g. 2,4-7)
    #[arg(long)]
    cpus: Option<CpuList>,
    /// UDP source port of stream 0; stream N uses this + N
    #[arg(long, default_value_t = 49152)]
    src_port: u16,
    /// Next-hop MAC address, when it is not in the neighbour table
    #[arg(long, value_parser = parse_mac)]
    dst_mac: Option<Mac>,
    /// VLAN IDs to tag frames with, outer first (100, or 100,200 for QinQ)
    #[arg(long, value_delimiter = ',', value_parser = clap::value_parser!(u16).range(1..=4094))]
    vlan: Vec<u16>,
    /// Protocol of the outer VLAN tag; inner tags are 802.1Q
    #[arg(long, value_enum, default_value_t = VlanProto::Dot1Q, requires = "vlan")]
    vlan_proto: VlanProto,
    /// IPv4 TOS / IPv6 traffic class byte, ECN bits included (e.g. 0xb8)
    #[arg(short = 'S', long, value_parser = |s: &str| number(s, 0xff).map(|v| v as u8), conflicts_with = "dscp")]
    tos: Option<u8>,
    /// DSCP, 0-63 or a name: ef, af11-af43, cs0-cs7, va, le
    #[arg(long, value_parser = parse_dscp)]
    dscp: Option<u8>,
    /// IPv4 TTL / IPv6 hop limit
    #[arg(long, default_value_t = 64, value_parser = clap::value_parser!(u8).range(1..))]
    ttl: u8,
    /// IPv6 flow label
    #[arg(short = 'L', long, default_value_t = 0, value_parser = |s: &str| number(s, 0xfffff))]
    flowlabel: u32,
    /// Print the final report as JSON instead of text
    #[arg(short = 'J', long)]
    json: bool,
}

#[derive(Clone)]
struct CpuList(Vec<usize>);

impl FromStr for CpuList {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let mut cpus = vec![];
        for part in s.split(',') {
            let (a, b) = part.split_once('-').unwrap_or((part, part));
            match (a.trim().parse::<usize>(), b.trim().parse::<usize>()) {
                (Ok(a), Ok(b)) if a <= b => cpus.extend(a..=b),
                _ => return Err(format!("invalid CPU list '{s}'")),
            }
        }
        cpus.sort_unstable();
        cpus.dedup();
        Ok(CpuList(cpus))
    }
}

/// A decimal or 0x-prefixed hexadecimal number up to `max`.
fn number(s: &str, max: u32) -> Result<u32, String> {
    match s.strip_prefix("0x") {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
    .filter(|&v| v <= max)
    .ok_or_else(|| format!("'{s}' is not a number from 0 to {max} ({max:#x})"))
}

/// The TOS byte for a DSCP given as a number or a name.
fn parse_dscp(s: &str) -> Result<u8, String> {
    let dscp = match s.to_ascii_lowercase().as_bytes() {
        [b'c', b's', n @ b'0'..=b'7'] => (n - b'0') * 8,
        [b'a', b'f', class @ b'1'..=b'4', drop @ b'1'..=b'3'] => (class - b'0') * 8 + (drop - b'0') * 2,
        b"ef" => 46,
        b"va" => 44,
        b"le" => 1,
        _ => number(s, 63)? as u8,
    };
    Ok(dscp << 2)
}

fn parse_rate(s: &str) -> Result<f64, String> {
    let (num, mult) = SI
        .iter()
        .find_map(|&(p, m)| Some((s.strip_suffix(|c: char| c.eq_ignore_ascii_case(&p))?, m)))
        .unwrap_or((s, 1.0));
    crate::positive(num).map(|v| v * mult)
}

/// The requested CPUs, or the first `n` this process may run on.
fn pick_cpus(requested: Option<CpuList>, n: usize) -> Result<Vec<usize>> {
    let set = sched_getaffinity(Pid::from_raw(0))?;
    let allowed: Vec<_> = (0..CpuSet::count()).filter(|&c| set.is_set(c).unwrap_or(false)).collect();
    match requested {
        Some(CpuList(cpus)) => match cpus.iter().find(|c| !allowed.contains(c)) {
            Some(c) => bail!("CPU {c} is not available to this process"),
            None => Ok(cpus),
        },
        None => {
            ensure!(allowed.len() >= n, "{n} streams need {n} CPUs, only {} available", allowed.len());
            Ok(allowed[..n].to_vec())
        }
    }
}

fn connect(target: SocketAddr, bind: Option<&Bind>) -> Result<TcpStream> {
    let sock = Socket::new(Domain::for_address(target), Type::STREAM, None)?;
    match bind {
        Some(Bind::Addr(ip)) => sock.bind(&SocketAddr::new(*ip, 0).into())?,
        Some(Bind::Iface(name, _)) => sock.bind_device(Some(name.as_bytes()))?,
        None => {}
    }
    sock.connect_timeout(&target.into(), Duration::from_secs(5))
        .with_context(|| format!("connecting to {target}"))?;
    Ok(sock.into())
}

fn attach_xmit(ebpf: &mut Ebpf, btf: Option<&Btf>) -> Result<()> {
    let btf = btf.context("no kernel BTF")?;
    for (prog, tracepoint) in [("xpeed_xmit", "xdp_devmap_xmit"), ("xpeed_redirect_err", "xdp_redirect_err")] {
        let tp: &mut BtfTracePoint = ebpf.program_mut(prog).unwrap().try_into()?;
        tp.load(tracepoint, btf)?;
        tp.attach()?;
    }
    Ok(())
}

/// The loaded sender programs and their per-stream counters.
struct Tx {
    _ebpf: Ebpf,
    /// xpeed_tx, for BPF_PROG_RUN.
    prog: RawFd,
    streams: Array<MapData, TxStream>,
    /// `None` when the XDP tracepoints can't be traced.
    xmit: Option<PerCpuArray<MapData, TxXmit>>,
    cpus: Vec<usize>,
}

impl Tx {
    fn load(ifindex: u32, iface: &str, udp_off: u32, mode: Mode, cpus: Vec<usize>) -> Result<Self> {
        let btf = Btf::from_sys_fs().ok();
        let pidns = fs::metadata("/proc/self/ns/pid")?;
        let mut ebpf = EbpfLoader::new()
            .set_global("tx_ifindex", &ifindex, true)
            .set_global("tx_udp_off", &udp_off, true)
            .set_global("tx_pidns_dev", &pidns.dev(), true)
            .set_global("tx_pidns_ino", &pidns.ino(), true)
            .set_global("tx_tgid", &std::process::id(), true)
            .load(TX_OBJ)
            .context("loading BPF object (needs root)")?;
        // Some drivers (i40e, ice, ixgbe…) only take redirects while an XDP
        // program is attached; attaching resets the link on many, so only when needed.
        if net::xdp_redirect_target(ifindex)? != Some(true) {
            if let Err(e) = bpf::load_xdp(&mut ebpf, "xpeed_pass")?.attach(iface, mode.flags()) {
                eprintln!("warning: cannot attach XDP to {iface} ({e}); redirects may fail if the driver needs it");
            }
        }
        if net::xdp_redirect_target(ifindex)? == Some(false) {
            bail!("{iface} doesn't accept XDP redirects (ndo_xdp_xmit), so xpeed can't send from it");
        }
        let xmit = match attach_xmit(&mut ebpf, btf.as_ref()) {
            Ok(()) => Some(PerCpuArray::try_from(ebpf.take_map("tx_xmit").unwrap())?),
            Err(e) => {
                eprintln!("warning: TX drops won't be counted: {e:#}");
                None
            }
        };
        let prog = bpf::load_xdp(&mut ebpf, "xpeed_tx")?.fd()?.as_fd().as_raw_fd();
        let streams = Array::try_from(ebpf.take_map("tx_streams").unwrap())?;
        Ok(Tx { _ebpf: ebpf, prog, streams, xmit, cpus })
    }

    fn generated(&self) -> Result<Vec<u64>> {
        (0..self.cpus.len() as u32).map(|i| Ok(self.streams.get(&i, 0)?.packets)).collect()
    }

    /// Per-stream driver counters, through the CPU each stream is pinned to.
    fn xmit(&self) -> Result<Option<Vec<TxXmit>>> {
        let Some(xmit) = &self.xmit else { return Ok(None) };
        let per_cpu = xmit.get(&0, 0)?;
        Ok(Some(self.cpus.iter().map(|&c| per_cpu[c]).collect()))
    }
}

/// SIGUSR1 only interrupts BPF_PROG_RUN, which then returns EINTR.
extern "C" fn on_kick(_: libc::c_int) {}

/// Total packet rate: the requested one, capped at the line rate. Drivers may
/// queue far more than the wire carries (fsl_dpa then stalls the device).
fn rate(requested: Option<f64>, line: Option<f64>, iface: &str) -> Option<f64> {
    match (requested, line) {
        (Some(r), Some(l)) if r > l => {
            eprintln!("warning: capping the rate to the line rate of {iface}, {}", si(l, "pps"));
            Some(l)
        }
        (r, l) => r.or(l),
    }
}

/// Sends `frame` until the deadline, at `pps` packets/s if given.
fn generate(prog: RawFd, frame: &[u8], cpu: usize, pps: Option<f64>, start: Instant, end: Instant) -> Result<()> {
    let mut set = CpuSet::new();
    set.set(cpu)?;
    sched_setaffinity(Pid::from_raw(0), &set).with_context(|| format!("pinning to CPU {cpu}"))?;
    let duration = (end - start).as_secs_f64();
    let mut queued = 0;
    while !STOP.load(Relaxed) {
        let now = Instant::now();
        if now >= end {
            break;
        }
        let n = match pps {
            None => CHUNK,
            Some(pps) => {
                let due = ((now - start).as_secs_f64() * pps) as u64;
                let want = queued + (pps * MIN_BATCH_SECS).max(1.0) as u64;
                if due < want {
                    let next = start + Duration::from_secs_f64((want as f64 / pps).min(duration));
                    thread::sleep(next.saturating_duration_since(now).min(MAX_SLEEP));
                    continue;
                }
                (due - queued).min(CHUNK)
            }
        };
        match bpf::xdp_run_live(prog, frame, n as u32) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            r => r.context("BPF_PROG_RUN with live frames failed (needs Linux >= 5.18, frames up to ~3.4 KB)")?,
        }
        queued += n;
    }
    Ok(())
}

/// Prints interval reports until `done()`; returns the elapsed time.
fn monitor(tx: &Tx, start: Instant, interval: f64, size: usize, quiet: bool, done: impl Fn() -> bool) -> Result<f64> {
    // (time, packets, drops) at the previous report
    let report = |last: &mut (f64, u64, u64), t1: f64| -> Result<()> {
        let packets: u64 = tx.generated()?.iter().sum();
        let drops = tx.xmit()?.map(|x| x.iter().map(|x| x.drops).sum::<u64>());
        if !quiet {
            println!("{}", tx_line(None, last.0, t1, packets - last.1, size, drops.map(|d| d - last.2)));
        }
        *last = (t1, packets, drops.unwrap_or(0));
        Ok(())
    };
    let mut last = (0.0, 0, 0);
    let mut next = interval;
    while !done() {
        thread::sleep(Duration::from_millis(10));
        if start.elapsed().as_secs_f64() >= next {
            report(&mut last, next)?;
            next += interval;
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    if elapsed - last.0 >= interval / 10.0 {
        report(&mut last, elapsed)?;
    }
    Ok(elapsed)
}

pub fn run(args: Args, common: Common) -> Result<()> {
    let target = (args.target.as_str(), common.port)
        .to_socket_addrs()
        .with_context(|| format!("resolving {}", args.target))?
        .next()
        .context("no address for target")?;
    let cpus = pick_cpus(args.cpus, args.parallel)?;
    let streams = cpus.len();
    ensure!((1..=MAX_STREAMS).contains(&streams), "between 1 and {MAX_STREAMS} streams are supported");
    ensure!(args.vlan.len() <= MAX_VLANS, "at most {MAX_VLANS} VLAN tags are supported");

    let bind = args.bind.as_ref();
    let route = net::route_get(target.ip(), bind.and_then(Bind::addr), bind.and_then(Bind::ifindex))?;
    let iface = net::ifname(route.ifindex)?;
    let ipv6 = target.is_ipv6();
    let tags = args.vlan.len();
    ensure!(ipv6 || args.flowlabel == 0, "--flowlabel needs an IPv6 target");
    let (min, max) = (packet::min_size(ipv6, tags), packet::max_size(net::iface_mtu(&iface)?, tags));
    let size = args.size.unwrap_or(min);
    ensure!((min..=max).contains(&size), "frame size must be between {min} and {max} bytes on {iface}");
    let tx = Tx::load(route.ifindex, &iface, packet::udp_offset(ipv6, tags) as u32, common.mode, cpus)?;
    ensure!(net::wait_carrier(&iface), "{iface} has no link");

    if !args.json {
        println!("Connecting to host {}, port {}", target.ip(), common.port);
    }
    let mut conn = Conn::new(connect(target, bind)?);
    let nexthop = route.gateway.unwrap_or(target.ip());
    let dst_mac = match args.dst_mac {
        Some(mac) => mac,
        None => net::neigh_get(route.ifindex, nexthop)?
            .with_context(|| format!("MAC address of {nexthop} unknown on {iface}; use --dst-mac"))?,
    };
    conn.send(&Msg::Hello(Hello { version: VERSION, streams, size, duration: args.duration }))?;
    let cookie = match conn.recv()? {
        Msg::Ready { cookie } => cookie,
        Msg::Error { message } => bail!("server refused the test: {message}"),
        m => bail!("unexpected message from server: {m:?}"),
    };
    let flow = Flow {
        src_mac: net::iface_mac(&iface)?,
        dst_mac,
        src: conn.stream().local_addr()?.ip(),
        dst: target.ip(),
        src_port: args.src_port,
        dst_port: common.port,
        vlans: args.vlan,
        vlan_proto: args.vlan_proto,
        tos: args.tos.or(args.dscp).unwrap_or(0),
        ttl: args.ttl,
        flowlabel: args.flowlabel,
    };
    let frames: Vec<_> = (0..streams).map(|i| packet::build(&flow, size, cookie, i as u16)).collect();
    let requested = args.pps.or(args.bitrate.map(|b| b / (size * 8) as f64));
    let total = rate(requested, net::iface_speed(&iface).map(|bps| packet::line_rate(bps, size)), &iface);
    let pps = total.map(|r| r / streams as f64);

    if !args.json {
        let (src, dst, via) = (flow.src, flow.dst, net::fmt_mac(&dst_mac));
        let rate = total.map_or("unlimited".into(), |r| si(r, "pps"));
        println!("Sending from {iface} {src} -> {dst} via {via}, {streams} stream(s), {size}-byte frames, {rate}");
        println!("{}", tx_header());
    }
    catch_signals(true)?;
    unsafe { signal(Signal::SIGUSR1, SigHandler::Handler(on_kick)) }?;
    let tids: Vec<_> = (0..streams).map(|_| AtomicUsize::new(0)).collect();
    let start = Instant::now();
    let end = start + Duration::from_secs_f64(args.duration);
    let elapsed = thread::scope(|s| -> Result<f64> {
        let workers: Vec<_> = frames
            .iter()
            .zip(&tx.cpus)
            .zip(&tids)
            .map(|((frame, &cpu), tid)| {
                s.spawn(move || {
                    tid.store(unsafe { libc::pthread_self() } as usize, Relaxed);
                    generate(tx.prog, frame, cpu, pps, start, end).inspect_err(|_| STOP.store(true, Relaxed))
                })
            })
            .collect();
        // Past the deadline or on Ctrl-C, keep kicking workers still inside
        // BPF_PROG_RUN: a slow driver can keep one call going for long.
        let done = || {
            let late = STOP.load(Relaxed) || Instant::now() >= end;
            let mut done = true;
            for (_, tid) in workers.iter().zip(&tids).filter(|(w, _)| !w.is_finished()) {
                done = false;
                let t = tid.load(Relaxed);
                if late && t != 0 {
                    unsafe { libc::pthread_kill(t as libc::pthread_t, libc::SIGUSR1) };
                }
            }
            done
        };
        let elapsed = monitor(&tx, start, common.interval, size, args.json, done)
            .inspect_err(|_| STOP.store(true, Relaxed));
        for w in workers {
            w.join().unwrap()?;
        }
        elapsed
    })?;
    // From here on Ctrl-C quits right away.
    catch_signals(false)?;

    let generated = tx.generated()?;
    let sent = tx.xmit()?.map_or_else(|| generated.clone(), |x| x.iter().map(|x| x.sent).collect());
    conn.send(&Msg::Done { sent: sent.clone(), duration: elapsed })?;
    let rx = match conn.recv()? {
        Msg::Results { streams: rx } if rx.len() == streams => rx,
        m => bail!("unexpected message from server: {m:?}"),
    };
    let streams = (0..streams).map(|i| StreamReport::new(generated[i], sent[i], &rx[i])).collect();
    let report = Report::new(elapsed, tx.xmit.is_some(), size, streams);
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        report.print(true);
    }
    if report.tx_counted && report.sum.sent == 0 && report.sum.generated > 0 {
        eprintln!("warning: {iface} accepted no frames; does its driver support XDP redirect (ndo_xdp_xmit)?");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[test]
    fn rates() {
        assert_eq!(parse_rate("10G"), Ok(10e9));
        assert_eq!(parse_rate("1.5k"), Ok(1500.0));
        assert_eq!(parse_rate("2500"), Ok(2500.0));
        for bad in ["fast", "0", "inf", "NaN", "-1M"] {
            assert!(parse_rate(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn rate_capped_at_line_rate() {
        let line = packet::line_rate(1e9, 64);
        assert_eq!(line.round(), 1_488_095.0);
        assert_eq!(packet::line_rate(1e9, 1518).round(), 81_274.0);
        assert_eq!(rate(Some(2e6), Some(line), "eth0"), Some(line));
        assert_eq!(rate(Some(1e5), Some(line), "eth0"), Some(1e5));
        assert_eq!(rate(None, Some(line), "eth0"), Some(line));
        assert_eq!(rate(Some(1e5), None, "eth0"), Some(1e5));
        assert_eq!(rate(None, None, "eth0"), None);
    }

    #[test]
    fn dscp_names() {
        for (name, tos) in [("ef", 0xb8), ("AF41", 0x88), ("af11", 0x28), ("cs6", 0xc0), ("le", 4), ("0x2e", 0xb8)] {
            assert_eq!(parse_dscp(name), Ok(tos), "{name}");
        }
        for bad in ["af44", "af51", "cs8", "64", "0x", "-1", "x"] {
            assert!(parse_dscp(bad).is_err(), "{bad}");
        }
    }

    fn parse(opts: &str) -> Option<Args> {
        let argv = ["xpeed", "client", "h"].into_iter().chain(opts.split_whitespace());
        match crate::Cli::try_parse_from(argv).ok()?.cmd {
            crate::Cmd::Client { args, .. } => Some(args),
            crate::Cmd::Server { .. } => None,
        }
    }

    #[test]
    fn header_options() {
        let a = parse("--vlan 100,200 --vlan-proto 802.1ad -S 0xb8 --ttl 5 -L 0xfffff").unwrap();
        assert_eq!((a.vlan, a.vlan_proto as u16, a.tos), (vec![100, 200], 0x88a8, Some(0xb8)));
        assert_eq!((a.ttl, a.flowlabel), (5, 0xfffff));
        assert_eq!(parse("--vlan 7 --vlan 8").unwrap().vlan, [7, 8]);
        for bad in [
            "--vlan 0", "--vlan 4095", "--vlan-proto 802.1ad", "-S 1 --dscp 1", "-S 256", "--ttl 0", "-L 0x100000",
        ] {
            assert!(parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn cpu_lists() {
        assert_eq!("2,4-6,4".parse::<CpuList>().unwrap().0, [2, 4, 5, 6]);
        assert!("3-1".parse::<CpuList>().is_err());
        assert!("a".parse::<CpuList>().is_err());
        assert!(pick_cpus(Some(CpuList(vec![CpuSet::count()])), 1).is_err());
    }
}
