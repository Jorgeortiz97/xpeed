//! Receiver: xpeed_rx counts and drops test packets; the control channel
//! hands out a per-test cookie and reports the counters back.

use std::{
    collections::hash_map::RandomState,
    hash::{BuildHasher, Hasher},
    io,
    net::{Ipv4Addr, TcpListener, TcpStream},
    sync::{Arc, Mutex, TryLockError, atomic::Ordering::Relaxed},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use aya::{
    EbpfLoader,
    maps::{Array, MapData, PerCpuArray, PerCpuValues},
    util::nr_cpus,
};

use crate::{
    Common, MAX_SECONDS, STOP,
    bpf::{self, MAX_STREAMS, RX_OBJ, RxStream},
    catch_signals,
    net::{self, Bind},
    proto::{Conn, Hello, Msg, RxResult, TIMEOUT, VERSION},
    report::{Report, StreamReport, rx_header, rx_line},
};

/// Time after `Done` for frames still in flight to arrive before counting stops.
const DRAIN: Duration = Duration::from_millis(100);
/// How often the accept loop checks for SIGINT/SIGTERM.
const ACCEPT_POLL: Duration = Duration::from_millis(100);

#[derive(clap::Args)]
pub struct Args {
    /// Interface to receive on (listening on 0.0.0.0), or a local address (listen on it and use its interface)
    #[arg(short = 'B', long)]
    bind: Bind,
    /// Exit after one test
    #[arg(short = '1', long)]
    one_off: bool,
}

struct Rx {
    cookie: Array<MapData, u16>,
    streams: PerCpuArray<MapData, RxStream>,
}

impl Rx {
    fn set_cookie(&mut self, cookie: u16) -> Result<()> {
        Ok(self.cookie.set(0, cookie.to_be(), 0)?)
    }

    fn reset(&mut self, n: usize) -> Result<()> {
        let cpus = nr_cpus().map_err(|(_, e)| e)?;
        for i in 0..n as u32 {
            self.streams.set(i, PerCpuValues::try_from(vec![RxStream::default(); cpus])?, 0)?;
        }
        Ok(())
    }

    /// Per-stream counters folded over CPUs. A stream normally lands on a
    /// single RX queue, so its jitter is taken from the busiest CPU.
    fn read(&self, n: usize) -> Result<Vec<RxStream>> {
        (0..n as u32)
            .map(|i| {
                let v = self.streams.get(&i, 0)?;
                Ok(RxStream {
                    packets: v.iter().map(|s| s.packets).sum(),
                    next_seq: v.iter().map(|s| s.next_seq).max().unwrap_or(0),
                    out_of_order: v.iter().map(|s| s.out_of_order).sum(),
                    jitter: v.iter().max_by_key(|s| s.packets).map_or(0, |s| s.jitter),
                    last_transit: 0,
                })
            })
            .collect()
    }
}

fn result(s: &RxStream) -> RxResult {
    RxResult { packets: s.packets, out_of_order: s.out_of_order, jitter_ns: s.jitter_ns() }
}

fn reject(conn: &mut Conn, message: String) -> Result<()> {
    conn.send(&Msg::Error { message: message.clone() })?;
    bail!(message)
}

/// Prints interval reports until the client sends `Done`, giving up if it
/// doesn't within `TIMEOUT` of the announced test duration.
///
/// The server can't tell frames lost on the network from frames the
/// client's driver dropped, so interval rows show sequence gaps; the final
/// report uses the driver-accepted counts the client sends with `Done`.
fn measure(conn: &mut Conn, rx: &Rx, hello: &Hello, interval: f64) -> Result<(Vec<u64>, f64)> {
    println!("{}", rx_header("Gaps/Expected (%)"));
    let start = Instant::now();
    let mut last = vec![RxStream::default(); hello.streams];
    let mut next = interval;
    loop {
        match conn.recv_timeout(Duration::from_secs_f64(next).saturating_sub(start.elapsed()))? {
            Some(Msg::Done { sent, duration }) if sent.len() == hello.streams => {
                thread::sleep(DRAIN);
                return Ok((sent, duration));
            }
            Some(m) => bail!("unexpected message: {m:?}"),
            None if next > hello.duration + TIMEOUT.as_secs_f64() => bail!("client stopped responding"),
            None => {}
        }
        let now = rx.read(hello.streams)?;
        let streams: Vec<_> = now
            .iter()
            .zip(&last)
            .map(|(n, l)| {
                let rx = RxResult {
                    packets: n.packets - l.packets,
                    out_of_order: n.out_of_order - l.out_of_order,
                    jitter_ns: n.jitter_ns(),
                };
                StreamReport::new(0, n.next_seq - l.next_seq, &rx)
            })
            .collect();
        println!("{}", rx_line(None, next - interval, next, hello.size, &StreamReport::total(&streams)));
        (last, next) = (now, next + interval);
    }
}

fn session(stream: TcpStream, rx: &Mutex<Rx>, interval: f64) -> Result<()> {
    let peer = stream.peer_addr()?;
    let mut conn = Conn::new(stream);
    let Msg::Hello(hello) = conn.recv()? else {
        bail!("{peer}: expected hello");
    };
    let mut rx = match rx.try_lock() {
        Ok(rx) => rx,
        // reset() and set_cookie() redo all state a panicked session left behind.
        Err(TryLockError::Poisoned(p)) => p.into_inner(),
        Err(TryLockError::WouldBlock) => return reject(&mut conn, "the server is busy running a test".into()),
    };
    let Hello { version, streams, size, duration } = hello;
    if version != VERSION || streams > MAX_STREAMS || !(duration > 0.0 && duration <= MAX_SECONDS) {
        return reject(&mut conn, format!("unsupported test: protocol {version}, {streams} streams, {duration} s"));
    }
    println!("Accepted connection from {peer}: {streams} stream(s), {size}-byte frames");

    let cookie = RandomState::new().build_hasher().finish() as u16 | 1;
    rx.reset(streams)?;
    rx.set_cookie(cookie)?;
    let res = conn.send(&Msg::Ready { cookie }).and_then(|_| measure(&mut conn, &rx, &hello, interval));
    rx.set_cookie(0)?;
    let (sent, duration) = res?;

    let results: Vec<_> = rx.read(streams)?.iter().map(result).collect();
    let streams = sent.iter().zip(&results).map(|(&s, r)| StreamReport::new(s, s, r)).collect();
    Report::new(duration, false, size, streams).print(false);
    conn.send(&Msg::Results { streams: results })
}

pub fn run(args: Args, common: Common) -> Result<()> {
    let (ip, iface) = match args.bind {
        Bind::Addr(ip) => (ip, net::iface_of(ip)?),
        Bind::Iface(name, _) => (Ipv4Addr::UNSPECIFIED.into(), name),
    };
    let listener =
        TcpListener::bind((ip, common.port)).with_context(|| format!("listening on {ip} port {}", common.port))?;
    listener.set_nonblocking(true)?;

    let mut ebpf = EbpfLoader::new()
        .set_global("rx_port", &common.port.to_be(), true)
        .load(RX_OBJ)
        .context("loading BPF object (needs root)")?;
    bpf::load_xdp(&mut ebpf, "xpeed_rx")?
        .attach(&iface, common.mode.flags())
        .with_context(|| format!("attaching XDP to {iface}"))?;
    if !net::wait_carrier(&iface) {
        eprintln!("warning: {iface} has no link");
    }
    let rx = Arc::new(Mutex::new(Rx {
        cookie: Array::try_from(ebpf.take_map("rx_cookie").unwrap())?,
        streams: PerCpuArray::try_from(ebpf.take_map("rx_streams").unwrap())?,
    }));

    // Leave through the return below even on Ctrl-C, so dropping `ebpf`
    // detaches XDP also on kernels without bpf_link (< 5.9).
    catch_signals(true)?;
    println!("Server listening on {ip} port {}, XDP attached to {iface}", common.port);
    while !STOP.load(Relaxed) {
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(ACCEPT_POLL);
                continue;
            }
            Err(e) => {
                eprintln!("accept: {e}");
                continue;
            }
        };
        let rx = rx.clone();
        let session = thread::spawn(move || {
            if let Err(e) = session(stream, &rx, common.interval) {
                eprintln!("error: {e:#}");
            }
        });
        if args.one_off {
            let _ = session.join();
            break;
        }
    }
    Ok(())
}
