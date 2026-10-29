//! End-to-end tests: a server and a client in two network namespaces joined
//! by a veth pair. They need root; the README shows how to run them.

use std::{
    io::{BufRead, BufReader, Read},
    process::{Child, Command, Output, Stdio},
    sync::atomic::{AtomicUsize, Ordering::Relaxed},
};

use serde_json::Value;

const XPEED: &str = env!("CARGO_BIN_EXE_xpeed");
const PPS: u64 = 50_000;

fn ip(args: &[&str]) {
    let out = Command::new("ip").args(args).output().unwrap();
    assert!(out.status.success(), "ip {}: {}", args.join(" "), String::from_utf8_lossy(&out.stderr));
}

/// Namespaces `client` (veth0: 10.0.0.1, 2001:db8::1) and `server` (veth1:
/// 10.0.0.2, 2001:db8::2), removed on drop along with the veth pair.
struct Veth {
    client: String,
    server: String,
    xpeed: Option<Child>,
}

impl Veth {
    fn new() -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let id = format!("xpeed-{}-{}", std::process::id(), N.fetch_add(1, Relaxed));
        let veth = Veth { client: format!("{id}-c"), server: format!("{id}-s"), xpeed: None };
        ip(&["netns", "add", &veth.client]);
        ip(&["netns", "add", &veth.server]);
        ip(&["link", "add", "veth0", "netns", &veth.client, "type", "veth", "peer", "veth1", "netns", &veth.server]);
        for (ns, dev, host) in [(&veth.client, "veth0", 1), (&veth.server, "veth1", 2)] {
            ip(&["-n", ns, "addr", "add", &format!("10.0.0.{host}/24"), "dev", dev]);
            ip(&["-n", ns, "addr", "add", &format!("2001:db8::{host}/64"), "dev", dev, "nodad"]);
            ip(&["-n", ns, "link", "set", dev, "up"]);
            ip(&["-n", ns, "link", "set", "lo", "up"]);
        }
        veth
    }

    /// Bounded, so a stuck control exchange fails the test instead of hanging it.
    /// `ip netns exec` execs `timeout`, so the child's pid is timeout's.
    fn exec(ns: &str, args: &[&str]) -> Command {
        let mut cmd = Command::new("ip");
        cmd.args(["netns", "exec", ns, "timeout", "-k", "5", "30", XPEED]).args(args);
        cmd
    }

    fn server(&mut self, bind: &str) {
        let mut child = Self::exec(&self.server, &["server", "-1", "-B", bind])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let ready = lines.by_ref().map_while(Result::ok).any(|l| l.starts_with("Server listening"));
        // Keep draining so interval reports never block the server.
        std::thread::spawn(move || lines.for_each(drop));
        self.xpeed = Some(child);
        assert!(ready, "server exited before listening");
    }

    fn client(&mut self, target: &str, opts: &str) -> Value {
        let pps = PPS.to_string();
        let mut args = vec!["client", target, "-J", "-t", "1", "--pps", &pps];
        args.extend(opts.split_whitespace());
        let Output { status, stdout, stderr } = Self::exec(&self.client, &args).output().unwrap();
        assert!(status.success(), "client failed: {}", String::from_utf8_lossy(&stderr));
        let mut server = self.xpeed.take().unwrap();
        let status = server.wait().unwrap();
        let mut errors = String::new();
        server.stderr.take().unwrap().read_to_string(&mut errors).unwrap();
        // A one-off server prints session errors but still exits with 0.
        assert!(status.success() && !errors.contains("error"), "server failed: {errors}");
        serde_json::from_slice(&stdout).unwrap()
    }
}

impl Drop for Veth {
    fn drop(&mut self) {
        // SIGKILL would stop only `timeout` and orphan xpeed; SIGTERM is
        // forwarded, and xpeed detaches its XDP program on it.
        if let Some(mut child) = self.xpeed.take() {
            unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
            let _ = child.wait();
        }
        for ns in [&self.client, &self.server] {
            let _ = Command::new("ip").args(["netns", "del", ns]).status();
        }
    }
}

fn assert_delivered(report: &Value, streams: usize, frame_size: u64) {
    let sum = &report["sum"];
    let n = |k: &str| sum[k].as_u64().unwrap();
    assert_eq!(report["streams"].as_array().unwrap().len(), streams);
    assert_eq!(report["frame_size"].as_u64(), Some(frame_size));
    assert!(report["tx_counted"].as_bool().unwrap());
    assert!(n("generated").abs_diff(PPS) < PPS / 5, "generated {}", n("generated"));
    assert_eq!(n("generated"), n("sent"), "TX drops");
    assert_eq!(n("received"), n("sent"));
    assert_eq!(n("out_of_order"), 0);
}

fn run(bind: &str, target: &str, opts: &str) -> Value {
    let mut veth = Veth::new();
    veth.server(bind);
    veth.client(target, opts)
}

#[test]
#[ignore = "needs root"]
fn ipv4() {
    assert_delivered(&run("veth1", "10.0.0.2", ""), 1, 64);
}

#[test]
#[ignore = "needs root"]
fn ipv6() {
    assert_delivered(&run("2001:db8::2", "2001:db8::2", ""), 1, 84);
}

#[test]
#[ignore = "needs root"]
fn parallel_streams() {
    let report = run("veth1", "10.0.0.2", "-P 2");
    assert_delivered(&report, 2, 64);
    for s in report["streams"].as_array().unwrap() {
        assert!(s["received"].as_u64().unwrap() > 0);
    }
}

#[test]
#[ignore = "needs root"]
fn qinq_full_size() {
    let report = run("veth1", "10.0.0.2", "-s 1518 --vlan 100,200 --vlan-proto 802.1ad --dscp ef");
    assert_delivered(&report, 1, 1518);
}
