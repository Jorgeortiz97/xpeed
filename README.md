# Xpeed

High-performance network benchmarking for Linux, powered by eBPF/XDP. It
works like iperf3 (client, server, TCP control channel, interval reports)
but both data paths run in XDP, the way xdp-trafficgen generates traffic.
Only UDP is supported for now.

## How it works

```
 client                                              server
 ──────                                              ──────
 thread per stream, pinned to a CPU                  xpeed_rx (XDP, on --bind iface)
   BPF_PROG_RUN(xpeed_tx, template, live frames)       parse eth/vlan/ipv4|ipv6/udp
     stamp seq + timestamp, fix UDP csum               match port + per-test cookie
     bpf_redirect(egress ifindex) ──── wire ────▶      per-CPU, per-stream counters
 tp_btf on xdp_devmap_xmit + xdp_redirect_err          (packets, seq, out-of-order, jitter)
   frames the driver accepted / dropped                XDP_DROP
 ◀───────────── TCP control: hello / ready(cookie) / done / results ─────────────▶
```

- **Client.** Each stream gets a template frame (Ethernet + IPv4/IPv6 + UDP
  + an 18-byte xpeed header) that is replayed with `BPF_PROG_RUN` in
  `BPF_F_TEST_XDP_LIVE_FRAMES` mode. `xpeed_tx` writes a 48-bit sequence
  number and a `bpf_ktime_get_ns()` timestamp into every frame, updates the
  UDP checksum incrementally and redirects the frame to the egress
  interface. `tp_btf` programs on `xdp_devmap_xmit` and `xdp_redirect_err`
  count, for this process only, how many frames the driver really accepted
  and how many were dropped on the way. That separates TX-side drops from
  network loss.
- **Server.** `xpeed_rx` is attached to the receiving interface. It counts
  matching packets per stream in per-CPU maps, tracks sequence gaps and
  reordering, estimates RFC 3550 jitter (clock offsets between hosts cancel
  out), and drops the packets. Other traffic passes untouched.
- **Control.** Newline-delimited JSON over TCP on the same port number. The
  server gives each test a random cookie, so stray or stale packets are
  never counted.

## Requirements

- Root, or `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_PERFMON` (+ `CAP_NET_RAW` for
  `-B <iface>` on the client).
- Client: Linux ≥ 5.18 (live frames) and an egress driver that can be an
  XDP redirect target (`ndo_xdp_xmit`). Some drivers (i40e, ice, ixgbe, …)
  only accept redirects while an XDP program is loaded. On Linux ≥ 6.3 the
  client asks the kernel and attaches a pass-through program only to those;
  older kernels always get it. Attaching resets the link on some NICs, and
  xpeed waits for it to come back. Interfaces that can't accept redirects,
  such as switch (DSA) ports or e1000, are rejected up front: xpeed can only
  receive on them. The offered rate is capped at the line rate because some drivers
  accept far more than the wire carries: fsl_dpa stalled a whole M2 that
  way.
- Server: Linux ≥ 5.2 (read-only BPF globals); native mode is preferred.
  The server detaches its program on Ctrl-C or SIGTERM. On kernels before
  5.9 a `kill -9` leaves it attached (`ip link set dev <iface> xdp off`
  removes it).
- veth: the receiving end needs an XDP program (the server's) or GRO
  enabled to accept redirected frames.
- Build: Rust ≥ 1.85, clang (any of `clang`, `clang-18`…`clang-21`, or set
  `CLANG`) and the Linux UAPI headers (`linux-libc-dev`).

## Build

```
cargo build --release
```

`build.rs` compiles `src/bpf/*.bpf.c` with clang and embeds the objects in
the binary; [Aya](https://aya-rs.dev) loads them at runtime.

## Usage

```
# receiver: attach to enp1s0f0, listen on 0.0.0.0
xpeed server -B enp1s0f0

# sender: 10 s of 64-byte frames at full speed from one CPU
xpeed client 10.0.0.2

# 4 streams on CPUs 2-5, 1518-byte frames, 9 Gbit/s total, 30 s
xpeed client 10.0.0.2 --cpus 2-5 -s 1518 -b 9G -t 30

# rate in packets/s, from a given source address, JSON report
xpeed client 2001:db8::2 -B 2001:db8::1 --pps 2M -J

# QoS test: DSCP EF inside QinQ tags 100 (802.1ad) and 200
xpeed client 10.0.0.2 --vlan 100,200 --vlan-proto 802.1ad --dscp ef
```

| Option | Side | Meaning |
|---|---|---|
| `-B, --bind <IFACE\|ADDR>` | both | Server: interface to attach XDP to (listening on 0.0.0.0), or a local address to listen on (its interface is used; needed for IPv6 clients). Client: source address or egress interface. |
| `-p, --port` | both | TCP control and UDP data port (default 5301). |
| `-m, --mode auto\|native\|skb` | both | XDP attach mode. On the client it applies to the pass-through program. |
| `-i, --interval` | both | Seconds between reports (at most a day). |
| `-1, --one-off` | server | Exit after one test. |
| `<TARGET>` | client | Server address or hostname. |
| `-t, --time` | client | Duration in seconds (default 10, at most a day). |
| `-s, --size` | client | Ethernet frame size including FCS and VLAN tags (default: the minimum, 64 for IPv4 and 84 for IPv6, plus 4 per tag). |
| `-b, --bitrate` / `--pps` | client | Total target rate (`k/M/G/T` suffixes), split across streams. Defaults to, and is capped at, the interface's line rate when its driver reports a link speed (unlimited otherwise). |
| `-P, --parallel` / `--cpus` | client | Number of streams, or the exact CPUs to send from (one stream each). |
| `--src-port` | client | UDP source port of stream 0; stream N uses this + N (spreads RSS). |
| `--dst-mac` | client | Next-hop MAC when it isn't in the neighbour table. |
| `--vlan` / `--vlan-proto` | client | One VLAN ID, or two for QinQ (outer first). The outer tag is 802.1Q unless `--vlan-proto 802.1ad`; inner tags are 802.1Q. |
| `-S, --tos` / `--dscp` | client | IPv4 TOS or IPv6 traffic class byte, ECN bits included (`0xb8`), or just the DSCP (`46`, `ef`, `af41`, `cs6`…). |
| `--ttl` | client | IPv4 TTL or IPv6 hop limit (default 64). |
| `-L, --flowlabel` | client | IPv6 flow label. |
| `-J, --json` | client | Final report as JSON. |

Rates and bitrates count Ethernet frames including FCS, not preamble or
inter-frame gap. Ctrl-C on the client stops the test early and still prints
the report.

### Output

```
[ ID] Interval               Packets          Rate          Bitrate   TX drops
[SUM]   0.00-1.00   sec     14880952    14.88 Mpps      7.62 Gbit/s          0
...
[ ID] Interval               Packets          Rate          Bitrate           Lost/Total (%)       Jitter     OOO
[SUM]   0.00-10.00  sec    148804760    14.88 Mpps      7.62 Gbit/s     4000/148808760 (0.00%)     0.812 us       0  receiver
```

- **TX drops**: frames that never left the client. Either the egress driver
  refused them (e.g. its TX ring was full) or the redirect failed before
  reaching it (interface down, no XDP TX support). `-` if the tracepoints
  couldn't be attached.
- **Lost/Total**: frames the driver accepted that never reached the server's
  XDP program.
- **Gaps/Expected**: the server's interval rows can't tell network loss from
  TX drops, so they show sequence-number gaps, which include both. Its
  final rows use the accepted counts from the client and show Lost/Total.
- **OOO**: out-of-order frames.

## Limitations

- UDP only.
- Frames up to about 3.4 KB (a live-frames limit) and no larger than the
  interface MTU. XDP allows one VLAN tag on top of the MTU, so with QinQ
  the IP packet must be 4 bytes smaller.
- `--vlan` tags frames on the routed interface; addresses and the control
  connection use its untagged network (VLAN sub-interfaces aren't XDP
  redirect targets).
- No IPv6 link-local targets.
- Streams are attributed to CPUs. Each stream needs its own CPU on the
  client, and on the server a stream should land on a single RX queue
  (normally true with RSS).
