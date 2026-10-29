//! Test frame templates.

use std::{iter, net::IpAddr};

use crate::{bpf::HDR_LEN, net::Mac};

const FCS_LEN: usize = 4;
const ETH_LEN: usize = 14;
const VLAN_LEN: usize = 4;
const UDP_LEN: usize = 8;
const IPPROTO_UDP: u8 = libc::IPPROTO_UDP as u8;
/// Preamble, start delimiter and inter-frame gap around each frame on the wire.
const WIRE_OVERHEAD: usize = 20;

#[derive(Clone, Copy, clap::ValueEnum)]
pub enum VlanProto {
    #[value(name = "802.1q")]
    Dot1Q = libc::ETH_P_8021Q as isize,
    #[value(name = "802.1ad")]
    Dot1AD = libc::ETH_P_8021AD as isize,
}

pub struct Flow {
    pub src_mac: Mac,
    pub dst_mac: Mac,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    /// VLAN IDs, outer first. The outer tag is `vlan_proto`, inner ones 802.1Q.
    pub vlans: Vec<u16>,
    pub vlan_proto: VlanProto,
    /// IPv4 TOS or IPv6 traffic class.
    pub tos: u8,
    pub ttl: u8,
    pub flowlabel: u32,
}

fn l3_offset(vlans: usize) -> usize {
    ETH_LEN + VLAN_LEN * vlans
}

pub fn udp_offset(ipv6: bool, vlans: usize) -> usize {
    l3_offset(vlans) + if ipv6 { 40 } else { 20 }
}

/// Smallest frame size, FCS included, that carries the xpeed header: 64
/// bytes for IPv4, 84 for IPv6, plus 4 per VLAN tag.
pub fn min_size(ipv6: bool, vlans: usize) -> usize {
    udp_offset(ipv6, vlans) + UDP_LEN + HDR_LEN + FCS_LEN
}

/// Frames per second a link of `bps` carries at most.
pub fn line_rate(bps: f64, size: usize) -> f64 {
    bps / ((size + WIRE_OVERHEAD) * 8) as f64
}

/// Largest frame size, FCS included, for an interface MTU. XDP may exceed
/// the MTU by one VLAN tag only (xdp_ok_fwd_dev), so with QinQ the IP packet
/// must be 4 bytes smaller.
pub fn max_size(mtu: usize, vlans: usize) -> usize {
    mtu + l3_offset(vlans.min(1)) + FCS_LEN
}

/// Writes big-endian 16-bit words from the start of `buf`.
fn put_words(buf: &mut [u8], words: impl IntoIterator<Item = u16>) {
    for (c, w) in buf.chunks_exact_mut(2).zip(words) {
        c.copy_from_slice(&w.to_be_bytes());
    }
}

fn csum(data: &[u8], mut sum: u32) -> u32 {
    for c in data.chunks(2) {
        sum += u32::from(u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]));
    }
    sum
}

fn fold(mut sum: u32) -> u16 {
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// UDP sends a computed 0 as 0xffff; 0 means "no checksum".
fn udp_check(sum: u32) -> u16 {
    match fold(sum) {
        0 => 0xffff,
        c => c,
    }
}

/// Frame of `size` bytes on the wire (the NIC appends the FCS) that stream
/// `stream` replays from source port `src_port + stream`; xpeed_tx fills in
/// the sequence number and timestamp.
pub fn build(flow: &Flow, size: usize, cookie: u16, stream: u16) -> Vec<u8> {
    let l3 = l3_offset(flow.vlans.len());
    let l4 = udp_offset(flow.dst.is_ipv6(), flow.vlans.len());
    let mut f = vec![0; size - FCS_LEN];
    let udp_len = (f.len() - l4) as u16;
    f[..6].copy_from_slice(&flow.dst_mac);
    f[6..12].copy_from_slice(&flow.src_mac);
    let ip = &mut f[l3..l4];
    let (ethertype, addrs) = match (flow.src, flow.dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            ip[0] = 0x45;
            ip[1] = flow.tos;
            ip[2..4].copy_from_slice(&(udp_len + 20).to_be_bytes());
            ip[6] = 0x40; // DF
            ip[8] = flow.ttl;
            ip[9] = IPPROTO_UDP;
            ip[12..16].copy_from_slice(&src.octets());
            ip[16..20].copy_from_slice(&dst.octets());
            let check = fold(csum(ip, 0));
            ip[10..12].copy_from_slice(&check.to_be_bytes());
            (libc::ETH_P_IP as u16, 12..20)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            ip[..4].copy_from_slice(&(6 << 28 | u32::from(flow.tos) << 20 | flow.flowlabel).to_be_bytes());
            ip[4..6].copy_from_slice(&udp_len.to_be_bytes());
            ip[6] = IPPROTO_UDP;
            ip[7] = flow.ttl;
            ip[8..24].copy_from_slice(&src.octets());
            ip[24..40].copy_from_slice(&dst.octets());
            (libc::ETH_P_IPV6 as u16, 8..40)
        }
        _ => panic!("source and target address families differ"),
    };
    let pseudo = csum(&ip[addrs], u32::from(IPPROTO_UDP) + u32::from(udp_len));
    let tpids = iter::once(flow.vlan_proto).chain(iter::repeat(VlanProto::Dot1Q));
    let tags = flow.vlans.iter().zip(tpids).flat_map(|(&id, proto)| [proto as u16, id]);
    put_words(&mut f[12..], tags.chain([ethertype]));
    let udp = &mut f[l4..];
    put_words(udp, [flow.src_port.wrapping_add(stream), flow.dst_port, udp_len, 0, cookie, stream]);
    let check = udp_check(csum(udp, pseudo));
    udp[6..8].copy_from_slice(&check.to_be_bytes());
    f
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::ip_bytes;

    fn flow(src: &str, dst: &str) -> Flow {
        Flow {
            src_mac: [2, 0, 0, 0, 0, 1],
            dst_mac: [2, 0, 0, 0, 0, 2],
            src: src.parse().unwrap(),
            dst: dst.parse().unwrap(),
            src_port: 49152,
            dst_port: 5301,
            vlans: vec![],
            vlan_proto: VlanProto::Dot1Q,
            tos: 0,
            ttl: 64,
            flowlabel: 0,
        }
    }

    fn udp_ok(f: &[u8], fl: &Flow) -> bool {
        let l4 = udp_offset(fl.dst.is_ipv6(), fl.vlans.len());
        let pseudo = csum(&ip_bytes(fl.dst), csum(&ip_bytes(fl.src), u32::from(IPPROTO_UDP) + (f.len() - l4) as u32));
        fold(csum(&f[l4..], pseudo)) == 0
    }

    /// Mirror of xpeed_tx: raw native-endian words, as the BPF program sees them.
    fn bpf_stamp(f: &mut [u8], l4: usize, seq: u64, ts: u64) {
        let rd = |f: &[u8], o: usize| u16::from_ne_bytes([f[o], f[o + 1]]);
        let mut delta = 0u32;
        for (off, n, mut val) in [(l4 + 12, 3, seq), (l4 + 18, 4, ts)] {
            for i in (0..n).rev() {
                let o = off + 2 * i;
                let new = u16::from_ne_bytes((val as u16).to_be_bytes());
                delta += u32::from(!rd(f, o)) + u32::from(new);
                f[o..o + 2].copy_from_slice(&new.to_ne_bytes());
                val >>= 16;
            }
        }
        let check = udp_check(delta + u32::from(!rd(f, l4 + 6)));
        f[l4 + 6..l4 + 8].copy_from_slice(&check.to_ne_bytes());
    }

    #[test]
    fn ipv4_frame() {
        let fl = flow("10.0.0.1", "10.0.0.2");
        let f = build(&fl, min_size(false, 0), 0xbeef, 3);
        assert_eq!(f.len(), 60);
        assert_eq!(fold(csum(&f[14..34], 0)), 0, "IPv4 header checksum");
        assert_eq!(&f[42..46], &[0xbe, 0xef, 0, 3]);
        assert!(udp_ok(&f, &fl));
    }

    #[test]
    fn header_fields() {
        let qos = |src, dst, vlans, vlan_proto| Flow {
            vlans,
            vlan_proto,
            tos: 0xb8,
            ttl: 7,
            flowlabel: 0xabcde,
            ..flow(src, dst)
        };
        let v4 = qos("10.0.0.1", "10.0.0.2", vec![100, 200], VlanProto::Dot1AD);
        let f = build(&v4, min_size(false, 2), 0xbeef, 0);
        assert_eq!(f.len(), 68);
        assert_eq!(&f[12..22], &[0x88, 0xa8, 0, 100, 0x81, 0, 0, 200, 8, 0]);
        assert_eq!((f[23], f[30]), (0xb8, 7));
        assert_eq!(fold(csum(&f[22..42], 0)), 0, "IPv4 header checksum");
        assert!(udp_ok(&f, &v4));

        let v6 = qos("2001:db8::1", "2001:db8::2", vec![4094], VlanProto::Dot1Q);
        let f = build(&v6, min_size(true, 1), 0xbeef, 0);
        assert_eq!(&f[12..22], &[0x81, 0, 0x0f, 0xfe, 0x86, 0xdd, 0x6b, 0x8a, 0xbc, 0xde]);
        assert_eq!(f[25], 7);
        assert!(udp_ok(&f, &v6));

        assert_eq!([0, 1, 2].map(|n| max_size(1500, n)), [1518, 1522, 1522]);
    }

    #[test]
    fn incremental_checksum_matches() {
        for (fl, size) in [(flow("10.0.0.1", "10.0.0.2"), 64), (flow("2001:db8::1", "2001:db8::2"), 1518)] {
            let l4 = udp_offset(fl.dst.is_ipv6(), 0);
            let mut f = build(&fl, size, 0x1234, 7);
            let mut x = 0x9e37_79b9_7f4a_7c15_u64;
            for seq in (0..2000).chain([0xffff, 0xffff_ffff, (1 << 48) - 1]) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                bpf_stamp(&mut f, l4, seq, x);
                assert!(udp_ok(&f, &fl), "seq {seq} ts {x:#x}");
                assert_eq!(&f[l4 + 12..l4 + 18], &seq.to_be_bytes()[2..]);
                assert_eq!(&f[l4 + 18..l4 + 26], &x.to_be_bytes());
            }
        }
    }
}
