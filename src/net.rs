//! Interface, route and neighbour lookups (rtnetlink, sysfs, getifaddrs).

use std::{
    fs, io,
    net::IpAddr,
    os::fd::AsRawFd,
    str::FromStr,
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use libc::{
    NDA_DST, NDA_LLADDR, NLA_TYPE_MASK, NUD_DELAY, NUD_NOARP, NUD_PERMANENT, NUD_PROBE, NUD_REACHABLE, NUD_STALE,
    RTA_DST, RTA_GATEWAY, RTA_OIF, RTA_SRC, RTM_GETNEIGH, RTM_GETROUTE, RTN_LOCAL,
};
use nix::{
    ifaddrs::getifaddrs,
    net::if_::if_nametoindex,
    sys::socket::{
        AddressFamily, MsgFlags, NetlinkAddr, SockFlag, SockProtocol, SockType,
        SockaddrStorage, bind, recv, send, socket,
    },
};

pub type Mac = [u8; 6];

/// `--bind` argument: a local address, or an interface name and index.
#[derive(Clone)]
pub enum Bind {
    Addr(IpAddr),
    Iface(String, u32),
}

impl Bind {
    pub fn addr(&self) -> Option<IpAddr> {
        match self {
            Bind::Addr(ip) => Some(*ip),
            Bind::Iface(..) => None,
        }
    }

    pub fn ifindex(&self) -> Option<u32> {
        match self {
            Bind::Addr(_) => None,
            Bind::Iface(_, index) => Some(*index),
        }
    }
}

impl FromStr for Bind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        match s.parse() {
            Ok(ip) => Ok(Bind::Addr(ip)),
            Err(_) => Ok(Bind::Iface(s.into(), ifindex(s).map_err(|e| e.to_string())?)),
        }
    }
}

pub fn parse_mac(s: &str) -> Result<Mac, String> {
    // from_str_radix alone would also take "+1" or "002".
    let hex2 = |b: &str| b.len() == 2 && b.bytes().all(|c| c.is_ascii_hexdigit());
    let octet = |b: &str| u8::from_str_radix(b, 16).ok().filter(|_| hex2(b));
    let bytes: Option<Vec<u8>> = s.split(':').map(octet).collect();
    bytes.and_then(|b| b.try_into().ok()).ok_or_else(|| format!("invalid MAC address '{s}'"))
}

pub fn fmt_mac(mac: &Mac) -> String {
    mac.map(|b| format!("{b:02x}")).join(":")
}

pub fn ifindex(name: &str) -> Result<u32> {
    if_nametoindex(name).with_context(|| format!("unknown interface '{name}'"))
}

pub fn ifname(index: u32) -> Result<String> {
    let mut buf = [0; libc::IF_NAMESIZE];
    let p = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    if p.is_null() {
        bail!("no interface with index {index}");
    }
    Ok(unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into())
}

fn sysfs(iface: &str, attr: &str) -> Result<String> {
    let path = format!("/sys/class/net/{iface}/{attr}");
    Ok(fs::read_to_string(&path).with_context(|| format!("reading {path}"))?.trim().into())
}

pub fn iface_mac(iface: &str) -> Result<Mac> {
    parse_mac(&sysfs(iface, "address")?).map_err(|e| anyhow!(e))
}

pub fn iface_mtu(iface: &str) -> Result<usize> {
    Ok(sysfs(iface, "mtu")?.parse()?)
}

/// Link speed in bit/s, if the driver reports one.
pub fn iface_speed(iface: &str) -> Option<f64> {
    let mbps: f64 = sysfs(iface, "speed").ok()?.parse().ok()?;
    (mbps > 0.0).then_some(mbps * 1e6)
}

/// Waits up to 10 s for `iface` to have carrier, since attaching XDP resets
/// the link on some drivers (fsl_dpa, i40e…). Returns whether it came up.
pub fn wait_carrier(iface: &str) -> bool {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !sysfs(iface, "carrier").is_ok_and(|c| c == "1") {
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(100));
    }
    true
}

fn sockaddr_ip(a: &SockaddrStorage) -> Option<IpAddr> {
    let v4 = a.as_sockaddr_in().map(|s| IpAddr::from(s.ip()));
    v4.or_else(|| a.as_sockaddr_in6().map(|s| s.ip().into()))
}

/// Name of the interface that owns the local address `ip`.
pub fn iface_of(ip: IpAddr) -> Result<String> {
    getifaddrs()?
        .find(|ifa| ifa.address.as_ref().and_then(sockaddr_ip) == Some(ip))
        .map(|ifa| ifa.interface_name)
        .with_context(|| format!("{ip} is not a local address"))
}

const NUD_VALID: u16 = NUD_REACHABLE | NUD_STALE | NUD_DELAY | NUD_PROBE | NUD_NOARP | NUD_PERMANENT;
const NLMSG_HDRLEN: usize = size_of::<libc::nlmsghdr>();
/// Size of both `struct rtmsg` and `struct ndmsg`.
const MSG_LEN: usize = 12;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

/// Iterates over `(type, payload)` of netlink attributes.
fn attrs(mut b: &[u8]) -> impl Iterator<Item = (u16, &[u8])> {
    std::iter::from_fn(move || {
        let len = usize::from(u16::from_ne_bytes(b.get(..2)?.try_into().ok()?));
        if len < 4 || len > b.len() {
            return None;
        }
        let item = (u16::from_ne_bytes([b[2], b[3]]) & NLA_TYPE_MASK as u16, &b[4..len]);
        b = &b[align4(len).min(b.len())..];
        Some(item)
    })
}

fn push_attr(msg: &mut Vec<u8>, ty: u16, data: &[u8]) {
    msg.extend(((4 + data.len()) as u16).to_ne_bytes());
    msg.extend(ty.to_ne_bytes());
    msg.extend(data);
    msg.resize(align4(msg.len()), 0);
}

pub(crate) fn ip_bytes(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => a.octets().into(),
        IpAddr::V6(a) => a.octets().into(),
    }
}

fn ip_from(b: &[u8]) -> Option<IpAddr> {
    let v4: Result<[u8; 4], _> = b.try_into();
    let v6: Result<[u8; 16], _> = b.try_into();
    v4.map(IpAddr::from).or(v6.map(IpAddr::from)).ok()
}

/// Zeroed rtmsg/ndmsg for the address family of `ip`.
fn msg(ip: IpAddr) -> Vec<u8> {
    let mut m = vec![0; MSG_LEN];
    m[0] = (if ip.is_ipv4() { libc::AF_INET } else { libc::AF_INET6 }) as u8;
    m
}

/// Sends one netlink request and returns the bodies of the replies.
fn netlink(proto: SockProtocol, ty: u16, dump: bool, body: &[u8]) -> Result<Vec<Vec<u8>>> {
    let sock = socket(AddressFamily::Netlink, SockType::Raw, SockFlag::SOCK_CLOEXEC, proto)?;
    let fd = sock.as_raw_fd();
    bind(fd, &NetlinkAddr::new(0, 0))?;
    let flags = (libc::NLM_F_REQUEST | if dump { libc::NLM_F_DUMP } else { 0 }) as u16;
    let mut msg = Vec::with_capacity(NLMSG_HDRLEN + body.len());
    msg.extend(((NLMSG_HDRLEN + body.len()) as u32).to_ne_bytes());
    msg.extend(ty.to_ne_bytes());
    msg.extend(flags.to_ne_bytes());
    msg.extend([0; 8]);
    msg.extend(body);
    send(fd, &msg, MsgFlags::empty())?;

    let mut replies = vec![];
    let mut buf = vec![0; 1 << 16];
    loop {
        let n = recv(fd, &mut buf, MsgFlags::empty())?;
        let mut b = &buf[..n];
        while b.len() >= NLMSG_HDRLEN {
            let len = (u32::from_ne_bytes(b[..4].try_into()?) as usize).clamp(NLMSG_HDRLEN, b.len());
            match i32::from(u16::from_ne_bytes([b[4], b[5]])) {
                libc::NLMSG_DONE => return Ok(replies),
                libc::NLMSG_ERROR => match i32::from_ne_bytes(b[NLMSG_HDRLEN..NLMSG_HDRLEN + 4].try_into()?) {
                    0 => return Ok(replies),
                    e => return Err(io::Error::from_raw_os_error(-e).into()),
                },
                _ => replies.push(b[NLMSG_HDRLEN..len].to_vec()),
            }
            b = &b[align4(len).min(b.len())..];
        }
        if !dump {
            return Ok(replies);
        }
    }
}

pub struct Route {
    pub ifindex: u32,
    pub gateway: Option<IpAddr>,
}

/// Equivalent of `ip route get <dst> [from <src>] [oif <oif>]`.
pub fn route_get(dst: IpAddr, src: Option<IpAddr>, oif: Option<u32>) -> Result<Route> {
    let bits = if dst.is_ipv4() { 32 } else { 128 };
    let mut req = msg(dst);
    req[1] = bits;
    push_attr(&mut req, RTA_DST, &ip_bytes(dst));
    if let Some(src) = src {
        req[2] = bits;
        push_attr(&mut req, RTA_SRC, &ip_bytes(src));
    }
    if let Some(oif) = oif {
        push_attr(&mut req, RTA_OIF, &oif.to_ne_bytes());
    }
    let reply = netlink(SockProtocol::NetlinkRoute, RTM_GETROUTE, false, &req)
        .with_context(|| format!("no route to {dst}"))?;
    let rt = reply.first().filter(|r| r.len() >= MSG_LEN).context("empty route reply")?;
    if rt[7] == RTN_LOCAL {
        bail!("{dst} is a local address; xpeed needs a real egress interface");
    }
    let mut route = Route { ifindex: 0, gateway: None };
    for (ty, data) in attrs(&rt[MSG_LEN..]) {
        match ty {
            RTA_OIF => route.ifindex = u32::from_ne_bytes(data.try_into()?),
            RTA_GATEWAY => route.gateway = ip_from(data),
            _ => {}
        }
    }
    Ok(route)
}

/// MAC address of `ip` in the neighbour table of `ifindex`, if resolved.
pub fn neigh_get(ifindex: u32, ip: IpAddr) -> Result<Option<Mac>> {
    let neighbours = netlink(SockProtocol::NetlinkRoute, RTM_GETNEIGH, true, &msg(ip))?;
    for n in neighbours.iter().filter(|n| n.len() >= MSG_LEN) {
        let state = u16::from_ne_bytes([n[8], n[9]]);
        if u32::from_ne_bytes(n[4..8].try_into()?) != ifindex || state & NUD_VALID == 0 {
            continue;
        }
        let (mut dst, mut mac) = (None, None);
        for (ty, data) in attrs(&n[MSG_LEN..]) {
            match ty {
                NDA_DST => dst = ip_from(data),
                NDA_LLADDR => mac = data.try_into().ok(),
                _ => {}
            }
        }
        if dst == Some(ip) && mac.is_some() {
            return Ok(mac);
        }
    }
    Ok(None)
}

const NETDEV_CMD_DEV_GET: u8 = 1;
const NETDEV_A_DEV_IFINDEX: u16 = 1;
const NETDEV_A_DEV_XDP_FEATURES: u16 = 3;
const NETDEV_XDP_ACT_NDO_XMIT: u64 = 1 << 2;

/// Sends one generic netlink request (version 1) and returns the attributes of its reply.
fn genl(family: u16, cmd: u8, attrs: &[u8]) -> Result<Vec<u8>> {
    let body = [&[cmd, 1, 0, 0][..], attrs].concat();
    let reply = netlink(SockProtocol::NetlinkGeneric, family, false, &body)?;
    Ok(reply.first().and_then(|r| r.get(4..)).context("empty generic netlink reply")?.to_vec())
}

/// Whether `ifindex` can be an XDP redirect target right now (`ndo_xdp_xmit`),
/// or `None` on kernels before 6.3, which don't report it.
pub fn xdp_redirect_target(ifindex: u32) -> Result<Option<bool>> {
    let mut req = vec![];
    push_attr(&mut req, libc::CTRL_ATTR_FAMILY_NAME as u16, b"netdev\0");
    let family = match genl(libc::GENL_ID_CTRL as u16, libc::CTRL_CMD_GETFAMILY as u8, &req) {
        Err(e) if e.downcast_ref::<io::Error>().and_then(io::Error::raw_os_error) == Some(libc::ENOENT) => {
            return Ok(None);
        }
        r => r?,
    };
    let id = attrs(&family)
        .find(|&(ty, _)| ty == libc::CTRL_ATTR_FAMILY_ID as u16)
        .and_then(|(_, v)| Some(u16::from_ne_bytes(v.try_into().ok()?)))
        .context("no netdev family id")?;
    let mut req = vec![];
    push_attr(&mut req, NETDEV_A_DEV_IFINDEX, &ifindex.to_ne_bytes());
    let dev = genl(id, NETDEV_CMD_DEV_GET, &req)?;
    let features = attrs(&dev)
        .find(|&(ty, _)| ty == NETDEV_A_DEV_XDP_FEATURES)
        .and_then(|(_, v)| Some(u64::from_ne_bytes(v.try_into().ok()?)))
        .unwrap_or(0);
    Ok(Some(features & NETDEV_XDP_ACT_NDO_XMIT != 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mac_roundtrip() {
        let mac = parse_mac("02:00:0a:ff:00:01").unwrap();
        assert_eq!(mac, [2, 0, 10, 255, 0, 1]);
        assert_eq!(fmt_mac(&mac), "02:00:0a:ff:00:01");
        let bad = ["02:00:0a:ff:00", "02:00:0a:ff:00:zz", "02:00:0a:ff:00:zz:01", "02:00:0a:ff:00:+1"];
        for bad in bad.into_iter().chain(["002:00:0a:ff:00:01"]) {
            assert!(parse_mac(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn attrs_roundtrip() {
        let mut msg = vec![];
        push_attr(&mut msg, RTA_DST, &[10, 0, 0, 1]);
        push_attr(&mut msg, RTA_OIF, &7u32.to_ne_bytes());
        push_attr(&mut msg, 9, &[1]);
        let got: Vec<_> = attrs(&msg).collect();
        assert_eq!(got, [(RTA_DST, &[10, 0, 0, 1][..]), (RTA_OIF, &7u32.to_ne_bytes()[..]), (9, &[1][..])]);
    }

    /// Runs against the host's kernel; needs no privileges.
    #[test]
    fn loopback_is_no_redirect_target() {
        if let Some(target) = xdp_redirect_target(1).unwrap() {
            assert!(!target);
        }
    }

    /// Runs against the host's routing table; needs no privileges.
    #[test]
    fn route_lookup() {
        let lo = route_get("127.0.0.1".parse().unwrap(), None, None);
        assert!(lo.err().unwrap().to_string().contains("local address"));
        if let Ok(r) = route_get("192.0.2.1".parse().unwrap(), None, None) {
            assert!(ifname(r.ifindex).is_ok());
        }
    }
}
