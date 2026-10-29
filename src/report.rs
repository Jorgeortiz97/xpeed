//! iperf3-style text output and the final JSON report.

use serde::Serialize;

use crate::proto::RxResult;

const SEPARATOR: &str = "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -";

/// Decimal unit prefixes, largest first.
pub const SI: [(char, f64); 4] = [('T', 1e12), ('G', 1e9), ('M', 1e6), ('k', 1e3)];

pub fn si(v: f64, unit: &str) -> String {
    match SI.iter().find(|&&(_, d)| v >= d) {
        Some(&(prefix, d)) => format!("{:.2} {prefix}{unit}", v / d),
        None => format!("{v:.2} {unit}"),
    }
}

/// Single layout for headers and rows, so they stay aligned.
fn columns(id: &str, interval: &str, packets: &str, rate: &str, bitrate: &str) -> String {
    format!("[{id}] {interval:<17} {packets:>12} {rate:>13} {bitrate:>16}")
}

fn tx_columns(head: String, drops: &str) -> String {
    format!("{head} {drops:>10}")
}

fn rx_columns(head: String, loss: &str, jitter: &str, ooo: &str) -> String {
    format!("{head} {loss:>24} {jitter:>12} {ooo:>7}")
}

fn head(id: Option<usize>, t0: f64, t1: f64, packets: u64, size: usize) -> String {
    let id = id.map_or("SUM".into(), |i| format!("{i:3}"));
    let pps = packets as f64 / (t1 - t0).max(1e-9);
    let bps = pps * (size * 8) as f64;
    let interval = format!("{t0:6.2}-{t1:<6.2} sec");
    columns(&id, &interval, &packets.to_string(), &si(pps, "pps"), &si(bps, "bit/s"))
}

fn titles() -> String {
    columns(" ID", "Interval", "Packets", "Rate", "Bitrate")
}

pub fn tx_header() -> String {
    tx_columns(titles(), "TX drops")
}

/// `loss` titles the loss column, whose meaning differs between reports.
pub fn rx_header(loss: &str) -> String {
    rx_columns(titles(), loss, "Jitter", "OOO")
}

pub fn tx_line(id: Option<usize>, t0: f64, t1: f64, packets: u64, size: usize, drops: Option<u64>) -> String {
    tx_columns(head(id, t0, t1, packets, size), &drops.map_or("-".into(), |d| d.to_string()))
}

pub fn rx_line(id: Option<usize>, t0: f64, t1: f64, size: usize, s: &StreamReport) -> String {
    let pct = 100.0 * s.lost as f64 / s.sent.max(1) as f64;
    let loss = format!("{}/{} ({pct:.2}%)", s.lost, s.sent);
    let jitter = format!("{:.3} us", s.jitter_ns / 1e3);
    rx_columns(head(id, t0, t1, s.received, size), &loss, &jitter, &s.out_of_order.to_string())
}

#[derive(Serialize, Default)]
pub struct StreamReport {
    /// Packets xpeed_tx stamped.
    pub generated: u64,
    /// Packets the egress driver accepted.
    pub sent: u64,
    pub received: u64,
    pub lost: u64,
    pub out_of_order: u64,
    pub jitter_ns: f64,
}

impl StreamReport {
    pub fn new(generated: u64, sent: u64, rx: &RxResult) -> Self {
        StreamReport {
            generated,
            sent,
            received: rx.packets,
            lost: sent.saturating_sub(rx.packets),
            out_of_order: rx.out_of_order,
            jitter_ns: rx.jitter_ns,
        }
    }

    /// Sum of `streams`, with jitter averaged by received packets.
    pub fn total(streams: &[StreamReport]) -> Self {
        let mut sum = StreamReport::default();
        for s in streams {
            sum.generated += s.generated;
            sum.sent += s.sent;
            sum.received += s.received;
            sum.lost += s.lost;
            sum.out_of_order += s.out_of_order;
            sum.jitter_ns += s.jitter_ns * s.received as f64;
        }
        sum.jitter_ns /= sum.received.max(1) as f64;
        sum
    }
}

#[derive(Serialize)]
pub struct Report {
    pub duration: f64,
    /// Whether `sent` comes from the driver (xdp_devmap_xmit) or equals `generated`.
    pub tx_counted: bool,
    pub frame_size: usize,
    pub streams: Vec<StreamReport>,
    pub sum: StreamReport,
}

impl Report {
    pub fn new(duration: f64, tx_counted: bool, frame_size: usize, streams: Vec<StreamReport>) -> Self {
        let sum = StreamReport::total(&streams);
        Report { duration, tx_counted, frame_size, streams, sum }
    }

    /// `sender` is false on the server, which can't tell TX drops.
    pub fn print(&self, sender: bool) {
        println!("{SEPARATOR}");
        let sum = (self.streams.len() > 1).then_some((None, &self.sum));
        let rows: Vec<_> = self.streams.iter().enumerate().map(|(i, s)| (Some(i), s)).chain(sum).collect();
        let (d, size) = (self.duration, self.frame_size);
        if sender {
            println!("{}", tx_header());
            for &(id, s) in &rows {
                let drops = self.tx_counted.then(|| s.generated - s.sent);
                println!("{}  sender", tx_line(id, 0.0, d, s.generated, size, drops));
            }
        }
        println!("{}", rx_header("Lost/Total (%)"));
        for &(id, s) in &rows {
            println!("{}  receiver", rx_line(id, 0.0, d, size, s));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units() {
        assert_eq!(si(14_880_952.0, "pps"), "14.88 Mpps");
        assert_eq!(si(7.62e9, "bit/s"), "7.62 Gbit/s");
        assert_eq!(si(12.0, "pps"), "12.00 pps");
    }

    #[test]
    fn sum_weights_jitter() {
        let rx = |packets, jitter_ns| RxResult { packets, out_of_order: 1, jitter_ns };
        let streams = vec![StreamReport::new(100, 100, &rx(90, 10.0)), StreamReport::new(10, 10, &rx(10, 110.0))];
        let r = Report::new(1.0, true, 64, streams);
        assert_eq!((r.sum.sent, r.sum.received, r.sum.lost, r.sum.out_of_order), (110, 100, 10, 2));
        assert_eq!(r.sum.jitter_ns, 20.0);
    }
}
