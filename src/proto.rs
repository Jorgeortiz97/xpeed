//! Control channel: newline-delimited JSON over TCP, like iperf3's.

use std::{
    io::{self, BufRead, BufReader, Read, Write},
    net::TcpStream,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 1;
/// How long either side waits for a control message.
pub const TIMEOUT: Duration = Duration::from_secs(10);
/// Longest control message accepted, well above a 256-stream `Results`.
const MAX_LINE: usize = 64 << 10;

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Msg {
    Hello(Hello),
    Ready { cookie: u16 },
    Error { message: String },
    /// Per-stream packets accepted by the egress driver, and sending time.
    Done { sent: Vec<u64>, duration: f64 },
    Results { streams: Vec<RxResult> },
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Hello {
    pub version: u32,
    pub streams: usize,
    pub size: usize,
    pub duration: f64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RxResult {
    pub packets: u64,
    pub out_of_order: u64,
    pub jitter_ns: f64,
}

pub struct Conn {
    reader: BufReader<TcpStream>,
    line: String,
}

impl Conn {
    pub fn new(stream: TcpStream) -> Self {
        Conn { reader: BufReader::new(stream), line: String::new() }
    }

    pub fn stream(&self) -> &TcpStream {
        self.reader.get_ref()
    }

    pub fn send(&mut self, msg: &Msg) -> Result<()> {
        let mut buf = serde_json::to_vec(msg)?;
        buf.push(b'\n');
        self.reader.get_mut().write_all(&buf)?;
        Ok(())
    }

    pub fn recv(&mut self) -> Result<Msg> {
        self.recv_timeout(TIMEOUT)?.context("timed out waiting for the peer")
    }

    /// `None` on timeout; a partial line is kept for the next call.
    pub fn recv_timeout(&mut self, timeout: Duration) -> Result<Option<Msg>> {
        self.stream().set_read_timeout(Some(timeout.max(Duration::from_millis(1))))?;
        let limit = MAX_LINE.saturating_sub(self.line.len()) as u64;
        match (&mut self.reader).take(limit).read_line(&mut self.line) {
            // Without a newline, the line hit the limit or the peer closed.
            Ok(_) if !self.line.ends_with('\n') && self.line.len() >= MAX_LINE => bail!("control message too long"),
            Ok(_) if !self.line.ends_with('\n') => bail!("connection closed by peer"),
            Ok(_) => {}
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => return Ok(None),
            Err(e) => return Err(e.into()),
        }
        let msg = serde_json::from_str(&self.line);
        self.line.clear();
        Ok(Some(msg?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair() -> (TcpStream, Conn) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        (client, Conn::new(listener.accept().unwrap().0))
    }

    #[test]
    fn partial_line_survives_timeout() {
        let (mut peer, mut conn) = pair();
        peer.write_all(br#"{"type":"ready","#).unwrap();
        assert!(conn.recv_timeout(Duration::from_millis(50)).unwrap().is_none());
        peer.write_all(b"\"cookie\":7}\n").unwrap();
        assert!(matches!(conn.recv().unwrap(), Msg::Ready { cookie: 7 }));
    }

    #[test]
    fn long_line_rejected() {
        let (mut peer, mut conn) = pair();
        peer.write_all(&vec![b' '; MAX_LINE + 1]).unwrap();
        assert!(conn.recv().unwrap_err().to_string().contains("too long"));
    }

    #[test]
    fn hello_wire_format() {
        let hello = Msg::Hello(Hello { version: 1, streams: 2, size: 64, duration: 10.0 });
        let json = serde_json::to_string(&hello).unwrap();
        assert_eq!(json, r#"{"type":"hello","version":1,"streams":2,"size":64,"duration":10.0}"#);
        assert!(matches!(serde_json::from_str(&json).unwrap(), Msg::Hello(Hello { streams: 2, .. })));
    }
}
