//! Per-app proxying.
//!
//! WinDivert sees every outbound TCP SYN, finds the owning process through the
//! TCP table and, if its exe matches a mask, "reflects" the connection into a
//! local relay (the classic WinDivert streamdump trick):
//!
//! ```text
//! app  A:p -> B:q   becomes   B:p -> A:relay (inbound)
//! relay A:relay -> B:p   becomes   B:q -> A:p (inbound)
//! ```
//!
//! The relay looks up the original port by `(B, p)` and opens `B:q` through the
//! upstream SOCKS5 / HTTP proxy. IPv6 TCP of chosen apps is reset so they fall
//! back to IPv4, and their UDP (QUIC, WebRTC) is dropped so nothing leaks.

use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering::Relaxed, Ordering::SeqCst};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use parking_lot::{Mutex, RwLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::runtime::Runtime;

use crate::divert::{self, Address, Api, Divert};
use crate::procs;
use crate::proxy::{self, ProxyConfig, Target};

/// App masks shared between the UI and the packet loop.
#[derive(Default)]
pub struct Rules {
    masks: RwLock<Vec<String>>,
    version: AtomicU64,
}

impl Rules {
    pub fn set(&self, masks: Vec<String>) {
        *self.masks.write() = masks;
        self.version.fetch_add(1, SeqCst);
    }

    fn version(&self) -> u64 {
        self.version.load(SeqCst)
    }

    pub fn matches(&self, exe: &str) -> bool {
        self.masks.read().iter().any(|m| procs::mask_matches(m, exe))
    }
}

#[derive(Default)]
pub struct Stats {
    pub active: AtomicUsize,
    pub total: AtomicU64,
    pub up: AtomicU64,
    pub down: AtomicU64,
    pub failed: AtomicU64,
    pub blocked: AtomicU64,
    pub last_error: Mutex<Option<String>>,
}

struct NatEntry {
    orig_port: u16,
    generation: u64,
    last_seen: Instant,
    closed: bool,
}

/// `(original destination ip, app's local port)` -> original destination port.
type Nat = Arc<Mutex<HashMap<(Ipv4Addr, u16), NatEntry>>>;

/// Every outbound IPv4 TCP packet (to rewrite redirected flows), IPv6 SYNs (to
/// reset them for chosen apps) and non-DNS UDP (to drop it for chosen apps).
pub const FILTER: &str = "outbound and !loopback and (\
    (ip and tcp) or \
    (ipv6 and tcp and tcp.Syn and !tcp.Ack) or \
    (udp and udp.DstPort != 53))";

pub struct Engine {
    divert: Arc<Divert>,
    thread: Option<JoinHandle<()>>,
    runtime: Option<Runtime>,
    stop: Arc<AtomicBool>,
    stats: Arc<Stats>,
}

impl Engine {
    pub fn start(cfg: ProxyConfig, rules: Arc<Rules>) -> Result<Engine, String> {
        if !procs::is_elevated() {
            return Err("Нужны права администратора: перезапусти приложение от админа".into());
        }
        let proxy_addr = cfg.resolve()?;
        let api = Api::load()?;
        procs::ensure_firewall_rule();

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("relay")
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        let listener = runtime
            .block_on(TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)))
            .map_err(|e| format!("relay не запустился: {e}"))?;
        let relay_port = listener.local_addr().map_err(|e| e.to_string())?.port();

        let divert = Arc::new(api.open(FILTER, 0)?);
        divert.set_param(divert::PARAM_QUEUE_LENGTH, 16384);
        divert.set_param(divert::PARAM_QUEUE_TIME, 4000);
        divert.set_param(divert::PARAM_QUEUE_SIZE, 32 * 1024 * 1024);

        let nat: Nat = Default::default();
        let stats = Arc::new(Stats::default());
        let stop = Arc::new(AtomicBool::new(false));

        runtime.spawn(accept_loop(listener, nat.clone(), Arc::new(cfg), proxy_addr, stats.clone()));

        let packet_loop = PacketLoop::new(nat, rules.clone(), stats.clone(), relay_port, proxy_addr);
        let stop_flag = stop.clone();
        let loop_divert = divert.clone();
        let thread = std::thread::Builder::new()
            .name("divert".into())
            .spawn(move || packet_loop.run(&loop_divert, &stop_flag))
            .map_err(|e| e.to_string())?;

        // Already open connections of chosen apps would stay direct; reset them.
        std::thread::spawn(move || reset_targets(&rules));

        Ok(Engine { divert, thread: Some(thread), runtime: Some(runtime), stop, stats })
    }

    pub fn stats(&self) -> &Arc<Stats> {
        &self.stats
    }

    fn shutdown(&mut self) {
        self.stop.store(true, SeqCst);
        self.divert.shutdown();
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
        if let Some(rt) = self.runtime.take() {
            rt.shutdown_background();
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Resets open IPv4 connections of processes matching the rules.
pub fn reset_targets(rules: &Rules) -> usize {
    let own = std::process::id();
    let names: HashMap<u32, String> = procs::snapshot().into_iter().collect();
    procs::reset_connections(|pid| pid != own && names.get(&pid).is_some_and(|n| rules.matches(n)))
}

async fn accept_loop(
    listener: TcpListener,
    nat: Nat,
    cfg: Arc<ProxyConfig>,
    proxy_addr: SocketAddr,
    stats: Arc<Stats>,
) {
    loop {
        let (client, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(_) => {
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
        };
        let SocketAddr::V4(peer) = peer else { continue };
        let key = (*peer.ip(), peer.port());
        let Some((orig_port, generation)) = nat.lock().get(&key).map(|e| (e.orig_port, e.generation)) else {
            continue;
        };
        let dest = SocketAddr::V4(SocketAddrV4::new(*peer.ip(), orig_port));
        tokio::spawn(relay(
            client,
            dest,
            key,
            generation,
            nat.clone(),
            cfg.clone(),
            proxy_addr,
            stats.clone(),
        ));
    }
}

#[allow(clippy::too_many_arguments)]
async fn relay(
    client: TcpStream,
    dest: SocketAddr,
    key: (Ipv4Addr, u16),
    generation: u64,
    nat: Nat,
    cfg: Arc<ProxyConfig>,
    proxy_addr: SocketAddr,
    stats: Arc<Stats>,
) {
    stats.active.fetch_add(1, Relaxed);
    stats.total.fetch_add(1, Relaxed);
    let _ = client.set_nodelay(true);
    match proxy::connect_via(proxy_addr, &cfg, &Target::Ip(dest)).await {
        Ok(upstream) => pipe(client, upstream, &stats).await,
        Err(e) => {
            stats.failed.fetch_add(1, Relaxed);
            *stats.last_error.lock() = Some(format!("{dest}: {e}"));
        }
    }
    stats.active.fetch_sub(1, Relaxed);
    if let Some(e) = nat.lock().get_mut(&key) {
        if e.generation == generation {
            e.closed = true;
            e.last_seen = Instant::now();
        }
    }
}

async fn pipe(client: TcpStream, upstream: TcpStream, stats: &Stats) {
    let (mut cr, mut cw) = client.into_split();
    let (mut ur, mut uw) = upstream.into_split();
    let up = async {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = cr.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            uw.write_all(&buf[..n]).await?;
            stats.up.fetch_add(n as u64, Relaxed);
        }
        uw.shutdown().await
    };
    let down = async {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = ur.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            cw.write_all(&buf[..n]).await?;
            stats.down.fetch_add(n as u64, Relaxed);
        }
        cw.shutdown().await
    };
    let _ = tokio::try_join!(up, down);
}

enum Verdict {
    Pass,
    Modified,
    Drop,
    /// Drop the packet and inject this one back to the sender.
    Reply(Vec<u8>),
}

struct PacketLoop {
    nat: Nat,
    rules: Arc<Rules>,
    stats: Arc<Stats>,
    relay_port: u16,
    proxy_addr: SocketAddr,
    own_pid: u32,
    generation: u64,
    tcp4: HashMap<(u16, Ipv4Addr, u16), u32>,
    tcp6: HashMap<(u16, Ipv6Addr, u16), u32>,
    udp4: HashMap<u16, (u32, Instant)>,
    udp6: HashMap<u16, (u32, Instant)>,
    targets: HashMap<u32, (bool, Instant)>,
    targets_version: u64,
    last_purge: Instant,
}

fn local_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || (o[0] == 100 && (o[1] & 0xC0) == 64)
}

fn local_v6(ip: Ipv6Addr) -> bool {
    let s0 = ip.segments()[0];
    ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() || (s0 & 0xffc0) == 0xfe80 || (s0 & 0xfe00) == 0xfc00
}

fn be16(p: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([p[at], p[at + 1]])
}

fn swap_v4_addrs(p: &mut [u8]) {
    for i in 0..4 {
        p.swap(12 + i, 16 + i);
    }
}

/// Builds a TCP RST+ACK answering an IPv6 SYN.
fn rst6(syn: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; 60];
    r[0] = 0x60;
    r[4..6].copy_from_slice(&20u16.to_be_bytes());
    r[6] = 6;
    r[7] = 64;
    r[8..24].copy_from_slice(&syn[24..40]);
    r[24..40].copy_from_slice(&syn[8..24]);
    r[40..42].copy_from_slice(&syn[42..44]);
    r[42..44].copy_from_slice(&syn[40..42]);
    let seq = u32::from_be_bytes([syn[44], syn[45], syn[46], syn[47]]);
    r[48..52].copy_from_slice(&seq.wrapping_add(1).to_be_bytes());
    r[52] = 5 << 4;
    r[53] = 0x14;
    r
}

impl PacketLoop {
    fn new(nat: Nat, rules: Arc<Rules>, stats: Arc<Stats>, relay_port: u16, proxy_addr: SocketAddr) -> Self {
        PacketLoop {
            nat,
            rules,
            stats,
            relay_port,
            proxy_addr,
            own_pid: std::process::id(),
            generation: 0,
            tcp4: HashMap::new(),
            tcp6: HashMap::new(),
            udp4: HashMap::new(),
            udp6: HashMap::new(),
            targets: HashMap::new(),
            targets_version: u64::MAX,
            last_purge: Instant::now(),
        }
    }

    fn run(mut self, divert: &Divert, stop: &AtomicBool) {
        let mut buf = vec![0u8; divert::MTU_MAX];
        let mut addr = Address::zeroed();
        loop {
            let len = match divert.recv(&mut buf, &mut addr) {
                Ok(n) => n,
                Err(code) => {
                    // 6 invalid handle, 232 no data (shutdown), 995 aborted
                    if stop.load(SeqCst) || matches!(code, 6 | 232 | 995) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
            };
            let pkt = &mut buf[..len];
            match self.handle(pkt, &mut addr) {
                Verdict::Pass => {
                    divert.send(pkt, &addr);
                }
                Verdict::Modified => {
                    divert.api().calc_checksums(pkt, &mut addr);
                    divert.send(pkt, &addr);
                }
                Verdict::Drop => {}
                Verdict::Reply(mut reply) => {
                    let mut a = addr;
                    a.set_outbound(false);
                    divert.api().calc_checksums(&mut reply, &mut a);
                    divert.send(&reply, &a);
                }
            }
            if self.last_purge.elapsed() > Duration::from_secs(10) {
                self.purge();
            }
        }
    }

    fn handle(&mut self, p: &mut [u8], addr: &mut Address) -> Verdict {
        if p.len() < 20 {
            return Verdict::Pass;
        }
        match p[0] >> 4 {
            4 => self.handle_v4(p, addr),
            6 => self.handle_v6(p),
            _ => Verdict::Pass,
        }
    }

    fn redirect(&self, p: &mut [u8], ihl: usize, addr: &mut Address) {
        p[ihl + 2..ihl + 4].copy_from_slice(&self.relay_port.to_be_bytes());
        swap_v4_addrs(p);
        addr.set_outbound(false);
    }

    fn handle_v4(&mut self, p: &mut [u8], addr: &mut Address) -> Verdict {
        let ihl = ((p[0] & 0x0f) as usize) * 4;
        if ihl < 20 || p.len() < ihl + 8 {
            return Verdict::Pass;
        }
        if be16(p, 6) & 0x1fff != 0 {
            return Verdict::Pass; // non-first fragment
        }
        let dst = Ipv4Addr::new(p[16], p[17], p[18], p[19]);
        let proto = p[9];
        let sport = be16(p, ihl);
        let dport = be16(p, ihl + 2);

        if proto == 17 {
            if local_v4(dst) {
                return Verdict::Pass;
            }
            return match self.udp4_pid(sport) {
                Some(pid) if self.is_target(pid) => {
                    self.stats.blocked.fetch_add(1, Relaxed);
                    Verdict::Drop
                }
                _ => Verdict::Pass,
            };
        }
        if proto != 6 || p.len() < ihl + 20 {
            return Verdict::Pass;
        }
        let flags = p[ihl + 13];
        let new_conn = flags & 0x02 != 0 && flags & 0x10 == 0;

        // Relay -> app.
        if sport == self.relay_port {
            let mut nat = self.nat.lock();
            return match nat.get_mut(&(dst, dport)) {
                Some(e) => {
                    e.last_seen = Instant::now();
                    p[ihl..ihl + 2].copy_from_slice(&e.orig_port.to_be_bytes());
                    swap_v4_addrs(p);
                    addr.set_outbound(false);
                    Verdict::Modified
                }
                None => Verdict::Drop,
            };
        }

        // App -> relay, connection already redirected.
        {
            let mut nat = self.nat.lock();
            if let Some(e) = nat.get_mut(&(dst, sport)) {
                if e.orig_port == dport && !(new_conn && e.closed) {
                    e.last_seen = Instant::now();
                    drop(nat);
                    self.redirect(p, ihl, addr);
                    return Verdict::Modified;
                }
            }
        }

        if !new_conn
            || local_v4(dst)
            || SocketAddr::V4(SocketAddrV4::new(dst, dport)) == self.proxy_addr
        {
            return Verdict::Pass;
        }
        match self.tcp4_pid(sport, dst, dport) {
            Some(pid) if self.is_target(pid) => {
                self.generation += 1;
                self.nat.lock().insert(
                    (dst, sport),
                    NatEntry { orig_port: dport, generation: self.generation, last_seen: Instant::now(), closed: false },
                );
                self.redirect(p, ihl, addr);
                Verdict::Modified
            }
            _ => Verdict::Pass,
        }
    }

    fn handle_v6(&mut self, p: &mut [u8]) -> Verdict {
        if p.len() < 48 {
            return Verdict::Pass;
        }
        let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&p[24..40]).unwrap());
        if local_v6(dst) {
            return Verdict::Pass;
        }
        let sport = be16(p, 40);
        let dport = be16(p, 42);
        match p[6] {
            17 => match self.udp6_pid(sport) {
                Some(pid) if self.is_target(pid) => {
                    self.stats.blocked.fetch_add(1, Relaxed);
                    Verdict::Drop
                }
                _ => Verdict::Pass,
            },
            6 if p.len() >= 60 => {
                let flags = p[53];
                if flags & 0x02 == 0 || flags & 0x10 != 0 {
                    return Verdict::Pass;
                }
                match self.tcp6_pid(sport, dst, dport) {
                    Some(pid) if self.is_target(pid) => Verdict::Reply(rst6(p)),
                    _ => Verdict::Pass,
                }
            }
            _ => Verdict::Pass,
        }
    }

    fn tcp4_pid(&mut self, lport: u16, raddr: Ipv4Addr, rport: u16) -> Option<u32> {
        let key = (lport, raddr, rport);
        if let Some(pid) = self.tcp4.get(&key) {
            return Some(*pid);
        }
        self.tcp4 = procs::tcp4_table()
            .iter()
            .map(|r| {
                (
                    (procs::port_from(r.dwLocalPort), procs::ipv4_from(r.dwRemoteAddr), procs::port_from(r.dwRemotePort)),
                    r.dwOwningPid,
                )
            })
            .collect();
        self.tcp4.get(&key).copied()
    }

    fn tcp6_pid(&mut self, lport: u16, raddr: Ipv6Addr, rport: u16) -> Option<u32> {
        let key = (lport, raddr, rport);
        if let Some(pid) = self.tcp6.get(&key) {
            return Some(*pid);
        }
        self.tcp6 = procs::tcp6_table()
            .iter()
            .map(|r| {
                (
                    (procs::port_from(r.dwLocalPort), Ipv6Addr::from(r.ucRemoteAddr), procs::port_from(r.dwRemotePort)),
                    r.dwOwningPid,
                )
            })
            .collect();
        self.tcp6.get(&key).copied()
    }

    fn udp4_pid(&mut self, lport: u16) -> Option<u32> {
        let fresh = |e: &(u32, Instant)| e.1.elapsed() < Duration::from_secs(5);
        if let Some(e) = self.udp4.get(&lport).filter(|e| fresh(e)) {
            return Some(e.0);
        }
        let now = Instant::now();
        self.udp4 = procs::udp4_table()
            .iter()
            .map(|r| (procs::port_from(r.dwLocalPort), (r.dwOwningPid, now)))
            .collect();
        self.udp4.get(&lport).map(|e| e.0)
    }

    fn udp6_pid(&mut self, lport: u16) -> Option<u32> {
        let fresh = |e: &(u32, Instant)| e.1.elapsed() < Duration::from_secs(5);
        if let Some(e) = self.udp6.get(&lport).filter(|e| fresh(e)) {
            return Some(e.0);
        }
        let now = Instant::now();
        self.udp6 = procs::udp6_table()
            .iter()
            .map(|r| (procs::port_from(r.dwLocalPort), (r.dwOwningPid, now)))
            .collect();
        self.udp6.get(&lport).map(|e| e.0)
    }

    fn is_target(&mut self, pid: u32) -> bool {
        if pid == self.own_pid || pid <= 4 {
            return false;
        }
        let version = self.rules.version();
        if version != self.targets_version {
            self.targets.clear();
            self.targets_version = version;
        }
        if let Some((hit, at)) = self.targets.get(&pid) {
            if at.elapsed() < Duration::from_secs(10) {
                return *hit;
            }
        }
        let hit = procs::process_name(pid).is_some_and(|n| self.rules.matches(&n));
        self.targets.insert(pid, (hit, Instant::now()));
        hit
    }

    fn purge(&mut self) {
        let now = Instant::now();
        self.nat.lock().retain(|_, e| {
            let idle = now - e.last_seen;
            if e.closed {
                idle < Duration::from_secs(60)
            } else {
                idle < Duration::from_secs(15 * 60)
            }
        });
        self.targets.retain(|_, (_, at)| now - *at < Duration::from_secs(60));
        self.last_purge = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::ProxyKind;
    use crate::proxy::test_support::{echo_server, socks5_server};

    const RELAY: u16 = 50000;
    const APP: [u8; 4] = [192, 168, 1, 5];
    const SERVER: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
    const CHROME_PID: u32 = 1234;
    const OTHER_PID: u32 = 777;

    fn tcp4(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16, flags: u8) -> Vec<u8> {
        let mut p = vec![0u8; 40];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&40u16.to_be_bytes());
        p[8] = 64;
        p[9] = 6;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&sport.to_be_bytes());
        p[22..24].copy_from_slice(&dport.to_be_bytes());
        p[24..28].copy_from_slice(&1000u32.to_be_bytes());
        p[32] = 5 << 4;
        p[33] = flags;
        p
    }

    fn outbound() -> Address {
        let mut a = Address::zeroed();
        a.set_outbound(true);
        a
    }

    /// A packet loop where pid 1234 is "chrome" and pid 777 is something else.
    fn packet_loop() -> PacketLoop {
        let rules = Arc::new(Rules::default());
        rules.set(vec!["chrome".into()]);
        let mut l = PacketLoop::new(
            Default::default(),
            rules.clone(),
            Arc::new(Stats::default()),
            RELAY,
            "9.9.9.9:1080".parse().unwrap(),
        );
        l.targets_version = rules.version();
        l.targets.insert(CHROME_PID, (true, Instant::now()));
        l.targets.insert(OTHER_PID, (false, Instant::now()));
        l
    }

    #[test]
    fn reflects_chosen_app_both_ways() {
        let mut l = packet_loop();
        l.tcp4.insert((51000, SERVER, 443), CHROME_PID);

        // app SYN  A:51000 -> S:443  =>  S:51000 -> A:relay, inbound
        let mut a = outbound();
        let mut syn = tcp4(APP, 51000, SERVER.octets(), 443, 0x02);
        assert!(matches!(l.handle(&mut syn, &mut a), Verdict::Modified));
        assert!(!a.is_outbound());
        assert_eq!(syn[12..16], SERVER.octets());
        assert_eq!(syn[16..20], APP);
        assert_eq!((be16(&syn, 20), be16(&syn, 22)), (51000, RELAY));

        // relay SYN-ACK  A:relay -> S:51000  =>  S:443 -> A:51000, inbound
        let mut a = outbound();
        let mut synack = tcp4(APP, RELAY, SERVER.octets(), 51000, 0x12);
        assert!(matches!(l.handle(&mut synack, &mut a), Verdict::Modified));
        assert!(!a.is_outbound());
        assert_eq!(synack[12..16], SERVER.octets());
        assert_eq!(synack[16..20], APP);
        assert_eq!((be16(&synack, 20), be16(&synack, 22)), (443, 51000));

        // later app data follows the NAT entry without any pid lookup
        l.tcp4.clear();
        let mut a = outbound();
        let mut data = tcp4(APP, 51000, SERVER.octets(), 443, 0x18);
        assert!(matches!(l.handle(&mut data, &mut a), Verdict::Modified));
        assert_eq!(be16(&data, 22), RELAY);
    }

    #[test]
    fn leaves_other_traffic_alone() {
        let mut l = packet_loop();
        l.tcp4.insert((52000, SERVER, 443), OTHER_PID);
        let lan = Ipv4Addr::new(192, 168, 1, 1);
        l.tcp4.insert((51001, lan, 80), CHROME_PID);

        for mut p in [
            tcp4(APP, 52000, SERVER.octets(), 443, 0x02), // other app
            tcp4(APP, 51001, lan.octets(), 80, 0x02),     // chrome to LAN
            tcp4(APP, 53000, SERVER.octets(), 443, 0x10), // unknown established flow
            tcp4(APP, 53001, [9, 9, 9, 9], 1080, 0x02),   // the proxy itself
        ] {
            let orig = p.clone();
            let mut a = outbound();
            assert!(matches!(l.handle(&mut p, &mut a), Verdict::Pass));
            assert_eq!(p, orig);
            assert!(a.is_outbound());
        }
    }

    #[test]
    fn ipv6_syn_of_chosen_app_is_reset() {
        let mut l = packet_loop();
        let src: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let dst: Ipv6Addr = "2606:2800:220:1::1".parse().unwrap();
        l.tcp6.insert((51500, dst, 443), CHROME_PID);
        let mut p = vec![0u8; 60];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&20u16.to_be_bytes());
        p[6] = 6;
        p[7] = 64;
        p[8..24].copy_from_slice(&src.octets());
        p[24..40].copy_from_slice(&dst.octets());
        p[40..42].copy_from_slice(&51500u16.to_be_bytes());
        p[42..44].copy_from_slice(&443u16.to_be_bytes());
        p[44..48].copy_from_slice(&7u32.to_be_bytes());
        p[52] = 5 << 4;
        p[53] = 0x02;
        let Verdict::Reply(r) = l.handle(&mut p, &mut outbound()) else {
            panic!("expected RST")
        };
        assert_eq!(r[8..24], dst.octets());
        assert_eq!(r[24..40], src.octets());
        assert_eq!((be16(&r, 40), be16(&r, 42)), (443, 51500));
        assert_eq!(u32::from_be_bytes([r[48], r[49], r[50], r[51]]), 8);
        assert_eq!(r[53], 0x14);
    }

    #[test]
    fn udp_of_chosen_app_is_dropped() {
        let mut l = packet_loop();
        l.udp4.insert(60000, (CHROME_PID, Instant::now()));
        l.udp4.insert(60001, (OTHER_PID, Instant::now()));
        let udp = |sport: u16| {
            let mut p = vec![0u8; 28];
            p[0] = 0x45;
            p[9] = 17;
            p[12..16].copy_from_slice(&APP);
            p[16..20].copy_from_slice(&SERVER.octets());
            p[20..22].copy_from_slice(&sport.to_be_bytes());
            p[22..24].copy_from_slice(&443u16.to_be_bytes());
            p
        };
        assert!(matches!(l.handle(&mut udp(60000), &mut outbound()), Verdict::Drop));
        assert!(matches!(l.handle(&mut udp(60001), &mut outbound()), Verdict::Pass));
    }

    /// WinDivertOpen compiles the filter before touching the driver, so a bad
    /// filter fails with ERROR_INVALID_PARAMETER even without admin rights.
    #[test]
    fn windivert_loads_and_filter_is_valid() {
        let api = Api::load().expect("WinDivert.dll loads");
        if let Err(e) = api.open(FILTER, 0) {
            assert!(!e.contains("os error 87"), "{e}");
            println!("open without admin: {e}");
        }
    }

    #[test]
    fn relay_forwards_through_socks5() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let echo_port = echo.local_addr().unwrap().port();
            tokio::spawn(echo_server(echo));

            let socks = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let socks_addr = socks.local_addr().unwrap();
            tokio::spawn(socks5_server(socks, "user", "secret"));

            let relay_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let relay_addr = relay_listener.local_addr().unwrap();
            let nat: Nat = Default::default();
            let stats = Arc::new(Stats::default());
            let cfg = ProxyConfig {
                kind: ProxyKind::Socks5,
                host: "127.0.0.1".into(),
                port: socks_addr.port(),
                user: "user".into(),
                pass: "secret".into(),
            };
            tokio::spawn(accept_loop(relay_listener, nat.clone(), Arc::new(cfg), socks_addr, stats.clone()));

            // The "app": its reflected connection arrives from (orig ip, app port).
            let sock = tokio::net::TcpSocket::new_v4().unwrap();
            sock.bind("127.0.0.1:0".parse().unwrap()).unwrap();
            let app_port = sock.local_addr().unwrap().port();
            nat.lock().insert(
                (Ipv4Addr::LOCALHOST, app_port),
                NatEntry { orig_port: echo_port, generation: 1, last_seen: Instant::now(), closed: false },
            );
            let mut c = sock.connect(relay_addr).await.unwrap();
            c.write_all(b"hello via proxy").await.unwrap();
            let mut buf = [0u8; 15];
            c.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello via proxy");
            drop(c);
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert_eq!(stats.total.load(Relaxed), 1);
            assert_eq!(stats.failed.load(Relaxed), 0);
            assert!(stats.up.load(Relaxed) >= 15 && stats.down.load(Relaxed) >= 15);
            assert!(nat.lock().get(&(Ipv4Addr::LOCALHOST, app_port)).unwrap().closed);
        });
    }
}
