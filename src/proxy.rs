//! Proxy settings, line parsing, SOCKS5 / HTTP CONNECT handshakes and the "Check" probe.

use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::time::{Duration, Instant};

use base64::Engine as _;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProxyKind {
    Http,
    Socks5,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyConfig {
    pub kind: ProxyKind,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub pass: String,
}

impl ProxyConfig {
    /// Resolves the proxy host once, preferring IPv4.
    pub fn resolve(&self) -> Result<SocketAddr, String> {
        let addrs: Vec<SocketAddr> = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|e| format!("Не удалось найти хост {}: {e}", self.host))?
            .collect();
        addrs
            .iter()
            .find(|a| a.is_ipv4())
            .or(addrs.first())
            .copied()
            .ok_or_else(|| format!("Хост {} не резолвится", self.host))
    }
}

/// Result of auto-parsing a pasted proxy line.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ParsedProxy {
    pub kind: Option<ProxyKind>,
    pub host: String,
    pub port: u16,
    pub user: Option<String>,
    pub pass: Option<String>,
}

fn parse_port(s: &str) -> Option<u16> {
    let s = s.trim();
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse::<u16>().ok().filter(|p| *p != 0)
}

/// A hostname or IPv4 literal: needs a dot (or be `localhost`), no odd characters.
fn is_host(s: &str) -> bool {
    let s = s.trim();
    !s.is_empty()
        && (s.contains('.') || s.eq_ignore_ascii_case("localhost"))
        && s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
}

fn split_host_port(s: &str) -> Option<(String, u16)> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port = parse_port(rest[end + 1..].strip_prefix(':')?)?;
        return Some((host.to_string(), port));
    }
    let (host, port) = s.rsplit_once(':')?;
    if !is_host(host) {
        return None;
    }
    Some((host.trim().to_string(), parse_port(port)?))
}

fn split_creds(s: &str) -> (Option<String>, Option<String>) {
    let s = s.trim();
    if s.is_empty() {
        return (None, None);
    }
    match s.split_once(':') {
        Some((u, p)) => (Some(u.to_string()), Some(p.to_string())),
        None => (Some(s.to_string()), None),
    }
}

/// Parses the common proxy-list formats:
/// `ip:port`, `ip:port:user:pass`, `user:pass:ip:port`, `user:pass@ip:port`,
/// `ip:port@user:pass`, `socks5://user:pass@ip:port`, `http://ip:port`,
/// and whitespace / `;` / `|` separated variants of these.
pub fn parse_proxy_line(input: &str) -> Option<ParsedProxy> {
    let mut s = input.trim().trim_end_matches('/').to_string();
    if s.is_empty() {
        return None;
    }

    let mut kind = None;
    if let Some(pos) = s.find("://") {
        kind = match s[..pos].to_ascii_lowercase().as_str() {
            "socks5" | "socks5h" | "socks" => Some(ProxyKind::Socks5),
            "http" | "https" => Some(ProxyKind::Http),
            _ => None,
        };
        s = s[pos + 3..].to_string();
    }

    if s.contains(|c: char| c.is_whitespace() || c == ';' || c == '|') {
        s = s
            .split(|c: char| c.is_whitespace() || c == ';' || c == '|')
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join(":");
    }

    if let Some(at) = s.rfind('@') {
        let (left, right) = (&s[..at], &s[at + 1..]);
        let (host, port, creds) = if let Some((h, p)) = split_host_port(right) {
            (h, p, left)
        } else if let Some((h, p)) = split_host_port(left) {
            (h, p, right)
        } else {
            return None;
        };
        let (user, pass) = split_creds(creds);
        return Some(ParsedProxy { kind, host, port, user, pass });
    }

    let parts: Vec<&str> = s.split(':').collect();
    let n = parts.len();
    if n < 2 {
        return None;
    }
    if is_host(parts[0]) {
        if let Some(port) = parse_port(parts[1]) {
            let user = parts.get(2).map(|u| u.to_string()).filter(|u| !u.is_empty());
            let pass = (n > 3).then(|| parts[3..].join(":"));
            return Some(ParsedProxy { kind, host: parts[0].to_string(), port, user, pass });
        }
    }
    if n >= 4 && is_host(parts[n - 2]) {
        if let Some(port) = parse_port(parts[n - 1]) {
            return Some(ParsedProxy {
                kind,
                host: parts[n - 2].to_string(),
                port,
                user: Some(parts[0].to_string()),
                pass: Some(parts[1..n - 2].join(":")),
            });
        }
    }
    None
}

/// Where the proxy should connect to.
pub enum Target {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl Target {
    fn host_port(&self) -> String {
        match self {
            Target::Ip(SocketAddr::V4(a)) => a.to_string(),
            Target::Ip(SocketAddr::V6(a)) => format!("[{}]:{}", a.ip(), a.port()),
            Target::Domain(h, p) => format!("{h}:{p}"),
        }
    }
}

fn err(msg: impl Into<String>) -> io::Error {
    io::Error::other(msg.into())
}

/// Opens a TCP connection to `target` through the proxy at `proxy_addr`.
pub async fn connect_via(
    proxy_addr: SocketAddr,
    cfg: &ProxyConfig,
    target: &Target,
) -> io::Result<TcpStream> {
    let mut s = timeout(CONNECT_TIMEOUT, TcpStream::connect(proxy_addr))
        .await
        .map_err(|_| err("таймаут подключения к прокси"))??;
    let _ = s.set_nodelay(true);
    let hs = async {
        match cfg.kind {
            ProxyKind::Socks5 => socks5_handshake(&mut s, cfg, target).await,
            ProxyKind::Http => http_connect(&mut s, cfg, target).await,
        }
    };
    timeout(CONNECT_TIMEOUT, hs)
        .await
        .map_err(|_| err("таймаут рукопожатия с прокси"))??;
    Ok(s)
}

async fn socks5_handshake(s: &mut TcpStream, cfg: &ProxyConfig, target: &Target) -> io::Result<()> {
    let with_auth = !cfg.user.is_empty();
    if with_auth {
        s.write_all(&[5, 2, 0, 2]).await?;
    } else {
        s.write_all(&[5, 1, 0]).await?;
    }
    let mut r = [0u8; 2];
    s.read_exact(&mut r).await?;
    if r[0] != 5 {
        return Err(err("это не SOCKS5 прокси"));
    }
    match r[1] {
        0 => {}
        2 => {
            let (u, p) = (cfg.user.as_bytes(), cfg.pass.as_bytes());
            if u.len() > 255 || p.len() > 255 {
                return Err(err("слишком длинный логин или пароль"));
            }
            let mut req = vec![1, u.len() as u8];
            req.extend_from_slice(u);
            req.push(p.len() as u8);
            req.extend_from_slice(p);
            s.write_all(&req).await?;
            s.read_exact(&mut r).await?;
            if r[1] != 0 {
                return Err(err("неверный логин или пароль"));
            }
        }
        0xFF if !with_auth => return Err(err("прокси требует логин и пароль")),
        _ => return Err(err("прокси отклонил способ авторизации")),
    }

    let mut req = vec![5, 1, 0];
    match target {
        Target::Ip(SocketAddr::V4(a)) => {
            req.push(1);
            req.extend_from_slice(&a.ip().octets());
            req.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Ip(SocketAddr::V6(a)) => {
            req.push(4);
            req.extend_from_slice(&a.ip().octets());
            req.extend_from_slice(&a.port().to_be_bytes());
        }
        Target::Domain(h, p) => {
            let h = &h.as_bytes()[..h.len().min(255)];
            req.push(3);
            req.push(h.len() as u8);
            req.extend_from_slice(h);
            req.extend_from_slice(&p.to_be_bytes());
        }
    }
    s.write_all(&req).await?;

    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0 {
        let why = match head[1] {
            1 => "общая ошибка сервера",
            2 => "запрещено правилами прокси",
            3 => "сеть недоступна",
            4 => "хост недоступен",
            5 => "в соединении отказано",
            6 => "TTL истёк",
            7 => "команда не поддерживается",
            8 => "тип адреса не поддерживается",
            _ => "неизвестная ошибка",
        };
        return Err(err(format!("SOCKS5: {why}")));
    }
    let skip = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize + 2
        }
        _ => return Err(err("SOCKS5: кривой ответ")),
    };
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest).await?;
    Ok(())
}

async fn http_connect(s: &mut TcpStream, cfg: &ProxyConfig, target: &Target) -> io::Result<()> {
    let hp = target.host_port();
    let mut req = format!("CONNECT {hp} HTTP/1.1\r\nHost: {hp}\r\nProxy-Connection: Keep-Alive\r\n");
    if !cfg.user.is_empty() {
        let token = base64::engine::general_purpose::STANDARD
            .encode(format!("{}:{}", cfg.user, cfg.pass));
        req.push_str(&format!("Proxy-Authorization: Basic {token}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).await?;

    // Read the response head byte by byte so no tunnelled bytes are swallowed.
    let mut head = Vec::with_capacity(256);
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if s.read(&mut b).await? == 0 {
            return Err(err("прокси закрыл соединение"));
        }
        head.push(b[0]);
        if head.len() > 16 * 1024 {
            return Err(err("слишком длинный ответ прокси"));
        }
    }
    let head = String::from_utf8_lossy(&head);
    let status_line = head.lines().next().unwrap_or_default();
    let code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .ok_or_else(|| err("это не HTTP прокси"))?;
    match code {
        200..=299 => Ok(()),
        407 => Err(err("неверный логин или пароль (407)")),
        _ => Err(err(format!("прокси ответил: {}", status_line.trim()))),
    }
}

pub struct CheckResult {
    pub ip: String,
    pub location: String,
    pub millis: u128,
}

async fn http_get_via(
    proxy_addr: SocketAddr,
    cfg: &ProxyConfig,
    host: &str,
    path: &str,
) -> io::Result<String> {
    let mut s = connect_via(proxy_addr, cfg, &Target::Domain(host.to_string(), 80)).await?;
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: easy-proxy/0.1\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    timeout(CONNECT_TIMEOUT, s.read_to_end(&mut buf))
        .await
        .map_err(|_| err("таймаут ответа"))??;
    let text = String::from_utf8_lossy(&buf).to_string();
    let body = text.split_once("\r\n\r\n").map(|(_, b)| b).unwrap_or("");
    match (body.find('{'), body.rfind('}')) {
        (Some(a), Some(b)) if b > a => Ok(body[a..=b].to_string()),
        _ => Err(err("пустой ответ через прокси")),
    }
}

/// Connects through the proxy and asks a public service for the exit IP.
pub async fn check(cfg: ProxyConfig) -> Result<CheckResult, String> {
    let started = Instant::now();
    let proxy_addr = tokio::task::spawn_blocking({
        let cfg = cfg.clone();
        move || cfg.resolve()
    })
    .await
    .map_err(|e| e.to_string())??;

    let ip_api = http_get_via(
        proxy_addr,
        &cfg,
        "ip-api.com",
        "/json/?fields=status,query,country,countryCode,city",
    )
    .await;
    match ip_api {
        Ok(body) => {
            let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
            let ip = v["query"].as_str().unwrap_or("?").to_string();
            let country = v["country"].as_str().unwrap_or("");
            let city = v["city"].as_str().unwrap_or("");
            let location = match (country.is_empty(), city.is_empty()) {
                (false, false) => format!("{country}, {city}"),
                (false, true) => country.to_string(),
                _ => String::new(),
            };
            Ok(CheckResult { ip, location, millis: started.elapsed().as_millis() })
        }
        Err(first) => {
            // ip-api may be blocked or rate limited; fall back to ipify.
            let body = http_get_via(proxy_addr, &cfg, "api.ipify.org", "/?format=json")
                .await
                .map_err(|_| first.to_string())?;
            let v: serde_json::Value = serde_json::from_str(&body).map_err(|e| e.to_string())?;
            Ok(CheckResult {
                ip: v["ip"].as_str().unwrap_or("?").to_string(),
                location: String::new(),
                millis: started.elapsed().as_millis(),
            })
        }
    }
}

/// Runs [`check`] on a private single-threaded runtime (for callers outside tokio).
pub fn check_blocking(cfg: ProxyConfig) -> Result<CheckResult, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    rt.block_on(check(cfg))
}

/// Tiny local SOCKS5 / HTTP CONNECT / echo servers for tests.
#[cfg(test)]
pub mod test_support {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    pub async fn echo_server(l: TcpListener) {
        while let Ok((mut s, _)) = l.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = s.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    }

    pub async fn socks5_server(l: TcpListener, user: &'static str, pass: &'static str) {
        while let Ok((mut c, _)) = l.accept().await {
            tokio::spawn(async move {
                let _ = async {
                    let mut b = [0u8; 2];
                    c.read_exact(&mut b).await?;
                    let mut methods = vec![0u8; b[1] as usize];
                    c.read_exact(&mut methods).await?;
                    if !methods.contains(&2) {
                        c.write_all(&[5, 0xFF]).await?;
                        return Ok(());
                    }
                    c.write_all(&[5, 2]).await?;
                    let mut v = [0u8; 2];
                    c.read_exact(&mut v).await?;
                    let mut u = vec![0u8; v[1] as usize];
                    c.read_exact(&mut u).await?;
                    let mut pl = [0u8; 1];
                    c.read_exact(&mut pl).await?;
                    let mut p = vec![0u8; pl[0] as usize];
                    c.read_exact(&mut p).await?;
                    let ok = u == user.as_bytes() && p == pass.as_bytes();
                    c.write_all(&[1, if ok { 0 } else { 1 }]).await?;
                    if !ok {
                        return Ok(());
                    }
                    let mut h = [0u8; 4];
                    c.read_exact(&mut h).await?;
                    let target = match h[3] {
                        1 => {
                            let mut a = [0u8; 6];
                            c.read_exact(&mut a).await?;
                            format!("{}.{}.{}.{}:{}", a[0], a[1], a[2], a[3], u16::from_be_bytes([a[4], a[5]]))
                        }
                        3 => {
                            let mut l = [0u8; 1];
                            c.read_exact(&mut l).await?;
                            let mut d = vec![0u8; l[0] as usize + 2];
                            c.read_exact(&mut d).await?;
                            let n = d.len();
                            format!("{}:{}", String::from_utf8_lossy(&d[..n - 2]), u16::from_be_bytes([d[n - 2], d[n - 1]]))
                        }
                        _ => return Ok(()),
                    };
                    let mut up = TcpStream::connect(target).await?;
                    c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
                    tokio::io::copy_bidirectional(&mut c, &mut up).await?;
                    Ok::<_, std::io::Error>(())
                }
                .await;
            });
        }
    }

    /// `auth` is the expected header value, e.g. `Basic dTpw`.
    pub async fn http_server(l: TcpListener, auth: &'static str) {
        while let Ok((mut c, _)) = l.accept().await {
            tokio::spawn(async move {
                let _ = async {
                    let mut head = Vec::new();
                    let mut b = [0u8; 1];
                    while !head.ends_with(b"\r\n\r\n") {
                        if c.read(&mut b).await? == 0 {
                            return Ok(());
                        }
                        head.push(b[0]);
                    }
                    let head = String::from_utf8_lossy(&head).to_string();
                    let target = head.split_whitespace().nth(1).unwrap_or_default().to_string();
                    let expected = format!("Proxy-Authorization: {auth}");
                    if !head.lines().any(|l| l == expected) {
                        c.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await?;
                        return Ok(());
                    }
                    let mut up = TcpStream::connect(target).await?;
                    c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
                    tokio::io::copy_bidirectional(&mut c, &mut up).await?;
                    Ok::<_, std::io::Error>(())
                }
                .await;
            });
        }
    }
}

#[cfg(test)]
mod handshake_tests {
    use super::test_support::*;
    use super::*;
    use tokio::net::TcpListener;

    async fn local() -> (TcpListener, SocketAddr) {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let a = l.local_addr().unwrap();
        (l, a)
    }

    fn cfg(kind: ProxyKind, addr: SocketAddr, user: &str, pass: &str) -> ProxyConfig {
        ProxyConfig { kind, host: "127.0.0.1".into(), port: addr.port(), user: user.into(), pass: pass.into() }
    }

    async fn roundtrip(kind: ProxyKind, pass: &str) -> io::Result<Vec<u8>> {
        let (echo, echo_addr) = local().await;
        tokio::spawn(echo_server(echo));
        let (px, px_addr) = local().await;
        match kind {
            ProxyKind::Socks5 => tokio::spawn(socks5_server(px, "user", "secret")),
            ProxyKind::Http => tokio::spawn(http_server(px, "Basic dXNlcjpzZWNyZXQ=")),
        };
        let mut s = connect_via(px_addr, &cfg(kind, px_addr, "user", pass), &Target::Ip(echo_addr)).await?;
        s.write_all(b"ping").await?;
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await?;
        Ok(buf.to_vec())
    }

    #[tokio::test]
    async fn socks5_tunnel_and_auth() {
        assert_eq!(roundtrip(ProxyKind::Socks5, "secret").await.unwrap(), b"ping");
        let e = roundtrip(ProxyKind::Socks5, "wrong").await.unwrap_err();
        assert!(e.to_string().contains("неверный логин"), "{e}");
    }

    #[tokio::test]
    async fn http_tunnel_and_auth() {
        assert_eq!(roundtrip(ProxyKind::Http, "secret").await.unwrap(), b"ping");
        let e = roundtrip(ProxyKind::Http, "wrong").await.unwrap_err();
        assert!(e.to_string().contains("407"), "{e}");
    }

    /// Needs internet: asks ip-api.com through a local SOCKS5 proxy.
    #[tokio::test]
    #[ignore]
    async fn check_through_local_socks5() {
        let (px, px_addr) = local().await;
        tokio::spawn(socks5_server(px, "user", "secret"));
        let r = check(cfg(ProxyKind::Socks5, px_addr, "user", "secret")).await.unwrap();
        println!("exit ip {} {} {}ms", r.ip, r.location, r.millis);
        assert!(r.ip.contains('.') || r.ip.contains(':'));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Row = (Option<ProxyKind>, String, u16, Option<String>, Option<String>);

    fn p(s: &str) -> Row {
        let r = parse_proxy_line(s).unwrap_or_else(|| panic!("failed: {s}"));
        (r.kind, r.host, r.port, r.user, r.pass)
    }

    #[test]
    fn formats() {
        let full: Row = (
            None,
            "1.2.3.4".into(),
            8080,
            Some("user".into()),
            Some("pa:ss".into()),
        );
        assert_eq!(p("1.2.3.4:8080:user:pa:ss"), full);
        assert_eq!(p("user:pa:ss:1.2.3.4:8080"), full);
        assert_eq!(p("user:pa:ss@1.2.3.4:8080"), full);
        assert_eq!(p("1.2.3.4:8080@user:pa:ss"), full);
        assert_eq!(p("  1.2.3.4 8080 user pa:ss "), full);
        assert_eq!(p("1.2.3.4:8080"), (None, "1.2.3.4".into(), 8080, None, None));
        assert_eq!(
            p("socks5://u:p@proxy.example.com:1080"),
            (
                Some(ProxyKind::Socks5),
                "proxy.example.com".into(),
                1080,
                Some("u".into()),
                Some("p".into())
            )
        );
        assert_eq!(p("http://1.2.3.4:3128/").0, Some(ProxyKind::Http));
        assert_eq!(p("user:12345:1.2.3.4:8080").3, Some("user".into()));
        assert!(parse_proxy_line("hello").is_none());
        assert!(parse_proxy_line("1.2.3.4:99999").is_none());
    }
}
