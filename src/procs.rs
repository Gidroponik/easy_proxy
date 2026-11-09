//! Windows process helpers: running apps, pid -> exe name, owner of a TCP/UDP port,
//! mask matching, elevation and the firewall rule for the local relay.

use std::collections::BTreeMap;
use std::ffi::c_void;
use std::net::Ipv4Addr;
use std::os::windows::process::CommandExt;
use std::process::Command;

use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP_STATE_DELETE_TCB,
    MIB_TCP_STATE_ESTAB, MIB_TCPROW_LH, MIB_TCPROW_LH_0, MIB_TCPROW_OWNER_PID,
    MIB_UDP6ROW_OWNER_PID, MIB_UDPROW_OWNER_PID, SetTcpEntry, TCP_TABLE_OWNER_PID_ALL,
    UDP_TABLE_OWNER_PID,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NO_WINDOW, OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
    QueryFullProcessImageNameW,
};
use windows_sys::Win32::UI::Shell::{IsUserAnAdmin, ShellExecuteW};
use windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// Running processes grouped by executable name (chrome.exe x 34 -> one row).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcGroup {
    pub name: String,
    pub count: usize,
}

const HIDDEN: &[&str] = &["[system process]", "system", "registry", "idle", "secure system", "memory compression"];

fn wide_to_string(w: &[u16]) -> String {
    let end = w.iter().position(|c| *c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

/// All processes as `(pid, exe name)`.
pub fn snapshot() -> Vec<(u32, String)> {
    let mut out = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snap == INVALID_HANDLE_VALUE {
            return out;
        }
        let mut e: PROCESSENTRY32W = std::mem::zeroed();
        e.dwSize = std::mem::size_of::<PROCESSENTRY32W>() as u32;
        if Process32FirstW(snap, &mut e) != 0 {
            loop {
                out.push((e.th32ProcessID, wide_to_string(&e.szExeFile)));
                if Process32NextW(snap, &mut e) == 0 {
                    break;
                }
            }
        }
        CloseHandle(snap);
    }
    out
}

pub fn list_processes() -> Vec<ProcGroup> {
    let mut groups: BTreeMap<String, ProcGroup> = BTreeMap::new();
    for (_, name) in snapshot() {
        let key = name.to_lowercase();
        if HIDDEN.contains(&key.as_str()) {
            continue;
        }
        groups
            .entry(key)
            .and_modify(|g| g.count += 1)
            .or_insert(ProcGroup { name, count: 1 });
    }
    groups.into_values().collect()
}

/// Lower-cased exe file name of a pid, e.g. `chrome.exe`.
pub fn process_name(pid: u32) -> Option<String> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if h.is_null() {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut len = buf.len() as u32;
        let ok = QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len);
        CloseHandle(h);
        if ok == 0 {
            return None;
        }
        let path = String::from_utf16_lossy(&buf[..len as usize]);
        path.rsplit('\\').next().map(|s| s.to_lowercase())
    }
}

fn glob(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star, mut mark) = (None::<usize>, 0usize);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            mark = t;
            p += 1;
        } else if let Some(s) = star {
            p = s + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

/// Case-insensitive mask match: `chrome`, `chrome.exe`, `chrom*`, `*telegram*`, `steam?.exe`.
pub fn mask_matches(mask: &str, name: &str) -> bool {
    let m = mask.trim().to_lowercase();
    let n = name.to_lowercase();
    if m.is_empty() {
        return false;
    }
    let stem = n.strip_suffix(".exe").unwrap_or(&n);
    if !m.contains(['*', '?']) {
        return n == m || stem == m;
    }
    glob(m.as_bytes(), n.as_bytes()) || glob(m.as_bytes(), stem.as_bytes())
}

pub fn port_from(dw: u32) -> u16 {
    u16::from_be(dw as u16)
}

pub fn ipv4_from(dw: u32) -> Ipv4Addr {
    Ipv4Addr::from(dw.to_ne_bytes())
}

/// Calls an IP Helper table function with a growing buffer and returns the rows.
fn fetch_rows<T: Copy>(call: impl Fn(*mut c_void, *mut u32) -> u32) -> Vec<T> {
    let mut size: u32 = 0;
    call(std::ptr::null_mut(), &mut size);
    for _ in 0..8 {
        let words = (size as usize + 4096) / 8 + 1;
        let mut buf = vec![0u64; words];
        let mut cap = (words * 8) as u32;
        let rc = call(buf.as_mut_ptr() as *mut c_void, &mut cap);
        if rc == 0 {
            unsafe {
                let base = buf.as_ptr() as *const u8;
                let n = *(base as *const u32) as usize;
                let rows = base.add(4) as *const T;
                return (0..n).map(|i| std::ptr::read_unaligned(rows.add(i))).collect();
            }
        }
        if rc != 122 {
            // anything but ERROR_INSUFFICIENT_BUFFER
            return Vec::new();
        }
        size = cap;
    }
    Vec::new()
}

pub fn tcp4_table() -> Vec<MIB_TCPROW_OWNER_PID> {
    fetch_rows(|p, s| unsafe { GetExtendedTcpTable(p, s, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0) })
}

pub fn tcp6_table() -> Vec<MIB_TCP6ROW_OWNER_PID> {
    fetch_rows(|p, s| unsafe { GetExtendedTcpTable(p, s, 0, AF_INET6 as u32, TCP_TABLE_OWNER_PID_ALL, 0) })
}

pub fn udp4_table() -> Vec<MIB_UDPROW_OWNER_PID> {
    fetch_rows(|p, s| unsafe { GetExtendedUdpTable(p, s, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0) })
}

pub fn udp6_table() -> Vec<MIB_UDP6ROW_OWNER_PID> {
    fetch_rows(|p, s| unsafe { GetExtendedUdpTable(p, s, 0, AF_INET6 as u32, UDP_TABLE_OWNER_PID, 0) })
}

/// Resets established IPv4 TCP connections owned by matching pids so the apps
/// reconnect (and go through the proxy). Returns how many were reset.
pub fn reset_connections(is_target: impl Fn(u32) -> bool) -> usize {
    let mut n = 0;
    for r in tcp4_table() {
        if r.dwState != MIB_TCP_STATE_ESTAB as u32 || !is_target(r.dwOwningPid) {
            continue;
        }
        let remote = ipv4_from(r.dwRemoteAddr);
        if remote.is_loopback() || remote.is_private() {
            continue;
        }
        let row = MIB_TCPROW_LH {
            Anonymous: MIB_TCPROW_LH_0 { dwState: MIB_TCP_STATE_DELETE_TCB as u32 },
            dwLocalAddr: r.dwLocalAddr,
            dwLocalPort: r.dwLocalPort,
            dwRemoteAddr: r.dwRemoteAddr,
            dwRemotePort: r.dwRemotePort,
        };
        if unsafe { SetTcpEntry(&row) } == 0 {
            n += 1;
        }
    }
    n
}

pub fn is_elevated() -> bool {
    unsafe { IsUserAnAdmin() != 0 }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Starts this exe again through UAC. Returns false if the user declined.
pub fn relaunch_elevated() -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let exe = wide(&exe.to_string_lossy());
    let verb = wide("runas");
    let args = wide("--elevated");
    let r = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            verb.as_ptr(),
            exe.as_ptr(),
            args.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    r as isize > 32
}

/// The relay receives reflected connections that look like they come from the
/// internet, so Windows Firewall must let them in for this exe.
pub fn ensure_firewall_rule() {
    let Ok(exe) = std::env::current_exe() else { return };
    let name = "name=\"ProxyApp relay\"";
    let _ = Command::new("netsh")
        .raw_arg("advfirewall firewall delete rule")
        .raw_arg(name)
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    let _ = Command::new("netsh")
        .raw_arg("advfirewall firewall add rule")
        .raw_arg(name)
        .raw_arg("dir=in action=allow protocol=TCP enable=yes profile=any")
        .raw_arg(format!("program=\"{}\"", exe.display()))
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks() {
        assert!(mask_matches("chrome", "chrome.exe"));
        assert!(mask_matches("Chrome.EXE", "chrome.exe"));
        assert!(mask_matches("chr*", "chrome.exe"));
        assert!(mask_matches("*gram*", "Telegram.exe"));
        assert!(mask_matches("steam?", "steam1.exe"));
        assert!(!mask_matches("chrome", "chromedriver.exe"));
        assert!(!mask_matches("", "chrome.exe"));
    }

    #[test]
    fn processes_listed() {
        let list = list_processes();
        assert!(!list.is_empty());
        assert!(tcp4_table().len() > 0 || udp4_table().len() > 0);
    }
}
