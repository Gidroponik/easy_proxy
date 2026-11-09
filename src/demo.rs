//! Mock data for README screenshots: `cargo run --features demo -- --demo <scene>`.
//!
//! Scenes: `empty`, `paste`, `parsed`, `checked`, `search`, `running`.
//! Nothing here touches the network, the real process list or the saved config.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;

use gpui_kit::{Context, Window};

use crate::engine::Stats;
use crate::procs::ProcGroup;
use crate::{CheckState, ProxyApp, RunState};

pub static ACTIVE: AtomicBool = AtomicBool::new(false);

/// 203.0.113.0/24 is TEST-NET-3 (RFC 5737), reserved for documentation.
const ADDR: &str = "203.0.113.45:1080";
const AUTH: &str = "demo_user:demo_pass";
const LINE: &str = "socks5://demo_user:demo_pass@203.0.113.45:1080";
const CHECK_OK: &str = "Работает · IP 203.0.113.45 · Amsterdam, Netherlands · 84 мс";

pub fn processes() -> Vec<ProcGroup> {
    let mut list: Vec<ProcGroup> = [
        ("chrome.exe", 27),
        ("Code.exe", 11),
        ("Discord.exe", 6),
        ("explorer.exe", 1),
        ("firefox.exe", 9),
        ("msedge.exe", 14),
        ("obs64.exe", 1),
        ("qbittorrent.exe", 1),
        ("Spotify.exe", 5),
        ("steam.exe", 1),
        ("steamwebhelper.exe", 8),
        ("Telegram.exe", 1),
        ("WindowsTerminal.exe", 2),
        ("Zoom.exe", 3),
    ]
    .into_iter()
    .map(|(name, count)| ProcGroup { name: name.into(), count })
    .collect();
    list.sort_by_key(|g| g.name.to_lowercase());
    list
}

pub fn app(scene: &str, window: &mut Window, cx: &mut Context<ProxyApp>) -> ProxyApp {
    ACTIVE.store(true, Relaxed);
    let (addr, auth, kind, masks): (&str, &str, &str, &[&str]) = match scene {
        "empty" => ("", "", "http", &[]),
        "paste" => (LINE, "", "http", &[]),
        "parsed" => (ADDR, AUTH, "socks5", &[]),
        "search" => (ADDR, AUTH, "socks5", &["chrome.exe", "telegram.exe", "*steam*"]),
        _ => (ADDR, AUTH, "socks5", &["chrome.exe", "telegram.exe", "discord.exe"]),
    };
    let config = serde_json::json!({ "addr": addr, "auth": auth, "kind": kind, "masks": masks });
    let mut app = ProxyApp::with_config(config, false, window, cx);
    app.elevated = true;
    app.procs = processes();
    if matches!(scene, "checked" | "search" | "running") {
        app.check = CheckState::Ok(CHECK_OK.into());
    }
    if scene == "search" {
        app.search.update(cx, |s, cx| s.set_value("steam", window, cx));
    }
    if scene == "running" {
        let s = Stats::default();
        s.active.store(14, Relaxed);
        s.total.store(386, Relaxed);
        s.up.store(6_815_744, Relaxed);
        s.down.store(241_172_480, Relaxed);
        s.blocked.store(52, Relaxed);
        app.run = RunState::Demo(Arc::new(s));
    }
    app
}
