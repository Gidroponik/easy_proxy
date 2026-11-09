#![cfg_attr(any(not(debug_assertions), feature = "demo"), windows_subsystem = "windows")]

#[cfg(feature = "demo")]
mod demo;
mod divert;
mod engine;
mod procs;
mod proxy;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::time::Duration;

use gpui_kit::component::button::{Button, ButtonGroup, ButtonVariants as _};
use gpui_kit::component::input::{Input, InputEditsEvent, InputEvent, InputState};
use gpui_kit::component::scroll::ScrollableElement as _;
use gpui_kit::component::*;
use gpui_kit::*;
use gpui_kit::prelude::FluentBuilder as _;

use engine::{Engine, Rules};
use proxy::{ProxyConfig, ProxyKind};

enum CheckState {
    Idle,
    Running,
    Ok(SharedString),
    Err(SharedString),
}

enum RunState {
    Stopped,
    Starting,
    Running(Engine),
    /// Fake session with fixed counters, used for README screenshots.
    #[cfg(feature = "demo")]
    Demo(Arc<engine::Stats>),
    Stopping,
}

impl RunState {
    fn stats(&self) -> Option<&Arc<engine::Stats>> {
        match self {
            RunState::Running(engine) => Some(engine.stats()),
            #[cfg(feature = "demo")]
            RunState::Demo(stats) => Some(stats),
            _ => None,
        }
    }

    fn is_running(&self) -> bool {
        self.stats().is_some()
    }
}

struct ProxyApp {
    addr: Entity<InputState>,
    auth: Entity<InputState>,
    /// Set by the edit event that precedes `Change` when the edit was a paste.
    addr_pasted: bool,
    auth_pasted: bool,
    search: Entity<InputState>,
    kind: ProxyKind,
    check: CheckState,
    procs: Vec<procs::ProcGroup>,
    masks: Vec<String>,
    rules: Arc<Rules>,
    run: RunState,
    run_error: Option<SharedString>,
    elevated: bool,
    /// Whether settings are saved to the config file in APPDATA.
    persist: bool,
    _subscriptions: Vec<Subscription>,
    _ticker: Task<()>,
}

fn config_path() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|p| PathBuf::from(p).join("ProxyApp").join("config.json"))
}

fn load_config() -> serde_json::Value {
    config_path()
        .and_then(|p| std::fs::read_to_string(p).ok())
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or(serde_json::Value::Null)
}

fn current_processes() -> Vec<procs::ProcGroup> {
    #[cfg(feature = "demo")]
    if demo::ACTIVE.load(Relaxed) {
        return demo::processes();
    }
    procs::list_processes()
}

fn plural_procs(n: usize) -> String {
    let word = match (n % 10, n % 100) {
        (1, r) if r != 11 => "процесс",
        (2..=4, r) if !(12..=14).contains(&r) => "процесса",
        _ => "процессов",
    };
    format!("{n} {word}")
}

fn human_bytes(b: u64) -> String {
    const UNITS: [&str; 5] = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1024.0 && i < UNITS.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{b} Б") } else { format!("{v:.1} {}", UNITS[i]) }
}

impl ProxyApp {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        Self::with_config(load_config(), true, window, cx)
    }

    fn with_config(saved: serde_json::Value, persist: bool, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let saved_str = |k: &str| saved[k].as_str().unwrap_or_default().to_string();

        let addr = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("ip:port — или вставь строку прокси целиком")
                .default_value(saved_str("addr"))
        });
        let auth = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("login:password (необязательно)")
                .masked(true)
                .default_value(saved_str("auth"))
        });
        let search = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Имя приложения или маска: chrome, telegram*, *steam*")
        });

        let kind = if saved["kind"].as_str() == Some("socks5") { ProxyKind::Socks5 } else { ProxyKind::Http };
        let masks: Vec<String> = saved["masks"]
            .as_array()
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default();
        let rules = Arc::new(Rules::default());
        rules.set(masks.clone());

        // Auto-parse a full proxy line when it is pasted (one edit inserts more
        // than a single character), on Enter, or when the field loses focus, so
        // typing `ip:port:login:pass` by hand is not split halfway.
        fn is_paste(ev: &InputEditsEvent) -> bool {
            ev.edits().iter().any(|(e, _)| e.new_end_byte.saturating_sub(e.start_byte) > 4)
        }
        let subscriptions = vec![
            cx.subscribe_in(&addr, window, |this, _, ev: &InputEditsEvent, _, _| {
                this.addr_pasted = is_paste(ev);
            }),
            cx.subscribe_in(&addr, window, |this, _, ev: &InputEvent, window, cx| match ev {
                InputEvent::Change if !std::mem::take(&mut this.addr_pasted) => {
                    this.check = CheckState::Idle;
                    cx.notify();
                }
                InputEvent::Change | InputEvent::PressEnter { .. } | InputEvent::Blur => {
                    this.auto_parse(false, window, cx)
                }
                _ => {}
            }),
            cx.subscribe_in(&auth, window, |this, _, ev: &InputEditsEvent, _, _| {
                this.auth_pasted = is_paste(ev);
            }),
            cx.subscribe_in(&auth, window, |this, _, ev: &InputEvent, window, cx| match ev {
                InputEvent::Change if !std::mem::take(&mut this.auth_pasted) => {
                    this.check = CheckState::Idle;
                    cx.notify();
                }
                InputEvent::Change | InputEvent::PressEnter { .. } | InputEvent::Blur => {
                    this.auto_parse(true, window, cx)
                }
                _ => {}
            }),
            cx.subscribe_in(&search, window, |this, _, ev: &InputEvent, window, cx| match ev {
                InputEvent::PressEnter { .. } => this.add_mask_from_search(window, cx),
                InputEvent::Change => cx.notify(),
                _ => {}
            }),
        ];

        let ticker = cx.spawn(async move |this, cx| {
            let mut tick = 0u32;
            loop {
                if tick % 3 == 0 {
                    let list = cx.background_spawn(async { current_processes() }).await;
                    let alive = this.update(cx, |this, cx| {
                        if this.procs != list {
                            this.procs = list;
                            cx.notify();
                        }
                    });
                    if alive.is_err() {
                        break;
                    }
                } else {
                    let alive = this.update(cx, |this, cx| {
                        if this.run.is_running() {
                            cx.notify();
                        }
                    });
                    if alive.is_err() {
                        break;
                    }
                }
                tick = tick.wrapping_add(1);
                cx.background_executor().timer(Duration::from_secs(1)).await;
            }
        });

        if addr.read(cx).value().is_empty() {
            addr.update(cx, |s, cx| s.focus(window, cx));
        }

        Self {
            addr,
            auth,
            addr_pasted: false,
            auth_pasted: false,
            search,
            kind,
            check: CheckState::Idle,
            procs: Vec::new(),
            masks,
            rules,
            run: RunState::Stopped,
            run_error: None,
            elevated: procs::is_elevated(),
            persist,
            _subscriptions: subscriptions,
            _ticker: ticker,
        }
    }

    /// Auto-parsing: a full proxy line pasted into either field is split into
    /// `ip:port`, `login:password` and the proxy type.
    fn auto_parse(&mut self, from_auth: bool, window: &mut Window, cx: &mut Context<Self>) {
        self.check = CheckState::Idle;
        let source = if from_auth { &self.auth } else { &self.addr };
        let text = source.read(cx).value().to_string();
        if let Some(p) = proxy::parse_proxy_line(&text) {
            let host_port = format!("{}:{}", p.host, p.port);
            let is_full_line = p.user.is_some() || p.kind.is_some() || text.trim() != host_port;
            // In the login field only react to unambiguous full lines.
            let accept = if from_auth { p.user.is_some() && p.pass.is_some() && text.contains(&host_port) } else { is_full_line };
            if accept {
                if let Some(kind) = p.kind {
                    self.kind = kind;
                }
                self.addr.update(cx, |s, cx| s.set_value(host_port, window, cx));
                let creds = match (p.user, p.pass) {
                    (Some(u), Some(pw)) => format!("{u}:{pw}"),
                    (Some(u), None) => u,
                    _ => String::new(),
                };
                if !creds.is_empty() || from_auth {
                    self.auth.update(cx, |s, cx| s.set_value(creds, window, cx));
                }
            }
        }
        cx.notify();
    }

    fn proxy_config(&self, cx: &App) -> Result<ProxyConfig, String> {
        let addr = self.addr.read(cx).value().to_string();
        let parsed = proxy::parse_proxy_line(&addr).ok_or("Введи прокси в формате ip:port")?;
        let auth = self.auth.read(cx).value().trim().to_string();
        let (user, pass) = if auth.is_empty() {
            (parsed.user.unwrap_or_default(), parsed.pass.unwrap_or_default())
        } else {
            match auth.split_once(':') {
                Some((u, p)) => (u.to_string(), p.to_string()),
                None => (auth, String::new()),
            }
        };
        Ok(ProxyConfig { kind: self.kind, host: parsed.host, port: parsed.port, user, pass })
    }

    fn save_config(&self, cx: &App) {
        if !self.persist {
            return;
        }
        let v = serde_json::json!({
            "addr": self.addr.read(cx).value().to_string(),
            "auth": self.auth.read(cx).value().to_string(),
            "kind": if self.kind == ProxyKind::Socks5 { "socks5" } else { "http" },
            "masks": self.masks,
        });
        if let Some(p) = config_path() {
            if let Some(dir) = p.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = std::fs::write(p, v.to_string());
        }
    }

    fn run_check(&mut self, cx: &mut Context<Self>) {
        let cfg = match self.proxy_config(cx) {
            Ok(c) => c,
            Err(e) => {
                self.check = CheckState::Err(e.into());
                cx.notify();
                return;
            }
        };
        self.save_config(cx);
        self.check = CheckState::Running;
        cx.notify();
        cx.spawn(async move |this, cx| {
            let result = cx.background_spawn(async move { proxy::check_blocking(cfg) }).await;
            this.update(cx, |this, cx| {
                this.check = match result {
                    Ok(r) => {
                        let mut text = format!("Работает · IP {}", r.ip);
                        if !r.location.is_empty() {
                            text.push_str(&format!(" · {}", r.location));
                        }
                        text.push_str(&format!(" · {} мс", r.millis));
                        CheckState::Ok(text.into())
                    }
                    Err(e) => CheckState::Err(format!("Не работает: {e}").into()),
                };
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn masks_changed(&mut self, cx: &mut Context<Self>) {
        self.rules.set(self.masks.clone());
        if self.run.is_running() {
            let rules = self.rules.clone();
            cx.background_spawn(async move {
                engine::reset_targets(&rules);
            })
            .detach();
        }
        self.save_config(cx);
        cx.notify();
    }

    fn toggle_app(&mut self, name: &str, cx: &mut Context<Self>) {
        let lower = name.to_lowercase();
        let stem = lower.strip_suffix(".exe").unwrap_or(&lower).to_string();
        let before = self.masks.len();
        self.masks.retain(|m| {
            let m = m.to_lowercase();
            m != lower && m != stem
        });
        if self.masks.len() == before {
            if self.masks.iter().any(|m| procs::mask_matches(m, &lower)) {
                return; // already covered by a wildcard mask
            }
            self.masks.push(lower);
        }
        self.masks_changed(cx);
    }

    fn remove_mask(&mut self, mask: &str, cx: &mut Context<Self>) {
        self.masks.retain(|m| m != mask);
        self.masks_changed(cx);
    }

    fn add_mask_from_search(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let text = self.search.read(cx).value().trim().to_lowercase();
        if text.is_empty() {
            return;
        }
        if !self.masks.contains(&text) {
            self.masks.push(text);
            self.masks_changed(cx);
        }
        self.search.update(cx, |s, cx| s.set_value("", window, cx));
        cx.notify();
    }

    fn start(&mut self, cx: &mut Context<Self>) {
        self.run_error = None;
        let cfg = match self.proxy_config(cx) {
            Ok(c) => c,
            Err(e) => {
                self.run_error = Some(e.into());
                cx.notify();
                return;
            }
        };
        if self.masks.is_empty() {
            self.run_error = Some("Выбери хотя бы одно приложение".into());
            cx.notify();
            return;
        }
        self.rules.set(self.masks.clone());
        self.save_config(cx);
        self.run = RunState::Starting;
        cx.notify();
        let rules = self.rules.clone();
        cx.spawn(async move |this, cx| {
            let result = cx.background_spawn(async move { Engine::start(cfg, rules) }).await;
            this.update(cx, |this, cx| {
                match result {
                    Ok(engine) => this.run = RunState::Running(engine),
                    Err(e) => {
                        this.run = RunState::Stopped;
                        this.run_error = Some(e.into());
                    }
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn stop(&mut self, cx: &mut Context<Self>) {
        let RunState::Running(engine) = std::mem::replace(&mut self.run, RunState::Stopping) else {
            return;
        };
        cx.notify();
        cx.spawn(async move |this, cx| {
            cx.background_spawn(async move { drop(engine) }).await;
            this.update(cx, |this, cx| {
                this.run = RunState::Stopped;
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn section_title(&self, text: &'static str, cx: &App) -> Div {
        div().text_xs().font_semibold().text_color(cx.theme().muted_foreground).child(text)
    }

    fn render_header(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let (dot, label) = match self.run {
            RunState::Starting => (cx.theme().warning, "Запуск…"),
            RunState::Stopping => (cx.theme().warning, "Остановка…"),
            RunState::Stopped => (cx.theme().muted_foreground, "Выключено"),
            _ => (cx.theme().success, "Работает"),
        };
        h_flex()
            .justify_between()
            .child(
                h_flex()
                    .gap_2()
                    .child(Icon::new(IconName::Network).text_color(cx.theme().primary))
                    .child(div().text_lg().font_semibold().child("Easy Proxy")),
            )
            .child(
                h_flex()
                    .gap_1p5()
                    .px_2p5()
                    .py_1()
                    .rounded_full()
                    .border_1()
                    .border_color(cx.theme().border)
                    .text_xs()
                    .child(div().size_2().rounded_full().bg(dot))
                    .child(label),
            )
    }

    fn render_admin_warning(&self, cx: &mut Context<Self>) -> impl IntoElement {
        h_flex()
            .gap_2()
            .p_3()
            .rounded_lg()
            .border_1()
            .border_color(cx.theme().warning)
            .text_sm()
            .child(Icon::new(IconName::TriangleAlert).small().text_color(cx.theme().warning))
            .child(div().flex_1().min_w_0().child("Без прав администратора перехват не запустится"))
            .child(
                Button::new("elevate")
                    .small()
                    .warning()
                    .label("Запустить от админа")
                    .on_click(|_, _, cx| {
                        if procs::relaunch_elevated() {
                            cx.quit();
                        }
                    }),
            )
    }

    fn render_proxy(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let muted = cx.theme().muted_foreground;
        let locked = !matches!(self.run, RunState::Stopped);
        let status = match &self.check {
            CheckState::Idle => None,
            CheckState::Running => Some((IconName::LoaderCircle, muted, SharedString::from("Проверяю…"))),
            CheckState::Ok(t) => Some((IconName::CircleCheck, cx.theme().success, t.clone())),
            CheckState::Err(t) => Some((IconName::CircleX, cx.theme().danger, t.clone())),
        };
        v_flex()
            .gap_2()
            .child(self.section_title("ПРОКСИ", cx))
            .child(
                Input::new(&self.addr)
                    .id("addr")
                    .prefix(Icon::new(IconName::Globe).small().text_color(muted))
                    .cleanable(true)
                    .disabled(locked),
            )
            .child(
                Input::new(&self.auth)
                    .id("auth")
                    .prefix(Icon::new(IconName::User).small().text_color(muted))
                    .mask_toggle()
                    .disabled(locked),
            )
            .child(
                h_flex()
                    .gap_2()
                    .child(
                        ButtonGroup::new("kind")
                            .outline()
                            .child(
                                Button::new("kind-http")
                                    .label("HTTP")
                                    .selected(self.kind == ProxyKind::Http)
                                    .disabled(locked),
                            )
                            .child(
                                Button::new("kind-socks5")
                                    .label("SOCKS5")
                                    .selected(self.kind == ProxyKind::Socks5)
                                    .disabled(locked),
                            )
                            .on_click(cx.listener(|this, picked: &Vec<usize>, _, cx| {
                                if picked.contains(&0) {
                                    this.kind = ProxyKind::Http;
                                } else if picked.contains(&1) {
                                    this.kind = ProxyKind::Socks5;
                                }
                                this.check = CheckState::Idle;
                                cx.notify();
                            })),
                    )
                    .child(div().flex_1())
                    .child(
                        Button::new("check")
                            .outline()
                            .icon(IconName::RefreshCw)
                            .label("Проверить")
                            .loading(matches!(self.check, CheckState::Running))
                            .on_click(cx.listener(|this, _, _, cx| this.run_check(cx))),
                    ),
            )
            .when_some(status, |el, (icon, color, text)| {
                el.child(
                    h_flex()
                        .gap_2()
                        .text_sm()
                        .text_color(color)
                        .child(Icon::new(icon).small())
                        .child(div().flex_1().child(text)),
                )
            })
    }

    fn render_apps(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let filter = self.search.read(cx).value().trim().to_lowercase();

        let chips = h_flex().flex_wrap().gap_1p5().children(self.masks.iter().map(|mask| {
            let running: usize = self
                .procs
                .iter()
                .filter(|g| procs::mask_matches(mask, &g.name))
                .map(|g| g.count)
                .sum();
            let to_remove = mask.clone();
            h_flex()
                .gap_1()
                .pl_2()
                .pr_0p5()
                .py_0p5()
                .rounded_md()
                .border_1()
                .border_color(theme.border)
                .bg(theme.secondary)
                .text_sm()
                .child(mask.clone())
                .child(
                    div()
                        .text_xs()
                        .text_color(if running > 0 { theme.success } else { theme.muted_foreground })
                        .child(if running > 0 { format!("· {running}") } else { "· не запущено".into() }),
                )
                .child(
                    Button::new(SharedString::from(format!("rm-{mask}")))
                        .ghost()
                        .xsmall()
                        .icon(IconName::Close)
                        .on_click(cx.listener(move |this, _, _, cx| this.remove_mask(&to_remove, cx))),
                )
        }));

        let rows = self
            .procs
            .iter()
            .filter(|g| {
                filter.is_empty() || g.name.to_lowercase().contains(&filter) || procs::mask_matches(&filter, &g.name)
            })
            .map(|g| {
                let picked = self.masks.iter().any(|m| procs::mask_matches(m, &g.name));
                let name = g.name.clone();
                h_flex()
                    .id(SharedString::from(format!("proc-{}", g.name.to_lowercase())))
                    .gap_2()
                    .px_3()
                    .py_1p5()
                    .cursor_pointer()
                    .border_b_1()
                    .border_color(theme.border)
                    .when(picked, |el| el.bg(theme.list_active))
                    .hover(|s| s.bg(theme.list_hover))
                    .child(
                        Icon::new(if picked { IconName::CircleCheck } else { IconName::Plus })
                            .small()
                            .text_color(if picked { theme.success } else { theme.muted_foreground }),
                    )
                    .child(div().flex_1().text_sm().child(g.name.clone()))
                    .child(div().text_xs().text_color(theme.muted_foreground).child(plural_procs(g.count)))
                    .on_click(cx.listener(move |this, _, _, cx| this.toggle_app(&name, cx)))
                    .test_support()
            })
            .collect::<Vec<_>>();
        let empty = rows.is_empty();

        v_flex()
            .flex_1()
            .min_h_0()
            .gap_2()
            .child(self.section_title("ПРИЛОЖЕНИЯ", cx))
            .child(
                h_flex()
                    .gap_2()
                    .child(
                        div().flex_1().child(
                            Input::new(&self.search)
                                .id("search")
                                .prefix(Icon::new(IconName::Search).small().text_color(theme.muted_foreground))
                                .cleanable(true),
                        ),
                    )
                    .child(
                        Button::new("add-mask")
                            .outline()
                            .icon(IconName::Plus)
                            .tooltip("Добавить как маску (Enter)")
                            .on_click(cx.listener(|this, _, window, cx| this.add_mask_from_search(window, cx))),
                    ),
            )
            .child(if self.masks.is_empty() {
                div()
                    .text_sm()
                    .text_color(theme.muted_foreground)
                    .child("Кликни по приложению ниже или введи маску и нажми Enter")
                    .into_any_element()
            } else {
                chips.into_any_element()
            })
            .child(
                div()
                    .flex_1()
                    .min_h_0()
                    .rounded_lg()
                    .border_1()
                    .border_color(theme.border)
                    .overflow_hidden()
                    .child(
                        v_flex()
                            .id("proc-list")
                            .size_full()
                            .overflow_y_scrollbar()
                            .when(empty, |el| {
                                el.child(
                                    div()
                                        .p_3()
                                        .text_sm()
                                        .text_color(theme.muted_foreground)
                                        .child("Не нашлось запущенных — Enter добавит это как маску"),
                                )
                            })
                            .children(rows),
                    ),
            )
    }

    fn render_footer(&self, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = cx.theme().clone();
        let button = match self.run {
            RunState::Stopped => Button::new("run")
                .primary()
                .icon(IconName::Play)
                .label("Запустить")
                .on_click(cx.listener(|this, _, _, cx| this.start(cx))),
            RunState::Starting => Button::new("run").primary().loading(true).label("Запуск…"),
            RunState::Stopping => Button::new("run").danger().loading(true).label("Остановка…"),
            _ => Button::new("run")
                .danger()
                .icon(IconName::Square)
                .label("Остановить")
                .on_click(cx.listener(|this, _, _, cx| this.stop(cx))),
        };

        let stats = match self.run.stats() {
            Some(s) => {
                let mut line = format!(
                    "Соединений: {} активных · {} всего · ↑ {} · ↓ {}",
                    s.active.load(Relaxed),
                    s.total.load(Relaxed),
                    human_bytes(s.up.load(Relaxed)),
                    human_bytes(s.down.load(Relaxed)),
                );
                let blocked = s.blocked.load(Relaxed);
                if blocked > 0 {
                    line.push_str(&format!(" · UDP заблокировано: {blocked}"));
                }
                let failed = s.failed.load(Relaxed);
                let last_error = s.last_error.lock().clone();
                Some((line, failed, last_error))
            }
            None => None,
        };

        v_flex()
            .gap_2()
            .when_some(self.run_error.clone(), |el, e| {
                el.child(
                    h_flex()
                        .gap_2()
                        .text_sm()
                        .text_color(theme.danger)
                        .child(Icon::new(IconName::CircleX).small())
                        .child(div().flex_1().child(e)),
                )
            })
            .child(button.large().w_full())
            .when_some(stats, |el, (line, failed, last_error)| {
                el.child(div().text_xs().text_color(theme.muted_foreground).child(line)).when(failed > 0, |el| {
                    el.child(div().text_xs().text_color(theme.danger).child(format!(
                        "Ошибок прокси: {failed}{}",
                        last_error.map(|e| format!(" · последняя: {e}")).unwrap_or_default()
                    )))
                })
            })
    }
}

impl Render for ProxyApp {
    fn render(&mut self, _: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        v_flex()
            .size_full()
            .p_4()
            .gap_4()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(self.render_header(cx))
            .when(!self.elevated, |el| el.child(self.render_admin_warning(cx)))
            .child(self.render_proxy(cx))
            .child(self.render_apps(cx))
            .child(self.render_footer(cx))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let skip_uac = args.iter().any(|a| a == "--elevated" || a == "--no-admin");
    #[cfg(feature = "demo")]
    let demo_scene = args.iter().position(|a| a == "--demo").map(|i| args.get(i + 1).cloned().unwrap_or_default());
    #[cfg(feature = "demo")]
    let skip_uac = skip_uac || demo_scene.is_some();
    if !procs::is_elevated() && !skip_uac && procs::relaunch_elevated() {
        return;
    }

    gpui_kit::application().with_assets(gpui_kit::assets::Assets).run(move |cx| {
        gpui_kit::init(cx);
        Theme::change(ThemeMode::Dark, None, cx);

        let options = WindowOptions {
            window_bounds: Some(WindowBounds::centered(size(px(560.), px(820.)), cx)),
            titlebar: Some(TitlebarOptions { title: Some("Easy Proxy".into()), ..Default::default() }),
            window_min_size: Some(size(px(480.), px(640.))),
            ..Default::default()
        };
        gpui_kit::open_window(options, cx, move |window, cx| {
            cx.new(|cx| {
                #[cfg(feature = "demo")]
                if let Some(scene) = &demo_scene {
                    return demo::app(scene, window, cx);
                }
                ProxyApp::new(window, cx)
            })
        })
        .expect("failed to open window");

        cx.on_window_closed(|cx, _| {
            if cx.windows().is_empty() {
                cx.quit();
            }
        })
        .detach();
        cx.activate(true);
    });
}

#[cfg(test)]
mod ui_tests {
    use super::{ProxyApp, RunState};
    use crate::procs::ProcGroup;
    use crate::proxy::ProxyKind;
    use gpui_kit::test::TestWindowExt;
    use gpui_kit::{
        AnyWindowHandle, AppContext, Bounds, ClipboardItem, Entity, TestAppContext, WindowBounds, WindowOptions, px,
        size,
    };

    fn open(cx: &mut TestAppContext) -> (AnyWindowHandle, Entity<ProxyApp>) {
        cx.update(gpui_kit::init);
        let (handle, view) = cx.update(|cx| {
            gpui_kit::open_window(
                WindowOptions {
                    window_bounds: Some(WindowBounds::Windowed(Bounds::new(
                        Default::default(),
                        size(px(560.), px(820.)),
                    ))),
                    ..Default::default()
                },
                cx,
                |window, cx| cx.new(|cx| ProxyApp::with_config(serde_json::Value::Null, false, window, cx)),
            )
            .expect("open test window")
        });
        (handle, view)
    }

    #[gpui_kit::test]
    fn pasted_proxy_line_is_split_into_fields(cx: &mut TestAppContext) {
        let (handle, view) = open(cx);
        cx.write_to_clipboard(ClipboardItem::new_string("socks5://myuser:pa:ss@45.12.34.56:1080".into()));
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            window.click("addr", cx);
            window.press("ctrl-v", cx);
        })
        .unwrap();
        cx.run_until_parked();
        cx.update(|cx| {
            let app = view.read(cx);
            assert_eq!(app.addr.read(cx).value().as_ref(), "45.12.34.56:1080");
            assert_eq!(app.auth.read(cx).value().as_ref(), "myuser:pa:ss");
            assert_eq!(app.kind, ProxyKind::Socks5);
            let cfg = app.proxy_config(cx).unwrap();
            assert_eq!((cfg.host.as_str(), cfg.port, cfg.user.as_str(), cfg.pass.as_str()), ("45.12.34.56", 1080, "myuser", "pa:ss"));
        });
    }

    #[gpui_kit::test]
    fn typed_line_is_split_only_on_enter(cx: &mut TestAppContext) {
        let (handle, view) = open(cx);
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            window.click("addr", cx);
            // Typing char by char must not split the line halfway.
            for ch in "1.2.3.4:8080:user:pass".chars() {
                window.input(&ch.to_string(), cx);
            }
            assert_eq!(window.find("addr").value(), Some("1.2.3.4:8080:user:pass"));
        })
        .unwrap();
        cx.run_until_parked();
        cx.update(|cx| {
            // Still not split after typing has settled.
            assert_eq!(view.read(cx).addr.read(cx).value().as_ref(), "1.2.3.4:8080:user:pass");
        });
        cx.update_window(handle, |_, window, cx| window.press("enter", cx)).unwrap();
        cx.run_until_parked();
        cx.update(|cx| {
            let app = view.read(cx);
            assert_eq!(app.addr.read(cx).value().as_ref(), "1.2.3.4:8080");
            assert_eq!(app.auth.read(cx).value().as_ref(), "user:pass");
            assert_eq!(app.kind, ProxyKind::Http);
        });
    }

    #[gpui_kit::test]
    fn picking_apps_and_masks(cx: &mut TestAppContext) {
        let (handle, view) = open(cx);
        cx.update(|cx| {
            view.update(cx, |app, cx| {
                app.procs = vec![
                    ProcGroup { name: "chrome.exe".into(), count: 34 },
                    ProcGroup { name: "Telegram.exe".into(), count: 1 },
                ];
                cx.notify();
            })
        });
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            window.click("proc-chrome.exe", cx);
        })
        .unwrap();
        cx.update(|cx| assert_eq!(view.read(cx).masks, vec!["chrome.exe".to_string()]));

        cx.update_window(handle, |_, window, cx| {
            window.click("proc-chrome.exe", cx);
            window.click("search", cx);
            window.input("telegr*", cx);
            window.press("enter", cx);
        })
        .unwrap();
        cx.run_until_parked();
        cx.update(|cx| {
            let app = view.read(cx);
            assert_eq!(app.search.read(cx).value().as_ref(), "");
            assert_eq!(app.masks, vec!["telegr*".to_string()]);
            assert!(app.rules.matches("telegram.exe"));
            assert!(!app.rules.matches("chrome.exe"));
        });
    }

    #[gpui_kit::test]
    fn start_needs_proxy_and_apps(cx: &mut TestAppContext) {
        let (handle, view) = open(cx);
        cx.update_window(handle, |_, window, cx| {
            window.render_frame(cx);
            window.click("run", cx);
        })
        .unwrap();
        cx.update(|cx| {
            let app = view.read(cx);
            assert!(matches!(app.run, RunState::Stopped));
            assert_eq!(app.run_error.as_deref(), Some("Введи прокси в формате ip:port"));
        });

        cx.update_window(handle, |_, window, cx| {
            window.click("addr", cx);
            window.input("1.2.3.4:8080", cx);
            window.click("run", cx);
        })
        .unwrap();
        cx.update(|cx| {
            assert_eq!(view.read(cx).run_error.as_deref(), Some("Выбери хотя бы одно приложение"));
        });
    }
}
