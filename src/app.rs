use crate::chains::{self, Chain, Step};
use crate::demo;
use crate::input::LineEdit;
use crate::macros::{self, Macro};
use crate::match_plan;
use crate::model::*;
use crate::persist::{self, AuditEntry, Config, Favorites, Paths};
use crate::rpc::{self, Cmd, Event};
use crate::venom::VenomSpec;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::collections::HashMap;
use tokio::sync::mpsc;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dash,
    Hosts,
    Modules,
    Sessions,
    Creds,
    Tasks,
    Chains,
    Reports,
    Console,
    Wizards,
}

impl Tab {
    pub fn all() -> [Tab; 10] {
        [
            Tab::Dash,
            Tab::Hosts,
            Tab::Modules,
            Tab::Sessions,
            Tab::Creds,
            Tab::Tasks,
            Tab::Chains,
            Tab::Reports,
            Tab::Console,
            Tab::Wizards,
        ]
    }

    pub fn title(self) -> &'static str {
        match self {
            Tab::Dash => "1 Dash",
            Tab::Hosts => "2 Hosts",
            Tab::Modules => "3 Mods",
            Tab::Sessions => "4 Sess",
            Tab::Creds => "5 Creds",
            Tab::Tasks => "6 Tasks",
            Tab::Chains => "7 Chains",
            Tab::Reports => "8 Rpt",
            Tab::Console => "9 Con",
            Tab::Wizards => "0 Wiz",
        }
    }

    pub fn from_digit(c: char) -> Option<Tab> {
        Some(match c {
            '1' => Tab::Dash,
            '2' => Tab::Hosts,
            '3' => Tab::Modules,
            '4' => Tab::Sessions,
            '5' => Tab::Creds,
            '6' => Tab::Tasks,
            '7' => Tab::Chains,
            '8' => Tab::Reports,
            '9' => Tab::Console,
            '0' => Tab::Wizards,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum HostPane {
    List,
    Detail,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum CredPane {
    Creds,
    Loot,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum WizardKind {
    Pentest,
    Validate,
    CredReuse,
    Payload,
    Evidence,
    AutoPlan,
}

impl WizardKind {
    pub fn all() -> [WizardKind; 6] {
        [
            WizardKind::Pentest,
            WizardKind::Validate,
            WizardKind::CredReuse,
            WizardKind::Payload,
            WizardKind::Evidence,
            WizardKind::AutoPlan,
        ]
    }

    pub fn title(self) -> &'static str {
        match self {
            WizardKind::Pentest => "Quick pentest",
            WizardKind::Validate => "Vuln validation",
            WizardKind::CredReuse => "Credential reuse",
            WizardKind::Payload => "Payload (msfvenom)",
            WizardKind::Evidence => "Evidence macro",
            WizardKind::AutoPlan => "Auto-exploit plan",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Connect,
    RunModule,
    RunPlan,
    RunChain,
    RunWizard,
    Venom,
    Discover,
    Import,
    Report,
    SessionStop,
    JobStop,
    CredReuse,
}

pub enum Modal {
    None,
    Help,
    Confirm {
        title: String,
        body: String,
        action: Action,
    },
    Message {
        title: String,
        body: String,
    },
    Edit {
        title: String,
        field: String,
    },
}

pub struct App {
    pub detail_scroll: u16,
    pub commands: crate::commands::Palette,
    pub tab: Tab,
    pub should_quit: bool,
    pub status: String,
    pub modal: Modal,
    pub edit: LineEdit,
    pub filter: String,
    pub filtering: bool,
    pub help_scroll: u16,
    pub demo: bool,
    pub connected: bool,
    pub busy: bool,
    pub paths: Paths,
    pub config: Config,
    pub favorites: Favorites,
    pub audit: Vec<AuditEntry>,
    pub snap: Snapshot,
    pub console: String,
    pub console_in: LineEdit,
    pub session_io: HashMap<String, String>,
    pub session_in: LineEdit,
    pub interact: bool,
    pub host_idx: usize,
    pub host_pane: HostPane,
    pub module_kind: ModuleKind,
    pub module_names: HashMap<String, Vec<String>>,
    pub module_idx: usize,
    pub module_info: Option<ModuleInfo>,
    pub option_idx: usize,
    pub session_idx: usize,
    pub cred_idx: usize,
    pub loot_idx: usize,
    pub cred_pane: CredPane,
    pub job_idx: usize,
    pub task_idx: usize,
    pub tasks: Vec<TaskLog>,
    pub chains: Vec<Chain>,
    pub chain_idx: usize,
    pub macros: Vec<Macro>,
    pub macro_idx: usize,
    pub wizard: WizardKind,
    pub wiz_field: usize,
    pub plan: Vec<PlanItem>,
    pub plan_idx: usize,
    pub min_rank: Rank,
    pub pentest_rhosts: String,
    pub pentest_ports: String,
    pub import_path: String,
    pub venom: VenomSpec,
    pub last_report: String,
    pub report_redact: bool,
    pub cmd_tx: Option<mpsc::UnboundedSender<Cmd>>,
    pub ev_rx: Option<mpsc::UnboundedReceiver<Event>>,
}

impl App {
    fn apply_aurora_theme(&mut self, id: &str) {
        self.config.theme = id.into();
        if let Err(err) = persist::save_config(&self.paths.config, &self.config) {
            self.status = format!("Saving theme: {err}");
        }
        crate::theme::set(id);
    }

    pub fn new(demo: bool) -> anyhow::Result<Self> {
        Self::with_paths(demo, Paths::resolve()?)
    }

    pub fn with_paths(demo: bool, paths: Paths) -> anyhow::Result<Self> {
        persist::seed_defaults(&paths)?;
        let mut config = persist::load_config(&paths.config);
        if config.password.is_empty() {
            if let Ok(p) = std::env::var("NEXUS_MSF_RPC_PASS") {
                config.password = p;
            } else if demo {
                config.password = "demo".into();
            } else {
                config.password = format!("nx-{}", &uuid::Uuid::new_v4().to_string()[..12]);
                persist::save_config(&paths.config, &config)?;
            }
        }
        crate::theme::set(&config.theme);
        let favorites = persist::load_favorites(&paths.favorites);
        let audit = persist::load_audit(&paths.audit, 80);
        let chains = chains::load_dir(&paths.chains);
        let macros = macros::load_dir(&paths.macros);
        let snap = if demo {
            demo::snapshot()
        } else {
            Snapshot::default()
        };
        let mut module_names = HashMap::new();
        if demo {
            for k in [
                ModuleKind::Exploit,
                ModuleKind::Auxiliary,
                ModuleKind::Post,
                ModuleKind::Payload,
            ] {
                module_names.insert(k.as_str().into(), demo::module_names(k));
            }
        }
        let status = if demo {
            "demo mode — no RPC (authorized testing only)".into()
        } else {
            format!(
                "disconnected · rpc {}:{} · Ctrl-G to connect",
                config.host, config.port
            )
        };
        Ok(Self {
            commands: crate::commands::Palette::default(),
            detail_scroll: 0,
            tab: Tab::Dash,
            should_quit: false,
            status,
            modal: Modal::None,
            edit: LineEdit::default(),
            filter: String::new(),
            filtering: false,
            help_scroll: 0,
            demo,
            connected: demo,
            busy: false,
            paths,
            config,
            favorites,
            audit,
            snap,
            console: if demo {
                "msf6 > # demo console\n".into()
            } else {
                String::new()
            },
            console_in: LineEdit::default(),
            session_io: HashMap::new(),
            session_in: LineEdit::default(),
            interact: false,
            host_idx: 0,
            host_pane: HostPane::List,
            module_kind: ModuleKind::Exploit,
            module_names,
            module_idx: 0,
            module_info: if demo {
                let n = demo::module_names(ModuleKind::Exploit);
                n.first().map(|name| demo::module_info("exploit", name))
            } else {
                None
            },
            option_idx: 0,
            session_idx: 0,
            cred_idx: 0,
            loot_idx: 0,
            cred_pane: CredPane::Creds,
            job_idx: 0,
            task_idx: 0,
            tasks: Vec::new(),
            chains,
            chain_idx: 0,
            macros,
            macro_idx: 0,
            wizard: WizardKind::Pentest,
            wiz_field: 0,
            plan: Vec::new(),
            plan_idx: 0,
            min_rank: Rank::Great,
            pentest_rhosts: "192.168.1.0/24".into(),
            pentest_ports: "22,80,443,445,3389".into(),
            import_path: String::new(),
            venom: VenomSpec::default(),
            last_report: String::new(),
            report_redact: true,
            cmd_tx: None,
            ev_rx: None,
        })
    }

    pub fn start_rpc(&mut self) {
        if self.demo {
            return;
        }
        let (tx, rx) = rpc::start_worker(self.config.clone());
        self.cmd_tx = Some(tx);
        self.ev_rx = Some(rx);
        self.busy = true;
        self.status = "connecting…".into();
        self.send(Cmd::Connect);
    }

    fn send(&mut self, cmd: Cmd) {
        if !self.demo && !self.connected && !matches!(cmd, Cmd::Connect | Cmd::Disconnect) {
            self.status = "not connected — Ctrl-G on Dash to connect".into();
            return;
        }
        if let Some(tx) = &self.cmd_tx {
            let _ = tx.send(cmd);
        }
    }

    pub async fn on_tick(&mut self) {
        crate::theme::refresh();
        let mut events = Vec::new();
        if let Some(rx) = self.ev_rx.as_mut() {
            while let Ok(e) = rx.try_recv() {
                events.push(e);
            }
        }
        for e in events {
            self.on_event(e);
        }
    }

    fn on_event(&mut self, e: Event) {
        match e {
            Event::Status(s) => self.status = s,
            Event::Error(s) => {
                self.busy = false;
                self.status = s.clone();
                if s.contains("not connected") {
                    self.modal = Modal::Confirm {
                        title: "Not connected to msfrpcd".into(),
                        body: format!("{s}\n\nConnect now?"),
                        action: Action::Connect,
                    };
                } else {
                    self.modal = Modal::Message {
                        title: "RPC error".into(),
                        body: s,
                    };
                }
            }
            Event::Connected(snap) => {
                self.connected = true;
                self.busy = false;
                self.apply_snap(snap);
                self.status = format!(
                    "connected {}  db={}  ws={}",
                    self.snap.version,
                    if self.snap.db_ok { "yes" } else { "no" },
                    self.snap.workspace
                );
                self.send(Cmd::ListModules {
                    kind: self.module_kind.as_str().into(),
                });
                let st = self.status.clone();
                self.audit("connect", &st);
            }
            Event::Snapshot(snap) => self.apply_snap(snap),
            Event::Console { data, busy } => {
                self.console.push_str(&data);
                if self.console.len() > 80_000 {
                    self.console = self.console[self.console.len() - 60_000..].to_string();
                }
                self.busy = busy;
            }
            Event::SessionIo { id, data } => {
                self.session_io.entry(id).or_default().push_str(&data);
            }
            Event::ModuleInfo(info) => {
                self.module_info = Some(info);
                self.option_idx = 0;
            }
            Event::ModuleList { kind, names } => {
                self.module_names.insert(kind, names);
                self.module_idx = 0;
                self.fetch_selected_module();
            }
            Event::TaskUpdate { id, status, detail } => {
                if let Some(t) = self.tasks.iter_mut().find(|t| t.id == id) {
                    t.status = status;
                    t.detail = detail;
                }
            }
        }
    }

    fn apply_snap(&mut self, snap: Snapshot) {
        self.snap = snap;
        self.clamp();
    }

    fn clamp(&mut self) {
        if self.host_idx >= self.snap.hosts.len() {
            self.host_idx = self.snap.hosts.len().saturating_sub(1);
        }
        if self.session_idx >= self.snap.sessions.len() {
            self.session_idx = self.snap.sessions.len().saturating_sub(1);
        }
        if self.cred_idx >= self.snap.creds.len() {
            self.cred_idx = self.snap.creds.len().saturating_sub(1);
        }
        if self.job_idx >= self.snap.jobs.len() {
            self.job_idx = self.snap.jobs.len().saturating_sub(1);
        }
        let n = self.current_modules().len();
        if self.module_idx >= n {
            self.module_idx = n.saturating_sub(1);
        }
    }

    pub fn current_modules(&self) -> Vec<&String> {
        let names = self
            .module_names
            .get(self.module_kind.as_str())
            .map(|v| v.as_slice())
            .unwrap_or(&[]);
        names
            .iter()
            .filter(|n| {
                self.filter.is_empty()
                    || n.to_ascii_lowercase()
                        .contains(&self.filter.to_ascii_lowercase())
                    || self.favorites.modules.iter().any(|f| f == *n)
            })
            .collect()
    }

    pub fn filtered_hosts(&self) -> Vec<usize> {
        self.snap
            .hosts
            .iter()
            .enumerate()
            .filter(|(_, h)| {
                if self.filter.is_empty() {
                    return true;
                }
                let f = self.filter.to_ascii_lowercase();
                h.address.contains(&self.filter)
                    || h.name.to_ascii_lowercase().contains(&f)
                    || h.os.to_ascii_lowercase().contains(&f)
            })
            .map(|(i, _)| i)
            .collect()
    }

    fn selected_module_name(&self) -> Option<String> {
        self.current_modules()
            .get(self.module_idx)
            .map(|s| (*s).clone())
    }

    fn fetch_selected_module(&mut self) {
        let Some(name) = self.selected_module_name() else {
            self.module_info = None;
            return;
        };
        if self.demo {
            self.module_info = Some(demo::module_info(self.module_kind.as_str(), &name));
            self.option_idx = 0;
            return;
        }
        if !self.connected {
            return;
        }
        self.send(Cmd::FetchModule {
            kind: self.module_kind.as_str().into(),
            name,
        });
    }

    fn audit(&mut self, action: &str, detail: &str) {
        if let Ok(e) = persist::append_audit(&self.paths.audit, action, detail) {
            self.audit.push(e);
            if self.audit.len() > 200 {
                self.audit.drain(0..self.audit.len() - 200);
            }
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        if self.filtering {
            self.handle_filter_key(key);
            return;
        }
        if !matches!(self.modal, Modal::None) {
            self.handle_modal_key(key);
            return;
        }
        if self.commands.open
            || (key.code == KeyCode::Char('k') && key.modifiers.contains(KeyModifiers::CONTROL))
        {
            if let Some(action) = self.commands.handle(key, ACTIONS) {
                if action.modifiers == KeyModifiers::ALT {
                    let id = match action.key {
                        KeyCode::Char('o') => "omarchy",
                        KeyCode::Char('t') => "terminal",
                        _ => "aurora",
                    };
                    self.apply_aurora_theme(id);
                } else {
                    self.handle_key(action.event());
                }
            }
            return;
        }
        if self.tab == Tab::Hosts && self.host_pane == HostPane::Detail {
            match key.code {
                KeyCode::Down | KeyCode::Char('j') => {
                    self.detail_scroll = self.detail_scroll.saturating_add(1);
                    return;
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.detail_scroll = self.detail_scroll.saturating_sub(1);
                    return;
                }
                KeyCode::PageDown => {
                    self.detail_scroll = self.detail_scroll.saturating_add(8);
                    return;
                }
                KeyCode::PageUp => {
                    self.detail_scroll = self.detail_scroll.saturating_sub(8);
                    return;
                }
                _ => {}
            }
        }
        if self.tab == Tab::Console && !key.modifiers.contains(KeyModifiers::CONTROL) {
            match key.code {
                KeyCode::Char(c @ '0'..='9') if self.console_in.value.is_empty() => {
                    if let Some(t) = Tab::from_digit(c) {
                        self.tab = t;
                        return;
                    }
                }
                KeyCode::Char('?') if self.console_in.value.is_empty() => {
                    self.modal = Modal::Help;
                    return;
                }
                KeyCode::Esc => {
                    self.tab = Tab::Dash;
                    return;
                }
                KeyCode::Enter => {
                    let line = self.console_in.value.clone();
                    self.console_in = LineEdit::default();
                    self.console.push_str(&format!("msf6 > {line}\n"));
                    if self.demo {
                        self.console.push_str("[demo] command not sent\n");
                    } else {
                        self.send(Cmd::ConsoleWrite(line));
                    }
                    return;
                }
                _ => {
                    if self.console_in.handle(key) {
                        return;
                    }
                }
            }
        }
        if self.interact && self.tab == Tab::Sessions {
            match key.code {
                KeyCode::Esc => {
                    self.interact = false;
                    return;
                }
                KeyCode::Enter => {
                    let line = self.session_in.value.clone();
                    self.session_in = LineEdit::default();
                    if let Some(s) = self.snap.sessions.get(self.session_idx).cloned() {
                        let meterpreter = s.kind.contains("meterpreter");
                        self.session_io
                            .entry(s.id.clone())
                            .or_default()
                            .push_str(&format!("> {line}\n"));
                        if self.demo {
                            self.session_io
                                .entry(s.id)
                                .or_default()
                                .push_str("[demo] not sent\n");
                        } else {
                            self.send(Cmd::SessionWrite {
                                id: s.id,
                                data: line,
                                meterpreter,
                            });
                        }
                    }
                    return;
                }
                _ => {
                    if self.session_in.handle(key) {
                        return;
                    }
                }
            }
        }
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.should_quit = true;
            }
            KeyCode::Char('?') => self.modal = Modal::Help,
            KeyCode::Char(c @ '0'..='9') => {
                if let Some(t) = Tab::from_digit(c) {
                    self.tab = t;
                    if t == Tab::Modules {
                        self.ensure_module_list();
                    }
                }
            }
            KeyCode::Tab => self.cycle_pane(1),
            KeyCode::BackTab => self.cycle_pane(-1),
            KeyCode::Char('/') => {
                self.filtering = true;
                self.edit = LineEdit::new(self.filter.clone());
            }
            KeyCode::Char('g') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.prompt_primary();
            }
            KeyCode::Char('y') => self.yank(),
            KeyCode::Char('r') => {
                if self.demo {
                    self.snap = demo::snapshot();
                    self.status = "demo snapshot reloaded".into();
                } else {
                    self.send(Cmd::Refresh);
                    self.status = "refreshing…".into();
                }
            }
            _ => self.handle_tab_key(key),
        }
    }

    fn ensure_module_list(&mut self) {
        if self
            .module_names
            .get(self.module_kind.as_str())
            .is_none_or(|v| v.is_empty())
            && !self.demo
            && self.connected
        {
            self.send(Cmd::ListModules {
                kind: self.module_kind.as_str().into(),
            });
        }
    }

    fn cycle_pane(&mut self, dir: i32) {
        match self.tab {
            Tab::Hosts => {
                self.host_pane = if self.host_pane == HostPane::List {
                    HostPane::Detail
                } else {
                    HostPane::List
                };
            }
            Tab::Creds => {
                self.cred_pane = if self.cred_pane == CredPane::Creds {
                    CredPane::Loot
                } else {
                    CredPane::Creds
                };
            }
            Tab::Modules if dir > 0 => {
                self.module_kind = self.module_kind.next();
                self.module_idx = 0;
                self.ensure_module_list();
                self.fetch_selected_module();
            }
            Tab::Wizards => {
                let all = WizardKind::all();
                let i = all.iter().position(|w| *w == self.wizard).unwrap_or(0) as i32;
                let n = all.len() as i32;
                self.wizard = all[((i + dir).rem_euclid(n)) as usize];
                self.wiz_field = 0;
            }
            _ => {}
        }
    }

    fn handle_filter_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.filtering = false;
                self.filter.clear();
            }
            KeyCode::Enter => {
                self.filter = self.edit.value.clone();
                self.filtering = false;
                self.module_idx = 0;
                self.host_idx = 0;
            }
            _ => {
                self.edit.handle(key);
            }
        }
    }

    fn handle_modal_key(&mut self, key: KeyEvent) {
        match &self.modal {
            Modal::Help => match key.code {
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') => {
                    self.modal = Modal::None;
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.help_scroll = self.help_scroll.saturating_add(1);
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.help_scroll = self.help_scroll.saturating_sub(1);
                }
                _ => {}
            },
            Modal::Message { .. } => {
                if matches!(
                    key.code,
                    KeyCode::Esc | KeyCode::Enter | KeyCode::Char('q') | KeyCode::Char(' ')
                ) {
                    self.modal = Modal::None;
                }
            }
            Modal::Confirm { action, .. } => match key.code {
                KeyCode::Esc | KeyCode::Char('n') => self.modal = Modal::None,
                KeyCode::Enter | KeyCode::Char('y') => {
                    let a = *action;
                    self.modal = Modal::None;
                    self.perform(a);
                }
                _ => {}
            },
            Modal::Edit { field, .. } => match key.code {
                KeyCode::Esc => self.modal = Modal::None,
                KeyCode::Enter => {
                    let field = field.clone();
                    let val = self.edit.value.clone();
                    self.modal = Modal::None;
                    self.apply_edit(&field, val);
                }
                _ => {
                    self.edit.handle(key);
                }
            },
            Modal::None => {}
        }
    }

    fn apply_edit(&mut self, field: &str, val: String) {
        match field {
            "rhosts" => self.pentest_rhosts = val,
            "ports" => self.pentest_ports = val,
            "import" => {
                self.import_path = val.clone();
                if !val.is_empty() {
                    self.confirm(Action::Import, "Import scan data?", &val);
                }
            }
            "payload" => self.venom.payload = val,
            "lhost" => self.venom.lhost = val,
            "lport" => self.venom.lport = val,
            "format" => self.venom.format = val,
            "encoder" => self.venom.encoder = val,
            "outfile" => self.venom.outfile = val,
            "workspace" => {
                if self.demo {
                    self.snap.workspace = val;
                } else {
                    self.send(Cmd::SetWorkspace(val));
                }
            }
            opt if opt.starts_with("opt:") => {
                let name = &opt[4..];
                if let Some(info) = self.module_info.as_mut() {
                    if let Some(o) = info.options.iter_mut().find(|o| o.name == name) {
                        o.value = val;
                    }
                }
            }
            _ => {}
        }
    }

    fn prompt_primary(&mut self) {
        if !self.demo && !self.connected && self.tab != Tab::Dash {
            self.confirm(
                Action::Connect,
                "Not connected to msfrpcd",
                &format!(
                    "{}://{}:{}  user={}\nConnect first, then retry.",
                    if self.config.ssl { "https" } else { "http" },
                    self.config.host,
                    self.config.port,
                    self.config.username
                ),
            );
            return;
        }
        match self.tab {
            Tab::Dash => self.confirm(
                Action::Connect,
                "Connect to msfrpcd?",
                &format!(
                    "{}://{}:{}  user={}  spawn={}  loopback={}",
                    if self.config.ssl { "https" } else { "http" },
                    self.config.host,
                    self.config.port,
                    self.config.username,
                    self.config.spawn,
                    self.config.is_loopback()
                ),
            ),
            Tab::Modules => self.confirm(
                Action::RunModule,
                "Execute module?",
                &self
                    .selected_module_name()
                    .unwrap_or_else(|| "(none)".into()),
            ),
            Tab::Hosts => self.confirm(
                Action::Discover,
                "Discovery scan (db_nmap)?",
                &format!("{} ports {}", self.pentest_rhosts, self.pentest_ports),
            ),
            Tab::Chains => {
                let name = self
                    .chains
                    .get(self.chain_idx)
                    .map(|c| c.summary())
                    .unwrap_or_else(|| "(none)".into());
                self.confirm(Action::RunChain, "Run task chain?", &name);
            }
            Tab::Reports => self.confirm(
                Action::Report,
                "Generate report?",
                &format!(
                    "workspace {}  redact={}",
                    self.snap.workspace, self.report_redact
                ),
            ),
            Tab::Sessions => self.confirm(
                Action::SessionStop,
                "Stop session?",
                &self
                    .snap
                    .sessions
                    .get(self.session_idx)
                    .map(|s| format!("{} {}", s.id, s.session_host))
                    .unwrap_or_default(),
            ),
            Tab::Tasks => self.confirm(
                Action::JobStop,
                "Stop job?",
                &self
                    .snap
                    .jobs
                    .get(self.job_idx)
                    .map(|j| format!("{} {}", j.id, j.name))
                    .unwrap_or_default(),
            ),
            Tab::Wizards => match self.wizard {
                WizardKind::Payload => {
                    self.confirm(Action::Venom, "Run msfvenom?", &self.venom.preview())
                }
                WizardKind::AutoPlan => self.confirm(
                    Action::RunPlan,
                    "Run selected plan items?",
                    &format!(
                        "{} selected / {} total  min_rank={}",
                        self.plan.iter().filter(|p| p.selected).count(),
                        self.plan.len(),
                        self.min_rank.as_str()
                    ),
                ),
                WizardKind::CredReuse => self.confirm(
                    Action::CredReuse,
                    "Reuse credentials against open login services?",
                    "Uses Framework auxiliary login scanners only.",
                ),
                _ => self.confirm(
                    Action::RunWizard,
                    self.wizard.title(),
                    "Runs against the current workspace. Confirm you are authorized.",
                ),
            },
            Tab::Creds => self.confirm(
                Action::CredReuse,
                "Credential reuse?",
                "Launch login scanners for selected creds.",
            ),
            Tab::Console => {}
        }
    }

    fn confirm(&mut self, action: Action, title: &str, body: &str) {
        self.modal = Modal::Confirm {
            title: title.into(),
            body: body.into(),
            action,
        };
    }

    fn perform(&mut self, action: Action) {
        match action {
            Action::Connect => self.connect(),
            Action::RunModule => self.run_selected_module(),
            Action::RunPlan => self.run_plan(),
            Action::RunChain => self.run_chain(),
            Action::RunWizard => self.run_wizard(),
            Action::Venom => self.run_venom(),
            Action::Discover => self.discover(),
            Action::Import => self.import_scan(),
            Action::Report => self.generate_report(),
            Action::SessionStop => {
                if let Some(s) = self.snap.sessions.get(self.session_idx) {
                    let id = s.id.clone();
                    self.audit("session.stop", &id);
                    if !self.demo {
                        self.send(Cmd::SessionStop(id));
                    } else {
                        self.snap.sessions.remove(self.session_idx);
                        self.clamp();
                        self.status = "demo session removed".into();
                    }
                }
            }
            Action::JobStop => {
                if let Some(j) = self.snap.jobs.get(self.job_idx) {
                    let id = j.id.clone();
                    self.audit("job.stop", &id);
                    if !self.demo {
                        self.send(Cmd::JobStop(id));
                    } else {
                        self.snap.jobs.remove(self.job_idx);
                        self.clamp();
                    }
                }
            }
            Action::CredReuse => self.cred_reuse(),
        }
    }

    fn connect(&mut self) {
        if self.demo {
            self.connected = true;
            self.snap = demo::snapshot();
            self.status = "demo already connected".into();
            return;
        }
        if !self.config.is_loopback() {
            self.modal = Modal::Message {
                title: "Refusing remote spawn".into(),
                body: format!(
                    "RPC host is {}. Spawn is loopback-only. Set host=127.0.0.1 or spawn=false and connect to an existing msfrpcd.",
                    self.config.host
                ),
            };
            if self.config.spawn {
                return;
            }
        }
        self.busy = true;
        self.status = "connecting…".into();
        self.send(Cmd::Connect);
    }

    fn run_selected_module(&mut self) {
        let Some(name) = self.selected_module_name() else {
            return;
        };
        let kind = self.module_kind.as_str().to_string();
        let mut opts = HashMap::new();
        if let Some(info) = &self.module_info {
            for o in &info.options {
                if !o.value.is_empty() {
                    opts.insert(o.name.clone(), o.value.clone());
                }
            }
        }
        self.push_task("module", &format!("{kind}/{name}"));
        self.audit("module.execute", &format!("{kind}/{name}"));
        if self.demo {
            self.status = format!("[demo] would execute {kind}/{name}");
            if let Some(t) = self.tasks.last_mut() {
                t.status = "demo".into();
            }
            return;
        }
        self.send(Cmd::ExecuteModule { kind, name, opts });
    }

    fn rebuild_plan(&mut self) {
        let catalog = crate::catalog::merge(&demo::modules());
        self.plan = match_plan::build_plan(&self.snap.hosts, &catalog, self.min_rank);
        self.plan_idx = 0;
        self.status = format!(
            "plan: {} items (min {})",
            self.plan.len(),
            self.min_rank.as_str()
        );
    }

    fn run_plan(&mut self) {
        let selected: Vec<PlanItem> = self.plan.iter().filter(|p| p.selected).cloned().collect();
        if selected.is_empty() {
            self.status = "no plan items selected".into();
            return;
        }
        self.push_task("auto-exploit", &format!("{} modules", selected.len()));
        self.audit(
            "auto-exploit",
            &selected
                .iter()
                .map(|p| format!("{}:{}", p.host, p.module))
                .collect::<Vec<_>>()
                .join(", "),
        );
        if self.demo {
            self.status = format!("[demo] would run {} plan items", selected.len());
            if let Some(t) = self.tasks.last_mut() {
                t.status = "demo".into();
                t.detail = selected
                    .iter()
                    .map(|p| format!("{} {}", p.host, p.module))
                    .collect::<Vec<_>>()
                    .join("\n");
            }
            return;
        }
        for p in selected {
            let mut opts = HashMap::new();
            opts.insert("RHOSTS".into(), p.host.clone());
            if let Some(port) = p.rport {
                opts.insert("RPORT".into(), port.to_string());
            }
            self.send(Cmd::ExecuteModule {
                kind: p.kind,
                name: p.module,
                opts,
            });
        }
    }

    fn run_chain(&mut self) {
        let Some(chain) = self.chains.get(self.chain_idx).cloned() else {
            return;
        };
        self.push_task("chain", &chain.name);
        self.audit("chain", &chain.name);
        if self.demo {
            self.status = format!("[demo] chain {}", chain.name);
            if let Some(t) = self.tasks.last_mut() {
                t.status = "demo".into();
                t.detail = chain
                    .steps
                    .iter()
                    .map(Chain::step_label)
                    .collect::<Vec<_>>()
                    .join("\n");
            }
            return;
        }
        for step in &chain.steps {
            match step {
                Step::Discover { rhosts, ports } => {
                    self.send(Cmd::ConsoleDiscover {
                        rhosts: rhosts.clone(),
                        ports: ports.clone(),
                    });
                }
                Step::Import { path } => self.send(Cmd::ImportData { path: path.clone() }),
                Step::AutoExploit { min_rank, .. } => {
                    if let Some(r) = Rank::parse(min_rank) {
                        self.min_rank = r;
                    }
                    self.rebuild_plan();
                    self.run_plan();
                }
                Step::CollectEvidence {
                    r#macro: macro_name,
                } => {
                    self.run_macro_named(&macro_name);
                }
                Step::Report { .. } => {
                    let _ = self.generate_report();
                }
                Step::Module {
                    kind,
                    name,
                    options,
                } => {
                    self.send(Cmd::ExecuteModule {
                        kind: kind.clone(),
                        name: name.clone(),
                        opts: options.clone(),
                    });
                }
            }
        }
    }

    fn run_wizard(&mut self) {
        match self.wizard {
            WizardKind::Pentest => {
                self.discover();
                self.rebuild_plan();
                self.tab = Tab::Wizards;
                self.wizard = WizardKind::AutoPlan;
                self.status =
                    "discovered (or queued). review auto-exploit plan, then Ctrl-G".into();
            }
            WizardKind::Validate => {
                self.import_scan();
                self.rebuild_plan();
                self.wizard = WizardKind::AutoPlan;
            }
            WizardKind::Evidence => self.run_macro_selected(),
            WizardKind::AutoPlan => self.rebuild_plan(),
            WizardKind::CredReuse => self.cred_reuse(),
            WizardKind::Payload => self.run_venom(),
        }
    }

    fn discover(&mut self) {
        self.push_task(
            "discover",
            &format!("{} {}", self.pentest_rhosts, self.pentest_ports),
        );
        let targets = self.pentest_rhosts.clone();
        self.audit("discover", &targets);
        if self.demo {
            self.status = "[demo] db_nmap not sent".into();
            if let Some(t) = self.tasks.last_mut() {
                t.status = "demo".into();
            }
            return;
        }
        self.send(Cmd::ConsoleDiscover {
            rhosts: self.pentest_rhosts.clone(),
            ports: self.pentest_ports.clone(),
        });
        self.tab = Tab::Console;
    }

    fn import_scan(&mut self) {
        if self.import_path.is_empty() {
            self.edit = LineEdit::new("/tmp/scan.xml");
            self.modal = Modal::Edit {
                title: "Import scan XML/Nessus path".into(),
                field: "import".into(),
            };
            return;
        }
        let path = self.import_path.clone();
        self.audit("import", &path);
        if self.demo {
            self.status = format!("[demo] import {}", self.import_path);
            return;
        }
        self.send(Cmd::ImportData {
            path: self.import_path.clone(),
        });
    }

    fn generate_report(&mut self) {
        match crate::reports::render(
            &self.paths.reports,
            &self.snap,
            &self.audit,
            self.report_redact,
        ) {
            Ok(files) => {
                self.last_report = files.dir.display().to_string();
                self.status = format!("report {}", files.dir.display());
                let last = self.last_report.clone();
                self.audit("report", &last);
                self.modal = Modal::Message {
                    title: "Report written".into(),
                    body: format!(
                        "{}\n{}\n{}",
                        files.markdown.display(),
                        files.html.display(),
                        files.json.display()
                    ),
                };
            }
            Err(e) => {
                self.modal = Modal::Message {
                    title: "Report failed".into(),
                    body: e.to_string(),
                };
            }
        }
    }

    fn run_venom(&mut self) {
        let preview = self.venom.preview();
        self.push_task("msfvenom", &preview);
        self.audit("msfvenom", &preview);
        if self.demo {
            self.status = format!("[demo] {preview}");
            if let Some(t) = self.tasks.last_mut() {
                t.status = "demo".into();
            }
            return;
        }
        let args = self.venom.argv();
        tokio::spawn(async move {
            let _ = tokio::process::Command::new(&args[0])
                .args(&args[1..])
                .status()
                .await;
        });
        self.status = format!("spawned {preview}");
    }

    fn cred_reuse(&mut self) {
        let n = self.snap.creds.len();
        self.push_task("cred-reuse", &format!("{n} creds"));
        self.audit("cred-reuse", &format!("{n} creds"));
        if self.demo {
            self.status = "[demo] would run login scanners for stored creds".into();
            return;
        }
        let scanners = [
            ("ssh", 22, "scanner/ssh/ssh_login"),
            ("smb", 445, "scanner/smb/smb_login"),
            ("ftp", 21, "scanner/ftp/ftp_login"),
            ("mysql", 3306, "scanner/mysql/mysql_login"),
        ];
        let mut jobs = Vec::new();
        for cred in &self.snap.creds {
            for host in &self.snap.hosts {
                for svc in &host.services {
                    if let Some((_, _, module)) = scanners
                        .iter()
                        .find(|(name, port, _)| svc.name == *name || svc.port == *port)
                    {
                        let mut opts = HashMap::new();
                        opts.insert("RHOSTS".into(), host.address.clone());
                        opts.insert("RPORT".into(), svc.port.to_string());
                        opts.insert("USERNAME".into(), cred.user.clone());
                        opts.insert("PASSWORD".into(), cred.pass.clone());
                        jobs.push((*module, opts));
                    }
                }
            }
        }
        for (module, opts) in jobs {
            self.send(Cmd::ExecuteModule {
                kind: "auxiliary".into(),
                name: module.into(),
                opts,
            });
        }
    }

    fn run_macro_selected(&mut self) {
        if let Some(m) = self.macros.get(self.macro_idx).cloned() {
            self.run_macro(&m);
        }
    }

    fn run_macro_named(&mut self, name: &str) {
        if let Some(m) = self.macros.iter().find(|m| m.name == name).cloned() {
            self.run_macro(&m);
        }
    }

    fn run_macro(&mut self, m: &Macro) {
        let Some(sess) = self.snap.sessions.get(self.session_idx).cloned() else {
            self.status = "no session for evidence macro".into();
            return;
        };
        self.push_task("macro", &m.name);
        self.audit("macro", &format!("{} on session {}", m.name, sess.id));
        if self.demo {
            self.status = format!("[demo] macro {} on session {}", m.name, sess.id);
            return;
        }
        for step in &m.steps {
            let mut opts = step.options.clone();
            opts.insert("SESSION".into(), sess.id.clone());
            let name = step.module.trim_start_matches("post/").to_string();
            self.send(Cmd::ExecuteModule {
                kind: "post".into(),
                name,
                opts,
            });
        }
    }

    fn push_task(&mut self, kind: &str, summary: &str) {
        self.tasks.insert(0, TaskLog::new(kind, summary));
        self.task_idx = 0;
    }

    fn yank(&mut self) {
        let text = match self.tab {
            Tab::Modules => self.selected_module_name().unwrap_or_default(),
            Tab::Hosts => self
                .snap
                .hosts
                .get(self.host_idx)
                .map(|h| h.address.clone())
                .unwrap_or_default(),
            Tab::Sessions => self
                .snap
                .sessions
                .get(self.session_idx)
                .map(|s| s.id.clone())
                .unwrap_or_default(),
            Tab::Wizards if self.wizard == WizardKind::Payload => self.venom.preview(),
            Tab::Reports => self.last_report.clone(),
            Tab::Console => self.console_in.value.clone(),
            _ => self.status.clone(),
        };
        if text.is_empty() {
            return;
        }
        if let Ok(mut clip) = arboard::Clipboard::new() {
            let _ = clip.set_text(&text);
            self.status = format!("yanked {text}");
        }
    }

    fn handle_tab_key(&mut self, key: KeyEvent) {
        match self.tab {
            Tab::Dash => match key.code {
                KeyCode::Char('e') => {
                    self.edit = LineEdit::new(self.snap.workspace.clone());
                    self.modal = Modal::Edit {
                        title: "workspace".into(),
                        field: "workspace".into(),
                    };
                }
                KeyCode::Char('[') => self.cycle_workspace(-1),
                KeyCode::Char(']') => self.cycle_workspace(1),
                _ => {}
            },
            Tab::Hosts => match key.code {
                KeyCode::Char('j') | KeyCode::Down => self.move_host(1),
                KeyCode::Char('k') | KeyCode::Up => self.move_host(-1),
                KeyCode::Char('i') => {
                    self.edit = LineEdit::new(self.import_path.clone());
                    self.modal = Modal::Edit {
                        title: "import path".into(),
                        field: "import".into(),
                    };
                }
                KeyCode::Char('a') => {
                    self.rebuild_plan();
                    self.tab = Tab::Wizards;
                    self.wizard = WizardKind::AutoPlan;
                }
                KeyCode::Enter => self.host_pane = HostPane::Detail,
                _ => {}
            },
            Tab::Modules => match key.code {
                KeyCode::Char('j') | KeyCode::Down => {
                    let n = self.current_modules().len();
                    move_idx(&mut self.module_idx, n, 1);
                    self.fetch_selected_module();
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    let n = self.current_modules().len();
                    move_idx(&mut self.module_idx, n, -1);
                    self.fetch_selected_module();
                }
                KeyCode::Char('t') => {
                    self.module_kind = self.module_kind.next();
                    self.module_idx = 0;
                    self.ensure_module_list();
                    self.fetch_selected_module();
                }
                KeyCode::Char('f') => self.toggle_favorite(),
                KeyCode::Enter => self.edit_selected_option(),
                KeyCode::Char('l') => {
                    let n = self
                        .module_info
                        .as_ref()
                        .map(|m| m.options.len())
                        .unwrap_or(0);
                    move_idx(&mut self.option_idx, n, 1);
                }
                KeyCode::Char('h') => {
                    let n = self
                        .module_info
                        .as_ref()
                        .map(|m| m.options.len())
                        .unwrap_or(0);
                    move_idx(&mut self.option_idx, n, -1);
                }
                _ => {}
            },
            Tab::Sessions => match key.code {
                KeyCode::Char('j') | KeyCode::Down => {
                    let n = self.snap.sessions.len();
                    move_idx(&mut self.session_idx, n, 1);
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    let n = self.snap.sessions.len();
                    move_idx(&mut self.session_idx, n, -1);
                }
                KeyCode::Char('i') => {
                    self.interact = true;
                    self.status = "session interact  Enter send  Esc back".into();
                }
                _ => {}
            },
            Tab::Creds => match key.code {
                KeyCode::Char('j') | KeyCode::Down => {
                    if self.cred_pane == CredPane::Creds {
                        let n = self.snap.creds.len();
                        move_idx(&mut self.cred_idx, n, 1);
                    } else {
                        let n = self.snap.loot.len();
                        move_idx(&mut self.loot_idx, n, 1);
                    }
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    if self.cred_pane == CredPane::Creds {
                        let n = self.snap.creds.len();
                        move_idx(&mut self.cred_idx, n, -1);
                    } else {
                        let n = self.snap.loot.len();
                        move_idx(&mut self.loot_idx, n, -1);
                    }
                }
                KeyCode::Char('x') => self.report_redact = !self.report_redact,
                _ => {}
            },
            Tab::Tasks => match key.code {
                KeyCode::Char('j') | KeyCode::Down => {
                    let n = self.tasks.len().max(self.snap.jobs.len());
                    move_idx(&mut self.task_idx, n, 1);
                    move_idx(&mut self.job_idx, self.snap.jobs.len(), 1);
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    let n = self.tasks.len().max(self.snap.jobs.len());
                    move_idx(&mut self.task_idx, n, -1);
                    move_idx(&mut self.job_idx, self.snap.jobs.len(), -1);
                }
                _ => {}
            },
            Tab::Chains => match key.code {
                KeyCode::Char('j') | KeyCode::Down => {
                    let n = self.chains.len();
                    move_idx(&mut self.chain_idx, n, 1);
                }
                KeyCode::Char('k') | KeyCode::Up => {
                    let n = self.chains.len();
                    move_idx(&mut self.chain_idx, n, -1);
                }
                _ => {}
            },
            Tab::Reports => match key.code {
                KeyCode::Char('x') => self.report_redact = !self.report_redact,
                _ => {}
            },
            Tab::Console => {}
            Tab::Wizards => self.handle_wizard_key(key),
        }
    }

    fn handle_wizard_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('j') | KeyCode::Down => {
                if self.wizard == WizardKind::AutoPlan {
                    let n = self.plan.len();
                    move_idx(&mut self.plan_idx, n, 1);
                } else {
                    self.wiz_field = self.wiz_field.saturating_add(1);
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                if self.wizard == WizardKind::AutoPlan {
                    let n = self.plan.len();
                    move_idx(&mut self.plan_idx, n, -1);
                } else {
                    self.wiz_field = self.wiz_field.saturating_sub(1);
                }
            }
            KeyCode::Char(' ') if self.wizard == WizardKind::AutoPlan => {
                if let Some(p) = self.plan.get_mut(self.plan_idx) {
                    p.selected = !p.selected;
                }
            }
            KeyCode::Char('a') if self.wizard == WizardKind::AutoPlan => self.rebuild_plan(),
            KeyCode::Char('+') => {
                self.min_rank = match self.min_rank {
                    Rank::Excellent => Rank::Great,
                    Rank::Great => Rank::Good,
                    Rank::Good => Rank::Normal,
                    _ => Rank::Normal,
                };
                self.rebuild_plan();
            }
            KeyCode::Char('-') => {
                self.min_rank = match self.min_rank {
                    Rank::Normal => Rank::Good,
                    Rank::Good => Rank::Great,
                    Rank::Great => Rank::Excellent,
                    other => other,
                };
                self.rebuild_plan();
            }
            KeyCode::Enter => self.edit_wizard_field(),
            KeyCode::Char('m') => {
                let n = self.macros.len();
                move_idx(&mut self.macro_idx, n, 1);
            }
            _ => {}
        }
    }

    fn edit_wizard_field(&mut self) {
        let (title, field, val) = match (self.wizard, self.wiz_field) {
            (WizardKind::Pentest, 0) => ("RHOSTS", "rhosts", self.pentest_rhosts.clone()),
            (WizardKind::Pentest, _) => ("ports", "ports", self.pentest_ports.clone()),
            (WizardKind::Validate, _) => ("import path", "import", self.import_path.clone()),
            (WizardKind::Payload, 0) => ("payload", "payload", self.venom.payload.clone()),
            (WizardKind::Payload, 1) => ("LHOST", "lhost", self.venom.lhost.clone()),
            (WizardKind::Payload, 2) => ("LPORT", "lport", self.venom.lport.clone()),
            (WizardKind::Payload, 3) => ("format", "format", self.venom.format.clone()),
            (WizardKind::Payload, 4) => ("encoder", "encoder", self.venom.encoder.clone()),
            (WizardKind::Payload, _) => ("outfile", "outfile", self.venom.outfile.clone()),
            _ => return,
        };
        self.edit = LineEdit::new(val);
        self.modal = Modal::Edit {
            title: title.into(),
            field: field.into(),
        };
    }

    fn edit_selected_option(&mut self) {
        let Some(info) = &self.module_info else {
            return;
        };
        let Some(opt) = info.options.get(self.option_idx) else {
            return;
        };
        self.edit = LineEdit::new(opt.value.clone());
        self.modal = Modal::Edit {
            title: format!("{} ({})", opt.name, opt.desc),
            field: format!("opt:{}", opt.name),
        };
    }

    fn toggle_favorite(&mut self) {
        let Some(name) = self.selected_module_name() else {
            return;
        };
        if let Some(i) = self.favorites.modules.iter().position(|m| *m == name) {
            self.favorites.modules.remove(i);
        } else {
            self.favorites.modules.push(name);
        }
        let _ = persist::save_favorites(&self.paths.favorites, &self.favorites);
    }

    fn move_host(&mut self, d: i32) {
        let ids = self.filtered_hosts();
        if ids.is_empty() {
            return;
        }
        let pos = ids.iter().position(|i| *i == self.host_idx).unwrap_or(0) as i32;
        let n = ids.len() as i32;
        let np = (pos + d).rem_euclid(n) as usize;
        self.host_idx = ids[np];
        self.detail_scroll = 0;
    }

    fn cycle_workspace(&mut self, d: i32) {
        let n = self.snap.workspaces.len();
        if n == 0 {
            return;
        }
        let pos = self
            .snap
            .workspaces
            .iter()
            .position(|w| *w == self.snap.workspace)
            .unwrap_or(0) as i32;
        let np = (pos + d).rem_euclid(n as i32) as usize;
        let name = self.snap.workspaces[np].clone();
        if self.demo {
            self.snap.workspace = name;
        } else {
            self.send(Cmd::SetWorkspace(name));
        }
    }

    pub fn is_favorite(&self, name: &str) -> bool {
        self.favorites.modules.iter().any(|m| m == name)
    }

    #[cfg(test)]
    pub fn rebuild_plan_for_test(&mut self) {
        self.rebuild_plan();
    }
}

fn move_idx(idx: &mut usize, len: usize, d: i32) {
    if len == 0 {
        *idx = 0;
        return;
    }
    *idx = ((*idx as i32 + d).rem_euclid(len as i32)) as usize;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn demo_builds_plan() {
        let mut app = App::new(true).expect("demo app");
        app.rebuild_plan_for_test();
        assert!(
            app.plan.iter().any(|p| p.module.contains("eternalblue")),
            "expected eternalblue match on demo DC: {:?}",
            app.plan.iter().map(|p| &p.module).collect::<Vec<_>>()
        );
    }
}

impl App {
    pub fn help_text() -> &'static str {
        "Breach — Aurora TUI for Metasploit Framework\n\
         Authorized testing only. Wraps msfrpcd / msfvenom; no exploit payloads shipped.\n\n\
         1 Dash   2 Hosts   3 Modules   4 Sessions   5 Creds\n\
         6 Tasks  7 Chains  8 Reports   9 Console    0 Wizards\n\n\
         Ctrl-G  confirm primary action (connect / run / scan / report)\n\
         /       filter     y yank      r refresh     q quit     ? this help\n\
         Tab     cycle pane / module type / wizard\n\
         j k     move       Enter edit  space toggle plan item\n\n\
         Hosts   i import path   a auto-exploit plan\n\
         Modules t type   f favorite   Enter option   l/h options\n\
         Sessions i interact (Esc back)\n\
         Wizards +/- min rank   a rebuild plan   m next macro\n\
         Dash    [ ] workspace   e rename workspace\n\n\
         RPC binds 127.0.0.1 by default. Password: NEXUS_MSF_RPC_PASS or config.toml (0600).\n\
         --demo walks the UI with sample data and never talks to Framework."
    }
}

pub const ACTIONS: &[crate::commands::Action] = &[
    crate::commands::Action::key("Dashboard", '1'),
    crate::commands::Action::key("Hosts", '2'),
    crate::commands::Action::key("Modules", '3'),
    crate::commands::Action::key("Sessions", '4'),
    crate::commands::Action::ctrl("Review and run", 'g'),
    crate::commands::Action::key("Filter", '/'),
    crate::commands::Action::key("Help", '?'),
    crate::commands::Action::theme("Aurora theme", 'a'),
    crate::commands::Action::theme("Follow Omarchy theme", 'o'),
    crate::commands::Action::theme("Terminal theme", 't'),
];
