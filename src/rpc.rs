use crate::model::*;
use crate::persist::Config;
use anyhow::{Context, Result, bail};
use rmpv::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::Child;
use tokio::sync::mpsc;

pub fn encode_call(method: &str, token: Option<&str>, args: &[Value]) -> Vec<u8> {
    let mut arr = vec![Value::from(method)];
    if let Some(t) = token {
        arr.push(Value::from(t));
    }
    arr.extend(args.iter().cloned());
    let mut buf = Vec::new();
    rmpv::encode::write_value(&mut buf, &Value::Array(arr)).expect("msgpack encode");
    buf
}

pub fn decode_value(bytes: &[u8]) -> Result<Value> {
    rmpv::decode::read_value(&mut &bytes[..]).context("msgpack decode")
}

pub fn rpc_error(v: &Value) -> Option<String> {
    let map = as_map(v)?;
    if map_bool(&map, "error") {
        Some(
            map_str(&map, "error_message")
                .or_else(|| map_str(&map, "error_class"))
                .unwrap_or_else(|| "rpc error".into()),
        )
    } else {
        None
    }
}

#[derive(Clone)]
pub struct Client {
    url: String,
    http: reqwest::Client,
    pub token: Option<String>,
}

impl Client {
    pub fn new(cfg: &Config) -> Result<Self> {
        let scheme = if cfg.ssl { "https" } else { "http" };
        let host = if cfg.host.contains(':') && !cfg.host.starts_with('[') {
            format!("[{}]", cfg.host)
        } else {
            cfg.host.clone()
        };
        let url = format!("{scheme}://{host}:{}{}", cfg.port, cfg.uri);
        let http = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(60))
            .no_proxy()
            .build()?;
        Ok(Self {
            url,
            http,
            token: None,
        })
    }

    pub(crate) fn endpoint(&self) -> &str {
        &self.url
    }

    pub async fn call(&self, method: &str, args: &[Value]) -> Result<Value> {
        let token = if method == "auth.login" {
            None
        } else {
            self.token.as_deref()
        };
        let body = encode_call(method, token, args);
        let resp = self
            .http
            .post(&self.url)
            .header("Content-Type", "binary/message-pack")
            .body(body)
            .send()
            .await
            .with_context(|| format!("POST {method}"))?;
        let resp = resp
            .error_for_status()
            .with_context(|| format!("HTTP response for {method}"))?;
        let bytes = resp.bytes().await?;
        let v = decode_value(&bytes)?;
        if let Some(err) = rpc_error(&v) {
            bail!("{method}: {err}");
        }
        Ok(v)
    }

    async fn workspace_rows(&self, method: &str, workspace: &str) -> Result<Value> {
        let key = method.strip_prefix("db.").context("database method")?;
        let mut all = Vec::new();
        loop {
            let options = Value::Map(vec![
                (Value::from("workspace"), Value::from(workspace)),
                (Value::from("limit"), Value::from(100)),
                (Value::from("offset"), Value::from(all.len() as u64)),
            ]);
            let response = self.call(method, &[options]).await?;
            let map =
                as_map(&response).with_context(|| format!("{method}: expected response map"))?;
            let page = map
                .iter()
                .find(|(k, _)| k == key)
                .and_then(|(_, v)| v.as_array())
                .with_context(|| format!("{method}: missing {key} rows"))?;
            let complete = page.len() < 100;
            all.extend(page.iter().cloned());
            if complete {
                break;
            }
        }
        Ok(Value::Map(vec![(Value::from(key), Value::Array(all))]))
    }
    pub async fn login(&mut self, user: &str, pass: &str) -> Result<()> {
        let v = self
            .call("auth.login", &[Value::from(user), Value::from(pass)])
            .await?;
        let map = as_map(&v).context("login response")?;
        let token = map_str(&map, "token").context("no token")?;
        self.token = Some(token);
        Ok(())
    }
}

#[derive(Debug)]
pub enum Cmd {
    Connect,
    #[allow(dead_code)]
    Disconnect,
    Shutdown(tokio::sync::oneshot::Sender<()>),
    Refresh,
    ConsoleWrite(String),
    RunWorkflow(Box<crate::workflow::Request>),
    CancelWorkflow(String),
    GeneratePayload {
        id: String,
        argv: Vec<String>,
    },
    SessionRead {
        id: String,
        meterpreter: bool,
    },
    SessionWrite {
        id: String,
        data: String,
        meterpreter: bool,
    },
    SetWorkspace(String),
    JobStop(String),
    SessionStop(String),
    FetchModule {
        kind: String,
        name: String,
    },
    ListModules {
        kind: String,
    },
}

#[derive(Debug)]
pub enum Event {
    WorkflowFinished(String),
    PlanReady(Vec<PlanItem>),
    Validation(ValidationResult),
    ReportReady(PathBuf),
    Status(String),
    Connected(Snapshot),
    Snapshot(Snapshot),
    Console {
        data: String,
        busy: bool,
    },
    SessionIo {
        id: String,
        data: String,
    },
    ModuleInfo(ModuleInfo),
    ModuleList {
        kind: String,
        names: Vec<String>,
    },
    Error(String),
    TaskUpdate {
        id: String,
        status: String,
        detail: String,
    },
}

pub fn start_worker(cfg: Config) -> (mpsc::UnboundedSender<Cmd>, mpsc::UnboundedReceiver<Event>) {
    let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
    let (ev_tx, ev_rx) = mpsc::unbounded_channel();
    tokio::spawn(worker_loop(cfg, cmd_rx, ev_tx));
    (cmd_tx, ev_rx)
}

struct Worker {
    cfg: Config,
    client: Option<Client>,
    child: Option<Child>,
    console_id: Option<String>,
    ev: mpsc::UnboundedSender<Event>,
    session_reads: HashMap<String, bool>,
    active: Option<(
        String,
        tokio::sync::watch::Sender<bool>,
        tokio::task::JoinHandle<()>,
    )>,
}

async fn worker_loop(
    cfg: Config,
    mut cmds: mpsc::UnboundedReceiver<Cmd>,
    ev: mpsc::UnboundedSender<Event>,
) {
    let mut w = Worker {
        cfg,
        client: None,
        child: None,
        console_id: None,
        session_reads: HashMap::new(),
        active: None,
        ev,
    };
    let mut ticker = tokio::time::interval(Duration::from_secs(2));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                if w.active.as_ref().is_some_and(|(_,_,task)|task.is_finished()){w.active=None;}
                if w.client.is_some() && w.active.is_none() {
                    let _ = w.refresh().await;
                    let _ = w.poll_console().await;
                    w.poll_sessions().await;
                }
            }
            msg = cmds.recv() => {
                let Some(cmd) = msg else { break };
                if let Err(e) = w.handle(cmd).await {
                    let _ = w.ev.send(Event::Error(e.to_string()));
                }
            }
        }
    }
    w.shutdown().await;
}

impl Worker {
    fn emit(&self, e: Event) {
        let _ = self.ev.send(e);
    }

    async fn handle(&mut self, cmd: Cmd) -> Result<()> {
        if self
            .active
            .as_ref()
            .is_some_and(|(_, _, task)| task.is_finished())
        {
            self.active = None;
        }
        if self.active.is_some()
            && matches!(
                cmd,
                Cmd::Connect
                    | Cmd::SetWorkspace(_)
                    | Cmd::ConsoleWrite(_)
                    | Cmd::SessionWrite { .. }
            )
        {
            bail!(
                "a workflow is active; cancel it before changing workspace or starting another operation"
            );
        }
        match cmd {
            Cmd::RunWorkflow(request) => {
                if self.active.is_some() || self.client.is_none() {
                    self.emit(Event::TaskUpdate {
                        id: request.id.clone(),
                        status: "failed".into(),
                        detail: "another workflow is active or RPC is disconnected".into(),
                    });
                    self.emit(Event::WorkflowFinished(request.id));
                    return Ok(());
                }
                let client = self.cli()?.clone();
                let ev = self.ev.clone();
                let (cancel, rx) = tokio::sync::watch::channel(false);
                let id = request.id.clone();
                let task =
                    tokio::spawn(crate::workflow::Runner::new(client, ev, rx, *request).run());
                self.active = Some((id, cancel, task));
                Ok(())
            }
            Cmd::CancelWorkflow(id) => {
                if let Some((active, cancel, _)) = &self.active {
                    if active == &id {
                        let _ = cancel.send(true);
                    }
                }
                Ok(())
            }
            Cmd::GeneratePayload { id, argv } => {
                if self.active.is_some() {
                    self.emit(Event::TaskUpdate {
                        id: id.clone(),
                        status: "failed".into(),
                        detail: "another workflow is active".into(),
                    });
                    self.emit(Event::WorkflowFinished(id));
                    return Ok(());
                }
                let ev = self.ev.clone();
                let task_id = id.clone();
                let (cancel, rx) = tokio::sync::watch::channel(false);
                let task = tokio::spawn(async move {
                    let (status, detail) = crate::venom::generate_cancellable(&argv, rx).await;
                    let _ = ev.send(Event::TaskUpdate {
                        id: task_id.clone(),
                        status,
                        detail,
                    });
                    let _ = ev.send(Event::WorkflowFinished(task_id));
                });
                self.active = Some((id, cancel, task));
                Ok(())
            }
            Cmd::Connect => self.connect().await,
            Cmd::Shutdown(done) => {
                self.shutdown().await;
                let _ = done.send(());
                Ok(())
            }
            Cmd::Disconnect => {
                self.shutdown().await;
                self.emit(Event::Status("disconnected".into()));
                Ok(())
            }
            Cmd::Refresh => self.refresh().await,
            Cmd::ConsoleWrite(s) => self.console_write(&s).await,
            Cmd::SessionRead { id, meterpreter } => {
                self.session_reads.insert(id.clone(), meterpreter);
                self.read_session(&id, meterpreter).await
            }
            Cmd::SessionWrite {
                id,
                data,
                meterpreter,
            } => self.session_write(&id, &data, meterpreter).await,
            Cmd::SetWorkspace(name) => self.set_workspace(&name).await,
            Cmd::JobStop(id) => {
                let c = self.cli()?;
                let _ = c.call("job.stop", &[Value::from(id.clone())]).await?;
                self.emit(Event::Status(format!("stopped job {id}")));
                self.refresh().await
            }
            Cmd::SessionStop(id) => {
                let sid = parse_sid(&id);
                let c = self.cli()?;
                let _ = c.call("session.stop", &[sid]).await?;
                self.session_reads.remove(&id);
                self.emit(Event::Status(format!("stopped session {id}")));
                self.refresh().await
            }
            Cmd::FetchModule { kind, name } => self.fetch_module(&kind, &name).await,
            Cmd::ListModules { kind } => self.list_modules(&kind).await,
        }
    }

    fn cli(&mut self) -> Result<&mut Client> {
        self.client
            .as_mut()
            .context("not connected to msfrpcd — press Ctrl-G on Dash to connect")
    }

    async fn connect(&mut self) -> Result<()> {
        if !self.cfg.is_loopback() && self.cfg.spawn {
            bail!(
                "refusing to spawn msfrpcd on non-loopback host {}",
                self.cfg.host
            );
        }
        self.emit(Event::Status("connecting…".into()));
        if let Err(e) = self.try_login().await {
            if self.cfg.spawn && self.cfg.is_loopback() {
                self.emit(Event::Status(format!(
                    "rpc not up ({e}); spawning msfrpcd on 127.0.0.1"
                )));
                self.spawn_msfrpcd().await?;
                tokio::time::sleep(Duration::from_millis(800)).await;
                let mut last = None;
                for _ in 0..25 {
                    match self.try_login().await {
                        Ok(()) => {
                            last = None;
                            break;
                        }
                        Err(e) => {
                            last = Some(e);
                            tokio::time::sleep(Duration::from_millis(400)).await;
                        }
                    }
                }
                if let Some(e) = last {
                    return Err(e).context(
                        "could not log in to msfrpcd (check password, SSL, and that the daemon is up)",
                    );
                }
            } else {
                return Err(e);
            }
        }
        self.ensure_console().await?;
        let snap = self.snapshot().await?;
        self.emit(Event::Connected(snap));
        Ok(())
    }

    async fn try_login(&mut self) -> Result<()> {
        let pass = self.cfg.resolved_password();
        if pass.is_empty() {
            bail!("no RPC password (set NEXUS_MSF_RPC_PASS or config.password)");
        }
        let mut client = Client::new(&self.cfg)?;
        client.login(&self.cfg.username, &pass).await?;
        self.client = Some(client);
        Ok(())
    }

    async fn spawn_msfrpcd(&mut self) -> Result<()> {
        let pass = self.cfg.resolved_password();
        if pass.is_empty() {
            bail!("cannot spawn msfrpcd without a password");
        }
        let bin = find_msfrpcd().context(
            "msfrpcd not found on PATH — install Metasploit Framework, or start it yourself:\n  msfrpcd -U msf -P \"$NEXUS_MSF_RPC_PASS\" -a 127.0.0.1 -p 55553 -S -f",
        )?;
        let port = self.cfg.port.to_string();
        let mut cmd = tokio::process::Command::new(&bin);
        cmd.args([
            "-U",
            &self.cfg.username,
            "-P",
            &pass,
            "-a",
            "127.0.0.1",
            "-p",
            &port,
            "-f",
        ])
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
        if !self.cfg.ssl {
            cmd.arg("-S");
        }
        // The spawned daemon binds IPv4 loopback, regardless of a localhost alias.
        self.cfg.host = "127.0.0.1".into();
        let mut child = cmd
            .spawn()
            .with_context(|| format!("spawn {} (is Metasploit installed?)", bin.display()))?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Some(status) = child.try_wait()? {
            let mut err = String::new();
            if let Some(mut s) = child.stderr.take() {
                let _ = tokio::io::AsyncReadExt::read_to_string(&mut s, &mut err).await;
            }
            bail!(
                "msfrpcd exited {status}: {}",
                err.trim().chars().take(400).collect::<String>()
            );
        }
        self.child = Some(child);
        Ok(())
    }

    async fn shutdown(&mut self) {
        if let Some((_, cancel, mut task)) = self.active.take() {
            let _ = cancel.send(true);
            if tokio::time::timeout(Duration::from_secs(5), &mut task)
                .await
                .is_err()
            {
                task.abort();
            }
        }
        if let (Some(c), Some(id)) = (self.client.as_ref(), self.console_id.as_ref()) {
            let _ = c.call("console.destroy", &[Value::from(id.as_str())]).await;
        }
        self.console_id = None;
        self.session_reads.clear();
        self.client = None;
        if let Some(mut ch) = self.child.take() {
            let _ = ch.kill().await;
        }
    }

    async fn ensure_console(&mut self) -> Result<()> {
        if self.console_id.is_some() {
            return Ok(());
        }
        let v = self.cli()?.call("console.create", &[]).await?;
        let map = as_map(&v).context("console.create")?;
        self.console_id = map_str(&map, "id");
        Ok(())
    }

    async fn console_write(&mut self, data: &str) -> Result<()> {
        self.ensure_console().await?;
        let id = self.console_id.clone().context("no console")?;
        let payload = if data.ends_with('\n') {
            data.to_string()
        } else {
            format!("{data}\n")
        };
        self.cli()?
            .call(
                "console.write",
                &[Value::from(id.as_str()), Value::from(payload)],
            )
            .await?;
        self.poll_console().await
    }

    async fn poll_console(&mut self) -> Result<()> {
        let Some(id) = self.console_id.clone() else {
            return Ok(());
        };
        let Some(c) = self.client.as_ref() else {
            return Ok(());
        };
        let v = c.call("console.read", &[Value::from(id.as_str())]).await?;
        let map = as_map(&v).unwrap_or_default();
        let data = map_str(&map, "data").unwrap_or_default();
        let busy = map_bool(&map, "busy");
        self.emit(Event::Console { data, busy });
        Ok(())
    }

    async fn session_write(&mut self, id: &str, data: &str, meterpreter: bool) -> Result<()> {
        let method = if meterpreter {
            "session.meterpreter_write"
        } else {
            "session.shell_write"
        };
        let payload = if data.ends_with('\n') {
            data.to_string()
        } else {
            format!("{data}\n")
        };
        self.cli()?
            .call(method, &[parse_sid(id), Value::from(payload)])
            .await?;
        self.session_reads.insert(id.to_owned(), meterpreter);
        self.read_session(id, meterpreter).await
    }
    async fn read_session(&mut self, id: &str, meterpreter: bool) -> Result<()> {
        let method = if meterpreter {
            "session.meterpreter_read"
        } else {
            "session.shell_read"
        };
        let v = self.cli()?.call(method, &[parse_sid(id)]).await?;
        let text = as_map(&v)
            .and_then(|m| map_str(&m, "data"))
            .or_else(|| value_string(&v))
            .unwrap_or_default();
        if !text.is_empty() {
            self.emit(Event::SessionIo {
                id: id.into(),
                data: text,
            });
        }
        Ok(())
    }
    async fn poll_sessions(&mut self) {
        let sessions: Vec<_> = self
            .session_reads
            .iter()
            .map(|(id, kind)| (id.clone(), *kind))
            .collect();
        for (id, kind) in sessions {
            if let Err(error) = self.read_session(&id, kind).await {
                self.session_reads.remove(&id);
                self.emit(Event::Error(format!("session {id}: {error}")));
            }
        }
    }

    async fn set_workspace(&mut self, name: &str) -> Result<()> {
        self.cli()?
            .call("db.set_workspace", &[Value::from(name)])
            .await?;
        self.refresh().await
    }

    async fn fetch_module(&mut self, kind: &str, name: &str) -> Result<()> {
        let v = self
            .cli()?
            .call("module.info", &[Value::from(kind), Value::from(name)])
            .await?;
        let info = parse_module_info(kind, name, &v);
        let ov = self
            .cli()?
            .call("module.options", &[Value::from(kind), Value::from(name)])
            .await
            .ok();
        let mut info = info;
        if let Some(ov) = ov {
            info.options = parse_options(&ov);
        }
        self.emit(Event::ModuleInfo(info));
        Ok(())
    }

    async fn list_modules(&mut self, kind: &str) -> Result<()> {
        let method = match kind {
            "exploit" => "module.exploits",
            "auxiliary" => "module.auxiliary",
            "post" => "module.post",
            "payload" => "module.payloads",
            "encoder" => "module.encoders",
            _ => "module.exploits",
        };
        let v = self.cli()?.call(method, &[]).await?;
        let mut names = Vec::new();
        if let Some(arr) = v.as_array() {
            for x in arr {
                if let Some(s) = x.as_str() {
                    names.push(s.to_string());
                }
            }
        } else if let Some(map) = as_map(&v) {
            for (k, val) in map {
                if let Some(arr) = val.as_array() {
                    for x in arr {
                        if let Some(s) = x.as_str() {
                            names.push(s.to_string());
                        }
                    }
                } else if let Some(s) = val.as_str() {
                    names.push(format!("{k}/{s}"));
                }
            }
        }
        names.sort();
        self.emit(Event::ModuleList {
            kind: kind.into(),
            names,
        });
        Ok(())
    }

    async fn refresh(&mut self) -> Result<()> {
        if self.client.is_none() {
            return Ok(());
        }
        match self.snapshot().await {
            Ok(s) => {
                self.emit(Event::Snapshot(s));
                Ok(())
            }
            Err(e) => {
                self.emit(Event::Error(format!("refresh: {e}")));
                Ok(())
            }
        }
    }

    async fn snapshot(&mut self) -> Result<Snapshot> {
        self.cli()?.snapshot().await
    }
}

impl Client {
    pub(crate) async fn snapshot(&self) -> Result<Snapshot> {
        self.snapshot_policy(false).await
    }
    pub(crate) async fn strict_snapshot(&self) -> Result<Snapshot> {
        self.snapshot_policy(true).await
    }
    async fn snapshot_rows(&self, method: &str, workspace: &str, strict: bool) -> Result<Value> {
        match self.workspace_rows(method, workspace).await {
            Ok(value) => Ok(value),
            Err(error) if strict => Err(error),
            Err(_) => Ok(Value::Nil),
        }
    }
    async fn snapshot_policy(&self, strict: bool) -> Result<Snapshot> {
        let c = self;
        let ver = c.call("core.version", &[]).await.unwrap_or(Value::Nil);
        let ver_map = as_map(&ver).unwrap_or_default();
        let db = c.call("db.status", &[]).await.unwrap_or(Value::Nil);
        let db_map = as_map(&db).unwrap_or_default();
        let stats = c.call("core.module_stats", &[]).await.unwrap_or(Value::Nil);
        let st_map = as_map(&stats).unwrap_or_default();
        let ws = c.call("db.current_workspace", &[]).await.ok();
        if strict {
            anyhow::ensure!(ws.is_some(), "cannot resolve current workspace");
        }
        let workspace = ws
            .as_ref()
            .and_then(|v| {
                as_map(v)
                    .and_then(|m| map_str(&m, "workspace"))
                    .or_else(|| v.as_str().map(|s| s.to_string()))
            })
            .unwrap_or_else(|| "default".into());
        if strict {
            anyhow::ensure!(
                map_str(&db_map, "db").is_some() || map_bool(&db_map, "ok"),
                "Framework database is disconnected; connect it before running workspace workflows"
            );
        }
        let wslist = c.call("db.workspaces", &[]).await.unwrap_or(Value::Nil);
        let workspaces = parse_workspaces(&wslist);
        let hosts = parse_hosts(&c.snapshot_rows("db.hosts", &workspace, strict).await?);
        let services = parse_services(&c.snapshot_rows("db.services", &workspace, strict).await?);
        let vulns = parse_vulns(&c.snapshot_rows("db.vulns", &workspace, strict).await?);
        let notes = parse_notes(&c.snapshot_rows("db.notes", &workspace, strict).await?);
        let creds = parse_creds(&c.snapshot_rows("db.creds", &workspace, strict).await?);
        let loot = parse_loot(&c.snapshot_rows("db.loots", &workspace, strict).await?);
        let sessions = parse_sessions(&match c.call("session.list", &[]).await {
            Ok(v) => v,
            Err(e) if strict => return Err(e),
            Err(_) => Value::Nil,
        });
        let jobs = parse_jobs(&match c.call("job.list", &[]).await {
            Ok(v) => v,
            Err(e) if strict => return Err(e),
            Err(_) => Value::Nil,
        });

        let mut host_map: HashMap<String, Host> = HashMap::new();
        for h in hosts {
            host_map.insert(h.address.clone(), h);
        }
        for s in services {
            let h = host_map.entry(s.0.clone()).or_insert_with(|| Host {
                address: s.0.clone(),
                ..Default::default()
            });
            h.services.push(s.1);
        }
        for v in vulns {
            let h = host_map.entry(v.0.clone()).or_insert_with(|| Host {
                address: v.0.clone(),
                ..Default::default()
            });
            h.vulns.push(v.1);
        }
        let mut hosts: Vec<Host> = host_map.into_values().collect();
        hosts.sort_by(|a, b| a.address.cmp(&b.address));

        Ok(Snapshot {
            version: map_str(&ver_map, "version").unwrap_or_else(|| "unknown".into()),
            ruby: map_str(&ver_map, "ruby").unwrap_or_default(),
            db_ok: map_str(&db_map, "db").is_some() || map_bool(&db_map, "ok"),
            workspace,
            workspaces,
            hosts,
            sessions,
            jobs,
            creds,
            loot,
            notes,
            module_stats: ModuleStats {
                exploits: map_u32(&st_map, "exploits"),
                auxiliary: map_u32(&st_map, "auxiliary"),
                post: map_u32(&st_map, "post"),
                payloads: map_u32(&st_map, "payloads"),
                encoders: map_u32(&st_map, "encoders"),
                nops: map_u32(&st_map, "nops"),
            },
        })
    }
}

fn find_msfrpcd() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("MSFRPCD") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let names = ["msfrpcd", "msfrpcd.ruby"];
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            for name in names {
                let p = dir.join(name);
                if p.is_file() {
                    return Some(p);
                }
            }
        }
    }
    const CANDIDATES: &[&str] = &[
        "/usr/bin/msfrpcd",
        "/usr/local/bin/msfrpcd",
        "/usr/share/metasploit-framework/msfrpcd",
        "/opt/metasploit-framework/bin/msfrpcd",
        "/opt/metasploit-framework/msfrpcd",
        "/snap/bin/msfrpcd",
    ];
    CANDIDATES
        .iter()
        .map(Path::new)
        .find(|p| p.is_file())
        .map(Path::to_path_buf)
}

fn parse_sid(id: &str) -> Value {
    if let Ok(n) = id.parse::<i64>() {
        Value::from(n)
    } else {
        Value::from(id)
    }
}

pub type Map = Vec<(String, Value)>;

/// Framework encodes RPC strings as MessagePack **bin**, not UTF-8 str.
pub fn value_string(v: &Value) -> Option<String> {
    if let Some(s) = v.as_str() {
        return Some(s.to_string());
    }
    if let Some(b) = v.as_slice() {
        if let Ok(s) = std::str::from_utf8(b) {
            return Some(s.to_string());
        }
    }
    if let Some(b) = v.as_bool() {
        return Some(b.to_string());
    }
    if let Some(n) = v.as_i64() {
        return Some(n.to_string());
    }
    if let Some(n) = v.as_f64() {
        return Some(n.to_string());
    }
    None
}

pub(crate) fn as_map(v: &Value) -> Option<Map> {
    let m = v.as_map()?;
    Some(
        m.iter()
            .filter_map(|(k, val)| value_string(k).map(|s| (s, val.clone())))
            .collect(),
    )
}

pub(crate) fn map_str(map: &Map, k: &str) -> Option<String> {
    map.iter()
        .find(|(key, _)| key == k)
        .and_then(|(_, v)| value_string(v))
}

pub(crate) fn map_bool(map: &Map, k: &str) -> bool {
    map.iter()
        .find(|(key, _)| key == k)
        .is_some_and(|(_, v)| v.as_bool().unwrap_or(false))
}

fn map_u32(map: &Map, k: &str) -> u32 {
    map.iter()
        .find(|(key, _)| key == k)
        .and_then(|(_, v)| v.as_u64().or_else(|| v.as_i64().map(|n| n as u64)))
        .unwrap_or(0) as u32
}

fn parse_workspaces(v: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(arr) = v.as_array() {
        for x in arr {
            if let Some(s) = x.as_str() {
                out.push(s.into());
            } else if let Some(m) = as_map(x) {
                if let Some(n) = map_str(&m, "name") {
                    out.push(n);
                }
            }
        }
    } else if let Some(m) = as_map(v) {
        if let Some(arr) = m
            .iter()
            .find(|(k, _)| k == "workspaces")
            .and_then(|(_, v)| v.as_array())
        {
            for x in arr {
                if let Some(s) = x.as_str() {
                    out.push(s.into());
                } else if let Some(mm) = as_map(x) {
                    if let Some(n) = map_str(&mm, "name") {
                        out.push(n);
                    }
                }
            }
        }
    }
    if out.is_empty() {
        out.push("default".into());
    }
    out
}

fn parse_hosts(v: &Value) -> Vec<Host> {
    rows(v, "hosts")
        .into_iter()
        .map(|m| Host {
            address: map_str(&m, "address").unwrap_or_default(),
            name: map_str(&m, "name").unwrap_or_default(),
            os: map_str(&m, "os_name")
                .or_else(|| map_str(&m, "os"))
                .unwrap_or_default(),
            purpose: map_str(&m, "purpose").unwrap_or_default(),
            info: map_str(&m, "info").unwrap_or_default(),
            services: Vec::new(),
            vulns: Vec::new(),
        })
        .collect()
}

fn parse_services(v: &Value) -> Vec<(String, Service)> {
    rows(v, "services")
        .into_iter()
        .map(|m| {
            let host = map_str(&m, "host")
                .or_else(|| map_str(&m, "address"))
                .unwrap_or_default();
            let svc = Service {
                port: map_str(&m, "port")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
                proto: map_str(&m, "proto").unwrap_or_else(|| "tcp".into()),
                name: map_str(&m, "name").unwrap_or_default(),
                state: map_str(&m, "state").unwrap_or_else(|| "open".into()),
                info: map_str(&m, "info").unwrap_or_default(),
            };
            (host, svc)
        })
        .collect()
}

fn parse_vulns(v: &Value) -> Vec<(String, Vuln)> {
    rows(v, "vulns")
        .into_iter()
        .map(|m| {
            let host = map_str(&m, "host")
                .or_else(|| map_str(&m, "address"))
                .unwrap_or_default();
            let refs = map_str(&m, "refs")
                .unwrap_or_default()
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            (
                host,
                Vuln {
                    name: map_str(&m, "name").unwrap_or_default(),
                    refs,
                    info: map_str(&m, "info").unwrap_or_default(),
                },
            )
        })
        .collect()
}

fn parse_notes(v: &Value) -> Vec<Note> {
    rows(v, "notes")
        .into_iter()
        .map(|m| Note {
            host: map_str(&m, "host").unwrap_or_default(),
            ntype: map_str(&m, "ntype")
                .or_else(|| map_str(&m, "type"))
                .unwrap_or_default(),
            data: map_str(&m, "data").unwrap_or_default(),
        })
        .collect()
}

fn parse_creds(v: &Value) -> Vec<Cred> {
    rows(v, "creds")
        .into_iter()
        .map(|m| Cred {
            host: map_str(&m, "host").unwrap_or_default(),
            service: map_str(&m, "sname")
                .or_else(|| map_str(&m, "service"))
                .unwrap_or_default(),
            user: map_str(&m, "user").unwrap_or_default(),
            pass: map_str(&m, "pass").unwrap_or_default(),
            kind: map_str(&m, "ptype")
                .or_else(|| map_str(&m, "type"))
                .unwrap_or_default(),
            realm: map_str(&m, "realm_value")
                .or_else(|| map_str(&m, "realm"))
                .unwrap_or_default(),
        })
        .collect()
}

fn parse_loot(v: &Value) -> Vec<Loot> {
    rows(v, "loots")
        .into_iter()
        .map(|m| Loot {
            host: map_str(&m, "host").unwrap_or_default(),
            ltype: map_str(&m, "ltype").unwrap_or_default(),
            name: map_str(&m, "name").unwrap_or_default(),
            info: map_str(&m, "info").unwrap_or_default(),
            path: map_str(&m, "path").unwrap_or_default(),
        })
        .collect()
}

fn parse_sessions(v: &Value) -> Vec<Session> {
    let mut out = Vec::new();
    if let Some(map) = as_map(v) {
        for (id, val) in map {
            let m = as_map(&val).unwrap_or_default();
            out.push(Session {
                id,
                kind: map_str(&m, "type").unwrap_or_default(),
                via_exploit: map_str(&m, "via_exploit").unwrap_or_default(),
                via_payload: map_str(&m, "via_payload").unwrap_or_default(),
                tunnel_local: map_str(&m, "tunnel_local").unwrap_or_default(),
                tunnel_peer: map_str(&m, "tunnel_peer").unwrap_or_default(),
                info: map_str(&m, "info").unwrap_or_default(),
                workspace: map_str(&m, "workspace").unwrap_or_default(),
                session_host: map_str(&m, "session_host")
                    .or_else(|| map_str(&m, "target_host"))
                    .unwrap_or_default(),
                platform: map_str(&m, "platform").unwrap_or_default(),
                arch: map_str(&m, "arch").unwrap_or_default(),
                routes: map_str(&m, "routes").unwrap_or_default(),
            });
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

fn parse_jobs(v: &Value) -> Vec<Job> {
    let mut out = Vec::new();
    if let Some(map) = as_map(v) {
        for (id, val) in map {
            let name = val.as_str().map(|s| s.to_string()).unwrap_or_else(|| {
                as_map(&val)
                    .and_then(|m| map_str(&m, "name"))
                    .unwrap_or_default()
            });
            out.push(Job { id, name });
        }
    }
    out.sort_by(|a, b| a.id.cmp(&b.id));
    out
}

fn rows(v: &Value, key: &str) -> Vec<Map> {
    if let Some(arr) = v.as_array() {
        return arr.iter().filter_map(as_map).collect();
    }
    if let Some(m) = as_map(v) {
        if let Some(arr) = m
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| v.as_array())
        {
            return arr.iter().filter_map(as_map).collect();
        }
        // single row
        if map_str(&m, "address").is_some() || map_str(&m, "host").is_some() {
            return vec![m];
        }
    }
    Vec::new()
}

pub fn parse_module_info(kind: &str, name: &str, v: &Value) -> ModuleInfo {
    let m = as_map(v).unwrap_or_default();
    let mut refs = Vec::new();
    if let Some((_, rv)) = m.iter().find(|(k, _)| k == "references") {
        if let Some(arr) = rv.as_array() {
            for item in arr {
                if let Some(pair) = item.as_array() {
                    let a = pair.first().and_then(value_string).unwrap_or_default();
                    let b = pair.get(1).and_then(value_string).unwrap_or_default();
                    if !b.is_empty() {
                        refs.push(format!("{a}-{b}"));
                    }
                } else if let Some(s) = value_string(item) {
                    refs.push(s);
                }
            }
        }
    }
    ModuleInfo {
        kind: kind.into(),
        fullname: name.into(),
        name: map_str(&m, "name").unwrap_or_else(|| name.into()),
        rank: map_str(&m, "rank").unwrap_or_else(|| "normal".into()),
        description: map_str(&m, "description").unwrap_or_default(),
        refs,
        options: Vec::new(),
    }
}

pub(crate) fn parse_options(v: &Value) -> Vec<ModuleOption> {
    let mut out = Vec::new();
    let Some(map) = as_map(v) else {
        return out;
    };
    for (name, val) in map {
        let m = as_map(&val).unwrap_or_default();
        let default = map_str(&m, "default").unwrap_or_default();
        out.push(ModuleOption {
            name: name.clone(),
            required: map_bool(&m, "required"),
            advanced: map_bool(&m, "advanced"),
            desc: map_str(&m, "desc").unwrap_or_default(),
            default: default.clone(),
            value: default,
            opt_type: map_str(&m, "type").unwrap_or_else(|| "string".into()),
        });
    }
    out.sort_by(|a, b| b.required.cmp(&a.required).then(a.name.cmp(&b.name)));
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn login_response_bin_keys() {
        // msfrpcd encodes map keys/values as msgpack bin, not str.
        let v = Value::Map(vec![
            (
                Value::Binary(b"result".to_vec()),
                Value::Binary(b"success".to_vec()),
            ),
            (
                Value::Binary(b"token".to_vec()),
                Value::Binary(b"TEMPUl2yTx1AMmX43T9WLeN8thjG1dul".to_vec()),
            ),
        ]);
        let map = as_map(&v).expect("map");
        assert_eq!(map_str(&map, "result").as_deref(), Some("success"));
        assert_eq!(
            map_str(&map, "token").as_deref(),
            Some("TEMPUl2yTx1AMmX43T9WLeN8thjG1dul")
        );
        assert!(rpc_error(&v).is_none());
    }

    #[test]
    fn login_response_from_wire() {
        let bytes: &[u8] =
            b"\x82\xc4\x06result\xc4\x07success\xc4\x05token\xc4 TEMPUl2yTx1AMmX43T9WLeN8thjG1dul";
        // 0x20 after last c4 is length 32; the space in the rust string is that byte.
        let v = decode_value(bytes).expect("decode");
        let map = as_map(&v).expect("map");
        assert_eq!(map_str(&map, "result").as_deref(), Some("success"));
        assert_eq!(map_str(&map, "token").unwrap().len(), 32);
    }
    pub(crate) async fn mock_rpc(
        replies: Vec<(&'static str, Value)>,
    ) -> (Config, tokio::task::JoinHandle<Vec<Value>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cfg = Config {
            port: listener.local_addr().unwrap().port(),
            spawn: false,
            ..Default::default()
        };
        let task = tokio::spawn(async move {
            let mut calls = Vec::new();
            for (method, response) in replies {
                let (mut stream, _) =
                    tokio::time::timeout(Duration::from_secs(5), listener.accept())
                        .await
                        .unwrap()
                        .unwrap();
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                let (offset, length) = loop {
                    let n = stream.read(&mut chunk).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&chunk[..n]);
                    if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                        let headers = String::from_utf8_lossy(&request[..end]);
                        let length = headers
                            .lines()
                            .find_map(|l| {
                                l.split_once(':')
                                    .filter(|(key, _)| key.eq_ignore_ascii_case("content-length"))
                                    .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                            })
                            .unwrap();
                        break (end + 4, length);
                    }
                };
                while request.len() < offset + length {
                    let n = stream.read(&mut chunk).await.unwrap();
                    assert!(n > 0);
                    request.extend_from_slice(&chunk[..n]);
                }
                let call = decode_value(&request[offset..offset + length]).unwrap();
                assert_eq!(call.as_array().unwrap()[0].as_str(), Some(method));
                calls.push(call);
                let mut body = Vec::new();
                rmpv::encode::write_value(&mut body, &response).unwrap();
                stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: binary/message-pack\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).as_bytes()).await.unwrap();
                stream.write_all(&body).await.unwrap();
            }
            calls
        });
        (cfg, task)
    }
    pub(crate) fn response(items: &[(&str, Value)]) -> Value {
        Value::Map(
            items
                .iter()
                .map(|(k, v)| (Value::from(*k), v.clone()))
                .collect(),
        )
    }
    fn test_worker(cfg: Config) -> (Worker, mpsc::UnboundedReceiver<Event>) {
        let (ev, rx) = mpsc::unbounded_channel();
        let mut client = Client::new(&cfg).unwrap();
        client.token = Some("test-token".into());
        (
            Worker {
                cfg,
                client: Some(client),
                child: None,
                console_id: Some("0".into()),
                session_reads: HashMap::new(),
                active: None,
                ev,
            },
            rx,
        )
    }
    #[tokio::test]
    async fn delayed_session_output_is_polled_after_the_first_read() {
        let (cfg, server) = mock_rpc(vec![
            (
                "session.shell_write",
                response(&[("write_count", Value::from(5))]),
            ),
            ("session.shell_read", response(&[("data", Value::from(""))])),
            (
                "session.shell_read",
                response(&[("data", Value::from("later output 🦀"))]),
            ),
        ])
        .await;
        let (mut worker, mut events) = test_worker(cfg);
        worker.session_write("7", "echo", false).await.unwrap();
        assert!(events.try_recv().is_err());
        worker.poll_sessions().await;
        assert!(
            matches!(events.try_recv().unwrap(),Event::SessionIo{id,data} if id=="7" && data=="later output 🦀")
        );
        let calls = server.await.unwrap();
        assert_eq!(calls[0].as_array().unwrap()[1].as_str(), Some("test-token"));
        assert_eq!(calls[0].as_array().unwrap()[3].as_str(), Some("echo\n"));
    }
    #[tokio::test]
    async fn console_idle_without_output_is_emitted() {
        let (cfg, server) = mock_rpc(vec![(
            "console.read",
            response(&[("data", Value::from("")), ("busy", Value::from(false))]),
        )])
        .await;
        let (mut worker, mut events) = test_worker(cfg);
        worker.poll_console().await.unwrap();
        assert!(
            matches!(events.try_recv().unwrap(),Event::Console{data,busy:false} if data.is_empty())
        );
        server.await.unwrap();
    }
    #[test]
    fn ipv6_rpc_host_is_bracketed() {
        let cfg = Config {
            host: "::1".into(),
            ..Default::default()
        };
        assert_eq!(Client::new(&cfg).unwrap().url, "http://[::1]:55553/api/");
    }
    #[tokio::test]
    #[ignore = "read-only integration check against installed Metasploit"]
    async fn installed_framework_readonly_rpc() {
        let isolated = tempfile::tempdir().unwrap();
        let socket = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        let cfg = Config {
            port,
            username: "msf".into(),
            password: uuid::Uuid::new_v4().to_string(),
            spawn: false,
            ..Default::default()
        };
        let mut daemon = tokio::process::Command::new("msfrpcd")
            .args([
                "-U",
                &cfg.username,
                "-P",
                &cfg.password,
                "-a",
                "127.0.0.1",
                "-p",
                &port.to_string(),
                "-S",
                "-f",
            ])
            .env("MSF_CFGROOT_CONFIG", isolated.path())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let (ev, mut events) = mpsc::unbounded_channel();
        let mut worker = Worker {
            cfg,
            client: None,
            child: None,
            console_id: None,
            session_reads: HashMap::new(),
            active: None,
            ev,
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if worker.try_login().await.is_ok() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "temporary RPC daemon did not become ready"
            );
            assert!(
                daemon.try_wait().unwrap().is_none(),
                "temporary RPC daemon exited"
            );
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        worker.ensure_console().await.unwrap();
        let snap = worker.snapshot().await.unwrap();
        assert!(
            snap.version.starts_with('6'),
            "unexpected Framework version {}",
            snap.version
        );
        worker.list_modules("auxiliary").await.unwrap();
        let mut found = false;
        while let Ok(event) = events.try_recv() {
            if let Event::ModuleList { names, .. } = event {
                assert!(names.iter().any(|n| n == "scanner/ssh/ssh_version"));
                found = true;
            }
        }
        assert!(found);
        worker
            .fetch_module("auxiliary", "scanner/ssh/ssh_version")
            .await
            .unwrap();
        assert!(
            matches!(events.try_recv().unwrap(),Event::ModuleInfo(info) if info.options.iter().any(|option|option.name=="RHOSTS"))
        );
        worker.poll_console().await.unwrap();
        let catalog = crate::catalog::live(
            worker.client.as_ref().unwrap(),
            &isolated.path().join("catalog.json"),
            true,
            |_, _| {},
        )
        .await
        .unwrap();
        assert!(
            catalog.len() > 1000,
            "live catalog should cover installed modules"
        );
        assert!(catalog.iter().any(|m| m.kind == "exploit"
            && m.fullname == "windows/smb/ms17_010_eternalblue"
            && m.refs.iter().any(|r| r == "CVE-2017-0144")));
        assert!(
            catalog
                .iter()
                .any(|m| m.kind == "auxiliary" && m.fullname == "scanner/ssh/ssh_version")
        );
        worker.shutdown().await;
        daemon.kill().await.unwrap();
        daemon.wait().await.unwrap();
    }
    #[tokio::test]
    async fn workspace_fetch_reads_more_than_one_page() {
        let page = (0..100)
            .map(|i| response(&[("address", Value::from(format!("192.0.2.{i}")))]))
            .collect::<Vec<_>>();
        let (cfg, server) = mock_rpc(vec![
            ("db.hosts", response(&[("hosts", Value::Array(page))])),
            (
                "db.hosts",
                response(&[(
                    "hosts",
                    Value::Array(vec![response(&[("address", Value::from("192.0.2.100"))])]),
                )]),
            ),
        ])
        .await;
        let (worker, _) = test_worker(cfg);
        let result = worker
            .client
            .as_ref()
            .unwrap()
            .workspace_rows("db.hosts", "audit")
            .await
            .unwrap();
        assert_eq!(parse_hosts(&result).len(), 101);
        let calls = server.await.unwrap();
        let options = as_map(&calls[1].as_array().unwrap()[2]).unwrap();
        assert_eq!(map_u32(&options, "offset"), 100);
        assert_eq!(map_str(&options, "workspace").as_deref(), Some("audit"));
    }
}
