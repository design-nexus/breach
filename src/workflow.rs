//! Ordered Framework workflows. Consequential actions enter only after UI confirmation.
use crate::{
    catalog,
    chains::{Chain, Step},
    macros::Macro,
    match_plan,
    model::*,
    persist::AuditEntry,
    rpc::{Client, Event, as_map, map_bool, map_str, parse_options},
};
use anyhow::{Context, Result, bail, ensure};
use rmpv::Value;
use std::{collections::HashMap, path::PathBuf, time::Duration};
use tokio::sync::{mpsc, watch};

#[derive(Clone, Debug)]
pub struct ModuleRun {
    pub kind: String,
    pub name: String,
    pub options: HashMap<String, String>,
    pub check: bool,
}

#[derive(Clone, Debug)]
pub enum Operation {
    Discover {
        targets: String,
        ports: String,
    },
    Import(String),
    Plan {
        min_rank: Rank,
        match_vulns: bool,
        match_ports: bool,
        execute: bool,
        validate: bool,
    },
    Modules(Vec<ModuleRun>),
    Evidence {
        name: String,
        session: Option<String>,
    },
    Report(Vec<String>),
}

#[derive(Clone, Debug)]
pub struct Request {
    pub id: String,
    pub steps: Vec<Operation>,
    pub continue_on_failure: bool,
    pub workspace: String,
    pub macros: Vec<Macro>,
    pub cache: PathBuf,
    pub reports: PathBuf,
    pub audit: Vec<AuditEntry>,
    pub tasks: Vec<TaskLog>,
    pub validations: Vec<ValidationResult>,
    pub redact: bool,
    pub local: bool,
    pub listener: HashMap<String, String>,
}

pub fn chain_steps(chain: &Chain) -> Result<Vec<Operation>> {
    ensure!(
        ["stop", "continue"].contains(&chain.on_fail.as_str()),
        "on_fail must be stop or continue"
    );
    ensure!(!chain.steps.is_empty(), "chain has no steps");
    chain
        .steps
        .iter()
        .map(|step| {
            Ok(match step {
                Step::Discover { rhosts, ports } => Operation::Discover {
                    targets: rhosts.clone(),
                    ports: ports.clone(),
                },
                Step::Import { path } => Operation::Import(path.clone()),
                Step::AutoExploit {
                    min_rank,
                    match_vulns,
                    match_ports,
                } => Operation::Plan {
                    min_rank: Rank::parse(min_rank).context("invalid minimum rank")?,
                    match_vulns: *match_vulns,
                    match_ports: *match_ports,
                    execute: true,
                    validate: false,
                },
                Step::CollectEvidence { r#macro } => Operation::Evidence {
                    name: r#macro.clone(),
                    session: None,
                },
                Step::Report { formats } => {
                    crate::reports::validate_formats(formats)?;
                    Operation::Report(formats.clone())
                }
                Step::Module {
                    kind,
                    name,
                    options,
                } => Operation::Modules(vec![ModuleRun {
                    kind: kind.clone(),
                    name: name.clone(),
                    options: options.clone(),
                    check: false,
                }]),
                Step::Validate { min_rank } => Operation::Plan {
                    min_rank: Rank::parse(min_rank).context("invalid minimum rank")?,
                    match_vulns: true,
                    match_ports: false,
                    execute: false,
                    validate: true,
                },
            })
        })
        .collect()
}

pub struct Runner {
    client: Client,
    ev: mpsc::UnboundedSender<Event>,
    cancel: watch::Receiver<bool>,
    request: Request,
    log: String,
    poll: Duration,
    timeout: Duration,
    step_number: usize,
}

impl Runner {
    pub fn new(
        client: Client,
        ev: mpsc::UnboundedSender<Event>,
        cancel: watch::Receiver<bool>,
        request: Request,
    ) -> Self {
        Self {
            client,
            ev,
            cancel,
            request,
            log: String::new(),
            poll: Duration::from_millis(250),
            timeout: Duration::from_secs(900),
            step_number: 0,
        }
    }
    fn emit(&self, event: Event) {
        let _ = self.ev.send(event);
    }
    fn progress(&mut self, detail: impl AsRef<str>) {
        self.log.push_str(detail.as_ref());
        self.log.push('\n');
        self.emit(Event::TaskUpdate {
            id: self.request.id.clone(),
            status: "running".into(),
            detail: self.log.clone(),
        });
    }
    fn cancelled(&self) -> bool {
        *self.cancel.borrow()
    }
    async fn pause(&mut self) -> Result<()> {
        ensure!(!self.cancelled(), "workflow cancelled");
        tokio::select! {
            _=tokio::time::sleep(self.poll)=>Ok(()),
            _=self.cancel.changed()=>{ensure!(!self.cancelled(), "workflow cancelled");Ok(())}
        }
    }
    #[cfg(test)]
    fn test_timings(&mut self) {
        self.poll = Duration::from_millis(1);
        self.timeout = Duration::from_secs(2);
    }

    pub async fn run(mut self) {
        let result = self.run_steps().await;
        let status = match &result {
            Ok(true) => "complete",
            Ok(false) => "partial",
            Err(_) if self.cancelled() => "cancelled",
            Err(_) => "failed",
        };
        if let Err(error) = result {
            self.log.push_str(&format!("{error:#}\n"));
        }
        self.emit(Event::TaskUpdate {
            id: self.request.id.clone(),
            status: status.into(),
            detail: self.log.clone(),
        });
        self.emit(Event::WorkflowFinished(self.request.id.clone()));
    }
    async fn run_steps(&mut self) -> Result<bool> {
        let mut success = true;
        for (i, step) in self.request.steps.clone().into_iter().enumerate() {
            ensure!(!self.cancelled(), "workflow cancelled");
            self.step_number = i + 1;
            self.progress(format!(
                "Step {}/{}: {}",
                i + 1,
                self.request.steps.len(),
                label(&step)
            ));
            let result = self.step(step).await;
            match result {
                Ok(()) => self.progress("Step complete"),
                Err(error) => {
                    self.progress(format!("Step failed: {error:#}"));
                    success = false;
                    if self.cancelled() || !self.request.continue_on_failure {
                        return Err(error);
                    }
                }
            }
        }
        Ok(success)
    }
    async fn snapshot(&self) -> Result<Snapshot> {
        self.snapshot_for(true).await
    }
    async fn snapshot_for(&self, require_database: bool) -> Result<Snapshot> {
        let snap = if require_database {
            self.client.strict_snapshot().await?
        } else {
            self.client.snapshot().await?
        };
        ensure!(
            snap.workspace == self.request.workspace,
            "workspace changed during workflow (expected {}, got {})",
            self.request.workspace,
            snap.workspace
        );
        self.emit(Event::Snapshot(snap.clone()));
        Ok(snap)
    }
    async fn step(&mut self, step: Operation) -> Result<()> {
        match step {
            Operation::Discover { targets, ports } => {
                self.snapshot().await?;
                self.discover(&targets, &ports).await?;
                self.snapshot().await?;
            }
            Operation::Import(path) => {
                self.snapshot().await?;
                let data = tokio::fs::read_to_string(&path)
                    .await
                    .with_context(|| format!("read import {path}"))?;
                let response = self
                    .client
                    .call(
                        "db.import_data",
                        &[Value::Map(vec![
                            ("data".into(), data.into()),
                            ("workspace".into(), self.request.workspace.clone().into()),
                        ])],
                    )
                    .await?;
                ensure_rpc_success(&response)?;
                self.snapshot().await?;
            }
            Operation::Plan {
                min_rank,
                match_vulns,
                match_ports,
                execute,
                validate,
            } => {
                let snap = self.snapshot().await?;
                let ev = self.ev.clone();
                let id = self.request.id.clone();
                let load = catalog::live(
                    &self.client,
                    &self.request.cache,
                    self.request.local,
                    |loaded, total| {
                        if loaded % 25 == 0 || loaded == total {
                            let _ = ev.send(Event::TaskUpdate {
                                id: id.clone(),
                                status: "running".into(),
                                detail: format!("Loading Framework metadata: {loaded}/{total}"),
                            });
                        }
                    },
                );
                let metadata = tokio::select! {
                    value=load=>value?,
                    _=self.cancel.changed()=>bail!("workflow cancelled"),
                };
                let plan = match_plan::build_plan_with_policy(
                    &snap.hosts,
                    &metadata,
                    min_rank,
                    match_vulns,
                    match_ports,
                );
                self.progress(format!(
                    "Matched {} items from {} installed modules",
                    plan.len(),
                    metadata.len()
                ));
                self.emit(Event::PlanReady(plan.clone()));
                if execute || validate {
                    let items = plan
                        .into_iter()
                        .filter(|p| validate || p.selected)
                        .map(|p| {
                            let mut options = if validate {
                                HashMap::new()
                            } else {
                                self.request.listener.clone()
                            };
                            options.insert("RHOSTS".into(), p.host);
                            if let Some(port) = p.rport {
                                options.insert("RPORT".into(), port.to_string());
                            }
                            ModuleRun {
                                kind: p.kind,
                                name: p.module,
                                options,
                                check: validate,
                            }
                        })
                        .collect::<Vec<_>>();
                    ensure!(!items.is_empty(), "no modules matched the workflow filters");
                    self.modules(items, validate).await?;
                    self.snapshot().await?;
                }
            }
            Operation::Modules(items) => {
                self.snapshot_for(false).await?;
                let validation = items.iter().all(|i| i.check);
                self.modules(items, validation).await?;
                self.snapshot_for(false).await?;
            }
            Operation::Evidence { name, session } => {
                let mac = self
                    .request
                    .macros
                    .iter()
                    .find(|m| m.name == name)
                    .cloned()
                    .with_context(|| format!("evidence macro not found: {name}"))?;
                let snap = self.snapshot_for(false).await?;
                let sessions = snap
                    .sessions
                    .iter()
                    .filter(|s| session.as_ref().is_none_or(|id| id == &s.id))
                    .filter(|s| platform_matches(&mac.platform, &s.platform))
                    .cloned()
                    .collect::<Vec<_>>();
                ensure!(
                    !sessions.is_empty(),
                    "no compatible session for macro {name} (platform {})",
                    mac.platform
                );
                ensure!(!mac.steps.is_empty(), "macro {name} has no steps");
                for session in sessions {
                    self.progress(format!(
                        "Evidence on session {} ({})",
                        session.id, session.platform
                    ));
                    let items = mac
                        .steps
                        .iter()
                        .map(|s| {
                            let mut options = s.options.clone();
                            options.insert("SESSION".into(), session.id.clone());
                            ModuleRun {
                                kind: "post".into(),
                                name: s.module.trim_start_matches("post/").into(),
                                options,
                                check: false,
                            }
                        })
                        .collect();
                    self.modules(items, false).await?;
                }
                self.snapshot_for(false).await?;
            }
            Operation::Report(formats) => {
                let snap = self.snapshot_for(false).await?;
                let mut tasks = self.request.tasks.clone();
                if let Some(task) = tasks.iter_mut().find(|t| t.id == self.request.id) {
                    task.detail = self.log.clone();
                    if self.step_number == self.request.steps.len() {
                        task.status = if self.log.contains("Step failed:") {
                            "partial"
                        } else {
                            "complete"
                        }
                        .into();
                    }
                }
                let files = crate::reports::render_full(
                    &self.request.reports,
                    &snap,
                    &self.request.audit,
                    &tasks,
                    &self.request.validations,
                    self.request.redact,
                    &formats,
                )?;
                self.progress(format!("Report: {}", files.dir.display()));
                self.emit(Event::ReportReady(files.dir));
            }
        }
        Ok(())
    }
    async fn modules(&mut self, items: Vec<ModuleRun>, validation: bool) -> Result<()> {
        ensure!(!items.is_empty(), "no module operations supplied");
        let mut errors = Vec::new();
        for item in items {
            ensure!(!self.cancelled(), "workflow cancelled");
            self.progress(format!(
                "{} {}/{} {}",
                if item.check { "Check" } else { "Execute" },
                item.kind,
                item.name,
                item.options
                    .get("RHOSTS")
                    .or_else(|| item.options.get("SESSION"))
                    .cloned()
                    .unwrap_or_default()
            ));
            let outcome = self.module(&item).await;
            if item.check {
                let host = item.options.get("RHOSTS").cloned().unwrap_or_default();
                let mut result = match &outcome {
                    Ok(value) => validation_result(host, &item.name, value),
                    Err(error) => ValidationResult {
                        workspace: String::new(),
                        checked_at: String::new(),
                        host,
                        module: item.name.clone(),
                        code: if error.to_string().contains("does not support check") {
                            "unsupported"
                        } else {
                            "error"
                        }
                        .into(),
                        message: format!("{error:#}"),
                        details: serde_json::Value::Null,
                    },
                };
                result.workspace = self.request.workspace.clone();
                result.checked_at = chrono::Utc::now().to_rfc3339();
                self.progress(format!("Validation: {} — {}", result.code, result.message));
                self.request.validations.push(result.clone());
                self.emit(Event::Validation(result));
            }
            if let Err(error) = outcome {
                if self.cancelled() {
                    return Err(error);
                }
                if !validation {
                    return Err(error);
                }
                // Unsupported checks are reported, never mistaken for negative findings.
                if !error.to_string().contains("does not support check") {
                    errors.push(format!("{error:#}"));
                }
            }
        }
        ensure!(
            errors.is_empty(),
            "validation errors: {}",
            errors.join("; ")
        );
        Ok(())
    }
    async fn module(&mut self, item: &ModuleRun) -> Result<Value> {
        let info = self
            .client
            .call(
                "module.info",
                &[item.kind.clone().into(), item.name.clone().into()],
            )
            .await?;
        let map = as_map(&info).context("module.info response")?;
        if item.check {
            ensure!(
                map_bool(&map, "check"),
                "module {}/{} does not support check",
                item.kind,
                item.name
            );
        }
        let options = map
            .iter()
            .find(|(k, _)| k == "options")
            .map(|(_, v)| parse_options(v))
            .unwrap_or_default();
        let mut supplied = item.options.clone();
        if options.iter().any(|o| o.name == "RHOST") && !supplied.contains_key("RHOST") {
            if let Some(host) = supplied.get("RHOSTS").cloned() {
                supplied.insert("RHOST".into(), host);
            }
        }
        for option in options.iter().filter(|o| o.required) {
            ensure!(
                supplied
                    .get(&option.name)
                    .is_some_and(|v| !v.trim().is_empty())
                    || !option.default.is_empty(),
                "missing required module option {} for {}/{}",
                option.name,
                item.kind,
                item.name
            );
        }
        let opts = Value::Map(
            supplied
                .iter()
                .map(|(k, v)| (k.clone().into(), v.clone().into()))
                .collect(),
        );
        ensure!(!self.cancelled(), "workflow cancelled");
        let result = self
            .client
            .call(
                if item.check {
                    "module.check"
                } else {
                    "module.execute"
                },
                &[item.kind.clone().into(), item.name.clone().into(), opts],
            )
            .await?;
        ensure_rpc_success(&result)?;
        let map = as_map(&result).context("module run response")?;
        // Payload/encoder execution returns bytes synchronously; do not mislabel it as a job.
        if let Some(data) = map
            .iter()
            .find(|(k, _)| k == "payload" || k == "encoded")
            .map(|(_, v)| v)
        {
            self.progress(format!(
                "Synchronous result ({} bytes)",
                crate::rpc::value_string(data).map_or(0, |s| s.len())
            ));
            return Ok(result);
        }
        let uuid = map_str(&map, "uuid").context("module run returned no tracking UUID")?;
        let job = map_str(&map, "job_id");
        self.progress(format!(
            "UUID={uuid} job={}",
            job.as_deref().unwrap_or("none")
        ));
        let deadline = tokio::time::Instant::now() + self.timeout;
        let outcome = loop {
            if self.cancelled() {
                break Err(anyhow::anyhow!("workflow cancelled"));
            }
            if tokio::time::Instant::now() >= deadline {
                break Err(anyhow::anyhow!(
                    "module timed out after {} seconds",
                    self.timeout.as_secs()
                ));
            }
            let args = [uuid.clone().into()];
            let reply = tokio::select! {
                reply=self.client.call("module.results",&args)=>reply,
                _=self.cancel.changed()=>break Err(anyhow::anyhow!("workflow cancelled")),
            };
            match reply {
                Err(error) => break Err(error),
                Ok(reply) => {
                    let Some(m) = as_map(&reply) else {
                        break Err(anyhow::anyhow!("invalid module results response"));
                    };
                    match map_str(&m, "status").as_deref() {
                        Some("completed") => {
                            break Ok(m
                                .iter()
                                .find(|(k, _)| k == "result")
                                .map(|(_, v)| v.clone())
                                .unwrap_or(Value::Nil));
                        }
                        Some("errored") => {
                            break Err(anyhow::anyhow!(
                                "module failed: {}",
                                map_str(&m, "error").unwrap_or_else(|| format!("{reply:?}"))
                            ));
                        }
                        Some("running" | "ready") => {}
                        other => {
                            break Err(anyhow::anyhow!("unknown module result status {other:?}"));
                        }
                    }
                }
            }
            if let Err(error) = self.pause().await {
                break Err(error);
            }
        };
        if outcome.is_err() {
            if let Some(job) = job {
                match tokio::time::timeout(
                    Duration::from_secs(3),
                    self.client.call("job.stop", &[job.clone().into()]),
                )
                .await
                {
                    Ok(Ok(value)) if ensure_rpc_success(&value).is_ok() => {}
                    result => self.progress(format!(
                        "Could not confirm stop of job {job}: {result:?}. Inspect Framework jobs."
                    )),
                }
            }
        }
        let _ = self.client.call("module.ack", &[uuid.into()]).await;
        outcome
    }
    async fn discover(&mut self, targets: &str, ports: &str) -> Result<()> {
        let command = discovery_command(targets, ports)?;
        let reply = self.client.call("console.create", &[]).await?;
        let id = as_map(&reply)
            .and_then(|m| map_str(&m, "id"))
            .context("discovery console id")?;
        let result = self.discover_console(&id, &command).await;
        let cleanup = self.client.call("console.destroy", &[id.into()]).await;
        result?;
        cleanup?;
        Ok(())
    }
    async fn discover_console(&mut self, id: &str, command: &str) -> Result<()> {
        ensure!(!self.cancelled(), "workflow cancelled");
        let reply = self
            .client
            .call("console.write", &[id.into(), command.into()])
            .await?;
        ensure_rpc_success(&reply)?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(1800);
        let mut started = false;
        let mut idle = 0;
        let mut output = String::new();
        loop {
            self.pause().await?;
            ensure!(
                tokio::time::Instant::now() < deadline,
                "discovery timed out"
            );
            let reply = self.client.call("console.read", &[id.into()]).await?;
            let m = as_map(&reply).context("discovery console response")?;
            let data = map_str(&m, "data").unwrap_or_default();
            let busy = map_bool(&m, "busy");
            started |= busy
                || data.contains("Nmap done:")
                || data
                    .lines()
                    .any(|line| line.trim_start().starts_with("[-]"));
            output.push_str(&data);
            if !data.is_empty() {
                self.emit(Event::Console { data, busy: false });
            }
            if started && !busy {
                idle += 1
            } else {
                idle = 0
            }
            if idle >= 2 {
                break;
            }
        }
        ensure!(
            !output
                .lines()
                .any(|line| line.trim_start().starts_with("[-]")),
            "discovery reported an error: {}",
            output
        );
        ensure!(
            output.contains("Nmap done:"),
            "discovery produced no Nmap completion output: {}",
            output
        );
        self.progress("Discovery finished; refreshing workspace");
        Ok(())
    }
}

fn ensure_rpc_success(value: &Value) -> Result<()> {
    if let Some(map) = as_map(value) {
        ensure!(
            map_str(&map, "result").as_deref() != Some("failure") && !map_bool(&map, "error"),
            "RPC operation failed: {value:?}"
        );
    }
    Ok(())
}
fn label(op: &Operation) -> String {
    match op {
        Operation::Discover { targets, ports } => format!("discover {targets} ports={ports}"),
        Operation::Import(p) => format!("import {p}"),
        Operation::Plan {
            execute, validate, ..
        } => if *validate {
            "validate vulnerabilities"
        } else if *execute {
            "execute matching plan"
        } else {
            "build review plan"
        }
        .into(),
        Operation::Modules(items) => format!("{} module operations", items.len()),
        Operation::Evidence { name, .. } => format!("evidence {name}"),
        Operation::Report(f) => format!("report {}", f.join(",")),
    }
}
pub fn discovery_command(targets: &str, ports: &str) -> Result<String> {
    ensure!(!targets.trim().is_empty(), "discovery requires targets");
    ensure!(
        targets
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ".:/-, ".contains(c))
            && !targets.split_whitespace().any(|t| t.starts_with('-')),
        "invalid discovery targets"
    );
    ensure!(
        ports
            .chars()
            .all(|c| c.is_ascii_digit() || ",:-TU ".contains(c)),
        "invalid port list"
    );
    Ok(if ports.trim().is_empty() {
        format!("db_nmap -sV {targets}\n")
    } else {
        format!("db_nmap -sV -p {} {targets}\n", ports.replace(' ', ""))
    })
}
pub fn platform_matches(required: &str, actual: &str) -> bool {
    let required = required.trim().to_ascii_lowercase();
    let actual = actual.to_ascii_lowercase();
    required.is_empty()
        || required == "multi"
        || required.split(',').any(|p| match p.trim() {
            "windows" => actual.contains("win"),
            "linux" => actual.contains("linux"),
            "osx" | "macos" => {
                actual.contains("osx") || actual.contains("darwin") || actual.contains("mac")
            }
            p => p == actual,
        })
}
fn value_json(value: &Value) -> serde_json::Value {
    match value {
        Value::Nil => serde_json::Value::Null,
        Value::Boolean(b) => (*b).into(),
        Value::Array(a) => serde_json::Value::Array(a.iter().map(value_json).collect()),
        Value::Map(m) => serde_json::Value::Object(
            m.iter()
                .filter_map(|(k, v)| crate::rpc::value_string(k).map(|k| (k, value_json(v))))
                .collect(),
        ),
        Value::Integer(i) => i
            .as_i64()
            .map(serde_json::Value::from)
            .or_else(|| i.as_u64().map(serde_json::Value::from))
            .unwrap_or_default(),
        Value::F32(n) => serde_json::json!(n),
        Value::F64(n) => serde_json::json!(n),
        _ => crate::rpc::value_string(value).unwrap_or_default().into(),
    }
}
fn validation_result(host: String, module: &str, value: &Value) -> ValidationResult {
    let m = as_map(value).unwrap_or_default();
    ValidationResult {
        workspace: String::new(),
        checked_at: String::new(),
        host,
        module: module.into(),
        code: map_str(&m, "code").unwrap_or_else(|| "unknown".into()),
        message: map_str(&m, "message")
            .unwrap_or_else(|| "Framework returned no check code".into()),
        details: value_json(value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::tests::{mock_rpc, response};
    fn snap(hosts: Vec<Value>, vulns: Vec<Value>, sessions: Value) -> Vec<(&'static str, Value)> {
        vec![
            ("core.version", response(&[("version", "test-6".into())])),
            (
                "db.status",
                response(&[("driver", "postgresql".into()), ("db", "lab".into())]),
            ),
            ("core.module_stats", response(&[])),
            (
                "db.current_workspace",
                response(&[("workspace", "lab".into())]),
            ),
            (
                "db.workspaces",
                response(&[("workspaces", Value::Array(vec!["lab".into()]))]),
            ),
            ("db.hosts", response(&[("hosts", Value::Array(hosts))])),
            (
                "db.services",
                response(&[("services", Value::Array(vec![]))]),
            ),
            ("db.vulns", response(&[("vulns", Value::Array(vulns))])),
            ("db.notes", response(&[("notes", Value::Array(vec![]))])),
            ("db.creds", response(&[("creds", Value::Array(vec![]))])),
            ("db.loots", response(&[("loots", Value::Array(vec![]))])),
            ("session.list", sessions),
            ("job.list", response(&[])),
        ]
    }
    fn empty_snap() -> Vec<(&'static str, Value)> {
        snap(vec![], vec![], response(&[]))
    }
    fn info(check: bool) -> Value {
        response(&[
            ("check", check.into()),
            (
                "options",
                response(&[("RHOSTS", response(&[("required", true.into())]))]),
            ),
        ])
    }
    fn item(name: &str, check: bool) -> ModuleRun {
        ModuleRun {
            kind: "exploit".into(),
            name: name.into(),
            options: HashMap::from([("RHOSTS".into(), "192.0.2.1".into())]),
            check,
        }
    }
    fn run_replies(check: bool, name: &str) -> Vec<(&'static str, Value)> {
        vec![
            ("module.info", info(true)),
            (
                if check {
                    "module.check"
                } else {
                    "module.execute"
                },
                response(&[("job_id", 7.into()), ("uuid", name.into())]),
            ),
            ("module.results", response(&[("status", "running".into())])),
            (
                "module.results",
                response(&[
                    ("status", "completed".into()),
                    (
                        "result",
                        if check {
                            response(&[
                                ("code", "vulnerable".into()),
                                ("message", "Mock finding".into()),
                            ])
                        } else {
                            Value::Nil
                        },
                    ),
                ]),
            ),
            ("module.ack", response(&[("success", true.into())])),
        ]
    }
    fn request(dir: &std::path::Path, steps: Vec<Operation>) -> Request {
        Request {
            id: "task-1".into(),
            steps,
            continue_on_failure: false,
            workspace: "lab".into(),
            macros: vec![],
            cache: dir.join("catalog.json"),
            reports: dir.join("reports"),
            audit: vec![],
            tasks: vec![],
            validations: vec![],
            redact: true,
            local: false,
            listener: HashMap::new(),
        }
    }
    async fn execute(
        replies: Vec<(&'static str, Value)>,
        request: Request,
    ) -> (Vec<Event>, Vec<Value>) {
        let (cfg, server) = mock_rpc(replies).await;
        let mut client = Client::new(&cfg).unwrap();
        client.token = Some("test-token".into());
        let (ev, mut rx) = mpsc::unbounded_channel();
        let (_tx, cancel) = watch::channel(false);
        let mut runner = Runner::new(client, ev, cancel, request);
        runner.test_timings();
        runner.run().await;
        let mut events = vec![];
        while let Ok(event) = rx.try_recv() {
            events.push(event)
        }
        (events, server.await.unwrap())
    }
    fn status(events: &[Event]) -> &str {
        events
            .iter()
            .rev()
            .find_map(|e| {
                if let Event::TaskUpdate { status, .. } = e {
                    Some(status.as_str())
                } else {
                    None
                }
            })
            .unwrap()
    }
    #[tokio::test]
    async fn modules_wait_for_results_before_next_module_and_refresh() {
        let dir = tempfile::tempdir().unwrap();
        let mut replies = empty_snap();
        replies.extend(run_replies(false, "one"));
        replies.extend(run_replies(false, "two"));
        replies.extend(empty_snap());
        let (events, calls) = execute(
            replies,
            request(
                dir.path(),
                vec![Operation::Modules(vec![
                    item("one", false),
                    item("two", false),
                ])],
            ),
        )
        .await;
        assert_eq!(status(&events), "complete");
        assert!(matches!(events.last(),Some(Event::WorkflowFinished(id)) if id=="task-1"));
        assert_eq!(
            calls[17].as_array().unwrap()[0].as_str(),
            Some("module.ack")
        );
        assert_eq!(
            calls[18].as_array().unwrap()[0].as_str(),
            Some("module.info")
        );
    }
    #[tokio::test]
    async fn checks_report_unsupported_then_supported_without_executing() {
        let dir = tempfile::tempdir().unwrap();
        let mut replies = empty_snap();
        replies.push(("module.info", info(false)));
        replies.extend(run_replies(true, "supported"));
        replies.extend(empty_snap());
        let (events, calls) = execute(
            replies,
            request(
                dir.path(),
                vec![Operation::Modules(vec![
                    item("unsupported", true),
                    item("supported", true),
                ])],
            ),
        )
        .await;
        assert_eq!(status(&events), "complete");
        let results = events
            .iter()
            .filter_map(|e| {
                if let Event::Validation(v) = e {
                    Some(v)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].code, "unsupported");
        assert_eq!(results[1].code, "vulnerable");
        assert_eq!(results[1].workspace, "lab");
        assert!(
            calls
                .iter()
                .all(|c| c.as_array().unwrap()[0].as_str() != Some("module.execute"))
        );
    }
    #[tokio::test]
    async fn failure_policy_stops_or_continues_and_marks_partial() {
        for continuation in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mut replies = empty_snap();
            replies.push(("module.info", info(true)));
            let mut missing = item("missing", false);
            missing.options.clear();
            if continuation {
                replies.extend(empty_snap());
            }
            let mut request = request(
                dir.path(),
                vec![
                    Operation::Modules(vec![missing]),
                    Operation::Report(vec!["json".into()]),
                ],
            );
            request.continue_on_failure = continuation;
            let (events, _) = execute(replies, request).await;
            assert_eq!(
                status(&events),
                if continuation { "partial" } else { "failed" }
            );
            assert_eq!(
                events.iter().any(|e| matches!(e, Event::ReportReady(_))),
                continuation
            );
        }
    }
    #[tokio::test]
    async fn cancellation_stops_current_job_and_acknowledges_result() {
        let dir = tempfile::tempdir().unwrap();
        let (cfg, server) = mock_rpc(vec![
            ("module.info", info(true)),
            (
                "module.execute",
                response(&[("job_id", 7.into()), ("uuid", "cancel-me".into())]),
            ),
            ("module.results", response(&[("status", "running".into())])),
            ("job.stop", response(&[("result", "success".into())])),
            ("module.ack", response(&[("success", true.into())])),
        ])
        .await;
        let client = Client::new(&cfg).unwrap();
        let (ev, _) = mpsc::unbounded_channel();
        let (tx, cancel) = watch::channel(false);
        let mut runner = Runner::new(client, ev, cancel, request(dir.path(), vec![]));
        runner.poll = Duration::from_secs(1);
        let task = tokio::spawn(async move { runner.module(&item("one", false)).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        tx.send(true).unwrap();
        assert!(
            task.await
                .unwrap()
                .unwrap_err()
                .to_string()
                .contains("cancelled")
        );
        let calls = server.await.unwrap();
        assert_eq!(calls[3].as_array().unwrap()[1].as_str(), Some("7"));
    }
    #[tokio::test]
    async fn discovery_uses_private_console_waits_and_destroys_it() {
        let dir = tempfile::tempdir().unwrap();
        let (cfg, server) = mock_rpc(vec![
            ("console.create", response(&[("id", "private".into())])),
            ("console.write", response(&[("wrote", 20.into())])),
            (
                "console.read",
                response(&[("busy", true.into()), ("data", "Starting Nmap".into())]),
            ),
            (
                "console.read",
                response(&[
                    ("busy", false.into()),
                    ("data", "Nmap done: 1 IP address".into()),
                ]),
            ),
            (
                "console.read",
                response(&[("busy", false.into()), ("data", "".into())]),
            ),
            ("console.destroy", response(&[("result", "success".into())])),
        ])
        .await;
        let client = Client::new(&cfg).unwrap();
        let (ev, _) = mpsc::unbounded_channel();
        let (_tx, cancel) = watch::channel(false);
        let mut runner = Runner::new(client, ev, cancel, request(dir.path(), vec![]));
        runner.test_timings();
        runner.discover("192.0.2.1", "22,80").await.unwrap();
        let calls = server.await.unwrap();
        assert_eq!(calls[1].as_array().unwrap()[1].as_str(), Some("private"));
        assert_eq!(
            calls[1].as_array().unwrap()[2].as_str(),
            Some("db_nmap -sV -p 22,80 192.0.2.1\n")
        );
    }
    #[tokio::test]
    async fn import_refreshes_hosts_before_live_matching_and_validation() {
        let dir = tempfile::tempdir().unwrap();
        let import = dir.path().join("scan.xml");
        std::fs::write(&import, "<nmaprun/>").unwrap();
        let populated = || {
            snap(
                vec![response(&[
                    ("address", "192.0.2.4".into()),
                    ("os_name", "Linux".into()),
                ])],
                vec![response(&[
                    ("host", "192.0.2.4".into()),
                    ("name", "fixture".into()),
                    ("refs", "CVE-2026-1234".into()),
                ])],
                response(&[]),
            )
        };
        let mut replies = empty_snap();
        replies.push(("db.import_data", response(&[("result", "success".into())])));
        replies.extend(populated());
        replies.extend(populated());
        replies.push(("core.version", response(&[("version", "test-6".into())])));
        replies.push((
            "module.search",
            Value::Array(vec![response(&[
                ("type", "exploit".into()),
                ("fullname", "exploit/linux/http/fixture".into()),
                ("rank", "great".into()),
            ])]),
        ));
        let meta = response(&[
            ("name", "Fixture".into()),
            ("rank", "great".into()),
            ("platform", Value::Array(vec!["linux".into()])),
            (
                "references",
                Value::Array(vec![Value::Array(vec!["CVE".into(), "2026-1234".into()])]),
            ),
            ("options", response(&[])),
        ]);
        replies.push(("module.info", meta));
        replies.extend(run_replies(true, "checked"));
        replies.extend(populated());
        replies.extend(populated());
        let (events, calls) = execute(
            replies,
            request(
                dir.path(),
                vec![
                    Operation::Import(import.display().to_string()),
                    Operation::Plan {
                        min_rank: Rank::Great,
                        match_vulns: true,
                        match_ports: false,
                        execute: false,
                        validate: true,
                    },
                    Operation::Report(vec!["json".into()]),
                ],
            ),
        )
        .await;
        assert_eq!(status(&events), "complete");
        assert!(events.iter().any(
            |e| matches!(e,Event::Validation(v) if v.host=="192.0.2.4" && v.code=="vulnerable")
        ));
        let path = events
            .iter()
            .find_map(|e| {
                if let Event::ReportReady(p) = e {
                    Some(p)
                } else {
                    None
                }
            })
            .unwrap();
        let report: serde_json::Value =
            serde_json::from_slice(&std::fs::read(path.join("report.json")).unwrap()).unwrap();
        assert_eq!(report["snapshot"]["hosts"][0]["address"], "192.0.2.4");
        assert_eq!(report["validations"][0]["code"], "vulnerable");
        assert!(!path.join("report.html").exists());
        assert!(
            calls
                .iter()
                .all(|c| c.as_array().unwrap()[0].as_str() != Some("module.execute"))
        );
    }
    #[test]
    fn chain_settings_and_input_guards_are_enforced() {
        let chain = Chain {
            name: "audit".into(),
            on_fail: "stop".into(),
            steps: vec![
                Step::AutoExploit {
                    min_rank: "great".into(),
                    match_vulns: false,
                    match_ports: true,
                },
                Step::Validate {
                    min_rank: "good".into(),
                },
                Step::Report {
                    formats: vec!["json".into()],
                },
            ],
        };
        let ops = chain_steps(&chain).unwrap();
        assert!(matches!(
            ops[0],
            Operation::Plan {
                match_vulns: false,
                match_ports: true,
                execute: true,
                ..
            }
        ));
        assert!(matches!(
            ops[1],
            Operation::Plan {
                validate: true,
                execute: false,
                ..
            }
        ));
        let mut invalid = chain;
        invalid.on_fail = "ignore".into();
        assert!(chain_steps(&invalid).is_err());
        assert!(discovery_command("192.0.2.1\nexit", "").is_err());
        assert!(discovery_command("--script file", "").is_err());
        assert!(discovery_command("192.0.2.1", "80;exit").is_err());
        assert!(platform_matches("windows", "Windows"));
        assert!(!platform_matches("windows", "linux"));
        assert!(!platform_matches("linux", ""));
    }
    #[tokio::test]
    async fn evidence_skips_incompatible_sessions_and_waits_for_each_step() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = response(&[
            (
                "1",
                response(&[("type", "meterpreter".into()), ("platform", "linux".into())]),
            ),
            (
                "2",
                response(&[
                    ("type", "meterpreter".into()),
                    ("platform", "windows".into()),
                ]),
            ),
        ]);
        let mut replies = snap(vec![], vec![], sessions.clone());
        for name in ["one", "two"] {
            let mut module = run_replies(false, name);
            module[0].1 = response(&[(
                "options",
                response(&[("SESSION", response(&[("required", true.into())]))]),
            )]);
            replies.extend(module);
        }
        replies.extend(snap(vec![], vec![], sessions));
        let mut req = request(
            dir.path(),
            vec![Operation::Evidence {
                name: "linux".into(),
                session: None,
            }],
        );
        req.macros = vec![Macro {
            name: "linux".into(),
            platform: "linux".into(),
            steps: vec![
                crate::macros::MacroStep {
                    module: "post/linux/one".into(),
                    options: HashMap::new(),
                },
                crate::macros::MacroStep {
                    module: "post/linux/two".into(),
                    options: HashMap::new(),
                },
            ],
        }];
        let (events, calls) = execute(replies, req).await;
        assert_eq!(status(&events), "complete");
        let executions = calls
            .iter()
            .filter(|c| c.as_array().unwrap()[0].as_str() == Some("module.execute"))
            .collect::<Vec<_>>();
        assert_eq!(executions.len(), 2);
        for execution in executions {
            let options = as_map(&execution.as_array().unwrap()[4]).unwrap();
            assert_eq!(map_str(&options, "SESSION").as_deref(), Some("1"));
        }
    }
    #[tokio::test]
    async fn module_timeout_stops_job_and_records_failure() {
        let dir = tempfile::tempdir().unwrap();
        let (cfg, server) = mock_rpc(vec![
            ("module.info", info(true)),
            (
                "module.execute",
                response(&[("job_id", 8.into()), ("uuid", "timed-out".into())]),
            ),
            ("job.stop", response(&[("result", "success".into())])),
            ("module.ack", response(&[("success", true.into())])),
        ])
        .await;
        let client = Client::new(&cfg).unwrap();
        let (ev, _) = mpsc::unbounded_channel();
        let (_tx, cancel) = watch::channel(false);
        let mut runner = Runner::new(client, ev, cancel, request(dir.path(), vec![]));
        runner.timeout = Duration::ZERO;
        assert!(
            runner
                .module(&item("timeout", false))
                .await
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
        server.await.unwrap();
    }
}
