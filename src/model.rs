use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Snapshot {
    pub version: String,
    pub ruby: String,
    pub db_ok: bool,
    pub workspace: String,
    pub workspaces: Vec<String>,
    pub hosts: Vec<Host>,
    pub sessions: Vec<Session>,
    pub jobs: Vec<Job>,
    pub creds: Vec<Cred>,
    pub loot: Vec<Loot>,
    pub notes: Vec<Note>,
    pub module_stats: ModuleStats,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ModuleStats {
    pub exploits: u32,
    pub auxiliary: u32,
    pub post: u32,
    pub payloads: u32,
    pub encoders: u32,
    pub nops: u32,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Host {
    pub address: String,
    pub name: String,
    pub os: String,
    pub purpose: String,
    pub info: String,
    pub services: Vec<Service>,
    pub vulns: Vec<Vuln>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Service {
    pub port: u16,
    pub proto: String,
    pub name: String,
    pub state: String,
    pub info: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Vuln {
    pub name: String,
    pub refs: Vec<String>,
    pub info: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub kind: String,
    pub via_exploit: String,
    pub via_payload: String,
    pub tunnel_local: String,
    pub tunnel_peer: String,
    pub info: String,
    pub workspace: String,
    pub session_host: String,
    pub platform: String,
    pub arch: String,
    pub routes: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Job {
    pub id: String,
    pub name: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Cred {
    pub host: String,
    pub service: String,
    pub user: String,
    pub pass: String,
    pub kind: String,
    pub realm: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Loot {
    pub host: String,
    pub ltype: String,
    pub name: String,
    pub info: String,
    pub path: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Note {
    pub host: String,
    pub ntype: String,
    pub data: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ModuleMeta {
    pub kind: String,
    pub fullname: String,
    pub rank: String,
    pub refs: Vec<String>,
    pub rport: Option<u16>,
    pub platforms: Vec<String>,
    pub description: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ModuleOption {
    pub name: String,
    pub required: bool,
    pub advanced: bool,
    pub desc: String,
    pub default: String,
    pub value: String,
    pub opt_type: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ModuleInfo {
    pub kind: String,
    pub fullname: String,
    pub name: String,
    pub rank: String,
    pub description: String,
    pub refs: Vec<String>,
    pub options: Vec<ModuleOption>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rank {
    Manual,
    Low,
    Average,
    Normal,
    Good,
    Great,
    Excellent,
}

impl Rank {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "manual" => Rank::Manual,
            "low" => Rank::Low,
            "average" => Rank::Average,
            "normal" => Rank::Normal,
            "good" => Rank::Good,
            "great" => Rank::Great,
            "excellent" => Rank::Excellent,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Rank::Manual => "manual",
            Rank::Low => "low",
            Rank::Average => "average",
            Rank::Normal => "normal",
            Rank::Good => "good",
            Rank::Great => "great",
            Rank::Excellent => "excellent",
        }
    }

    pub fn rank_at_least(module: &str, min: Rank) -> bool {
        Rank::parse(module).is_some_and(|r| r >= min)
    }
}

impl PartialOrd for Rank {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Rank {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (*self as u8).cmp(&(*other as u8))
    }
}

#[derive(Clone, Debug)]
pub struct PlanItem {
    pub host: String,
    pub module: String,
    pub kind: String,
    pub rank: String,
    pub reason: String,
    pub rport: Option<u16>,
    pub selected: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskLog {
    #[serde(default)]
    pub workspace: String,
    pub id: String,
    pub started: String,
    pub kind: String,
    pub summary: String,
    pub status: String,
    pub detail: String,
}

impl TaskLog {
    pub fn new(kind: &str, summary: &str) -> Self {
        Self {
            workspace: String::new(),
            id: uuid::Uuid::new_v4().to_string()[..8].to_string(),
            started: chrono::Utc::now().format("%H:%M:%S").to_string(),
            kind: kind.into(),
            summary: summary.into(),
            status: "running".into(),
            detail: String::new(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleKind {
    Exploit,
    Auxiliary,
    Post,
    Payload,
    Encoder,
}

impl ModuleKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ModuleKind::Exploit => "exploit",
            ModuleKind::Auxiliary => "auxiliary",
            ModuleKind::Post => "post",
            ModuleKind::Payload => "payload",
            ModuleKind::Encoder => "encoder",
        }
    }

    pub fn next(self) -> Self {
        match self {
            ModuleKind::Exploit => ModuleKind::Auxiliary,
            ModuleKind::Auxiliary => ModuleKind::Post,
            ModuleKind::Post => ModuleKind::Payload,
            ModuleKind::Payload => ModuleKind::Encoder,
            ModuleKind::Encoder => ModuleKind::Exploit,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ValidationResult {
    #[serde(default)]
    pub workspace: String,
    #[serde(default)]
    pub checked_at: String,
    pub host: String,
    pub module: String,
    pub code: String,
    pub message: String,
    pub details: serde_json::Value,
}
