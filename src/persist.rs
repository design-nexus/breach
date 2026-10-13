use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_theme")]
    pub theme: String,
    #[serde(default = "default_host")]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_user")]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub ssl: bool,
    #[serde(default = "default_true")]
    pub spawn: bool,
    #[serde(default = "default_uri")]
    pub uri: String,
}

fn default_theme() -> String {
    "crimson".into()
}
fn default_host() -> String {
    "127.0.0.1".into()
}
fn default_port() -> u16 {
    55553
}
fn default_user() -> String {
    "msf".into()
}
fn default_true() -> bool {
    true
}
fn default_uri() -> String {
    "/api/".into()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            theme: default_theme(),
            host: default_host(),
            port: default_port(),
            username: default_user(),
            password: String::new(),
            ssl: false,
            spawn: true,
            uri: default_uri(),
        }
    }
}

impl Config {
    pub fn is_loopback(&self) -> bool {
        matches!(self.host.as_str(), "127.0.0.1" | "localhost" | "::1")
    }

    pub fn resolved_password(&self) -> String {
        Self::password_with_override(
            &self.password,
            std::env::var("NEXUS_MSF_RPC_PASS").ok().as_deref(),
        )
    }
    fn password_with_override(configured: &str, overridden: Option<&str>) -> String {
        overridden
            .filter(|s| !s.is_empty())
            .unwrap_or(configured)
            .to_owned()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct Favorites {
    pub modules: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    pub ts: String,
    pub action: String,
    pub detail: String,
}

pub struct Paths {
    #[allow(dead_code)]
    pub data: PathBuf,
    #[allow(dead_code)]
    pub config_dir: PathBuf,
    pub config: PathBuf,
    pub audit: PathBuf,
    pub chains: PathBuf,
    pub macros: PathBuf,
    pub reports: PathBuf,
    pub favorites: PathBuf,
    #[allow(dead_code)]
    pub cache: PathBuf,
}

impl Paths {
    pub fn resolve() -> anyhow::Result<Self> {
        let data = dirs::data_local_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("nexus-msf");
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("nexus-msf");
        std::fs::create_dir_all(data.join("chains"))?;
        std::fs::create_dir_all(data.join("macros"))?;
        std::fs::create_dir_all(data.join("reports"))?;
        std::fs::create_dir_all(data.join("cache"))?;
        std::fs::create_dir_all(&config_dir)?;
        Ok(Self {
            chains: data.join("chains"),
            macros: data.join("macros"),
            reports: data.join("reports"),
            favorites: data.join("favorites.toml"),
            cache: data.join("cache"),
            audit: data.join("audit.jsonl"),
            config: config_dir.join("config.toml"),
            data,
            config_dir,
        })
    }
}

pub fn load_config(path: &Path) -> Config {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_config(path: &Path, cfg: &Config) -> anyhow::Result<()> {
    let s = toml::to_string_pretty(cfg)?;
    std::fs::write(path, s).with_context(|| format!("write {}", path.display()))?;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    Ok(())
}

pub fn load_favorites(path: &Path) -> Favorites {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| toml::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn save_favorites(path: &Path, fav: &Favorites) -> anyhow::Result<()> {
    std::fs::write(path, toml::to_string_pretty(fav)?)?;
    Ok(())
}

pub fn append_audit(path: &Path, action: &str, detail: &str) -> anyhow::Result<AuditEntry> {
    let entry = AuditEntry {
        ts: chrono::Utc::now().to_rfc3339(),
        action: action.into(),
        detail: detail.into(),
    };
    let mut line = serde_json::to_string(&entry)?;
    line.push('\n');
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    f.write_all(line.as_bytes())?;
    Ok(entry)
}

pub fn load_audit(path: &Path, limit: usize) -> Vec<AuditEntry> {
    let Ok(s) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let mut out: Vec<AuditEntry> = s
        .lines()
        .rev()
        .filter_map(|l| serde_json::from_str(l).ok())
        .take(limit)
        .collect();
    out.reverse();
    out
}

pub fn seed_defaults(paths: &Paths) -> anyhow::Result<()> {
    crate::chains::seed_example(&paths.chains)?;
    crate::macros::seed_defaults(&paths.macros)?;
    if !paths.config.exists() {
        save_config(&paths.config, &Config::default())?;
    }
    Ok(())
}

#[cfg(test)]
mod password_override_tests {
    use super::*;
    #[test]
    fn explicit_environment_password_overrides_saved_password() {
        assert_eq!(
            Config::password_with_override("saved", Some("explicit")),
            "explicit"
        );
        assert_eq!(Config::password_with_override("saved", Some("")), "saved");
        assert_eq!(Config::password_with_override("saved", None), "saved");
    }
}

pub fn save_private_json(path: &Path, value: &impl Serialize) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let temporary = path.with_extension(format!("{}.tmp", uuid::Uuid::new_v4()));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    std::fs::rename(temporary, path)?;
    Ok(())
}
pub fn load_tasks(path: &Path) -> Vec<crate::model::TaskLog> {
    let mut tasks: Vec<crate::model::TaskLog> = std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    for task in &mut tasks {
        if task.status == "running" {
            task.status = "interrupted".into();
            task.detail.push_str("\nApp closed before completion was recorded; inspect Framework jobs before restarting.");
        }
    }
    tasks
}
pub fn load_validations(path: &Path) -> Vec<crate::model::ValidationResult> {
    std::fs::read(path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

#[cfg(test)]
mod workflow_persistence_tests {
    #[test]
    fn task_restart_marks_running_interrupted_and_keeps_completed_records() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tasks.json");
        let running = crate::model::TaskLog::new("chain", "queued");
        let mut complete = running.clone();
        complete.status = "complete".into();
        super::save_private_json(&path, &vec![running, complete]).unwrap();
        let records = super::load_tasks(&path);
        assert_eq!(records[0].status, "interrupted");
        assert_eq!(records[1].status, "complete");
        assert!(records[0].detail.contains("Framework jobs"));
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
