use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Chain {
    pub name: String,
    #[serde(default = "default_on_fail")]
    pub on_fail: String,
    #[serde(default)]
    pub steps: Vec<Step>,
}

fn default_on_fail() -> String {
    "stop".into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Step {
    Discover {
        rhosts: String,
        #[serde(default)]
        ports: String,
    },
    Import {
        path: String,
    },
    AutoExploit {
        #[serde(default = "default_rank")]
        min_rank: String,
        #[serde(default = "default_true")]
        match_vulns: bool,
        #[serde(default = "default_true")]
        match_ports: bool,
    },
    Validate {
        #[serde(default = "default_rank")]
        min_rank: String,
    },
    CollectEvidence {
        #[serde(default = "default_macro")]
        r#macro: String,
    },
    Report {
        #[serde(default = "default_formats")]
        formats: Vec<String>,
    },
    Module {
        kind: String,
        name: String,
        #[serde(default)]
        options: std::collections::HashMap<String, String>,
    },
}

fn default_rank() -> String {
    "great".into()
}
fn default_true() -> bool {
    true
}
fn default_macro() -> String {
    "default-windows".into()
}
fn default_formats() -> Vec<String> {
    vec!["html".into(), "md".into()]
}

impl Chain {
    pub fn summary(&self) -> String {
        format!("{} ({} steps)", self.name, self.steps.len())
    }

    pub fn step_label(step: &Step) -> String {
        match step {
            Step::Discover { rhosts, ports } => {
                format!("discover {rhosts} ports={ports}")
            }
            Step::Import { path } => format!("import {path}"),
            Step::AutoExploit {
                min_rank,
                match_vulns,
                match_ports,
            } => format!("auto-exploit min={min_rank} vulns={match_vulns} ports={match_ports}"),
            Step::Validate { min_rank } => format!("validate min={min_rank}"),
            Step::CollectEvidence { r#macro } => format!("evidence macro={macro}"),
            Step::Report { formats } => format!("report {}", formats.join(",")),
            Step::Module { kind, name, .. } => format!("module {kind}/{name}"),
        }
    }
}

pub fn load_dir(dir: &Path) -> Vec<Chain> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }
        if let Ok(s) = std::fs::read_to_string(&p) {
            if let Ok(c) = toml::from_str::<Chain>(&s) {
                out.push(c);
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

pub fn save(dir: &Path, chain: &Chain) -> anyhow::Result<()> {
    let slug = chain
        .name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .to_ascii_lowercase();
    let path = dir.join(format!("{slug}.toml"));
    std::fs::write(&path, toml::to_string_pretty(chain)?)
        .with_context(|| format!("write {}", path.display()))
}

pub fn seed_example(dir: &Path) -> anyhow::Result<()> {
    if std::fs::read_dir(dir)?.next().is_some() {
        return Ok(());
    }
    save(
        dir,
        &Chain {
            name: "quick-pentest".into(),
            on_fail: "stop".into(),
            steps: vec![
                Step::Discover {
                    rhosts: "192.168.1.0/24".into(),
                    ports: "22,80,443,445,3389".into(),
                },
                Step::AutoExploit {
                    min_rank: "great".into(),
                    match_vulns: true,
                    match_ports: true,
                },
                Step::CollectEvidence {
                    r#macro: "default-windows".into(),
                },
                Step::Report {
                    formats: vec!["html".into(), "md".into()],
                },
            ],
        },
    )?;
    save(
        dir,
        &Chain {
            name: "validate-import".into(),
            on_fail: "continue".into(),
            steps: vec![
                Step::Import {
                    path: "/tmp/scan.xml".into(),
                },
                Step::Validate {
                    min_rank: "great".into(),
                },
                Step::Report {
                    formats: vec!["md".into()],
                },
            ],
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_chain() {
        let raw = r#"
name = "weekly-smb"
on_fail = "stop"

[[steps]]
type = "discover"
rhosts = "10.0.0.0/24"
ports = "445"

[[steps]]
type = "auto_exploit"
min_rank = "great"
"#;
        let c: Chain = toml::from_str(raw).unwrap();
        assert_eq!(c.name, "weekly-smb");
        assert_eq!(c.steps.len(), 2);
        assert!(matches!(c.steps[1], Step::AutoExploit { .. }));
    }
}
