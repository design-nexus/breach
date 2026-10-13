use crate::model::Snapshot;
use crate::persist::AuditEntry;
use anyhow::Context;
use std::path::{Path, PathBuf};

pub struct ReportFiles {
    pub dir: PathBuf,
    pub markdown: PathBuf,
    pub html: PathBuf,
    pub json: PathBuf,
}

#[cfg(test)]
pub fn render(
    dir: &Path,
    snap: &Snapshot,
    audit: &[AuditEntry],
    redact: bool,
) -> anyhow::Result<ReportFiles> {
    render_full(
        dir,
        snap,
        audit,
        &[],
        &[],
        redact,
        &["md".into(), "html".into(), "json".into()],
    )
}

pub fn validate_formats(formats: &[String]) -> anyhow::Result<()> {
    anyhow::ensure!(!formats.is_empty(), "choose at least one report format");
    for format in formats {
        anyhow::ensure!(
            ["md", "html", "json"].contains(&format.as_str()),
            "unsupported report format: {format}"
        );
    }
    Ok(())
}

pub fn render_full(
    dir: &Path,
    snap: &Snapshot,
    audit: &[AuditEntry],
    tasks: &[crate::model::TaskLog],
    validations: &[crate::model::ValidationResult],
    redact: bool,
    formats: &[String],
) -> anyhow::Result<ReportFiles> {
    validate_formats(formats)?;
    let mut evidence = serde_json::json!({"snapshot":snap,"audit":audit,"tasks":tasks,"validations":validations,
        "generated":chrono::Utc::now().to_rfc3339(),"redacted":redact});
    if redact {
        redact_value(
            &mut evidence,
            &snap
                .creds
                .iter()
                .map(|c| c.pass.clone())
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>(),
            false,
        );
    }
    let safe_snap: Snapshot = serde_json::from_value(evidence["snapshot"].clone())?;
    let safe_audit: Vec<AuditEntry> = serde_json::from_value(evidence["audit"].clone())?;
    let mut md = markdown(&safe_snap, &safe_audit, false);
    md.push_str("\n## Validation results\n\n");
    for result in evidence["validations"].as_array().into_iter().flatten() {
        md.push_str(&format!(
            "- {} {}: **{}** — {}\n",
            result["host"].as_str().unwrap_or(""),
            result["module"].as_str().unwrap_or(""),
            result["code"].as_str().unwrap_or(""),
            result["message"].as_str().unwrap_or("")
        ));
    }
    md.push_str("\n## Full workspace evidence and task history\n\n```json\n");
    md.push_str(&serde_json::to_string_pretty(&evidence)?);
    md.push_str("\n```\n");
    let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let slug = snap
        .workspace
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>();
    let out = dir.join(format!(
        "{stamp}-{slug}-{}",
        &uuid::Uuid::new_v4().to_string()[..8]
    ));
    std::fs::create_dir_all(&out)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&out, std::fs::Permissions::from_mode(0o700))?;
    let files = ReportFiles {
        markdown: out.join("report.md"),
        html: out.join("report.html"),
        json: out.join("report.json"),
        dir: out,
    };
    for format in formats {
        let (path, text) = match format.as_str() {
            "md" => (&files.markdown, md.clone()),
            "html" => (&files.html, html_page(&md, &safe_snap.workspace)),
            _ => (&files.json, serde_json::to_string_pretty(&evidence)?),
        };
        std::fs::write(path, text).context("write report")?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(files)
}

/// Masks known credential values everywhere, and fields explicitly named as secrets.
/// Free text containing unknown secrets cannot be classified reliably.
fn redact_value(value: &mut serde_json::Value, secrets: &[String], sensitive: bool) {
    if sensitive && !value.is_null() {
        *value = "[REDACTED]".into();
        return;
    }
    match value {
        serde_json::Value::String(text) => {
            for secret in secrets {
                if !secret.is_empty() {
                    *text = text.replace(secret, "[REDACTED]");
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                redact_value(value, secrets, false)
            }
        }
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                let key = key.to_ascii_lowercase();
                let sensitive = [
                    "pass",
                    "password",
                    "passwd",
                    "secret",
                    "token",
                    "private_key",
                    "hash",
                ]
                .iter()
                .any(|s| key == *s || key.ends_with(&format!("_{s}")));
                redact_value(value, secrets, sensitive);
            }
        }
        _ => {}
    }
}

pub fn markdown(snap: &Snapshot, audit: &[AuditEntry], redact: bool) -> String {
    let mut s = String::new();
    s.push_str("# breach workspace report\n\n");
    s.push_str(&format!(
        "Workspace **{}** · Framework **{}** · generated {}\n\n",
        snap.workspace,
        snap.version,
        chrono::Utc::now().to_rfc3339()
    ));
    s.push_str("## Summary\n\n");
    s.push_str(&format!(
        "| Hosts | Services | Vulns | Sessions | Creds | Loot | Jobs |\n|---:|---:|---:|---:|---:|---:|---:|\n| {} | {} | {} | {} | {} | {} | {} |\n\n",
        snap.hosts.len(),
        snap.hosts.iter().map(|h| h.services.len()).sum::<usize>(),
        snap.hosts.iter().map(|h| h.vulns.len()).sum::<usize>(),
        snap.sessions.len(),
        snap.creds.len(),
        snap.loot.len(),
        snap.jobs.len(),
    ));

    s.push_str("## Hosts\n\n");
    for h in &snap.hosts {
        let name = if h.name.is_empty() {
            String::new()
        } else {
            format!(" ({})", h.name)
        };
        s.push_str(&format!("### {}{name}\n\n", h.address));
        if !h.os.is_empty() {
            s.push_str(&format!("- OS: {}\n", h.os));
        }
        if h.services.is_empty() {
            s.push_str("- no services\n");
        } else {
            s.push_str("- services:\n");
            for svc in &h.services {
                s.push_str(&format!(
                    "  - {}/{}/{} {} {}\n",
                    svc.port, svc.proto, svc.name, svc.state, svc.info
                ));
            }
        }
        if !h.vulns.is_empty() {
            s.push_str("- vulns:\n");
            for v in &h.vulns {
                s.push_str(&format!("  - {} [{}]\n", v.name, v.refs.join(", ")));
            }
        }
        s.push('\n');
    }

    s.push_str("## Sessions\n\n");
    if snap.sessions.is_empty() {
        s.push_str("_none_\n\n");
    } else {
        for sess in &snap.sessions {
            s.push_str(&format!(
                "- `{}` {} {} via {}\n",
                sess.id, sess.kind, sess.session_host, sess.via_exploit
            ));
        }
        s.push('\n');
    }

    s.push_str("## Credentials\n\n");
    if snap.creds.is_empty() {
        s.push_str("_none_\n\n");
    } else {
        for c in &snap.creds {
            let pass = if redact {
                "••••".into()
            } else {
                c.pass.clone()
            };
            s.push_str(&format!(
                "- {} {} \\{} / {}\n",
                c.host, c.service, c.user, pass
            ));
        }
        s.push('\n');
    }

    s.push_str("## Loot\n\n");
    if snap.loot.is_empty() {
        s.push_str("_none_\n\n");
    } else {
        for l in &snap.loot {
            s.push_str(&format!("- {} {} {}\n", l.host, l.ltype, l.name));
        }
        s.push('\n');
    }

    s.push_str("## Activity\n\n");
    if audit.is_empty() {
        s.push_str("_none_\n");
    } else {
        for a in audit {
            s.push_str(&format!("- {} **{}** {}\n", a.ts, a.action, a.detail));
        }
    }
    s
}

fn html_page(md: &str, workspace: &str) -> String {
    let escaped = html_escape(md);
    let workspace = html_escape(workspace);
    format!(
        r#"<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>breach · {workspace}</title>
<style>
  body {{ background:#171820; color:#ececf4; font-family: ui-monospace, monospace; margin: 2rem; }}
  h1,h2,h3 {{ color:#b5a0ff; }}
  a {{ color:#83d9dc; }}
  code {{ color:#a3d6b0; }}
  table {{ border-collapse: collapse; }}
  td, th {{ border: 1px solid #3d4054; padding: .3rem .6rem; }}
  pre {{ white-space: pre-wrap; background:#222432; padding: 1rem; border: 1px solid #3d4054; }}
</style></head>
<body>
<p style="color:#b5a0ff">Breach · Aurora · authorized testing only</p>
<pre>{escaped}</pre>
</body></html>
"#
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Host;

    #[test]
    fn reports_stay_inside_the_reports_directory_and_have_unique_paths() {
        let dir = tempfile::tempdir().unwrap();
        let mut snap = Snapshot::default();
        snap.workspace = "../../outside<script>".into();
        let first = render(dir.path(), &snap, &[], true).unwrap();
        let second = render(dir.path(), &snap, &[], true).unwrap();
        assert_eq!(first.dir.parent(), Some(dir.path()));
        assert_ne!(first.dir, second.dir);
        let html = std::fs::read_to_string(first.html).unwrap();
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }
    #[test]
    fn report_contains_host() {
        let mut snap = Snapshot::default();
        snap.workspace = "lab".into();
        snap.hosts.push(Host {
            address: "10.0.0.5".into(),
            name: "dc1".into(),
            ..Default::default()
        });
        let md = markdown(&snap, &[], true);
        assert!(md.contains("10.0.0.5"));
        assert!(md.contains("lab"));
    }
    #[test]
    fn full_reports_honor_formats_and_redact_secrets_across_evidence() {
        use crate::model::{Cred, Note, TaskLog, ValidationResult};
        let dir = tempfile::tempdir().unwrap();
        let secret = "fixture-secret-123";
        let snap = Snapshot {
            workspace: "lab".into(),
            creds: vec![Cred {
                pass: secret.into(),
                user: "tester".into(),
                ..Default::default()
            }],
            notes: vec![Note {
                data: format!("reused {secret}"),
                ..Default::default()
            }],
            hosts: vec![Host {
                address: "192.0.2.1".into(),
                info: secret.into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut task = TaskLog::new("test", "fixture");
        task.detail = secret.into();
        let validation = ValidationResult {
            workspace: "lab".into(),
            code: "vulnerable".into(),
            details: serde_json::json!({"token":"different-secret","message":secret}),
            ..Default::default()
        };
        let files = render_full(
            dir.path(),
            &snap,
            &[],
            &[task],
            &[validation],
            true,
            &["json".into(), "md".into()],
        )
        .unwrap();
        assert!(!files.html.exists());
        for path in [&files.markdown, &files.json] {
            let text = std::fs::read_to_string(path).unwrap();
            assert!(!text.contains(secret));
            assert!(!text.contains("different-secret"));
            assert!(text.contains("[REDACTED]"));
        }
        let json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(files.json).unwrap()).unwrap();
        assert_eq!(json["snapshot"]["hosts"][0]["address"], "192.0.2.1");
        assert_eq!(json["validations"][0]["code"], "vulnerable");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&files.dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert!(render_full(dir.path(), &snap, &[], &[], &[], false, &["pdf".into()]).is_err());
        let raw = render_full(dir.path(), &snap, &[], &[], &[], false, &["json".into()]).unwrap();
        assert!(std::fs::read_to_string(raw.json).unwrap().contains(secret));
    }
}
