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

pub fn render(
    dir: &Path,
    snap: &Snapshot,
    audit: &[AuditEntry],
    redact: bool,
) -> anyhow::Result<ReportFiles> {
    let stamp = chrono::Utc::now().format("%Y%m%d-%H%M%S");
    let out = dir.join(format!("{stamp}-{}", snap.workspace));
    std::fs::create_dir_all(&out)?;
    let md = markdown(snap, audit, redact);
    let html = html_page(&md, &snap.workspace);
    let json = serde_json::json!({
        "workspace": snap.workspace,
        "version": snap.version,
        "hosts": snap.hosts.len(),
        "sessions": snap.sessions.len(),
        "creds": snap.creds.len(),
        "generated": chrono::Utc::now().to_rfc3339(),
    });
    let files = ReportFiles {
        markdown: out.join("report.md"),
        html: out.join("report.html"),
        json: out.join("report.json"),
        dir: out,
    };
    std::fs::write(&files.markdown, md).context("write md")?;
    std::fs::write(&files.html, html).context("write html")?;
    std::fs::write(&files.json, serde_json::to_string_pretty(&json)?).context("write json")?;
    Ok(files)
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
}
