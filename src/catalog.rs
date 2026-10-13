use crate::model::ModuleMeta;

/// Well-known Framework module metadata for the planner.
/// Paths and CVE ids only — no exploit code.
pub fn builtin() -> Vec<ModuleMeta> {
    [
        (
            "exploit",
            "windows/smb/ms17_010_eternalblue",
            "great",
            Some(445),
            &["CVE-2017-0144"][..],
            &["windows"][..],
        ),
        (
            "exploit",
            "windows/smb/ms08_067_netapi",
            "great",
            Some(445),
            &["CVE-2008-4250"],
            &["windows"],
        ),
        (
            "exploit",
            "windows/smb/psexec",
            "excellent",
            Some(445),
            &[],
            &["windows"],
        ),
        (
            "exploit",
            "windows/smb/ms17_010_psexec",
            "excellent",
            Some(445),
            &["CVE-2017-0144"],
            &["windows"],
        ),
        (
            "exploit",
            "unix/ftp/vsftpd_234_backdoor",
            "excellent",
            Some(21),
            &[],
            &["linux"],
        ),
        (
            "exploit",
            "unix/irc/unreal_ircd_3281_backdoor",
            "excellent",
            Some(6667),
            &[],
            &["linux"],
        ),
        (
            "exploit",
            "multi/http/struts2_content_type_ognl",
            "excellent",
            Some(80),
            &["CVE-2017-5638"],
            &[],
        ),
        (
            "exploit",
            "multi/http/tomcat_mgr_upload",
            "excellent",
            Some(8080),
            &[],
            &[],
        ),
        (
            "exploit",
            "linux/samba/is_known_pipename",
            "excellent",
            Some(445),
            &["CVE-2017-7494"],
            &["linux"],
        ),
        (
            "exploit",
            "windows/rdp/cve_2019_0708_bluekeep_rce",
            "manual",
            Some(3389),
            &["CVE-2019-0708"],
            &["windows"],
        ),
        (
            "auxiliary",
            "scanner/ssh/ssh_version",
            "normal",
            Some(22),
            &[],
            &[],
        ),
        (
            "auxiliary",
            "scanner/ssh/ssh_login",
            "normal",
            Some(22),
            &[],
            &[],
        ),
        (
            "auxiliary",
            "scanner/smb/smb_version",
            "normal",
            Some(445),
            &[],
            &[],
        ),
        (
            "auxiliary",
            "scanner/smb/smb_login",
            "normal",
            Some(445),
            &[],
            &[],
        ),
        (
            "auxiliary",
            "scanner/http/http_version",
            "normal",
            Some(80),
            &[],
            &[],
        ),
        (
            "auxiliary",
            "scanner/ftp/ftp_version",
            "normal",
            Some(21),
            &[],
            &[],
        ),
        (
            "auxiliary",
            "scanner/rdp/rdp_scanner",
            "normal",
            Some(3389),
            &[],
            &[],
        ),
        ("auxiliary", "server/socks_proxy", "normal", None, &[], &[]),
        ("exploit", "multi/handler", "normal", None, &[], &[]),
    ]
    .into_iter()
    .map(|(kind, fullname, rank, rport, refs, plats)| ModuleMeta {
        kind: kind.into(),
        fullname: fullname.into(),
        rank: rank.into(),
        rport,
        refs: refs.iter().map(|s| (*s).to_string()).collect(),
        platforms: plats.iter().map(|s| (*s).to_string()).collect(),
        description: String::new(),
    })
    .collect()
}

pub fn merge(cached: &[ModuleMeta]) -> Vec<ModuleMeta> {
    let mut all = builtin();
    for m in cached {
        if let Some(existing) = all
            .iter_mut()
            .find(|x| x.fullname == m.fullname && x.kind == m.kind)
        {
            if !m.refs.is_empty() {
                existing.refs.clone_from(&m.refs);
            }
            if m.rport.is_some() {
                existing.rport = m.rport;
            }
            if !m.rank.is_empty() {
                existing.rank.clone_from(&m.rank);
            }
        } else {
            all.push(m.clone());
        }
    }
    all
}

/// Framework's installed metadata cache; never used as an offline demo fallback.
pub fn installed_metadata() -> Vec<ModuleMeta> {
    let mut paths = vec![
        std::path::PathBuf::from("/opt/metasploit/db/modules_metadata_base.json"),
        std::path::PathBuf::from("/usr/share/metasploit-framework/db/modules_metadata_base.json"),
    ];
    if let Some(home) = dirs::home_dir() {
        paths.push(home.join(".msf4/store/modules_metadata.json"));
    }
    let mut modules = std::collections::HashMap::new();
    for path in paths {
        if let Ok(bytes) = std::fs::read(path) {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                for module in metadata_json(&value) {
                    modules.insert(format!("{}/{}", module.kind, module.fullname), module);
                }
            }
        }
    }
    modules.into_values().collect()
}

pub fn rank_name(value: &str) -> String {
    match value {
        "0" => "manual",
        "100" => "low",
        "200" => "average",
        "300" => "normal",
        "400" => "good",
        "500" => "great",
        "600" => "excellent",
        other => other,
    }
    .to_ascii_lowercase()
}

fn metadata_json(value: &serde_json::Value) -> Vec<ModuleMeta> {
    value
        .as_object()
        .into_iter()
        .flat_map(|m| m.values())
        .filter_map(|m| {
            let kind = m.get("type")?.as_str()?;
            if !["exploit", "auxiliary"].contains(&kind) {
                return None;
            }
            let full = m
                .get("fullname")?
                .as_str()?
                .strip_prefix(&format!("{kind}/"))?
                .to_string();
            let rank = m
                .get("rank")
                .map(|v| {
                    v.as_str()
                        .map(str::to_owned)
                        .unwrap_or_else(|| v.to_string())
                })
                .unwrap_or_default();
            Some(ModuleMeta {
                kind: kind.into(),
                fullname: full,
                rank: rank_name(&rank),
                refs: m
                    .get("references")
                    .and_then(|v| v.as_array())
                    .into_iter()
                    .flatten()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect(),
                rport: m
                    .get("rport")
                    .and_then(|v| v.as_u64())
                    .and_then(|p| u16::try_from(p).ok()),
                platforms: m
                    .get("platform")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .split(',')
                    .map(|s| s.trim().to_ascii_lowercase())
                    .filter(|s| !s.is_empty())
                    .collect(),
                description: m
                    .get("description")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .into(),
            })
        })
        .collect()
}

#[derive(serde::Serialize, serde::Deserialize)]
struct Cache {
    endpoint: String,
    version: String,
    generated: i64,
    modules: Vec<ModuleMeta>,
}

pub async fn live(
    client: &crate::rpc::Client,
    cache: &std::path::Path,
    local: bool,
    progress: impl Fn(usize, usize),
) -> anyhow::Result<Vec<ModuleMeta>> {
    use crate::rpc::{as_map, map_str, value_string};
    use anyhow::Context;
    use futures::{StreamExt, stream};
    let version_value = client.call("core.version", &[]).await?;
    let version = as_map(&version_value)
        .and_then(|m| map_str(&m, "version"))
        .context("Framework version missing")?;
    let mut cached = std::collections::HashMap::new();
    if let Ok(bytes) = std::fs::read(cache) {
        if let Ok(c) = serde_json::from_slice::<Cache>(&bytes) {
            if c.endpoint == client.endpoint()
                && c.version == version
                && chrono::Utc::now().timestamp() - c.generated < 86400
            {
                for m in c.modules {
                    cached.insert(format!("{}/{}", m.kind, m.fullname), m);
                }
            }
        }
    }
    if local && cached.is_empty() {
        for m in installed_metadata() {
            cached.insert(format!("{}/{}", m.kind, m.fullname), m);
        }
    }
    let names = client
        .call(
            "module.search",
            &[rmpv::Value::from("type:exploit type:auxiliary")],
        )
        .await?;
    let names = names
        .as_array()
        .context("module.search must return an array")?;
    let mut result = Vec::new();
    let mut missing = Vec::new();
    for row in names {
        let m = as_map(row).context("module.search row")?;
        let kind = map_str(&m, "type").context("module type")?;
        if !["exploit", "auxiliary"].contains(&kind.as_str()) {
            continue;
        }
        let full = map_str(&m, "fullname").context("module fullname")?;
        let name = full
            .strip_prefix(&format!("{kind}/"))
            .unwrap_or(&full)
            .to_string();
        if let Some(c) = cached.remove(&format!("{kind}/{name}")) {
            result.push(c)
        } else {
            missing.push((kind, name))
        }
    }
    let total = result.len() + missing.len();
    progress(result.len(), total);
    let mut requests = stream::iter(missing.into_iter().map(|(kind, name)| async move {
        let v = client
            .call("module.info", &[kind.clone().into(), name.clone().into()])
            .await?;
        let m = as_map(&v).context("module info")?;
        let info = crate::rpc::parse_module_info(&kind, &name, &v);
        let options_value = m
            .iter()
            .find(|(k, _)| k == "options")
            .map(|(_, v)| v.clone())
            .unwrap_or(rmpv::Value::Nil);
        let options = crate::rpc::parse_options(&options_value);
        let platforms = m
            .iter()
            .find(|(k, _)| k == "platform")
            .and_then(|(_, v)| v.as_array())
            .into_iter()
            .flatten()
            .filter_map(value_string)
            .map(|s| s.to_ascii_lowercase())
            .collect();
        Ok::<_, anyhow::Error>(ModuleMeta {
            kind,
            fullname: name,
            rank: rank_name(&info.rank),
            refs: info.refs,
            rport: options
                .iter()
                .find(|o| o.name == "RPORT")
                .and_then(|o| o.default.parse().ok()),
            platforms,
            description: info.description,
        })
    }))
    .buffer_unordered(8);
    while let Some(m) = requests.next().await {
        result.push(m?);
        progress(result.len(), total);
    }
    result.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.fullname.cmp(&b.fullname)));
    anyhow::ensure!(
        !result.is_empty(),
        "Framework returned an empty matching catalog"
    );
    let c = Cache {
        endpoint: client.endpoint().into(),
        version,
        generated: chrono::Utc::now().timestamp(),
        modules: result.clone(),
    };
    std::fs::write(cache, serde_json::to_vec(&c)?)?;
    Ok(result)
}
