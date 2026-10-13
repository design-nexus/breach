use crate::model::{Host, ModuleMeta, PlanItem, Rank};

/// Normalize identifiers so "CVE-2017-0144", "CVE 2017-0144", and "cve-2017-0144" match.
pub fn normalize_ref(raw: &str) -> String {
    let s = raw.trim().to_ascii_uppercase().replace('_', "-");
    let s = s.replace([' ', '/'], "-");
    let s = s.replace("--", "-");
    if let Some(rest) = s.strip_prefix("CVE-") {
        return format!("CVE-{rest}");
    }
    s
}

fn host_os_hint(os: &str) -> Option<&'static str> {
    let o = os.to_ascii_lowercase();
    if o.contains("win") {
        Some("windows")
    } else if o.contains("linux") || o.contains("ubuntu") || o.contains("debian") {
        Some("linux")
    } else if o.contains("osx") || o.contains("mac") || o.contains("darwin") {
        Some("osx")
    } else {
        None
    }
}

fn platform_ok(module: &ModuleMeta, host: &Host) -> bool {
    if module.platforms.is_empty() {
        return true;
    }
    let Some(hint) = host_os_hint(&host.os) else {
        return true;
    };
    module.platforms.iter().any(|p| {
        let p = p.to_ascii_lowercase();
        p.contains(hint) || p == "multi" || (p == "unix" && ["linux", "osx"].contains(&hint))
    })
}

fn refs_overlap(module: &ModuleMeta, vuln_refs: &[String], vuln_name: &str) -> Option<String> {
    let mut mrefs: Vec<String> = module.refs.iter().map(|r| normalize_ref(r)).collect();
    mrefs.sort();
    mrefs.dedup();
    let mut vrefs: Vec<String> = vuln_refs.iter().map(|r| normalize_ref(r)).collect();
    if !vuln_name.is_empty() {
        vrefs.push(normalize_ref(vuln_name));
    }
    vrefs.sort();
    vrefs.dedup();
    for r in &vrefs {
        if r.is_empty() {
            continue;
        }
        if mrefs.iter().any(|m| m == r) {
            return Some(r.clone());
        }
    }
    None
}

fn service_match(module: &ModuleMeta, host: &Host) -> Option<(u16, String)> {
    for svc in &host.services {
        if svc.state != "open" && !svc.state.is_empty() {
            continue;
        }
        if let Some(rp) = module.rport {
            if rp == svc.port {
                return Some((svc.port, format!("port {rp} open ({})", svc.name)));
            }
        }
        if !svc.name.is_empty() {
            let n = svc.name.to_ascii_lowercase();
            let full = module.fullname.to_ascii_lowercase();
            if full.split('/').any(|p| p == n) || full.contains(&format!("/{n}/")) {
                return Some((svc.port, format!("service '{n}' in module path")));
            }
        }
    }
    None
}

pub fn build_plan(hosts: &[Host], modules: &[ModuleMeta], min_rank: Rank) -> Vec<PlanItem> {
    build_plan_with_policy(hosts, modules, min_rank, true, true)
}

pub fn build_plan_with_policy(
    hosts: &[Host],
    modules: &[ModuleMeta],
    min_rank: Rank,
    match_vulns: bool,
    match_ports: bool,
) -> Vec<PlanItem> {
    let mut items = Vec::new();
    for host in hosts {
        for module in modules {
            if !Rank::rank_at_least(&module.rank, min_rank) {
                continue;
            }
            if module.kind != "exploit" && module.kind != "auxiliary" {
                continue;
            }
            if !platform_ok(module, host) {
                continue;
            }
            let mut reason = None;
            for v in host.vulns.iter().filter(|_| match_vulns) {
                if let Some(r) = refs_overlap(module, &v.refs, &v.name) {
                    reason = Some(format!("vuln ref {r} ({})", v.name));
                    break;
                }
            }
            let mut rport = module.rport;
            if reason.is_none() && match_ports {
                if let Some((port, why)) = service_match(module, host) {
                    rport = Some(port);
                    reason = Some(why);
                }
            }
            if let Some(reason) = reason {
                items.push(PlanItem {
                    host: host.address.clone(),
                    module: module.fullname.clone(),
                    kind: module.kind.clone(),
                    rank: module.rank.clone(),
                    reason,
                    rport,
                    selected: Rank::parse(&module.rank).is_some_and(|r| r >= Rank::Great),
                });
            }
        }
    }
    items.sort_by(|a, b| {
        let ra = Rank::parse(&a.rank).unwrap_or(Rank::Manual);
        let rb = Rank::parse(&b.rank).unwrap_or(Rank::Manual);
        rb.cmp(&ra)
            .then(a.host.cmp(&b.host))
            .then(a.module.cmp(&b.module))
    });
    items
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Host, ModuleMeta, Service, Vuln};

    fn eternalblue() -> ModuleMeta {
        ModuleMeta {
            kind: "exploit".into(),
            fullname: "windows/smb/ms17_010_eternalblue".into(),
            rank: "great".into(),
            refs: vec!["CVE-2017-0144".into()],
            rport: Some(445),
            platforms: vec!["windows".into()],
            description: "SMB".into(),
        }
    }

    #[test]
    fn cve_match_selects_great() {
        let host = Host {
            address: "10.0.0.5".into(),
            os: "Windows 7".into(),
            vulns: vec![Vuln {
                name: "MS17-010".into(),
                refs: vec!["CVE-2017-0144".into()],
                info: String::new(),
            }],
            services: vec![Service {
                port: 445,
                proto: "tcp".into(),
                name: "smb".into(),
                state: "open".into(),
                info: String::new(),
            }],
            ..Default::default()
        };
        let plan = build_plan(&[host], &[eternalblue()], Rank::Great);
        assert_eq!(plan.len(), 1);
        assert!(plan[0].selected);
        assert!(plan[0].reason.contains("CVE-2017-0144"));
    }

    #[test]
    fn rank_filter_drops_normal() {
        let mut m = eternalblue();
        m.rank = "normal".into();
        let host = Host {
            address: "10.0.0.5".into(),
            os: "Windows".into(),
            vulns: vec![Vuln {
                name: "x".into(),
                refs: vec!["CVE-2017-0144".into()],
                info: String::new(),
            }],
            ..Default::default()
        };
        let plan = build_plan(&[host], &[m], Rank::Great);
        assert!(plan.is_empty());
    }

    #[test]
    fn linux_host_skips_windows_module() {
        let host = Host {
            address: "10.0.0.8".into(),
            os: "Ubuntu Linux".into(),
            services: vec![Service {
                port: 445,
                proto: "tcp".into(),
                name: "smb".into(),
                state: "open".into(),
                info: String::new(),
            }],
            ..Default::default()
        };
        let plan = build_plan(&[host], &[eternalblue()], Rank::Good);
        assert!(plan.is_empty());
    }

    #[test]
    fn service_name_match() {
        let m = ModuleMeta {
            kind: "auxiliary".into(),
            fullname: "scanner/ssh/ssh_version".into(),
            rank: "normal".into(),
            refs: vec![],
            rport: Some(22),
            platforms: vec![],
            description: String::new(),
        };
        let host = Host {
            address: "10.0.0.9".into(),
            services: vec![Service {
                port: 22,
                proto: "tcp".into(),
                name: "ssh".into(),
                state: "open".into(),
                info: String::new(),
            }],
            ..Default::default()
        };
        let plan = build_plan(&[host], &[m], Rank::Normal);
        assert_eq!(plan.len(), 1);
        assert!(!plan[0].selected);
    }

    #[test]
    fn normalize_variants() {
        assert_eq!(normalize_ref("cve 2017-0144"), "CVE-2017-0144");
        assert_eq!(normalize_ref("CVE-2017-0144"), "CVE-2017-0144");
    }
    #[test]
    fn matching_filters_are_independent_and_cve_matches_are_exact() {
        let host = Host {
            address: "192.0.2.1".into(),
            os: "Windows".into(),
            services: vec![Service {
                port: 445,
                state: "open".into(),
                ..Default::default()
            }],
            vulns: vec![Vuln {
                name: "fixture".into(),
                refs: vec!["CVE-2017-014".into()],
                ..Default::default()
            }],
            ..Default::default()
        };
        assert!(
            build_plan_with_policy(&[host.clone()], &[eternalblue()], Rank::Great, true, false)
                .is_empty()
        );
        assert_eq!(
            build_plan_with_policy(&[host.clone()], &[eternalblue()], Rank::Great, false, true)
                .len(),
            1
        );
        assert!(
            build_plan_with_policy(&[host], &[eternalblue()], Rank::Great, false, false).is_empty()
        );
        let mut unix = eternalblue();
        unix.platforms = vec!["unix".into()];
        assert!(platform_ok(
            &unix,
            &Host {
                os: "Linux".into(),
                ..Default::default()
            }
        ));
    }
}
