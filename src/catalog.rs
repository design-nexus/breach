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
