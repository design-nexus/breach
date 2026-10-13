use crate::app::{App, CredPane, HostPane, Modal, Tab, WizardKind};
use crate::chains::Chain;
use crate::theme;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Tabs, Wrap};

pub fn draw(frame: &mut Frame, app: &App) {
    let area = frame.area();
    frame.render_widget(Block::default().style(theme::bg()), area);

    if area.width < 30 || area.height < 10 {
        frame.render_widget(
            Paragraph::new("breach · needs 30×10\nResize terminal; q quits"),
            area,
        );
        return;
    }
    let chunks = Layout::vertical([
        Constraint::Length(4),
        Constraint::Min(8),
        Constraint::Length(2),
    ])
    .split(area);

    draw_header(frame, app, chunks[0]);
    match app.tab {
        Tab::Dash => draw_dash(frame, app, chunks[1]),
        Tab::Hosts => draw_hosts(frame, app, chunks[1]),
        Tab::Modules => draw_modules(frame, app, chunks[1]),
        Tab::Sessions => draw_sessions(frame, app, chunks[1]),
        Tab::Creds => draw_creds(frame, app, chunks[1]),
        Tab::Tasks => draw_tasks(frame, app, chunks[1]),
        Tab::Chains => draw_chains(frame, app, chunks[1]),
        Tab::Reports => draw_reports(frame, app, chunks[1]),
        Tab::Console => draw_console(frame, app, chunks[1]),
        Tab::Wizards => draw_wizards(frame, app, chunks[1]),
    }
    draw_status(frame, app, chunks[2]);

    if app.filtering {
        draw_prompt(frame, area, "filter", &app.edit.value, app.edit.cursor);
    }
    match &app.modal {
        Modal::None => {}
        Modal::Help => draw_help(frame, area, app.help_scroll),
        Modal::Confirm { title, body, .. } => draw_confirm(frame, area, title, body),
        Modal::Message { title, body } => draw_confirm(frame, area, title, body),
        Modal::Edit { title, .. } => {
            draw_prompt(frame, area, title, &app.edit.value, app.edit.cursor);
        }
    }
    app.commands.draw(
        frame,
        crate::app::ACTIONS,
        theme::bg_color(),
        theme::fg(),
        theme::purple(),
        theme::current(),
    );
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let [identity, tabs, context] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Length(2),
    ])
    .areas(area);
    let state = if app.demo {
        "○ demo"
    } else if app.connected {
        "● RPC connected"
    } else {
        "○ RPC offline"
    };
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" breach", theme::title()),
            Span::styled("  Metasploit / workspace lab  ", theme::muted()),
            Span::styled(state, theme::ok()),
        ])),
        identity,
    );
    let all = Tab::all();
    let selected = all.iter().position(|t| *t == app.tab).unwrap_or(0);
    let start = if area.width < 100 {
        selected.saturating_sub(2)
    } else {
        0
    };
    let count = if area.width < 100 { 5 } else { 10 };
    let titles: Vec<Line> = all
        .iter()
        .skip(start)
        .take(count)
        .map(|t| Line::from(t.title()))
        .collect();
    frame.render_widget(
        Tabs::new(titles)
            .select(selected - start)
            .highlight_style(theme::accent())
            .divider("  "),
        tabs,
    );
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" Workspace ", theme::muted()),
            Span::styled(
                if app.snap.workspace.is_empty() {
                    "—"
                } else {
                    &app.snap.workspace
                },
                theme::ip(),
            ),
            Span::styled(
                format!(
                    "   Hosts {}  Sessions {}  Jobs {}",
                    app.snap.hosts.len(),
                    app.snap.sessions.len(),
                    app.snap.jobs.len()
                ),
                theme::muted(),
            ),
        ])),
        context,
    );
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let [keys, status] =
        Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);
    frame.render_widget(
        Paragraph::new(" Tab pane  / filter  ^K actions  q quit").style(theme::muted()),
        keys,
    );
    let area = status;
    let state = if app.busy {
        Span::styled(" BUSY ", theme::warn().add_modifier(Modifier::BOLD))
    } else if app.connected {
        Span::styled(" LIVE ", theme::ok().add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" OFF  ", theme::err().add_modifier(Modifier::BOLD))
    };
    let line = Line::from(vec![
        state,
        Span::styled(
            format!(
                " h:{} s:{} j:{} c:{} ",
                app.snap.hosts.len(),
                app.snap.sessions.len(),
                app.snap.jobs.len(),
                app.snap.creds.len()
            ),
            theme::ip(),
        ),
        Span::styled(format!(" {} ", app.status), theme::muted()),
        Span::styled("  Tab pane  / filter  ^K actions  q quit", theme::muted()),
    ]);
    frame.render_widget(Paragraph::new(line).style(theme::bg()), area);
}

fn pane(title: &str, focused: bool) -> Block<'_> {
    Block::bordered()
        .border_style(theme::pane_border(focused))
        .title(Span::styled(
            title,
            if focused {
                theme::accent()
            } else {
                theme::muted()
            },
        ))
}

fn draw_dash(frame: &mut Frame, app: &App, area: Rect) {
    let cols =
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).split(area);
    let st = &app.snap.module_stats;
    let left = vec![
        Line::from(Span::styled("Connection", theme::title())),
        Line::from(format!(
            "  {}://{}:{}  ssl={}  spawn={}",
            if app.config.ssl { "https" } else { "http" },
            app.config.host,
            app.config.port,
            app.config.ssl,
            app.config.spawn
        )),
        Line::from(format!(
            "  user {}  loopback {}",
            app.config.username,
            app.config.is_loopback()
        )),
        Line::from(""),
        Line::from(Span::styled("Framework", theme::title())),
        Line::from(format!(
            "  version  {}  ruby {}",
            empty(&app.snap.version),
            empty(&app.snap.ruby)
        )),
        Line::from(format!(
            "  database {}",
            if app.snap.db_ok {
                "connected"
            } else {
                "not ready"
            }
        )),
        Line::from(format!("  workspace {}", empty(&app.snap.workspace))),
        Line::from(format!("  workspaces {}", app.snap.workspaces.join(", "))),
        Line::from(""),
        Line::from(Span::styled("Modules", theme::title())),
        Line::from(format!(
            "  exploit {}  aux {}  post {}  payload {}  enc {}  nop {}",
            st.exploits, st.auxiliary, st.post, st.payloads, st.encoders, st.nops
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Ctrl-G connect   [ ] workspace   e edit ws",
            theme::muted(),
        )),
        Line::from(Span::styled(
            "Only test systems you own or have permission to test.",
            theme::warn(),
        )),
    ];
    frame.render_widget(
        Paragraph::new(left).block(pane(" overview ", true)),
        cols[0],
    );

    let mut right = vec![Line::from(Span::styled("Recent activity", theme::title()))];
    if app.audit.is_empty() {
        right.push(Line::from(Span::styled("  (empty)", theme::muted())));
    }
    for e in app.audit.iter().rev().take(18) {
        right.push(Line::from(vec![
            Span::styled(format!("  {} ", ts_short(&e.ts)), theme::muted()),
            Span::styled(&e.action, theme::flag()),
            Span::styled(format!(" {}", truncate(&e.detail, 40)), theme::muted()),
        ]));
    }
    frame.render_widget(Paragraph::new(right).block(pane(" audit ", false)), cols[1]);
}

fn draw_hosts(frame: &mut Frame, app: &App, area: Rect) {
    let cols = if area.width < 70 {
        if app.host_pane == HostPane::List {
            [area, Rect::default()]
        } else {
            [Rect::default(), area]
        }
    } else {
        Layout::horizontal([Constraint::Length(30), Constraint::Min(1)]).areas(area)
    };
    let ids = app.filtered_hosts();
    let mut lines = Vec::new();
    for (n, hi) in ids.iter().enumerate() {
        let h = &app.snap.hosts[*hi];
        let sel = *hi == app.host_idx;
        let style = if sel && app.host_pane == HostPane::List {
            theme::selected()
        } else if sel {
            theme::accent()
        } else {
            theme::bg()
        };
        let mark = if sel { "▸" } else { " " };
        lines.push(Line::from(Span::styled(
            format!("{mark} {}", h.address),
            style,
        )));
        lines.push(Line::from(Span::styled(
            format!("  {} · {} services", truncate(&h.os, 16), h.services.len()),
            theme::muted(),
        )));
        if n > 40 {
            break;
        }
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled(
            "no hosts — import nmap XML (i) or discover (Ctrl-G)",
            theme::muted(),
        )));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((
                (ids.iter().position(|i| *i == app.host_idx).unwrap_or(0) * 2)
                    .saturating_sub(cols[0].height.saturating_sub(4) as usize)
                    as u16,
                0,
            ))
            .block(pane(
                " hosts  a plan  i import ",
                app.host_pane == HostPane::List,
            )),
        cols[0],
    );

    let mut detail = Vec::new();
    if let Some(h) = app.snap.hosts.get(app.host_idx) {
        detail.push(Line::from(Span::styled(
            format!("{}  {}", h.address, h.name),
            theme::ip(),
        )));
        detail.push(Line::from(Span::styled(&h.os, theme::hostname())));
        if !h.purpose.is_empty() || !h.info.is_empty() {
            detail.push(Line::from(Span::styled(
                format!("{}  {}", h.purpose, h.info),
                theme::muted(),
            )));
        }
        detail.push(Line::from(""));
        detail.push(Line::from(Span::styled("services", theme::title())));
        for s in &h.services {
            let st = if s.state == "open" {
                theme::ok()
            } else {
                theme::muted()
            };
            detail.push(Line::from(Span::styled(
                format!("  {:>5}/{:<4} {:<12} {}", s.port, s.proto, s.name, s.info),
                st,
            )));
        }
        detail.push(Line::from(""));
        detail.push(Line::from(Span::styled(
            "Review plan · recorded findings",
            theme::title(),
        )));
        if h.vulns.is_empty() {
            detail.push(Line::from(Span::styled("  (none)", theme::muted())));
        }
        for v in &h.vulns {
            detail.push(Line::from(Span::styled(
                format!("  {} [{}] {}", v.name, v.refs.join(", "), v.info),
                theme::warn(),
            )));
        }
        let notes: Vec<_> = app
            .snap
            .notes
            .iter()
            .filter(|n| n.host == h.address)
            .collect();
        if !notes.is_empty() {
            detail.push(Line::from(""));
            detail.push(Line::from(Span::styled("notes", theme::title())));
            for n in notes {
                detail.push(Line::from(Span::styled(
                    format!("  {} {}", n.ntype, n.data),
                    theme::muted(),
                )));
            }
        }
    }
    frame.render_widget(
        Paragraph::new(detail)
            .wrap(Wrap { trim: false })
            .scroll((app.detail_scroll, 0))
            .block(pane(" detail ", app.host_pane == HostPane::Detail)),
        cols[1],
    );
}

fn draw_modules(frame: &mut Frame, app: &App, area: Rect) {
    let cols =
        Layout::horizontal([Constraint::Percentage(48), Constraint::Percentage(52)]).split(area);
    let names = app.current_modules();
    let mut lines = vec![Line::from(Span::styled(
        format!(
            "type={}  {} shown  t cycle  f favorite",
            app.module_kind.as_str(),
            names.len()
        ),
        theme::muted(),
    ))];
    for (i, n) in names.iter().enumerate() {
        let sel = i == app.module_idx;
        let star = if app.is_favorite(n) { "*" } else { " " };
        let style = if sel { theme::selected() } else { theme::bg() };
        let mark = if sel { "▸" } else { " " };
        lines.push(Line::from(Span::styled(format!("{mark}{star} {n}"), style)));
        if lines.len() > 40 {
            break;
        }
    }
    frame.render_widget(
        Paragraph::new(lines).block(pane(" modules ", true)),
        cols[0],
    );

    let mut info_lines = Vec::new();
    if let Some(m) = &app.module_info {
        info_lines.push(Line::from(Span::styled(
            format!("{}/{}", m.kind, m.fullname),
            theme::title(),
        )));
        info_lines.push(Line::from(Span::styled(&m.name, theme::script())));
        info_lines.push(Line::from(vec![
            Span::styled("rank ", theme::muted()),
            Span::styled(&m.rank, theme::rank_style(&m.rank)),
        ]));
        if !m.refs.is_empty() {
            info_lines.push(Line::from(Span::styled(
                format!("refs {}", m.refs.join(" ")),
                theme::script(),
            )));
        }
        info_lines.push(Line::from(""));
        for (i, para) in wrap_desc(&m.description, 52).into_iter().enumerate() {
            if i > 6 {
                break;
            }
            info_lines.push(Line::from(Span::styled(para, theme::muted())));
        }
        info_lines.push(Line::from(""));
        info_lines.push(Line::from(Span::styled(
            "options  Enter edit  Ctrl-G execute",
            theme::muted(),
        )));
        for (i, o) in m.options.iter().enumerate() {
            let sel = i == app.option_idx;
            let req = if o.required { "*" } else { " " };
            let style = if sel { theme::selected() } else { theme::bg() };
            info_lines.push(Line::from(Span::styled(
                format!(
                    "{req}{:<12} {:<16} ({}){} def={}",
                    o.name,
                    o.value,
                    o.opt_type,
                    if o.advanced { " adv" } else { "" },
                    o.default
                ),
                style,
            )));
        }
    } else {
        info_lines.push(Line::from(Span::styled("select a module", theme::muted())));
    }
    frame.render_widget(
        Paragraph::new(info_lines)
            .block(pane(" info ", false))
            .wrap(Wrap { trim: true }),
        cols[1],
    );
}

fn draw_sessions(frame: &mut Frame, app: &App, area: Rect) {
    let rows =
        Layout::vertical([Constraint::Percentage(45), Constraint::Percentage(55)]).split(area);
    let mut lines = Vec::new();
    for (i, s) in app.snap.sessions.iter().enumerate() {
        let sel = i == app.session_idx;
        let style = if sel { theme::selected() } else { theme::bg() };
        let mark = if sel { "▸" } else { " " };
        lines.push(Line::from(Span::styled(
            format!(
                "{mark} {:>3} {:<12} {:<16} {:<10} {}  {}",
                s.id,
                s.kind,
                s.session_host,
                s.platform,
                s.workspace,
                truncate(&s.info, 28)
            ),
            style,
        )));
        lines.push(Line::from(Span::styled(
            format!(
                "     via {} ({})  {} → {}  {}  routes {}",
                s.via_exploit,
                s.via_payload,
                s.tunnel_local,
                s.tunnel_peer,
                s.arch,
                if s.routes.is_empty() { "-" } else { &s.routes }
            ),
            theme::muted(),
        )));
    }
    if lines.is_empty() {
        lines.push(Line::from(Span::styled("no sessions", theme::muted())));
    }
    frame.render_widget(
        Paragraph::new(lines).block(pane(" sessions  i interact  Ctrl-G stop ", true)),
        rows[0],
    );

    let sid = app
        .snap
        .sessions
        .get(app.session_idx)
        .map(|s| s.id.as_str())
        .unwrap_or("");
    let io = app.session_io.get(sid).cloned().unwrap_or_default();
    let tail = tail_lines(&io, 12);
    let mut body: Vec<Line> = tail
        .iter()
        .map(|l| Line::from(Span::styled(l.as_str(), theme::ok())))
        .collect();
    if app.interact {
        body.push(Line::from(Span::styled(
            format!("> {}_", app.session_in.value),
            theme::accent(),
        )));
    } else {
        body.push(Line::from(Span::styled(
            "press i to interact",
            theme::muted(),
        )));
    }
    frame.render_widget(
        Paragraph::new(body).block(pane(" interact ", app.interact)),
        rows[1],
    );
}

fn draw_creds(frame: &mut Frame, app: &App, area: Rect) {
    let cols =
        Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).split(area);
    let mut cl = vec![Line::from(Span::styled(
        format!("redact={}  x toggle  Ctrl-G reuse", app.report_redact),
        theme::muted(),
    ))];
    for (i, c) in app.snap.creds.iter().enumerate() {
        let sel = i == app.cred_idx && app.cred_pane == CredPane::Creds;
        let pass = if app.report_redact {
            "••••"
        } else {
            c.pass.as_str()
        };
        cl.push(Line::from(Span::styled(
            format!(
                "{} {:<16} {:<8} {} {}\\{}  {}",
                if sel { "▸" } else { " " },
                c.host,
                c.service,
                c.kind,
                c.realm,
                c.user,
                pass
            ),
            if sel { theme::selected() } else { theme::bg() },
        )));
    }
    if app.snap.creds.is_empty() {
        cl.push(Line::from(Span::styled("no credentials", theme::muted())));
    }
    frame.render_widget(
        Paragraph::new(cl).block(pane(" credentials ", app.cred_pane == CredPane::Creds)),
        cols[0],
    );

    let mut ll = Vec::new();
    for (i, l) in app.snap.loot.iter().enumerate() {
        let sel = i == app.loot_idx && app.cred_pane == CredPane::Loot;
        ll.push(Line::from(Span::styled(
            format!(
                "{} {} {} {} {} {}",
                if sel { "▸" } else { " " },
                l.host,
                l.ltype,
                l.name,
                l.info,
                l.path
            ),
            if sel { theme::selected() } else { theme::bg() },
        )));
    }
    if ll.is_empty() {
        ll.push(Line::from(Span::styled("no loot", theme::muted())));
    }
    frame.render_widget(
        Paragraph::new(ll).block(pane(" loot ", app.cred_pane == CredPane::Loot)),
        cols[1],
    );
}

fn draw_tasks(frame: &mut Frame, app: &App, area: Rect) {
    let cols =
        Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)]).split(area);
    let mut jobs = Vec::new();
    for (i, j) in app.snap.jobs.iter().enumerate() {
        let sel = i == app.job_idx;
        jobs.push(Line::from(Span::styled(
            format!("{} {:>3} {}", if sel { "▸" } else { " " }, j.id, j.name),
            if sel { theme::selected() } else { theme::bg() },
        )));
    }
    if jobs.is_empty() {
        jobs.push(Line::from(Span::styled("no jobs", theme::muted())));
    }
    frame.render_widget(
        Paragraph::new(jobs).block(pane(" jobs  Ctrl-G stop ", true)),
        cols[0],
    );

    let mut tasks = Vec::new();
    for (i, t) in app.tasks.iter().enumerate() {
        let sel = i == app.task_idx;
        tasks.push(Line::from(Span::styled(
            format!(
                "{} {} {:<10} {:<8} {}",
                if sel { "▸" } else { " " },
                t.started,
                t.kind,
                t.status,
                truncate(&t.summary, 36)
            ),
            if sel { theme::selected() } else { theme::bg() },
        )));
        if !t.detail.is_empty() && sel {
            for line in t.detail.lines().take(8) {
                tasks.push(Line::from(Span::styled(
                    format!("    {line}"),
                    theme::muted(),
                )));
            }
        }
    }
    if tasks.is_empty() {
        tasks.push(Line::from(Span::styled(
            "no local tasks yet",
            theme::muted(),
        )));
    }
    frame.render_widget(
        Paragraph::new(tasks).block(pane(" task log ", false)),
        cols[1],
    );
}

fn draw_chains(frame: &mut Frame, app: &App, area: Rect) {
    let cols =
        Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).split(area);
    let mut list = Vec::new();
    for (i, c) in app.chains.iter().enumerate() {
        let sel = i == app.chain_idx;
        list.push(Line::from(Span::styled(
            format!("{} {}", if sel { "▸" } else { " " }, c.summary()),
            if sel { theme::selected() } else { theme::bg() },
        )));
    }
    if list.is_empty() {
        list.push(Line::from(Span::styled("no chains", theme::muted())));
    }
    frame.render_widget(
        Paragraph::new(list).block(pane(" chains  Ctrl-G run ", true)),
        cols[0],
    );
    let mut steps = Vec::new();
    if let Some(c) = app.chains.get(app.chain_idx) {
        steps.push(Line::from(Span::styled(
            format!("on_fail={}", c.on_fail),
            theme::muted(),
        )));
        for (i, st) in c.steps.iter().enumerate() {
            steps.push(Line::from(Span::styled(
                format!("  {}. {}", i + 1, Chain::step_label(st)),
                theme::ok(),
            )));
        }
    }
    frame.render_widget(Paragraph::new(steps).block(pane(" steps ", false)), cols[1]);
}

fn draw_reports(frame: &mut Frame, app: &App, area: Rect) {
    let lines = vec![
        Line::from(Span::styled("Workspace report", theme::title())),
        Line::from(""),
        Line::from(format!("workspace  {}", empty(&app.snap.workspace))),
        Line::from(format!("hosts      {}", app.snap.hosts.len())),
        Line::from(format!("sessions   {}", app.snap.sessions.len())),
        Line::from(format!("creds      {}", app.snap.creds.len())),
        Line::from(format!("loot       {}", app.snap.loot.len())),
        Line::from(format!(
            "redact secrets  {}   (x toggles)",
            app.report_redact
        )),
        Line::from(""),
        Line::from(Span::styled(
            "Ctrl-G writes HTML + Markdown + JSON under",
            theme::muted(),
        )),
        Line::from(Span::styled(
            app.paths.reports.display().to_string(),
            theme::ip(),
        )),
        Line::from(""),
        Line::from(Span::styled(
            if app.last_report.is_empty() {
                "no report generated this session".into()
            } else {
                format!("last {}", app.last_report)
            },
            theme::ok(),
        )),
    ];
    frame.render_widget(Paragraph::new(lines).block(pane(" reports ", true)), area);
}

fn draw_console(frame: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::vertical([Constraint::Min(4), Constraint::Length(3)]).split(area);
    let tail = tail_lines(&app.console, (rows[0].height.saturating_sub(2)) as usize);
    let body: Vec<Line> = tail
        .iter()
        .map(|l| Line::from(Span::styled(l.as_str(), theme::ok())))
        .collect();
    frame.render_widget(
        Paragraph::new(body).block(pane(" msfconsole ", true)),
        rows[0],
    );
    let prompt = Paragraph::new(Line::from(vec![
        Span::styled(" msf6 > ", theme::accent()),
        Span::styled(&app.console_in.value, theme::flag()),
        Span::styled("█", theme::accent()),
    ]))
    .block(pane(" input  Enter send  Esc dash ", true));
    frame.render_widget(prompt, rows[1]);
}

fn draw_wizards(frame: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::horizontal([Constraint::Length(28), Constraint::Min(40)]).split(area);
    let mut list = Vec::new();
    for (i, w) in WizardKind::all().into_iter().enumerate() {
        let sel = w == app.wizard;
        list.push(Line::from(Span::styled(
            format!("{} {}", if sel { "▸" } else { " " }, w.title()),
            if sel { theme::selected() } else { theme::bg() },
        )));
        let _ = i;
    }
    frame.render_widget(
        Paragraph::new(list).block(pane(" wizards  Tab ", true)),
        cols[0],
    );

    let right = match app.wizard {
        WizardKind::Pentest => vec![
            Line::from(Span::styled("Quick pentest", theme::title())),
            Line::from(Span::styled(
                "Discover → plan → (you confirm exploit) → report",
                theme::muted(),
            )),
            Line::from(""),
            field(0, app.wiz_field, "RHOSTS", &app.pentest_rhosts),
            field(1, app.wiz_field, "ports", &app.pentest_ports),
            Line::from(""),
            Line::from(Span::styled("Enter edit  Ctrl-G start", theme::muted())),
        ],
        WizardKind::Validate => vec![
            Line::from(Span::styled("Vulnerability validation", theme::title())),
            Line::from(Span::styled(
                "Import a scan, match modules by CVE/service, review plan.",
                theme::muted(),
            )),
            Line::from(""),
            field(0, app.wiz_field, "import", &app.import_path),
            Line::from(""),
            Line::from(Span::styled("Ctrl-G import + build plan", theme::muted())),
        ],
        WizardKind::CredReuse => vec![
            Line::from(Span::styled("Credential reuse", theme::title())),
            Line::from(format!("{} stored creds", app.snap.creds.len())),
            Line::from(Span::styled(
                "Runs Framework login scanners (ssh/smb/ftp/mysql) with stored creds.",
                theme::muted(),
            )),
            Line::from(""),
            Line::from(Span::styled("Ctrl-G launch", theme::muted())),
        ],
        WizardKind::Payload => vec![
            Line::from(Span::styled("msfvenom wrapper", theme::title())),
            field(0, app.wiz_field, "payload", &app.venom.payload),
            field(1, app.wiz_field, "LHOST", &app.venom.lhost),
            field(2, app.wiz_field, "LPORT", &app.venom.lport),
            field(3, app.wiz_field, "format", &app.venom.format),
            field(4, app.wiz_field, "encoder", &app.venom.encoder),
            field(5, app.wiz_field, "outfile", &app.venom.outfile),
            Line::from(""),
            Line::from(Span::styled(app.venom.preview(), theme::flag())),
            Line::from(Span::styled("Ctrl-G spawn msfvenom", theme::muted())),
        ],
        WizardKind::Evidence => {
            let mut v = vec![
                Line::from(Span::styled("Post-exploit evidence macros", theme::title())),
                Line::from(Span::styled(
                    "Runs post modules on the selected session (4 Sess).",
                    theme::muted(),
                )),
                Line::from(""),
            ];
            for (i, m) in app.macros.iter().enumerate() {
                let sel = i == app.macro_idx;
                v.push(Line::from(Span::styled(
                    format!(
                        "{} {} ({}) {} steps",
                        if sel { "▸" } else { " " },
                        m.name,
                        m.platform,
                        m.steps.len()
                    ),
                    if sel { theme::selected() } else { theme::bg() },
                )));
            }
            v.push(Line::from(Span::styled(
                "m next macro  Ctrl-G run",
                theme::muted(),
            )));
            v
        }
        WizardKind::AutoPlan => {
            let mut v = vec![
                Line::from(Span::styled(
                    format!(
                        "Auto-exploit plan  min={}  space toggle  a rebuild  +/- rank",
                        app.min_rank.as_str()
                    ),
                    theme::title(),
                )),
                Line::from(Span::styled(
                    "Nothing runs until you Ctrl-G. Matches CVE refs, then open ports.",
                    theme::muted(),
                )),
                Line::from(""),
            ];
            if app.plan.is_empty() {
                v.push(Line::from(Span::styled(
                    "no matches — import hosts or press a to rebuild",
                    theme::warn(),
                )));
            }
            for (i, p) in app.plan.iter().enumerate() {
                let sel = i == app.plan_idx;
                let mark = if p.selected { "[x]" } else { "[ ]" };
                v.push(Line::from(Span::styled(
                    format!(
                        "{} {} {:<16} {:<8} {}  {}",
                        if sel { "▸" } else { " " },
                        mark,
                        p.host,
                        p.rank,
                        p.module,
                        p.reason
                    ),
                    if sel {
                        theme::selected()
                    } else if p.selected {
                        theme::ok()
                    } else {
                        theme::muted()
                    },
                )));
            }
            v
        }
    };
    frame.render_widget(
        Paragraph::new(right)
            .block(pane(" wizard ", true))
            .wrap(Wrap { trim: true }),
        cols[1],
    );
}

fn field<'a>(idx: usize, cur: usize, label: &'a str, value: &'a str) -> Line<'a> {
    let sel = idx == cur;
    Line::from(Span::styled(
        format!(
            "  {:<10} {}",
            label,
            if value.is_empty() { "…" } else { value }
        ),
        if sel { theme::selected() } else { theme::bg() },
    ))
}

fn draw_help(frame: &mut Frame, area: Rect, scroll: u16) {
    let rect = centered(area, 80, 85);
    frame.render_widget(Clear, rect);
    frame.render_widget(
        Paragraph::new(App::help_text())
            .style(theme::bg())
            .scroll((scroll, 0))
            .wrap(Wrap { trim: false })
            .block(
                Block::bordered()
                    .border_style(Style::default().fg(theme::pink()))
                    .title(Span::styled(" help  Esc ", theme::title())),
            ),
        rect,
    );
}

fn draw_confirm(frame: &mut Frame, area: Rect, title: &str, body: &str) {
    let rect = centered(area, 70, 40);
    frame.render_widget(Clear, rect);
    let text = format!("{body}\n\nEnter/y confirm   Esc/n cancel");
    frame.render_widget(
        Paragraph::new(text)
            .style(theme::bg())
            .wrap(Wrap { trim: true })
            .alignment(Alignment::Left)
            .block(
                Block::bordered()
                    .border_style(Style::default().fg(theme::orange()))
                    .title(Span::styled(format!(" {title} "), theme::warn())),
            ),
        rect,
    );
}

fn draw_prompt(frame: &mut Frame, area: Rect, title: &str, value: &str, cursor: usize) {
    let rect = centered(area, 70, 20);
    frame.render_widget(Clear, rect);
    let mut shown = value.to_string();
    let byte = value
        .char_indices()
        .nth(cursor)
        .map(|(i, _)| i)
        .unwrap_or(value.len());
    shown.insert(byte, '▌');
    let cursor_column = unicode_width::UnicodeWidthStr::width(&shown[..byte]);
    let offset = cursor_column
        .saturating_sub(rect.width.saturating_sub(4) as usize)
        .min(u16::MAX as usize) as u16;

    frame.render_widget(
        Paragraph::new(shown)
            .scroll((0, offset))
            .style(theme::bg())
            .block(
                Block::bordered()
                    .border_style(Style::default().fg(theme::pink()))
                    .title(Span::styled(format!(" {title} "), theme::accent())),
            ),
        rect,
    );
}

fn centered(area: Rect, pct_x: u16, pct_y: u16) -> Rect {
    let v = Layout::vertical([
        Constraint::Percentage((100 - pct_y) / 2),
        Constraint::Percentage(pct_y),
        Constraint::Percentage((100 - pct_y) / 2),
    ])
    .split(area);
    Layout::horizontal([
        Constraint::Percentage((100 - pct_x) / 2),
        Constraint::Percentage(pct_x),
        Constraint::Percentage((100 - pct_x) / 2),
    ])
    .split(v[1])[1]
}

fn truncate(s: &str, n: usize) -> String {
    use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};
    if s.width() <= n {
        return s.to_owned();
    }
    if n == 0 {
        return String::new();
    }
    let mut text = String::new();
    let mut width = 0;
    for c in s.chars() {
        let next = c.width().unwrap_or(0);
        if width + next > n - 1 {
            break;
        }
        text.push(c);
        width += next;
    }
    text.push('…');
    text
}

fn ts_short(ts: &str) -> String {
    if let Some(short) = ts.get(11..19) {
        short.to_string()
    } else {
        ts.to_string()
    }
}

fn empty(s: &str) -> &str {
    if s.is_empty() { "—" } else { s }
}

fn wrap_desc(s: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    for w in s.split_whitespace() {
        if cur.len() + w.len() + 1 > width {
            lines.push(cur);
            cur = w.to_string();
        } else {
            if !cur.is_empty() {
                cur.push(' ');
            }
            cur.push_str(w);
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    lines
}

fn tail_lines(s: &str, n: usize) -> Vec<String> {
    let lines: Vec<&str> = s.lines().collect();
    lines
        .iter()
        .skip(lines.len().saturating_sub(n))
        .map(|l| l.to_string())
        .collect()
}

#[cfg(test)]
mod aurora_audit {
    use super::*;
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::{Terminal, backend::TestBackend};
    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }
    fn commands() -> KeyEvent {
        KeyEvent::new(KeyCode::Char('k'), KeyModifiers::CONTROL)
    }
    fn fixture(dir: &std::path::Path) -> App {
        for name in ["chains", "macros", "reports", "cache"] {
            std::fs::create_dir_all(dir.join(name)).unwrap();
        }
        let paths = crate::persist::Paths {
            data: dir.into(),
            config_dir: dir.into(),
            config: dir.join("config.toml"),
            audit: dir.join("audit.jsonl"),
            chains: dir.join("chains"),
            macros: dir.join("macros"),
            reports: dir.join("reports"),
            favorites: dir.join("favorites.toml"),
            cache: dir.join("cache"),
        };
        let mut app = App::with_paths(true, paths).unwrap();
        app.tab = Tab::Hosts;
        app
    }
    #[test]
    fn hosts_cycle_both_ways_and_inputs_own_commands() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = fixture(dir.path());
        app.handle_key(key(KeyCode::Tab));
        assert!(app.host_pane == HostPane::Detail);
        app.handle_key(key(KeyCode::Tab));
        assert!(app.host_pane == HostPane::List);
        app.handle_key(key(KeyCode::Char('/')));
        app.handle_key(commands());
        assert!(!app.commands.open);
        app.handle_key(key(KeyCode::Esc));
        app.handle_key(commands());
        assert!(app.commands.open);
        assert!(app.demo);
    }
    #[test]
    fn responsive_render_matrix() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = fixture(dir.path());
        // One terminal exercises shrink/grow transitions, rather than independent initial frames.
        let mut resizing = Terminal::new(TestBackend::new(120, 40)).unwrap();
        for &(w, h) in &[
            (120, 40),
            (60, 20),
            (80, 24),
            (30, 10),
            (100, 30),
            (120, 40),
        ] {
            resizing.backend_mut().resize(w, h);
            resizing.draw(|f| draw(f, &app)).unwrap();
            assert_eq!(resizing.backend().buffer().area.width, w);
        }
        for &(w, h) in crate::audit::SIZES {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|f| draw(f, &app)).unwrap();
            let buffer = term.backend().buffer();
            if w >= 30 && h >= 10 {
                assert!(crate::audit::text(buffer).contains("breach"));
            }
            crate::audit::capture("breach", "main", buffer);
        }
        app.host_pane = HostPane::Detail;
        for &(w, h) in &crate::audit::SIZES[..4] {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|f| draw(f, &app)).unwrap();
            crate::audit::capture("breach", "focused", term.backend().buffer());
        }
        app.handle_key(commands());
        for &(w, h) in &crate::audit::SIZES[..4] {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|f| draw(f, &app)).unwrap();
            let buffer = term.backend().buffer();
            assert!(crate::audit::text(buffer).contains("Actions"));
            crate::audit::capture("breach", "actions", buffer);
        }
        app.commands.open = false;
        app.snap = Default::default();
        app.connected = false;
        app.host_pane = HostPane::List;
        for tab in Tab::all() {
            app.tab = tab;
            for &(w, h) in &crate::audit::SIZES[..4] {
                let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
                term.draw(|f| draw(f, &app)).unwrap();
                crate::audit::capture("breach", "offline", term.backend().buffer());
            }
        }
    }
}

#[cfg(test)]
mod unicode_regressions {
    use super::*;
    #[test]
    fn labels_fit_display_columns() {
        use unicode_width::UnicodeWidthStr;
        for width in 0..10 {
            assert!(truncate("你好 🦀 cafe\u{301}", width).width() <= width);
        }
    }
}
