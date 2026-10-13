use crate::app::{App, CredPane, HostPane, Modal, Tab, WizardKind};
use crate::chains::Chain;
use crate::model::ModuleKind;
use crate::theme;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, List, ListItem, ListState, Paragraph, Wrap};

pub fn draw(frame: &mut Frame, app: &App) {
    app.navigation.begin(frame.area());
    let area = frame.area();
    frame.render_widget(Block::default().style(theme::bg()), area);

    if area.width < 30 || area.height < 14 {
        frame.render_widget(
            Paragraph::new("breach · needs 30×14\nResize terminal; q quits"),
            area,
        );
        return;
    }
    let chrome = chrome();
    let area = chrome.shell(frame, area);
    let title_h = crate::aurora::title_height(area.height);
    let nav_h = 3;
    let context_h = if area.height >= 26 { 2 } else { 1 };
    let chunks = Layout::vertical([
        Constraint::Length(title_h + nav_h + context_h),
        Constraint::Min(1),
        Constraint::Length(if area.height >= 26 { 4 } else { 3 }),
    ])
    .split(area);

    draw_header(frame, app, chunks[0]);
    let body = crate::aurora::body(chunks[1]);
    match app.tab {
        Tab::Dash => draw_dash(frame, app, body),
        Tab::Hosts => draw_hosts(frame, app, body),
        Tab::Modules => draw_modules(frame, app, body),
        Tab::Sessions => draw_sessions(frame, app, body),
        Tab::Creds => draw_creds(frame, app, body),
        Tab::Tasks => draw_tasks(frame, app, body),
        Tab::Chains => draw_chains(frame, app, body),
        Tab::Reports => draw_reports(frame, app, body),
        Tab::Console => draw_console(frame, app, body),
        Tab::Wizards => draw_wizards(frame, app, body),
    }
    let footer = chrome.footer(frame, chunks[2]);
    draw_status(frame, app, footer);

    if app.filtering {
        draw_prompt(frame, area, "filter", &app.edit.value, app.edit.cursor);
    }
    match &app.modal {
        Modal::None => {}
        Modal::Help => draw_help(frame, area, app.help_scroll),
        Modal::Confirm { title, body, .. } => {
            draw_confirm(frame, area, title, body, app.help_scroll)
        }
        Modal::Message { title, body } => draw_confirm(frame, area, title, body, app.help_scroll),
        Modal::Edit { title, .. } => {
            draw_prompt(frame, area, title, &app.edit.value, app.edit.cursor);
        }
    }
    if matches!(app.modal, Modal::Confirm { .. }) {
        let popup = centered(area, 70, 40);
        app.navigation
            .dialog_buttons(frame, popup, app.navigation_skin());
    }
    app.commands.draw(
        frame,
        &app.command_actions(),
        theme::bg_color(),
        theme::fg(),
        theme::purple(),
        theme::selected().bg.unwrap_or(theme::current()),
    );
    app.draw_navigation(frame);
}

fn chrome() -> crate::aurora::Chrome {
    crate::aurora::Chrome {
        base: theme::bg(),
        muted: theme::muted(),
        accent: theme::title(),
        data: theme::ip(),
        border: Style::default().fg(theme::comment()),
        deep: Style::default().bg(theme::deep()).fg(theme::fg()),
    }
}

fn draw_header(frame: &mut Frame, app: &App, area: Rect) {
    let height = frame.area().height.saturating_sub(2);
    let [identity, tabs, context] = Layout::vertical([
        Constraint::Length(crate::aurora::title_height(height)),
        Constraint::Length(3),
        Constraint::Min(0),
    ])
    .areas(area);
    let state = if app.demo {
        "○ demo"
    } else if app.connected {
        "● RPC connected"
    } else {
        "○ RPC offline"
    };
    chrome().title(
        frame,
        identity,
        "breach",
        "Metasploit / workspace lab",
        state,
        if app.connected || app.demo {
            theme::ok()
        } else {
            theme::err()
        },
    );
    app.navigation_bar(frame, tabs);
    let context = Block::default()
        .padding(ratatui::widgets::Padding::horizontal(2))
        .inner(context);
    let [workspace, counts] = Layout::horizontal([
        Constraint::Min(1),
        Constraint::Length(34.min(context.width / 2)),
    ])
    .areas(context);
    frame.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("Workspace ", theme::muted()),
            Span::styled(
                if app.snap.workspace.is_empty() {
                    "—"
                } else {
                    &app.snap.workspace
                },
                theme::ip(),
            ),
        ])),
        workspace,
    );
    frame.render_widget(
        Paragraph::new(format!(
            "Hosts {}  Sessions {}  Jobs {}",
            app.snap.hosts.len(),
            app.snap.sessions.len(),
            app.snap.jobs.len()
        ))
        .style(theme::muted())
        .alignment(Alignment::Right),
        counts,
    );
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let [keys, status] =
        Layout::vertical([Constraint::Length(1), Constraint::Length(1)]).areas(area);
    frame.render_widget(
        Paragraph::new(crate::navigation::shortcuts(
            &app.footer_hints(),
            keys.width,
            theme::title(),
            theme::muted(),
        ))
        .style(chrome().deep),
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
    ]);
    frame.render_widget(Paragraph::new(line).style(chrome().deep), area);
}

fn pane(title: &str, focused: bool) -> Block<'_> {
    Block::bordered()
        .border_type(ratatui::widgets::BorderType::Rounded)
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
    let cols = if area.width < 80 {
        if app.focused_pane() == 0 {
            [area, Rect::default()]
        } else {
            [Rect::default(), area]
        }
    } else {
        Layout::horizontal([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(area)
    };
    app.navigation.pane(cols[0], 0);
    app.navigation.pane(cols[1], 1);
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
        Paragraph::new(left)
            .scroll((app.detail_scroll, 0))
            .block(pane(" overview ", app.focused_pane() == 0)),
        cols[0],
    );

    let mut right = vec![Line::from(Span::styled("Recent activity", theme::title()))];
    if app.audit.is_empty() {
        right.push(Line::from(Span::styled("  (empty)", theme::muted())));
    }
    for e in app.audit.iter().rev() {
        right.push(Line::from(vec![
            Span::styled(format!("  {} ", ts_short(&e.ts)), theme::muted()),
            Span::styled(&e.action, theme::flag()),
            Span::styled(format!(" {}", truncate(&e.detail, 40)), theme::muted()),
        ]));
    }
    frame.render_widget(
        Paragraph::new(right)
            .scroll((app.detail_scroll, 0))
            .block(pane(" audit ", app.focused_pane() == 1)),
        cols[1],
    );
    app.navigation.details(cols[1], 1);
}

fn draw_hosts(frame: &mut Frame, app: &App, area: Rect) {
    let [list_area, details] = if area.width < 70 {
        if app.host_pane == HostPane::List {
            [area, Rect::default()]
        } else {
            [Rect::default(), area]
        }
    } else {
        let [list, _gutter, detail] = Layout::horizontal([
            Constraint::Length(if area.width >= 100 { 29 } else { 24 }),
            Constraint::Length(3),
            Constraint::Min(1),
        ])
        .areas(area);
        [list, detail]
    };
    app.navigation.pane(list_area, 0);
    app.navigation.details(details, 1);
    if !list_area.is_empty() {
        let list_area = crate::aurora::sidebar(
            frame,
            list_area,
            Style::default().fg(if app.host_pane == HostPane::List {
                theme::purple()
            } else {
                theme::comment()
            }),
        );
        let ids = app.filtered_hosts();
        let spaced = list_area.height >= 18;
        let row_h = if spaced { 3 } else { 2 };
        let compact = list_area.height < 10;
        let heading_h = if compact { 1 } else { 2 };
        let gap_h = u16::from(!compact);
        let note_h = if compact { 1 } else { 2 };
        let list_h = (ids.len() as u16 * row_h)
            .max(2)
            .min(list_area.height.saturating_sub(heading_h + gap_h + note_h));
        let [heading, list, _gap, note, _space] = Layout::vertical([
            Constraint::Length(heading_h),
            Constraint::Length(list_h),
            Constraint::Length(gap_h),
            Constraint::Length(note_h),
            Constraint::Min(0),
        ])
        .areas(list_area);
        frame.render_widget(Paragraph::new("Hosts").style(theme::title()), heading);
        let mut items = Vec::new();
        for hi in &ids {
            let host = &app.snap.hosts[*hi];
            let mut lines = vec![
                Line::from(Span::styled(
                    format!(
                        "{}{}",
                        if *hi == app.host_idx { "▸ " } else { "  " },
                        host.address
                    ),
                    if *hi == app.host_idx {
                        theme::accent()
                    } else {
                        theme::bg()
                    },
                )),
                Line::from(Span::styled(
                    format!(
                        "  {} · {} services",
                        truncate(&host.os, 18),
                        host.services.len()
                    ),
                    theme::muted(),
                )),
            ];
            if spaced {
                lines.push(Line::from(""));
            }
            items.push(ratatui::widgets::ListItem::new(lines));
        }
        if items.is_empty() {
            items.push(ratatui::widgets::ListItem::new(
                "No hosts. Import Nmap XML (i) or discover (Ctrl+G).",
            ));
        }
        let mut state = ratatui::widgets::ListState::default();
        state.select(ids.iter().position(|i| *i == app.host_idx));
        frame.render_stateful_widget(
            ratatui::widgets::List::new(items).highlight_style(theme::selected()),
            list,
            &mut state,
        );
        app.navigation.rows(
            list,
            0,
            state.offset(),
            row_h,
            ids.len().saturating_sub(state.offset()),
        );
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("(/)", theme::accent()),
                Span::styled(" filter hosts", theme::muted()),
            ])),
            note,
        );
    }

    if details.is_empty() {
        return;
    }
    let Some(host) = app.snap.hosts.get(app.host_idx) else {
        frame.render_widget(
            Paragraph::new("Select a host to inspect services and findings.").style(theme::muted()),
            details,
        );
        return;
    };
    // Compose a real card into a scrollable buffer so the review panel and all
    // service/finding/note data remain reachable in a small terminal.
    use ratatui::widgets::Widget;
    let width = details.width;
    let inner_width = width.saturating_sub(4).max(1) as usize;
    let notes: Vec<_> = app
        .snap
        .notes
        .iter()
        .filter(|n| n.host == host.address)
        .collect();
    let mut review = vec![
        Line::from(Span::styled("Review plan", theme::title())),
        Line::from(Span::styled(
            format!("{} recorded findings", host.vulns.len()),
            theme::bg(),
        )),
    ];
    for finding in &host.vulns {
        review.push(Line::from(Span::styled(
            format!(
                "{} [{}] {}",
                finding.name,
                finding.refs.join(", "),
                finding.info
            ),
            theme::warn(),
        )));
    }
    review.push(Line::from(Span::styled(
        "Inspect evidence and module matches before execution.",
        theme::muted(),
    )));
    review.push(Line::from(vec![
        Span::styled("(a)", theme::accent()),
        Span::styled(" Build review plan", theme::bg()),
    ]));
    let review_h = review
        .iter()
        .map(|line| line.width().div_ceil(inner_width).max(1))
        .sum::<usize>() as u16
        + 2;
    let service_rows = if details.height >= 22 { 2 } else { 1 };
    let services_h = 2 + host.services.len() as u16 * service_rows;
    let notes_h = if notes.is_empty() {
        0
    } else {
        3 + notes
            .iter()
            .map(|n| {
                (n.ntype.len() + n.data.len() + 1)
                    .div_ceil(width.max(1) as usize)
                    .max(1)
            })
            .sum::<usize>() as u16
    };
    let meta_h = 3;
    let height = meta_h + services_h + 1 + review_h + notes_h;
    let mut buffer = ratatui::buffer::Buffer::empty(Rect::new(0, 0, width, height));
    Block::default()
        .style(theme::bg())
        .render(buffer.area, &mut buffer);
    let [metadata, services, _gap, card, notes_area] = Layout::vertical([
        Constraint::Length(meta_h),
        Constraint::Length(services_h),
        Constraint::Length(1),
        Constraint::Length(review_h),
        Constraint::Length(notes_h),
    ])
    .areas(buffer.area);
    let [name, alive] = Layout::horizontal([Constraint::Min(1), Constraint::Length(11)])
        .areas(Rect::new(0, 0, width, 1));
    Paragraph::new(host.address.as_str())
        .style(theme::title())
        .render(name, &mut buffer);
    let up = host.services.iter().any(|service| service.state == "open");
    Paragraph::new(if up { "● alive" } else { "○ inactive" })
        .style(if up { theme::ok() } else { theme::muted() })
        .alignment(Alignment::Right)
        .render(alive, &mut buffer);
    let meta = vec![Line::from(vec![
        Span::styled(host.os.as_str(), theme::hostname()),
        Span::styled(
            format!(" · {} · {} · {}", host.name, host.purpose, host.info),
            theme::muted(),
        ),
    ])];
    Paragraph::new(meta).wrap(Wrap { trim: false }).render(
        Rect::new(0, 1, width, metadata.height.saturating_sub(1)),
        &mut buffer,
    );
    let mut service_lines = vec![
        Line::from(Span::styled("Services", theme::title())),
        Line::from(""),
    ];
    for service in &host.services {
        service_lines.push(Line::from(vec![
            Span::styled(
                format!("{:<12}", format!("{}/{}", service.port, service.proto)),
                theme::ip(),
            ),
            Span::styled(
                format!("{:<14}", service.name),
                if service.state == "open" {
                    theme::bg()
                } else {
                    theme::muted()
                },
            ),
            Span::styled(
                format!(
                    "{}{}",
                    service.info,
                    if service.state == "open" {
                        String::new()
                    } else {
                        format!(" · {}", service.state)
                    }
                ),
                theme::muted(),
            ),
        ]));
        if service_rows == 2 {
            service_lines.push(Line::from(Span::styled(
                "─".repeat(width as usize),
                Style::default().fg(theme::comment()),
            )));
        }
    }
    Paragraph::new(service_lines)
        .wrap(Wrap { trim: false })
        .render(services, &mut buffer);
    let block = Block::bordered()
        .border_type(ratatui::widgets::BorderType::Rounded)
        .border_style(Style::default().fg(if app.host_pane == HostPane::Detail {
            theme::purple()
        } else {
            theme::comment()
        }))
        .padding(ratatui::widgets::Padding::horizontal(1));
    let inner = block.inner(card);
    block.render(card, &mut buffer);
    Paragraph::new(review)
        .wrap(Wrap { trim: false })
        .render(inner, &mut buffer);
    if !notes.is_empty() {
        let mut lines = vec![
            Line::from(""),
            Line::from(Span::styled("Notes", theme::title())),
            Line::from(""),
        ];
        for note in notes {
            lines.push(Line::from(Span::styled(
                format!("{} {}", note.ntype, note.data),
                theme::muted(),
            )));
        }
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .render(notes_area, &mut buffer);
    }
    let scroll = app.detail_scroll.min(height.saturating_sub(details.height));
    for y in 0..details.height.min(height.saturating_sub(scroll)) {
        for x in 0..width {
            frame.buffer_mut()[(details.x + x, details.y + y)] = buffer[(x, y + scroll)].clone();
        }
    }
}

fn draw_modules(frame: &mut Frame, app: &App, area: Rect) {
    let cols = if area.width < 80 {
        if app.focused_pane() == 0 {
            [area, Rect::default()]
        } else {
            [Rect::default(), area]
        }
    } else {
        Layout::horizontal([Constraint::Percentage(48), Constraint::Percentage(52)]).areas(area)
    };
    app.navigation.pane(cols[0], 0);
    app.navigation.pane(cols[1], 1);
    if !cols[0].is_empty() {
        let block = pane(" Modules · (t) type ", app.focused_pane() == 0);
        let inner = block.inner(cols[0]);
        frame.render_widget(block, cols[0]);
        let [selector, list] =
            Layout::vertical([Constraint::Length(2.min(inner.height)), Constraint::Min(0)])
                .areas(inner);
        let types = [
            ("Exploit", ModuleKind::Exploit),
            ("Auxiliary", ModuleKind::Auxiliary),
            ("Post", ModuleKind::Post),
            ("Payload", ModuleKind::Payload),
            ("Encoder", ModuleKind::Encoder),
        ];
        let current = types
            .iter()
            .position(|(_, k)| *k == app.module_kind)
            .unwrap_or(0);
        let text = format!(
            "‹ {} › · {} modules",
            types[current].0,
            app.current_modules().len()
        );
        frame.render_widget(Paragraph::new(text).style(theme::title()), selector);
        app.navigation.hit(
            selector,
            crate::navigation::Intent::Command("Module type picker"),
        );
        let items = app
            .current_modules()
            .iter()
            .map(|n| {
                ListItem::new(format!(
                    "{} {}",
                    if app.is_favorite(n) { "★" } else { " " },
                    n
                ))
            })
            .collect();
        app.navigation
            .list(frame, list, 0, items, app.module_idx, app.navigation_skin());
    }
    if cols[1].is_empty() {
        return;
    }
    let block = pane(
        " Options / details · (Enter) edit ",
        app.focused_pane() == 1,
    );
    let inner = block.inner(cols[1]);
    frame.render_widget(block, cols[1]);
    let [info, options] =
        Layout::vertical([Constraint::Percentage(45), Constraint::Min(3)]).areas(inner);
    app.navigation.details(info, 1);
    if let Some(module) = &app.module_info {
        let details = format!(
            "{}/{}\n{} · rank {}\n{}\n\n{}",
            module.kind,
            module.fullname,
            module.name,
            module.rank,
            module.refs.join(" "),
            module.description
        );
        frame.render_widget(
            Paragraph::new(details)
                .wrap(Wrap { trim: false })
                .scroll((app.detail_scroll, 0))
                .style(theme::muted()),
            info,
        );
        let items = module
            .options
            .iter()
            .map(|o| {
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("{}{} ", if o.required { "*" } else { " " }, o.name),
                        theme::title(),
                    ),
                    Span::styled(
                        format!(
                            "{} ({}){} def={}",
                            o.value,
                            o.opt_type,
                            if o.advanced { " adv" } else { "" },
                            o.default
                        ),
                        theme::bg(),
                    ),
                ]))
            })
            .collect();
        app.navigation.list(
            frame,
            options,
            1,
            items,
            app.option_idx,
            app.navigation_skin(),
        );
    } else {
        frame.render_widget(
            Paragraph::new("Select a module to view its options").style(theme::muted()),
            info,
        );
    }
}

fn draw_sessions(frame: &mut Frame, app: &App, area: Rect) {
    let rows = if area.width < 80 {
        if app.focused_pane() == 0 {
            [area, Rect::default()]
        } else {
            [Rect::default(), area]
        }
    } else {
        Layout::vertical([Constraint::Percentage(45), Constraint::Percentage(55)]).areas(area)
    };
    app.navigation.pane(rows[0], 0);
    app.navigation.pane(rows[1], 1);
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
    let block = pane(" Sessions · (Enter) interact ", app.focused_pane() == 0);
    let inner = block.inner(rows[0]);
    frame.render_widget(block, rows[0]);
    let items = lines
        .chunks(2)
        .map(|rows| ListItem::new(rows.to_vec()))
        .collect::<Vec<_>>();
    let mut state = ListState::default().with_selected(Some(app.session_idx));
    frame.render_stateful_widget(
        List::new(items).highlight_style(theme::selected()),
        inner,
        &mut state,
    );
    app.navigation.rows(
        inner,
        0,
        state.offset(),
        2,
        app.snap.sessions.len().saturating_sub(state.offset()),
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
        Paragraph::new(body).block(pane(" interact ", app.focused_pane() == 1)),
        rows[1],
    );

    app.navigation.details(rows[1], 1);
}

fn draw_creds(frame: &mut Frame, app: &App, area: Rect) {
    let cols = if area.width < 80 {
        if app.focused_pane() == 0 {
            [area, Rect::default()]
        } else {
            [Rect::default(), area]
        }
    } else {
        Layout::horizontal([Constraint::Percentage(55), Constraint::Percentage(45)]).areas(area)
    };
    app.navigation.pane(cols[0], 0);
    app.navigation.pane(cols[1], 1);
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
    let block = pane(
        " Credentials · (x) redact · (Ctrl+G) reuse ",
        app.focused_pane() == 0,
    );
    let inner = block.inner(cols[0]);
    frame.render_widget(block, cols[0]);
    let [head, list] = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(inner);
    frame.render_widget(Paragraph::new(cl.remove(0)), head);
    app.navigation.list(
        frame,
        list,
        0,
        cl.into_iter().map(ListItem::new).collect(),
        app.cred_idx,
        app.navigation_skin(),
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
    let block = pane(" Loot ", app.focused_pane() == 1);
    let inner = block.inner(cols[1]);
    frame.render_widget(block, cols[1]);
    app.navigation.list(
        frame,
        inner,
        1,
        ll.into_iter().map(ListItem::new).collect(),
        app.loot_idx,
        app.navigation_skin(),
    );
}

fn draw_tasks(frame: &mut Frame, app: &App, area: Rect) {
    let cols = if area.width < 80 {
        if app.focused_pane() == 0 {
            [area, Rect::default()]
        } else {
            [Rect::default(), area]
        }
    } else {
        Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(area)
    };
    app.navigation.pane(cols[0], 0);
    app.navigation.pane(cols[1], 1);
    if !cols[0].is_empty() {
        let block = pane(" Jobs · (Ctrl+G) stop ", app.focused_pane() == 0);
        let inner = block.inner(cols[0]);
        frame.render_widget(block, cols[0]);
        let items = app
            .snap
            .jobs
            .iter()
            .map(|j| ListItem::new(format!("{} {}", j.id, j.name)))
            .collect();
        app.navigation
            .list(frame, inner, 0, items, app.job_idx, app.navigation_skin());
    }
    if !cols[1].is_empty() {
        let block = pane(" Task log · (Ctrl+X) cancel ", app.focused_pane() == 1);
        let inner = block.inner(cols[1]);
        frame.render_widget(block, cols[1]);
        let [list, detail] = Layout::vertical([
            Constraint::Length((inner.height / 3).max(1)),
            Constraint::Min(0),
        ])
        .areas(inner);
        let items = app
            .tasks
            .iter()
            .map(|t| {
                ListItem::new(format!(
                    "{} {} · {} · {}",
                    t.started, t.kind, t.status, t.summary
                ))
            })
            .collect();
        app.navigation
            .list(frame, list, 1, items, app.task_idx, app.navigation_skin());
        app.navigation.details(detail, 1);
        let text = app
            .tasks
            .get(app.task_idx)
            .map(|t| format!("{} · {}\n{}\n{}", t.kind, t.status, t.summary, t.detail))
            .unwrap_or_else(|| "No local tasks yet".into());
        frame.render_widget(
            Paragraph::new(text)
                .wrap(Wrap { trim: false })
                .scroll((app.detail_scroll, 0))
                .style(theme::muted()),
            detail,
        );
    }
}

fn draw_chains(frame: &mut Frame, app: &App, area: Rect) {
    let cols = if area.width < 80 {
        if app.focused_pane() == 0 {
            [area, Rect::default()]
        } else {
            [Rect::default(), area]
        }
    } else {
        Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(area)
    };
    app.navigation.pane(cols[0], 0);
    app.navigation.pane(cols[1], 1);
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
    let block = pane(" Chains · (Ctrl+G) review/run ", app.focused_pane() == 0);
    let inner = block.inner(cols[0]);
    frame.render_widget(block, cols[0]);
    app.navigation.list(
        frame,
        inner,
        0,
        list.into_iter().map(ListItem::new).collect(),
        app.chain_idx,
        app.navigation_skin(),
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
    frame.render_widget(
        Paragraph::new(steps)
            .block(pane(
                " steps · (PgUp/PgDn) scroll ",
                app.focused_pane() == 1,
            ))
            .scroll((app.detail_scroll, 0)),
        cols[1],
    );

    app.navigation.details(cols[1], 1);
}

fn draw_reports(frame: &mut Frame, app: &App, area: Rect) {
    app.navigation.details(area, 0);
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
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((app.detail_scroll, 0))
            .block(pane(" reports ", true)),
        area,
    );
}

fn draw_console(frame: &mut Frame, app: &App, area: Rect) {
    let rows = Layout::vertical([Constraint::Min(4), Constraint::Length(3)]).split(area);
    app.navigation.pane(rows[0], 0);
    app.navigation.pane(rows[1], 1);
    let tail = tail_lines(&app.console, (rows[0].height.saturating_sub(2)) as usize);
    let body: Vec<Line> = tail
        .iter()
        .map(|l| Line::from(Span::styled(l.as_str(), theme::ok())))
        .collect();
    frame.render_widget(
        Paragraph::new(body).block(pane(" msfconsole ", app.focused_pane() == 0)),
        rows[0],
    );
    let prompt = Paragraph::new(Line::from(vec![
        Span::styled(" msf6 > ", theme::accent()),
        Span::styled(&app.console_in.value, theme::flag()),
        Span::styled("█", theme::accent()),
    ]))
    .block(pane(
        " input  Enter send  Esc dash ",
        app.focused_pane() == 1,
    ));
    frame.render_widget(prompt, rows[1]);
    app.navigation.details(rows[0], 0);
}

fn draw_wizards(frame: &mut Frame, app: &App, area: Rect) {
    let cols = if area.width < 80 {
        if app.focused_pane() == 0 {
            [area, Rect::default()]
        } else {
            [Rect::default(), area]
        }
    } else {
        Layout::horizontal([Constraint::Length(28), Constraint::Min(40)]).areas(area)
    };
    app.navigation.pane(cols[0], 0);
    app.navigation.pane(cols[1], 1);
    let mut list = Vec::new();
    for (i, w) in WizardKind::all().into_iter().enumerate() {
        let sel = w == app.wizard;
        list.push(Line::from(Span::styled(
            format!("{} {}", if sel { "▸" } else { " " }, w.title()),
            if sel { theme::selected() } else { theme::bg() },
        )));
        let _ = i;
    }
    let block = pane(" Wizards · (Enter) open ", app.focused_pane() == 0);
    let inner = block.inner(cols[0]);
    frame.render_widget(block, cols[0]);
    let selected = WizardKind::all()
        .iter()
        .position(|w| *w == app.wizard)
        .unwrap_or(0);
    app.navigation.list(
        frame,
        inner,
        0,
        list.into_iter().map(ListItem::new).collect(),
        selected,
        app.navigation_skin(),
    );
    if cols[1].is_empty() {
        return;
    }
    if app.wizard == WizardKind::AutoPlan {
        let block = pane(
            " review plan · (v) check · (Ctrl-G) execute ",
            app.focused_pane() == 1,
        );
        let inner = block.inner(cols[1]);
        frame.render_widget(block, cols[1]);
        let [header, list] = Layout::vertical([
            Constraint::Length(if inner.height >= 8 { 3 } else { 1 }),
            Constraint::Min(0),
        ])
        .areas(inner);
        frame.render_widget(
            Paragraph::new(vec![
                Line::from(Span::styled(
                    format!(
                        "Auto-exploit plan · min {} · {} matches",
                        app.min_rank.as_str(),
                        app.plan.len()
                    ),
                    theme::title(),
                )),
                Line::from(Span::styled(
                    "(space) select · (a) rebuild · (+/-) rank",
                    theme::muted(),
                )),
                Line::from(Span::styled(
                    "Review matches before executing or checking.",
                    theme::muted(),
                )),
            ]),
            header,
        );
        let width = list.width.saturating_sub(2).max(1) as usize;
        let items = app
            .plan
            .iter()
            .map(|p| {
                let text = format!(
                    "{} {} {} {}\n{}",
                    if p.selected { "[x]" } else { "[ ]" },
                    p.host,
                    p.rank,
                    p.module,
                    p.reason
                );
                let mut lines = Vec::new();
                for row in text.lines() {
                    let mut line = String::new();
                    let mut used = 0;
                    for ch in row.chars() {
                        let cw = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
                        if used + cw > width && !line.is_empty() {
                            lines.push(Line::from(std::mem::take(&mut line)));
                            used = 0;
                        }
                        line.push(ch);
                        used += cw;
                    }
                    lines.push(Line::from(line));
                }
                ListItem::new(lines).style(if p.selected {
                    theme::ok()
                } else {
                    theme::muted()
                })
            })
            .collect::<Vec<_>>();
        let heights = items.iter().map(ListItem::height).collect::<Vec<_>>();
        if items.is_empty() {
            frame.render_widget(
                Paragraph::new("No matches. Import hosts or (a) rebuild.").style(theme::muted()),
                list,
            );
        } else {
            let mut state =
                ListState::default().with_selected(Some(app.plan_idx.min(items.len() - 1)));
            frame.render_stateful_widget(
                List::new(items)
                    .highlight_style(theme::selected())
                    .highlight_symbol("▸ "),
                list,
                &mut state,
            );
            let offset = state.offset();
            let mut y = list.y;
            for (i, height) in heights.iter().enumerate().skip(offset) {
                if y >= list.bottom() {
                    break;
                }
                let height = (*height as u16).min(list.bottom() - y);
                app.navigation.hit(
                    Rect::new(list.x, y, list.width, height),
                    crate::navigation::Intent::Row(1, i),
                );
                y += height;
            }
        }
        return;
    }
    app.navigation.rows(
        cols[0].inner(ratatui::layout::Margin::new(1, 1)),
        0,
        0,
        1,
        WizardKind::all().len(),
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
        WizardKind::Validate => {
            let mut lines = vec![
                Line::from(Span::styled("Vulnerability validation", theme::title())),
                Line::from(Span::styled(
                    "Import vulnerabilities, match CVEs, run supported module checks.",
                    theme::muted(),
                )),
                Line::from(""),
                field(0, app.wiz_field, "import", &app.import_path),
                Line::from(""),
                Line::from(Span::styled(
                    "(Ctrl-G) import + validate · results saved in Reports",
                    theme::muted(),
                )),
            ];
            for result in app
                .validations
                .iter()
                .filter(|v| v.workspace == app.snap.workspace)
            {
                lines.push(Line::from(Span::styled(
                    format!(
                        "{} {} · {} · {}",
                        result.host, result.module, result.code, result.message
                    ),
                    if result.code == "vulnerable" {
                        theme::err()
                    } else {
                        theme::muted()
                    },
                )));
            }
            lines
        }
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
        WizardKind::AutoPlan => unreachable!("plan rendered separately"),
    };
    frame.render_widget(
        Paragraph::new(right)
            .block(pane(" wizard ", app.focused_pane() == 1))
            .scroll((app.detail_scroll, 0))
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

fn draw_confirm(frame: &mut Frame, area: Rect, title: &str, body: &str, scroll: u16) {
    let rect = centered(area, 70, 40);
    frame.render_widget(Clear, rect);
    let block = Block::bordered()
        .border_style(Style::default().fg(theme::orange()))
        .title(Span::styled(format!(" {title} "), theme::warn()))
        .style(theme::bg());
    let inner = block.inner(rect);
    frame.render_widget(block, rect);
    let text = format!("{body}\n\n(Enter/y) confirm · (Esc/n) cancel · (PgUp/PgDn) scroll");
    // Keep text above the confirmation buttons, including on compact terminals.
    let body_area = Rect::new(
        inner.x,
        inner.y,
        inner.width,
        inner.height.saturating_sub(2),
    );
    frame.render_widget(
        Paragraph::new(text)
            .scroll((scroll, 0))
            .style(theme::bg())
            .wrap(Wrap { trim: true })
            .alignment(Alignment::Left),
        body_area,
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
    fn compact_wizard_picker_and_plan_show_the_focused_content() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = fixture(dir.path());
        app.tab = Tab::Wizards;
        app.wizard = WizardKind::AutoPlan;
        app.rebuild_plan_for_test();
        let mut terminal = Terminal::new(TestBackend::new(60, 20)).unwrap();
        app.focus_pane(0);
        terminal.draw(|f| draw(f, &app)).unwrap();
        assert!(crate::audit::text(terminal.backend().buffer()).contains("Auto-exploit plan"));
        app.focus_pane(1);
        terminal.draw(|f| draw(f, &app)).unwrap();
        assert!(crate::audit::text(terminal.backend().buffer()).contains("10.0.0.12"));
    }
    #[tokio::test]
    async fn security_themes_keep_every_screen_and_pane_navigable() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = fixture(dir.path());
        for id in ["crimson", "aurora"] {
            let action = app
                .command_actions()
                .into_iter()
                .find(|a| {
                    a.label
                        == if id == "crimson" {
                            "Crimson theme"
                        } else {
                            "Aurora theme"
                        }
                })
                .expect("theme action");
            assert_eq!(action.target, crate::navigation::Intent::Theme(id));
            app.dispatch_intent(action.target);
            let screens = app
                .navigation_entries()
                .iter()
                .filter(|e| matches!(e.target, crate::navigation::Intent::Screen(_)))
                .count();
            for screen in 0..screens {
                app.select_screen(screen);
                for pane in 0..app.pane_names().len() {
                    app.focus_pane(pane);
                    for &(w, h) in &crate::audit::SIZES[..4] {
                        let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
                        terminal.draw(|f| draw(f, &app)).unwrap();
                        let buffer = terminal.backend().buffer();
                        assert!(crate::audit::text(buffer).contains("(F2)"));
                        crate::audit::verify_footer(buffer);
                        crate::audit::capture(
                            "breach",
                            &format!("{id}-screen{screen}-pane{pane}"),
                            buffer,
                        );
                    }
                }
            }
        }
    }
    #[tokio::test]
    async fn common_navigation_contract_preserves_focus_and_drafts() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = fixture(dir.path());
        app.focus_pane(0);
        if app.navigation_editing() {
            let _ = app.handle_key(key(KeyCode::Esc));
        }
        let screen = app.navigation_screen();
        let pane = app.focused_pane();
        let _ = app.handle_key(key(KeyCode::Tab));
        assert_eq!(
            app.navigation_screen(),
            crate::navigation::step(
                screen,
                app.navigation_entries()
                    .iter()
                    .filter(|e| matches!(e.target, crate::navigation::Intent::Screen(_)))
                    .count(),
                1
            )
        );
        if app.navigation_editing() {
            let _ = app.handle_key(key(KeyCode::Esc));
        }
        let _ = app.handle_key(key(KeyCode::BackTab));
        assert_eq!(app.navigation_screen(), screen);
        let _ = app.handle_key(key(KeyCode::F(6)));
        assert_eq!(
            app.focused_pane(),
            crate::navigation::step(pane, app.pane_names().len(), 1)
        );
        let _ = app.handle_key(KeyEvent::new(KeyCode::F(6), KeyModifiers::SHIFT));
        assert_eq!(app.focused_pane(), pane);
        let _ = app.handle_key(key(KeyCode::F(2)));
        assert!(app.navigation.open);
        let _ = app.handle_key(key(KeyCode::Char('1')));
        assert!(!app.navigation.open);
        assert_eq!(app.navigation_screen(), 0);
        app.select_screen(screen);
        let _ = app.handle_key(key(KeyCode::F(2)));
        assert!(app.navigation.open);

        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|f| draw(f, &app)).unwrap();
        assert!(crate::audit::text(terminal.backend().buffer()).contains("Navigate"));
        let _ = app.handle_key(key(KeyCode::Esc));
        assert!(!app.navigation.open);
        terminal.draw(|f| draw(f, &app)).unwrap();
        let buffer = terminal.backend().buffer();
        let mut hit = None;
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width.saturating_sub(3) {
                if buffer[(x, y)].symbol() == "("
                    && buffer[(x + 1, y)].symbol() == "F"
                    && buffer[(x + 2, y)].symbol() == "2"
                {
                    hit = Some((x, y));
                    break;
                }
            }
            if hit.is_some() {
                break;
            }
        }
        let (x, y) = hit.expect("visible clickable navigation");
        app.navigation_mouse(crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            column: x,
            row: y,
            modifiers: KeyModifiers::NONE,
        });
        assert!(app.navigation.open);
        let _ = app.handle_key(key(KeyCode::Esc));

        let _ = app.handle_key(commands());
        assert!(app.commands.open);
        let _ = app.handle_key(key(KeyCode::Esc));
    }
    #[tokio::test]
    async fn all_screens_and_focus_targets_fit_the_navigation_matrix() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = fixture(dir.path());
        let screens = app
            .navigation_entries()
            .iter()
            .filter(|e| matches!(e.target, crate::navigation::Intent::Screen(_)))
            .count();
        for screen in 0..screens {
            app.select_screen(screen);
            for pane in 0..app.pane_names().len() {
                app.focus_pane(pane);
                for &(w, h) in &crate::audit::SIZES[..4] {
                    let mut terminal = Terminal::new(TestBackend::new(w, h)).unwrap();
                    terminal.draw(|f| draw(f, &app)).unwrap();
                    let buffer = terminal.backend().buffer();
                    assert!(
                        crate::audit::text(buffer).contains("(F2)"),
                        "screen {screen} pane {pane} must expose navigation at {w}x{h}"
                    );
                    crate::audit::verify_footer(buffer);
                    crate::audit::capture(
                        "breach",
                        &format!("navigation-screen{screen}-pane{pane}"),
                        buffer,
                    );
                    let before = app.navigation_screen();
                    app.navigation_mouse(crossterm::event::MouseEvent {
                        kind: crossterm::event::MouseEventKind::Down(
                            crossterm::event::MouseButton::Left,
                        ),
                        column: w + 1,
                        row: h + 1,
                        modifiers: KeyModifiers::NONE,
                    });
                    assert_eq!(app.navigation_screen(), before);
                }
            }
        }
    }
    #[test]
    fn hosts_cycle_both_ways_and_inputs_own_commands() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = fixture(dir.path());
        app.handle_key(key(KeyCode::F(6)));
        assert!(app.host_pane == HostPane::Detail);
        app.handle_key(key(KeyCode::F(6)));
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
    #[ignore = "interactive mock fixture for visual QA"]
    fn live_preview() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = fixture(dir.path());
        if let Ok(id) = std::env::var("TUI_PREVIEW_THEME") {
            crate::theme::set(&id);
        }
        match std::env::var("AURORA_PREVIEW_SCREEN").as_deref() {
            Ok("plan") => {
                app.tab = Tab::Wizards;
                app.wizard = WizardKind::AutoPlan;
                app.rebuild_plan_for_test();
            }
            Ok("validation") => {
                app.tab = Tab::Wizards;
                app.wizard = WizardKind::Validate;
                app.validations = vec![crate::model::ValidationResult {
                    workspace: app.snap.workspace.clone(),
                    host: "192.0.2.10".into(),
                    module: "windows/smb/ms17_010_eternalblue".into(),
                    code: "vulnerable".into(),
                    message: "Mock: target is vulnerable".into(),
                    ..Default::default()
                }];
            }
            Ok("tasks") => {
                app.tab = Tab::Tasks;
                let mut task = crate::model::TaskLog::new("chain", "fixture validation workflow");
                task.status = "complete".into();
                task.detail="Step 1/3: import scan.xml\nStep complete\nStep 2/3: validate vulnerabilities\nUUID=mock-job job=7\nValidation: vulnerable — mock finding\nStep complete\nStep 3/3: report json,html\nStep complete".into();
                app.tasks = vec![task];
            }
            _ => {}
        }
        if std::env::var("AURORA_PREVIEW_SCREEN").is_ok() {
            app.focus_pane(1);
        }
        match std::env::var("AURORA_NAV_PREVIEW").as_deref() {
            Ok("confirm") => {
                app.modal=Modal::Confirm{title:"Run reviewed plan?".into(),body:"Mock review: selected modules and targets. No backend operations run in this preview.".into(),action:crate::app::Action::RunPlan};
            }
            Ok("menu") => app.navigation.toggle(),
            Ok("actions") => app.commands.open = true,
            Ok("focused") => app.focus_pane(1),
            _ => {}
        }
        crate::audit::live_preview(
            &mut app,
            |f, a| draw(f, a),
            |a, k| {
                if matches!(
                    k.code,
                    KeyCode::F(2)
                        | KeyCode::F(6)
                        | KeyCode::Tab
                        | KeyCode::BackTab
                        | KeyCode::Down
                        | KeyCode::Up
                        | KeyCode::Esc
                        | KeyCode::Char('0'..='9')
                ) {
                    a.handle_key(k);
                }
            },
        );
    }

    #[test]
    fn pro_workflow_views_fit_and_large_plan_selection_stays_visible() {
        let dir = tempfile::tempdir().unwrap();
        let mut app = fixture(dir.path());
        app.tab = Tab::Wizards;
        app.wizard = WizardKind::AutoPlan;
        app.plan = (0..200)
            .map(|i| crate::model::PlanItem {
                host: format!("192.0.2.{i}"),
                module: format!("linux/http/fixture_{i}"),
                kind: "exploit".into(),
                rank: "great".into(),
                reason: "CVE-2026-1234 match".into(),
                rport: Some(80),
                selected: true,
            })
            .collect();
        app.plan_idx = 199;
        app.focus_pane(1);
        for &(w, h) in &crate::audit::SIZES[..4] {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|f| draw(f, &app)).unwrap();
            let text = crate::audit::text(term.backend().buffer());
            assert!(
                text.contains("192.0.2.199"),
                "selected plan must remain visible at {w}x{h}: {text}"
            );
            crate::audit::verify_footer(term.backend().buffer());
        }
        app.wizard = WizardKind::Validate;
        app.validations = vec![crate::model::ValidationResult {
            workspace: app.snap.workspace.clone(),
            host: "192.0.2.4".into(),
            code: "vulnerable".into(),
            message: "Mock finding".into(),
            ..Default::default()
        }];
        for wizard in WizardKind::all() {
            app.wizard = wizard;
            for &(w, h) in &crate::audit::SIZES[..4] {
                let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
                term.draw(|f| draw(f, &app)).unwrap();
                crate::audit::verify_footer(term.backend().buffer());
            }
        }
        app.tab = Tab::Tasks;
        app.active_workflow = Some("fixture".into());
        for &(w, h) in &crate::audit::SIZES[..4] {
            let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
            term.draw(|f| draw(f, &app)).unwrap();
            crate::audit::verify_footer(term.backend().buffer());
        }
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
            if w >= 30 && h >= 14 {
                assert!(
                    buffer
                        .content
                        .iter()
                        .any(|cell| matches!(cell.symbol(), "█" | "▀" | "▄")
                            && cell.fg == crate::theme::pink())
                );
            }
            if w >= 60 && h >= 20 {
                assert!(
                    crate::audit::text(buffer).contains("10.0.0.5"),
                    "selected host must remain visible below the larger title"
                );
            }
            crate::audit::verify_footer(buffer);
            if w >= 80 && h >= 30 {
                for y in 12..h - 6 {
                    for x in w / 2..w - 8 {
                        assert_eq!(
                            buffer[(x, y)].bg,
                            theme::bg_color(),
                            "host inspector background at {x},{y}"
                        );
                    }
                }
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
                crate::audit::verify_footer(term.backend().buffer());
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
