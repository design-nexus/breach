const NAV_SCREENS: &[crate::navigation::Screen] = &[
    crate::navigation::Screen {
        name: "Dashboard",
        key: '1',
    },
    crate::navigation::Screen {
        name: "Hosts",
        key: '2',
    },
    crate::navigation::Screen {
        name: "Modules",
        key: '3',
    },
    crate::navigation::Screen {
        name: "Sessions",
        key: '4',
    },
    crate::navigation::Screen {
        name: "Credentials",
        key: '5',
    },
    crate::navigation::Screen {
        name: "Tasks",
        key: '6',
    },
    crate::navigation::Screen {
        name: "Chains",
        key: '7',
    },
    crate::navigation::Screen {
        name: "Reports",
        key: '8',
    },
    crate::navigation::Screen {
        name: "Console",
        key: '9',
    },
    crate::navigation::Screen {
        name: "Wizards",
        key: '0',
    },
];
impl App {
    pub fn navigation_skin(&self) -> crate::navigation::Skin {
        crate::navigation::Skin {
            base: crate::theme::bg(),
            muted: crate::theme::muted(),
            accent: crate::theme::title(),
            selected: crate::theme::selected(),
            border: ratatui::style::Style::default().fg(crate::theme::comment()),
        }
    }
    pub fn navigation_screen(&self) -> usize {
        Tab::all().iter().position(|t| *t == self.tab).unwrap_or(0)
    }
    pub fn pane_names(&self) -> &'static [&'static str] {
        match self.tab {
            Tab::Dash => &["Overview", "Activity"],
            Tab::Hosts => &["Hosts", "Inspector"],
            Tab::Modules => &["Modules", "Options / details"],
            Tab::Sessions => &["Sessions", "Interaction"],
            Tab::Creds => &["Credentials", "Loot"],
            Tab::Tasks => &["Jobs", "Task log"],
            Tab::Chains => &["Chains", "Steps"],
            Tab::Reports => &["Reports"],
            Tab::Console => &["Output", "Input"],
            Tab::Wizards => &["Wizard picker", "Wizard content"],
        }
    }
    pub fn focused_pane(&self) -> usize {
        match self.tab {
            Tab::Hosts => usize::from(self.host_pane == HostPane::Detail),
            Tab::Creds => usize::from(self.cred_pane == CredPane::Loot),
            _ => self.navigation.focus[self.navigation_screen()],
        }
    }
    pub fn navigation_editing(&self) -> bool {
        (self.tab == Tab::Console && self.focused_pane() == 1)
            || (self.tab == Tab::Sessions && self.interact)
    }
    pub fn navigation_entries(&self) -> Vec<crate::navigation::Entry> {
        let mut entries = crate::navigation::entries(NAV_SCREENS, self.pane_names());
        if self.tab == Tab::Modules {
            for (i, name) in ["Exploit", "Auxiliary", "Post", "Payload", "Encoder"]
                .iter()
                .enumerate()
            {
                entries.push(crate::navigation::Entry {
                    label: format!("Type · {name}"),
                    shortcut: "←/→".into(),
                    target: crate::navigation::Intent::Selector(i),
                    reason: None,
                });
            }
        }
        entries
    }
    pub fn navigation_bar(&self, frame: &mut ratatui::Frame, area: ratatui::layout::Rect) {
        self.navigation.bar(
            frame,
            area,
            NAV_SCREENS,
            self.navigation_screen(),
            self.pane_names(),
            self.focused_pane(),
            self.navigation_editing(),
            self.navigation_skin(),
        );
    }
    pub fn draw_navigation(&self, frame: &mut ratatui::Frame) {
        self.navigation
            .draw(frame, &self.navigation_entries(), self.navigation_skin());
    }
    pub fn focus_pane(&mut self, p: usize) {
        let p = p.min(self.pane_names().len().saturating_sub(1));
        let screen = self.navigation_screen();
        self.navigation.focus[screen] = p;
        match self.tab {
            Tab::Hosts => {
                self.host_pane = if p == 0 {
                    HostPane::List
                } else {
                    HostPane::Detail
                }
            }
            Tab::Creds => {
                self.cred_pane = if p == 0 {
                    CredPane::Creds
                } else {
                    CredPane::Loot
                }
            }
            Tab::Sessions if p == 0 => self.interact = false,
            _ => {}
        }
    }
    pub fn select_screen(&mut self, screen: usize) {
        if screen >= NAV_SCREENS.len() {
            return;
        }
        let old = self.navigation_screen();
        if old == screen {
            return;
        }
        self.navigation.focus[old] = self.focused_pane();
        self.navigation.scroll[old] = self.detail_scroll;
        self.detail_scroll = self.navigation.scroll[screen];
        self.tab = Tab::all()[screen];
        self.focus_pane(self.navigation.focus[screen]);
    }
    fn navigation_key(&mut self, key: KeyEvent) -> bool {
        if self.commands.open {
            return false;
        }
        if self.navigation.open {
            let entries = self.navigation_entries();
            if let Some(intent) = self.navigation.key(key, &entries) {
                self.dispatch_intent(intent);
            }
            return true;
        }
        match key.code {
            KeyCode::F(2) => {
                self.navigation.toggle();
                true
            }
            KeyCode::F(6) => {
                let direction = if key.modifiers.contains(KeyModifiers::SHIFT) {
                    -1
                } else {
                    1
                };
                self.focus_pane(crate::navigation::step(
                    self.focused_pane(),
                    self.pane_names().len(),
                    direction,
                ));
                true
            }
            KeyCode::Tab | KeyCode::BackTab => {
                if !self.navigation_editing() {
                    let d = if key.code == KeyCode::Tab {
                        -1i32 + 2
                    } else {
                        -1
                    };
                    self.select_screen(crate::navigation::step(
                        self.navigation_screen(),
                        NAV_SCREENS.len(),
                        d,
                    ));
                }
                true
            }
            KeyCode::Char(c)
                if !self.navigation_editing()
                    && key.modifiers.is_empty()
                    && NAV_SCREENS.iter().any(|s| s.key == c) =>
            {
                let i = NAV_SCREENS.iter().position(|s| s.key == c).unwrap();
                self.select_screen(i);
                true
            }
            KeyCode::Esc => {
                let p = if self.navigation_editing()
                    && self.focused_pane() == 0
                    && self.pane_names().len() > 1
                {
                    1
                } else {
                    self.focused_pane().saturating_sub(1)
                };
                self.focus_pane(p);
                true
            }
            KeyCode::Down | KeyCode::Up | KeyCode::Char('j' | 'k')
                if !self.navigation_editing()
                    && !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                let d = if matches!(key.code, KeyCode::Down | KeyCode::Char('j')) {
                    1
                } else {
                    -1
                };
                self.navigation_scroll(self.focused_pane(), d);
                true
            }
            KeyCode::PageDown | KeyCode::PageUp
                if !self.navigation_editing()
                    && !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                let d = if key.code == KeyCode::PageDown { 8 } else { -8 };
                self.navigation_scroll(self.focused_pane(), d);
                true
            }
            KeyCode::F(1) => {
                self.modal = Modal::Help;
                true
            }
            KeyCode::Char('x') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.navigation_cancel();
                true
            }
            _ => false,
        }
    }
    fn navigation_cancel(&mut self) {
        if self.active_workflow.is_some() {
            self.confirm(
                Action::CancelWorkflow,
                "Cancel active workflow?",
                "Requests the current Framework job to stop and cancels remaining steps.",
            );
        } else {
            self.status = "No workflow is running".into();
        }
    }
    pub fn dispatch_intent(&mut self, intent: crate::navigation::Intent) {
        use crate::navigation::Intent;
        match intent {
            Intent::Screen(screen) => {
                self.navigation.open = false;
                self.select_screen(screen)
            }
            Intent::Pane(p) => {
                self.navigation.open = false;
                self.focus_pane(p)
            }
            Intent::Menu => self.navigation.toggle(),
            Intent::Details(p) => self.focus_pane(p),
            Intent::ScrollDetails(p, d) => {
                self.focus_pane(p);
                self.navigation_details_scroll(p, d)
            }
            Intent::Selector(i) => {
                self.navigation.open = false;
                self.navigation_selector(i)
            }
            Intent::Theme(id) => self.apply_aurora_theme(id),
            Intent::Command(id) => self.navigation_command(id),
            Intent::Row(p, i) => {
                self.focus_pane(p);
                self.navigation_row(p, i, false)
            }
            Intent::Activate(p, i) => {
                self.focus_pane(p);
                self.navigation_row(p, i, true)
            }
            Intent::Scroll(p, d) => {
                self.focus_pane(p);
                self.navigation_scroll(p, d)
            }
        }
    }
    pub fn command_actions(&self) -> Vec<crate::commands::Action> {
        let mut actions = NAV_SCREENS
            .iter()
            .enumerate()
            .map(|(i, s)| crate::commands::Action::screen(s.name, i, s.key))
            .collect::<Vec<_>>();
        actions.extend(self.pane_names().iter().enumerate().map(|(i, p)| {
            crate::commands::Action::function(p, 6, crate::navigation::Intent::Pane(i))
        }));
        actions.push(crate::commands::Action::function(
            "Navigate",
            2,
            crate::navigation::Intent::Menu,
        ));
        actions.extend(
            ACTIONS
                .iter()
                .filter(|a| !matches!(a.key, KeyCode::Char('0'..='9')))
                .cloned(),
        );
        for action in &mut actions {
            let reason = match action.label {
                "Validate selected plan modules"
                    if self.tab != Tab::Wizards || self.wizard != WizardKind::AutoPlan =>
                {
                    Some("Open Wizards and select Auto-plan")
                }
                "Validate selected plan modules" if self.plan.is_empty() => {
                    Some("Build a plan first")
                }
                "Validate selected plan modules" if self.active_workflow.is_some() => {
                    Some("Wait for or cancel the active workflow")
                }
                "Cancel active workflow" if self.active_workflow.is_none() => {
                    Some("No workflow is running")
                }
                _ => None,
            };
            if let Some(reason) = reason {
                action.disabled = Some(reason.into());
            }
        }
        actions
    }
}

impl App {
    fn navigation_command(&mut self, id: &str) {
        match id {
            "Confirm" => {
                if let Modal::Confirm { action, .. } = &self.modal {
                    let action = *action;
                    self.modal = Modal::None;
                    self.perform(action);
                }
            }
            "Cancel" => self.modal = Modal::None,
            "Module type picker" => {
                self.navigation.toggle();
                self.navigation.query = "Type ·".into();
            }
            "Help" => self.modal = Modal::Help,
            "Review and run" => self.prompt_primary(),
            "Validate selected plan modules" => self.confirm(
                Action::ValidatePlan,
                "Check selected plan modules?",
                "Runs supported module.check methods against selected targets.",
            ),
            "Cancel active workflow" => self.navigation_cancel(),
            "Filter" => {
                self.filtering = true;
                self.edit = LineEdit::new(self.filter.clone());
            }
            "Connect RPC" => self.confirm(
                Action::Connect,
                "Connect to RPC?",
                "Connect to the configured Framework instance.",
            ),
            _ => {}
        }
    }
    fn navigation_row(&mut self, pane: usize, index: usize, activate: bool) {
        match self.tab {
            Tab::Hosts => {
                if let Some(host) = self.filtered_hosts().get(index) {
                    self.host_idx = *host;
                }
                if activate {
                    self.focus_pane(1)
                }
            }
            Tab::Modules => {
                if pane == 0 {
                    self.module_idx = index.min(self.current_modules().len().saturating_sub(1));
                    self.fetch_selected_module();
                    if activate {
                        self.focus_pane(1)
                    }
                } else {
                    self.option_idx = index.min(
                        self.module_info
                            .as_ref()
                            .map(|m| m.options.len())
                            .unwrap_or(0)
                            .saturating_sub(1),
                    );
                    if activate {
                        self.edit_selected_option();
                    }
                }
            }
            Tab::Sessions => {
                self.session_idx = index.min(self.snap.sessions.len().saturating_sub(1));
                if activate && pane == 0 {
                    self.focus_pane(1);
                    self.begin_interaction();
                }
            }
            Tab::Creds => {
                if pane == 0 {
                    self.cred_idx = index.min(self.snap.creds.len().saturating_sub(1))
                } else {
                    self.loot_idx = index.min(self.snap.loot.len().saturating_sub(1))
                }
            }
            Tab::Tasks => {
                if pane == 0 {
                    self.job_idx = index.min(self.snap.jobs.len().saturating_sub(1))
                } else {
                    self.task_idx = index.min(self.tasks.len().saturating_sub(1))
                }
            }
            Tab::Chains => {
                self.chain_idx = index.min(self.chains.len().saturating_sub(1));
                if activate {
                    self.focus_pane(1)
                }
            }
            Tab::Wizards => {
                if pane == 0 {
                    self.wizard = WizardKind::all()[index.min(WizardKind::all().len() - 1)];
                    self.wiz_field = 0;
                    if activate {
                        self.focus_pane(1)
                    }
                } else if self.wizard == WizardKind::AutoPlan {
                    self.plan_idx = index.min(self.plan.len().saturating_sub(1));
                    if activate {
                        if let Some(p) = self.plan.get_mut(self.plan_idx) {
                            p.selected = !p.selected
                        }
                    }
                } else {
                    self.wiz_field = index;
                    if activate {
                        self.edit_wizard_field();
                    }
                }
            }
            _ => {}
        }
    }
    fn navigation_scroll(&mut self, pane: usize, d: i32) {
        match self.tab {
            Tab::Hosts if pane == 0 => self.move_host(d),
            Tab::Modules if pane == 0 => {
                let n = self.current_modules().len();
                move_idx(&mut self.module_idx, n, d);
                self.fetch_selected_module()
            }
            Tab::Modules => {
                let n = self
                    .module_info
                    .as_ref()
                    .map(|m| m.options.len())
                    .unwrap_or(0);
                move_idx(&mut self.option_idx, n, d)
            }
            Tab::Sessions if pane == 0 => {
                move_idx(&mut self.session_idx, self.snap.sessions.len(), d)
            }
            Tab::Creds => {
                if pane == 0 {
                    move_idx(&mut self.cred_idx, self.snap.creds.len(), d)
                } else {
                    move_idx(&mut self.loot_idx, self.snap.loot.len(), d)
                }
            }
            Tab::Tasks if pane == 0 => move_idx(&mut self.job_idx, self.snap.jobs.len(), d),
            Tab::Tasks if d.abs() < 8 => {
                move_idx(&mut self.task_idx, self.tasks.len(), d);
                self.detail_scroll = 0;
            }
            Tab::Chains if pane == 0 => move_idx(&mut self.chain_idx, self.chains.len(), d),
            Tab::Wizards if pane == 0 => {
                let i = WizardKind::all()
                    .iter()
                    .position(|w| *w == self.wizard)
                    .unwrap_or(0);
                self.wizard =
                    WizardKind::all()[crate::navigation::step(i, WizardKind::all().len(), d)];
                self.wiz_field = 0;
            }
            Tab::Wizards if self.wizard == WizardKind::AutoPlan => {
                move_idx(&mut self.plan_idx, self.plan.len(), d)
            }
            Tab::Wizards => self.wiz_field = (self.wiz_field as i32 + d).max(0) as usize,
            _ => {
                if d < 0 {
                    self.detail_scroll = self.detail_scroll.saturating_sub(3)
                } else {
                    self.detail_scroll = self.detail_scroll.saturating_add(3)
                }
            }
        }
    }
    fn begin_interaction(&mut self) {
        if let Some(session) = self.snap.sessions.get(self.session_idx).cloned() {
            self.interact = true;
            if !self.demo {
                self.send(Cmd::SessionRead {
                    id: session.id,
                    meterpreter: session.kind.contains("meterpreter"),
                });
            }
        } else {
            self.status = "Select a session first".into();
        }
    }
    pub fn navigation_mouse(&mut self, event: crossterm::event::MouseEvent) {
        if self.filtering {
            return;
        }
        if !matches!(self.modal, Modal::None) {
            if let Some(intent) = self.navigation.mouse(event) {
                if matches!(
                    intent,
                    crate::navigation::Intent::Command("Confirm" | "Cancel")
                ) {
                    self.dispatch_intent(intent);
                }
            }
            return;
        }
        if self.navigation.open {
            let entries = self.navigation_entries();
            if let Some(intent) = self.navigation.menu_mouse(event, &entries) {
                self.dispatch_intent(intent);
            }
            return;
        }
        if self.commands.open {
            if let Some(action) = self.commands.mouse(event, &self.command_actions()) {
                self.dispatch_intent(action.target);
            }
            return;
        }
        if let Some(intent) = self.navigation.mouse(event) {
            self.dispatch_intent(intent);
        }
    }
}

impl App {
    fn navigation_details_scroll(&mut self, _p: usize, d: i32) {
        self.detail_scroll = (self.detail_scroll as i32 + d * 3).clamp(0, u16::MAX as i32) as u16;
    }
    fn navigation_selector(&mut self, i: usize) {
        if self.tab == Tab::Modules {
            self.module_kind = match i {
                0 => ModuleKind::Exploit,
                1 => ModuleKind::Auxiliary,
                2 => ModuleKind::Post,
                3 => ModuleKind::Payload,
                _ => ModuleKind::Encoder,
            };
            self.module_idx = 0;
            self.ensure_module_list();
            self.fetch_selected_module();
        } else if self.tab == Tab::Wizards {
            self.wizard = WizardKind::all()[i.min(WizardKind::all().len() - 1)];
            self.wiz_field = 0;
        }
    }
}

impl App {
    pub fn footer_hints(&self) -> Vec<(&'static str, &'static str)> {
        match self.tab {
            Tab::Dash => vec![
                ("Ctrl+G", "connect"),
                ("Ctrl+K", "actions"),
                ("e", "workspace"),
            ],
            Tab::Hosts => {
                if self.focused_pane() == 0 {
                    vec![("Enter", "inspect"), ("Ctrl+K", "actions"), ("/", "filter")]
                } else {
                    vec![
                        ("PgUp/PgDn", "scroll"),
                        ("Ctrl+K", "actions"),
                        ("a", "build plan"),
                    ]
                }
            }
            Tab::Modules => {
                if self.focused_pane() == 0 {
                    vec![
                        ("Enter", "options"),
                        ("Ctrl+K", "actions"),
                        ("←/→", "type"),
                        ("/", "filter"),
                    ]
                } else {
                    vec![
                        ("Enter", "edit option"),
                        ("Ctrl+K", "actions"),
                        ("Ctrl+G", "review/run"),
                    ]
                }
            }
            Tab::Sessions => {
                if self.interact {
                    vec![
                        ("Enter", "send"),
                        ("Ctrl+K", "actions"),
                        ("Esc", "leave input"),
                    ]
                } else {
                    vec![
                        ("Enter", "interact"),
                        ("Ctrl+K", "actions"),
                        ("Ctrl+G", "stop session"),
                    ]
                }
            }
            Tab::Creds => vec![
                ("↑/↓", "select"),
                ("Ctrl+K", "actions"),
                ("Ctrl+G", "review reuse"),
            ],
            Tab::Tasks => {
                if self.active_workflow.is_some() {
                    vec![
                        ("Ctrl+X", "cancel"),
                        ("Ctrl+K", "actions"),
                        ("PgUp/PgDn", "scroll"),
                    ]
                } else {
                    vec![
                        ("PgUp/PgDn", "scroll"),
                        ("Ctrl+K", "actions"),
                        ("Ctrl+G", "stop job"),
                    ]
                }
            }
            Tab::Chains => vec![
                ("Ctrl+G", "review chain"),
                ("Ctrl+K", "actions"),
                ("PgUp/PgDn", "scroll"),
            ],
            Tab::Reports => vec![
                ("Ctrl+G", "generate"),
                ("Ctrl+K", "actions"),
                ("x", "redaction"),
            ],
            Tab::Console => {
                if self.focused_pane() == 0 {
                    vec![
                        ("Enter", "edit command"),
                        ("Ctrl+K", "actions"),
                        ("PgUp/PgDn", "scroll"),
                    ]
                } else {
                    vec![
                        ("Enter", "send"),
                        ("Ctrl+K", "actions"),
                        ("Esc", "leave input"),
                    ]
                }
            }
            Tab::Wizards => {
                if self.focused_pane() == 0 {
                    vec![
                        ("Enter", "open wizard"),
                        ("Ctrl+K", "actions"),
                        ("↑/↓", "choose"),
                    ]
                } else if self.wizard == WizardKind::AutoPlan {
                    vec![
                        ("Space", "select"),
                        ("Ctrl+K", "actions"),
                        ("v", "check"),
                        ("Ctrl+G", "review/run"),
                    ]
                } else {
                    vec![
                        ("Enter", "edit"),
                        ("Ctrl+K", "actions"),
                        ("Ctrl+G", "review/run"),
                    ]
                }
            }
        }
    }
}
