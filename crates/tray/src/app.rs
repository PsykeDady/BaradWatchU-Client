//! Tray application state machine. Runs on the event-loop thread; slow work (agent calls,
//! dialogs) happens on worker threads that post messages back.
use crate::{
    agent::{Agent, DashboardRoute},
    icon,
    model::{self, Health, Note, Notifier, Snapshot, Urgency},
    platform::{self, DialogOutcome, InstanceLock, Poster},
};
use std::{
    collections::HashSet,
    path::PathBuf,
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tray_icon::{
    menu::{CheckMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem},
    TrayIcon, TrayIconBuilder,
};

const POLL_INTERVAL: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub enum Msg {
    Tick,
    Snapshot(Result<Snapshot, String>),
    Menu(String),
    AuditDone(Result<(), String>),
    ConsentClosed {
        request_id: String,
        outcome: DialogOutcome,
    },
    ConsentRecorded(Result<String, String>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Control {
    Continue,
    Exit,
}

struct Items {
    header: MenuItem,
    last_line: MenuItem,
    open: MenuItem,
    audit: MenuItem,
    last: MenuItem,
    history: MenuItem,
    pending: MenuItem,
    events: MenuItem,
    autostart: CheckMenuItem,
    about: MenuItem,
    quit: MenuItem,
}

pub struct App {
    language: baradwatchu_messages::Language,
    agent: Agent,
    post: Poster,
    tray: TrayIcon,
    items: Items,
    exe: PathBuf,
    snapshot: Option<Snapshot>,
    comm_error: Option<String>,
    notifier: Notifier,
    health: Option<Health>,
    polling: bool,
    auditing: bool,
    dialog_open: bool,
    offered: HashSet<String>,
    _lock: InstanceLock,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn note(title: &str, body: &str, urgency: Urgency) -> Note {
    Note {
        title: title.into(),
        body: body.into(),
        urgency,
    }
}

impl App {
    pub fn new(post: Poster, agent: Agent, lock: InstanceLock) -> Result<Self, String> {
        let language = baradwatchu_messages::configured_language();
        let tr = |key| baradwatchu_messages::message(key, language).to_owned();
        let exe = std::env::current_exe()
            .map_err(|_| baradwatchu_messages::message("tray.error.executable", language))?;
        let item = |id: &str, text: &str, enabled: bool| MenuItem::with_id(id, text, enabled, None);
        let items = Items {
            header: item(
                "header",
                &format!("BaradWatchU — {}", tr("tray.starting")),
                false,
            ),
            last_line: item("last-line", &tr("tray.waiting"), false),
            open: item("open", &tr("tray.open_dashboard"), true),
            audit: item("audit", &tr("tray.audit"), true),
            last: item("last", &tr("tray.last_result"), true),
            history: item("history", &tr("tray.history"), true),
            pending: item("pending", &format!("{}: 0", tr("tray.pending")), false),
            events: item("events", &tr("tray.notifications"), true),
            autostart: CheckMenuItem::with_id(
                "autostart",
                tr("tray.start_login"),
                true,
                platform::autostart_enabled(),
                None,
            ),
            about: item("about", &tr("tray.about"), true),
            quit: item("quit", &tr("tray.quit"), true),
        };
        let menu = Menu::new();
        let separator = PredefinedMenuItem::separator;
        menu.append_items(&[
            &items.header,
            &items.last_line,
            &separator(),
            &items.open,
            &items.audit,
            &items.last,
            &items.history,
            &separator(),
            &items.pending,
            &items.events,
            &separator(),
            &items.autostart,
            &items.about,
            &items.quit,
        ])
        .map_err(|_| baradwatchu_messages::message("tray.error.menu", language))?;
        let tray = TrayIconBuilder::new()
            .with_id("baradwatchu")
            .with_title("BaradWatchU")
            .with_tooltip(baradwatchu_messages::message("tray.tooltip", language))
            .with_menu(Box::new(menu))
            .with_icon(
                icon::icon(Health::Unreachable)
                    .ok_or_else(|| baradwatchu_messages::message("tray.error.icon", language))?,
            )
            .build()
            .map_err(|error| {
                baradwatchu_messages::message("tray.error.icon_create", language)
                    .replace("{error}", &error.to_string())
            })?;
        let menu_post = post.clone();
        MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
            menu_post(Msg::Menu(event.id.0.clone()));
        }));
        let tick_post = post.clone();
        thread::spawn(move || loop {
            tick_post(Msg::Tick);
            thread::sleep(POLL_INTERVAL);
        });
        Ok(Self {
            language,
            agent,
            post,
            tray,
            items,
            exe,
            snapshot: None,
            comm_error: None,
            notifier: Notifier::default(),
            health: None,
            polling: false,
            auditing: false,
            dialog_open: false,
            offered: HashSet::new(),
            _lock: lock,
        })
    }

    fn spawn(&self, task: impl FnOnce() -> Msg + Send + 'static) {
        let post = self.post.clone();
        thread::spawn(move || post(task()));
    }

    pub fn handle(&mut self, message: Msg) -> Control {
        match message {
            Msg::Tick => self.poll(),
            Msg::Snapshot(result) => self.on_snapshot(result),
            Msg::Menu(id) => return self.on_menu(&id),
            Msg::AuditDone(result) => {
                self.auditing = false;
                if let Err(error) = result {
                    let error = baradwatchu_messages::localize_diagnostic(&error, self.language);
                    platform::notify(note(
                        baradwatchu_messages::message("tray.audit_error", self.language),
                        &error,
                        Urgency::Critical,
                    ));
                }
                self.refresh_menu();
                self.poll();
            }
            Msg::ConsentClosed {
                request_id,
                outcome,
            } => self.on_consent_closed(request_id, outcome),
            Msg::ConsentRecorded(result) => {
                if let Err(error) = result {
                    let error = baradwatchu_messages::localize_diagnostic(&error, self.language);
                    platform::notify(note(
                        baradwatchu_messages::message("tray.consent_error", self.language),
                        &error,
                        Urgency::Critical,
                    ));
                }
                self.poll();
            }
        }
        Control::Continue
    }

    fn poll(&mut self) {
        if self.polling {
            return;
        }
        self.polling = true;
        let agent = self.agent.clone();
        let cursor = self.notifier.cursor();
        self.spawn(move || Msg::Snapshot(agent.snapshot(cursor)));
    }

    fn on_snapshot(&mut self, result: Result<Snapshot, String>) {
        self.polling = false;
        match result {
            Ok(snapshot) => {
                for item in self.notifier.on_snapshot(&snapshot) {
                    platform::notify(item);
                }
                self.snapshot = Some(snapshot);
                self.comm_error = None;
            }
            Err(error) => {
                let error = baradwatchu_messages::localize_diagnostic(&error, self.language);
                for item in self.notifier.on_failure(&error) {
                    platform::notify(item);
                }
                self.snapshot = None;
                self.comm_error = Some(error);
            }
        }
        self.refresh();
        self.offer_next_consent(false);
    }

    fn refresh(&mut self) {
        self.language = baradwatchu_messages::configured_language();
        let health = model::health(self.snapshot.as_ref());
        if self.health != Some(health) {
            if let Some(image) = icon::icon(health) {
                let _ = self.tray.set_icon(Some(image));
            }
            self.health = Some(health);
        }
        let summary = model::summary_in(
            self.snapshot.as_ref(),
            self.comm_error.as_deref(),
            now_ms(),
            self.language,
        );
        let _ = self.tray.set_tooltip(Some(&summary));
        self.items.header.set_text(format!(
            "BaradWatchU — {}",
            model::health_label_in(health, self.language)
        ));
        self.items
            .last_line
            .set_text(
                summary
                    .lines()
                    .nth(1)
                    .unwrap_or(baradwatchu_messages::message(
                        "tray.last_unavailable",
                        self.language,
                    )),
            );
        self.refresh_menu();
    }

    fn refresh_menu(&self) {
        // The preference can be changed from the dashboard while the tray is running.
        let language = baradwatchu_messages::configured_language();
        let text = |key| baradwatchu_messages::message(key, language);
        self.items.audit.set_enabled(!self.auditing);
        self.items.audit.set_text(if self.auditing {
            text("tray.audit_running")
        } else {
            text("tray.audit")
        });
        self.items.open.set_text(text("tray.open_dashboard"));
        self.items.last.set_text(text("tray.last_result"));
        self.items.history.set_text(text("tray.history"));
        self.items.events.set_text(text("tray.notifications"));
        self.items.about.set_text(text("tray.about"));
        self.items.quit.set_text(text("tray.quit"));
        self.items.autostart.set_text(text("tray.start_login"));
        let pending = self
            .snapshot
            .as_ref()
            .map_or(0, |snapshot| snapshot.pending_consents.len());
        self.items
            .pending
            .set_text(format!("{}: {pending}", text("tray.pending")));
        self.items.pending.set_enabled(pending > 0);
        self.items
            .autostart
            .set_checked(platform::autostart_enabled());
    }

    fn on_menu(&mut self, id: &str) -> Control {
        match id {
            "open" => self.open_dashboard(DashboardRoute::Status),
            "history" => self.open_dashboard(DashboardRoute::History),
            "events" => self.open_dashboard(DashboardRoute::Notifications),
            "audit" if !self.auditing => {
                self.auditing = true;
                self.refresh_menu();
                let agent = self.agent.clone();
                self.spawn(move || Msg::AuditDone(agent.audit()));
            }
            "last" => {
                let text = model::summary_in(
                    self.snapshot.as_ref(),
                    self.comm_error.as_deref(),
                    now_ms(),
                    self.language,
                );
                let title = baradwatchu_messages::message("tray.last_title", self.language);
                if !platform::info_dialog(title, &text) {
                    platform::notify(note(title, &text, Urgency::Low));
                }
            }
            "pending" => self.offer_next_consent(true),
            "autostart" => {
                let wanted = !platform::autostart_enabled();
                if let Err(error) = platform::set_autostart(wanted, &self.exe) {
                    let error = baradwatchu_messages::localize_diagnostic(&error, self.language);
                    platform::notify(note(
                        baradwatchu_messages::message("tray.autostart_error", self.language),
                        &error,
                        Urgency::Normal,
                    ));
                }
                self.refresh_menu();
            }
            "about" => {
                let agent_state = match &self.snapshot {
                    Some(snapshot) => {
                        baradwatchu_messages::message("tray.about_reachable", self.language)
                            .replace("{version}", &snapshot.agent_version)
                    }
                    None => baradwatchu_messages::message("tray.about_unreachable", self.language)
                        .into(),
                };
                let text = format!(
                    "BaradWatchU Tray {}\n{}: {} ({agent_state})\n\n{}",
                    env!("CARGO_PKG_VERSION"),
                    baradwatchu_messages::message("agent.label", self.language),
                    self.agent.path().display(),
                    baradwatchu_messages::message("tray.about_body", self.language)
                );
                let title = baradwatchu_messages::message("tray.about_title", self.language);
                if !platform::info_dialog(title, &text) {
                    platform::notify(note(title, &text, Urgency::Low));
                }
            }
            "quit" => return Control::Exit,
            _ => {}
        }
        Control::Continue
    }

    fn open_dashboard(&self, route: DashboardRoute) {
        if let Err(error) = self.agent.open_dashboard(route) {
            let error = baradwatchu_messages::localize_diagnostic(&error, self.language);
            platform::notify(note(
                baradwatchu_messages::message("tray.dashboard_error", self.language),
                &error,
                Urgency::Normal,
            ));
        }
    }

    /// Opens the dedicated consent window for the next pending request: automatically once
    /// per request, or again on demand from the menu. Never decides by itself.
    fn offer_next_consent(&mut self, on_demand: bool) {
        if self.dialog_open {
            return;
        }
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        let next = snapshot
            .pending_consents
            .iter()
            .find(|consent| on_demand || !self.offered.contains(&consent.request_id))
            .cloned();
        let Some(consent) = next else {
            if on_demand {
                self.open_dashboard(DashboardRoute::Notifications);
            }
            return;
        };
        self.offered.insert(consent.request_id.clone());
        self.dialog_open = true;
        let post = self.post.clone();
        let request_id = consent.request_id.clone();
        platform::consent_dialog(
            baradwatchu_messages::message("tray.consent_title", self.language),
            &consent.prompt,
            platform::dialog_timeout(consent.remaining_seconds),
            Box::new(move |outcome| {
                post(Msg::ConsentClosed {
                    request_id,
                    outcome,
                })
            }),
        );
    }

    fn on_consent_closed(&mut self, request_id: String, outcome: DialogOutcome) {
        self.dialog_open = false;
        let accept = match outcome {
            DialogOutcome::Accept => true,
            DialogOutcome::Reject => false,
            // No answer is not an answer: nothing is sent to the agent, the request stays
            // pending (re-openable from the menu) until it expires unauthorized.
            DialogOutcome::Later | DialogOutcome::TimedOut => {
                self.poll();
                return;
            }
            DialogOutcome::Unavailable(reason) => {
                let reason = baradwatchu_messages::localize_diagnostic(&reason, self.language);
                platform::notify(note(
                    baradwatchu_messages::message("tray.consent_window_error", self.language),
                    &baradwatchu_messages::message("tray.consent_window_hint", self.language)
                        .replace("{reason}", &reason)
                        .replace("{id}", &request_id),
                    Urgency::Critical,
                ));
                return;
            }
        };
        let agent = self.agent.clone();
        self.spawn(move || Msg::ConsentRecorded(agent.decide(&request_id, accept)));
    }
}
