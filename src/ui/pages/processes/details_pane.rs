//! Lower pane of the Processes page showing details of the selected process
//! (libraries, open files, network connections, threads, environment and
//! security attributes), modelled after Process Explorer's lower pane and
//! properties tabs.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib::{self, clone};
use gtk::{gio, pango};
use process_data::details::{self, FdKind};

use crate::utils::TICK_RATE;
use crate::utils::i18n::{i18n, i18n_f, ni18n_f};
use crate::utils::secrets;
use crate::utils::units::{convert_storage, format_time};
use crate::utils::virustotal::{self, Lookup};
use crate::utils::yara::{self, ScanReport};

type ModeCallback = Box<dyn Fn(DetailsMode)>;
type VirusTotalCallback = Box<dyn Fn(libc::pid_t, String)>;

/// Maximum number of columns any mode uses
const MAX_COLUMNS: usize = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetailsMode {
    Libraries,
    Files,
    Network,
    Threads,
    Environment,
    Security,
    Yara,
    VirusTotal,
}

impl DetailsMode {
    pub const ALL: [Self; 8] = [
        Self::Libraries,
        Self::Files,
        Self::Network,
        Self::Threads,
        Self::Environment,
        Self::Security,
        Self::Yara,
        Self::VirusTotal,
    ];

    /// Modes whose data is fetched on request (a button), not on every refresh.
    pub fn is_on_demand(self) -> bool {
        matches!(self, Self::Yara | Self::VirusTotal)
    }

    pub fn from_index(index: u32) -> Self {
        Self::ALL
            .get(index as usize)
            .copied()
            .unwrap_or(Self::Libraries)
    }

    pub fn index(self) -> u32 {
        Self::ALL.iter().position(|mode| *mode == self).unwrap_or(0) as u32
    }

    pub fn label(self) -> String {
        match self {
            Self::Libraries => i18n("Libraries"),
            Self::Files => i18n("Files"),
            Self::Network => i18n("Network"),
            Self::Threads => i18n("Threads"),
            Self::Environment => i18n("Environment"),
            Self::Security => i18n("Security"),
            // not translated, it's the name of the tool
            Self::Yara => "YARA".to_string(),
            Self::VirusTotal => "VirusTotal".to_string(),
        }
    }

    pub fn headers(self) -> Vec<String> {
        match self {
            Self::Libraries => vec![i18n("Path"), i18n("Size"), i18n("Permissions")],
            Self::Files => vec![i18n("FD"), i18n("Type"), i18n("Target")],
            Self::Network => vec![
                i18n("Protocol"),
                i18n("Local Address"),
                i18n("Remote Address"),
                i18n("State"),
            ],
            Self::Threads => vec![
                i18n("Thread ID"),
                i18n("Name"),
                i18n("State"),
                i18n("CPU Time"),
            ],
            Self::Environment => vec![i18n("Variable"), i18n("Value")],
            Self::Security => vec![i18n("Property"), i18n("Value")],
            Self::Yara => vec![i18n("Rule"), i18n("Tags"), i18n("File")],
            Self::VirusTotal => vec![i18n("Property"), i18n("Value")],
        }
    }

    /// Fetches the rows of this mode for a process, one `Vec<String>` per row.
    pub fn rows(self, pid: libc::pid_t) -> anyhow::Result<Vec<Vec<String>>> {
        Ok(match self {
            Self::Libraries => details::read_mapped_files(pid)?
                .into_iter()
                .map(|file| {
                    vec![
                        file.path,
                        convert_storage(file.size as f64, false),
                        file.perms,
                    ]
                })
                .collect(),
            Self::Files => details::read_open_files(pid)?
                .into_iter()
                .map(|file| {
                    let kind = match file.kind {
                        FdKind::File => i18n("File"),
                        FdKind::Socket => i18n("Socket"),
                        FdKind::Pipe => i18n("Pipe"),
                        FdKind::AnonInode => i18n("Special"),
                        FdKind::Other => i18n("Other"),
                    };
                    vec![file.fd.to_string(), kind, file.target]
                })
                .collect(),
            Self::Network => details::read_sockets(pid)?
                .into_iter()
                .map(|socket| {
                    vec![
                        socket.protocol.to_string(),
                        socket.local,
                        socket.remote,
                        socket.state.to_string(),
                    ]
                })
                .collect(),
            Self::Threads => details::read_threads(pid)?
                .into_iter()
                .map(|thread| {
                    vec![
                        thread.tid.to_string(),
                        thread.name,
                        thread.state.to_string(),
                        format_time(thread.cpu_ticks as f64 / *TICK_RATE as f64),
                    ]
                })
                .collect(),
            Self::Environment => details::read_environment(pid)?
                .into_iter()
                .map(|(name, value)| vec![name, value])
                .collect(),
            // scanning takes long, so it's done on request, see `DetailsPane::scan`
            Self::Yara | Self::VirusTotal => Vec::new(),
            Self::Security => {
                let info = details::read_security(pid)?;
                let join = |items: &[String]| {
                    if items.is_empty() {
                        i18n("None")
                    } else {
                        items.join(", ")
                    }
                };
                let ids = |ids: &[u32], users: bool| {
                    ids.iter()
                        .map(|id| {
                            if users {
                                format!("{} ({id})", process_data::username_for_uid(*id))
                            } else {
                                id.to_string()
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                let yes_no = |value: Option<bool>| match value {
                    Some(true) => i18n("Yes"),
                    Some(false) => i18n("No"),
                    None => i18n("N/A"),
                };
                vec![
                    vec![
                        i18n("User IDs (real, effective, saved, filesystem)"),
                        ids(&info.uids, true),
                    ],
                    vec![i18n("Group IDs"), ids(&info.gids, false)],
                    vec![i18n("Supplementary Groups"), ids(&info.groups, false)],
                    vec![
                        i18n("Effective Capabilities"),
                        join(&info.capabilities_effective),
                    ],
                    vec![
                        i18n("Permitted Capabilities"),
                        join(&info.capabilities_permitted),
                    ],
                    vec![i18n("No New Privileges"), yes_no(info.no_new_privs)],
                    vec![
                        i18n("Seccomp"),
                        info.seccomp.map_or_else(|| i18n("N/A"), str::to_string),
                    ],
                    vec![
                        i18n("Security Label (SELinux/AppArmor)"),
                        info.lsm_context.unwrap_or_else(|| i18n("N/A")),
                    ],
                ]
            }
        })
    }
}

/// Looks the executable of a process up on VirusTotal.
async fn virustotal_outcome(pid: libc::pid_t) -> YaraOutcome {
    let key = match secrets::virustotal_key().await {
        Ok(Some(key)) => key,
        Ok(None) => {
            return YaraOutcome::message(i18n(
                "No VirusTotal API key. Add one in Preferences → Processes → VirusTotal",
            ));
        }
        Err(error) => {
            return YaraOutcome::message(i18n_f(
                "Could not read the API key from the keyring: {}",
                &[&error],
            ));
        }
    };

    let executable = gio::spawn_blocking(move || {
        let path = std::fs::read_link(format!("/proc/{pid}/exe"))?;
        let hash = process_data::hash::sha256_file_hex(format!("/proc/{pid}/exe"))?;
        Ok::<_, std::io::Error>((path, hash))
    })
    .await;
    let Ok(Ok((path, hash))) = executable else {
        return YaraOutcome::message(i18n("Could not read the executable of this process"));
    };

    let property = |name: String, value: String| format!("{}\t{}", clean(&name), clean(&value));
    let mut rows = vec![
        property(i18n("File"), path.to_string_lossy().to_string()),
        property(i18n("SHA-256"), hash.clone()),
    ];

    match virustotal::check(&hash, &key).await {
        Ok(Lookup::Found(reputation)) => {
            let checked = glib::DateTime::from_unix_local(reputation.checked_at)
                .ok()
                .and_then(|date| date.format("%x %X").ok())
                .map(|date| date.to_string())
                .unwrap_or_default();
            rows.push(property(i18n("Detections"), reputation.summary()));
            rows.push(property(i18n("Report"), reputation.permalink.clone()));
            rows.push(property(i18n("Checked"), checked));
            YaraOutcome {
                rows,
                summary: i18n_f("VirusTotal — {} detections", &[&reputation.summary()]),
                problems: String::new(),
                column: Some(reputation.summary()),
            }
        }
        Ok(Lookup::Unknown) => {
            rows.push(property(
                i18n("Detections"),
                i18n("Not known to VirusTotal"),
            ));
            YaraOutcome {
                rows,
                summary: i18n("VirusTotal — this file is not known"),
                problems: String::new(),
                column: Some(i18n("Unknown")),
            }
        }
        Err(error) => YaraOutcome {
            rows,
            summary: error.message(),
            problems: String::new(),
            column: None,
        },
    }
}

/// The widget itself. Cheap to clone, all clones share state.
#[derive(Clone)]
pub struct DetailsPane {
    inner: Rc<Inner>,
}

struct Inner {
    root: gtk::Box,
    columns: Vec<gtk::ColumnViewColumn>,
    store: gio::ListStore,
    mode: Cell<DetailsMode>,
    pid: Cell<Option<libc::pid_t>>,
    /// rows currently shown, to avoid rebuilding the list when nothing changed
    shown: RefCell<Option<Vec<String>>>,
    title: gtk::Label,
    on_mode_changed: RefCell<Option<ModeCallback>>,
    /// mode selector, its items are in the order of `DetailsMode::ALL`
    mode_selector: RefCell<Option<gtk::DropDown>>,
    scan_button: gtk::Button,
    rules_button: gtk::Button,
    memory_button: gtk::Button,
    scanning: Cell<bool>,
    /// results of the last YARA scan of each process
    yara_results: RefCell<HashMap<libc::pid_t, YaraOutcome>>,
    /// results of the last VirusTotal check of each process
    virustotal_results: RefCell<HashMap<libc::pid_t, YaraOutcome>>,
    on_virustotal_result: RefCell<Option<VirusTotalCallback>>,
}

/// What a YARA scan of one process found, ready to be shown.
#[derive(Debug, Clone, PartialEq, Eq)]
struct YaraOutcome {
    rows: Vec<String>,
    summary: String,
    /// rule files that failed to compile, one per line
    problems: String,
    /// text for the VirusTotal column of the process list
    column: Option<String>,
}

impl YaraOutcome {
    fn message(summary: String) -> Self {
        Self {
            rows: Vec::new(),
            summary,
            problems: String::new(),
            column: None,
        }
    }
}

/// One line per rule file that failed to compile.
fn rule_problems(errors: &[yara::RuleError]) -> String {
    errors
        .iter()
        .map(|error| {
            format!(
                "{}: {}",
                error.file.display(),
                error.message.lines().next().unwrap_or_default()
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn clean(field: &str) -> String {
    field.replace(['\t', '\n'], " ")
}

/// Tab-separated rows (rule, tags, where) for matches.
fn yara_rows(matches: &[yara::YaraMatch]) -> Vec<String> {
    matches
        .iter()
        .map(|found| {
            format!(
                "{}\t{}\t{}",
                clean(&found.rule),
                clean(&found.tags.join(", ")),
                clean(&found.target.to_string())
            )
        })
        .collect()
}

fn yara_memory_summary(report: &yara::MemoryReport) -> String {
    if report.denied {
        return i18n(
            "Access to the memory of this process was denied. Scanning memory needs a process of your own with ptrace allowed (kernel.yama.ptrace_scope=0) or root.",
        );
    }

    let mut summary = format!(
        "YARA (memory) — {}; {}, {:.1} MiB",
        ni18n_f(
            "{} match",
            "{} matches",
            report.matches.len() as u32,
            &[&report.matches.len().to_string()]
        ),
        ni18n_f(
            "{} region scanned",
            "{} regions scanned",
            report.regions_scanned as u32,
            &[&report.regions_scanned.to_string()]
        ),
        report.bytes_scanned as f64 / (1024.0 * 1024.0),
    );
    if report.regions_failed > 0 {
        summary.push_str(&format!(
            " ({} {})",
            report.regions_failed,
            i18n("unreadable")
        ));
    }
    if report.regions_skipped > 0 {
        summary.push_str(&format!(
            " ({} {})",
            report.regions_skipped,
            i18n("skipped, too big")
        ));
    }
    summary
}

fn yara_summary(report: &ScanReport) -> String {
    let mut summary = format!(
        "YARA — {}; {}",
        ni18n_f(
            "{} match",
            "{} matches",
            report.matches.len() as u32,
            &[&report.matches.len().to_string()]
        ),
        ni18n_f(
            "{} file scanned",
            "{} files scanned",
            report.files_scanned as u32,
            &[&report.files_scanned.to_string()]
        ),
    );
    if report.files_failed > 0 {
        summary.push_str(&format!(
            " ({} {})",
            report.files_failed,
            i18n("unreadable")
        ));
    }
    if report.files_skipped > 0 {
        summary.push_str(&format!(
            " ({} {})",
            report.files_skipped,
            i18n("skipped, too big")
        ));
    }
    summary
}

impl DetailsPane {
    pub fn new(initial_mode: DetailsMode) -> Self {
        let root = gtk::Box::new(gtk::Orientation::Vertical, 0);

        let store = gio::ListStore::new::<gtk::StringObject>();
        let selection = gtk::NoSelection::new(Some(store.clone()));
        let column_view = gtk::ColumnView::new(Some(selection));
        column_view.add_css_class("resources-columnview");
        column_view.set_show_row_separators(false);

        let columns: Vec<gtk::ColumnViewColumn> = (0..MAX_COLUMNS)
            .map(|index| {
                let factory = gtk::SignalListItemFactory::new();
                factory.connect_setup(|_, item| {
                    let label = gtk::Label::builder()
                        .xalign(0.0)
                        .ellipsize(pango::EllipsizeMode::End)
                        .selectable(false)
                        .build();
                    item.downcast_ref::<gtk::ListItem>()
                        .unwrap()
                        .set_child(Some(&label));
                });
                factory.connect_bind(move |_, item| {
                    let item = item.downcast_ref::<gtk::ListItem>().unwrap();
                    let (Some(label), Some(row)) = (
                        item.child().and_downcast::<gtk::Label>(),
                        item.item().and_downcast::<gtk::StringObject>(),
                    ) else {
                        return;
                    };
                    let text = row
                        .string()
                        .split('\t')
                        .nth(index)
                        .unwrap_or_default()
                        .to_string();
                    label.set_tooltip_text(Some(&text));
                    label.set_text(&text);
                });
                let column = gtk::ColumnViewColumn::new(None, Some(factory));
                column.set_resizable(true);
                column_view.append_column(&column);
                column
            })
            .collect();

        let title = gtk::Label::new(None);
        title.add_css_class("dim-label");
        title.set_xalign(0.0);
        title.set_hexpand(true);
        title.set_ellipsize(pango::EllipsizeMode::End);

        let scrolled = gtk::ScrolledWindow::builder()
            .child(&column_view)
            .vexpand(true)
            .hexpand(true)
            .build();

        let inner = Rc::new(Inner {
            root,
            columns,
            store,
            mode: Cell::new(initial_mode),
            pid: Cell::new(None),
            shown: RefCell::new(None),
            title,
            on_mode_changed: RefCell::new(None),
            mode_selector: RefCell::new(None),
            scan_button: gtk::Button::with_label(&i18n("Scan")),
            rules_button: gtk::Button::from_icon_name("folder-open-symbolic"),
            memory_button: gtk::Button::with_label(&i18n("Scan Memory")),
            scanning: Cell::new(false),
            yara_results: RefCell::new(HashMap::new()),
            virustotal_results: RefCell::new(HashMap::new()),
            on_virustotal_result: RefCell::new(None),
        });
        let this = Self { inner };

        // mode selector, a dropdown as there are too many modes for tabs
        let labels: Vec<String> = DetailsMode::ALL.iter().map(|mode| mode.label()).collect();
        let selector =
            gtk::DropDown::from_strings(&labels.iter().map(String::as_str).collect::<Vec<_>>());
        selector.set_selected(initial_mode.index());
        selector.set_tooltip_text(Some(&i18n("Which details to show")));
        selector.connect_selected_notify(clone!(
            #[strong]
            this,
            move |dropdown| {
                let mode = DetailsMode::from_index(dropdown.selected());
                if this.inner.mode.get() != mode {
                    this.set_mode(mode);
                    if let Some(callback) = &*this.inner.on_mode_changed.borrow() {
                        callback(mode);
                    }
                }
            }
        ));
        *this.inner.mode_selector.borrow_mut() = Some(selector.clone());

        this.inner.scan_button.add_css_class("suggested-action");
        this.inner.scan_button.set_tooltip_text(Some(&i18n(
            "Scan the executable and libraries of this process with the YARA rules",
        )));
        this.inner.scan_button.connect_clicked(clone!(
            #[strong]
            this,
            move |_| this.scan()
        ));
        this.inner.memory_button.set_tooltip_text(Some(&i18n(
            "Scan the heap, stack and other memory of this process with the YARA rules",
        )));
        this.inner.memory_button.connect_clicked(clone!(
            #[strong]
            this,
            move |_| this.scan_yara(true)
        ));
        this.inner
            .rules_button
            .set_tooltip_text(Some(&i18n("Open the Folder with YARA Rules")));
        this.inner.rules_button.connect_clicked(clone!(
            #[strong]
            this,
            move |_| this.open_rules_folder()
        ));

        let header = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        header.set_margin_top(6);
        header.set_margin_bottom(6);
        header.set_margin_start(12);
        header.set_margin_end(12);
        header.append(&selector);
        let spacer = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        spacer.set_hexpand(true);
        header.append(&spacer);
        header.append(&this.inner.rules_button);
        header.append(&this.inner.memory_button);
        header.append(&this.inner.scan_button);

        this.inner.root.append(&header);
        this.inner
            .root
            .append(&gtk::Separator::new(gtk::Orientation::Horizontal));
        // status line (counts, hints, problems) in its own row so that it has room
        this.inner.title.set_margin_start(12);
        this.inner.title.set_margin_end(12);
        this.inner.title.set_margin_top(4);
        this.inner.title.set_margin_bottom(4);
        this.inner.root.append(&this.inner.title);
        this.inner
            .root
            .append(&gtk::Separator::new(gtk::Orientation::Horizontal));
        this.inner.root.append(&scrolled);

        this.apply_headers();
        this
    }

    pub fn widget(&self) -> &gtk::Box {
        &self.inner.root
    }

    pub fn connect_mode_changed(&self, callback: impl Fn(DetailsMode) + 'static) {
        *self.inner.on_mode_changed.borrow_mut() = Some(Box::new(callback));
    }

    pub fn set_mode(&self, mode: DetailsMode) {
        if self.inner.mode.replace(mode) != mode {
            self.apply_headers();
            *self.inner.shown.borrow_mut() = None;
            self.refresh();
        }
    }

    /// Switches to a mode like the user choosing it, i.e. the selector
    /// follows and the change is reported to the callback.
    pub fn show_mode(&self, mode: DetailsMode) {
        let selector = self.inner.mode_selector.borrow().clone();
        match selector {
            Some(selector) if selector.selected() != mode.index() => {
                selector.set_selected(mode.index());
            }
            _ => self.set_mode(mode),
        }
    }

    /// Sets the process whose details are shown, `None` if no single process
    /// is selected.
    pub fn set_pid(&self, pid: Option<libc::pid_t>) {
        if self.inner.pid.replace(pid) != pid {
            *self.inner.shown.borrow_mut() = None;
            self.refresh();
        }
    }

    fn apply_headers(&self) {
        let mode = self.inner.mode.get();
        let is_yara = mode == DetailsMode::Yara;
        self.inner.scan_button.set_visible(mode.is_on_demand());
        self.inner.rules_button.set_visible(is_yara);
        self.inner.memory_button.set_visible(is_yara);
        match mode {
            DetailsMode::VirusTotal => {
                self.inner.scan_button.set_label(&i18n("Check"));
                self.inner.scan_button.set_tooltip_text(Some(&i18n(
                    "Look up the executable of this process on VirusTotal",
                )));
            }
            _ => {
                self.inner.scan_button.set_label(&i18n("Scan"));
                self.inner.scan_button.set_tooltip_text(Some(&i18n(
                    "Scan the executable and libraries of this process with the YARA rules",
                )));
            }
        }

        let headers = self.inner.mode.get().headers();
        for (index, column) in self.inner.columns.iter().enumerate() {
            column.set_visible(index < headers.len());
            column.set_title(headers.get(index).map(String::as_str));
            // the last visible column takes the remaining space
            column.set_expand(index + 1 == headers.len());
            column.set_fixed_width(match (self.inner.mode.get(), index) {
                (DetailsMode::Libraries, 0) => 480,
                (DetailsMode::Security | DetailsMode::Environment, 0) => 260,
                (DetailsMode::Network, 1 | 2) => 200,
                (DetailsMode::Threads, 1) => 200,
                (DetailsMode::Yara | DetailsMode::VirusTotal, 0) => 260,
                (DetailsMode::Yara, 1) => 160,
                _ if index + 1 == headers.len() => -1,
                _ => 110,
            });
        }
    }

    /// Scans the shown process with the rules in the rules directory. The
    /// rules are loaded anew every time, so changes to them are picked up.
    pub fn scan(&self) {
        if self.inner.mode.get() == DetailsMode::VirusTotal {
            self.check_virustotal();
        } else {
            self.scan_yara(false);
        }
    }

    pub fn connect_virustotal_result(&self, callback: impl Fn(libc::pid_t, String) + 'static) {
        *self.inner.on_virustotal_result.borrow_mut() = Some(Box::new(callback));
    }

    fn check_virustotal(&self) {
        let inner = &self.inner;
        let Some(pid) = inner.pid.get() else {
            return;
        };
        if inner.scanning.replace(true) {
            return;
        }
        self.refresh();

        let this = self.clone();
        glib::spawn_future_local(async move {
            let outcome = virustotal_outcome(pid).await;

            this.inner.scanning.set(false);
            if let (Some(text), Some(callback)) =
                (&outcome.column, &*this.inner.on_virustotal_result.borrow())
            {
                callback(pid, text.clone());
            }
            this.inner
                .virustotal_results
                .borrow_mut()
                .insert(pid, outcome);
            *this.inner.shown.borrow_mut() = None;
            this.inner.scan_button.set_sensitive(true);
            this.refresh();
        });
    }

    fn scan_yara(&self, memory: bool) {
        let inner = &self.inner;
        let Some(pid) = inner.pid.get() else {
            return;
        };
        if inner.scanning.replace(true) {
            return;
        }
        self.refresh();

        let this = self.clone();
        glib::spawn_future_local(async move {
            let dir = yara::rules_dir();
            let outcome = gio::spawn_blocking(move || {
                let rules = yara::load_rules(&dir);

                if rules.is_empty() {
                    let mut summary =
                        i18n_f("No YARA rules found in {}", &[&dir.to_string_lossy()]);
                    if let Some(error) = rules.errors.first() {
                        summary.push_str(&format!(
                            " — {}: {}",
                            error.file.display(),
                            error.message.lines().next().unwrap_or_default()
                        ));
                    }
                    return YaraOutcome {
                        rows: Vec::new(),
                        summary,
                        problems: rule_problems(&rules.errors),
                        column: None,
                    };
                }

                let (rows, mut summary) = if memory {
                    match yara::scan_process_memory(&rules, pid) {
                        Ok(report) => (yara_rows(&report.matches), yara_memory_summary(&report)),
                        Err(error) => (Vec::new(), error.to_string()),
                    }
                } else {
                    let report = yara::scan_process(&rules, pid);
                    (yara_rows(&report.matches), yara_summary(&report))
                };
                if !rules.errors.is_empty() {
                    summary.push_str(&format!(
                        " — {}",
                        ni18n_f(
                            "{} rule file could not be compiled",
                            "{} rule files could not be compiled",
                            rules.errors.len() as u32,
                            &[&rules.errors.len().to_string()],
                        )
                    ));
                }
                YaraOutcome {
                    rows,
                    summary,
                    problems: rule_problems(&rules.errors),
                    column: None,
                }
            })
            .await;

            this.inner.scanning.set(false);
            if let Ok(outcome) = outcome {
                this.inner.yara_results.borrow_mut().insert(pid, outcome);
            }
            *this.inner.shown.borrow_mut() = None;
            this.inner.scan_button.set_sensitive(true);
            this.refresh();
        });
    }

    fn open_rules_folder(&self) {
        let dir = yara::rules_dir();
        let _ = std::fs::create_dir_all(&dir);
        let launcher = gtk::FileLauncher::new(Some(&gio::File::for_path(&dir)));
        let window = self.inner.root.root().and_downcast::<gtk::Window>();
        launcher.launch(window.as_ref(), gio::Cancellable::NONE, |_| {});
    }

    /// Re-reads the data for the current process and mode.
    pub fn refresh(&self) {
        let inner = &self.inner;
        let mode = inner.mode.get();

        let mut tooltip = String::new();
        let (rows, title): (Vec<String>, String) = match inner.pid.get() {
            None => (
                Vec::new(),
                i18n("Select a single process to see its details"),
            ),
            Some(pid) if mode.is_on_demand() => {
                let scanning = inner.scanning.get();
                inner.scan_button.set_sensitive(!scanning);
                inner.memory_button.set_sensitive(!scanning);
                let results = if mode == DetailsMode::Yara {
                    &inner.yara_results
                } else {
                    &inner.virustotal_results
                };
                match results.borrow().get(&pid) {
                    _ if scanning => (Vec::new(), i18n("Working…")),
                    Some(outcome) => {
                        tooltip = outcome.problems.clone();
                        (outcome.rows.clone(), outcome.summary.clone())
                    }
                    None if mode == DetailsMode::Yara => (
                        Vec::new(),
                        i18n("Press Scan to check this process with your YARA rules"),
                    ),
                    None => (
                        Vec::new(),
                        i18n("Press Check to look this process up on VirusTotal"),
                    ),
                }
            }
            Some(pid) => match mode.rows(pid) {
                Ok(rows) => {
                    let title = format!("{} — {}", mode.label(), rows.len());
                    (rows.into_iter().map(|row| row.join("\t")).collect(), title)
                }
                Err(_) => (
                    Vec::new(),
                    i18n("Not available (the process has ended or access is denied)"),
                ),
            },
        };

        inner.title.set_text(&title);
        inner.title.set_tooltip_text(
            Some(&tooltip)
                .filter(|text| !text.is_empty())
                .map(String::as_str),
        );

        if inner.shown.borrow().as_ref() == Some(&rows) {
            return;
        }

        let items: Vec<gtk::StringObject> =
            rows.iter().map(|row| gtk::StringObject::new(row)).collect();
        inner.store.splice(0, inner.store.n_items(), &items);
        *inner.shown.borrow_mut() = Some(rows);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yara_rows_are_tab_safe() {
        let report = ScanReport {
            matches: vec![yara::YaraMatch {
                rule: "has\ttab".into(),
                tags: vec!["a".into(), "b".into()],
                target: yara::Target::File("/tmp/with\nnewline".into()),
            }],
            files_scanned: 3,
            files_failed: 0,
            files_skipped: 0,
        };
        let rows = yara_rows(&report.matches);
        assert_eq!(rows, vec!["has tab\ta, b\t/tmp/with newline"]);
        assert_eq!(
            rows[0].split('\t').count(),
            DetailsMode::Yara.headers().len()
        );
    }

    #[test]
    fn yara_summary_mentions_problems() {
        let report = ScanReport {
            files_failed: 2,
            files_skipped: 1,
            ..ScanReport::default()
        };
        let summary = yara_summary(&report);
        assert!(summary.contains("0 matches"), "{summary}");
        assert!(summary.contains("2 unreadable"), "{summary}");
        assert!(summary.contains("1 skipped"), "{summary}");
    }

    #[test]
    fn yara_memory_summary_explains_denial_and_problems() {
        let denied = yara::MemoryReport {
            denied: true,
            ..Default::default()
        };
        assert!(yara_memory_summary(&denied).contains("denied"));

        let report = yara::MemoryReport {
            regions_scanned: 3,
            bytes_scanned: 3 * 1024 * 1024,
            regions_failed: 1,
            regions_skipped: 2,
            ..Default::default()
        };
        let summary = yara_memory_summary(&report);
        assert!(summary.contains("3 regions scanned"), "{summary}");
        assert!(summary.contains("3.0 MiB"), "{summary}");
        assert!(summary.contains("1 unreadable"), "{summary}");
        assert!(summary.contains("2 skipped"), "{summary}");
    }

    #[test]
    fn mode_index_roundtrip() {
        for mode in DetailsMode::ALL {
            assert_eq!(DetailsMode::from_index(mode.index()), mode);
        }
        assert_eq!(DetailsMode::from_index(99), DetailsMode::Libraries);
    }
}
