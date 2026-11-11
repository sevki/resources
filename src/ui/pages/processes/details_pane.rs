//! Lower pane of the Processes page showing details of the selected process
//! (libraries, open files, network connections, threads, environment and
//! security attributes), modelled after Process Explorer's lower pane and
//! properties tabs.

use std::cell::{Cell, RefCell};
use std::rc::Rc;

use adw::prelude::*;
use gtk::glib::clone;
use gtk::{gio, pango};
use process_data::details::{self, FdKind};

use crate::utils::TICK_RATE;
use crate::utils::i18n::i18n;
use crate::utils::units::{convert_storage, format_time};

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
}

impl DetailsMode {
    pub const ALL: [Self; 6] = [
        Self::Libraries,
        Self::Files,
        Self::Network,
        Self::Threads,
        Self::Environment,
        Self::Security,
    ];

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
    on_mode_changed: RefCell<Option<Box<dyn Fn(DetailsMode)>>>,
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
        });
        let this = Self { inner };

        // mode selector
        let selector = gtk::Box::new(gtk::Orientation::Horizontal, 0);
        selector.add_css_class("linked");
        let mut group: Option<gtk::ToggleButton> = None;
        for mode in DetailsMode::ALL {
            let button = gtk::ToggleButton::with_label(&mode.label());
            button.set_active(mode == initial_mode);
            if let Some(group) = &group {
                button.set_group(Some(group));
            } else {
                group = Some(button.clone());
            }
            button.connect_toggled(clone!(
                #[strong]
                this,
                move |button| {
                    if button.is_active() {
                        this.set_mode(mode);
                        if let Some(callback) = &*this.inner.on_mode_changed.borrow() {
                            callback(mode);
                        }
                    }
                }
            ));
            selector.append(&button);
        }

        let header = gtk::Box::new(gtk::Orientation::Horizontal, 12);
        header.set_margin_top(6);
        header.set_margin_bottom(6);
        header.set_margin_start(12);
        header.set_margin_end(12);
        header.append(&selector);
        header.append(&this.inner.title);

        this.inner.root.append(&header);
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

    /// Sets the process whose details are shown, `None` if no single process
    /// is selected.
    pub fn set_pid(&self, pid: Option<libc::pid_t>) {
        if self.inner.pid.replace(pid) != pid {
            *self.inner.shown.borrow_mut() = None;
            self.refresh();
        }
    }

    fn apply_headers(&self) {
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
                _ if index + 1 == headers.len() => -1,
                _ => 110,
            });
        }
    }

    /// Re-reads the data for the current process and mode.
    pub fn refresh(&self) {
        let inner = &self.inner;
        let mode = inner.mode.get();

        let (rows, title): (Vec<String>, String) = match inner.pid.get() {
            None => (
                Vec::new(),
                i18n("Select a single process to see its details"),
            ),
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
    fn mode_index_roundtrip() {
        for mode in DetailsMode::ALL {
            assert_eq!(DetailsMode::from_index(mode.index()), mode);
        }
        assert_eq!(DetailsMode::from_index(99), DetailsMode::Libraries);
    }
}
