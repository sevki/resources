//! "Find Open File or Library" — searches all processes for open files and
//! mapped libraries matching a text, like Process Explorer's Find Handle or
//! DLL.

use adw::prelude::*;
use gtk::gio;
use gtk::glib::{self, clone};
use process_data::details::{self, FindKind, FindMatch};

use crate::utils::i18n::{i18n, i18n_f};

/// Upper bound of shown results so that searching for e.g. "/" stays responsive
const MAX_RESULTS: usize = 500;

fn process_name(pid: libc::pid_t) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|name| name.trim().to_string())
        .unwrap_or_else(|_| i18n("Unknown"))
}

pub fn present(parent: &impl IsA<gtk::Widget>) {
    let dialog = adw::Dialog::builder()
        .title(i18n("Find Open File or Library"))
        .content_width(640)
        .content_height(520)
        .build();

    let entry = gtk::SearchEntry::builder()
        .placeholder_text(i18n("Part of a file or library path, then press Enter"))
        .hexpand(true)
        .build();

    let status = adw::StatusPage::builder()
        .icon_name("search-symbolic")
        .title(i18n("Search Processes"))
        .description(i18n(
            "Find which processes have a file open or a library loaded",
        ))
        .build();

    let list = gtk::ListBox::builder()
        .selection_mode(gtk::SelectionMode::None)
        .css_classes(["boxed-list"])
        .margin_top(12)
        .margin_bottom(12)
        .margin_start(12)
        .margin_end(12)
        .valign(gtk::Align::Start)
        .build();

    let stack = gtk::Stack::new();
    stack.add_named(&status, Some("status"));
    stack.add_named(
        &gtk::ScrolledWindow::builder()
            .child(&list)
            .vexpand(true)
            .build(),
        Some("results"),
    );

    let header = adw::HeaderBar::new();
    let toolbar = adw::ToolbarView::new();
    toolbar.add_top_bar(&header);
    let search_box = gtk::Box::builder()
        .margin_start(12)
        .margin_end(12)
        .margin_bottom(6)
        .build();
    search_box.append(&entry);
    toolbar.add_top_bar(&search_box);
    toolbar.set_content(Some(&stack));
    dialog.set_child(Some(&toolbar));

    entry.connect_activate(clone!(
        #[weak]
        list,
        #[weak]
        stack,
        #[weak]
        status,
        move |entry| {
            let needle = entry.text().to_string();
            if needle.trim().is_empty() {
                return;
            }

            status.set_icon_name(Some("system-search-symbolic"));
            status.set_title(&i18n("Searching…"));
            status.set_description(None);
            stack.set_visible_child_name("status");

            glib::spawn_future_local(clone!(
                #[weak]
                list,
                #[weak]
                stack,
                #[weak]
                status,
                async move {
                    let result = gio::spawn_blocking(move || {
                        let matches = details::find_all(&needle);
                        let total = matches.len();
                        let shown: Vec<(FindMatch, String)> = matches
                            .into_iter()
                            .take(MAX_RESULTS)
                            .map(|found| {
                                let name = process_name(found.pid);
                                (found, name)
                            })
                            .collect();
                        (shown, total)
                    })
                    .await;

                    let Ok((shown, total)) = result else {
                        return;
                    };

                    list.remove_all();

                    if shown.is_empty() {
                        status.set_icon_name(Some("system-search-symbolic"));
                        status.set_title(&i18n("No Matches"));
                        status.set_description(Some(&i18n(
                            "No accessible process has a matching file open or library loaded",
                        )));
                        stack.set_visible_child_name("status");
                        return;
                    }

                    for (found, name) in &shown {
                        let kind = match found.kind {
                            FindKind::Library => i18n("Library"),
                            FindKind::File => i18n("Open file"),
                        };
                        let row = adw::ActionRow::builder()
                            .title(glib::markup_escape_text(&found.target))
                            .subtitle(glib::markup_escape_text(&format!(
                                "{name} ({}) — {kind}",
                                found.pid
                            )))
                            .title_selectable(true)
                            .build();
                        list.append(&row);
                    }

                    if total > shown.len() {
                        list.append(
                            &adw::ActionRow::builder()
                                .title(i18n_f(
                                    "Showing the first {} of {} matches",
                                    &[&shown.len().to_string(), &total.to_string()],
                                ))
                                .build(),
                        );
                    }

                    stack.set_visible_child_name("results");
                }
            ));
        }
    ));

    dialog.present(Some(parent));
    entry.grab_focus();
}
