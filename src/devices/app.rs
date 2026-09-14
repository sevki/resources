use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    sync::LazyLock,
    time::Instant,
};

use anyhow::{Context, Result, bail};
use gio_unix::DesktopAppInfo;
use gtk::{
    gio::{File, FileIcon, Icon, ThemedIcon},
    glib::GString,
    prelude::AppInfoExt,
};
use ini::Properties;
use lazy_regex::{Lazy, Regex, lazy_regex};
use log::{debug, info, trace};
use process_data::{
    Containerization, ProcessData,
    gpu_usage::{GpuFractions, GpuIdentifier, GpuUsageAccumulator},
    pci_slot::PciSlot,
};

use crate::utils::{boot_time, i18n::i18n, read_parsed, snapd};

use futures::future::{FutureExt, LocalBoxFuture, Shared};

use super::process::{Process, ProcessAction};

fn gpu_fractions<'a>(
    processes: impl Iterator<Item = &'a Process>,
    gpu_filter: Option<GpuIdentifier>,
) -> GpuFractions {
    let mut usage = GpuUsageAccumulator::default();
    for process in processes {
        for (gpu, new) in &process.data.gpu_usage_stats {
            if gpu_filter.is_some_and(|filter| filter != *gpu) {
                continue;
            }
            if let Some(old) = process.gpu_usage_stats_last.get(gpu) {
                usage.add(*gpu, new, old);
            }
        }
    }
    usage.fractions()
}

// This contains executable names that are blocklisted from being recognized as applications
const DESKTOP_EXEC_BLOCKLIST: &[&str] = &["bash", "zsh", "fish", "sh", "ksh", "flatpak"];

// This contains IDs of desktop files that shouldn't be counted as applications for whatever reason
static APP_ID_BLOCKLIST: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    HashMap::from([
        (
            "org.gnome.Terminal.Preferences",
            "Prevents the actual Terminal app \"org.gnome.Terminal\" from being shown",
        ),
        (
            "org.freedesktop.IBus.Panel.Extension.Gtk3",
            "Technical application",
        ),
        ("org.gnome.RemoteDesktop.Handover", "Technical application"),
        (
            "gnome-software-local-file-packagekit",
            "Technical application",
        ),
        ("snap-handle-link", "Technical application"),
        ("gnome-about-panel", "Technical application"),
        ("gnome-applications-panel", "Technical application"),
        ("gnome-background-panel", "Technical application"),
        ("gnome-bluetooth-panel", "Technical application"),
        ("gnome-color-panel", "Technical application"),
        ("gnome-datetime-panel", "Technical application"),
        ("gnome-display-panel", "Technical application"),
        ("gnome-keyboard-panel", "Technical application"),
        ("gnome-mouse-panel", "Technical application"),
        ("gnome-multitasking-panel", "Technical application"),
        ("gnome-network-panel", "Technical application"),
        ("gnome-notifications-panel", "Technical application"),
        ("gnome-online-accounts-panel", "Technical application"),
        ("gnome-power-panel", "Technical application"),
        ("gnome-printers-panel", "Technical application"),
        ("gnome-privacy-panel", "Technical application"),
        ("gnome-region-panel", "Technical application"),
        ("gnome-search-panel", "Technical application"),
        ("gnome-sharing-panel", "Technical application"),
        ("gnome-sound-panel", "Technical application"),
        ("gnome-system-panel", "Technical application"),
        ("gnome-universal-access-panel", "Technical application"),
        ("gnome-users-panel", "Technical application"),
        ("gnome-wacom-panel", "Technical application"),
        ("gnome-wifi-panel", "Technical application"),
        ("gnome-wwan-panel", "Technical application"),
        ("org.freedesktop.Xwayland", "Technical application"),
    ])
});

static RE_ENV_FILTER: Lazy<Regex> = lazy_regex!(r"env\s*\S*=\S*\s*(.*)");

static RE_FLATPAK_FILTER: Lazy<Regex> = lazy_regex!(r"flatpak run .* --command=(\S*)");

static RE_STEAM_APPID: Lazy<Regex> = lazy_regex!(r"steam://rungameid/(\d+)");

fn format_path(path: &str) -> String {
    if path.starts_with("~/") {
        // $HOME may not include a trailing /, so we must not remove the extra trailing /
        path.replace(
            '~',
            &std::env::var("HOME").unwrap_or_else(|_| "/".to_string()),
        )
    } else {
        path.parse().unwrap()
    }
}

// Adapted from Mission Center: https://gitlab.com/mission-center-devs/mission-center/
pub static DATA_DIRS: LazyLock<Vec<PathBuf>> = LazyLock::new(|| {
    let local_share = format_path("~/.local/share");
    let mut data_dirs: Vec<PathBuf> = std::env::var("XDG_DATA_DIRS")
        .unwrap_or_else(|_| format!("/usr/share:{local_share}"))
        .split(':')
        .map(format_path)
        .map(PathBuf::from)
        .collect();
    data_dirs.push(PathBuf::from(local_share));
    data_dirs
});

// This contains known occurrences of processes having a too distinct name from the actual app
// The HashMap is used like this:
//   Key: The name of the executable of the process
//   Value: What it should be replaced with when finding out to which app it belongs
static KNOWN_EXECUTABLE_NAME_EXCEPTIONS: LazyLock<HashMap<&'static str, &'static str>> =
    LazyLock::new(|| {
        HashMap::from([
            ("firefox-bin", "firefox"),
            ("oosplash", "libreoffice"),
            ("soffice.bin", "libreoffice"),
            ("resources-processes", "resources"),
            ("gnome-terminal-server", "gnome-terminal"),
            ("chrome", "google-chrome-stable"),
        ])
    });

static MESSAGE_LOCALES: LazyLock<Vec<String>> = LazyLock::new(|| {
    const LOCALE_ENV_VAR_NAMES: &[&str] = &["LC_MESSAGES", "LANGUAGE", "LANG", "LC_ALL"];
    let mut return_vec: Vec<String> = Vec::new();

    for env in LOCALE_ENV_VAR_NAMES {
        if let Ok(locales) = std::env::var(env) {
            // split because LANGUAGE may contain multiple languages
            for locale in locales.split(':') {
                let locale = locale.to_string();

                if !return_vec.contains(&locale) {
                    return_vec.push(locale.clone());
                }

                if let Some(no_character_encoding) = locale.split_once('.') {
                    let no_character_encoding = no_character_encoding.0.to_string();
                    if !return_vec.contains(&no_character_encoding) {
                        return_vec.push(no_character_encoding);
                    }
                }

                if let Some(no_country_code) = locale.split_once('_') {
                    let no_country_code = no_country_code.0.to_string();
                    if !return_vec.contains(&no_country_code) {
                        return_vec.push(no_country_code);
                    }
                }
            }
        }
    }

    debug!(
        "Using the following locales for app names and descriptions: {:?}",
        return_vec
    );

    return_vec
});

/// Future that resolves to an optional app ID once deferred association completes.
type DeferredAppFuture = Shared<LocalBoxFuture<'static, Option<String>>>;

/// The result of attempting to associate a process with an app.
/// When association must be deferred (e.g. waiting for an async query), the future is returned.
enum AppAssociation {
    Resolved(Option<String>),
    Pending(DeferredAppFuture),
}

#[derive(Debug, Clone, Default)]
pub struct AppsContext {
    apps: HashMap<Option<String>, App>,
    processes: HashMap<i32, Process>,
    gpus_with_combined_media_engine: Vec<GpuIdentifier>,
    deferred: HashMap<i32, DeferredAppFuture>,
}

/// Represents an application installed on the system. It doesn't
/// have to be running (i.e. have alive processes).
#[derive(Debug, Clone)]
pub struct App {
    processes: Vec<i32>,
    pub commandline: Option<String>,
    pub executable_name: Option<String>,
    pub display_name: String,
    pub description: Option<String>,
    pub icon: Icon,
    pub id: Option<String>,
    pub read_bytes_from_dead_processes: u64,
    pub write_bytes_from_dead_processes: u64,
    pub containerization: Containerization,
}

/// Parsed key-value data from a .desktop file, produced by a parser strategy.
struct DesktopEntry {
    id: Option<String>,
    exec: Option<String>,
    icon: Option<String>,
    name: Option<String>,
    comment: Option<String>,
    has_snap: bool,
    has_appimage: bool,
    steam_appid: Option<String>,
}

impl App {
    pub fn all() -> Vec<Self> {
        debug!("Detecting installed apps");

        let start = Instant::now();

        let applications_dir: Vec<_> = DATA_DIRS
            .iter()
            .map(|path| path.join("applications"))
            .collect();

        debug!("Using the following directories for app detection: {applications_dir:?}");

        let mut apps: Vec<_> = applications_dir
            .iter()
            .filter_map(|applications_path| {
                applications_path.read_dir().ok().map(|read| {
                    read.filter_map(|file_res| {
                        file_res
                            .ok()
                            .and_then(|file| Self::from_desktop_file(file.path()).ok())
                    })
                })
            })
            .flatten()
            .collect();

        let elapsed = start.elapsed();

        info!("Detected {} apps within {elapsed:.2?}", apps.len());

        apps.push(Self {
            processes: Vec::new(),
            commandline: None,
            executable_name: None,
            display_name: i18n("System Processes"),
            description: None,
            icon: ThemedIcon::new("system-processes").into(),
            id: None,
            read_bytes_from_dead_processes: 0,
            write_bytes_from_dead_processes: 0,
            containerization: Containerization::None,
        });

        apps
    }

    fn from_desktop_file_gio<P: AsRef<Path>>(file_path: P) -> Result<DesktopEntry> {
        let file_path = file_path.as_ref();

        let desktop_entry = DesktopAppInfo::from_filename(file_path).with_context(|| {
            format!(
                "unable to load desktop app info from {}",
                file_path.to_string_lossy()
            )
        })?;

        let id = desktop_entry
            .string("X-Flatpak")
            .or_else(|| desktop_entry.string("X-AppImage-Identifier"))
            .map(String::from);

        let exec = desktop_entry
            .string("X-ExecLocation")
            .or_else(|| desktop_entry.string("Exec"))
            .map(String::from);

        let icon = desktop_entry.string("Icon").map(String::from);

        let name = desktop_entry.locale_string("Name").map(String::from);
        let comment = desktop_entry.description().map(String::from);

        let has_snap = desktop_entry.has_key("X-SnapInstanceName");
        let has_appimage = desktop_entry.has_key("X-AppImage-Identifier");

        let steam_appid = exec
            .as_deref()
            .and_then(|e| RE_STEAM_APPID.captures(e))
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        Ok(DesktopEntry {
            id,
            exec,
            icon,
            name,
            comment,
            has_snap,
            has_appimage,
            steam_appid,
        })
    }

    fn from_desktop_file_own_implementation<P: AsRef<Path>>(file_path: P) -> Result<DesktopEntry> {
        let ini = ini::Ini::load_from_str(&read_parsed::<String>(file_path.as_ref())?)?;
        let desktop_entry = ini
            .section(Some("Desktop Entry"))
            .context("no desktop entry section")?;

        let id = desktop_entry
            .get("X-Flatpak")
            .or_else(|| desktop_entry.get("X-AppImage-Identifier"));

        let exec = desktop_entry
            .get("X-ExecLocation")
            .or_else(|| desktop_entry.get("Exec"));

        let icon = desktop_entry.get("Icon");

        let name = Self::try_get_locale(desktop_entry, "Name");

        let comment = Self::try_get_locale(desktop_entry, "Comment");

        let has_snap = desktop_entry.get("X-SnapInstanceName").is_some();
        let has_appimage = desktop_entry.get("X-AppImage-Identifier").is_some();

        let steam_appid = exec
            .and_then(|e| RE_STEAM_APPID.captures(e))
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string());

        Ok(DesktopEntry {
            id: id.map(std::string::ToString::to_string),
            exec: exec.map(std::string::ToString::to_string),
            icon: icon.map(std::string::ToString::to_string),
            name,
            comment,
            has_snap,
            has_appimage,
            steam_appid,
        })
    }

    fn try_get_locale<S: AsRef<str>>(properties: &Properties, property: S) -> Option<String> {
        for locale in MESSAGE_LOCALES.iter() {
            if let Some(n) = properties.get(format!("{}[{locale}]", property.as_ref())) {
                return Some(n.to_string());
            }
        }

        properties
            .get(property)
            .map(std::string::ToString::to_string)
    }

    pub fn from_desktop_file<P: AsRef<Path>>(file_path: P) -> Result<Self> {
        let file_path = file_path.as_ref();

        // try gio first for distros with langpacks, fallback to own implementation because gio
        // doesn't work too well with flatpaks
        let entry = Self::from_desktop_file_gio(file_path)
            .or_else(|_| Self::from_desktop_file_own_implementation(file_path))?;

        let id = entry
            .id
            .clone()
            .or_else(|| {
                file_path
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
            })
            .context("unable to get ID of desktop file")
            .inspect_err(|_| trace!("Unable to get an ID for this .desktop file"))?;

        if let Some(reason) = APP_ID_BLOCKLIST.get(id.as_str()) {
            debug!("Skipping {id} because it's blocklisted ({reason})");
            bail!("{id} is blocklisted (reason: {reason})")
        }

        let exec = entry.exec.as_deref();
        let is_flatpak = exec.is_some_and(|e| e.starts_with("/usr/bin/flatpak run"));
        let commandline = exec
            .and_then(|e| {
                RE_ENV_FILTER
                    .captures(e)
                    .and_then(|c| c.get(1))
                    .map(|m| m.as_str())
                    .or(Some(e))
            })
            .map(str::to_string);

        let executable_name = commandline.clone().map(|cmdline| {
            RE_FLATPAK_FILTER
                .captures(&cmdline)
                .and_then(|c| c.get(1))
                .map(|m| m.as_str().to_string())
                .unwrap_or(cmdline)
                .split(' ')
                .nth(0)
                .unwrap_or_default()
                .split('/')
                .nth_back(0)
                .unwrap_or_default()
                .to_string()
        });

        let executable_name = if let Some(ref steam_appid) = entry.steam_appid {
            Some(format!("steam_{steam_appid}"))
        } else {
            executable_name
        };

        if let Some(ref executable_name) = executable_name
            && DESKTOP_EXEC_BLOCKLIST.contains(&executable_name.as_str())
        {
            debug!("Skipping {id} because its executable {executable_name} is blocklisted…");
            bail!("{id}'s executable {executable_name} is blocklisted")
        }

        let icon = entry.icon.as_ref().map_or_else(
            || ThemedIcon::new("generic-process").into(),
            |icon_key| {
                if Path::new(&format_path(icon_key)).exists() {
                    FileIcon::new(&File::for_path(icon_key)).into()
                } else {
                    ThemedIcon::new(icon_key).into()
                }
            },
        );

        let display_name = entry.name.unwrap_or_else(|| id.clone());
        let description = entry.comment;

        let containerization = if is_flatpak {
            Containerization::Flatpak
        } else if entry.has_snap {
            Containerization::Snap
        } else if entry.has_appimage {
            Containerization::AppImage
        } else {
            Containerization::None
        };

        let kind = match containerization {
            Containerization::Flatpak => "Flatpak",
            Containerization::Snap => "Snap",
            Containerization::AppImage => "AppImage",
            Containerization::Portable => "portable",
            Containerization::None => "native",
        };
        debug!(
            "Found {kind} app \"{display_name}\" (ID: {id:?}) at {} with commandline `{}` (detected executable name: {})",
            file_path.to_string_lossy(),
            commandline.as_ref().unwrap_or(&"<None>".into()),
            executable_name.as_ref().unwrap_or(&"<None>".into()),
        );

        Ok(Self {
            processes: Vec::new(),
            commandline,
            executable_name,
            display_name,
            description,
            icon,
            id: Some(id),
            read_bytes_from_dead_processes: 0,
            write_bytes_from_dead_processes: 0,
            containerization,
        })
    }

    /// Adds a process to the processes `HashMap` and also
    /// updates the `Process`' icon to the one of this
    /// `App`
    pub fn add_process(&mut self, process: &mut Process) {
        process.icon = self.icon.clone();
        self.processes.push(process.data.pid);
    }

    pub fn remove_process(&mut self, process: &Process) {
        self.processes.retain(|p| *p != process.data.pid);
    }

    #[must_use]
    pub const fn is_running(&self) -> bool {
        !self.processes.is_empty()
    }

    pub fn processes_iter<'a>(
        &'a self,
        apps: &'a AppsContext,
    ) -> impl Iterator<Item = &'a Process> {
        apps.processes_iter()
            .filter(move |process| self.processes.contains(&process.data.pid))
    }

    pub fn processes_iter_mut<'a>(
        &'a mut self,
        apps: &'a mut AppsContext,
    ) -> impl Iterator<Item = &'a mut Process> {
        apps.processes_iter_mut()
            .filter(move |process| self.processes.contains(&process.data.pid))
    }

    #[must_use]
    pub fn memory_usage(&self, apps: &AppsContext) -> usize {
        self.processes_iter(apps).map(Process::mem_usage).sum()
    }

    #[must_use]
    pub fn swap_usage(&self, apps: &AppsContext) -> usize {
        self.processes_iter(apps)
            .map(|process| process.data.swap_usage)
            .sum()
    }

    #[must_use]
    pub fn cpu_time_ratio(&self, apps: &AppsContext) -> f32 {
        self.processes_iter(apps).map(Process::cpu_time_ratio).sum()
    }

    #[must_use]
    pub fn read_speed(&self, apps: &AppsContext) -> f64 {
        self.processes_iter(apps)
            .filter_map(Process::read_speed)
            .sum()
    }

    #[must_use]
    pub fn read_total(&self, apps: &AppsContext) -> u64 {
        self.read_bytes_from_dead_processes.saturating_add(
            self.processes_iter(apps)
                .filter_map(|process| process.data.read_bytes)
                .sum::<u64>(),
        )
    }

    #[must_use]
    pub fn write_speed(&self, apps: &AppsContext) -> f64 {
        self.processes_iter(apps)
            .filter_map(Process::write_speed)
            .sum()
    }

    #[must_use]
    pub fn write_total(&self, apps: &AppsContext) -> u64 {
        self.write_bytes_from_dead_processes.saturating_add(
            self.processes_iter(apps)
                .filter_map(|process| process.data.write_bytes)
                .sum::<u64>(),
        )
    }

    #[must_use]
    pub fn gpu_usage(&self, apps: &AppsContext) -> f32 {
        gpu_fractions(self.processes_iter(apps), None).gfx
    }

    #[must_use]
    pub fn enc_usage(&self, apps: &AppsContext) -> f32 {
        gpu_fractions(self.processes_iter(apps), None).enc
    }

    #[must_use]
    pub fn dec_usage(&self, apps: &AppsContext) -> f32 {
        gpu_fractions(self.processes_iter(apps), None).dec
    }

    #[must_use]
    pub fn gpu_mem_usage(&self, apps: &AppsContext) -> u64 {
        self.processes_iter(apps).map(Process::gpu_mem_usage).sum()
    }

    #[must_use]
    pub fn starttime(&self, apps: &AppsContext) -> f64 {
        self.processes_iter(apps)
            .map(Process::starttime)
            .min_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap_or_default()
    }

    pub fn execute_process_action(
        &self,
        apps: &AppsContext,
        action: ProcessAction,
    ) -> Vec<Result<()>> {
        self.processes_iter(apps)
            .map(|process| process.execute_process_action(action))
            .collect()
    }

    pub fn running_since(&self, apps: &AppsContext) -> Result<GString> {
        boot_time()
            .and_then(|boot_time| {
                boot_time
                    .add_seconds(self.starttime(apps))
                    .context("unable to add seconds to boot time")
            })
            .and_then(|time| time.format("%c").context("unable to format running_since"))
    }

    pub const fn running_processes(&self) -> usize {
        self.processes.len()
    }
}

impl AppsContext {
    /// Creates a new `AppsContext` object, this operation is quite expensive
    /// so try to do it only one time during the lifetime of the program.
    /// Please call `refresh()` immediately after this function.
    pub fn new(gpus_with_combined_media_engine: Vec<GpuIdentifier>) -> Self {
        let apps: HashMap<Option<String>, App> = App::all()
            .into_iter()
            .map(|app| (app.id.clone(), app))
            .collect();

        Self {
            apps,
            processes: HashMap::new(),
            gpus_with_combined_media_engine,
            deferred: HashMap::new(),
        }
    }

    pub fn gpu_fraction(&self, gpu_identifier: GpuIdentifier) -> f32 {
        gpu_fractions(self.processes_iter(), Some(gpu_identifier))
            .gfx
            .clamp(0.0, 1.0)
    }

    pub fn encoder_fraction(&self, gpu_identifier: GpuIdentifier) -> f32 {
        gpu_fractions(self.processes_iter(), Some(gpu_identifier))
            .enc
            .clamp(0.0, 1.0)
    }

    pub fn decoder_fraction(&self, gpu_identifier: GpuIdentifier) -> f32 {
        gpu_fractions(self.processes_iter(), Some(gpu_identifier))
            .dec
            .clamp(0.0, 1.0)
    }

    pub fn npu_fraction(&self, pci_slot: PciSlot) -> f32 {
        self.processes_iter()
            .map(|process| {
                (
                    &process.data.npu_usage_stats,
                    &process.npu_usage_stats_last,
                    process.data.timestamp,
                    process.timestamp_last,
                )
            })
            .map(|(new, old, timestamp, timestamp_last)| {
                (
                    new.get(&pci_slot),
                    old.get(&pci_slot),
                    timestamp,
                    timestamp_last,
                )
            })
            .filter_map(|(new, old, timestamp, timestamp_last)| match (new, old) {
                (Some(new), Some(old)) => Some((new, old, timestamp, timestamp_last)),
                _ => None,
            })
            .map(|(new, old, timestamp, timestamp_last)| {
                let time_delta = timestamp.saturating_sub(timestamp_last);
                new.usage_fraction(old, time_delta).unwrap_or_default()
            })
            .sum::<f32>()
            .clamp(0.0, 1.0)
    }

    pub fn npu_mem(&self, pci_slot: PciSlot) -> u64 {
        self.processes_iter()
            .filter_map(|process| {
                process
                    .data
                    .npu_usage_stats
                    .get(&pci_slot)
                    .and_then(process_data::npu_usage::NpuUsageStats::mem)
            })
            .sum()
    }

    pub fn vram_usage(&self, gpu_identifier: GpuIdentifier) -> u64 {
        self.processes_iter()
            .filter_map(|process| {
                process
                    .data
                    .gpu_usage_stats
                    .get(&gpu_identifier)
                    .and_then(process_data::gpu_usage::GpuClientSnapshots::mem)
            })
            .sum()
    }

    fn app_associated_with_process(&self, process: &Process) -> AppAssociation {
        if let Some(assoc) = self.try_steam_appid_match(process) {
            return assoc;
        }
        if let Some(assoc) = self.try_cgroup_match(process) {
            return assoc;
        }
        if let Some(assoc) = self.try_appimage_match(process) {
            return assoc;
        }
        if let Some(assoc) = self.try_snap_match(process) {
            return assoc;
        }
        if let Some(app) = self.exact_executable_match(process) {
            debug!(
                "Associating process {} with app {:?} via exact executable match",
                process.data.pid,
                app.id.as_deref().unwrap_or("N/A")
            );
            return AppAssociation::Resolved(app.id.clone());
        }
        if let Some(app) = self.parent_app_match(process) {
            debug!(
                "Associating process {} with app {:?} via parent process {}",
                process.data.pid,
                app.id.as_deref().unwrap_or("N/A"),
                process.data.parent_pid,
            );
            return AppAssociation::Resolved(app.id.clone());
        }

        AppAssociation::Resolved(self.fallback_commandline_match(process))
    }

    fn try_steam_appid_match(&self, process: &Process) -> Option<AppAssociation> {
        let steam_appid = process.data.steam_appid.as_ref()?;
        let app = self
            .apps
            .values()
            .find(|app| app.executable_name.as_deref() == Some(&format!("steam_{steam_appid}")))?;

        debug!(
            "Associating process {} with Steam game {:?} via Steam App ID {}",
            process.data.pid,
            app.id.as_deref().unwrap_or("N/A"),
            steam_appid
        );
        Some(AppAssociation::Resolved(app.id.clone()))
    }

    fn try_cgroup_match(&self, process: &Process) -> Option<AppAssociation> {
        let cgroup_app = self
            .apps
            .get(&Some(process.data.cgroup.clone().unwrap_or_default()))?;

        // skip cgroup match for Steam processes that have a SteamAppId
        // (should be matched by AppId above, not by Steam's own cgroup)
        if process.data.steam_appid.is_some() && cgroup_app.id.as_deref() == Some("steam") {
            return None;
        }

        debug!(
            "Associating process {} with app {:?} via cgroup match",
            process.data.pid,
            cgroup_app.id.as_deref().unwrap_or("N/A")
        );
        Some(AppAssociation::Resolved(cgroup_app.id.clone()))
    }

    fn try_appimage_match(&self, process: &Process) -> Option<AppAssociation> {
        let appimage_path = process.data.appimage_path.as_ref()?;
        let app = self.apps.values().find(|app| {
            app.containerization == Containerization::AppImage
                && app
                    .commandline
                    .as_ref()
                    .is_some_and(|exe| exe == appimage_path)
        })?;

        Some(AppAssociation::Resolved(app.id.clone()))
    }

    fn try_snap_match(&self, process: &Process) -> Option<AppAssociation> {
        if process.data.containerization != Containerization::Snap {
            return None;
        }
        let (snap_name, snap_app) = process
            .data
            .cgroup
            .as_deref()
            .and_then(|c| c.split_once('.'))?;

        let fut = snapd::get_desktop_id(snap_name, snap_app);
        match fut.clone().now_or_never() {
            None => {
                debug!(
                    "Deferring association of snap process {} until async query completes",
                    process.data.pid
                );
                Some(AppAssociation::Pending(fut))
            }
            Some(Some(id)) if self.apps.contains_key(&Some(id.clone())) => {
                debug!(
                    "Associating snap process {} with app {id:?} via snapd query",
                    process.data.pid
                );
                Some(AppAssociation::Resolved(Some(id)))
            }
            Some(None) => {
                let id = format!("{snap_name}_{snap_app}");
                self.apps.contains_key(&Some(id.clone())).then(|| {
                    debug!(
                        "Associating snap process {} with app {id:?} via cgroup fallback",
                        process.data.pid
                    );
                    AppAssociation::Resolved(Some(id))
                })
            }
            Some(_) => None,
        }
    }

    fn exact_executable_match(&self, process: &Process) -> Option<&App> {
        self.apps
            .get(&Some(process.executable_path.clone()))
            .or_else(|| self.apps.get(&Some(process.executable_name.clone())))
    }

    fn parent_app_match(&self, process: &Process) -> Option<&App> {
        self.apps
            .values()
            .find(|app| app.id.is_some() && app.processes.contains(&process.data.parent_pid))
    }

    fn fallback_commandline_match(&self, process: &Process) -> Option<String> {
        self.apps
            .values()
            .find(|app| {
                app.commandline
                    .as_ref()
                    .is_some_and(|c| c == &process.executable_path)
                    || app
                        .executable_name
                        .as_ref()
                        .and_then(|name| {
                            KNOWN_EXECUTABLE_NAME_EXCEPTIONS
                                .get(process.executable_name.as_str())
                                .map(|sub| sub == name)
                        })
                        .unwrap_or(false)
            })
            .and_then(|app| app.id.clone())
    }

    pub fn get_process(&self, pid: i32) -> Option<&Process> {
        self.processes.get(&pid)
    }

    pub fn get_app(&self, id: &Option<String>) -> Option<&App> {
        self.apps.get(id)
    }

    pub fn processes_iter(&self) -> impl Iterator<Item = &Process> {
        self.processes.values()
    }

    pub fn processes_iter_mut(&mut self) -> impl Iterator<Item = &mut Process> {
        self.processes.values_mut()
    }

    pub fn apps_iter(&self) -> impl Iterator<Item = &App> {
        self.apps.values()
    }

    pub fn running_apps_iter(&self) -> impl Iterator<Item = &App> {
        self.apps_iter().filter(|app| {
            app.is_running()
                && !app
                    .id
                    .as_ref()
                    .is_some_and(|id| id.starts_with("xdg-desktop-portal"))
        })
    }

    /// Refreshes the statistics about the running applications and processes.
    /// For new processes whose association is deferred (awaiting an async query),
    /// the result is picked up on the next call once the future resolves.
    pub fn refresh(&mut self, new_process_data: Vec<ProcessData>) {
        trace!("Refreshing AppsContext…");
        let start = Instant::now();

        // Drain deferred: associate any processes whose pending future has now resolved.
        let resolved_pids: Vec<i32> = self
            .deferred
            .iter()
            .filter_map(|(&pid, fut)| fut.clone().now_or_never().is_some().then_some(pid))
            .collect();
        for pid in resolved_pids {
            self.deferred.remove(&pid);
            let Some(process) = self.processes.get(&pid) else {
                continue;
            };
            // Re-invoke app_associated_with_process; now that the future has resolved
            // it will return Resolved (either matched or heuristic fallback).
            let AppAssociation::Resolved(app_id) = self.app_associated_with_process(process) else {
                continue;
            };
            debug!("Associating deferred process {pid} with app {app_id:?}");
            let Some(process) = self.processes.get_mut(&pid) else {
                continue;
            };
            self.apps.get_mut(&app_id).unwrap().add_process(process);
        }

        let mut updated_processes = HashSet::new();

        for mut process_data in new_process_data {
            trace!("Refreshing process {}…", process_data.pid);
            updated_processes.insert(process_data.pid);

            // this is awkward: since AppsContext is the only object around that knows what GPUs have combined media
            // engines, it is here where we have to manipulate the GpuClientSnapshots objects with PciSlots of those GPUs
            // whose media engine is combined (i.e. no discrimination between enc and dec stats)
            process_data
                .gpu_usage_stats
                .iter_mut()
                .filter(|(pci_slot, _)| self.gpus_with_combined_media_engine.contains(pci_slot))
                .for_each(|(pci_slot, stats)| {
                    trace!("Manually adjusting GPU stats of {} for {pci_slot} due to combined media engine", process_data.pid);

                    stats.combine_media_engines();
                });

            // refresh our old processes
            if let Some(old_process) = self.processes.get_mut(&process_data.pid) {
                trace!("{} has been there before, updating it", process_data.pid);

                old_process.cpu_time_last = old_process
                    .data
                    .user_cpu_time
                    .saturating_add(old_process.data.system_cpu_time);
                old_process.timestamp_last = old_process.data.timestamp;
                old_process.read_bytes_last = old_process.data.read_bytes;
                old_process.write_bytes_last = old_process.data.write_bytes;
                for (gpu, stats) in &mut process_data.gpu_usage_stats {
                    if let Some(old) = old_process.data.gpu_usage_stats.get(gpu) {
                        stats.retain_busy_high_water(old);
                    }
                }
                old_process.gpu_usage_stats_last = old_process.data.gpu_usage_stats.clone();
                old_process.npu_usage_stats_last = old_process.data.npu_usage_stats.clone();

                old_process.data = process_data.clone();
            } else {
                // this is a new process, see if it belongs to a graphical app
                trace!("{} is a new process", process_data.pid);

                let mut new_process = Process::from_process_data(process_data);
                let pid = new_process.data.pid;

                match self.app_associated_with_process(&new_process) {
                    AppAssociation::Resolved(app_id) => {
                        self.apps
                            .get_mut(&app_id)
                            .unwrap()
                            .add_process(&mut new_process);
                    }
                    AppAssociation::Pending(fut) => {
                        self.deferred.insert(pid, fut);
                    }
                }
                self.processes.insert(pid, new_process);
            }
        }

        // collect the I/O stats for died app processes so an app doesn't suddenly have less total disk I/O
        self.apps.values_mut().for_each(|app| {
            let (read_dead, write_dead) = app
                .processes
                .iter()
                .filter(|pid| !updated_processes.contains(*pid)) // only dead processes
                .filter_map(|pid| self.processes.get(pid)) // ignore about non-existing processes
                .map(|process| (process.data.read_bytes, process.data.write_bytes)) // get their read_bytes and write_bytes
                .filter_map(
                    // filter out any processes whose IO stats we were not allowed to see
                    |(read_bytes, write_bytes)| match (read_bytes, write_bytes) {
                        (Some(read), Some(write)) => Some((read, write)),
                        _ => None,
                    },
                )
                .reduce(|sum, current| {
                    // sum them up
                    (
                        sum.0.saturating_add(current.0),
                        sum.1.saturating_add(current.1),
                    )
                })
                .unwrap_or((0, 0)); // if there were no processes, it's 0 for both

            app.read_bytes_from_dead_processes += read_dead;
            app.write_bytes_from_dead_processes += write_dead;

            if read_dead > 0 || write_dead > 0 {
                trace!(
                    "{} has a process which died earlier, keeping I/O stats",
                    app.display_name
                );
            }

            app.processes.retain(|pid| updated_processes.contains(pid));

            if !app.is_running() {
                app.read_bytes_from_dead_processes = 0;
                app.write_bytes_from_dead_processes = 0;
            }
        });

        // all the not-updated processes have unfortunately died, probably
        self.processes
            .retain(|pid, _| updated_processes.contains(pid));

        // Drop pids from deferred that belong to processes that no longer exist.
        self.deferred
            .retain(|pid, _| updated_processes.contains(pid));

        trace!("AppsContext refresh done within {:.2?}", start.elapsed());
    }
}
