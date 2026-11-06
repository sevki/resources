use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::LazyLock;

use anyhow::{Context, Result};
use log::{debug, trace};
use nutype::nutype;
use serde::{Deserialize, Serialize};

use crate::cgroup;
use crate::fdinfo::{self, Fdinfo};
use crate::gpu_usage::{GpuClientSnapshots, GpuIdentifier};
use crate::npu_usage::NpuUsageStats;
use crate::nvidia::NvidiaSnapshot;
use crate::pci_slot::PciSlot;
use crate::proc_files::{IoFields, StatFields, StatusFields};
use crate::pss::{self};
use crate::util::{read_parsed, unix_as_millis};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
pub enum PssMode {
    /// don't read any PSS as all
    Disabled,
    /// approximate PSS (more expensive, more accurate)
    Approximate,
    /// use exact PSS provided by the kernel (most expensive, most accurate)
    Exact,
}

#[nutype(
    validate(less_or_equal = 19),
    validate(greater_or_equal = -20),
    derive(
        Debug,
        Default,
        Clone,
        Hash,
        PartialEq,
        Eq,
        Serialize,
        Deserialize,
        Copy,
        FromStr,
        Deref,
        TryFrom,
        Display,
        PartialOrd,
        Ord,
    ),
    default = 0
)]
pub struct Niceness(i8);

#[derive(
    Debug, Clone, Default, Hash, PartialEq, Eq, Serialize, Deserialize, Copy, PartialOrd, Ord,
)]
pub enum Containerization {
    #[default]
    None,
    Flatpak,
    Portable,
    Snap,
    AppImage,
}

impl Containerization {
    #[must_use]
    pub fn detect(
        proc_root: &Path,
        commandline: &str,
        launcher: &str,
        has_appimage_path: bool,
    ) -> Self {
        if commandline.starts_with("/snap/") || launcher == "snap" {
            Self::Snap
        } else if proc_root.join("top.kimiblock.portable").exists() || launcher == "portable" {
            Self::Portable
        } else if proc_root.join(".flatpak-info").exists() || launcher == "flatpak" {
            Self::Flatpak
        } else if has_appimage_path {
            Self::AppImage
        } else {
            Self::None
        }
    }
}

static USERS_CACHE: LazyLock<HashMap<libc::uid_t, String>> = LazyLock::new(|| {
    debug!("Initializing users cache…");
    let users: HashMap<libc::uid_t, String> = unsafe { uzers::all_users() }
        .map(|user| {
            trace!("Found user {}", user.name().to_string_lossy());
            (user.uid(), user.name().to_string_lossy().to_string())
        })
        .collect();
    debug!("Found {} users", users.len());
    users
});

#[must_use]
pub fn username_for_uid(uid: libc::uid_t) -> String {
    USERS_CACHE.get(&uid).cloned().unwrap_or(uid.to_string())
}

/// data that could be transferred using `resources-processes`, separated from
/// `Process` mainly due to `Icon` not being able to derive `Serialize` and
/// `Deserialize`.
#[derive(Debug, Default, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessData {
    pub pid: libc::pid_t,
    pub parent_pid: libc::pid_t,
    pub user: String,
    pub comm: String,
    pub commandline: String,
    pub user_cpu_time: u64,
    pub system_cpu_time: u64,
    pub niceness: Niceness,
    pub affinity: Vec<bool>,
    pub rss: usize,
    pub rss_shmem: usize,
    pub rss_anon: usize,
    pub rss_file: usize,
    pub vm_size: usize,
    pub pss: Option<usize>,
    pub swap_usage: usize,
    pub starttime: u64, // in clock ticks, see man proc(5)!
    pub cgroup: Option<String>,
    pub containerization: Containerization,
    pub read_bytes: Option<u64>,
    pub write_bytes: Option<u64>,
    pub timestamp: u64,
    pub gpu_usage_stats: BTreeMap<GpuIdentifier, GpuClientSnapshots>,
    pub npu_usage_stats: BTreeMap<PciSlot, NpuUsageStats>,
    pub appimage_path: Option<String>,
    pub steam_appid: Option<u32>,
}

impl ProcessData {
    pub fn all_process_data(pss_mode: PssMode) -> Result<Vec<Self>> {
        let nvidia_stats = NvidiaSnapshot::new();

        let mut process_data = vec![];
        for entry in std::fs::read_dir("/proc")?.flatten() {
            if entry.file_name().to_string_lossy().parse::<u32>().is_ok() {
                let data = ProcessData::try_from_path(
                    entry.path(),
                    pss_mode == PssMode::Exact,
                    &nvidia_stats,
                );

                if let Ok(data) = data {
                    process_data.push(data);
                }
            }
        }

        // second pass to approximate PSS for processes where PSS could not be determined (or exact
        // PSS is disabled), this is the basic algorithm:
        // - parse /proc/<pid>/maps
        // - count how many processes map each file
        // - scale each process's RssFile by a VSZ-weighted average of 1/sharer_count across its
        //   mappings
        // - approximated PSS = RssAnon + ScaledRssFile + RssShmem
        // this is a bit more CPU-intensive than just reading e.g. RssAnon, but way less than
        // reading PSS while being pretty accurate for most cases
        if pss_mode != PssMode::Disabled {
            let pids_with_mapped_rss: Vec<libc::pid_t> = process_data
                .iter()
                .filter(|d| d.rss_file > 0 || d.rss_shmem > 0)
                .map(|d| d.pid)
                .collect();

            let (all_mappings, sharer_counts) = pss::collect_file_mappings(&pids_with_mapped_rss);
            for data in &mut process_data {
                if data.pss.is_none() {
                    data.pss = Some(pss::approx_pss(
                        data.pid,
                        data.rss_anon,
                        data.rss_file,
                        data.rss_shmem,
                        all_mappings.get(&data.pid),
                        &sharer_counts,
                    ));
                }
            }
        }

        Ok(process_data)
    }

    pub fn try_from_path<P: AsRef<Path>>(
        proc_path: P,
        pss_enabled: bool,
        nvidia_stats: &NvidiaSnapshot,
    ) -> Result<Self> {
        let proc_path = proc_path.as_ref();
        let pid = proc_path
            .file_name()
            .context("proc_path terminates in ..")?
            .to_str()
            .context("can't turn OsStr to str")?
            .parse()?;

        trace!("Inspecting process {pid}…");

        let raw_stat = read_parsed::<String>(proc_path.join("stat"))?;
        let raw_status = read_parsed::<String>(proc_path.join("status"))?;
        let comm = read_parsed::<String>(proc_path.join("comm"))?;
        let commandline = read_parsed::<String>(proc_path.join("cmdline"))?;
        let io = read_parsed::<String>(proc_path.join("io")).ok();

        let status = StatusFields::parse(pid, &raw_status)?;
        let user = username_for_uid(status.uid);
        trace!("User of {pid} determined to be {user}");

        let comm = comm.replace('\n', "");
        trace!("Comm of {pid} determined to be {comm}");

        let stat = StatFields::parse(pid, &raw_stat)?;

        let pss = if pss_enabled {
            pss::read_exact_pss(pid)
        } else {
            None
        };

        let (launcher, cgroup) = read_parsed::<String>(proc_path.join("cgroup"))
            .map(cgroup::sanitize_cgroup)
            .map(|(launcher, cgroup)| (launcher.unwrap_or_default(), cgroup)) // we only need the launcher for some checks here locally
            .unwrap_or_default();
        trace!("Launcher of {pid} determined to be {launcher}");
        trace!("Cgroup of {pid} determined to be {cgroup:?}");

        let environ = read_parsed::<String>(proc_path.join("environ"))
            .unwrap_or_default()
            .split('\0')
            .filter_map(|e| e.split_once('='))
            .map(|(x, y)| (x.to_string(), y.to_string()))
            .collect::<HashMap<_, _>>();

        let appimage_path = environ.get("APPIMAGE").map(std::borrow::ToOwned::to_owned);
        let steam_appid = environ.get("SteamAppId").and_then(|s| s.parse().ok());

        let containerization = Containerization::detect(
            &proc_path.join("root"),
            &commandline,
            &launcher,
            appimage_path.is_some(),
        );
        trace!("Containerization of {pid} determined to be {containerization:?}");

        let io = IoFields::parse(pid, io.as_deref());

        trace!("Collecting fdinfo statistics for {pid}…");
        let fdinfos: Vec<Fdinfo> = fdinfo::collect_fdinfos(pid).unwrap_or_default();

        trace!("Collecting NVIDIA statistics for {pid}…");
        let mut gpu_usage_stats = fdinfo::other_gpu_usage_stats(&fdinfos);
        gpu_usage_stats.extend(nvidia_stats.gpu_usage_stats_all(pid));

        let npu_usage_stats = fdinfo::npu_usage_stats(&fdinfos);

        let timestamp = unix_as_millis();

        trace!("Process {pid} done");

        Ok(Self {
            pid,
            parent_pid: stat.parent_pid,
            user,
            comm,
            commandline,
            user_cpu_time: stat.user_cpu_time,
            system_cpu_time: stat.system_cpu_time,
            niceness: stat.niceness,
            affinity: status.affinity,
            pss,
            rss: status.rss,
            rss_anon: status.rss_anon,
            rss_file: status.rss_file,
            rss_shmem: status.rss_shmem,
            vm_size: status.vm_size,
            swap_usage: status.swap_usage,
            starttime: stat.starttime,
            cgroup,
            containerization,
            read_bytes: io.read_bytes,
            write_bytes: io.write_bytes,
            timestamp,
            gpu_usage_stats,
            npu_usage_stats,
            appimage_path,
            steam_appid,
        })
    }
}
