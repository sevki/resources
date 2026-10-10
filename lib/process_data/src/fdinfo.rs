use std::collections::{HashMap, HashSet};
use std::iter::Sum;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Result, bail};
use lazy_regex::{Lazy, Regex, lazy_regex};
use log::trace;

use crate::gpu_usage::{GpuIdentifier, GpuUsageStats};
use crate::npu_usage::NpuUsageStats;
use crate::pci_slot::PciSlot;
use crate::util::read_parsed;

const DRM_DRIVER: &str = "drm-driver";
const DRM_PDEV: &str = "drm-pdev";

static RE_DRM_KIB: Lazy<Regex> = lazy_regex!(r"(\d+)\s*KiB");
static RE_DRM_TIME: Lazy<Regex> = lazy_regex!(r"(\d+)\s*ns");
static RE_DRM_UNITS: Lazy<Regex> = lazy_regex!(r"(\d+)");

static GFX_NS_DRM_FIELDS: Lazy<HashMap<&str, Vec<&str>>> = Lazy::new(|| {
    HashMap::from_iter([
        ("amdgpu", vec!["drm-engine-compute", "drm-engine-gfx"]),
        ("i915", vec!["drm-engine-render"]),
        ("panthor", vec!["drm-engine-panthor"]),
        ("v3d", vec!["drm-engine-render"]),
    ])
});

static GFX_CYCLES_DRM_FIELDS: Lazy<HashMap<&str, Vec<&str>>> =
    Lazy::new(|| HashMap::from_iter([("xe", vec!["drm-cycles-rcs"])]));

static GFX_TOTAL_CYCLES_DRM_FIELDS: Lazy<HashMap<&str, Vec<&str>>> =
    Lazy::new(|| HashMap::from_iter([("xe", vec!["drm-total-cycles-rcs"])]));

static COMPUTE_CYCLES_DRM_FIELDS: Lazy<HashMap<&str, Vec<&str>>> =
    Lazy::new(|| HashMap::from_iter([("xe", vec!["drm-cycles-ccs"])]));

static COMPUTE_TOTAL_CYCLES_DRM_FIELDS: Lazy<HashMap<&str, Vec<&str>>> =
    Lazy::new(|| HashMap::from_iter([("xe", vec!["drm-total-cycles-ccs"])]));

static ENC_NS_DRM_FIELDS: Lazy<HashMap<&str, Vec<&str>>> = Lazy::new(|| {
    HashMap::from_iter([
        ("amdgpu", vec!["drm-engine-enc"]),
        ("i915", vec!["drm-engine-video"]),
    ])
});

static ENC_CYCLES_DRM_FIELDS: Lazy<HashMap<&str, Vec<&str>>> =
    Lazy::new(|| HashMap::from_iter([("xe", vec!["drm-cycles-vcs"])]));

static ENC_TOTAL_CYCLES_DRM_FIELDS: Lazy<HashMap<&str, Vec<&str>>> =
    Lazy::new(|| HashMap::from_iter([("xe", vec!["drm-total-cycles-vcs"])]));

static DEC_NS_DRM_FIELDS: Lazy<HashMap<&str, Vec<&str>>> =
    Lazy::new(|| HashMap::from_iter([("amdgpu", vec!["drm-engine-dec"])]));

static NPU_NS_FIELDS: Lazy<HashMap<&str, Vec<&str>>> =
    Lazy::new(|| HashMap::from_iter([("amdxdna_accel_driver", vec!["drm-engine-npu-amdxdna"])]));

static MEM_DRM_FIELDS: Lazy<HashMap<&str, Vec<&str>>> = Lazy::new(|| {
    HashMap::from_iter([
        ("amdgpu", vec!["drm-memory-gtt", "drm-memory-vram"]),
        ("amdxdna_accel_driver", vec!["drm-total-memory"]),
        ("i915", vec!["drm-total-local0", "drm-total-system0"]),
        ("panthor", vec!["drm-total-memory"]),
        ("v3d", vec!["drm-total-memory"]),
        ("xe", vec!["drm-total-gtt", "drm-total-vram0"]),
    ])
});

pub type FdKey = (libc::pid_t, usize);

#[derive(Debug, Clone)]
pub struct Fdinfo {
    pub pid: libc::pid_t,
    pub fdinfo_num: usize,
    pub content: HashMap<String, String>,
    pub target: Option<PathBuf>,
}

fn parse_fdinfo<S: Into<String>>(file_contents: S) -> HashMap<String, String> {
    file_contents
        .into()
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect::<HashMap<_, _>>()
}

pub fn collect_fdinfos(
    pid: libc::pid_t,
    non_gpu_fdinfos: &mut HashSet<FdKey>,
    non_npu_fdinfos: &mut HashSet<FdKey>,
    symlink_cache: &mut HashMap<FdKey, PathBuf>,
) -> Result<Vec<Fdinfo>> {
    let fdinfo_dir = PathBuf::from(format!("/proc/{pid}/fdinfo"));
    let fd_dir = PathBuf::from(format!("/proc/{pid}/fd"));

    let mut seen_targets: HashMap<PathBuf, usize> = HashMap::new();
    let mut return_vec = Vec::new();

    for entry in std::fs::read_dir(fdinfo_dir)? {
        let entry = entry?;
        let fdinfo_path = entry.path();

        let fd_num = fdinfo_path
            .file_name()
            .and_then(|osstr| osstr.to_str())
            .unwrap_or("0")
            .parse::<usize>()
            .unwrap_or(0);

        let is_cached_non_gpu = non_gpu_fdinfos.contains(&(pid, fd_num));
        let is_cached_non_npu = non_npu_fdinfos.contains(&(pid, fd_num));

        let fd_symlink = fd_dir.join(fd_num.to_string());
        let symlink_target = {
            if let Some(cached_target) = symlink_cache.get(&(pid, fd_num)) {
                Some(cached_target.clone())
            } else {
                std::fs::read_link(&fd_symlink).ok()
            }
        };

        if is_cached_non_gpu && is_cached_non_npu {
            if let Some(ref target) = symlink_target {
                // skip if target doesn't look like a GPU/NPU device
                let target_str = target.to_string_lossy();
                if !target_str.contains("/dev/dri/") && !target_str.contains("/dev/accel/") {
                    trace!(
                        "fdinfo is known to be not related with NPUs and GPUs (target: {:?}), skipping",
                        target
                    );
                    continue;
                }
                // target changed to a GPU/NPU device, remove from cache
                trace!("fdinfo target changed to GPU/NPU device, removing from cache");
                non_gpu_fdinfos.remove(&(pid, fd_num));
                non_npu_fdinfos.remove(&(pid, fd_num));
            }
        }

        if let Some(ref target) = symlink_target {
            if let Some(&first_fd) = seen_targets.get(target) {
                trace!(
                    "fdinfo {} points to same target as fd {} (target: {:?}), skipping",
                    fd_num, first_fd, target
                );
                continue;
            }
            seen_targets.insert(target.clone(), fd_num);
            symlink_cache.insert((pid, fd_num), target.clone());
        }

        trace!("fdinfo passed all checks, reading and parsing…");

        let content = match read_parsed::<String>(fdinfo_path) {
            Ok(content) => content,
            Err(_) => {
                trace!("couldn't read fdinfo, skipping…");
                non_gpu_fdinfos.insert((pid, fd_num));
                non_npu_fdinfos.insert((pid, fd_num));
                continue;
            }
        };

        return_vec.push(Fdinfo {
            pid,
            fdinfo_num: fd_num,
            content: parse_fdinfo(content),
            target: symlink_target,
        });
    }

    Ok(return_vec)
}

fn parse_drm_fields<T: FromStr + Sum, S: AsRef<str>>(
    fdinfo: &Fdinfo,
    field_names: &[S],
    regex: &Regex,
) -> T {
    field_names
        .iter()
        .filter_map(|name| {
            fdinfo.content.get(name.as_ref()).and_then(|value| {
                regex
                    .captures(value)
                    .and_then(|captures| captures.get(1))
                    .and_then(|capture| capture.as_str().parse::<T>().ok())
            })
        })
        .sum()
}

fn drm_field<T: FromStr + Sum + Default>(
    driver: &str,
    fields: &Lazy<HashMap<&str, Vec<&str>>>,
    fdinfo: &Fdinfo,
    regex: &Regex,
) -> T {
    fields
        .get(driver)
        .map(|names| parse_drm_fields(fdinfo, names, regex))
        .unwrap_or_default()
}

fn drm_mem_bytes(driver: &str, fdinfo: &Fdinfo) -> u64 {
    MEM_DRM_FIELDS
        .get(driver)
        .map(|names| parse_drm_fields::<u64, _>(fdinfo, names, &RE_DRM_KIB).saturating_mul(1024))
        .unwrap_or_default()
}

/// Resolves a DRM device node (e.g. `/dev/dri/renderD128`) to the number of the DRM card it
/// belongs to (e.g. `1` for `card1`), matching the enumerator used for non-PCI GPUs
fn drm_card_enumerator(device_node: &Path) -> Option<usize> {
    let node_name = device_node.strip_prefix("/dev/dri").ok()?.to_str()?;

    if let Some(card) = node_name.strip_prefix("card") {
        return card.parse().ok();
    }

    std::fs::read_dir(
        Path::new("/sys/class/drm")
            .join(node_name)
            .join("device/drm"),
    )
    .ok()?
    .flatten()
    .find_map(|entry| {
        entry
            .file_name()
            .to_str()
            .and_then(|name| name.strip_prefix("card"))
            .and_then(|card| card.parse().ok())
    })
}

fn extract_gpu_usage_from_fdinfo(fdinfo: &Fdinfo) -> Result<(GpuIdentifier, GpuUsageStats)> {
    let Some(driver) = fdinfo.content.get(DRM_DRIVER) else {
        bail!("unable to find gpu information in this fdinfo");
    };

    // drm-pdev is only printed for PCI devices, so for platform GPUs (e.g. Arm SoCs) fall back to
    // the DRM card behind the device node this fd points to
    let gpu_identifier = fdinfo
        .content
        .get(DRM_PDEV)
        .and_then(|field| PciSlot::from_str(field).ok())
        .map(GpuIdentifier::PciSlot)
        .or_else(|| {
            fdinfo
                .target
                .as_deref()
                .and_then(drm_card_enumerator)
                .map(GpuIdentifier::Enumerator)
        })
        .unwrap_or_default();

    let stats = match driver.as_str() {
        "amdgpu" => GpuUsageStats::AmdgpuStats {
            gfx_ns: drm_field(driver, &GFX_NS_DRM_FIELDS, fdinfo, &RE_DRM_TIME),
            enc_ns: drm_field(driver, &ENC_NS_DRM_FIELDS, fdinfo, &RE_DRM_TIME),
            dec_ns: drm_field(driver, &DEC_NS_DRM_FIELDS, fdinfo, &RE_DRM_TIME),
            mem_bytes: drm_mem_bytes(driver, fdinfo),
        },
        "i915" => GpuUsageStats::I915Stats {
            gfx_ns: drm_field(driver, &GFX_NS_DRM_FIELDS, fdinfo, &RE_DRM_TIME),
            video_ns: drm_field(driver, &ENC_NS_DRM_FIELDS, fdinfo, &RE_DRM_TIME),
        },
        "panthor" => GpuUsageStats::PanthorStats {
            gfx_ns: drm_field(driver, &GFX_NS_DRM_FIELDS, fdinfo, &RE_DRM_TIME),
            mem_bytes: drm_mem_bytes(driver, fdinfo),
        },
        "v3d" => GpuUsageStats::V3dStats {
            gfx_ns: drm_field(driver, &GFX_NS_DRM_FIELDS, fdinfo, &RE_DRM_TIME),
            mem_bytes: drm_mem_bytes(driver, fdinfo),
        },
        "xe" => GpuUsageStats::XeStats {
            gfx_cycles: drm_field(driver, &GFX_CYCLES_DRM_FIELDS, fdinfo, &RE_DRM_UNITS),
            gfx_total_cycles: drm_field(
                driver,
                &GFX_TOTAL_CYCLES_DRM_FIELDS,
                fdinfo,
                &RE_DRM_UNITS,
            ),
            compute_cycles: drm_field(driver, &COMPUTE_CYCLES_DRM_FIELDS, fdinfo, &RE_DRM_UNITS),
            compute_total_cycles: drm_field(
                driver,
                &COMPUTE_TOTAL_CYCLES_DRM_FIELDS,
                fdinfo,
                &RE_DRM_UNITS,
            ),
            video_cycles: drm_field(driver, &ENC_CYCLES_DRM_FIELDS, fdinfo, &RE_DRM_UNITS),
            video_total_cycles: drm_field(
                driver,
                &ENC_TOTAL_CYCLES_DRM_FIELDS,
                fdinfo,
                &RE_DRM_UNITS,
            ),
            mem_bytes: drm_mem_bytes(driver, fdinfo),
        },
        _ => bail!("unable to read stats from driver"),
    };

    Ok((gpu_identifier, stats))
}

fn extract_npu_usage_from_fdinfo(fdinfo: &Fdinfo) -> Result<(PciSlot, NpuUsageStats)> {
    let Some(driver) = fdinfo.content.get(DRM_DRIVER) else {
        bail!("unable to find gpu information in this fdinfo");
    };

    let gpu_identifier = fdinfo
        .content
        .get(DRM_PDEV)
        .and_then(|field| PciSlot::from_str(field).ok())
        .unwrap_or_default();

    let stats = match driver.as_str() {
        "amdxdna_accel_driver" => NpuUsageStats::AmdxdnaStats {
            usage_ns: drm_field(driver, &NPU_NS_FIELDS, fdinfo, &RE_DRM_TIME),
            mem_bytes: drm_mem_bytes(driver, fdinfo),
        },
        _ => bail!("unable to read stats from driver"),
    };

    Ok((gpu_identifier, stats))
}

#[must_use]
pub fn other_gpu_usage_stats(
    fdinfos: &[Fdinfo],
    non_gpu_fdinfos: &mut HashSet<FdKey>,
) -> std::collections::BTreeMap<GpuIdentifier, GpuUsageStats> {
    let mut return_map = std::collections::BTreeMap::new();

    for fdinfo in fdinfos {
        if let Ok((identifier, stats)) = extract_gpu_usage_from_fdinfo(fdinfo) {
            trace!(
                "Successfully got GPU statistics from fdinfo {}/{}",
                fdinfo.pid, fdinfo.fdinfo_num
            );
            return_map
                .entry(identifier)
                .and_modify(|existing_value: &mut GpuUsageStats| {
                    *existing_value = existing_value.greater(&stats);
                })
                .or_insert(stats);
        } else {
            trace!(
                "fdinfo {}/{} is not GPU-related, will be skipped in the future",
                fdinfo.pid, fdinfo.fdinfo_num
            );
            non_gpu_fdinfos.insert((fdinfo.pid, fdinfo.fdinfo_num));
        }
    }

    return_map
}

#[must_use]
pub fn npu_usage_stats(
    fdinfos: &[Fdinfo],
    non_npu_fdinfos: &mut HashSet<FdKey>,
) -> std::collections::BTreeMap<PciSlot, NpuUsageStats> {
    let mut return_map = std::collections::BTreeMap::new();

    for fdinfo in fdinfos {
        if let Ok((identifier, stats)) = extract_npu_usage_from_fdinfo(fdinfo) {
            trace!(
                "Successfully got NPU statistics from fdinfo {}/{}",
                fdinfo.pid, fdinfo.fdinfo_num
            );
            return_map
                .entry(identifier)
                .and_modify(|existing_value: &mut NpuUsageStats| {
                    *existing_value = existing_value.greater(&stats);
                })
                .or_insert(stats);
        } else {
            trace!(
                "fdinfo {}/{} is not NPU-related, will be skipped in the future",
                fdinfo.pid, fdinfo.fdinfo_num
            );
            non_npu_fdinfos.insert((fdinfo.pid, fdinfo.fdinfo_num));
        }
    }

    return_map
}
