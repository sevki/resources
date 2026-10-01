use std::collections::{HashMap, HashSet};
use std::iter::Sum;
use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Result, bail};
use lazy_regex::{Lazy, Regex, lazy_regex};
use log::trace;

use crate::gpu_usage::{GpuIdentifier, GpuUsageStats};
use crate::npu_usage::{
    AMDXDNA_BUSY_FIELDS, AMDXDNA_MEMORY_FIELDS, AMDXDNA_TOTAL_MEMORY_FIELD, NpuUsageStats,
};
use crate::pci_slot::PciSlot;
use crate::util::read_parsed;

const DRM_DRIVER: &str = "drm-driver";
const DRM_PDEV: &str = "drm-pdev";

// drm_fdinfo_print_size() prints bytes, KiB or MiB
static RE_DRM_SIZE: Lazy<Regex> = lazy_regex!(r"(\d+)\s*([KMG]iB)?");
static RE_DRM_TIME: Lazy<Regex> = lazy_regex!(r"(\d+)\s*ns");
static RE_DRM_UNITS: Lazy<Regex> = lazy_regex!(r"(\d+)");

static GFX_NS_DRM_FIELDS: Lazy<HashMap<&str, Vec<&str>>> = Lazy::new(|| {
    HashMap::from_iter([
        ("amdgpu", vec!["drm-engine-compute", "drm-engine-gfx"]),
        ("i915", vec!["drm-engine-render"]),
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
    Lazy::new(|| HashMap::from_iter([("amdxdna_accel_driver", AMDXDNA_BUSY_FIELDS.to_vec())]));

static MEM_DRM_FIELDS: Lazy<HashMap<&str, Vec<&str>>> = Lazy::new(|| {
    HashMap::from_iter([
        ("amdgpu", vec!["drm-memory-gtt", "drm-memory-vram"]),
        ("amdxdna_accel_driver", vec![AMDXDNA_TOTAL_MEMORY_FIELD]),
        ("i915", vec!["drm-total-local0", "drm-total-system0"]),
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

fn drm_sizes(fdinfo: &Fdinfo, field_names: &[&str]) -> u64 {
    field_names
        .iter()
        .filter_map(|name| {
            let captures = RE_DRM_SIZE.captures(fdinfo.content.get(*name)?)?;
            let size = captures.get(1)?.as_str().parse::<u64>().ok()?;
            let unit = match captures.get(2).map(|unit| unit.as_str()) {
                Some("KiB") => 1 << 10,
                Some("MiB") => 1 << 20,
                Some("GiB") => 1 << 30,
                _ => 1,
            };
            Some(size.saturating_mul(unit))
        })
        .sum()
}

fn drm_mem_bytes(driver: &str, fdinfo: &Fdinfo) -> u64 {
    MEM_DRM_FIELDS
        .get(driver)
        .map(|names| drm_sizes(fdinfo, names))
        .unwrap_or_default()
}

fn amdxdna_mem_bytes(fdinfo: &Fdinfo) -> u64 {
    // drivers before 2026-03 only have drm-total-memory
    if AMDXDNA_MEMORY_FIELDS
        .iter()
        .any(|name| fdinfo.content.contains_key(*name))
    {
        drm_sizes(fdinfo, &AMDXDNA_MEMORY_FIELDS)
    } else {
        drm_mem_bytes("amdxdna_accel_driver", fdinfo)
    }
}

fn extract_gpu_usage_from_fdinfo(fdinfo: &Fdinfo) -> Result<(GpuIdentifier, GpuUsageStats)> {
    let Some(driver) = fdinfo.content.get(DRM_DRIVER) else {
        bail!("unable to find gpu information in this fdinfo");
    };

    let gpu_identifier = fdinfo
        .content
        .get(DRM_PDEV)
        .and_then(|field| PciSlot::from_str(field).ok())
        .map(GpuIdentifier::PciSlot)
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
            mem_bytes: amdxdna_mem_bytes(fdinfo),
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

#[cfg(test)]
mod test {
    use super::{Fdinfo, extract_npu_usage_from_fdinfo, parse_fdinfo};
    use crate::npu_usage::NpuUsageStats;
    use pretty_assertions::assert_eq;

    fn npu_stats(content: &str) -> NpuUsageStats {
        let fdinfo = Fdinfo {
            pid: 1,
            fdinfo_num: 3,
            content: parse_fdinfo(content),
        };
        extract_npu_usage_from_fdinfo(&fdinfo).unwrap().1
    }

    #[test]
    fn amdxdna_stats() {
        let stats = npu_stats(
            "drm-driver:\tamdxdna_accel_driver\n\
             drm-pdev:\t0000:c5:00.1\n\
             drm-engine-amdxdna_accel_driver:\t1075280385 ns\n\
             amdxdna_accel_driver-heap-alloc:\t524 KiB\n\
             amdxdna_accel_driver-internal-alloc:\t65540 KiB\n\
             amdxdna_accel_driver-external-alloc:\t53 MiB\n\
             drm-total-memory:\t120320 KiB\n\
             drm-shared-memory:\t0\n",
        );
        assert_eq!(
            stats,
            NpuUsageStats::AmdxdnaStats {
                usage_ns: 1_075_280_385,
                mem_bytes: (65540 << 10) + (53 << 20),
            }
        );
    }

    #[test]
    fn amdxdna_legacy_stats() {
        let stats = npu_stats(
            "drm-driver:\tamdxdna_accel_driver\n\
             drm-pdev:\t0000:c5:00.1\n\
             drm-engine-npu-amdxdna:\t5000 ns\n\
             drm-total-memory:\t64 MiB\n\
             drm-shared-memory:\t0\n",
        );
        assert_eq!(
            stats,
            NpuUsageStats::AmdxdnaStats {
                usage_ns: 5000,
                mem_bytes: 64 << 20,
            }
        );
    }
}
