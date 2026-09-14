use std::collections::HashMap;
use std::iter::Sum;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Result, bail};
use lazy_regex::{Lazy, Regex, lazy_regex};
use log::trace;

use crate::gpu_usage::{GpuClientId, GpuClientSnapshots, GpuDriverStats, GpuIdentifier};
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
        ("v3d", vec!["drm-total-memory"]),
        ("xe", vec!["drm-total-gtt", "drm-total-vram0"]),
    ])
});

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

pub fn collect_fdinfos(pid: libc::pid_t) -> Result<Vec<Fdinfo>> {
    collect_fdinfos_from(pid, &PathBuf::from(format!("/proc/{pid}")))
}

fn collect_fdinfos_from(pid: libc::pid_t, proc_dir: &Path) -> Result<Vec<Fdinfo>> {
    let fdinfo_dir = proc_dir.join("fdinfo");
    let fd_dir = proc_dir.join("fd");

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

        // Recheck the actual FD on every scan: paths and descriptor numbers
        // identify neither the lifetime nor the identity of an open DRM client.
        if let Ok(metadata) = std::fs::metadata(fd_dir.join(fd_num.to_string())) {
            let major = libc::major(metadata.rdev());
            if metadata.mode() & libc::S_IFMT != libc::S_IFCHR || !matches!(major, 226 | 261) {
                continue;
            }
        }
        // If metadata cannot be read, still try fdinfo (permissions can differ).
        trace!("fdinfo passed all checks, reading and parsing…");

        let content = match read_parsed::<String>(fdinfo_path) {
            Ok(content) => content,
            Err(_) => {
                trace!("couldn't read fdinfo, skipping…");
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

fn drm_mem_bytes(driver: &str, fdinfo: &Fdinfo) -> u64 {
    MEM_DRM_FIELDS
        .get(driver)
        .map(|names| parse_drm_fields::<u64, _>(fdinfo, names, &RE_DRM_KIB).saturating_mul(1024))
        .unwrap_or_default()
}

fn extract_gpu_usage_from_fdinfo(fdinfo: &Fdinfo) -> Result<(GpuIdentifier, GpuDriverStats)> {
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
        "amdgpu" => GpuDriverStats::AmdgpuStats {
            gfx_ns: drm_field(driver, &GFX_NS_DRM_FIELDS, fdinfo, &RE_DRM_TIME),
            enc_ns: drm_field(driver, &ENC_NS_DRM_FIELDS, fdinfo, &RE_DRM_TIME),
            dec_ns: drm_field(driver, &DEC_NS_DRM_FIELDS, fdinfo, &RE_DRM_TIME),
            mem_bytes: drm_mem_bytes(driver, fdinfo),
        },
        "i915" => GpuDriverStats::I915Stats {
            gfx_ns: drm_field(driver, &GFX_NS_DRM_FIELDS, fdinfo, &RE_DRM_TIME),
            video_ns: drm_field(driver, &ENC_NS_DRM_FIELDS, fdinfo, &RE_DRM_TIME),
        },
        "v3d" => GpuDriverStats::V3dStats {
            gfx_ns: drm_field(driver, &GFX_NS_DRM_FIELDS, fdinfo, &RE_DRM_TIME),
            mem_bytes: drm_mem_bytes(driver, fdinfo),
        },
        "xe" => GpuDriverStats::XeStats {
            render_cycles: drm_field(driver, &GFX_CYCLES_DRM_FIELDS, fdinfo, &RE_DRM_UNITS),
            render_total_cycles: drm_field(
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
) -> std::collections::BTreeMap<GpuIdentifier, GpuClientSnapshots> {
    let mut return_map = std::collections::BTreeMap::new();

    for fdinfo in fdinfos {
        if let Ok((identifier, stats)) = extract_gpu_usage_from_fdinfo(fdinfo) {
            trace!(
                "Successfully got GPU statistics from fdinfo {}/{}",
                fdinfo.pid, fdinfo.fdinfo_num
            );
            let client = fdinfo
                .content
                .get("drm-client-id")
                .and_then(|id| id.parse().ok())
                .map(GpuClientId::Drm)
                .unwrap_or(GpuClientId::Fd {
                    pid: fdinfo.pid,
                    fd: fdinfo.fdinfo_num,
                });
            return_map
                .entry(identifier)
                .or_insert_with(GpuClientSnapshots::default)
                .insert_client(client, stats);
        } else {
            trace!(
                "fdinfo {}/{} is not supported GPU statistics",
                fdinfo.pid, fdinfo.fdinfo_num
            );
        }
    }

    return_map
}

#[must_use]
pub fn npu_usage_stats(fdinfos: &[Fdinfo]) -> std::collections::BTreeMap<PciSlot, NpuUsageStats> {
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
                "fdinfo {}/{} is not supported NPU statistics",
                fdinfo.pid, fdinfo.fdinfo_num
            );
        }
    }

    return_map
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn fdinfo(fd: usize, client: Option<u64>, busy: u64) -> Fdinfo {
        let mut content = format!(
            "drm-driver: xe\ndrm-pdev: 0000:00:02.0\ndrm-cycles-rcs: {busy}\ndrm-total-cycles-rcs: 10000\n"
        );
        if let Some(client) = client {
            content.push_str(&format!("drm-client-id: {client}\n"));
        }
        Fdinfo {
            pid: 43997,
            fdinfo_num: fd,
            content: parse_fdinfo(content),
        }
    }

    #[test]
    fn distinct_clients_survive_and_duplicate_client_keeps_a_complete_sample() {
        let rows = [
            fdinfo(274, Some(263), 0),
            fdinfo(304, Some(266), 8000),
            fdinfo(305, Some(266), 8001),
        ];
        let result = other_gpu_usage_stats(&rows);
        let stats = result.values().next().unwrap();
        assert_eq!(stats.clients.len(), 2);
        let GpuDriverStats::XeStats {
            render_cycles,
            render_total_cycles,
            ..
        } = stats.clients[&GpuClientId::Drm(266)].driver_stats
        else {
            panic!()
        };
        assert_eq!((render_cycles, render_total_cycles), (8000, 10000));
    }

    #[test]
    fn missing_client_ids_are_not_merged_with_client_zero() {
        let rows = [
            fdinfo(1, None, 1),
            fdinfo(2, None, 2),
            fdinfo(3, Some(0), 3),
        ];
        let result = other_gpu_usage_stats(&rows);
        assert_eq!(result.values().next().unwrap().clients.len(), 3);
    }

    #[test]
    fn client_ids_are_scoped_to_the_device() {
        let a = fdinfo(1, Some(1), 10);
        let mut b = fdinfo(2, Some(1), 20);
        b.content.insert(DRM_PDEV.into(), "0000:01:00.0".into());
        assert_eq!(other_gpu_usage_stats(&[a, b]).len(), 2);
    }

    struct ProcFixture(PathBuf);
    impl ProcFixture {
        fn new() -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let path = std::env::temp_dir().join(format!(
                "resources-fdinfo-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            std::fs::create_dir(path.join("fd")).unwrap();
            std::fs::create_dir(path.join("fdinfo")).unwrap();
            Self(path)
        }
        fn write(&self, fd: usize, client: u64) {
            let row = fdinfo(fd, Some(client), 100);
            let content: String = row
                .content
                .iter()
                .map(|(k, v)| format!("{k}: {v}\n"))
                .collect();
            std::fs::write(self.0.join("fdinfo").join(fd.to_string()), content).unwrap();
        }
    }
    impl Drop for ProcFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn collection_does_not_deduplicate_device_paths() {
        let fixture = ProcFixture::new();
        for (fd, client) in [(274, 263), (304, 266)] {
            fixture.write(fd, client);
            // A missing device also exercises the fdinfo fallback when stat fails.
            symlink(
                "/dev/dri/resources-test-missing-render-node",
                fixture.0.join("fd").join(fd.to_string()),
            )
            .unwrap();
        }
        let rows = collect_fdinfos_from(43997, &fixture.0).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(
            other_gpu_usage_stats(&rows)
                .values()
                .next()
                .unwrap()
                .clients
                .len(),
            2
        );
    }

    #[test]
    fn reused_fd_is_reclassified_on_every_scan() {
        let fixture = ProcFixture::new();
        let link = fixture.0.join("fd/304");
        fixture.write(304, 266);
        symlink("/dev/null", &link).unwrap();
        assert!(collect_fdinfos_from(43997, &fixture.0).unwrap().is_empty());
        std::fs::remove_file(&link).unwrap();
        symlink("/dev/dri/resources-test-missing-render-node", &link).unwrap();
        let rows = collect_fdinfos_from(43997, &fixture.0).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].content["drm-client-id"], "266");
        fixture.write(304, 999);
        let rows = collect_fdinfos_from(43997, &fixture.0).unwrap();
        assert_eq!(rows[0].content["drm-client-id"], "999");
    }
}
