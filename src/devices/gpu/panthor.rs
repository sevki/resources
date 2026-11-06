use anyhow::{Context, Result, bail};
use glob::glob;
use log::{debug, trace};
use process_data::gpu_usage::GpuIdentifier;

use std::{
    fs::File,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
};

use crate::{devices::pci::Device, utils::read_parsed};

use super::GpuImpl;

// _IOWR('d', DRM_COMMAND_BASE + DRM_PANTHOR_DEV_QUERY, struct drm_panthor_dev_query)
const DRM_IOCTL_PANTHOR_DEV_QUERY: libc::c_ulong = 0xC010_6440;
const DRM_PANTHOR_DEV_QUERY_GPU_INFO: u32 = 0;
const GPU_FEATURES_RAY_INTERSECTION: u64 = 1 << 2;

/// `struct drm_panthor_dev_query` from `include/uapi/drm/panthor_drm.h`
#[repr(C)]
struct DrmPanthorDevQuery {
    query_type: u32,
    size: u32,
    pointer: u64,
}

/// `struct drm_panthor_gpu_info` from `include/uapi/drm/panthor_drm.h`, older kernels fill in
/// fewer fields and zero the rest
#[repr(C)]
#[derive(Debug, Default)]
struct DrmPanthorGpuInfo {
    gpu_id: u32,
    gpu_rev: u32,
    csf_id: u32,
    l2_features: u32,
    tiler_features: u32,
    mem_features: u32,
    mmu_features: u32,
    thread_features: u32,
    max_threads: u32,
    thread_max_workgroup_size: u32,
    thread_max_barrier_size: u32,
    coherency_features: u32,
    texture_features: [u32; 4],
    as_present: u32,
    selected_coherency: u32,
    shader_present: u64,
    l2_present: u64,
    tiler_present: u64,
    core_features: u32,
    pad: u32,
    gpu_features: u64,
}

impl DrmPanthorGpuInfo {
    fn query(render_node: &Path) -> Result<Self> {
        let file = File::open(render_node)?;
        let mut gpu_info = Self::default();
        let mut query = DrmPanthorDevQuery {
            query_type: DRM_PANTHOR_DEV_QUERY_GPU_INFO,
            size: size_of::<Self>() as u32,
            pointer: &raw mut gpu_info as u64,
        };

        // SAFETY: `query` points to a valid `drm_panthor_gpu_info` of the given size, which outlives the call
        let ret = unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                DRM_IOCTL_PANTHOR_DEV_QUERY,
                &raw mut query,
            )
        };

        if ret != 0 {
            bail!(
                "DRM_IOCTL_PANTHOR_DEV_QUERY failed: {}",
                std::io::Error::last_os_error()
            );
        }

        Ok(gpu_info)
    }

    /// Mirrors `panthor_gpu_model_name()` in `drivers/gpu/drm/panthor/panthor_hw.c`
    fn model_name(&self) -> Option<&'static str> {
        let arch_major = self.gpu_id >> 28;
        let product_major = (self.gpu_id >> 16) & 0xf;
        let shader_core_count = self.shader_present.count_ones();
        let ray_intersection = self.gpu_features & GPU_FEATURES_RAY_INTERSECTION != 0;

        let name = match (arch_major, product_major) {
            (10, 2) => "Mali-G710",
            (10, 3) => "Mali-G510",
            (10, 4) => "Mali-G310",
            (10, 7) => "Mali-G610",
            (11, 2) if shader_core_count > 10 && ray_intersection => "Mali-G715-Immortalis",
            (11, 2) if shader_core_count >= 7 => "Mali-G715",
            (11, 2 | 3) => "Mali-G615",
            (12, 0) if shader_core_count >= 10 && ray_intersection => "Mali-G720-Immortalis",
            (12, 0) if shader_core_count >= 6 => "Mali-G720",
            (12, 0 | 1) => "Mali-G620",
            (13, 0) if shader_core_count >= 10 && ray_intersection => "Mali-G925-Immortalis",
            (13, 0) if shader_core_count >= 6 => "Mali-G725",
            (13, 0 | 1) => "Mali-G625",
            (14, 0) => "Mali-G1-Ultra",
            (14, 1) => "Mali-G1-Premium",
            (14, 3) => "Mali-G1-Pro",
            _ => return None,
        };

        Some(name)
    }
}

#[derive(Debug, Clone, Default)]

pub struct PanthorGpu {
    pub device: Option<&'static Device>,
    pub gpu_identifier: GpuIdentifier,
    pub driver: String,
    sysfs_path: PathBuf,
    first_hwmon_path: Option<PathBuf>,
    devfreq_path: Option<PathBuf>,
    thermal_zone_path: Option<PathBuf>,
    model_name: Option<&'static str>,
}

impl PanthorGpu {
    pub fn new(
        device: Option<&'static Device>,
        gpu_identifier: GpuIdentifier,
        driver: String,
        sysfs_path: PathBuf,
        first_hwmon_path: Option<PathBuf>,
    ) -> Self {
        let devfreq_path = glob(&format!(
            "{}/device/devfreq/*",
            sysfs_path.to_string_lossy()
        ))
        .ok()
        .and_then(|mut paths| paths.find_map(std::result::Result::ok));

        // Mali GPUs don't register a hwmon device, their temperature sensor is exposed as a thermal
        // zone instead (e.g. "gpu-thermal" on RK3588)
        let thermal_zone_path =
            glob("/sys/class/thermal/thermal_zone*")
                .ok()
                .and_then(|mut paths| {
                    paths.find_map(|path| {
                        path.ok().filter(|path| {
                            read_parsed::<String>(path.join("type"))
                                .is_ok_and(|zone_type| zone_type.starts_with("gpu"))
                        })
                    })
                });

        let model_name = glob(&format!(
            "{}/device/drm/renderD*",
            sysfs_path.to_string_lossy()
        ))
        .ok()
        .and_then(|mut paths| paths.find_map(std::result::Result::ok))
        .and_then(|path| {
            path.file_name()
                .map(|name| Path::new("/dev/dri").join(name))
        })
        .and_then(|render_node| {
            DrmPanthorGpuInfo::query(&render_node)
                .inspect(|gpu_info| trace!("Queried {render_node:?}: {gpu_info:?}"))
                .inspect_err(|e| debug!("Unable to query {render_node:?}: {e}"))
                .ok()
        })
        .and_then(|gpu_info| gpu_info.model_name());

        Self {
            device,
            gpu_identifier,
            driver,
            sysfs_path,
            first_hwmon_path,
            devfreq_path,
            thermal_zone_path,
            model_name,
        }
    }
}

impl GpuImpl for PanthorGpu {
    fn device(&self) -> Option<&'static Device> {
        self.device
    }

    fn gpu_identifier(&self) -> GpuIdentifier {
        self.gpu_identifier
    }

    fn driver(&self) -> &str {
        &self.driver
    }

    fn sysfs_path(&self) -> &Path {
        &self.sysfs_path
    }

    fn first_hwmon(&self) -> Option<&Path> {
        self.first_hwmon_path.as_deref()
    }

    fn name(&self) -> Result<String> {
        self.model_name
            .map(str::to_owned)
            .context("unknown Mali GPU")
    }

    fn vendor_name(&self) -> Result<String> {
        Ok("Arm".into())
    }

    // panthor has no device-wide busy counter, usage is summed up from the processes' fdinfo
    fn usage(&self) -> Result<f64> {
        bail!("usage not implemented for panthor")
    }

    fn encode_usage(&self) -> Result<f64> {
        bail!("encode usage not implemented for panthor")
    }

    fn decode_usage(&self) -> Result<f64> {
        bail!("decode usage not implemented for panthor")
    }

    fn combined_media_engine(&self) -> Result<bool> {
        Ok(true)
    }

    // used memory is summed up from the processes' fdinfo
    fn used_vram(&self) -> Result<u64> {
        bail!("used memory not implemented for panthor")
    }

    fn total_vram(&self) -> Result<u64> {
        bail!("panthor GPUs use shared system memory")
    }

    fn temperature(&self) -> Result<f64> {
        self.thermal_zone_path
            .as_ref()
            .context("no GPU thermal zone found")
            .and_then(|path| read_parsed::<f64>(path.join("temp")))
            .map(|millicelsius| millicelsius / 1000.0)
            .or_else(|_| self.hwmon_temperature())
    }

    fn power_usage(&self) -> Result<f64> {
        self.hwmon_power_usage()
    }

    fn core_frequency(&self) -> Result<f64> {
        self.devfreq_path
            .as_ref()
            .context("no devfreq found")
            .and_then(|path| read_parsed::<f64>(path.join("cur_freq")))
    }

    fn vram_frequency(&self) -> Result<f64> {
        bail!("panthor GPUs use shared system memory")
    }

    fn power_cap(&self) -> Result<f64> {
        self.hwmon_power_cap()
    }

    fn power_cap_max(&self) -> Result<f64> {
        self.hwmon_power_cap_max()
    }
}

#[cfg(test)]
mod test {
    use super::DrmPanthorGpuInfo;

    #[test]
    fn model_name_rk3588() {
        // Mali-G610 MC4 as found in the RK3588
        let gpu_info = DrmPanthorGpuInfo {
            gpu_id: 0xa867_0005,
            shader_present: 0x50005,
            ..Default::default()
        };
        assert_eq!(gpu_info.model_name(), Some("Mali-G610"));
    }

    #[test]
    fn model_name_core_count_dependent() {
        let small = DrmPanthorGpuInfo {
            gpu_id: 0xb002_0000,
            shader_present: 0b11,
            ..Default::default()
        };
        assert_eq!(small.model_name(), Some("Mali-G615"));

        let immortalis = DrmPanthorGpuInfo {
            gpu_id: 0xb002_0000,
            shader_present: 0xfff,
            gpu_features: super::GPU_FEATURES_RAY_INTERSECTION,
            ..Default::default()
        };
        assert_eq!(immortalis.model_name(), Some("Mali-G715-Immortalis"));
    }

    #[test]
    fn model_name_unknown() {
        let gpu_info = DrmPanthorGpuInfo {
            gpu_id: 0x9000_0000,
            ..Default::default()
        };
        assert_eq!(gpu_info.model_name(), None);
    }
}
