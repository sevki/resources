use anyhow::{Context, Result, bail};
use process_data::npu_usage::{
    AMDXDNA_BUSY_FIELDS, AMDXDNA_MEMORY_FIELDS, AMDXDNA_TOTAL_MEMORY_FIELD,
};
use process_data::pci_slot::PciSlot;

use std::cell::Cell;
use std::fs::File;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use crate::devices::pci::Device;
use crate::utils::read_parsed;

use super::NpuImpl;

const DRM_IOCTL_BASE: u8 = b'd';
const DRM_COMMAND_BASE: u8 = 0x40;
const DRM_AMDXDNA_GET_INFO: u8 = 7;
const DRM_AMDXDNA_QUERY_CLOCK_METADATA: u32 = 3;
const DRM_AMDXDNA_QUERY_SENSORS: u32 = 4;
const DRM_AMDXDNA_QUERY_RESOURCE_INFO: u32 = 12;

const AMDXDNA_SENSOR_TYPE_POWER: u8 = 0;
const AMDXDNA_SENSOR_TYPE_COLUMN_UTILIZATION: u8 = 1;

const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

const fn ioc(dir: u32, ty: u8, nr: u8, size: usize) -> libc::c_ulong {
    ((dir << 30) | ((ty as u32) << 8) | (nr as u32) | ((size as u32) << 16)) as libc::c_ulong
}

const fn iowr<T>(ty: u8, nr: u8) -> libc::c_ulong {
    ioc(IOC_READ | IOC_WRITE, ty, nr, std::mem::size_of::<T>())
}

#[repr(C)]
struct AmdxdnaDrmGetInfo {
    param: u32,
    buffer_size: u32,
    buffer: u64,
}

#[repr(C)]
#[derive(Default)]
struct AmdxdnaDrmGetResourceInfo {
    clk_max: u64,
    tops_max: u64,
    task_max: u64,
    tops_curr: u64,
    task_curr: u64,
}

#[repr(C)]
#[derive(Default)]
struct AmdxdnaDrmQueryClock {
    name: [u8; 16],
    freq_mhz: u32,
    _pad: u32,
}

#[repr(C)]
#[derive(Default)]
struct AmdxdnaDrmQueryClockMetadata {
    mp_npu_clock: AmdxdnaDrmQueryClock,
    h_clock: AmdxdnaDrmQueryClock,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
struct AmdxdnaDrmQuerySensor {
    label: [u8; 64],
    input: u32,
    max: u32,
    average: u32,
    highest: u32,
    status: [u8; 64],
    units: [u8; 16],
    unitm: i8,
    sensor_type: u8,
    _pad: [u8; 6],
}

impl Default for AmdxdnaDrmQuerySensor {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct Sources {
    // the Flatpak has no access to /dev/accel
    queries: bool,
    // since 2026-04, 2024-09 in the legacy out-of-tree driver
    fdinfo_busy_time: bool,
    // since 2026-03, 2024-09 in the legacy out-of-tree driver
    fdinfo_memory: bool,
    // since 2026-05
    hwmon_power: bool,
    hwmon_temperature: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct Sample {
    h_clock: Option<f64>,
    tops: Option<u64>,
    power: Option<f64>,
    utilization: Option<f64>,
}

#[derive(Debug, Clone, Copy, Default)]
struct State {
    awake: bool,
    interrupts: Option<u64>,
    busy: bool,
    // whether `sample` was queried since the NPU last woke up
    fresh: bool,
    sample: Option<Sample>,
}

#[derive(Debug, Clone, Default)]
pub struct AmdNpu {
    pub device: Option<&'static Device>,
    pub pci_slot: PciSlot,
    pub driver: String,
    sysfs_path: PathBuf,
    first_hwmon_path: Option<PathBuf>,
    sources: Sources,
    state: Cell<State>,
}

fn get_info<T: Default>(file: &File, param: u32) -> Result<(T, usize)> {
    let mut value = T::default();
    let mut get_info = AmdxdnaDrmGetInfo {
        param,
        buffer_size: std::mem::size_of::<T>() as u32,
        buffer: &raw mut value as u64,
    };

    let ioctl_cmd =
        iowr::<AmdxdnaDrmGetInfo>(DRM_IOCTL_BASE, DRM_COMMAND_BASE + DRM_AMDXDNA_GET_INFO);

    let ret = unsafe { libc::ioctl(file.as_raw_fd(), ioctl_cmd, &mut get_info) };
    if ret < 0 {
        bail!("ioctl failed: {}", std::io::Error::last_os_error());
    }

    Ok((value, get_info.buffer_size as usize))
}

impl AmdNpu {
    pub fn new(
        device: Option<&'static Device>,
        pci_slot: PciSlot,
        driver: String,
        sysfs_path: PathBuf,
        first_hwmon_path: Option<PathBuf>,
    ) -> Self {
        let mut npu = Self {
            device,
            pci_slot,
            driver,
            sysfs_path,
            first_hwmon_path,
            ..Default::default()
        };

        // without access to the device, the processes' fdinfo is the only source left
        let (queries, (fdinfo_busy_time, fdinfo_memory)) = match npu.probe_fdinfo() {
            Ok(fields) => (true, fields),
            Err(_) => (false, (true, true)),
        };
        npu.sources = Sources {
            queries,
            fdinfo_busy_time,
            fdinfo_memory,
            hwmon_power: npu
                .hwmon_path()
                .is_ok_and(|path| path.join("power1_input").exists()),
            // EOPNOTSUPP where the PMF has no NPU temperature
            hwmon_temperature: npu.hwmon_temperature().is_ok(),
        };

        npu
    }

    fn open(&self) -> Result<File> {
        let accel_name = self.sysfs_path.file_name().context("invalid sysfs path")?;
        File::open(Path::new("/dev/accel").join(accel_name)).context("failed to open accel device")
    }

    // opening the device does not wake it up
    fn probe_fdinfo(&self) -> Result<(bool, bool)> {
        let file = self.open()?;
        let fdinfo = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", file.as_raw_fd()))?;
        let has = |field: &str| {
            fdinfo
                .lines()
                .any(|line| line.split_once(':').is_some_and(|(key, _)| key == field))
        };

        Ok((
            AMDXDNA_BUSY_FIELDS.iter().any(|field| has(field)),
            AMDXDNA_MEMORY_FIELDS.iter().any(|field| has(field)) || has(AMDXDNA_TOTAL_MEMORY_FIELD),
        ))
    }

    fn awake(&self) -> bool {
        read_parsed::<String>(self.sysfs_path.join("device/power/runtime_status"))
            .map_or(true, |status| {
                !matches!(status.as_str(), "suspended" | "suspending" | "resuming")
            })
    }

    // mailbox interrupts: job completions, context changes, power transitions; none for our queries
    fn interrupts(&self) -> Result<u64> {
        let vectors = std::fs::read_dir(self.sysfs_path.join("device/msi_irqs"))?
            .filter_map(|entry| entry.ok()?.file_name().to_str()?.parse::<usize>().ok())
            .collect::<Vec<_>>();

        let stat = std::fs::read_to_string("/proc/stat")?;
        let counts = stat
            .lines()
            .find_map(|line| line.strip_prefix("intr "))
            .context("no interrupt counts in /proc/stat")?
            .split_ascii_whitespace()
            .skip(1) // the total
            .collect::<Vec<_>>();

        Ok(vectors
            .iter()
            .filter_map(|&irq| counts.get(irq)?.parse::<u64>().ok())
            .sum())
    }

    fn query(&self, previous: Option<Sample>) -> Sample {
        let mut sample = Sample::default();
        let Ok(file) = self.open() else {
            return sample;
        };

        // measured by the PMF since 2026-03, the DPM level's nominal clock before; 0 on AIE4
        sample.h_clock =
            get_info::<AmdxdnaDrmQueryClockMetadata>(&file, DRM_AMDXDNA_QUERY_CLOCK_METADATA)
                .ok()
                .map(|(clocks, _)| clocks.h_clock.freq_mhz)
                .filter(|&mhz| mhz > 0)
                .map(|mhz| f64::from(mhz) * 1_000_000.0);

        // not tops_max: it is for the top DPM level's nominal 1800 MHz, the real clock is 1810 MHz
        sample.tops = match previous {
            Some(previous) if previous.tops.is_some() && previous.h_clock == sample.h_clock => {
                previous.tops
            }
            _ => get_info::<AmdxdnaDrmGetResourceInfo>(&file, DRM_AMDXDNA_QUERY_RESOURCE_INFO)
                .ok()
                .map(|(resources, _)| resources.tops_curr)
                .filter(|&tops| tops > 0),
        };

        // Linux 7.2 and the legacy driver have the PMF's values only behind this ioctl
        if (!self.sources.hwmon_power || !self.sources.fdinfo_busy_time)
            && let Ok((sensors, size)) =
                get_info::<[AmdxdnaDrmQuerySensor; 16]>(&file, DRM_AMDXDNA_QUERY_SENSORS)
        {
            let count = size / std::mem::size_of::<AmdxdnaDrmQuerySensor>();
            let sensors = &sensors[..count.min(sensors.len())];
            let value = |sensor: &AmdxdnaDrmQuerySensor| {
                f64::from(sensor.input) * 10.0f64.powi(i32::from(sensor.unitm))
            };

            sample.power = sensors
                .iter()
                .find(|sensor| sensor.sensor_type == AMDXDNA_SENSOR_TYPE_POWER)
                .map(value);

            let columns = sensors
                .iter()
                .filter(|sensor| sensor.sensor_type == AMDXDNA_SENSOR_TYPE_COLUMN_UTILIZATION)
                .map(value)
                .collect::<Vec<_>>();
            if !columns.is_empty() {
                sample.utilization =
                    Some(columns.iter().sum::<f64>() / columns.len() as f64 / 100.0);
            }
        }

        sample
    }

    fn sampled<T>(&self, value: impl Fn(&Sample) -> Option<T>, zero: T) -> Result<T> {
        if !self.sources.queries {
            bail!("no access to the device");
        }

        let state = self.state.get();
        match (state.awake, state.sample.as_ref().map(value)) {
            (true, Some(Some(value))) => Ok(value),
            (false, None | Some(Some(_))) => Ok(zero),
            _ => bail!("not reported by this driver"),
        }
    }
}

impl NpuImpl for AmdNpu {
    fn device(&self) -> Option<&'static Device> {
        self.device
    }

    fn pci_slot(&self) -> PciSlot {
        self.pci_slot
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

    fn update(&self) {
        let mut state = self.state.get();

        state.awake = self.awake();
        if !state.awake || !self.sources.queries {
            state.busy = false;
            state.fresh = false;
            self.state.set(state);
            return;
        }

        let interrupts = self.interrupts().ok();
        state.busy = interrupts.is_some() && interrupts != state.interrupts;
        state.interrupts = interrupts;

        // queries restart the autosuspend delay: an idle NPU keeps its last values
        if state.busy || !state.fresh {
            state.sample = Some(self.query(state.sample));
            state.fresh = true;
        }

        self.state.set(state);
    }

    fn busy_time_per_client(&self) -> bool {
        self.sources.fdinfo_busy_time
    }

    fn memory_per_client(&self) -> bool {
        self.sources.fdinfo_memory
    }

    fn hide_unavailable(&self) -> bool {
        true
    }

    fn name(&self) -> Result<String> {
        self.drm_name()
    }

    fn usage(&self) -> Result<f64> {
        if self.sources.fdinfo_busy_time {
            bail!("busy time is per client");
        }

        // the PMF counts clocked columns as busy, idle ones too in turbo mode
        let busy = self.state.get().busy;
        self.sampled(|sample| sample.utilization, 0.0)
            .map(|utilization| if busy { utilization } else { 0.0 })
    }

    fn used_memory(&self) -> Result<u64> {
        bail!("memory is per client")
    }

    fn total_memory(&self) -> Result<u64> {
        bail!("the NPU works in system memory")
    }

    fn temperature(&self) -> Result<f64> {
        if !self.sources.hwmon_temperature {
            bail!("no NPU temperature");
        }

        self.hwmon_temperature()
    }

    fn power_usage(&self) -> Result<f64> {
        if !self.sources.hwmon_power {
            return self.sampled(|sample| sample.power, 0.0);
        }

        // suspended, it draws nothing: skip the PMF query (~0.6 ms of CPU)
        if !self.state.get().awake {
            return Ok(0.0);
        }

        read_parsed::<isize>(self.hwmon_path()?.join("power1_input"))
            .map(|power| power as f64 / 1_000_000.0)
    }

    fn core_frequency(&self) -> Result<f64> {
        self.sampled(|sample| sample.h_clock, 0.0)
    }

    fn memory_frequency(&self) -> Result<f64> {
        bail!("the NPU works in system memory")
    }

    fn tops(&self) -> Result<u64> {
        self.sampled(|sample| sample.tops, 0)
    }

    fn power_cap(&self) -> Result<f64> {
        bail!("no NPU power cap")
    }

    fn power_cap_max(&self) -> Result<f64> {
        bail!("no NPU power cap")
    }
}
