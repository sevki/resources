use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;

use anyhow::{Context, Result};
use lazy_regex::Lazy;
use log::{debug, warn};
use nvml_wrapper::enums::device::UsedGpuMemory;
use nvml_wrapper::error::NvmlError;
use nvml_wrapper::struct_wrappers::device::{ProcessInfo, ProcessUtilizationSample};
use nvml_wrapper::{Device, Nvml};

use crate::gpu_usage::{GpuClientSnapshots, GpuDriverStats, GpuIdentifier};
use crate::pci_slot::PciSlot;
use crate::units::IntegerPercentage;
use crate::util::unix_as_millis;

static NVML: Lazy<Result<Nvml, NvmlError>> = Lazy::new(|| {
    debug!("Initializing connection to NVML…");
    Nvml::init().inspect_err(|err| warn!("Unable to connect to NVML: {err}"))
});

static NVML_DEVICES: Lazy<Vec<(PciSlot, Device)>> = Lazy::new(|| {
    let Ok(nvml) = NVML.as_ref() else {
        return Vec::new();
    };

    debug!("Looking for NVIDIA devices…");
    let device_count = nvml.device_count().unwrap_or(0);
    let mut return_vec = Vec::with_capacity(device_count as usize);
    for i in 0..device_count {
        let Ok(gpu) = nvml.device_by_index(i) else {
            continue;
        };
        let Ok(pci_slot) = gpu.pci_info().map(|pci_info| pci_info.bus_id) else {
            continue;
        };
        let Ok(pci_slot) = PciSlot::from_str(&pci_slot) else {
            continue;
        };
        debug!(
            "Found {} at {}",
            gpu.name().unwrap_or("N/A".into()),
            pci_slot
        );
        return_vec.push((pci_slot, gpu));
    }
    return_vec
});

#[derive(Debug, Default)]
pub struct NvidiaSnapshot {
    process_stats: HashMap<PciSlot, Vec<ProcessUtilizationSample>>,
    process_infos: HashMap<PciSlot, Vec<ProcessInfo>>,
}

impl NvidiaSnapshot {
    #[must_use]
    pub fn new() -> Self {
        let mut process_stats = HashMap::with_capacity(NVML_DEVICES.len());
        let mut process_infos = HashMap::with_capacity(NVML_DEVICES.len());

        for (pci_slot, gpu) in NVML_DEVICES.iter() {
            process_stats.insert(
                *pci_slot,
                gpu.process_utilization_stats(
                    unix_as_millis()
                        .saturating_mul(1000)
                        .saturating_sub(5_000_000),
                )
                .unwrap_or_default(),
            );

            let mut comp_gfx_stats = gpu.running_graphics_processes().unwrap_or_default();
            comp_gfx_stats.extend(gpu.running_compute_processes().unwrap_or_default());
            process_infos.insert(*pci_slot, comp_gfx_stats);
        }

        Self {
            process_stats,
            process_infos,
        }
    }

    fn gpu_stats_for_slot(
        &self,
        pid: libc::pid_t,
        pci_slot: PciSlot,
    ) -> Result<GpuClientSnapshots> {
        let this_process_stats = self
            .process_stats
            .get(&pci_slot)
            .context("couldn't find GPU with this PCI slot")?
            .iter()
            .filter(|process| process.pid == pid as u32)
            .map(|stats| (stats.sm_util, stats.enc_util, stats.dec_util))
            .reduce(|acc, curr| (acc.0 + curr.0, acc.1 + curr.1, acc.2 + curr.2));

        let this_process_mem_stats: u64 = self
            .process_infos
            .get(&pci_slot)
            .context("couldn't find GPU with this PCI slot")?
            .iter()
            .filter(|process| process.pid == pid as u32)
            .map(|stats| match stats.used_gpu_memory {
                UsedGpuMemory::Unavailable => 0,
                UsedGpuMemory::Used(bytes) => bytes,
            })
            .sum();

        Ok(GpuClientSnapshots::from_client(
            crate::gpu_usage::GpuClientId::Process(pid),
            GpuDriverStats::NvidiaStats {
                gfx_percentage: IntegerPercentage::try_new(
                    this_process_stats.unwrap_or_default().0 as u8,
                )?,
                mem_bytes: this_process_mem_stats,
                enc_percentage: IntegerPercentage::try_new(
                    this_process_stats.unwrap_or_default().1 as u8,
                )?,
                dec_percentage: IntegerPercentage::try_new(
                    this_process_stats.unwrap_or_default().2 as u8,
                )?,
            },
        ))
    }

    #[must_use]
    pub fn gpu_usage_stats_all(
        &self,
        pid: libc::pid_t,
    ) -> BTreeMap<GpuIdentifier, GpuClientSnapshots> {
        let mut return_map = BTreeMap::new();

        for (pci_slot, _) in NVML_DEVICES.iter() {
            if let Ok(stats) = self.gpu_stats_for_slot(pid, *pci_slot) {
                return_map.insert(GpuIdentifier::PciSlot(*pci_slot), stats);
            }
        }

        return_map
    }
}
