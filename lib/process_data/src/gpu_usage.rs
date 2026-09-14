use std::{
    collections::{BTreeMap, HashSet},
    fmt::Display,
    sync::LazyLock,
    time::Instant,
};

use serde::{Deserialize, Serialize};

use crate::pci_slot::PciSlot;
use crate::units::{IntegerPercentage, cycles_delta_to_usage_fraction, ns_delta_to_usage_fraction};

/// DRM client IDs are scoped to a GPU, not a PID or a device-node path.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GpuClientId {
    Drm(u64),
    /// Older drivers without client IDs cannot reliably identify shared clients.
    Fd {
        pid: libc::pid_t,
        fd: usize,
    },
    Process(libc::pid_t),
}

/// One observation of a client, timestamped by the process sampling helper.
#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuClientSnapshot {
    pub driver_stats: GpuDriverStats,
    pub timestamp_ms: u64,
}

/// The distinct clients observed for one GPU during a process scan.
#[derive(Debug, Clone, Default, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct GpuClientSnapshots {
    pub clients: BTreeMap<GpuClientId, GpuClientSnapshot>,
}

impl GpuClientSnapshots {
    pub fn from_client(id: GpuClientId, driver_stats: GpuDriverStats) -> Self {
        let mut stats = Self::default();
        stats.insert_client(id, driver_stats);
        stats
    }

    pub fn insert_client(&mut self, id: GpuClientId, driver_stats: GpuDriverStats) {
        static START: LazyLock<Instant> = LazyLock::new(Instant::now);
        // Keep one complete sample. Repeated FD observations must not add load or
        // combine busy counters and clock values from different observations.
        self.clients.entry(id).or_insert_with(|| GpuClientSnapshot {
            driver_stats,
            timestamp_ms: START.elapsed().as_millis() as u64,
        });
    }

    pub fn retain_busy_high_water(&mut self, old: &Self) {
        for (id, sample) in &mut self.clients {
            if let Some(previous) = old.clients.get(id) {
                if sample.timestamp_ms < previous.timestamp_ms {
                    continue; // The sampling helper restarted; establish a new baseline.
                }
                sample
                    .driver_stats
                    .retain_busy_high_water(&previous.driver_stats);
            }
        }
    }

    pub fn combine_media_engines(&mut self) {
        for sample in self.clients.values_mut() {
            sample.driver_stats.combine_media_engines();
        }
    }

    pub fn fractions(&self, old: &Self) -> GpuFractions {
        let mut usage = GpuUsageAccumulator::default();
        usage.add(GpuIdentifier::default(), self, old);
        usage.fractions()
    }

    pub fn mem(&self) -> Option<u64> {
        // Preserve the existing conservative memory estimate. Different clients
        // may reference shared buffers; summing them is a separate accounting issue.
        self.clients
            .values()
            .filter_map(|sample| sample.driver_stats.mem())
            .max()
    }
}

#[derive(Debug, Default)]
pub struct GpuFractions {
    pub gfx: f32,
    pub enc: f32,
    pub dec: f32,
}

#[derive(Default)]
struct GpuEngineFractions {
    render: f32,
    compute: f32,
    encode: f32,
    decode: f32,
}

/// Collect unique clients before combining engine loads. Used for both the GPU
/// page and application totals, where a client may be held by multiple processes.
#[derive(Default)]
pub struct GpuUsageAccumulator {
    seen: HashSet<(GpuIdentifier, GpuClientId)>,
    engines: BTreeMap<GpuIdentifier, GpuEngineFractions>,
}

impl GpuUsageAccumulator {
    pub fn add(&mut self, gpu: GpuIdentifier, new: &GpuClientSnapshots, old: &GpuClientSnapshots) {
        for (id, sample) in &new.clients {
            let Some(previous) = old.clients.get(id) else {
                continue;
            };
            if sample.timestamp_ms < previous.timestamp_ms {
                continue;
            }
            if !self.seen.insert((gpu, *id)) {
                continue;
            }
            let elapsed = sample.timestamp_ms.saturating_sub(previous.timestamp_ms);
            let new_stats = &sample.driver_stats;
            let old_stats = &previous.driver_stats;
            let engines = self.engines.entry(gpu).or_default();
            if let (
                GpuDriverStats::XeStats {
                    render_cycles: new_render_cycles,
                    render_total_cycles: new_render_total_cycles,
                    compute_cycles: new_compute_cycles,
                    compute_total_cycles: new_compute_total_cycles,
                    ..
                },
                GpuDriverStats::XeStats {
                    render_cycles: old_render_cycles,
                    render_total_cycles: old_render_total_cycles,
                    compute_cycles: old_compute_cycles,
                    compute_total_cycles: old_compute_total_cycles,
                    ..
                },
            ) = (new_stats, old_stats)
            {
                engines.render += cycles_delta_to_usage_fraction(
                    *new_render_cycles,
                    *old_render_cycles,
                    *new_render_total_cycles,
                    *old_render_total_cycles,
                )
                .unwrap_or_default();
                engines.compute += cycles_delta_to_usage_fraction(
                    *new_compute_cycles,
                    *old_compute_cycles,
                    *new_compute_total_cycles,
                    *old_compute_total_cycles,
                )
                .unwrap_or_default();
            } else {
                engines.render += new_stats
                    .gfx_fraction(old_stats, elapsed)
                    .unwrap_or_default();
            }
            engines.encode += new_stats
                .enc_fraction(old_stats, elapsed)
                .unwrap_or_default();
            engines.decode += new_stats
                .dec_fraction(old_stats, elapsed)
                .unwrap_or_default();
        }
    }

    pub fn fractions(&self) -> GpuFractions {
        let mut result = GpuFractions::default();
        for engines in self.engines.values() {
            result.gfx += engines.render.max(engines.compute);
            result.enc += engines.encode;
            result.dec += engines.decode;
        }
        result
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize, Copy, PartialOrd, Ord)]
pub enum GpuIdentifier {
    PciSlot(PciSlot),
    Enumerator(usize),
}

impl Default for GpuIdentifier {
    fn default() -> Self {
        GpuIdentifier::Enumerator(0)
    }
}

impl Display for GpuIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GpuIdentifier::PciSlot(pci_slot) => write!(f, "{pci_slot}"),
            GpuIdentifier::Enumerator(enumerator) => write!(f, "{enumerator}"),
        }
    }
}

/// Raw driver statistics, including cumulative counters and instantaneous gauges.
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub enum GpuDriverStats {
    AmdgpuStats {
        gfx_ns: u64,
        enc_ns: u64,
        dec_ns: u64,
        mem_bytes: u64,
    },
    I915Stats {
        gfx_ns: u64,
        video_ns: u64,
    },
    NvidiaStats {
        gfx_percentage: IntegerPercentage,
        enc_percentage: IntegerPercentage,
        dec_percentage: IntegerPercentage,
        mem_bytes: u64,
    },
    V3dStats {
        gfx_ns: u64,
        mem_bytes: u64,
    },
    XeStats {
        render_cycles: u64,
        render_total_cycles: u64,
        compute_cycles: u64,
        compute_total_cycles: u64,
        video_cycles: u64,
        video_total_cycles: u64,
        mem_bytes: u64,
    },
}

fn max_option(first: Option<f32>, second: Option<f32>) -> Option<f32> {
    first
        .zip(second)
        .map(|(first, second)| first.max(second))
        .or(first.or(second))
}

impl GpuDriverStats {
    #[must_use]
    pub fn gfx_fraction(&self, old: &Self, time_delta_ms: u64) -> Option<f32> {
        match (self, old) {
            (
                Self::AmdgpuStats {
                    gfx_ns: new_graphics_ns,
                    ..
                },
                Self::AmdgpuStats {
                    gfx_ns: old_graphics_ns,
                    ..
                },
            )
            | (
                Self::I915Stats {
                    gfx_ns: new_graphics_ns,
                    ..
                },
                Self::I915Stats {
                    gfx_ns: old_graphics_ns,
                    ..
                },
            )
            | (
                Self::V3dStats {
                    gfx_ns: new_graphics_ns,
                    ..
                },
                Self::V3dStats {
                    gfx_ns: old_graphics_ns,
                    ..
                },
            ) => ns_delta_to_usage_fraction(*new_graphics_ns, *old_graphics_ns, time_delta_ms),
            (Self::NvidiaStats { gfx_percentage, .. }, Self::NvidiaStats { .. }) => {
                Some(gfx_percentage.fraction())
            }
            (
                Self::XeStats {
                    render_cycles: new_render_cycles,
                    render_total_cycles: new_render_total_cycles,
                    compute_cycles: new_compute_cycles,
                    compute_total_cycles: new_compute_total_cycles,
                    ..
                },
                Self::XeStats {
                    render_cycles: old_render_cycles,
                    render_total_cycles: old_render_total_cycles,
                    compute_cycles: old_compute_cycles,
                    compute_total_cycles: old_compute_total_cycles,
                    ..
                },
            ) => {
                // Right now, Resources doesn't differentiate between compute and gfx load, and since xe gives us cycles
                // instead of ns for whatever reason, we need to do this hack :/
                max_option(
                    cycles_delta_to_usage_fraction(
                        *new_render_cycles,
                        *old_render_cycles,
                        *new_render_total_cycles,
                        *old_render_total_cycles,
                    ),
                    cycles_delta_to_usage_fraction(
                        *new_compute_cycles,
                        *old_compute_cycles,
                        *new_compute_total_cycles,
                        *old_compute_total_cycles,
                    ),
                )
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn enc_fraction(&self, old: &Self, time_delta_ms: u64) -> Option<f32> {
        match (self, old) {
            (
                Self::AmdgpuStats {
                    enc_ns: new_busy_ns,
                    ..
                },
                Self::AmdgpuStats {
                    enc_ns: old_busy_ns,
                    ..
                },
            )
            | (
                Self::I915Stats {
                    video_ns: new_busy_ns,
                    ..
                },
                Self::I915Stats {
                    video_ns: old_busy_ns,
                    ..
                },
            ) => ns_delta_to_usage_fraction(*new_busy_ns, *old_busy_ns, time_delta_ms),
            (Self::NvidiaStats { enc_percentage, .. }, Self::NvidiaStats { .. }) => {
                Some(enc_percentage.fraction())
            }
            (
                Self::XeStats {
                    video_cycles: new_video_cycles,
                    video_total_cycles: new_video_total_cycles,
                    ..
                },
                Self::XeStats {
                    video_cycles: old_video_cycles,
                    video_total_cycles: old_video_total_cycles,
                    ..
                },
            ) => cycles_delta_to_usage_fraction(
                *new_video_cycles,
                *old_video_cycles,
                *new_video_total_cycles,
                *old_video_total_cycles,
            ),
            _ => None,
        }
    }

    #[must_use]
    pub fn dec_fraction(&self, old: &Self, time_delta_ms: u64) -> Option<f32> {
        match (self, old) {
            (
                Self::AmdgpuStats {
                    dec_ns: new_busy_ns,
                    ..
                },
                Self::AmdgpuStats {
                    dec_ns: old_busy_ns,
                    ..
                },
            ) => ns_delta_to_usage_fraction(*new_busy_ns, *old_busy_ns, time_delta_ms),
            (Self::NvidiaStats { dec_percentage, .. }, Self::NvidiaStats { .. }) => {
                Some(dec_percentage.fraction())
            }
            (
                Self::XeStats {
                    video_cycles: new_video_cycles,
                    video_total_cycles: new_video_total_cycles,
                    ..
                },
                Self::XeStats {
                    video_cycles: old_video_cycles,
                    video_total_cycles: old_video_total_cycles,
                    ..
                },
            ) => cycles_delta_to_usage_fraction(
                *new_video_cycles,
                *old_video_cycles,
                *new_video_total_cycles,
                *old_video_total_cycles,
            ),
            _ => None,
        }
    }

    #[must_use]
    pub fn mem(&self) -> Option<u64> {
        match self {
            Self::AmdgpuStats { mem_bytes, .. }
            | Self::NvidiaStats { mem_bytes, .. }
            | Self::V3dStats { mem_bytes, .. }
            | Self::XeStats { mem_bytes, .. } => Some(*mem_bytes),
            Self::I915Stats { .. } => None,
        }
    }

    /// Keep busy counters monotonic within one client, without mixing clock samples.
    fn retain_busy_high_water(&mut self, old: &Self) {
        match (self, old) {
            (
                Self::AmdgpuStats {
                    gfx_ns,
                    enc_ns,
                    dec_ns,
                    ..
                },
                Self::AmdgpuStats {
                    gfx_ns: old_graphics_ns,
                    enc_ns: old_encode_ns,
                    dec_ns: old_decode_ns,
                    ..
                },
            ) => {
                *gfx_ns = (*gfx_ns).max(*old_graphics_ns);
                *enc_ns = (*enc_ns).max(*old_encode_ns);
                *dec_ns = (*dec_ns).max(*old_decode_ns);
            }
            (
                Self::I915Stats { gfx_ns, video_ns },
                Self::I915Stats {
                    gfx_ns: old_graphics_ns,
                    video_ns: old_video_ns,
                },
            ) => {
                *gfx_ns = (*gfx_ns).max(*old_graphics_ns);
                *video_ns = (*video_ns).max(*old_video_ns);
            }
            (
                Self::V3dStats { gfx_ns, .. },
                Self::V3dStats {
                    gfx_ns: old_graphics_ns,
                    ..
                },
            ) => *gfx_ns = (*gfx_ns).max(*old_graphics_ns),
            (
                Self::XeStats {
                    render_cycles,
                    render_total_cycles,
                    compute_cycles,
                    compute_total_cycles,
                    video_cycles,
                    video_total_cycles,
                    ..
                },
                Self::XeStats {
                    render_cycles: old_render_cycles,
                    render_total_cycles: old_render_total_cycles,
                    compute_cycles: old_compute_cycles,
                    compute_total_cycles: old_compute_total_cycles,
                    video_cycles: old_video_cycles,
                    video_total_cycles: old_video_total_cycles,
                    ..
                },
            ) => {
                // A GPU clock reset establishes a new baseline instead of retaining the old epoch.
                if *render_total_cycles >= *old_render_total_cycles {
                    *render_cycles = (*render_cycles).max(*old_render_cycles);
                }
                if *compute_total_cycles >= *old_compute_total_cycles {
                    *compute_cycles = (*compute_cycles).max(*old_compute_cycles);
                }
                if *video_total_cycles >= *old_video_total_cycles {
                    *video_cycles = (*video_cycles).max(*old_video_cycles);
                }
            }
            _ => {}
        }
    }

    fn combine_media_engines(&mut self) {
        if let Self::AmdgpuStats { enc_ns, dec_ns, .. } = self {
            *enc_ns = (*enc_ns).max(*dec_ns);
            *dec_ns = *enc_ns;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn xe(render: u64, compute: u64, total: u64) -> GpuDriverStats {
        GpuDriverStats::XeStats {
            render_cycles: render,
            render_total_cycles: total,
            compute_cycles: compute,
            compute_total_cycles: total,
            video_cycles: 0,
            video_total_cycles: total,
            mem_bytes: 0,
        }
    }

    fn samples(rows: &[(u64, GpuDriverStats)], timestamp_ms: u64) -> GpuClientSnapshots {
        GpuClientSnapshots {
            clients: rows
                .iter()
                .map(|(id, driver_stats)| {
                    (
                        GpuClientId::Drm(*id),
                        GpuClientSnapshot {
                            driver_stats: *driver_stats,
                            timestamp_ms,
                        },
                    )
                })
                .collect(),
        }
    }

    fn assert_fraction(actual: f32, expected: f32) {
        assert!(
            (actual - expected).abs() < 0.00001,
            "{actual} != {expected}"
        );
    }

    #[test]
    fn miside_active_client_survives_idle_clients() {
        // Real PID 43997: FDs 274, 294, 304, 365, all renderD128.
        let old = samples(
            &[
                (263, xe(0, 0, 1_526_476_827_990)),
                (265, xe(0, 0, 1_526_476_833_406)),
                (266, xe(1_567_766_235, 0, 1_526_476_837_237)),
                (267, xe(1_379, 0, 1_526_476_850_747)),
            ],
            0,
        );
        let new = samples(
            &[
                (263, xe(0, 0, 1_526_515_372_448)),
                (265, xe(0, 0, 1_526_515_378_162)),
                (266, xe(1_585_206_254, 0, 1_526_515_381_674)),
                (267, xe(1_379, 0, 1_526_515_395_868)),
            ],
            2007,
        );
        assert_fraction(new.fractions(&old).gfx, 17_440_019.0 / 38_544_437.0);
    }

    #[test]
    fn independent_clients_add_usage_without_adding_clock_denominators() {
        let old = samples(
            &[
                (1, xe(1000, 0, 1000)),
                (2, xe(0, 0, 1000)),
                (3, xe(0, 0, 1000)),
            ],
            0,
        );
        let new = samples(
            &[
                (1, xe(1060, 0, 1100)),
                (2, xe(20, 0, 1100)),
                (3, xe(0, 0, 1100)),
            ],
            1000,
        );
        assert_fraction(new.fractions(&old).gfx, 0.8);
    }

    #[test]
    fn duplicates_across_processes_count_once_and_gpu_ids_remain_distinct() {
        let old = samples(&[(1, xe(0, 0, 100))], 0);
        let new = samples(&[(1, xe(60, 0, 200))], 1000);
        let mut usage = GpuUsageAccumulator::default();
        usage.add(GpuIdentifier::Enumerator(0), &new, &old);
        usage.add(GpuIdentifier::Enumerator(0), &new, &old);
        assert_fraction(usage.fractions().gfx, 0.6);
        usage.add(GpuIdentifier::Enumerator(1), &new, &old);
        assert_fraction(usage.fractions().gfx, 1.2);
    }

    #[test]
    fn render_and_compute_are_combined_after_client_aggregation() {
        let old_a = samples(&[(1, xe(0, 0, 100))], 0);
        let new_a = samples(&[(1, xe(60, 0, 200))], 1000);
        let old_b = samples(&[(2, xe(0, 0, 100))], 0);
        let new_b = samples(&[(2, xe(0, 60, 200))], 1000);
        let mut usage = GpuUsageAccumulator::default();
        usage.add(GpuIdentifier::default(), &new_a, &old_a);
        usage.add(GpuIdentifier::default(), &new_b, &old_b);
        assert_fraction(usage.fractions().gfx, 0.6);
    }

    #[test]
    fn client_turnover_does_not_create_spikes_or_hide_surviving_load() {
        let old = samples(&[(1, xe(10000, 0, 100)), (2, xe(100, 0, 100))], 0);
        let new = samples(&[(2, xe(180, 0, 200)), (3, xe(9000, 0, 200))], 1000);
        assert_fraction(new.fractions(&old).gfx, 0.8);
    }

    #[test]
    fn busy_counter_regression_does_not_double_count_recovery() {
        let old = samples(&[(1, xe(100, 0, 1000))], 0);
        let mut regressed = samples(&[(1, xe(90, 0, 1100))], 1000);
        regressed.retain_busy_high_water(&old);
        assert_fraction(regressed.fractions(&old).gfx, 0.0);
        let mut recovered = samples(&[(1, xe(110, 0, 1200))], 2000);
        recovered.retain_busy_high_water(&regressed);
        assert_fraction(recovered.fractions(&regressed).gfx, 0.1);
    }

    #[test]
    fn gpu_clock_reset_starts_a_new_baseline() {
        let old = samples(&[(1, xe(1000, 0, 2000))], 0);
        let mut reset = samples(&[(1, xe(10, 0, 100))], 1000);
        reset.retain_busy_high_water(&old);
        assert_fraction(reset.fractions(&old).gfx, 0.0);
        let mut next = samples(&[(1, xe(60, 0, 200))], 2000);
        next.retain_busy_high_water(&reset);
        assert_fraction(next.fractions(&reset).gfx, 0.5);
    }

    #[test]
    fn ns_clients_keep_separate_lifetimes_and_sampling_intervals() {
        let stats = |n| GpuDriverStats::I915Stats {
            gfx_ns: n,
            video_ns: 0,
        };
        let old = samples(
            &[(1, stats(100_000_000_000)), (2, stats(10_000_000_000))],
            1000,
        );
        let new = samples(
            &[(1, stats(100_020_000_000)), (2, stats(10_800_000_000))],
            2000,
        );
        assert_fraction(new.fractions(&old).gfx, 0.82);
    }

    #[test]
    fn combined_media_engines_are_adjusted_per_client() {
        let stats = |enc_ns, dec_ns| GpuDriverStats::AmdgpuStats {
            gfx_ns: 0,
            enc_ns,
            dec_ns,
            mem_bytes: 0,
        };
        let mut old = samples(&[(1, stats(0, 0)), (2, stats(0, 0))], 1000);
        let mut new = samples(
            &[(1, stats(600_000_000, 0)), (2, stats(0, 200_000_000))],
            2000,
        );
        old.combine_media_engines();
        new.combine_media_engines();
        assert_fraction(new.fractions(&old).enc, 0.8);
        assert_fraction(new.fractions(&old).dec, 0.8);
    }
}
