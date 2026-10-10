use std::fmt::Display;

use serde::{Deserialize, Serialize};

use crate::pci_slot::PciSlot;
use crate::units::{IntegerPercentage, cycles_delta_to_usage_fraction, ns_delta_to_usage_fraction};

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
            GpuIdentifier::Enumerator(e) => write!(f, "{e}"),
        }
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Ord)]
pub enum GpuUsageStats {
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
    PanthorStats {
        gfx_ns: u64,
        mem_bytes: u64,
    },
    XeStats {
        gfx_cycles: u64,
        gfx_total_cycles: u64,
        compute_cycles: u64,
        compute_total_cycles: u64,
        video_cycles: u64,
        video_total_cycles: u64,
        mem_bytes: u64,
    },
}

fn max_option(a: Option<f32>, b: Option<f32>) -> Option<f32> {
    a.zip(b).map(|(x, y)| x.max(y)).or(a.or(b))
}

impl GpuUsageStats {
    #[must_use]
    pub fn gfx_fraction(&self, old: &Self, time_delta_ms: u64) -> Option<f32> {
        match (self, old) {
            (Self::AmdgpuStats { gfx_ns: a, .. }, Self::AmdgpuStats { gfx_ns: b, .. })
            | (Self::I915Stats { gfx_ns: a, .. }, Self::I915Stats { gfx_ns: b, .. })
            | (Self::V3dStats { gfx_ns: a, .. }, Self::V3dStats { gfx_ns: b, .. })
            | (Self::PanthorStats { gfx_ns: a, .. }, Self::PanthorStats { gfx_ns: b, .. }) => {
                ns_delta_to_usage_fraction(*a, *b, time_delta_ms)
            }
            (Self::NvidiaStats { gfx_percentage, .. }, Self::NvidiaStats { .. }) => {
                Some(gfx_percentage.fraction())
            }
            (
                Self::XeStats {
                    gfx_cycles: a_gfx,
                    gfx_total_cycles: a_gfx_total,
                    compute_cycles: a_compute,
                    compute_total_cycles: a_compute_total,
                    ..
                },
                Self::XeStats {
                    gfx_cycles: b_gfx,
                    gfx_total_cycles: b_gfx_total,
                    compute_cycles: b_compute,
                    compute_total_cycles: b_compute_total,
                    ..
                },
            ) => {
                // Right now, Resources doesn't differentiate between compute and gfx load, and since xe gives us cycles
                // instead of ns for whatever reason, we need to do this hack :/
                max_option(
                    cycles_delta_to_usage_fraction(*a_gfx, *b_gfx, *a_gfx_total, *b_gfx_total),
                    cycles_delta_to_usage_fraction(
                        *a_compute,
                        *b_compute,
                        *a_compute_total,
                        *b_compute_total,
                    ),
                )
            }
            _ => None,
        }
    }

    #[must_use]
    pub fn enc_fraction(&self, old: &Self, time_delta_ms: u64) -> Option<f32> {
        match (self, old) {
            (Self::AmdgpuStats { enc_ns: a, .. }, Self::AmdgpuStats { enc_ns: b, .. })
            | (Self::I915Stats { video_ns: a, .. }, Self::I915Stats { video_ns: b, .. }) => {
                ns_delta_to_usage_fraction(*a, *b, time_delta_ms)
            }
            (Self::NvidiaStats { enc_percentage, .. }, Self::NvidiaStats { .. }) => {
                Some(enc_percentage.fraction())
            }
            (
                Self::XeStats {
                    video_cycles: a,
                    video_total_cycles: a_total,
                    ..
                },
                Self::XeStats {
                    video_cycles: b,
                    video_total_cycles: b_total,
                    ..
                },
            ) => cycles_delta_to_usage_fraction(*a, *b, *a_total, *b_total),
            _ => None,
        }
    }

    #[must_use]
    pub fn dec_fraction(&self, old: &Self, time_delta_ms: u64) -> Option<f32> {
        match (self, old) {
            (Self::AmdgpuStats { dec_ns: a, .. }, Self::AmdgpuStats { dec_ns: b, .. }) => {
                ns_delta_to_usage_fraction(*a, *b, time_delta_ms)
            }
            (Self::NvidiaStats { dec_percentage, .. }, Self::NvidiaStats { .. }) => {
                Some(dec_percentage.fraction())
            }
            (
                Self::XeStats {
                    video_cycles: a,
                    video_total_cycles: a_total,
                    ..
                },
                Self::XeStats {
                    video_cycles: b,
                    video_total_cycles: b_total,
                    ..
                },
            ) => cycles_delta_to_usage_fraction(*a, *b, *a_total, *b_total),
            _ => None,
        }
    }

    #[must_use]
    pub fn mem(&self) -> Option<u64> {
        match self {
            Self::AmdgpuStats { mem_bytes, .. }
            | Self::NvidiaStats { mem_bytes, .. }
            | Self::V3dStats { mem_bytes, .. }
            | Self::PanthorStats { mem_bytes, .. }
            | Self::XeStats { mem_bytes, .. } => Some(*mem_bytes),
            Self::I915Stats { .. } => None,
        }
    }

    #[must_use]
    pub fn greater(&self, other: &Self) -> Self {
        match (self, other) {
            (
                Self::AmdgpuStats {
                    gfx_ns: a_gfx,
                    enc_ns: a_enc,
                    dec_ns: a_dec,
                    mem_bytes: a_mem,
                },
                Self::AmdgpuStats {
                    gfx_ns: b_gfx,
                    enc_ns: b_enc,
                    dec_ns: b_dec,
                    mem_bytes: b_mem,
                },
            ) => Self::AmdgpuStats {
                gfx_ns: *a_gfx.max(b_gfx),
                enc_ns: *a_enc.max(b_enc),
                dec_ns: *a_dec.max(b_dec),
                mem_bytes: *a_mem.max(b_mem),
            },
            (
                Self::I915Stats {
                    gfx_ns: a_gfx,
                    video_ns: a_video,
                },
                Self::I915Stats {
                    gfx_ns: b_gfx,
                    video_ns: b_video,
                },
            ) => Self::I915Stats {
                gfx_ns: *a_gfx.max(b_gfx),
                video_ns: *a_video.max(b_video),
            },
            (
                Self::NvidiaStats {
                    gfx_percentage: a_gfx,
                    enc_percentage: a_enc,
                    dec_percentage: a_dec,
                    mem_bytes: a_mem,
                },
                Self::NvidiaStats {
                    gfx_percentage: b_gfx,
                    enc_percentage: b_enc,
                    dec_percentage: b_dec,
                    mem_bytes: b_mem,
                },
            ) => Self::NvidiaStats {
                gfx_percentage: *a_gfx.max(b_gfx),
                enc_percentage: *a_enc.max(b_enc),
                dec_percentage: *a_dec.max(b_dec),
                mem_bytes: *a_mem.max(b_mem),
            },
            (
                Self::V3dStats {
                    gfx_ns: a_gfx,
                    mem_bytes: a_mem,
                },
                Self::V3dStats {
                    gfx_ns: b_gfx,
                    mem_bytes: b_mem,
                },
            ) => Self::V3dStats {
                gfx_ns: *a_gfx.max(b_gfx),
                mem_bytes: *a_mem.max(b_mem),
            },
            (
                Self::PanthorStats {
                    gfx_ns: a_gfx,
                    mem_bytes: a_mem,
                },
                Self::PanthorStats {
                    gfx_ns: b_gfx,
                    mem_bytes: b_mem,
                },
            ) => Self::PanthorStats {
                gfx_ns: *a_gfx.max(b_gfx),
                mem_bytes: *a_mem.max(b_mem),
            },
            (
                Self::XeStats {
                    gfx_cycles: a_gfx,
                    gfx_total_cycles: a_gfx_total,
                    compute_cycles: a_compute,
                    compute_total_cycles: a_compute_total,
                    video_cycles: a_video,
                    video_total_cycles: a_video_total,
                    mem_bytes: a_mem,
                },
                Self::XeStats {
                    gfx_cycles: b_gfx,
                    gfx_total_cycles: b_gfx_total,
                    compute_cycles: b_compute,
                    compute_total_cycles: b_compute_total,
                    video_cycles: b_video,
                    video_total_cycles: b_video_total,
                    mem_bytes: b_mem,
                },
            ) => Self::XeStats {
                gfx_cycles: *a_gfx.max(b_gfx),
                gfx_total_cycles: *a_gfx_total.max(b_gfx_total),
                compute_cycles: *a_compute.max(b_compute),
                compute_total_cycles: *a_compute_total.max(b_compute_total),
                video_cycles: *a_video.max(b_video),
                video_total_cycles: *a_video_total.max(b_video_total),
                mem_bytes: *a_mem.max(b_mem),
            },
            _ => *self,
        }
    }
}
