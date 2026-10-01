use serde::{Deserialize, Serialize};

use crate::units::ns_delta_to_usage_fraction;

// drm-engine-npu-amdxdna in the legacy out-of-tree driver
pub const AMDXDNA_BUSY_FIELDS: [&str; 2] =
    ["drm-engine-amdxdna_accel_driver", "drm-engine-npu-amdxdna"];

// drm-total-memory counts the dev BOs twice: they are carved out of the heap BO
pub const AMDXDNA_MEMORY_FIELDS: [&str; 2] = [
    "amdxdna_accel_driver-internal-alloc",
    "amdxdna_accel_driver-external-alloc",
];

pub const AMDXDNA_TOTAL_MEMORY_FIELD: &str = "drm-total-memory";

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize, Copy)]
pub enum NpuUsageStats {
    AmdxdnaStats { usage_ns: u64, mem_bytes: u64 },
}

impl NpuUsageStats {
    #[must_use]
    pub fn usage_fraction(&self, old: &Self, time_delta_ms: u64) -> Option<f32> {
        match (self, old) {
            (Self::AmdxdnaStats { usage_ns: a, .. }, Self::AmdxdnaStats { usage_ns: b, .. }) => {
                ns_delta_to_usage_fraction(*a, *b, time_delta_ms)
            }
        }
    }

    #[must_use]
    pub fn mem(&self) -> Option<u64> {
        match self {
            Self::AmdxdnaStats { mem_bytes, .. } => Some(*mem_bytes),
        }
    }

    #[must_use]
    pub fn greater(&self, other: &Self) -> Self {
        match (self, other) {
            (
                Self::AmdxdnaStats {
                    usage_ns: a_ns,
                    mem_bytes: a_mem,
                },
                Self::AmdxdnaStats {
                    usage_ns: b_ns,
                    mem_bytes: b_mem,
                },
            ) => Self::AmdxdnaStats {
                usage_ns: *a_ns.max(b_ns),
                mem_bytes: *a_mem.max(b_mem),
            },
        }
    }
}
