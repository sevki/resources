use anyhow::{Context, Result};
use lazy_regex::{Lazy, Regex, lazy_regex};
use log::trace;

use crate::process_data::Niceness;
use crate::util::{NUM_CPUS, extract_from_regex};

// /proc/<pid>/stat

// we split the stat contents where the executable name ends, which is the second element
const STAT_OFFSET: usize = 2;
const STAT_STATE: usize = 3 - STAT_OFFSET - 1;
const STAT_PARENT_PID: usize = 3 - STAT_OFFSET;
const STAT_USER_CPU_TIME: usize = 13 - STAT_OFFSET;
const STAT_SYSTEM_CPU_TIME: usize = 14 - STAT_OFFSET;
const STAT_NICE: usize = 18 - STAT_OFFSET;
const STAT_STARTTIME: usize = 21 - STAT_OFFSET;

pub struct StatFields {
    /// single-character process state, see man proc(5) (e.g. 'R', 'S', 'T', 'Z')
    pub state: char,
    pub parent_pid: libc::pid_t,
    pub user_cpu_time: u64,
    pub system_cpu_time: u64,
    pub niceness: Niceness,
    pub starttime: u64, // in clock ticks, see man proc(5)!
}

impl StatFields {
    pub fn parse(pid: libc::pid_t, raw: &str) -> Result<Self> {
        let fields = raw
            .split(')')
            .next_back()
            .context("stat doesn't have ')'")
            .inspect_err(|err| trace!("Can't parse 'stat': {err}"))?
            .split(' ')
            .skip(1) // the first element would be a space, let's ignore that
            .collect::<Vec<_>>();

        let field = |index: usize, label: &str| -> Result<&str> {
            fields
                .get(index)
                .copied()
                .context("wrong stat file format")
                .inspect_err(|err| trace!("Can't parse {label} from 'stat': {err}"))
        };

        let state = field(STAT_STATE, "state")?
            .chars()
            .next()
            .context("empty state field in stat")?;
        trace!("State of {pid} determined to be {state}");

        let parent_pid = field(STAT_PARENT_PID, "parent pid")?
            .parse()
            .context("couldn't parse stat file content to int")?;
        trace!("Parent pid of {pid} determined to be {parent_pid}");

        let user_cpu_time = field(STAT_USER_CPU_TIME, "user cpu time")?
            .parse()
            .context("couldn't parse stat file content to int")?;
        trace!("User CPU time of {pid} determined to be {user_cpu_time}");

        let system_cpu_time = field(STAT_SYSTEM_CPU_TIME, "system cpu time")?
            .parse()
            .context("couldn't parse stat file content to int")?;
        trace!("System CPU time of {pid} determined to be {system_cpu_time}");

        let niceness = field(STAT_NICE, "nice")?
            .parse()
            .context("couldn't parse stat file content to int")?;
        trace!("Nice of {pid} determined to be {niceness}");

        let starttime = field(STAT_STARTTIME, "start time")?
            .parse()
            .context("couldn't parse stat file content to int")?;
        trace!("Starttime of {pid} determined to be {starttime}");

        Ok(StatFields {
            state,
            parent_pid,
            user_cpu_time,
            system_cpu_time,
            niceness,
            starttime,
        })
    }
}

// /proc/<pid>/status

static RE_UID: Lazy<Regex> = lazy_regex!(r"Uid:\s*(\d+)");
static RE_AFFINITY: Lazy<Regex> = lazy_regex!(r"Cpus_allowed:\s*([0-9A-Fa-f]+)");
static RE_RSS_ANON: Lazy<Regex> = lazy_regex!(r"RssAnon:\s*([0-9]+)\s*kB");
static RE_RSS_SHMEM: Lazy<Regex> = lazy_regex!(r"RssShmem:\s*([0-9]+)\s*kB");
static RE_RSS_FILE: Lazy<Regex> = lazy_regex!(r"RssFile:\s*([0-9]+)\s*kB");
static RE_VM_RSS: Lazy<Regex> = lazy_regex!(r"VmRSS:\s*([0-9]+)\s*kB");
static RE_VM_SIZE: Lazy<Regex> = lazy_regex!(r"VmSize:\s*([0-9]+)\s*kB");
static RE_SWAP_USAGE: Lazy<Regex> = lazy_regex!(r"VmSwap:\s*([0-9]+)\s*kB");

pub struct StatusFields {
    pub uid: u32,
    /// logical CPU mask
    pub affinity: Vec<bool>,
    pub rss: usize,
    pub rss_anon: usize,
    pub rss_shmem: usize,
    pub rss_file: usize,
    pub vm_size: usize,
    pub swap_usage: usize,
}

impl StatusFields {
    fn get_uid(status: &str) -> Result<u32> {
        if let Some(captures) = RE_UID.captures(status) {
            let first_num_str = captures.get(1).context("no uid found")?;
            first_num_str
                .as_str()
                .parse::<u32>()
                .context("couldn't parse uid in /status")
        } else {
            Ok(0)
        }
    }

    fn parse_affinity(status: &str) -> Vec<bool> {
        let mut affinity = Vec::with_capacity(*NUM_CPUS);

        extract_from_regex::<String, _>(&RE_AFFINITY, status)
            .unwrap_or_default()
            .chars()
            .map(|c| c.to_digit(16).unwrap_or_default())
            .rev()
            .for_each(|int| {
                // we want the bits and there are 4 bits in a hex digit
                (0..4).for_each(|i| {
                    // this should prevent wrong size affinity vecs if the thread count is not
                    // divisible by 4
                    if affinity.len() < *NUM_CPUS {
                        affinity.push((int & (1 << i)) != 0);
                    }
                });
            });

        affinity
    }

    pub fn parse(pid: libc::pid_t, status: &str) -> Result<Self> {
        let uid = Self::get_uid(status)?;

        let affinity = Self::parse_affinity(status);
        trace!("Affinity of {pid} determined to be {affinity:?}");

        let swap_usage = extract_from_regex::<usize, _>(&RE_SWAP_USAGE, status)
            .unwrap_or_default()
            .saturating_mul(1024);
        trace!("Swap usage of {pid} determined to be {swap_usage}");

        let rss = extract_from_regex::<usize, _>(&RE_VM_RSS, status)
            .unwrap_or_default()
            .saturating_mul(1024);
        trace!("VmRSS of {pid} determined to be {rss}");

        let rss_anon = extract_from_regex::<usize, _>(&RE_RSS_ANON, status)
            .unwrap_or_default()
            .saturating_mul(1024);
        trace!("RssAnon of {pid} determined to be {rss_anon}");

        let rss_shmem = extract_from_regex::<usize, _>(&RE_RSS_SHMEM, status)
            .unwrap_or_default()
            .saturating_mul(1024);
        trace!("RssShmem of {pid} determined to be {rss_shmem}");

        let rss_file = extract_from_regex::<usize, _>(&RE_RSS_FILE, status)
            .unwrap_or_default()
            .saturating_mul(1024);
        trace!("RssFile of {pid} determined to be {rss_file}");

        let vm_size = extract_from_regex::<usize, _>(&RE_VM_SIZE, status)
            .unwrap_or_default()
            .saturating_mul(1024);
        trace!("VmSize of {pid} determined to be {vm_size}");

        Ok(StatusFields {
            uid,
            affinity,
            rss,
            rss_anon,
            rss_shmem,
            rss_file,
            vm_size,
            swap_usage,
        })
    }
}

// /proc/<pid>/io

static RE_IO_READ: Lazy<Regex> = lazy_regex!(r"read_bytes:\s*(\d+)");
static RE_IO_WRITE: Lazy<Regex> = lazy_regex!(r"write_bytes:\s*(\d+)");

pub struct IoFields {
    pub read_bytes: Option<u64>,
    pub write_bytes: Option<u64>,
}

impl IoFields {
    pub fn parse(pid: libc::pid_t, io: Option<&str>) -> IoFields {
        let read_bytes = io.and_then(|io| {
            RE_IO_READ
                .captures(io)
                .and_then(|captures| captures.get(1))
                .and_then(|capture| capture.as_str().parse::<u64>().ok())
        });
        trace!("Read bytes of {pid} determined to be {read_bytes:?}");

        let write_bytes = io.and_then(|io| {
            RE_IO_WRITE
                .captures(io)
                .and_then(|captures| captures.get(1))
                .and_then(|capture| capture.as_str().parse::<u64>().ok())
        });
        trace!("Written bytes of {pid} determined to be {write_bytes:?}");

        IoFields {
            read_bytes,
            write_bytes,
        }
    }
}

#[cfg(test)]
mod stat_tests {
    use super::*;

    const STAT_LINE: &str = "1234 (my (weird) proc) T 42 1234 1234 0 -1 4194560 100 0 0 0 7 3 0 0 20 0 1 0 5555 1000 100 18446744073709551615 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0";

    #[test]
    fn parses_state_and_parent() {
        let stat = StatFields::parse(1234, STAT_LINE).unwrap();
        assert_eq!(stat.state, 'T');
        assert_eq!(stat.parent_pid, 42);
        assert_eq!(stat.user_cpu_time, 7);
        assert_eq!(stat.system_cpu_time, 3);
        assert_eq!(stat.starttime, 5555);
    }
}
