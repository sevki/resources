//! Per-process detail information read from `/proc/<pid>/…`, as shown in the
//! lower pane of the Processes page (loosely modelled after Process Explorer):
//! mapped libraries, open files, sockets, threads, environment and security
//! attributes.
//!
//! All parsing is done by pure functions on strings so it can be unit tested;
//! the `read_*` functions are thin wrappers around the filesystem.

use std::collections::{BTreeMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use anyhow::{Context, Result};

// ---------------------------------------------------------------- libraries

/// A file mapped into a process' address space (shared library, executable,
/// memory-mapped data file…), with all of its mappings merged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedFile {
    pub path: String,
    /// total size of all mappings of the file in bytes
    pub size: u64,
    /// union of the permissions of all mappings, e.g. `r-xp`
    pub perms: String,
}

/// Parses `/proc/<pid>/maps`, keeping only file-backed mappings.
#[must_use]
pub fn parse_maps(maps: &str) -> Vec<MappedFile> {
    let mut by_path: BTreeMap<String, (u64, [bool; 3])> = BTreeMap::new();

    for line in maps.lines() {
        // address perms offset dev inode [path]
        let mut parts = line.splitn(6, char::is_whitespace);
        let (Some(range), Some(perms)) = (parts.next(), parts.next()) else {
            continue;
        };
        let path = line
            .splitn(6, char::is_whitespace)
            .nth(5)
            .map(str::trim)
            .unwrap_or_default();
        // anonymous mappings and [heap], [stack], … are not libraries
        if !path.starts_with('/') {
            continue;
        }
        let Some((start, end)) = range.split_once('-') else {
            continue;
        };
        let (Ok(start), Ok(end)) = (u64::from_str_radix(start, 16), u64::from_str_radix(end, 16))
        else {
            continue;
        };

        let entry = by_path.entry(path.to_string()).or_default();
        entry.0 += end.saturating_sub(start);
        for (i, c) in ['r', 'w', 'x'].iter().enumerate() {
            entry.1[i] |= perms.chars().nth(i) == Some(*c);
        }
    }

    by_path
        .into_iter()
        .map(|(path, (size, [r, w, x]))| MappedFile {
            path,
            size,
            perms: format!(
                "{}{}{}",
                if r { 'r' } else { '-' },
                if w { 'w' } else { '-' },
                if x { 'x' } else { '-' }
            ),
        })
        .collect()
}

/// One line of `/proc/<pid>/maps`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    pub start: u64,
    pub end: u64,
    /// e.g. `rw-p`
    pub perms: String,
    /// backing file, or `[heap]`, `[stack]`, …; empty for anonymous memory
    pub path: String,
}

impl Mapping {
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub fn readable(&self) -> bool {
        self.perms.starts_with('r')
    }

    pub fn writable(&self) -> bool {
        self.perms.chars().nth(1) == Some('w')
    }
}

/// Parses every mapping of `/proc/<pid>/maps`, anonymous ones included.
#[must_use]
pub fn parse_mappings(maps: &str) -> Vec<Mapping> {
    maps.lines()
        .filter_map(|line| {
            // address perms offset dev inode [path]
            let mut parts = line.splitn(6, char::is_whitespace);
            let range = parts.next()?;
            let perms = parts.next()?;
            let (start, end) = range.split_once('-')?;
            let path = line
                .splitn(6, char::is_whitespace)
                .nth(5)
                .map(str::trim)
                .unwrap_or_default();
            Some(Mapping {
                start: u64::from_str_radix(start, 16).ok()?,
                end: u64::from_str_radix(end, 16).ok()?,
                perms: perms.to_string(),
                path: path.to_string(),
            })
        })
        .collect()
}

pub fn read_mappings(pid: libc::pid_t) -> Result<Vec<Mapping>> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .with_context(|| format!("can't read maps of {pid}"))?;
    Ok(parse_mappings(&maps))
}

pub fn read_mapped_files(pid: libc::pid_t) -> Result<Vec<MappedFile>> {
    let maps = std::fs::read_to_string(format!("/proc/{pid}/maps"))
        .with_context(|| format!("can't read maps of {pid}"))?;
    Ok(parse_maps(&maps))
}

// -------------------------------------------------------------- open files

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FdKind {
    File,
    Socket,
    Pipe,
    /// eventfd, epoll, timerfd, …
    AnonInode,
    Other,
}

/// Open file descriptor of a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenFile {
    pub fd: u32,
    pub kind: FdKind,
    /// path, or a description such as `socket:[1234]`
    pub target: String,
    /// inode number for sockets and pipes
    pub inode: Option<u64>,
}

#[must_use]
pub fn classify_fd_target(target: &str) -> (FdKind, Option<u64>) {
    let inode = |prefix: &str| {
        target
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix(']'))
            .and_then(|number| number.parse().ok())
    };

    if target.starts_with('/') {
        (FdKind::File, None)
    } else if let Some(inode) = inode("socket:[") {
        (FdKind::Socket, Some(inode))
    } else if let Some(inode) = inode("pipe:[") {
        (FdKind::Pipe, Some(inode))
    } else if target.starts_with("anon_inode:") {
        (FdKind::AnonInode, None)
    } else {
        (FdKind::Other, None)
    }
}

pub fn read_open_files(pid: libc::pid_t) -> Result<Vec<OpenFile>> {
    let mut files: Vec<OpenFile> = std::fs::read_dir(format!("/proc/{pid}/fd"))
        .with_context(|| format!("can't list file descriptors of {pid}"))?
        .flatten()
        .filter_map(|entry| {
            let fd: u32 = entry.file_name().to_str()?.parse().ok()?;
            let target: PathBuf = std::fs::read_link(entry.path()).ok()?;
            let target = target.to_string_lossy().to_string();
            let (kind, inode) = classify_fd_target(&target);
            Some(OpenFile {
                fd,
                kind,
                target,
                inode,
            })
        })
        .collect();
    files.sort_by_key(|file| file.fd);
    Ok(files)
}

// ----------------------------------------------------------------- sockets

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketEntry {
    pub protocol: &'static str,
    pub local: String,
    pub remote: String,
    pub state: &'static str,
    pub inode: u64,
}

fn parse_hex_v4(hex: &str) -> Option<Ipv4Addr> {
    // the kernel prints the address as a native-endian (little endian) u32
    u32::from_str_radix(hex, 16)
        .ok()
        .map(|value| Ipv4Addr::from(value.swap_bytes()))
}

fn parse_hex_v6(hex: &str) -> Option<Ipv6Addr> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    // four words, each printed as native-endian u32
    for word in 0..4 {
        let value = u32::from_str_radix(&hex[word * 8..word * 8 + 8], 16).ok()?;
        bytes[word * 4..word * 4 + 4].copy_from_slice(&value.swap_bytes().to_be_bytes());
    }
    Some(Ipv6Addr::from(bytes))
}

fn parse_endpoint(endpoint: &str, ipv6: bool) -> Option<String> {
    let (address, port) = endpoint.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    Some(if ipv6 {
        format!("[{}]:{port}", parse_hex_v6(address)?)
    } else {
        format!("{}:{port}", parse_hex_v4(address)?)
    })
}

/// TCP state names as defined in `include/net/tcp_states.h`
#[must_use]
pub fn tcp_state_name(code: &str) -> &'static str {
    match code {
        "01" => "ESTABLISHED",
        "02" => "SYN_SENT",
        "03" => "SYN_RECV",
        "04" => "FIN_WAIT1",
        "05" => "FIN_WAIT2",
        "06" => "TIME_WAIT",
        "07" => "CLOSE",
        "08" => "CLOSE_WAIT",
        "09" => "LAST_ACK",
        "0A" => "LISTEN",
        "0B" => "CLOSING",
        "0C" => "NEW_SYN_RECV",
        _ => "UNKNOWN",
    }
}

/// Parses one of `/proc/net/{tcp,tcp6,udp,udp6}`.
#[must_use]
pub fn parse_net(content: &str, protocol: &'static str, ipv6: bool) -> Vec<SocketEntry> {
    let is_tcp = protocol.starts_with("TCP");

    content
        .lines()
        .skip(1) // header
        .filter_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            // sl local rem st tx:rx tr:when retrnsmt uid timeout inode
            let local = parse_endpoint(fields.get(1)?, ipv6)?;
            let remote = parse_endpoint(fields.get(2)?, ipv6)?;
            let state_code = fields.get(3)?;
            let inode: u64 = fields.get(9)?.parse().ok()?;
            Some(SocketEntry {
                protocol,
                local,
                remote,
                state: if is_tcp {
                    tcp_state_name(state_code)
                } else if *state_code == "07" {
                    // unconnected UDP sockets are reported as TCP_CLOSE
                    "-"
                } else {
                    "ESTABLISHED"
                },
                inode,
            })
        })
        .collect()
}

/// Returns the TCP and UDP sockets of a process.
pub fn read_sockets(pid: libc::pid_t) -> Result<Vec<SocketEntry>> {
    let inodes: HashSet<u64> = read_open_files(pid)?
        .into_iter()
        .filter(|file| file.kind == FdKind::Socket)
        .filter_map(|file| file.inode)
        .collect();

    let mut sockets = Vec::new();
    for (file, protocol, ipv6) in [
        ("tcp", "TCP", false),
        ("tcp6", "TCP6", true),
        ("udp", "UDP", false),
        ("udp6", "UDP6", true),
    ] {
        // using the process' own view of the network namespace
        if let Ok(content) = std::fs::read_to_string(format!("/proc/{pid}/net/{file}")) {
            sockets.extend(
                parse_net(&content, protocol, ipv6)
                    .into_iter()
                    .filter(|socket| inodes.contains(&socket.inode)),
            );
        }
    }
    Ok(sockets)
}

// ----------------------------------------------------------------- threads

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreadEntry {
    pub tid: libc::pid_t,
    pub name: String,
    pub state: char,
    /// user + system CPU time in clock ticks
    pub cpu_ticks: u64,
    /// nice value
    pub priority: i64,
}

/// Parses `/proc/<pid>/task/<tid>/stat`.
#[must_use]
pub fn parse_thread_stat(stat: &str) -> Option<ThreadEntry> {
    let open = stat.find('(')?;
    let close = stat.rfind(')')?;
    let tid = stat[..open].trim().parse().ok()?;
    let name = stat[open + 1..close].to_string();
    let rest: Vec<&str> = stat[close + 1..].split_whitespace().collect();
    // rest[0] = state (field 3), utime = field 14, stime = field 15, nice = field 19
    Some(ThreadEntry {
        tid,
        name,
        state: rest.first()?.chars().next()?,
        cpu_ticks: rest.get(11)?.parse::<u64>().ok()? + rest.get(12)?.parse::<u64>().ok()?,
        priority: rest.get(16)?.parse().ok()?,
    })
}

pub fn read_threads(pid: libc::pid_t) -> Result<Vec<ThreadEntry>> {
    let mut threads: Vec<ThreadEntry> = std::fs::read_dir(format!("/proc/{pid}/task"))
        .with_context(|| format!("can't list threads of {pid}"))?
        .flatten()
        .filter_map(|entry| {
            let stat = std::fs::read_to_string(entry.path().join("stat")).ok()?;
            parse_thread_stat(&stat)
        })
        .collect();
    threads.sort_by_key(|thread| thread.tid);
    Ok(threads)
}

// ------------------------------------------------------------- environment

/// Parses `/proc/<pid>/environ` into `(name, value)` pairs.
#[must_use]
pub fn parse_environ(environ: &[u8]) -> Vec<(String, String)> {
    environ
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let entry = String::from_utf8_lossy(entry);
            match entry.split_once('=') {
                Some((name, value)) => (name.to_string(), value.to_string()),
                None => (entry.to_string(), String::new()),
            }
        })
        .collect()
}

pub fn read_environment(pid: libc::pid_t) -> Result<Vec<(String, String)>> {
    let environ = std::fs::read(format!("/proc/{pid}/environ"))
        .with_context(|| format!("can't read environment of {pid}"))?;
    Ok(parse_environ(&environ))
}

// ---------------------------------------------------------------- security

const CAPABILITIES: [&str; 41] = [
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
    "CAP_AUDIT_WRITE",
    "CAP_AUDIT_CONTROL",
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
    "CAP_SYSLOG",
    "CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND",
    "CAP_AUDIT_READ",
    "CAP_PERFMON",
    "CAP_BPF",
    "CAP_CHECKPOINT_RESTORE",
];

/// Decodes a capability bit mask (as hexadecimal string) into names.
#[must_use]
pub fn decode_capabilities(hex: &str) -> Vec<String> {
    let Ok(mask) = u64::from_str_radix(hex.trim(), 16) else {
        return Vec::new();
    };
    (0..64)
        .filter(|bit| mask & (1 << bit) != 0)
        .map(|bit| {
            CAPABILITIES
                .get(bit)
                .map_or_else(|| format!("CAP_{bit}"), |name| (*name).to_string())
        })
        .collect()
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecurityInfo {
    /// real, effective, saved and filesystem user IDs
    pub uids: Vec<u32>,
    pub gids: Vec<u32>,
    pub groups: Vec<u32>,
    pub capabilities_effective: Vec<String>,
    pub capabilities_permitted: Vec<String>,
    pub no_new_privs: Option<bool>,
    /// `disabled`, `strict` or `filter`
    pub seccomp: Option<&'static str>,
    /// SELinux / AppArmor context from `/proc/<pid>/attr/current`
    pub lsm_context: Option<String>,
}

/// Parses `/proc/<pid>/status` (the LSM context is read separately).
#[must_use]
pub fn parse_security(status: &str) -> SecurityInfo {
    let mut info = SecurityInfo::default();
    let numbers = |value: &str| -> Vec<u32> {
        value
            .split_whitespace()
            .filter_map(|number| number.parse().ok())
            .collect()
    };

    for line in status.lines() {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key {
            "Uid" => info.uids = numbers(value),
            "Gid" => info.gids = numbers(value),
            "Groups" => info.groups = numbers(value),
            "CapEff" => info.capabilities_effective = decode_capabilities(value),
            "CapPrm" => info.capabilities_permitted = decode_capabilities(value),
            "NoNewPrivs" => info.no_new_privs = Some(value == "1"),
            "Seccomp" => {
                info.seccomp = match value {
                    "0" => Some("disabled"),
                    "1" => Some("strict"),
                    "2" => Some("filter"),
                    _ => None,
                }
            }
            _ => {}
        }
    }

    info
}

pub fn read_security(pid: libc::pid_t) -> Result<SecurityInfo> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .with_context(|| format!("can't read status of {pid}"))?;
    let mut info = parse_security(&status);
    info.lsm_context = std::fs::read_to_string(format!("/proc/{pid}/attr/current"))
        .ok()
        .map(|context| context.trim_end_matches(['\0', '\n']).to_string())
        .filter(|context| !context.is_empty());
    Ok(info)
}

// -------------------------------------------------------------------- find

/// A file, library or socket of some process matching a search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindMatch {
    pub pid: libc::pid_t,
    pub kind: FindKind,
    pub target: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindKind {
    Library,
    File,
}

/// Case-insensitive substring match of `needle` against the libraries and
/// open files of a single process. Silently yields nothing for processes that
/// can't be inspected.
#[must_use]
pub fn find_in_process(pid: libc::pid_t, needle: &str) -> Vec<FindMatch> {
    let needle = needle.to_lowercase();
    let mut matches = Vec::new();

    if let Ok(libraries) = read_mapped_files(pid) {
        matches.extend(
            libraries
                .into_iter()
                .filter(|library| library.path.to_lowercase().contains(&needle))
                .map(|library| FindMatch {
                    pid,
                    kind: FindKind::Library,
                    target: library.path,
                }),
        );
    }
    if let Ok(files) = read_open_files(pid) {
        matches.extend(
            files
                .into_iter()
                .filter(|file| file.kind == FdKind::File)
                .filter(|file| file.target.to_lowercase().contains(&needle))
                .map(|file| FindMatch {
                    pid,
                    kind: FindKind::File,
                    target: file.target,
                }),
        );
    }

    matches
}

/// Searches all processes, see [`find_in_process`].
#[must_use]
pub fn find_all(needle: &str) -> Vec<FindMatch> {
    if needle.trim().is_empty() {
        return Vec::new();
    }
    let mut pids: Vec<libc::pid_t> = std::fs::read_dir("/proc")
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
        .collect();
    pids.sort_unstable();
    pids.into_iter()
        .flat_map(|pid| find_in_process(pid, needle.trim()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_own_executable_and_open_file() {
        let pid = std::process::id() as libc::pid_t;
        let exe = std::fs::read_link("/proc/self/exe").unwrap();
        let name = exe.file_name().unwrap().to_string_lossy().to_string();

        let matches = find_in_process(pid, &name.to_uppercase());
        assert!(
            matches
                .iter()
                .any(|m| m.kind == FindKind::Library && m.target.contains(&name)),
            "{matches:?}"
        );

        let path = std::env::temp_dir().join(format!("res-find-test-{pid}"));
        let _file = std::fs::File::create(&path).unwrap();
        let matches = find_in_process(pid, &format!("res-find-test-{pid}"));
        std::fs::remove_file(&path).ok();
        assert!(
            matches.iter().any(|m| m.kind == FindKind::File),
            "{matches:?}"
        );

        assert!(find_all("   ").is_empty());
        assert!(find_all(&format!("res-find-test-{pid}-nonexistent")).is_empty());
    }

    #[test]
    fn maps_merge_by_path_and_skip_anonymous() {
        let maps = "\
55d0c8a00000-55d0c8a21000 r--p 00000000 08:01 1234 /usr/bin/foo
55d0c8a21000-55d0c8a50000 r-xp 00021000 08:01 1234 /usr/bin/foo
55d0c9a00000-55d0c9a21000 rw-p 00000000 00:00 0 [heap]
7f0000000000-7f0000001000 rw-p 00000000 00:00 0
7f1000000000-7f1000002000 r-xp 00000000 08:01 99 /usr/lib/libbar.so.1 (deleted)
";
        let files = parse_maps(maps);
        assert_eq!(files.len(), 2);
        assert_eq!(files[0].path, "/usr/bin/foo");
        assert_eq!(files[0].size, 0x21000 + 0x2f000);
        assert_eq!(files[0].perms, "r-x");
        assert_eq!(files[1].path, "/usr/lib/libbar.so.1 (deleted)");
        assert_eq!(files[1].size, 0x2000);
    }

    #[test]
    fn parses_raw_mappings() {
        let maps = "\
55d0c8a00000-55d0c8a21000 r--p 00000000 08:01 1234 /usr/bin/foo
55d0c9a00000-55d0c9a21000 rw-p 00000000 00:00 0 [heap]
7f0000000000-7f0000001000 rw-p 00000000 00:00 0
garbage line
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 [vsyscall]
";
        let mappings = parse_mappings(maps);
        assert_eq!(mappings.len(), 4);
        assert_eq!(mappings[0].path, "/usr/bin/foo");
        assert!(mappings[0].readable() && !mappings[0].writable());
        assert_eq!(mappings[1].path, "[heap]");
        assert!(mappings[1].writable());
        assert_eq!(mappings[2].path, "");
        assert_eq!(mappings[2].size(), 0x1000);
        assert!(!mappings[3].readable());
    }

    #[test]
    fn paths_with_spaces_survive() {
        let maps = "7f1000000000-7f1000001000 r--p 00000000 08:01 99 /opt/My App/lib.so\n";
        assert_eq!(parse_maps(maps)[0].path, "/opt/My App/lib.so");
    }

    #[test]
    fn classifies_fd_targets() {
        assert_eq!(classify_fd_target("/etc/passwd"), (FdKind::File, None));
        assert_eq!(
            classify_fd_target("socket:[4242]"),
            (FdKind::Socket, Some(4242))
        );
        assert_eq!(classify_fd_target("pipe:[7]"), (FdKind::Pipe, Some(7)));
        assert_eq!(
            classify_fd_target("anon_inode:[eventpoll]"),
            (FdKind::AnonInode, None)
        );
        assert_eq!(classify_fd_target("weird"), (FdKind::Other, None));
    }

    #[test]
    fn parses_ipv4_tcp() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 4242 1 0000000000000000 100 0 0 10 0\n   1: 0100007F:C350 0100007F:0050 01 00000000:00000000 00:00000000 00000000  1000        0 4343 1 0000000000000000 20 4 30 10 -1\n";
        let sockets = parse_net(content, "TCP", false);
        assert_eq!(sockets.len(), 2);
        assert_eq!(sockets[0].local, "127.0.0.1:80");
        assert_eq!(sockets[0].remote, "0.0.0.0:0");
        assert_eq!(sockets[0].state, "LISTEN");
        assert_eq!(sockets[0].inode, 4242);
        assert_eq!(sockets[1].local, "127.0.0.1:50000");
        assert_eq!(sockets[1].state, "ESTABLISHED");
    }

    #[test]
    fn parses_ipv6() {
        // ::1 is 00000000 00000000 00000000 01000000
        let content = "header\n   0: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 555 1\n";
        let sockets = parse_net(content, "TCP6", true);
        assert_eq!(sockets[0].local, "[::1]:22");
        assert_eq!(sockets[0].remote, "[::]:0");
    }

    #[test]
    fn udp_state() {
        let content = "header\n   0: 0100007F:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 9 2\n";
        assert_eq!(parse_net(content, "UDP", false)[0].state, "-");
    }

    #[test]
    fn garbage_lines_are_skipped() {
        assert!(parse_net("header\nnot a real line\n", "TCP", false).is_empty());
    }

    #[test]
    fn parses_thread_stat_with_odd_names() {
        let stat = "4321 (my (odd) thread) S 1 4321 4321 0 -1 4194560 10 0 0 0 7 3 0 0 20 -5 1 0 5555 1000 100 0";
        let thread = parse_thread_stat(stat).unwrap();
        assert_eq!(thread.tid, 4321);
        assert_eq!(thread.name, "my (odd) thread");
        assert_eq!(thread.state, 'S');
        assert_eq!(thread.cpu_ticks, 10);
        assert_eq!(thread.priority, -5);
    }

    #[test]
    fn parses_environ() {
        let env = parse_environ(b"HOME=/root\0EMPTY=\0NOEQUALS\0\0A=b=c\0");
        assert_eq!(
            env,
            vec![
                ("HOME".into(), "/root".into()),
                ("EMPTY".into(), String::new()),
                ("NOEQUALS".into(), String::new()),
                ("A".into(), "b=c".into()),
            ]
        );
    }

    #[test]
    fn decodes_capabilities() {
        assert!(decode_capabilities("0000000000000000").is_empty());
        assert_eq!(
            decode_capabilities("0000000000000023"),
            vec!["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_KILL"]
        );
        // bit 63 has no name
        assert_eq!(decode_capabilities("8000000000000000"), vec!["CAP_63"]);
        assert!(decode_capabilities("zz").is_empty());
    }

    #[test]
    fn parses_security() {
        let status = "Name:\tfoo\nUid:\t1000\t1000\t1000\t1000\nGid:\t100\t100\t100\t100\nGroups:\t100 27 \nCapEff:\t0000000000000400\nCapPrm:\t0000000000000400\nNoNewPrivs:\t1\nSeccomp:\t2\n";
        let info = parse_security(status);
        assert_eq!(info.uids, vec![1000; 4]);
        assert_eq!(info.groups, vec![100, 27]);
        assert_eq!(info.capabilities_effective, vec!["CAP_NET_BIND_SERVICE"]);
        assert_eq!(info.no_new_privs, Some(true));
        assert_eq!(info.seccomp, Some("filter"));
    }

    #[test]
    fn reads_own_process() {
        let pid = std::process::id() as libc::pid_t;
        assert!(!read_threads(pid).unwrap().is_empty());
        assert!(read_environment(pid).is_ok());
        assert!(read_open_files(pid).unwrap().iter().any(|f| f.fd == 0));
        assert!(
            read_mapped_files(pid)
                .unwrap()
                .iter()
                .any(|file| file.perms.contains('x'))
        );
        assert!(read_security(pid).unwrap().uids.len() == 4);
        assert!(read_sockets(pid).is_ok());
    }
}
