//! YARA scanning of processes using [YARA-X](https://virustotal.github.io/yara-x/).
//!
//! Rules are `.yar`/`.yara` files in a rules directory (by default
//! `<user data dir>/resources/yara`). Every file is compiled into its own
//! namespace, so rule names only have to be unique within a file, and a file
//! that fails to compile is reported without keeping the others from loading.
//!
//! A process is scanned by scanning the files it runs and has mapped
//! (executable and shared libraries). Process memory isn't scanned.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use process_data::details::Mapping;

use crate::utils::{host_proc, i18n::i18n};
use yara_x::{Compiler, Rules, Scanner, SourceCode};

/// Files bigger than this are not scanned
const MAX_FILE_SIZE: u64 = 256 * 1024 * 1024;
/// Maximum time a single file may take
const FILE_TIMEOUT: Duration = Duration::from_secs(30);
/// How deep rule files are searched for in the rules directory
const MAX_DEPTH: usize = 4;

/// Directory rules are loaded from.
pub fn rules_dir() -> PathBuf {
    gtk::glib::user_data_dir().join("resources").join("yara")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleError {
    pub file: PathBuf,
    pub message: String,
}

/// A compiled rule set. Cheap to clone and safe to send to other threads.
#[derive(Clone)]
pub struct RuleSet {
    rules: Arc<Rules>,
    /// Number of rule files that were compiled successfully
    pub files_loaded: usize,
    /// Number of rules in all successfully compiled files
    pub rule_count: usize,
    /// Files that failed to compile (or couldn't be read)
    pub errors: Vec<RuleError>,
}

impl std::fmt::Debug for RuleSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleSet")
            .field("files_loaded", &self.files_loaded)
            .field("rule_count", &self.rule_count)
            .field("errors", &self.errors)
            .finish()
    }
}

impl RuleSet {
    pub fn is_empty(&self) -> bool {
        self.rule_count == 0
    }
}

/// What a rule matched in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    File(PathBuf),
    /// A memory region of a process, e.g. `[heap]`
    Memory {
        start: u64,
        end: u64,
        description: String,
    },
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(path) => write!(f, "{}", path.display()),
            Self::Memory {
                start,
                end,
                description,
            } => write!(f, "[memory] {description} {start:#x}-{end:#x}"),
        }
    }
}

/// A rule that matched.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraMatch {
    pub rule: String,
    pub tags: Vec<String>,
    pub target: Target,
}

/// Result of scanning a process.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScanReport {
    pub matches: Vec<YaraMatch>,
    pub files_scanned: usize,
    /// Files that couldn't be read or scanned
    pub files_failed: usize,
    /// Files that were not scanned because they are too big or not regular files
    pub files_skipped: usize,
}

/// All `.yar`/`.yara` files below `dir`, sorted.
pub fn collect_rule_files(dir: &Path) -> Vec<PathBuf> {
    fn walk(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if file_type.is_dir() {
                if depth < MAX_DEPTH {
                    walk(&path, depth + 1, out);
                }
            } else if file_type.is_file()
                && path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| {
                        ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara")
                    })
            {
                out.push(path);
            }
        }
    }

    let mut files = Vec::new();
    walk(dir, 0, &mut files);
    files.sort();
    files
}

/// Compiles all rule files in `dir`. A missing directory yields an empty set.
pub fn load_rules(dir: &Path) -> RuleSet {
    let mut compiler = Compiler::new();
    let mut errors = Vec::new();
    let mut files_loaded = 0;

    for file in collect_rule_files(dir) {
        let source = match std::fs::read_to_string(&file) {
            Ok(source) => source,
            Err(error) => {
                errors.push(RuleError {
                    file,
                    message: error.to_string(),
                });
                continue;
            }
        };

        let namespace = file
            .strip_prefix(dir)
            .unwrap_or(&file)
            .to_string_lossy()
            .to_string();
        compiler.new_namespace(&namespace);

        match compiler.add_source(SourceCode::from(source.as_str()).with_origin(&namespace)) {
            Ok(_) => files_loaded += 1,
            Err(error) => errors.push(RuleError {
                file,
                message: error.to_string(),
            }),
        }
    }

    let rules = compiler.build();
    let rule_count = rules.iter().count();

    RuleSet {
        rules: Arc::new(rules),
        files_loaded,
        rule_count,
        errors,
    }
}

fn scan_one(scanner: &mut Scanner<'_>, path: &Path, into: &mut Vec<YaraMatch>) -> Result<()> {
    let results = scanner
        .scan_file(path)
        .with_context(|| format!("can't scan {}", path.display()))?;

    for rule in results.matching_rules() {
        into.push(YaraMatch {
            rule: rule.identifier().to_string(),
            tags: rule
                .tags()
                .map(|tag| tag.identifier().to_string())
                .collect(),
            target: Target::File(path.to_path_buf()),
        });
    }
    Ok(())
}

fn new_scanner(rules: &RuleSet) -> Scanner<'_> {
    let mut scanner = Scanner::new(&rules.rules);
    scanner.set_timeout(FILE_TIMEOUT);
    scanner
}

/// Scans a single file.
pub fn scan_file(rules: &RuleSet, path: &Path) -> Result<Vec<YaraMatch>> {
    let mut matches = Vec::new();
    scan_one(&mut new_scanner(rules), path, &mut matches)?;
    Ok(matches)
}

/// The files to scan for a process: the executable and everything mapped,
/// as `(path as the process sees it, path to open)`, deduplicated, plus the
/// number of candidates that had to be skipped.
fn process_files(pid: libc::pid_t) -> (Vec<(PathBuf, PathBuf)>, usize) {
    let mut wanted: BTreeSet<PathBuf> = BTreeSet::new();

    if let Ok(exe) = host_proc::executable(pid) {
        wanted.insert(PathBuf::from(exe.path));
    }
    if let Ok(mapped) = host_proc::mapped_files(pid) {
        wanted.extend(mapped.into_iter().map(|file| PathBuf::from(file.path)));
    }

    let mut files = Vec::new();
    let mut skipped = 0;
    for path in wanted {
        let Ok(relative) = path.strip_prefix("/") else {
            continue;
        };
        // through the process' root so that files of containers are found
        let via_root = PathBuf::from(format!("/proc/{pid}/root")).join(relative);
        // inside Flatpak the files of the host are below /run/host
        let candidates = [
            via_root,
            path.clone(),
            PathBuf::from("/run/host").join(relative),
        ];

        let existing = candidates.iter().find_map(|candidate| {
            std::fs::metadata(candidate)
                .ok()
                .map(|metadata| (candidate, metadata))
        });
        match existing {
            // deleted files can't be opened by name anymore, not worth counting
            None => {}
            Some((candidate, metadata))
                if metadata.is_file() && metadata.len() <= MAX_FILE_SIZE =>
            {
                files.push((path.clone(), candidate.clone()));
            }
            Some(_) => skipped += 1,
        }
    }
    (files, skipped)
}

/// Scans the executable and mapped libraries of a process.
pub fn scan_process(rules: &RuleSet, pid: libc::pid_t) -> ScanReport {
    let mut report = ScanReport::default();
    if rules.is_empty() {
        return report;
    }

    let (files, skipped) = process_files(pid);
    report.files_skipped = skipped;

    let mut scanner = new_scanner(rules);
    for (shown, openable) in files {
        let before = report.matches.len();
        match scan_one(&mut scanner, &openable, &mut report.matches) {
            Ok(()) => report.files_scanned += 1,
            Err(_) => report.files_failed += 1,
        }
        // report the path as the process sees it
        for found in &mut report.matches[before..] {
            found.target = Target::File(shown.clone());
        }
    }
    report
}

// ----------------------------------------------------------------- memory

/// Regions bigger than this are not scanned
const MAX_REGION_SIZE: u64 = 128 * 1024 * 1024;

/// Result of scanning the memory of a process.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemoryReport {
    pub matches: Vec<YaraMatch>,
    pub regions_scanned: usize,
    pub bytes_scanned: u64,
    /// Regions that couldn't be read (e.g. unmapped meanwhile)
    pub regions_failed: usize,
    /// Regions that are too big
    pub regions_skipped: usize,
    /// The memory of the process may not be read at all (needs the same user
    /// with ptrace allowed, or root)
    pub denied: bool,
}

/// Whether a mapping is worth scanning as memory. File-backed read-only
/// mappings are skipped because their content is what the file scan sees;
/// anonymous memory, heap, stack, shared memory and writable file mappings
/// (initialized data) are not.
pub fn is_scannable_region(region: &Mapping) -> bool {
    if !region.readable() || region.size() == 0 {
        return false;
    }
    let path = region.path.as_str();
    match path {
        "" => true,
        // kernel provided, can't be read like normal memory
        "[vvar]" | "[vvar_vclock]" | "[vsyscall]" | "[uprobes]" => false,
        _ if path.starts_with('[') => true,
        _ if path.starts_with("/memfd:") || path.starts_with("/SYSV") => true,
        // devices (e.g. GPU memory) can have side effects when read
        _ if path.starts_with("/dev/") && !path.starts_with("/dev/shm/") => false,
        _ => region.writable(),
    }
}

fn describe_region(region: &Mapping) -> String {
    let kind = if region.path.is_empty() {
        "anonymous".to_string()
    } else {
        region.path.clone()
    };
    format!("{kind} {}", region.perms)
}

/// Reads up to `len` bytes at `offset`, stopping early at the first error.
fn read_region(mem: &std::fs::File, offset: u64, len: usize) -> Result<Vec<u8>, std::io::Error> {
    use std::os::unix::fs::FileExt;

    let mut buffer = vec![0u8; len];
    let mut filled = 0;
    while filled < len {
        match mem.read_at(&mut buffer[filled..], offset + filled as u64) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) if filled == 0 => return Err(error),
            Err(_) => break,
        }
    }
    buffer.truncate(filled);
    Ok(buffer)
}

/// Scans the memory of a process. Unlike files, memory can only be read when
/// the kernel allows tracing the process, which is the case for processes of
/// the same user if `ptrace_scope` is 0 (and for children), and for root.
///
/// A process can't scan itself: its own memory contains the compiled rules,
/// which would match themselves.
pub fn scan_process_memory(rules: &RuleSet, pid: libc::pid_t) -> Result<MemoryReport> {
    anyhow::ensure!(
        pid != std::process::id() as libc::pid_t,
        "a process can't scan its own memory, the rules in it would match themselves"
    );

    anyhow::ensure!(
        !host_proc::via_helper(),
        i18n("Scanning memory isn't possible from inside the Flatpak sandbox")
    );

    let mut report = MemoryReport::default();
    if rules.is_empty() {
        return Ok(report);
    }

    let regions = process_data::details::read_mappings(pid)?;
    let mem = match std::fs::File::open(format!("/proc/{pid}/mem")) {
        Ok(mem) => mem,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            report.denied = true;
            return Ok(report);
        }
        Err(error) => return Err(error).context("can't open the memory of the process"),
    };

    let mut scanner = new_scanner(rules);
    for region in regions.iter().filter(|region| is_scannable_region(region)) {
        if region.size() > MAX_REGION_SIZE {
            report.regions_skipped += 1;
            continue;
        }

        let data = match read_region(&mem, region.start, region.size() as usize) {
            Ok(data) if !data.is_empty() => data,
            Ok(_) | Err(_) => {
                report.regions_failed += 1;
                continue;
            }
        };

        match scanner.scan(&data) {
            Ok(results) => {
                report.regions_scanned += 1;
                report.bytes_scanned += data.len() as u64;
                for rule in results.matching_rules() {
                    report.matches.push(YaraMatch {
                        rule: rule.identifier().to_string(),
                        tags: rule
                            .tags()
                            .map(|tag| tag.identifier().to_string())
                            .collect(),
                        target: Target::Memory {
                            start: region.start,
                            end: region.end,
                            description: describe_region(region),
                        },
                    });
                }
            }
            Err(_) => report.regions_failed += 1,
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!("res-yara-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn write(&self, name: &str, content: &str) -> PathBuf {
            let path = self.0.join(name);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, content).unwrap();
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const NEEDLE_RULE: &str = r#"
        rule has_needle : suspicious test {
            strings: $a = "needle-in-haystack"
            condition: $a
        }
    "#;

    #[test]
    fn missing_directory_is_an_empty_set() {
        let set = load_rules(Path::new("/definitely/not/here"));
        assert!(set.is_empty());
        assert_eq!(set.files_loaded, 0);
        assert!(set.errors.is_empty());
    }

    #[test]
    fn collects_only_rule_files_recursively() {
        let dir = TempDir::new("collect");
        dir.write("a.yar", NEEDLE_RULE);
        dir.write("sub/b.YARA", NEEDLE_RULE);
        dir.write("c.txt", "not a rule");
        let files = collect_rule_files(&dir.0);
        assert_eq!(files.len(), 2);
        assert!(files[0].ends_with("a.yar"));
        assert!(files[1].ends_with("sub/b.YARA"));
    }

    #[test]
    fn matches_with_tags_and_namespaces_per_file() {
        let dir = TempDir::new("match");
        // the same rule name in two files must not clash
        dir.write("one.yar", NEEDLE_RULE);
        dir.write("two.yar", NEEDLE_RULE);
        let set = load_rules(&dir.0);
        assert_eq!(set.files_loaded, 2);
        assert_eq!(set.rule_count, 2);
        assert!(set.errors.is_empty());

        let target = dir.write("target.bin", "xx needle-in-haystack xx");
        let matches = scan_file(&set, &target).unwrap();
        assert_eq!(matches.len(), 2);
        assert!(matches.iter().all(|m| m.rule == "has_needle"));
        assert_eq!(matches[0].tags, vec!["suspicious", "test"]);
        assert_eq!(matches[0].target, Target::File(target));

        let clean = dir.write("clean.bin", "nothing to see");
        assert!(scan_file(&set, &clean).unwrap().is_empty());
    }

    #[test]
    fn broken_file_is_reported_but_others_still_load() {
        let dir = TempDir::new("broken");
        dir.write("good.yar", NEEDLE_RULE);
        dir.write("bad.yar", "rule broken { condition: undefined_identifier }");
        let set = load_rules(&dir.0);
        assert_eq!(set.files_loaded, 1);
        assert_eq!(set.rule_count, 1);
        assert_eq!(set.errors.len(), 1);
        assert!(set.errors[0].file.ends_with("bad.yar"));
        assert!(!set.errors[0].message.is_empty());

        let target = dir.write("t.bin", "needle-in-haystack");
        assert_eq!(scan_file(&set, &target).unwrap().len(), 1);
    }

    #[test]
    fn scanning_a_missing_file_is_an_error() {
        let dir = TempDir::new("missing");
        dir.write("r.yar", NEEDLE_RULE);
        let set = load_rules(&dir.0);
        assert!(scan_file(&set, Path::new("/no/such/file")).is_err());
    }

    #[test]
    fn scans_executable_and_libraries_of_a_process() {
        let dir = TempDir::new("process");
        // every ELF file
        dir.write("elf.yar", "rule elf { condition: uint32(0) == 0x464c457f }");
        let set = load_rules(&dir.0);
        assert_eq!(set.rule_count, 1);

        // a small program; the test binary itself can be too big to scan
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("can't start sleep");
        // wait until it has exec'd so its executable is the one we expect
        let exe = loop {
            let exe = std::fs::read_link(format!("/proc/{}/exe", child.id())).unwrap();
            if exe.file_name().is_some_and(|name| name == "sleep") {
                break exe;
            }
            std::thread::sleep(Duration::from_millis(10));
        };

        let report = scan_process(&set, child.id() as libc::pid_t);
        let _ = child.kill();
        let _ = child.wait();

        assert!(report.files_scanned >= 1, "{report:?}");
        assert!(
            report
                .matches
                .iter()
                .any(|m| m.rule == "elf" && m.target == Target::File(exe.clone())),
            "{report:?}"
        );
    }

    #[test]
    fn files_that_are_too_big_are_counted_as_skipped() {
        let dir = TempDir::new("skipped");
        dir.write("elf.yar", "rule elf { condition: uint32(0) == 0x464c457f }");
        let set = load_rules(&dir.0);
        let report = scan_process(&set, std::process::id() as libc::pid_t);
        // the test binary has debug info and a WebAssembly runtime in it and
        // may or may not be bigger than the limit; either way it must be
        // accounted for
        let own_exe_size = std::fs::metadata("/proc/self/exe").unwrap().len();
        if own_exe_size > MAX_FILE_SIZE {
            assert!(report.files_skipped >= 1, "{report:?}");
        } else {
            assert!(report.files_scanned >= 1, "{report:?}");
        }
    }

    #[test]
    fn empty_rule_set_scans_nothing() {
        let set = load_rules(Path::new("/definitely/not/here"));
        let report = scan_process(&set, std::process::id() as libc::pid_t);
        assert_eq!(report, ScanReport::default());
    }

    #[test]
    fn dead_process_yields_an_empty_report() {
        let dir = TempDir::new("dead");
        dir.write("elf.yar", "rule elf { condition: uint32(0) == 0x464c457f }");
        let set = load_rules(&dir.0);
        let report = scan_process(&set, i32::MAX);
        assert!(report.matches.is_empty());
        assert_eq!(report.files_scanned, 0);
    }

    fn region(perms: &str, path: &str) -> Mapping {
        Mapping {
            start: 0x1000,
            end: 0x3000,
            perms: perms.into(),
            path: path.into(),
        }
    }

    #[test]
    fn region_selection() {
        assert!(is_scannable_region(&region("rw-p", "")));
        assert!(is_scannable_region(&region("rw-p", "[heap]")));
        assert!(is_scannable_region(&region("rw-p", "[stack]")));
        assert!(is_scannable_region(&region("rw-s", "/memfd:foo (deleted)")));
        assert!(is_scannable_region(&region("rw-s", "/dev/shm/x")));
        // initialized data of a library, but not its read-only code
        assert!(is_scannable_region(&region("rw-p", "/usr/lib/libc.so.6")));
        assert!(!is_scannable_region(&region("r-xp", "/usr/lib/libc.so.6")));
        assert!(!is_scannable_region(&region("r--p", "/usr/lib/libc.so.6")));
        // not readable or special
        assert!(!is_scannable_region(&region("---p", "")));
        assert!(!is_scannable_region(&region("r--p", "[vvar]")));
        assert!(!is_scannable_region(&region("--xp", "[vsyscall]")));
        assert!(!is_scannable_region(&region("rw-s", "/dev/dri/card0")));
        let mut empty = region("rw-p", "");
        empty.end = empty.start;
        assert!(!is_scannable_region(&empty));
    }

    #[test]
    fn target_display() {
        assert_eq!(Target::File("/bin/ls".into()).to_string(), "/bin/ls");
        assert_eq!(
            Target::Memory {
                start: 0x1000,
                end: 0x2000,
                description: "[heap] rw-p".into()
            }
            .to_string(),
            "[memory] [heap] rw-p 0x1000-0x2000"
        );
    }

    #[test]
    fn finds_strings_in_the_memory_of_another_process() {
        let dir = TempDir::new("memory");
        dir.write(
            "mem.yar",
            r#"rule marker { strings: $a = "memory-marker-9f3b2c71" condition: $a }"#,
        );
        let set = load_rules(&dir.0);

        // the marker is in the environment of the child, which lives in its
        // stack memory
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .env("RES_YARA_TEST", "memory-marker-9f3b2c71")
            .spawn()
            .expect("can't start sleep");
        let pid = child.id() as libc::pid_t;
        // wait until it has exec'd
        while std::fs::read_link(format!("/proc/{pid}/exe"))
            .is_ok_and(|exe| exe.file_name().is_none_or(|name| name != "sleep"))
        {
            std::thread::sleep(Duration::from_millis(10));
        }

        let report = scan_process_memory(&set, pid);
        let _ = child.kill();
        let _ = child.wait();

        let report = report.unwrap();
        assert!(!report.denied, "{report:?}");
        assert!(report.regions_scanned >= 1, "{report:?}");
        assert!(report.bytes_scanned > 0);
        assert!(
            report
                .matches
                .iter()
                .any(|m| m.rule == "marker" && matches!(m.target, Target::Memory { .. })),
            "{report:?}"
        );
    }

    #[test]
    fn scanning_the_own_process_is_refused() {
        let dir = TempDir::new("self");
        dir.write("r.yar", NEEDLE_RULE);
        let set = load_rules(&dir.0);
        assert!(scan_process_memory(&set, std::process::id() as libc::pid_t).is_err());
    }

    #[test]
    fn empty_rules_and_dead_processes_are_fine() {
        let empty = load_rules(Path::new("/definitely/not/here"));
        assert_eq!(
            scan_process_memory(&empty, 1).unwrap(),
            MemoryReport::default()
        );

        let dir = TempDir::new("dead-memory");
        dir.write("r.yar", NEEDLE_RULE);
        let set = load_rules(&dir.0);
        assert!(scan_process_memory(&set, i32::MAX).is_err());
    }
}
