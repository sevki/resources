//! Access to `/proc/<pid>` details of processes (libraries, open files,
//! sockets, …).
//!
//! Natively these are read directly. Inside Flatpak the sandbox only sees
//! its own processes, so the same questions are put to the
//! `resources-processes` helper, which runs on the host (see
//! `devices::process::helper_command`) and answers them as JSON.
//!
//! Everything here blocks (for a helper query, for the time of spawning a
//! process) and should be called from a worker thread where that matters.

use std::process::Stdio;

use anyhow::{Context, Result};
use process_data::details::{
    self, ExecutableInfo, FindMatch, MappedFile, Mapping, OpenFile, SecurityInfo, SocketEntry,
    ThreadEntry,
};
use serde::de::DeserializeOwned;

use crate::devices::process::helper_command;

/// Set (to anything) to use the helper even outside of Flatpak, for testing.
pub const FORCE_HELPER_ENV: &str = "RESOURCES_PROC_VIA_HELPER";

/// Whether process details have to be asked from the helper.
pub fn via_helper() -> bool {
    // The unit tests read /proc directly wherever they run: the build
    // sandbox of Flatpak counts as Flatpak but has no helper to ask. The
    // helper path is tested by `tests/host_helper.rs`, which forces it.
    #[cfg(test)]
    {
        std::env::var_os(FORCE_HELPER_ENV).is_some()
    }
    #[cfg(not(test))]
    {
        *crate::utils::IS_FLATPAK || std::env::var_os(FORCE_HELPER_ENV).is_some()
    }
}

fn query<T: DeserializeOwned>(
    kind: &str,
    pid: Option<libc::pid_t>,
    needle: Option<&str>,
) -> Result<T> {
    let mut args = vec!["--query".to_string(), kind.to_string()];
    if let Some(pid) = pid {
        args.extend(["--pid".to_string(), pid.to_string()]);
    }
    if let Some(needle) = needle {
        args.extend(["--needle".to_string(), needle.to_string()]);
    }
    let args: Vec<&str> = args.iter().map(String::as_str).collect();

    let output = helper_command(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .context("can't run the resources-processes helper")?;
    anyhow::ensure!(
        output.status.success(),
        "the resources-processes helper failed ({})",
        output.status
    );

    let answer: Result<T, String> = serde_json::from_slice(&output.stdout)
        .context("the resources-processes helper gave an answer that can't be read")?;
    answer.map_err(anyhow::Error::msg)
}

macro_rules! details_fn {
    ($name:ident, $direct:path, $kind:literal, $ty:ty) => {
        pub fn $name(pid: libc::pid_t) -> Result<$ty> {
            if via_helper() {
                query($kind, Some(pid), None)
            } else {
                $direct(pid)
            }
        }
    };
}

details_fn!(
    mapped_files,
    details::read_mapped_files,
    "libraries",
    Vec<MappedFile>
);
details_fn!(mappings, details::read_mappings, "mappings", Vec<Mapping>);
details_fn!(open_files, details::read_open_files, "files", Vec<OpenFile>);
details_fn!(sockets, details::read_sockets, "sockets", Vec<SocketEntry>);
details_fn!(threads, details::read_threads, "threads", Vec<ThreadEntry>);
details_fn!(
    environment,
    details::read_environment,
    "environment",
    Vec<(String, String)>
);
details_fn!(security, details::read_security, "security", SecurityInfo);
details_fn!(
    executable,
    details::read_executable_info,
    "executable",
    ExecutableInfo
);

/// Searches all processes for open files and libraries matching `needle`.
pub fn find_all(needle: &str) -> Vec<FindMatch> {
    if via_helper() {
        query("find", None, Some(needle)).unwrap_or_default()
    } else {
        details::find_all(needle)
    }
}
