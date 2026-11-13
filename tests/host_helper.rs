//! Tests the path used inside Flatpak, where process details are asked from
//! the `resources-processes` helper instead of being read directly: the
//! helper binary is run for real (it is built together with the tests) and
//! its answers are compared with direct reads.

use std::process::Command;

use process_data::details;
use resources::utils::host_proc;

const HELPER: &str = env!("CARGO_BIN_EXE_resources-processes");

fn own_pid() -> libc::pid_t {
    std::process::id() as libc::pid_t
}

/// The helper binary itself, with its answer as JSON.
fn helper_json(args: &[&str]) -> serde_json::Value {
    let output = Command::new(HELPER).args(args).output().unwrap();
    assert!(output.status.success(), "{args:?}: {}", output.status);
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn helper_binary_answers_queries_as_json() {
    let pid = own_pid().to_string();

    let libraries = helper_json(&["--query", "libraries", "--pid", &pid]);
    assert!(
        libraries["Ok"]
            .as_array()
            .is_some_and(|libs| !libs.is_empty())
    );

    let security = helper_json(&["--query", "security", "--pid", &pid]);
    assert_eq!(security["Ok"]["uids"].as_array().unwrap().len(), 4);

    // a missing pid and a dead process are errors in the answer, not crashes
    let missing = helper_json(&["--query", "libraries"]);
    assert!(missing["Err"].as_str().unwrap().contains("--pid"));
    let dead = helper_json(&["--query", "threads", "--pid", &i32::MAX.to_string()]);
    assert!(dead["Err"].is_string());
}

// One test function for everything that goes through `host_proc`, because it
// switches the process-wide environment over to the helper.
#[test]
fn host_proc_through_the_helper_matches_direct_reads() {
    // SAFETY: this is the only test of this binary that touches the
    // environment, and it does so before anything reads it.
    unsafe {
        std::env::set_var(resources::devices::process::HELPER_PATH_ENV, HELPER);
        std::env::set_var(host_proc::FORCE_HELPER_ENV, "1");
    }
    assert!(host_proc::via_helper());
    let pid = own_pid();

    // data that doesn't change while we look at it
    assert_eq!(
        host_proc::mapped_files(pid).unwrap(),
        details::read_mapped_files(pid).unwrap()
    );
    assert_eq!(
        host_proc::executable(pid).unwrap(),
        details::read_executable_info(pid).unwrap()
    );
    assert_eq!(
        host_proc::environment(pid).unwrap(),
        details::read_environment(pid).unwrap()
    );
    assert_eq!(
        host_proc::security(pid).unwrap().uids,
        details::read_security(pid).unwrap().uids
    );
    assert_eq!(
        host_proc::mappings(pid).unwrap().first().map(|m| m.start),
        details::read_mappings(pid)
            .unwrap()
            .first()
            .map(|m| m.start)
    );

    // data that does (the helper's own pipes show up in our file descriptors)
    let files = host_proc::open_files(pid).unwrap();
    assert!(files.iter().any(|file| file.fd == 0));
    let threads = host_proc::threads(pid).unwrap();
    assert!(threads.iter().any(|thread| thread.tid == pid));
    assert!(host_proc::sockets(pid).is_ok());

    // errors arrive with their message
    let error = host_proc::mapped_files(i32::MAX).unwrap_err().to_string();
    assert!(error.contains("can't read maps"), "{error}");

    // searching all processes finds a file we hold open
    let path = std::env::temp_dir().join(format!("res-helper-find-{pid}"));
    let _open = std::fs::File::create(&path).unwrap();
    let matches = host_proc::find_all(&format!("res-helper-find-{pid}"));
    std::fs::remove_file(&path).ok();
    assert!(
        matches
            .iter()
            .any(|found| found.pid == pid && found.kind == details::FindKind::File),
        "{matches:?}"
    );
}
