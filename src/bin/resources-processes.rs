use anyhow::Result;
use log::{debug, info, trace};
use process_data::{ProcessData, PssMode};
use ron::ser::PrettyConfig;
use std::{
    collections::{HashMap, HashSet},
    io::{Read, Write},
    path::PathBuf,
    time::Instant,
};

use clap::{Parser, ValueEnum};
use process_data::details;
use serde::Serialize;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Output once and then exit
    #[arg(short, long, default_value_t = false)]
    once: bool,

    /// Use Rusty Object Notation (use this only for debugging this binary on its own, Resources won't be able to decode RON)
    #[arg(short, long, default_value_t = false)]
    ron: bool,

    /// How/If to read PSS memory statistics
    #[arg(value_enum, short, long, default_value_t = PssMode::Disabled)]
    pss: PssMode,

    /// Answer a single question about one process (or, for `find`, about all
    /// of them) as JSON, then exit. Used by Resources to look at processes
    /// that its sandbox can't see.
    #[arg(long, value_enum)]
    query: Option<Query>,

    /// Process the query is about
    #[arg(long)]
    pid: Option<libc::pid_t>,

    /// Text to search for with `--query find`
    #[arg(long)]
    needle: Option<String>,
}

/// What can be asked with `--query`, see `process_data::details`.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum Query {
    /// Mapped files (libraries)
    Libraries,
    /// All memory mappings
    Mappings,
    /// Open file descriptors
    Files,
    /// TCP and UDP sockets
    Sockets,
    Threads,
    Environment,
    Security,
    /// Executable path and SHA-256
    Executable,
    /// Open files and libraries of all processes matching `--needle`
    Find,
}

/// Serializes the answer as `{"Ok": …}` or `{"Err": "message"}`.
fn reply<T: Serialize>(result: Result<T>) -> Result<()> {
    let result: std::result::Result<T, String> = result.map_err(|error| format!("{error:#}"));
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, &result)?;
    stdout.flush()?;
    Ok(())
}

fn answer(query: Query, pid: Option<libc::pid_t>, needle: Option<String>) -> Result<()> {
    if let Query::Find = query {
        return reply(Ok(details::find_all(&needle.unwrap_or_default())));
    }

    let Some(pid) = pid else {
        return reply::<()>(Err(anyhow::anyhow!("--pid is required for this query")));
    };
    match query {
        Query::Libraries => reply(details::read_mapped_files(pid)),
        Query::Mappings => reply(details::read_mappings(pid)),
        Query::Files => reply(details::read_open_files(pid)),
        Query::Sockets => reply(details::read_sockets(pid)),
        Query::Threads => reply(details::read_threads(pid)),
        Query::Environment => reply(details::read_environment(pid)),
        Query::Security => reply(details::read_security(pid)),
        Query::Executable => reply(details::read_executable_info(pid)),
        Query::Find => unreachable!("handled above"),
    }
}

fn main() -> Result<()> {
    // Initialize logger
    pretty_env_logger::init();

    info!("Starting resources-processes…");

    debug!("Parsing arguments…");
    let args = Args::parse();

    if let Some(query) = args.query {
        return answer(query, args.pid, args.needle);
    }

    let mut non_gpu_fdinfos = HashSet::new();
    let mut non_npu_fdinfos = HashSet::new();
    let mut symlink_cache = HashMap::new();

    if args.once {
        output(
            args.ron,
            args.pss,
            &mut non_gpu_fdinfos,
            &mut non_npu_fdinfos,
            &mut symlink_cache,
        )?;
        return Ok(());
    }

    debug!("Ready");

    loop {
        let mut buffer = [0; 1];

        std::io::stdin().read_exact(&mut buffer)?;
        trace!("Received character, initiating scan…");

        output(
            args.ron,
            args.pss,
            &mut non_gpu_fdinfos,
            &mut non_npu_fdinfos,
            &mut symlink_cache,
        )?;
    }
}

fn output(
    ron: bool,
    pss: PssMode,
    non_gpu_fdinfos: &mut HashSet<(libc::pid_t, usize)>,
    non_npu_fdinfos: &mut HashSet<(libc::pid_t, usize)>,
    symlink_cache: &mut HashMap<(libc::pid_t, usize), PathBuf>,
) -> Result<()> {
    let start = Instant::now();

    trace!("Gathering process data…");
    let data = ProcessData::all_process_data(non_gpu_fdinfos, non_npu_fdinfos, symlink_cache, pss)?;

    let elapsed = start.elapsed();
    trace!(
        "Gathered data for {} processes within {elapsed:.2?}",
        data.len()
    );

    let encoded = if ron {
        trace!("Encoding process data using ron (Resources will not be able to read this!)…");
        ron::ser::to_string_pretty(&data, PrettyConfig::default())?
            .as_bytes()
            .to_vec()
    } else {
        trace!("Encoding process data using rmp…");
        rmp_serde::to_vec(&data)?
    };

    let len_byte_array = encoded.len().to_le_bytes();

    trace!("Preparing stdout…");
    let stdout = std::io::stdout();
    let mut handle = stdout.lock();

    trace!("Sending content length ({})…", encoded.len());
    handle.write_all(&len_byte_array)?;

    trace!("Sending content…");
    handle.write_all(&encoded)?;

    trace!("Flushing…");
    handle.flush()?;
    Ok(())
}
