//! `ghost mcp`: an MCP server over stdio whose tools work on targets
//! through ghostd. An MCP client starts it (Claude Code: `claude mcp add
//! ghost -- ghost mcp`); stdout carries only the protocol and logs go to
//! stderr. Every tool takes a `target`; its result is structured content
//! and, as text, a one-line summary followed by the same result as JSON
//! (for clients that pass only the text on), and a failure is a tool error
//! in ghostd's or ssh's words.

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    fmt::Write as _,
    future::Future,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context as _, Result, anyhow, bail};
use clap::Args;
use ghostd_protocol::{
    v1::{ExecSpec, Outcome, Program, Request, Response, Stream},
    v2,
};
use rmcp::{
    ErrorData, Peer, RoleServer, ServerHandler, ServiceExt as _,
    handler::server::{common::schema_for_output, router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, ContentBlock, Implementation, ProgressNotificationParam, RequestMetaObject,
        ServerCapabilities, ServerConfig,
    },
    tool, tool_handler, tool_router,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::{
    StatusView,
    conn::{self, BULK_THRESHOLD, Pool},
    install::{self, Installed},
    ops::{self, Direction, JobView, LogOf, MAX_INLINE, StatView, SyncReport, Via},
    sessions::{self, MachineView, ScreenView, SessionView, WaitView},
    target::{Resolver, parse_target},
};
use crate::Cli;

/// The most text one result's text block carries: its summary and its
/// structured content as JSON. A tool cuts a target's output, a file or a
/// listing so that it fits ([`FIELD_CAP`]), and the result says how to get
/// the rest.
pub(crate) const TEXT_CAP: usize = 256 * 1024;

/// The most a result's text of a file or a log takes as JSON, so that the
/// text block, its summary and other fields with it, stays within
/// [`TEXT_CAP`].
pub(crate) const FIELD_CAP: usize = TEXT_CAP - 8 * 1024;

/// How many of the last bytes of each stream an exec result carries.
pub(crate) const EXEC_OUTPUT_CAP: u64 = 64 * 1024;

/// The most bytes a read or a log read asks for.
const MAX_READ: u32 = 1024 * 1024;

/// How often an install reports its progress.
const PROGRESS_INTERVAL: Duration = Duration::from_secs(10);

/// `ghost mcp` takes no arguments of its own.
#[derive(Args)]
pub(crate) struct McpArgs {}

/// Serves the tools on stdin and stdout until the client ends the session.
pub(crate) async fn serve(cli: &Cli, _args: &McpArgs) -> Result<()> {
    let cwd = std::env::current_dir().context("read the working directory")?;
    let resolver = Arc::new(Resolver::new(
        &cli.globals.api_url,
        cli.globals.seed_file.clone(),
        false,
    ));
    let server = GhostServer::new(resolver, cwd);
    let service = server
        .serve((tokio::io::stdin(), tokio::io::stdout()))
        .await
        .context("start the MCP session")?;
    service.waiting().await.context("serve the MCP session")?;
    Ok(())
}

/// The MCP server: its tools and the connection pools of the targets they
/// named.
#[derive(Clone)]
pub(crate) struct GhostServer {
    inner: Arc<Inner>,
    tool_router: ToolRouter<Self>,
}

struct Inner {
    resolver: Arc<Resolver>,
    pools: Mutex<HashMap<String, Arc<Pool>>>,
    cwd: PathBuf,
}

/// A successful result: the value as structured content, and as text the
/// summary and then the same value as JSON, as MCP advises for clients that
/// pass only the text on (they would otherwise never see a program's
/// output or a file's text).
fn done<T: Serialize>(summary: &str, value: &T) -> Result<CallToolResult, ErrorData> {
    let value = serde_json::to_value(value)
        .map_err(|error| ErrorData::internal_error(error.to_string(), None))?;
    let text = result_text(summary, &value);
    let mut result = CallToolResult::success(vec![ContentBlock::text(text)]);
    result.structured_content = Some(value);
    Ok(result)
}

/// What a cut text block ends with.
const CUT_NOTE: &str = "\n[cut at 256 KiB; the structured content holds the whole result, and offset, max_bytes, to_path or output_file get the rest]";

/// A result's text block: the summary, a line break, the value as JSON; cut
/// to [`TEXT_CAP`] with [`CUT_NOTE`] when it is longer (the tools cut
/// their payloads so that it seldom is).
pub(crate) fn result_text(summary: &str, value: &serde_json::Value) -> String {
    let mut text = String::with_capacity(summary.len() + 1);
    text.push_str(summary);
    text.push('\n');
    text.push_str(&value.to_string());
    if text.len() > TEXT_CAP {
        cap_text(&mut text, TEXT_CAP - CUT_NOTE.len());
        text.push_str(CUT_NOTE);
    }
    text
}

/// A tool's answer: a failure is a tool error with its message, never a
/// protocol error.
fn answer<T: Serialize>(result: Result<(String, T)>) -> Result<CallToolResult, ErrorData> {
    match result {
        Ok((summary, value)) => done(&summary, &value),
        Err(error) => Ok(CallToolResult::error(vec![ContentBlock::text(format!(
            "{error:#}"
        ))])),
    }
}

/// A tool's result with what ghost knows about the machine's identity.
#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct Checked<T> {
    #[serde(flatten)]
    result: T,
    /// Whether ghostd checked the machine's identity (its host ID) for this
    /// call: false for a ghostd older than 0.2.0, which cannot; absent when
    /// no connection was made.
    #[serde(skip_serializing_if = "Option::is_none")]
    host_check: Option<bool>,
    /// What ghost noticed on the way: a new host ID it learned for a
    /// reinstalled instance, a target that moved, a ghostd too old to check
    /// the machine's identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    notice: Option<String>,
}

tokio::task_local! {
    /// The pool the tool call that runs used (see [`GhostServer::respond`]).
    static USED: RefCell<Option<Arc<Pool>>>;
}

/// The bytes `value` takes as JSON, with the comma that follows it in a
/// list.
fn json_size<T: Serialize>(value: &T) -> usize {
    serde_json::to_string(value).map_or(0, |json| json.len() + 1)
}

fn size_text(bytes: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let value = bytes as f64;
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", value / 1024.0)
    } else {
        format!("{:.1} MiB", value / (1024.0 * 1024.0))
    }
}

/// The program fields `ghostd_exec` and `ghostd_job_start` share.
#[derive(Debug, Default, Deserialize, JsonSchema)]
pub(crate) struct ProgramInput {
    /// The program and its arguments, passed as they are without a shell
    /// (no quoting needed); argv[0] without a slash is looked up in PATH.
    /// Give exactly one of argv, script and `script_file`.
    #[serde(default)]
    argv: Option<Vec<String>>,
    /// A script's text, written to a file and run with `interpreter`
    /// (default: its #! line, else /bin/sh).
    #[serde(default)]
    script: Option<String>,
    /// A local script file (the user's own file, read as the user; relative
    /// to ghost mcp's working directory), run as `script` is.
    #[serde(default)]
    script_file: Option<String>,
    /// The script's interpreter and its arguments, such as `["bash", "-e"]`.
    #[serde(default)]
    interpreter: Option<Vec<String>>,
    /// The script's arguments.
    #[serde(default)]
    args: Vec<String>,
    /// Text for the program's stdin (default: none, /dev/null).
    #[serde(default)]
    stdin: Option<String>,
    /// A local file whose bytes are the program's stdin (up to 8 MiB).
    #[serde(default)]
    stdin_file: Option<String>,
    /// Variables to set.
    #[serde(default)]
    env: BTreeMap<String, String>,
    /// Variables to remove.
    #[serde(default)]
    unset: Vec<String>,
    /// The working directory on the target (default: the home directory;
    /// relative paths are relative to it).
    #[serde(default)]
    cwd: Option<String>,
    /// Run it through the user's login shell, for a PATH set in ~/.profile.
    #[serde(default)]
    login: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct ExecInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    #[serde(flatten)]
    program: ProgramInput,
    /// Stop it after this many seconds (default 120).
    #[serde(default)]
    timeout_seconds: Option<u64>,
    /// At the timeout, leave it running as a job (its `job_id` is in the
    /// result) instead of stopping it.
    #[serde(default)]
    keep_on_timeout: bool,
    /// A local file that gets the program's FULL stdout, read from the
    /// job's log (the result only carries the last 64 KiB).
    #[serde(default)]
    output_file: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
#[allow(clippy::struct_excessive_bools)] // the result's flags, as JSON
pub(crate) struct ExecOutput {
    /// The job the run was; its logs stay readable with `ghostd_job_logs`.
    job_id: String,
    exit_code: Option<i32>,
    signal: Option<i32>,
    timed_out: bool,
    /// It timed out and still runs as job `job_id`.
    still_running: bool,
    failed_to_start: Option<String>,
    /// The last 64 KiB of stdout, as text (lossy when not UTF-8).
    stdout: String,
    stdout_valid_utf8: bool,
    /// Where `stdout` starts in the whole stream; more than 0 means earlier
    /// bytes are in the job's log.
    stdout_offset: u64,
    stdout_total: u64,
    stderr: String,
    stderr_valid_utf8: bool,
    stderr_offset: u64,
    stderr_total: u64,
    /// Background processes it left that were stopped when it ended; start
    /// servers with `ghostd_job_start` instead.
    stopped: u32,
    duration_ms: u64,
    /// The local file that got all of stdout.
    output_file: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct JobStartInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    #[serde(flatten)]
    program: ProgramInput,
    /// Stop the job after this many seconds (default: never).
    #[serde(default)]
    timeout_seconds: Option<u64>,
    /// A name for the job, shown in `ghostd_job_list`.
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct JobStarted {
    job_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct TargetInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct JobListInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    /// Finished jobs too (default: only the ones not finished).
    #[serde(default)]
    include_finished: bool,
    /// At most this many, newest first (default 100).
    #[serde(default)]
    limit: Option<u32>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct JobList {
    jobs: Vec<JobView>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct JobInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    job_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct JobWaitInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    job_id: String,
    /// Wait at most this many seconds (at most 60, the default).
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum StreamInput {
    #[default]
    Stdout,
    Stderr,
}

impl From<StreamInput> for Stream {
    fn from(stream: StreamInput) -> Self {
        match stream {
            StreamInput::Stdout => Self::Stdout,
            StreamInput::Stderr => Self::Stderr,
        }
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct JobLogsInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    job_id: String,
    /// stdout (default) or stderr.
    #[serde(default)]
    stream: StreamInput,
    /// Read from this byte offset of the stream (default: the last
    /// `max_bytes`, the tail).
    #[serde(default)]
    offset: Option<u64>,
    /// At most this many bytes (default 64 KiB, at most 1 MiB; a result
    /// carries at most 256 KiB of text).
    #[serde(default)]
    max_bytes: Option<u32>,
    /// A local file that gets the whole stream the log still keeps instead
    /// (any size).
    #[serde(default)]
    to_path: Option<String>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub(crate) struct LogOutput {
    /// The bytes read, as text (lossy when not UTF-8); empty with `to_path`.
    text: String,
    valid_utf8: bool,
    /// The offset of the first byte read.
    offset: u64,
    /// Where to read on from.
    next_offset: u64,
    /// All bytes the stream produced so far.
    total: u64,
    /// The lowest offset the log still keeps (older bytes rotated away).
    first_available: u64,
    /// The job finished and `total` is final.
    ended: bool,
    /// More bytes follow `next_offset` than this result carries.
    truncated: bool,
    /// The local file that got the stream, and how many bytes.
    to_path: Option<String>,
    bytes_written: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct JobSignalInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    job_id: String,
    /// A signal name (TERM, INT, HUP, KILL, USR1, …) or number.
    signal: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct JobStopInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    job_id: String,
    /// Seconds between SIGTERM and SIGKILL.
    #[serde(default)]
    grace_seconds: Option<u64>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct Done {
    /// What was done.
    done: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct FileReadInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    /// The file on the target (relative to the home directory).
    path: String,
    /// Start at this byte (default 0).
    #[serde(default)]
    offset: Option<u64>,
    /// At most this many bytes (default 256 KiB, at most 1 MiB; a result
    /// carries at most 256 KiB of text).
    #[serde(default)]
    max_bytes: Option<u32>,
    /// A local file that gets the whole file instead (any size; the user's
    /// own file, written as the user, relative to ghost mcp's working
    /// directory), its SHA-256 checked.
    #[serde(default)]
    to_path: Option<String>,
}

#[derive(Debug, Default, Serialize, JsonSchema)]
pub(crate) struct FileReadOutput {
    path: String,
    /// The bytes read, as text (lossy when not UTF-8); empty with `to_path`.
    text: String,
    valid_utf8: bool,
    offset: u64,
    next_offset: u64,
    /// The file's size.
    size: u64,
    /// The read reached the end of the file.
    eof: bool,
    to_path: Option<String>,
    sha256: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct FileWriteInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    /// The file on the target (relative to the home directory); replaced
    /// atomically.
    path: String,
    /// The new content as text. Give content or `from_path`.
    #[serde(default)]
    content: Option<String>,
    /// A local file whose bytes are the new content (any size; the user's
    /// own file, read as the user, relative to ghost mcp's working
    /// directory).
    #[serde(default)]
    from_path: Option<String>,
    /// The mode in octal, such as "755" (default: an existing file's, else
    /// 644).
    #[serde(default)]
    mode: Option<String>,
    /// Create missing parent directories.
    #[serde(default)]
    create_dirs: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct Written {
    path: String,
    size: u64,
    sha256: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct FileEditInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    /// The file on the target (relative to the home directory).
    path: String,
    /// The exact text to replace; it must occur once unless `replace_all`.
    old: String,
    /// The text to put in its place.
    new: String,
    /// Replace every occurrence.
    #[serde(default)]
    replace_all: bool,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct Edited {
    path: String,
    replacements: u64,
    sha256: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct FileListInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    /// The directory on the target (relative to the home directory; "" or
    /// "." is the home directory).
    path: String,
    /// How deep to list (default 1, at most 16).
    #[serde(default)]
    depth: Option<u32>,
    /// At most this many entries (default 1000).
    #[serde(default)]
    max_entries: Option<u32>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct ListedEntry {
    /// Relative to the listed directory.
    path: String,
    #[serde(flatten)]
    stat: StatView,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct Listing {
    entries: Vec<ListedEntry>,
    /// More entries exist than were listed.
    truncated: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct FileSearchInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    /// A regular expression (ripgrep's syntax).
    pattern: String,
    /// Where to search (relative to the home directory; default: it).
    #[serde(default)]
    path: Option<String>,
    /// Globs as ripgrep's -g, such as "*.rs" or "!target".
    #[serde(default)]
    globs: Vec<String>,
    #[serde(default)]
    case_insensitive: bool,
    /// Search hidden files too.
    #[serde(default)]
    hidden: bool,
    /// At most this many matches (default 200).
    #[serde(default)]
    max_matches: Option<u32>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct SearchMatch {
    /// Relative to the searched path.
    path: String,
    line_number: u64,
    line: String,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct Matches {
    matches: Vec<SearchMatch>,
    truncated: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct FileStatInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    /// The path on the target (relative to the home directory).
    path: String,
    /// Follow a symlink (default true).
    #[serde(default)]
    follow: Option<bool>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct StatOutput {
    path: String,
    #[serde(flatten)]
    stat: StatView,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct FileRemoveInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    /// The path on the target (relative to the home directory).
    path: String,
    /// Remove a directory and everything in it.
    #[serde(default)]
    recursive: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct FileRenameInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    from: String,
    to: String,
    /// Replace an existing `to`.
    #[serde(default)]
    overwrite: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct FileMkdirInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    /// The directory on the target (relative to the home directory).
    path: String,
    /// Create missing parents too, and accept an existing directory
    /// (default true).
    #[serde(default)]
    parents: Option<bool>,
    /// The mode in octal (default 755).
    #[serde(default)]
    mode: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum DirectionInput {
    /// Local to the target.
    Up,
    /// The target to local.
    Down,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct SyncInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    /// up: `local_dir` to `remote_dir`; down: `remote_dir` to `local_dir`.
    direction: DirectionInput,
    /// The local directory (the user's own files, read and written as the
    /// user, relative to ghost mcp's working directory).
    local_dir: String,
    /// The directory on the target (relative to the home directory).
    remote_dir: String,
    /// Remove files of the destination that the source lacks.
    #[serde(default)]
    delete: bool,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct InstallInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    /// Build ghostd on the target from its public repository instead of
    /// installing the release channel's build (needs a C compiler there;
    /// any machine ghostd builds for).
    #[serde(default)]
    from_source: bool,
    /// With `from_source`, the tag, branch or commit to build (default: the
    /// latest tag); implies `from_source`.
    #[serde(default, rename = "ref")]
    reference: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct SessionStartInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    /// The program and its arguments, without a shell (default: the user's
    /// login shell).
    #[serde(default)]
    argv: Option<Vec<String>>,
    /// Variables to set (TERM is xterm-256color unless set here).
    #[serde(default)]
    env: BTreeMap<String, String>,
    /// The working directory on the target (default: the home directory).
    #[serde(default)]
    cwd: Option<String>,
    /// The terminal's width, 20 to 500 (default 120).
    #[serde(default)]
    cols: Option<u16>,
    /// The terminal's height, 5 to 200 (default 40).
    #[serde(default)]
    rows: Option<u16>,
    /// A name for the session, shown in `ghostd_session_list`.
    #[serde(default)]
    name: Option<String>,
    /// The session's ID, `s` and 16 lowercase hex digits (default: ghost
    /// chooses one). The same start again with the same ID answers the
    /// session it started instead of starting a second, so a start whose
    /// answer was lost can be sent again.
    #[serde(default)]
    session_id: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct SessionStarted {
    session_id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct SessionSendInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    session_id: String,
    /// Text to type as it is; it is typed before `keys`.
    #[serde(default)]
    text: Option<String>,
    /// Keys to press after the text, in order: `Enter`, `Tab`, `Escape`,
    /// `Backspace`, `Delete`, `Up`, `Down`, `Left`, `Right`, `Home`, `End`,
    /// `PageUp`, `PageDown`, `Insert`, `F1` to `F12`, `Ctrl-<letter>`
    /// (`Ctrl-C`, `Ctrl-D`), `Alt-<character>`.
    #[serde(default)]
    keys: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub(crate) enum UntilInput {
    /// The program wrote output after `since` (default: after the read
    /// arrived).
    Changed,
    /// `regex` matches the screen's text.
    Matches,
    /// The program has exited.
    Exited,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct SessionReadInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    session_id: String,
    /// Answer when this holds, or at `wait_ms` (default: at once).
    #[serde(default)]
    until: Option<UntilInput>,
    /// With until matches: the regex (Rust's regex syntax).
    #[serde(default)]
    regex: Option<String>,
    /// With until changed: the `changed_since` of an earlier read.
    #[serde(default)]
    since: Option<u64>,
    /// How long to wait for `until`, at most 60000 (default 10000).
    #[serde(default)]
    wait_ms: Option<u64>,
    /// Lines above the screen to answer too, at most 1000 (default 0).
    #[serde(default)]
    scrollback: Option<u32>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct SessionResizeInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    session_id: String,
    /// 20 to 500.
    cols: u16,
    /// 5 to 200.
    rows: u16,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct SessionSignalInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    session_id: String,
    /// A signal name (INT, TERM, HUP, KILL, …) or number.
    signal: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct SessionCloseInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    session_id: String,
    /// Seconds between SIGHUP and SIGKILL.
    #[serde(default)]
    grace_seconds: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct SessionLogInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    session_id: String,
    /// Read from this byte offset (default: the last `max_bytes`, the
    /// tail).
    #[serde(default)]
    offset: Option<u64>,
    /// At most this many bytes (default 64 KiB, at most 1 MiB; a result
    /// carries at most 256 KiB of text).
    #[serde(default)]
    max_bytes: Option<u32>,
    /// A local file that gets all the output the log still keeps instead
    /// (any size).
    #[serde(default)]
    to_path: Option<String>,
}

#[derive(Debug, Serialize, JsonSchema)]
pub(crate) struct SessionList {
    sessions: Vec<SessionView>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub(crate) struct WaitInput {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    target: String,
    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours.
    #[serde(default)]
    refresh: bool,
    /// Until a TCP connection to this port succeeds.
    #[serde(default)]
    port: Option<u16>,
    /// With port: the host to connect to (default 127.0.0.1).
    #[serde(default)]
    host: Option<String>,
    /// Until this http:// URL (no TLS) answers a GET with `status`, or any
    /// 2xx or 3xx.
    #[serde(default)]
    http: Option<String>,
    /// With http: the status to wait for.
    #[serde(default)]
    status: Option<u16>,
    /// Until this path exists (relative to the home directory).
    #[serde(default)]
    file_exists: Option<String>,
    /// Until `regex` matches this file's last 1 MiB.
    #[serde(default)]
    file_contains: Option<String>,
    /// Until `regex` matches what this job writes after the wait began.
    #[serde(default)]
    job_output: Option<String>,
    /// With `job_output`: stdout (default) or stderr.
    #[serde(default)]
    stream: Option<StreamInput>,
    /// Until `regex` matches what this session writes after the wait began.
    #[serde(default)]
    session_output: Option<String>,
    /// With `file_contains`, `job_output` or `session_output`: the regex (Rust's
    /// regex syntax).
    #[serde(default)]
    regex: Option<String>,
    /// Until no process with this ID runs.
    #[serde(default)]
    process_gone: Option<u32>,
    /// Until this job finishes.
    #[serde(default)]
    job_finished: Option<String>,
    /// Until this session's program exits.
    #[serde(default)]
    session_exited: Option<String>,
    /// Give up after this many seconds, at most 300 (default 60).
    #[serde(default)]
    timeout_seconds: Option<u64>,
    /// How often to look, in milliseconds (default 250, at least 50).
    #[serde(default)]
    interval_ms: Option<u64>,
}

/// A signal by its name or number.
pub(crate) fn parse_signal(value: &str) -> Result<i32> {
    if let Ok(number) = value.parse::<i32>() {
        if (1..=64).contains(&number) {
            return Ok(number);
        }
        bail!("{value} is not a signal number");
    }
    let name = value.trim_start_matches("SIG").to_ascii_uppercase();
    let number = match name.trim_start_matches("SIG") {
        "HUP" => 1,
        "INT" => 2,
        "QUIT" => 3,
        "KILL" => 9,
        "USR1" => 10,
        "USR2" => 12,
        "ALRM" => 14,
        "TERM" => 15,
        "CONT" => 18,
        "STOP" => 19,
        "TSTP" => 20,
        "WINCH" => 28,
        _ => bail!("{value} is not a signal this knows; give its number"),
    };
    Ok(number)
}

/// Cuts `text` to at most `cap` bytes at a character boundary; answers
/// whether it cut.
fn cap_text(text: &mut String, cap: usize) -> bool {
    if text.len() <= cap {
        return false;
    }
    let mut end = cap;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    true
}

impl GhostServer {
    pub(crate) fn new(resolver: Arc<Resolver>, cwd: PathBuf) -> Self {
        Self {
            inner: Arc::new(Inner {
                resolver,
                pools: Mutex::new(HashMap::new()),
                cwd,
            }),
            tool_router: Self::tool_router(),
        }
    }

    /// The pool of `target`, made on first use.
    fn pool(&self, target: &str) -> Result<Arc<Pool>> {
        let parsed = parse_target(target).map_err(|error| anyhow!("target {target:?}: {error}"))?;
        let mut pools = self
            .inner
            .pools
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        Ok(Arc::clone(pools.entry(target.to_owned()).or_insert_with(
            || {
                Arc::new(Pool::new(
                    target,
                    parsed,
                    None,
                    Arc::clone(&self.inner.resolver),
                ))
            },
        )))
    }

    /// The pool of `target`, looked up through the API first with
    /// `refresh`; the tool call's result says what it learned about the
    /// machine's identity ([`GhostServer::respond`]).
    async fn pool_for(&self, target: &str, refresh: bool) -> Result<Arc<Pool>> {
        let pool = self.pool(target)?;
        let _ = USED.try_with(|used| *used.borrow_mut() = Some(Arc::clone(&pool)));
        if refresh {
            pool.refresh().await?;
        }
        Ok(pool)
    }

    /// A tool's answer, as [`answer`] makes it, with whether the target's
    /// ghostd checked the machine's identity and what ghost noticed.
    async fn respond<T: Serialize>(
        &self,
        work: impl Future<Output = Result<(String, T)>>,
    ) -> Result<CallToolResult, ErrorData> {
        let ((result, mut notices), pool) = USED
            .scope(RefCell::new(None), async {
                let ran = conn::collecting(work).await;
                (ran, USED.with(RefCell::take))
            })
            .await;
        let host_check = pool.as_ref().and_then(|pool| pool.host_check());
        match result {
            Ok((mut summary, result)) => {
                if let Some(note) = pool.as_ref().and_then(|pool| pool.host_check_note()) {
                    notices.push(note);
                }
                let notice = (!notices.is_empty()).then(|| notices.join("; "));
                if let Some(notice) = &notice {
                    let _ = write!(summary, "; {notice}");
                }
                done(
                    &summary,
                    &Checked {
                        result,
                        host_check,
                        notice,
                    },
                )
            }
            Err(error) => {
                let mut text = format!("{error:#}");
                for notice in notices {
                    let _ = write!(text, "; {notice}");
                }
                Ok(CallToolResult::error(vec![ContentBlock::text(text)]))
            }
        }
    }

    /// A pool given for tests.
    #[cfg(test)]
    pub(crate) fn with_pool(self, target: &str, pool: Pool) -> Self {
        self.inner
            .pools
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(target.to_owned(), Arc::new(pool));
        self
    }

    /// The pool of `target` (tests).
    #[cfg(test)]
    pub(crate) fn pool_of(&self, target: &str) -> Arc<Pool> {
        self.pool(target).expect("a pool")
    }

    /// A local path: relative ones are relative to the working directory.
    fn local(&self, path: &str) -> PathBuf {
        self.inner.cwd.join(path)
    }

    pub(crate) fn spec(&self, input: &ProgramInput) -> Result<ExecSpec> {
        let to_bytes = |values: &[String]| values.iter().map(|value| ops::bytes(value)).collect();
        let program = match (&input.argv, &input.script, &input.script_file) {
            (Some(argv), None, None) => {
                if argv.is_empty() {
                    bail!("argv is empty: give the program and its arguments");
                }
                Program::Argv(to_bytes(argv))
            }
            (None, Some(script), None) => Program::Script {
                body: ops::bytes(script),
                interpreter: input.interpreter.as_deref().map(to_bytes),
                args: to_bytes(&input.args),
            },
            (None, None, Some(file)) => {
                let path = self.local(file);
                let body =
                    std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
                Program::Script {
                    body,
                    interpreter: input.interpreter.as_deref().map(to_bytes),
                    args: to_bytes(&input.args),
                }
            }
            _ => bail!("give exactly one of argv, script and script_file"),
        };
        if let Program::Script { body, .. } = &program
            && body.len() > MAX_INLINE
        {
            bail!("the script is larger than 8 MiB");
        }
        let stdin = match (&input.stdin, &input.stdin_file) {
            (Some(text), None) => Some(ops::bytes(text)),
            (None, Some(file)) => {
                let path = self.local(file);
                Some(std::fs::read(&path).with_context(|| format!("read {}", path.display()))?)
            }
            (None, None) => None,
            (Some(_), Some(_)) => bail!("give stdin or stdin_file, not both"),
        };
        if stdin.as_ref().is_some_and(|stdin| stdin.len() > MAX_INLINE) {
            bail!("stdin is larger than 8 MiB; write it to a file with ghostd_file_write first");
        }
        let spec = ExecSpec {
            program,
            stdin,
            env: input
                .env
                .iter()
                .map(|(name, value)| (ops::bytes(name), ops::bytes(value)))
                .collect(),
            env_remove: input.unset.iter().map(|name| ops::bytes(name)).collect(),
            env_clear: false,
            cwd: input.cwd.as_deref().map(ops::bytes),
            login: input.login,
            timeout_ms: None,
            output_cap: None,
            keep_on_timeout: false,
            name: None,
            job_id: None,
        };
        ops::check_spec_size(&spec)
            .map_err(|error| anyhow!("{error}; write stdin to a file with ghostd_file_write first and give the program its path"))?;
        Ok(spec)
    }

    async fn exec(&self, input: ExecInput) -> Result<(String, ExecOutput)> {
        let pool = self.pool_for(&input.target, input.refresh).await?;
        let mut spec = self.spec(&input.program)?;
        spec.timeout_ms = Some(input.timeout_seconds.unwrap_or(120).saturating_mul(1000));
        spec.keep_on_timeout = input.keep_on_timeout;
        spec.output_cap = Some(EXEC_OUTPUT_CAP);
        let result = ops::exec(&pool, spec).await?;
        let output_file = match &input.output_file {
            // A program that never started has no output, and no log to
            // copy: the result says why.
            Some(_) if matches!(result.outcome, Outcome::FailedToStart { .. }) => None,
            Some(file) => {
                let path = self.local(file);
                let mut sink = std::fs::File::create(&path)
                    .with_context(|| format!("create {}", path.display()))?;
                // Much output takes a connection of its own.
                let bulk = if result.stdout.total > BULK_THRESHOLD {
                    Some(pool.bulk().await?)
                } else {
                    None
                };
                ops::copy_log(
                    bulk.as_ref().map_or(Via::Short(&pool), Via::Bulk),
                    &result.job_id,
                    Stream::Stdout,
                    0,
                    Some(result.stdout.total),
                    &mut sink,
                )
                .await?;
                Some(path.display().to_string())
            }
            None => None,
        };
        let (exit_code, signal, timed_out, still_running, failed_to_start) = match &result.outcome {
            Outcome::Exited { code } => (Some(*code), None, false, false, None),
            Outcome::Signaled { signal } => (None, Some(*signal), false, false, None),
            Outcome::TimedOut { killed } => (None, None, true, !killed, None),
            Outcome::FailedToStart { message } => (None, None, false, false, Some(message.clone())),
        };
        let (stdout, stdout_valid_utf8, stdout_skip) =
            ops::lossy(&result.stdout.data, result.stdout.offset > 0);
        let (stderr, stderr_valid_utf8, stderr_skip) =
            ops::lossy(&result.stderr.data, result.stderr.offset > 0);
        let mut summary = format!(
            "{} in {} ms; stdout {}, stderr {}",
            ops::outcome_summary(&result),
            result.duration_ms,
            size_text(result.stdout.total),
            size_text(result.stderr.total)
        );
        if result.stdout.offset > 0 || result.stderr.offset > 0 {
            let _ = write!(
                summary,
                " (the result holds the last bytes; ghostd_job_logs {} or output_file reads the rest)",
                result.job_id
            );
        }
        if result.stopped > 0 {
            let _ = write!(
                summary,
                "; {} background process(es) it left were stopped (use ghostd_job_start for servers)",
                result.stopped
            );
        }
        Ok((
            summary,
            ExecOutput {
                job_id: result.job_id.clone(),
                exit_code,
                signal,
                timed_out,
                still_running,
                failed_to_start,
                stdout,
                stdout_valid_utf8,
                stdout_offset: result.stdout.offset + stdout_skip as u64,
                stdout_total: result.stdout.total,
                stderr,
                stderr_valid_utf8,
                stderr_offset: result.stderr.offset + stderr_skip as u64,
                stderr_total: result.stderr.total,
                stopped: result.stopped,
                duration_ms: result.duration_ms,
                output_file,
            },
        ))
    }

    async fn job_start(&self, input: JobStartInput) -> Result<(String, JobStarted)> {
        let pool = self.pool_for(&input.target, input.refresh).await?;
        let mut spec = self.spec(&input.program)?;
        spec.timeout_ms = input
            .timeout_seconds
            .map(|seconds| seconds.saturating_mul(1000));
        spec.name = input.name;
        let job_id = ops::job_start(&pool, spec).await?;
        Ok((format!("started job {job_id}"), JobStarted { job_id }))
    }

    async fn job_list(&self, input: JobListInput) -> Result<(String, JobList)> {
        let pool = self.pool_for(&input.target, input.refresh).await?;
        let jobs = match pool
            .call(Request::JobList {
                include_finished: input.include_finished,
                limit: input.limit.unwrap_or(0),
            })
            .await?
        {
            Response::Jobs(jobs) => jobs,
            other => return Err(ops::unexpected(&other)),
        };
        let jobs: Vec<JobView> = jobs.iter().map(JobView::from).collect();
        Ok((format!("{} job(s)", jobs.len()), JobList { jobs }))
    }

    async fn job_request(
        &self,
        target: &str,
        refresh: bool,
        request: Request,
    ) -> Result<(String, JobView)> {
        let pool = self.pool_for(target, refresh).await?;
        let info = ops::job_info(Via::Short(&pool), request).await?;
        let view = JobView::from(&info);
        let summary = format!(
            "job {} is {}{}{}",
            view.job_id,
            view.state,
            view.exit_code
                .map(|code| format!(" with {code}"))
                .unwrap_or_default(),
            if view.finished {
                ", finished"
            } else {
                ", not finished"
            }
        );
        Ok((summary, view))
    }

    async fn job_logs(&self, input: JobLogsInput) -> Result<(String, LogOutput)> {
        let pool = self.pool_for(&input.target, input.refresh).await?;
        let stream = Stream::from(input.stream);
        self.read_log(
            &pool,
            LogOf::Job(&input.job_id, stream),
            input.offset,
            input.max_bytes,
            input.to_path.as_deref(),
        )
        .await
    }

    /// A slice of a job's or a session's log as text, or all of it into the
    /// local file `to_path`.
    async fn read_log(
        &self,
        pool: &Pool,
        log: LogOf<'_>,
        offset: Option<u64>,
        max_bytes: Option<u32>,
        to_path: Option<&str>,
    ) -> Result<(String, LogOutput)> {
        let what = match log {
            LogOf::Job(_, stream) => ops::stream_name(stream).to_owned(),
            LogOf::Session(_) => "output".to_owned(),
        };
        if let Some(file) = to_path {
            let path = self.local(file);
            let first = ops::slice_of(Via::Short(pool), log, None, 0).await?;
            let mut sink = std::fs::File::create(&path)
                .with_context(|| format!("create {}", path.display()))?;
            // Much output takes a connection of its own.
            let bulk = if first.total.saturating_sub(first.first_available) > BULK_THRESHOLD {
                Some(pool.bulk().await?)
            } else {
                None
            };
            let (total, ended) = ops::copy_log_of(
                bulk.as_ref().map_or(Via::Short(pool), Via::Bulk),
                log,
                first.first_available,
                None,
                &mut sink,
            )
            .await?;
            let written = total.saturating_sub(first.first_available);
            return Ok((
                format!(
                    "wrote {} of {what} to {}",
                    size_text(written),
                    path.display()
                ),
                LogOutput {
                    offset: first.first_available,
                    next_offset: total,
                    total,
                    first_available: first.first_available,
                    ended,
                    to_path: Some(path.display().to_string()),
                    bytes_written: Some(written),
                    valid_utf8: true,
                    ..LogOutput::default()
                },
            ));
        }
        let max = max_bytes.unwrap_or(64 * 1024).clamp(1, MAX_READ);
        let slice = ops::slice_of(Via::Short(pool), log, offset, max).await?;
        let cut = offset.is_none() && slice.offset > 0;
        let ops::CutText {
            text,
            valid_utf8,
            skipped,
            used,
            cut: capped,
        } = ops::text_within(
            &slice.data,
            cut,
            FIELD_CAP,
            slice.offset + slice.data.len() as u64 >= slice.total && slice.ended,
        );
        let offset = slice.offset + skipped as u64;
        let next_offset = if capped {
            offset + used as u64
        } else {
            slice.offset + slice.data.len() as u64
        };
        let truncated = next_offset < slice.total;
        let mut summary = format!(
            "{} of {what} bytes {}..{} of {}",
            size_text(next_offset - offset),
            offset,
            next_offset,
            slice.total
        );
        if truncated {
            let _ = write!(
                summary,
                "; more from offset {next_offset}, or to_path for all of it"
            );
        }
        if slice.ended {
            summary.push_str(match log {
                LogOf::Job(..) => "; the job finished",
                LogOf::Session(_) => "; the session's program ended",
            });
        }
        Ok((
            summary,
            LogOutput {
                text,
                valid_utf8,
                offset,
                next_offset,
                total: slice.total,
                first_available: slice.first_available,
                ended: slice.ended,
                truncated,
                to_path: None,
                bytes_written: None,
            },
        ))
    }

    async fn file_read(&self, input: FileReadInput) -> Result<(String, FileReadOutput)> {
        let pool = self.pool_for(&input.target, input.refresh).await?;
        let remote = ops::bytes(&input.path);
        if let Some(file) = &input.to_path {
            let path = self.local(file);
            let got = ops::download(&pool, None, &remote, &path).await?;
            return Ok((
                format!(
                    "wrote {} ({}) to {}",
                    input.path,
                    size_text(got.size),
                    path.display()
                ),
                FileReadOutput {
                    path: input.path,
                    valid_utf8: true,
                    next_offset: got.size,
                    size: got.size,
                    eof: true,
                    to_path: Some(path.display().to_string()),
                    sha256: Some(ops::hex(&got.sha256)),
                    ..FileReadOutput::default()
                },
            ));
        }
        let offset = input.offset.unwrap_or(0);
        let max = input
            .max_bytes
            .unwrap_or(u32::try_from(TEXT_CAP).unwrap_or(MAX_READ))
            .clamp(1, MAX_READ);
        let (data, size, eof) = match pool
            .call(Request::FileRead {
                path: remote,
                offset,
                len: max,
            })
            .await?
        {
            Response::FileData { data, size, eof } => (data, size, eof),
            other => return Err(ops::unexpected(&other)),
        };
        let ops::CutText {
            text,
            valid_utf8,
            used,
            cut,
            ..
        } = ops::text_within(&data, false, FIELD_CAP, eof);
        let mut next_offset = offset + data.len() as u64;
        let mut eof = eof;
        if cut {
            next_offset = offset + used as u64;
            eof = false;
        }
        let mut summary = format!(
            "{} bytes {}..{} of {}",
            input.path, offset, next_offset, size
        );
        if !eof {
            let _ = write!(
                summary,
                "; more from offset {next_offset}, or to_path for the whole file"
            );
        }
        if !valid_utf8 {
            summary.push_str("; not valid UTF-8 (shown lossy; to_path gets the bytes)");
        }
        Ok((
            summary,
            FileReadOutput {
                path: input.path,
                text,
                valid_utf8,
                offset,
                next_offset,
                size,
                eof,
                to_path: None,
                sha256: None,
            },
        ))
    }

    async fn file_write(&self, input: FileWriteInput) -> Result<(String, Written)> {
        let pool = self.pool_for(&input.target, input.refresh).await?;
        let mode = input
            .mode
            .as_deref()
            .map(ops::parse_mode)
            .transpose()
            .map_err(anyhow::Error::msg)?;
        let remote = ops::bytes(&input.path);
        let written = match (&input.content, &input.from_path) {
            (Some(content), None) => {
                ops::write_file(
                    Via::Short(&pool),
                    &remote,
                    ops::bytes(content),
                    mode,
                    input.create_dirs,
                )
                .await?
            }
            (None, Some(file)) => {
                let path = self.local(file);
                ops::upload(&pool, None, &path, &remote, mode, input.create_dirs).await?
            }
            _ => bail!("give content or from_path, one of them"),
        };
        Ok((
            format!("wrote {} ({})", input.path, size_text(written.size)),
            Written {
                path: input.path,
                size: written.size,
                sha256: ops::hex(&written.sha256),
            },
        ))
    }

    async fn file_edit(&self, input: FileEditInput) -> Result<(String, Edited)> {
        let pool = self.pool_for(&input.target, input.refresh).await?;
        let (replacements, sha256) = match pool
            .call(Request::FileEdit {
                path: ops::bytes(&input.path),
                old: ops::bytes(&input.old),
                new: ops::bytes(&input.new),
                replace_all: input.replace_all,
            })
            .await?
        {
            Response::Edited {
                replacements,
                sha256,
            } => (replacements, sha256),
            other => return Err(ops::unexpected(&other)),
        };
        Ok((
            format!("{} replacement(s) in {}", replacements, input.path),
            Edited {
                path: input.path,
                replacements,
                sha256: ops::hex(&sha256),
            },
        ))
    }

    async fn file_list(&self, input: FileListInput) -> Result<(String, Listing)> {
        let pool = self.pool_for(&input.target, input.refresh).await?;
        let (entries, mut truncated) = match pool
            .call(Request::FileList {
                path: ops::bytes(&input.path),
                depth: input.depth.unwrap_or(1),
                max_entries: input.max_entries.unwrap_or(0),
            })
            .await?
        {
            Response::Listing { entries, truncated } => (entries, truncated),
            other => return Err(ops::unexpected(&other)),
        };
        let mut listed = Vec::new();
        let mut size = 0;
        for (path, stat) in &entries {
            let entry = ListedEntry {
                path: ops::shown(path),
                stat: StatView::from(stat),
            };
            size += json_size(&entry);
            if size > FIELD_CAP {
                truncated = true;
                break;
            }
            listed.push(entry);
        }
        let summary = format!(
            "{} entr{}{}",
            listed.len(),
            if listed.len() == 1 { "y" } else { "ies" },
            if truncated {
                " (more exist: list a deeper path or raise max_entries)"
            } else {
                ""
            }
        );
        Ok((
            summary,
            Listing {
                entries: listed,
                truncated,
            },
        ))
    }

    async fn file_search(&self, input: FileSearchInput) -> Result<(String, Matches)> {
        let pool = self.pool_for(&input.target, input.refresh).await?;
        let (found, mut truncated) = match pool
            .call(Request::FileSearch {
                pattern: input.pattern,
                path: input.path.as_deref().map(ops::bytes).unwrap_or_default(),
                globs: input.globs,
                case_insensitive: input.case_insensitive,
                hidden: input.hidden,
                max_matches: input.max_matches.unwrap_or(0),
            })
            .await?
        {
            Response::Matches { matches, truncated } => (matches, truncated),
            other => return Err(ops::unexpected(&other)),
        };
        let mut matches = Vec::new();
        let mut size = 0;
        for found in &found {
            let (line, _, _) = ops::lossy(&found.line, false);
            let entry = SearchMatch {
                path: ops::shown(&found.path),
                line_number: found.line_number,
                line,
            };
            size += json_size(&entry);
            if size > FIELD_CAP {
                truncated = true;
                break;
            }
            matches.push(entry);
        }
        Ok((
            format!(
                "{} match(es){}",
                matches.len(),
                if truncated { ", more exist" } else { "" }
            ),
            Matches { matches, truncated },
        ))
    }

    async fn file_stat(&self, input: FileStatInput) -> Result<(String, StatOutput)> {
        let pool = self.pool_for(&input.target, input.refresh).await?;
        let stat = ops::stat(
            Via::Short(&pool),
            &ops::bytes(&input.path),
            input.follow.unwrap_or(true),
        )
        .await?;
        let view = StatView::from(&stat);
        Ok((
            format!(
                "{} is a {} of {} bytes, mode {}",
                input.path, view.kind, view.size, view.mode
            ),
            StatOutput {
                path: input.path,
                stat: view,
            },
        ))
    }

    async fn simple(
        &self,
        target: &str,
        refresh: bool,
        request: Request,
        done: String,
    ) -> Result<(String, Done)> {
        let pool = self.pool_for(target, refresh).await?;
        pool.call(request).await?;
        Ok((done.clone(), Done { done }))
    }

    async fn sync(&self, input: SyncInput) -> Result<(String, SyncReport)> {
        let pool = self.pool_for(&input.target, input.refresh).await?;
        let direction = match input.direction {
            DirectionInput::Up => Direction::Up,
            DirectionInput::Down => Direction::Down,
        };
        let local = self.local(&input.local_dir);
        if direction == Direction::Up && !local.is_dir() {
            bail!("{} is not a directory", local.display());
        }
        let report = ops::sync(
            &pool,
            direction,
            &local,
            &ops::bytes(&input.remote_dir),
            input.delete,
        )
        .await?;
        Ok((
            format!(
                "{} file(s): {} copied ({}), {} unchanged, {} deleted, {} kept, {} skipped",
                report.files,
                report.copied,
                size_text(report.bytes_copied),
                report.unchanged,
                report.deleted,
                report.kept,
                report.skipped
            ),
            report,
        ))
    }

    async fn install(
        &self,
        input: InstallInput,
        meta: &RequestMetaObject,
        peer: &Peer<RoleServer>,
    ) -> Result<(String, Installed)> {
        if let Some(reference) = &input.reference {
            install::valid_ref(reference).map_err(anyhow::Error::msg)?;
        }
        let pool = self.pool_for(&input.target, input.refresh).await?;
        let last = Arc::new(Mutex::new(String::new()));
        let ticker = meta.get_progress_token().map(|token| {
            let last = Arc::clone(&last);
            let peer = peer.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(PROGRESS_INTERVAL);
                interval.tick().await;
                let mut ticks = 0u32;
                loop {
                    interval.tick().await;
                    ticks += 1;
                    let message = last
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .clone();
                    let _ = peer
                        .notify_progress(
                            ProgressNotificationParam::new(token.clone(), f64::from(ticks))
                                .with_message(message),
                        )
                        .await;
                }
            })
        });
        let kept = Arc::clone(&last);
        let source = super::install_source(
            self.inner.resolver.api_url(),
            input.from_source,
            input.reference.clone(),
        );
        let installed = install::install(&pool, &source, move |line| {
            if !line.trim().is_empty() {
                line.clone_into(
                    &mut kept
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner),
                );
            }
        })
        .await;
        if let Some(ticker) = ticker {
            ticker.abort();
        }
        let installed = installed?;
        let summary = match &installed.note {
            Some(note) => format!("installed after {} s, but {note}", installed.seconds),
            None if installed.unchanged => format!(
                "release {} was installed on {} already (nothing replaced); ghostd {} answers",
                installed.release.as_deref().unwrap_or_default(),
                installed.target,
                installed.ghostd_version
            ),
            None => format!(
                "ghostd {} answers on {} after {} s",
                installed.ghostd_version, installed.target, installed.seconds
            ),
        };
        Ok((summary, installed))
    }

    async fn session_start(&self, input: SessionStartInput) -> Result<(String, SessionStarted)> {
        let pool = self.pool_for(&input.target, input.refresh).await?;
        let spec = v2::SessionSpec {
            argv: input
                .argv
                .map(|argv| argv.iter().map(|arg| ops::bytes(arg)).collect()),
            env: input
                .env
                .iter()
                .map(|(name, value)| (ops::bytes(name), ops::bytes(value)))
                .collect(),
            env_remove: Vec::new(),
            cwd: input.cwd.as_deref().map(ops::bytes),
            cols: input.cols,
            rows: input.rows,
            session_id: input.session_id,
            name: input.name,
        };
        if spec.argv.as_ref().is_some_and(Vec::is_empty) {
            bail!(
                "argv is empty: give the program and its arguments, or leave argv out for the login shell"
            );
        }
        let session_id = sessions::start(&pool, spec).await?;
        Ok((
            format!(
                "started session {session_id}: type with ghostd_session_send, look with ghostd_session_read"
            ),
            SessionStarted { session_id },
        ))
    }

    async fn session_send(&self, input: SessionSendInput) -> Result<(String, Done)> {
        let mut typed = Vec::new();
        if let Some(text) = &input.text {
            typed.push(sessions::Input::Text(text.clone()));
        }
        typed.extend(input.keys.iter().cloned().map(sessions::Input::Key));
        let keys = sessions::keys(&typed)?;
        let pool = self.pool_for(&input.target, input.refresh).await?;
        sessions::send(&pool, &input.session_id, keys).await?;
        let done = format!("typed into session {}", input.session_id);
        Ok((done.clone(), Done { done }))
    }

    async fn session_read(&self, input: SessionReadInput) -> Result<(String, ScreenView)> {
        let until = match (input.until, input.regex) {
            (Some(UntilInput::Changed), None) => Some(v2::Until::Changed { since: input.since }),
            (Some(UntilInput::Matches), Some(regex)) => Some(v2::Until::Matches(regex)),
            (Some(UntilInput::Matches), None) => bail!("until matches needs the regex"),
            (Some(UntilInput::Exited), None) => Some(v2::Until::Exited),
            (None, None) => None,
            (_, Some(_)) => bail!("regex goes with until matches"),
        };
        if input.since.is_some() && !matches!(until, Some(v2::Until::Changed { .. })) {
            bail!("since goes with until changed");
        }
        let wait_ms = if until.is_some() {
            input
                .wait_ms
                .unwrap_or(10_000)
                .min(sessions::MAX_READ_WAIT_MS)
        } else {
            0
        };
        let pool = self.pool_for(&input.target, input.refresh).await?;
        let screen = sessions::read(
            &pool,
            &input.session_id,
            wait_ms,
            until,
            input.scrollback.unwrap_or(0),
        )
        .await?;
        let view = ScreenView::new(&input.session_id, screen, FIELD_CAP);
        let mut summary = format!(
            "session {}: {}x{} screen, cursor at {},{}",
            view.session_id, view.cols, view.rows, view.cursor_row, view.cursor_col
        );
        match view.until_met {
            Some(true) => summary.push_str(", until met"),
            Some(false) => summary.push_str(", until not met before wait_ms"),
            None => {}
        }
        if view.exited {
            summary.push_str(", the program exited");
        }
        if view.truncated {
            summary.push_str(", cut to fit (less scrollback reads all of it)");
        }
        Ok((summary, view))
    }

    async fn session_resize(&self, input: SessionResizeInput) -> Result<(String, Done)> {
        let pool = self.pool_for(&input.target, input.refresh).await?;
        sessions::resize(&pool, &input.session_id, input.cols, input.rows).await?;
        let done = format!(
            "resized session {} to {}x{}",
            input.session_id, input.cols, input.rows
        );
        Ok((done.clone(), Done { done }))
    }

    async fn session_signal(&self, input: SessionSignalInput) -> Result<(String, Done)> {
        let signal = parse_signal(&input.signal)?;
        let pool = self.pool_for(&input.target, input.refresh).await?;
        sessions::signal(&pool, &input.session_id, signal).await?;
        let done = format!("sent signal {signal} to session {}", input.session_id);
        Ok((done.clone(), Done { done }))
    }

    async fn session_list(&self, input: TargetInput) -> Result<(String, SessionList)> {
        let pool = self.pool_for(&input.target, input.refresh).await?;
        let sessions: Vec<SessionView> = sessions::list(&pool)
            .await?
            .iter()
            .map(SessionView::from)
            .collect();
        Ok((
            format!("{} session(s)", sessions.len()),
            SessionList { sessions },
        ))
    }

    async fn session_close(&self, input: SessionCloseInput) -> Result<(String, SessionView)> {
        let pool = self.pool_for(&input.target, input.refresh).await?;
        let info = sessions::close(
            &pool,
            &input.session_id,
            input
                .grace_seconds
                .map(|seconds| seconds.saturating_mul(1000)),
        )
        .await?;
        let view = SessionView::from(&info);
        Ok((
            format!("closed session {}: {}", view.session_id, view.state),
            view,
        ))
    }

    async fn session_log(&self, input: SessionLogInput) -> Result<(String, LogOutput)> {
        let pool = self.pool_for(&input.target, input.refresh).await?;
        self.read_log(
            &pool,
            LogOf::Session(&input.session_id),
            input.offset,
            input.max_bytes,
            input.to_path.as_deref(),
        )
        .await
    }

    async fn wait(&self, input: WaitInput) -> Result<(String, WaitView)> {
        let condition = sessions::ConditionParts {
            port: input.port,
            host: input.host,
            http: input.http,
            status: input.status,
            file_exists: input.file_exists,
            file_contains: input.file_contains,
            job_output: input.job_output,
            session_output: input.session_output,
            regex: input.regex,
            stream: input.stream.map(Stream::from),
            process_gone: input.process_gone,
            job_finished: input.job_finished,
            session_exited: input.session_exited,
        }
        .condition()?;
        let pool = self.pool_for(&input.target, input.refresh).await?;
        let waited = sessions::wait(
            &pool,
            condition,
            input
                .timeout_seconds
                .unwrap_or(sessions::DEFAULT_WAIT_SECONDS),
            input.interval_ms,
        )
        .await?;
        Ok((
            format!(
                "{} after {} ms: {}",
                if waited.met { "met" } else { "not met" },
                waited.elapsed_ms,
                waited.detail
            ),
            waited,
        ))
    }

    async fn machine_state(&self, input: TargetInput) -> Result<(String, MachineView)> {
        let pool = self.pool_for(&input.target, input.refresh).await?;
        let mut machine = sessions::machine(&pool).await?;
        // A busy machine's sockets could pass the result's cap.
        let mut cut = 0;
        while json_size(&machine) > FIELD_CAP && machine.listening.pop().is_some() {
            cut += 1;
        }
        if cut > 0 {
            machine.notes.push(format!(
                "{cut} listening socket(s) left out to fit the result; ghostd_exec ss -ltnup lists them all"
            ));
        }
        Ok((machine.summary(), machine))
    }

    async fn status(&self, input: TargetInput) -> Result<(String, StatusView)> {
        let pool = self.pool_for(&input.target, input.refresh).await?;
        let status = super::status(&pool, Some(self.inner.resolver.api_url())).await?;
        let mut summary = format!(
            "ghostd {} answers on {} ({}) in {} ms",
            status.ghostd_version, status.target, status.endpoint, status.latency_ms
        );
        match (&status.update, &status.channel_ghostd_version) {
            (Some(_), Some(version)) => {
                let _ = write!(
                    summary,
                    "; the release channel has ghostd {version}: ghostd_install updates it"
                );
            }
            (None, Some(_)) => summary.push_str("; it is the release channel's version"),
            _ => {}
        }
        Ok((summary, status))
    }
}

#[tool_router]
impl GhostServer {
    #[tool(
        description = "Run a program on a target to its end and get its exit code and output. \
The program is an argv array passed without a shell (no quoting), or a script. The result \
carries the last 64 KiB of stdout and stderr with offsets and totals; output_file gets all \
of stdout, ghostd_job_logs reads more. A plain background process the program leaves \
(cmd &, nohup cmd &) is stopped when it ends: start long-running work and servers with \
ghostd_job_start. Default timeout 120 s. Local paths (script_file, stdin_file, \
output_file) are the user's own files, read and written as the user, relative to ghost \
mcp's working directory.",
        output_schema = schema_for_output::<Checked<ExecOutput>>()
    )]
    async fn ghostd_exec(
        &self,
        Parameters(input): Parameters<ExecInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.exec(input))).await
    }

    #[tool(
        description = "Start a program on a target as a job that outlives this call (a \
server, a build, anything long) and get its job_id at once. What it starts in the \
background belongs to the job; ghostd_job_stop stops all of it. Follow it with \
ghostd_job_status, ghostd_job_wait and ghostd_job_logs.",
        output_schema = schema_for_output::<Checked<JobStarted>>()
    )]
    async fn ghostd_job_start(
        &self,
        Parameters(input): Parameters<JobStartInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.job_start(input))).await
    }

    #[tool(
        description = "List the jobs on a target, newest first.",
        output_schema = schema_for_output::<Checked<JobList>>()
    )]
    async fn ghostd_job_list(
        &self,
        Parameters(input): Parameters<JobListInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.job_list(input))).await
    }

    #[tool(
        description = "A job's state: running or how it ended, whether it finished, its \
processes and output sizes.",
        output_schema = schema_for_output::<Checked<JobView>>()
    )]
    async fn ghostd_job_status(
        &self,
        Parameters(input): Parameters<JobInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.job_request(
            &input.target,
            input.refresh,
            Request::JobStatus {
                job_id: input.job_id,
            },
        )))
        .await
    }

    #[tool(
        description = "Wait for a job to finish, at most timeout_seconds (at most 60); \
the result says whether it finished.",
        output_schema = schema_for_output::<Checked<JobView>>()
    )]
    async fn ghostd_job_wait(
        &self,
        Parameters(input): Parameters<JobWaitInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let seconds = input.timeout_seconds.unwrap_or(60).min(60);
        self.respond(Box::pin(self.job_request(
            &input.target,
            input.refresh,
            Request::JobWait {
                job_id: input.job_id,
                timeout_ms: seconds * 1000,
            },
        )))
        .await
    }

    #[tool(
        description = "Read a job's stdout or stderr: from an offset, or the tail; at most \
256 KiB of text per result (next_offset says where to go on). to_path writes the whole \
stream to a local file of the user's instead.",
        output_schema = schema_for_output::<Checked<LogOutput>>()
    )]
    async fn ghostd_job_logs(
        &self,
        Parameters(input): Parameters<JobLogsInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.job_logs(input))).await
    }

    #[tool(
        description = "Send a signal to a job's program (its process group).",
        output_schema = schema_for_output::<Checked<Done>>()
    )]
    async fn ghostd_job_signal(
        &self,
        Parameters(input): Parameters<JobSignalInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let signal = match parse_signal(&input.signal) {
            Ok(signal) => signal,
            Err(error) => return answer::<Done>(Err(error)),
        };
        let done = format!("sent signal {signal} to job {}", input.job_id);
        self.respond(Box::pin(self.simple(
            &input.target,
            input.refresh,
            Request::JobSignal {
                job_id: input.job_id,
                signal,
            },
            done,
        )))
        .await
    }

    #[tool(
        description = "Stop a job and everything it started (SIGTERM, then SIGKILL after \
the grace); answers once all of it is gone.",
        output_schema = schema_for_output::<Checked<JobView>>()
    )]
    async fn ghostd_job_stop(
        &self,
        Parameters(input): Parameters<JobStopInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(
            self.job_request(
                &input.target,
                input.refresh,
                Request::JobStop {
                    job_id: input.job_id,
                    grace_ms: input
                        .grace_seconds
                        .map(|seconds| seconds.saturating_mul(1000)),
                },
            ),
        ))
        .await
    }

    #[tool(
        description = "Remove a finished job and its logs.",
        output_schema = schema_for_output::<Checked<Done>>()
    )]
    async fn ghostd_job_remove(
        &self,
        Parameters(input): Parameters<JobInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let done = format!("removed job {}", input.job_id);
        self.respond(Box::pin(self.simple(
            &input.target,
            input.refresh,
            Request::JobRemove {
                job_id: input.job_id,
            },
            done,
        )))
        .await
    }

    #[tool(
        description = "Read a file on a target as text: from offset, at most 256 KiB per \
result (next_offset says where to go on). to_path copies the whole file, any size, to a \
local file of the user's instead (written as the user, relative to ghost mcp's working \
directory), its SHA-256 checked.",
        output_schema = schema_for_output::<Checked<FileReadOutput>>()
    )]
    async fn ghostd_file_read(
        &self,
        Parameters(input): Parameters<FileReadInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.file_read(input))).await
    }

    #[tool(
        description = "Write a file on a target atomically, from content or from a local \
file of the user's (from_path, any size, read as the user, relative to ghost mcp's \
working directory). Keeps an existing file's mode unless mode is given.",
        output_schema = schema_for_output::<Checked<Written>>()
    )]
    async fn ghostd_file_write(
        &self,
        Parameters(input): Parameters<FileWriteInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.file_write(input))).await
    }

    #[tool(
        description = "Replace exact text in a file on a target, atomically: `old` must \
occur exactly once unless replace_all.",
        output_schema = schema_for_output::<Checked<Edited>>()
    )]
    async fn ghostd_file_edit(
        &self,
        Parameters(input): Parameters<FileEditInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.file_edit(input))).await
    }

    #[tool(
        description = "List a directory on a target, depth first, hidden files included, \
symlinks not followed.",
        output_schema = schema_for_output::<Checked<Listing>>()
    )]
    async fn ghostd_file_list(
        &self,
        Parameters(input): Parameters<FileListInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.file_list(input))).await
    }

    #[tool(
        description = "Search files on a target with a regular expression, as ripgrep \
does (.gitignore respected, binary files skipped).",
        output_schema = schema_for_output::<Checked<Matches>>()
    )]
    async fn ghostd_file_search(
        &self,
        Parameters(input): Parameters<FileSearchInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.file_search(input))).await
    }

    #[tool(
        description = "A path's metadata on a target: kind, size, mode, mtime, owner.",
        output_schema = schema_for_output::<Checked<StatOutput>>()
    )]
    async fn ghostd_file_stat(
        &self,
        Parameters(input): Parameters<FileStatInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.file_stat(input))).await
    }

    #[tool(
        description = "Remove a file, or with recursive a directory and all in it, on a target.",
        output_schema = schema_for_output::<Checked<Done>>()
    )]
    async fn ghostd_file_remove(
        &self,
        Parameters(input): Parameters<FileRemoveInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let done = format!("removed {}", input.path);
        self.respond(Box::pin(self.simple(
            &input.target,
            input.refresh,
            Request::FileRemove {
                path: ops::bytes(&input.path),
                recursive: input.recursive,
            },
            done,
        )))
        .await
    }

    #[tool(
        description = "Rename or move a path on a target; an existing destination only \
with overwrite.",
        output_schema = schema_for_output::<Checked<Done>>()
    )]
    async fn ghostd_file_rename(
        &self,
        Parameters(input): Parameters<FileRenameInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let done = format!("renamed {} to {}", input.from, input.to);
        self.respond(Box::pin(self.simple(
            &input.target,
            input.refresh,
            Request::FileRename {
                from: ops::bytes(&input.from),
                to: ops::bytes(&input.to),
                overwrite: input.overwrite,
            },
            done,
        )))
        .await
    }

    #[tool(
        description = "Create a directory on a target (with its parents by default).",
        output_schema = schema_for_output::<Checked<Done>>()
    )]
    async fn ghostd_file_mkdir(
        &self,
        Parameters(input): Parameters<FileMkdirInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let mode = match input.mode.as_deref().map(ops::parse_mode).transpose() {
            Ok(mode) => mode,
            Err(error) => return answer::<Done>(Err(anyhow!(error))),
        };
        let done = format!("made {}", input.path);
        self.respond(Box::pin(self.simple(
            &input.target,
            input.refresh,
            Request::FileMkdir {
                path: ops::bytes(&input.path),
                parents: input.parents.unwrap_or(true),
                mode,
            },
            done,
        )))
        .await
    }

    #[tool(
        description = "Make a directory on a target hold what a local directory holds \
(up), or the other way round (down): compares each file's size and then its SHA-256 and \
copies only the files that differ; with delete, removes files the source does not have. \
A directory that cannot be listed stops the sync. Symlinks are left out, and a sync down \
never writes through a local symlink. local_dir is the user's own directory, read and \
written as the user, relative to ghost mcp's working directory.",
        output_schema = schema_for_output::<Checked<SyncReport>>()
    )]
    async fn ghostd_sync(
        &self,
        Parameters(input): Parameters<SyncInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.sync(input))).await
    }

    #[tool(
        description = "Install or update ghostd on a target over SSH. By default the \
release channel's build: ghost checks its signature and SHA-256 and copies it over \
(the target needs only sh, uname and sha256sum; x86_64 only). from_source (or a ref) \
builds it there from its public repository instead (needs a C compiler; installs Rust \
for the user when missing; takes minutes). Updating is installing again: a running \
ghostd daemon is stopped so the next connection starts the new binary, and its jobs \
keep running; installing the release that is there already replaces nothing and leaves \
its daemon and connections alone (unchanged). Sends progress with the last output line \
every 10 s. When a daemon that still runs the old binary answers afterwards, the result \
says so (restart_needed, note).",
        output_schema = schema_for_output::<Checked<Installed>>()
    )]
    async fn ghostd_install(
        &self,
        Parameters(input): Parameters<InstallInput>,
        meta: RequestMetaObject,
        peer: Peer<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.install(input, &meta, &peer)))
            .await
    }

    #[tool(
        description = "Whether ghostd answers on a target: its version, protocol version \
and latency, and the release channel's current version (update_available, and the \
command that updates it; the channel is asked for at most 5 s, else channel_error \
says so).",
        output_schema = schema_for_output::<StatusView>()
    )]
    async fn ghostd_status(
        &self,
        Parameters(input): Parameters<TargetInput>,
    ) -> Result<CallToolResult, ErrorData> {
        let (status, notices) = conn::collecting(self.status(input)).await;
        answer(status.map(|(mut summary, mut status)| {
            if !notices.is_empty() {
                let notice = notices.join("; ");
                let _ = write!(summary, "; {notice}");
                status.notice = Some(notice);
            }
            if let Some(note) = &status.host_check_note {
                let _ = write!(summary, "; {note}");
            }
            (summary, status)
        }))
    }
    #[tool(
        description = "Start a program on a terminal (PTY) of its own, a session, that \
outlives this call: for anything interactive, such as a REPL, an installer that asks \
questions, a debugger or a full-screen program (top, vi). Default: the user's login \
shell. Answers its session_id at once; type into it with ghostd_session_send and look at \
its screen with ghostd_session_read. For a program that needs no input, use \
ghostd_exec or ghostd_job_start instead.",
        output_schema = schema_for_output::<Checked<SessionStarted>>()
    )]
    async fn ghostd_session_start(
        &self,
        Parameters(input): Parameters<SessionStartInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.session_start(input))).await
    }

    #[tool(
        description = "Type into a session: text as it is, then named keys (Enter, Tab, \
Escape, Backspace, Up, Down, PageUp, F1-F12, Ctrl-C, Ctrl-D, Alt-x, …). It is never sent \
twice: when the connection drops, the tool says the input may or may not have been \
typed; read the session to see. Follow it with ghostd_session_read and until.",
        output_schema = schema_for_output::<Checked<Done>>()
    )]
    async fn ghostd_session_send(
        &self,
        Parameters(input): Parameters<SessionSendInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.session_send(input))).await
    }

    #[tool(
        description = "A session's screen as text, with the cursor, the title and \
whether its program exited. until waits up to wait_ms (at most 60000) for new output \
(changed, after `since`, the changed_since of an earlier read), for a regex to match the \
screen (matches), or for the program to exit (exited); until_met says whether it held. \
scrollback adds lines above the screen.",
        output_schema = schema_for_output::<Checked<ScreenView>>()
    )]
    async fn ghostd_session_read(
        &self,
        Parameters(input): Parameters<SessionReadInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.session_read(input))).await
    }

    #[tool(
        description = "Resize a session's terminal.",
        output_schema = schema_for_output::<Checked<Done>>()
    )]
    async fn ghostd_session_resize(
        &self,
        Parameters(input): Parameters<SessionResizeInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.session_resize(input))).await
    }

    #[tool(
        description = "Send a signal to the program in a session's foreground (its \
process group), such as INT to interrupt it.",
        output_schema = schema_for_output::<Checked<Done>>()
    )]
    async fn ghostd_session_signal(
        &self,
        Parameters(input): Parameters<SessionSignalInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.session_signal(input))).await
    }

    #[tool(
        description = "List the sessions on a target, live and ended, newest first.",
        output_schema = schema_for_output::<Checked<SessionList>>()
    )]
    async fn ghostd_session_list(
        &self,
        Parameters(input): Parameters<TargetInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.session_list(input))).await
    }

    #[tool(
        description = "Close a session: hang it up and stop everything it started \
(SIGHUP, then SIGKILL after the grace); its last screen and output stay readable.",
        output_schema = schema_for_output::<Checked<SessionView>>()
    )]
    async fn ghostd_session_close(
        &self,
        Parameters(input): Parameters<SessionCloseInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.session_close(input))).await
    }

    #[tool(
        description = "Read a session's raw output as it came, terminal escapes \
included: from an offset, or the tail; at most 256 KiB of text per result (next_offset \
says where to go on). to_path writes all of it to a local file of the user's instead.",
        output_schema = schema_for_output::<Checked<LogOutput>>()
    )]
    async fn ghostd_session_log(
        &self,
        Parameters(input): Parameters<SessionLogInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.session_log(input))).await
    }

    #[tool(
        description = "Wait on a target for a condition, looked at there every 250 ms, \
instead of polling with ghostd_exec: is the server up yet, has the file appeared, has the \
job said it is ready. Exactly one of: port (and host), http (an http:// URL; no TLS: for \
https wait for the port), file_exists, file_contains (with regex), job_output or \
session_output (with regex; output written after the wait began), process_gone (a pid), \
job_finished, session_exited. timeout_seconds at most 300 (default 60); met says whether \
it held, detail what it saw last.",
        output_schema = schema_for_output::<Checked<WaitView>>()
    )]
    async fn ghostd_wait(
        &self,
        Parameters(input): Parameters<WaitInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.wait(input))).await
    }

    #[tool(
        description = "What is going on on a machine, or wrong with it, in one call: OS, \
kernel, uptime, load, memory, disks, listening ports (with the process for the user's \
own), failing systemd units, and the last kernel and journal errors.",
        output_schema = schema_for_output::<Checked<MachineView>>()
    )]
    async fn ghostd_machine_state(
        &self,
        Parameters(input): Parameters<TargetInput>,
    ) -> Result<CallToolResult, ErrorData> {
        self.respond(Box::pin(self.machine_state(input))).await
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for GhostServer {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("ghost", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Work on machines through ghostd: run programs (ghostd_exec, argv arrays, \
no quoting), start long-running work as jobs (ghostd_job_start), and read, write, edit, \
search and sync files. A target is an instance ID or name of the Gigahost account, \
ssh://[user@]host[:port], or local. Interactive programs (a REPL, an installer that asks \
questions) run in sessions (ghostd_session_start, _send, _read); ghostd_wait waits for a \
port, a URL, a file or a job instead of polling; ghostd_machine_state says what is going \
on on a machine. ghostd_install installs ghostd on a target that lacks it, and updates it \
(ghostd_status says when the release channel has another version). Every request names \
the machine's host ID ghost learned, so a name or an address that now reaches another \
machine runs nothing. An instance's name and address are cached for 24 hours: after a rename, \
or a new instance of the name, made elsewhere (the website, another device), pass refresh: \
true.",
            )
    }
}
