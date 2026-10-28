//! What `ghost x`, `ghost ghostd` and `ghost mcp` share: execs, job logs,
//! transfers, sync, and the JSON views of ghostd's answers.

use std::{
    collections::BTreeMap,
    ffi::OsStr,
    fs,
    io::{Read as _, Write},
    os::unix::{ffi::OsStrExt as _, fs::PermissionsExt as _},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ghostd_protocol::{
    v1::{
        ExecResult, ExecSpec, FileKind, JobInfo, JobState, LogSlice, Outcome, Request, Response,
        Stat, Stream,
    },
    v2::{self, ErrorKind},
};
use schemars::JsonSchema;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::conn::{BULK_THRESHOLD, Bulk, Pool, is_remote};

/// The data one read, chunk or log slice carries: 4 MiB, half of ghostd's
/// 8 MiB cap, so a frame never comes near its 16 MiB limit.
pub(crate) const SLICE: u32 = 4 * 1024 * 1024;

/// The most bytes of stdin, a written file's content or a script that one
/// request carries (ghostd's cap on one data field).
pub(crate) const MAX_INLINE: usize = ghostd_protocol::v1::MAX_DATA;

/// Where a call goes: the pool's shared connection, with its retries, or a
/// bulk connection of its own.
#[derive(Clone, Copy)]
pub(crate) enum Via<'a> {
    Short(&'a Pool),
    Bulk(&'a Bulk<'a>),
}

impl Via<'_> {
    pub(crate) async fn call(self, request: Request) -> Result<Response> {
        match self {
            Self::Short(pool) => pool.call(request).await,
            Self::Bulk(bulk) => bulk.call(request).await,
        }
    }

    pub(crate) async fn call2(self, request: v2::Request) -> Result<v2::Response> {
        match self {
            Self::Short(pool) => pool.call2(request).await,
            Self::Bulk(bulk) => bulk.call2(request).await,
        }
    }
}

/// A log ghostd keeps: a job's stream, or a session's output.
#[derive(Clone, Copy, Debug)]
pub(crate) enum LogOf<'a> {
    Job(&'a str, Stream),
    Session(&'a str),
}

impl LogOf<'_> {
    /// For people: `job j…'s stdout`, `session s…'s output`.
    pub(crate) fn describe(self) -> String {
        match self {
            Self::Job(job_id, stream) => format!("job {job_id}'s {}", stream_name(stream)),
            Self::Session(session_id) => format!("session {session_id}'s output"),
        }
    }
}

pub(crate) fn unexpected(response: &Response) -> anyhow::Error {
    anyhow!("ghostd answered with an unexpected {response:?}")
}

/// Refuses an exec or job whose request would not fit in one frame (a
/// script and stdin of up to 8 MiB each), naming the sizes.
pub(crate) fn check_spec_size(spec: &ExecSpec) -> Result<()> {
    let request = v2::Request::V1(Request::Exec(spec.clone()));
    super::conn::check_size(&request).map_err(|error| {
        let script = match &spec.program {
            ghostd_protocol::v1::Program::Script { body, .. } => body.len(),
            ghostd_protocol::v1::Program::Argv(_) => 0,
        };
        let stdin = spec.stdin.as_ref().map_or(0, Vec::len);
        anyhow!("{error} (the script takes {script} bytes, stdin {stdin})")
    })
}

/// Runs `spec` to its end and answers its result.
pub(crate) async fn exec(pool: &Pool, spec: ExecSpec) -> Result<ExecResult> {
    match pool.call(Request::Exec(spec)).await? {
        Response::Exec(result) => Ok(result),
        other => Err(unexpected(&other)),
    }
}

/// Starts `spec` as a job and answers its ID.
pub(crate) async fn job_start(pool: &Pool, spec: ExecSpec) -> Result<String> {
    match pool.call(Request::JobStart(spec)).await? {
        Response::JobStarted { job_id } => Ok(job_id),
        other => Err(unexpected(&other)),
    }
}

pub(crate) async fn job_info(via: Via<'_>, request: Request) -> Result<JobInfo> {
    match via.call(request).await? {
        Response::Job(info) => Ok(info),
        other => Err(unexpected(&other)),
    }
}

pub(crate) async fn log_slice(
    via: Via<'_>,
    job_id: &str,
    stream: Stream,
    offset: Option<u64>,
    max_len: u32,
) -> Result<LogSlice> {
    slice_of(via, LogOf::Job(job_id, stream), offset, max_len).await
}

/// A slice of a job's or a session's log.
pub(crate) async fn slice_of(
    via: Via<'_>,
    log: LogOf<'_>,
    offset: Option<u64>,
    max_len: u32,
) -> Result<LogSlice> {
    let request = match log {
        LogOf::Job(job_id, stream) => v2::Request::V1(Request::JobLogRead {
            job_id: job_id.to_owned(),
            stream,
            offset,
            max_len,
        }),
        LogOf::Session(session_id) => v2::Request::SessionLogRead {
            session_id: session_id.to_owned(),
            offset,
            max_len,
        },
    };
    match via.call2(request).await? {
        v2::Response::V1(Response::LogSlice(slice)) => Ok(slice),
        other => Err(anyhow!("ghostd answered with an unexpected {other:?}")),
    }
}

/// Copies bytes `from..to` of a job's stream from its log to `sink`, in
/// slices; `to` `None` copies to the log's current end. Answers the last
/// slice's state (`total`, `ended`).
pub(crate) async fn copy_log(
    via: Via<'_>,
    job_id: &str,
    stream: Stream,
    from: u64,
    to: Option<u64>,
    sink: &mut (dyn Write + Send),
) -> Result<(u64, bool)> {
    copy_log_of(via, LogOf::Job(job_id, stream), from, to, sink).await
}

/// [`copy_log`] of a job's or a session's log.
pub(crate) async fn copy_log_of(
    via: Via<'_>,
    log: LogOf<'_>,
    from: u64,
    to: Option<u64>,
    sink: &mut (dyn Write + Send),
) -> Result<(u64, bool)> {
    let mut position = from;
    loop {
        let want = match to {
            Some(to) if position >= to => break,
            Some(to) => u32::try_from((to - position).min(u64::from(SLICE))).unwrap_or(SLICE),
            None => SLICE,
        };
        let slice = slice_of(via, log, Some(position), want).await?;
        if slice.offset > position {
            bail!(
                "{} log no longer holds bytes {position}..{}: it rotated (it keeps bytes from {})",
                log.describe(),
                slice.offset,
                slice.first_available
            );
        }
        if slice.data.is_empty() {
            if to.is_some_and(|to| slice.total < to) {
                bail!(
                    "{} log ends at {} bytes, before {}",
                    log.describe(),
                    slice.total,
                    to.unwrap_or_default()
                );
            }
            return Ok((slice.total, slice.ended));
        }
        sink.write_all(&slice.data).context("write the output")?;
        position = slice.offset + slice.data.len() as u64;
        if to.is_none() && position >= slice.total {
            return Ok((slice.total, slice.ended));
        }
    }
    sink.flush().context("write the output")?;
    Ok((position, false))
}

pub(crate) fn stream_name(stream: Stream) -> &'static str {
    match stream {
        Stream::Stdout => "stdout",
        Stream::Stderr => "stderr",
    }
}

/// `text` with a string's bytes: a path or an argument from JSON.
pub(crate) fn bytes(text: &str) -> Vec<u8> {
    text.as_bytes().to_vec()
}

/// A path or name from ghostd, for people (lossy, controls escaped).
pub(crate) fn shown(bytes: &[u8]) -> String {
    crate::escape_control(&String::from_utf8_lossy(bytes)).into_owned()
}

/// Bytes as text for a result: lossy UTF-8, and whether they were valid.
/// When the bytes start inside a stream (`cut`), up to three continuation
/// bytes at the start belong to a character cut off by the slice and are
/// skipped; the answer says how many.
pub(crate) fn lossy(data: &[u8], cut: bool) -> (String, bool, usize) {
    let skip = if cut {
        data.iter()
            .take(3)
            .take_while(|byte| (0x80..0xc0).contains(*byte))
            .count()
    } else {
        0
    };
    let data = &data[skip..];
    match std::str::from_utf8(data) {
        Ok(text) => (text.to_owned(), true, skip),
        Err(_) => (String::from_utf8_lossy(data).into_owned(), false, skip),
    }
}

/// Bytes as text for a result, as [`lossy`] makes it, cut where its JSON
/// would pass `cap` bytes.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct CutText {
    pub(crate) text: String,
    /// The bytes taken were valid UTF-8.
    pub(crate) valid_utf8: bool,
    /// Continuation bytes skipped at the start (see [`lossy`]).
    pub(crate) skipped: usize,
    /// The bytes after the skipped ones that `text` holds.
    pub(crate) used: usize,
    /// `text` stops before the bytes' end.
    pub(crate) cut: bool,
}

/// The bytes a character takes in JSON, as `serde_json` writes it.
fn json_width(character: char) -> usize {
    match character {
        '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
        character if u32::from(character) < 0x20 => 6,
        character => character.len_utf8(),
    }
}

/// [`lossy`], cut at a character so that the text takes at most `cap`
/// bytes as JSON, with the count of the bytes it holds: where a next read
/// goes on from. Unless the bytes are the stream's last (`at_end`), a
/// character the bytes' end cuts off is left for the next read, which then
/// starts at its first byte, instead of being shown as invalid.
pub(crate) fn text_within(data: &[u8], starts_inside: bool, cap: usize, at_end: bool) -> CutText {
    let skipped = if starts_inside {
        data.iter()
            .take(3)
            .take_while(|byte| (0x80..0xc0).contains(*byte))
            .count()
    } else {
        0
    };
    let mut text = String::new();
    let mut width = 0;
    let mut used = 0;
    let mut valid_utf8 = true;
    for chunk in data[skipped..].utf8_chunks() {
        for character in chunk.valid().chars() {
            width += json_width(character);
            if width > cap {
                return CutText {
                    text,
                    valid_utf8,
                    skipped,
                    used,
                    cut: true,
                };
            }
            text.push(character);
            used += character.len_utf8();
        }
        if !chunk.invalid().is_empty() {
            // Left for the next read only when this one shows something:
            // a slice that is nothing but the start of one character would
            // otherwise never advance.
            let unfinished = !at_end
                && skipped + used > 0
                && skipped + used + chunk.invalid().len() == data.len()
                && std::str::from_utf8(chunk.invalid())
                    .is_err_and(|error| error.error_len().is_none());
            if unfinished {
                return CutText {
                    text,
                    valid_utf8,
                    skipped,
                    used,
                    cut: true,
                };
            }
            width += char::REPLACEMENT_CHARACTER.len_utf8();
            if width > cap {
                return CutText {
                    text,
                    valid_utf8,
                    skipped,
                    used,
                    cut: true,
                };
            }
            valid_utf8 = false;
            text.push(char::REPLACEMENT_CHARACTER);
            used += chunk.invalid().len();
        }
    }
    CutText {
        text,
        valid_utf8,
        skipped,
        used,
        cut: false,
    }
}

/// The last bytes of a stream as `x --json` prints them: UTF-8 text, or
/// base64 when it is not valid UTF-8.
pub(crate) fn output_json(name: &str, output: &ghostd_protocol::v1::Output) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    match std::str::from_utf8(&output.data) {
        Ok(text) => {
            object.insert(name.to_owned(), text.into());
        }
        Err(_) => {
            object.insert(
                format!("{name}_base64"),
                STANDARD.encode(&output.data).into(),
            );
        }
    }
    object.insert(format!("{name}_offset"), output.offset.into());
    object.insert(format!("{name}_total"), output.total.into());
    serde_json::Value::Object(object)
}

/// A job as results show it.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct JobView {
    pub(crate) job_id: String,
    pub(crate) name: Option<String>,
    /// The first four arguments, at most 200 characters.
    pub(crate) command: String,
    /// `running`, `exited`, `signaled` or `lost` (the program's state).
    pub(crate) state: String,
    pub(crate) exit_code: Option<i32>,
    pub(crate) signal: Option<i32>,
    /// Nothing the job started is left and its final state is written.
    pub(crate) finished: bool,
    /// Processes still in the job's session, the program included.
    pub(crate) processes: u32,
    pub(crate) pid: Option<u32>,
    /// Milliseconds since the Unix epoch.
    pub(crate) started_at_ms: u64,
    pub(crate) ended_at_ms: Option<u64>,
    pub(crate) stdout_bytes: u64,
    pub(crate) stderr_bytes: u64,
}

impl From<&JobInfo> for JobView {
    fn from(info: &JobInfo) -> Self {
        let (state, exit_code, signal) = match info.state {
            JobState::Running => ("running", None, None),
            JobState::Exited { code } => ("exited", Some(code), None),
            JobState::Signaled { signal } => ("signaled", None, Some(signal)),
            JobState::Lost => ("lost", None, None),
        };
        Self {
            job_id: info.job_id.clone(),
            name: info.name.clone(),
            command: crate::escape_control(&info.argv_summary).into_owned(),
            state: state.to_owned(),
            exit_code,
            signal,
            finished: info.finished,
            processes: info.processes,
            pid: info.pid,
            started_at_ms: info.started_at_ms,
            ended_at_ms: info.ended_at_ms,
            stdout_bytes: info.stdout_total,
            stderr_bytes: info.stderr_total,
        }
    }
}

/// A file's metadata as results show it.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct StatView {
    /// `file`, `dir`, `symlink` or `other`.
    pub(crate) kind: String,
    pub(crate) size: u64,
    /// The permission bits in octal, such as `644`.
    pub(crate) mode: String,
    /// Milliseconds since the Unix epoch.
    pub(crate) mtime_ms: i64,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) link_target: Option<String>,
}

impl From<&Stat> for StatView {
    fn from(stat: &Stat) -> Self {
        Self {
            kind: kind_name(stat.kind).to_owned(),
            size: stat.size,
            mode: format!("{:o}", stat.mode),
            mtime_ms: stat.mtime_ms,
            uid: stat.uid,
            gid: stat.gid,
            link_target: stat.link_target.as_deref().map(shown),
        }
    }
}

fn kind_name(kind: FileKind) -> &'static str {
    match kind {
        FileKind::File => "file",
        FileKind::Dir => "dir",
        FileKind::Symlink => "symlink",
        FileKind::Other => "other",
    }
}

/// How an exec ended, for exit codes and summaries.
pub(crate) fn outcome_summary(result: &ExecResult) -> String {
    match &result.outcome {
        Outcome::Exited { code } => format!("exited with {code}"),
        Outcome::Signaled { signal } => format!("killed by signal {signal}"),
        Outcome::TimedOut { killed: true } => "timed out and was stopped".to_owned(),
        Outcome::TimedOut { killed: false } => {
            format!("timed out and still runs as job {}", result.job_id)
        }
        Outcome::FailedToStart { message } => {
            format!("failed to start: {}", crate::escape_control(message))
        }
    }
}

/// An octal mode such as `644` or `0755`.
pub(crate) fn parse_mode(value: &str) -> Result<u32, String> {
    let digits = value.strip_prefix("0o").unwrap_or(value);
    match u32::from_str_radix(digits, 8) {
        Ok(mode) if mode <= 0o7777 && !digits.is_empty() => Ok(mode),
        _ => Err(format!("{value:?} is not an octal mode such as 644")),
    }
}

/// What a transfer did.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Transferred {
    pub(crate) size: u64,
    pub(crate) sha256: [u8; 32],
}

pub(crate) fn hex(digest: &[u8]) -> String {
    use std::fmt::Write as _;
    digest.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// The SHA-256 of a local file.
pub(crate) fn local_sha256(path: &Path) -> Result<(u64, [u8; 32])> {
    let mut file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut size = 0u64;
    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        size += read as u64;
    }
    Ok((size, hasher.finalize().into()))
}

/// Writes a local file to `remote`: one `FileWrite` up to 1 MiB on the
/// shared connection, else a chunked upload on a connection of its own,
/// its SHA-256 checked by ghostd before the file is put in place.
pub(crate) async fn upload(
    pool: &Pool,
    bulk: Option<&Bulk<'_>>,
    local: &Path,
    remote: &[u8],
    mode: Option<u32>,
    create_dirs: bool,
) -> Result<Transferred> {
    let size = fs::metadata(local)
        .with_context(|| format!("inspect {}", local.display()))?
        .len();
    if size <= BULK_THRESHOLD {
        let data = fs::read(local).with_context(|| format!("read {}", local.display()))?;
        let via = bulk.map_or(Via::Short(pool), Via::Bulk);
        return write_file(via, remote, data, mode, create_dirs).await;
    }
    if let Some(bulk) = bulk {
        upload_chunks(bulk, local, remote, mode, create_dirs).await
    } else {
        let bulk = pool.bulk().await?;
        upload_chunks(&bulk, local, remote, mode, create_dirs).await
    }
}

/// One `FileWrite`.
pub(crate) async fn write_file(
    via: Via<'_>,
    remote: &[u8],
    data: Vec<u8>,
    mode: Option<u32>,
    create_dirs: bool,
) -> Result<Transferred> {
    if data.len() > MAX_INLINE {
        bail!(
            "{} bytes are more than one write carries ({MAX_INLINE})",
            data.len()
        );
    }
    match via
        .call(Request::FileWrite {
            path: remote.to_vec(),
            data,
            mode,
            create_dirs,
        })
        .await?
    {
        Response::Written { size, sha256 } => Ok(Transferred { size, sha256 }),
        other => Err(unexpected(&other)),
    }
}

async fn upload_chunks(
    bulk: &Bulk<'_>,
    local: &Path,
    remote: &[u8],
    mode: Option<u32>,
    create_dirs: bool,
) -> Result<Transferred> {
    let mut file = fs::File::open(local).with_context(|| format!("open {}", local.display()))?;
    let handle = match bulk
        .call(Request::UploadBegin {
            path: remote.to_vec(),
            mode,
            create_dirs,
        })
        .await?
    {
        Response::Upload { handle } => handle,
        other => return Err(unexpected(&other)),
    };
    // A transfer dropped halfway (a cancelled tool call) leaves the upload
    // open on this connection; it is then not reused, and ghostd removes
    // the unfinished file when the connection ends.
    let mut unfinished = Unfinished {
        link: bulk.link(),
        ended: false,
    };
    let sent = async {
        let mut hasher = Sha256::new();
        let mut offset = 0u64;
        let mut buffer = vec![0u8; SLICE as usize];
        loop {
            let read = read_full(&mut file, &mut buffer)
                .with_context(|| format!("read {}", local.display()))?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
            bulk.call(Request::UploadChunk {
                handle,
                offset,
                data: buffer[..read].to_vec(),
            })
            .await?;
            offset += read as u64;
        }
        let digest: [u8; 32] = hasher.finalize().into();
        match bulk
            .call(Request::UploadEnd {
                handle,
                sha256: Some(digest),
            })
            .await?
        {
            Response::Written { size, sha256 } => Ok(Transferred { size, sha256 }),
            other => Err(unexpected(&other)),
        }
    }
    .await;
    if sent.is_err() && bulk.link().alive() {
        let _ = bulk.call(Request::UploadAbort { handle }).await;
    }
    unfinished.ended = true;
    sent
}

/// Discards a connection when dropped before the transfer on it ended.
struct Unfinished {
    link: std::sync::Arc<super::conn::Link>,
    ended: bool,
}

impl Drop for Unfinished {
    fn drop(&mut self) {
        if !self.ended {
            self.link.discard();
        }
    }
}

fn read_full(file: &mut fs::File, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buffer.len() {
        match file.read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

pub(crate) async fn stat(via: Via<'_>, remote: &[u8], follow: bool) -> Result<Stat> {
    match via
        .call(Request::FileStat {
            path: remote.to_vec(),
            follow,
        })
        .await?
    {
        Response::Stat(stat) => Ok(stat),
        other => Err(unexpected(&other)),
    }
}

pub(crate) async fn remote_hash(via: Via<'_>, remote: &[u8]) -> Result<(u64, [u8; 32])> {
    match via
        .call(Request::FileHash {
            path: remote.to_vec(),
        })
        .await?
    {
        Response::Hash { size, sha256 } => Ok((size, sha256)),
        other => Err(unexpected(&other)),
    }
}

/// Reads the remote file `remote` whole into the local file `local`
/// (replaced atomically), on a connection of its own when it is larger
/// than 1 MiB, and checks its SHA-256 against ghostd's.
pub(crate) async fn download(
    pool: &Pool,
    bulk: Option<&Bulk<'_>>,
    remote: &[u8],
    local: &Path,
) -> Result<Transferred> {
    let via = bulk.map_or(Via::Short(pool), Via::Bulk);
    let size = stat(via, remote, true).await?.size;
    if size > BULK_THRESHOLD && bulk.is_none() {
        let bulk = pool.bulk().await?;
        return download_via(Via::Bulk(&bulk), remote, local).await;
    }
    download_via(via, remote, local).await
}

async fn download_via(via: Via<'_>, remote: &[u8], local: &Path) -> Result<Transferred> {
    let partial = partial_path(local);
    let result = async {
        let mut file =
            fs::File::create(&partial).with_context(|| format!("create {}", partial.display()))?;
        let mut hasher = Sha256::new();
        let mut offset = 0u64;
        loop {
            let (data, eof) = match via
                .call(Request::FileRead {
                    path: remote.to_vec(),
                    offset,
                    len: SLICE,
                })
                .await?
            {
                Response::FileData { data, eof, .. } => (data, eof),
                other => return Err(unexpected(&other)),
            };
            hasher.update(&data);
            file.write_all(&data)
                .with_context(|| format!("write {}", partial.display()))?;
            offset += data.len() as u64;
            if eof || data.is_empty() {
                break;
            }
        }
        file.sync_all()
            .with_context(|| format!("write {}", partial.display()))?;
        let digest: [u8; 32] = hasher.finalize().into();
        let (size, sha256) = remote_hash(via, remote).await?;
        if size != offset || sha256 != digest {
            bail!(
                "{} changed while it was read (read {offset} bytes, it now has {size}); read it again",
                shown(remote)
            );
        }
        fs::rename(&partial, local)
            .with_context(|| format!("rename {} to {}", partial.display(), local.display()))?;
        Ok(Transferred {
            size,
            sha256: digest,
        })
    }
    .await;
    if result.is_err() {
        let _ = fs::remove_file(&partial);
    }
    result
}

/// A temporary file beside `local`, renamed over it once complete.
pub(crate) fn partial_path(local: &Path) -> PathBuf {
    let mut name = local
        .file_name()
        .map(OsStr::to_os_string)
        .unwrap_or_default();
    name.push(format!(".ghost-partial-{}", std::process::id()));
    local.with_file_name(name)
}

/// Which way a sync copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Direction {
    /// Local to remote.
    Up,
    /// Remote to local.
    Down,
}

/// What a sync did.
#[derive(Clone, Debug, Default, Serialize, JsonSchema)]
pub(crate) struct SyncReport {
    /// Files in the source.
    pub(crate) files: u64,
    /// Files that were the same on both sides (size, then SHA-256).
    pub(crate) unchanged: u64,
    /// Files copied because they were missing or different.
    pub(crate) copied: u64,
    pub(crate) bytes_copied: u64,
    /// Files removed from the destination (with `delete`).
    pub(crate) deleted: u64,
    /// Files of the destination that `delete` left in place: the source
    /// has something at their path that the sync leaves out, such as a
    /// symlink to a directory.
    pub(crate) kept: u64,
    /// Source entries left out: symlinks and special files, and down, files
    /// below a local symlink (a sync never writes through one).
    pub(crate) skipped: u64,
}

/// A file of a tree, by its path relative to the tree's root.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Entry {
    size: u64,
    mode: u32,
}

/// The regular files below `root`, by relative path (`/`-separated).
fn local_tree(root: &Path) -> Result<(BTreeMap<Vec<u8>, Entry>, u64)> {
    let mut files = BTreeMap::new();
    let mut skipped = 0;
    let mut pending = vec![(root.to_path_buf(), Vec::new())];
    while let Some((directory, prefix)) = pending.pop() {
        let entries =
            fs::read_dir(&directory).with_context(|| format!("list {}", directory.display()))?;
        for entry in entries {
            let entry = entry.with_context(|| format!("list {}", directory.display()))?;
            let mut relative = prefix.clone();
            if !relative.is_empty() {
                relative.push(b'/');
            }
            relative.extend_from_slice(entry.file_name().as_bytes());
            let metadata = fs::symlink_metadata(entry.path())
                .with_context(|| format!("inspect {}", entry.path().display()))?;
            if metadata.is_dir() {
                pending.push((entry.path(), relative));
            } else if metadata.is_file() {
                files.insert(
                    relative,
                    Entry {
                        size: metadata.len(),
                        mode: metadata.permissions().mode() & 0o7777,
                    },
                );
            } else {
                skipped += 1;
            }
        }
    }
    Ok((files, skipped))
}

/// The most entries a sync lists on the remote side.
const SYNC_ENTRIES: usize = 100_000;

/// The longest relative path a sync takes from a remote listing (Linux's
/// `PATH_MAX`).
const SYNC_PATH_BYTES: usize = 4096;

/// The remote side of a sync.
#[derive(Debug, Default)]
pub(crate) struct RemoteTree {
    pub(crate) files: BTreeMap<Vec<u8>, Entry>,
    pub(crate) skipped: u64,
    /// Entries listed so far.
    listed: usize,
}

/// A relative path from a remote listing, checked before it names a local
/// file: at most [`SYNC_PATH_BYTES`], not absolute, and every
/// `/`-separated component a plain name (not empty, `.` or `..`, no NUL).
/// A ghostd that answers anything else is refused, so that a compromised
/// target cannot make a sync down write or remove a file outside its
/// `local_dir`.
pub(crate) fn plain_relative(path: &[u8]) -> Result<()> {
    let plain = !path.is_empty()
        && path.len() <= SYNC_PATH_BYTES
        && path
            .split(|byte| *byte == b'/')
            .all(|component| !matches!(component, b"" | b"." | b"..") && !component.contains(&0));
    if !plain {
        bail!(
            "ghostd listed {:?}, which is not a plain relative path; the sync stops",
            shown(path)
        );
    }
    Ok(())
}

/// `base/path`, or `path` for the root.
fn join_relative(base: &[u8], path: &[u8]) -> Vec<u8> {
    let mut joined = base.to_vec();
    if !joined.is_empty() {
        joined.push(b'/');
    }
    joined.extend_from_slice(path);
    joined
}

impl RemoteTree {
    /// Adds one listing of the directory `base` (relative to the tree's
    /// root, empty for the root), and answers the directories it shows
    /// nothing below: empty ones, ones ghostd could not enter (it lists an
    /// unreadable directory without its entries), and ones deeper than one
    /// listing goes. Each of them is listed on its own next, so that a sync
    /// never takes a part of the tree it did not see for a part that is
    /// not there.
    pub(crate) fn add(&mut self, base: &[u8], entries: &[(Vec<u8>, Stat)]) -> Result<Vec<Vec<u8>>> {
        self.listed += entries.len();
        if self.listed > SYNC_ENTRIES {
            bail!(
                "the remote directory holds more than {SYNC_ENTRIES} entries, more than a sync lists"
            );
        }
        let mut pending = Vec::new();
        for (index, (path, stat)) in entries.iter().enumerate() {
            plain_relative(path)?;
            let relative = join_relative(base, path);
            plain_relative(&relative)?;
            match stat.kind {
                FileKind::File => {
                    self.files.insert(
                        relative,
                        Entry {
                            size: stat.size,
                            mode: stat.mode,
                        },
                    );
                }
                FileKind::Dir => {
                    // Listings go depth first: what is below a directory
                    // follows it at once.
                    let entered = entries.get(index + 1).is_some_and(|(next, _)| {
                        next.len() > path.len()
                            && next.starts_with(path)
                            && next[path.len()] == b'/'
                    });
                    if !entered {
                        pending.push(relative);
                    }
                }
                FileKind::Symlink | FileKind::Other => self.skipped += 1,
            }
        }
        Ok(pending)
    }
}

/// The regular files below the remote `root`, by relative path; an absent
/// root is an empty tree. A directory that cannot be listed stops the
/// sync: what it holds is not known, so nothing may be taken as missing.
async fn remote_tree(via: Via<'_>, root: &[u8]) -> Result<RemoteTree> {
    let mut tree = RemoteTree::default();
    let mut pending = vec![Vec::new()];
    while let Some(base) = pending.pop() {
        let path = if base.is_empty() {
            root.to_vec()
        } else {
            join_remote(root, &base)
        };
        let listing = via
            .call(Request::FileList {
                path: path.clone(),
                depth: 16,
                max_entries: u32::try_from(SYNC_ENTRIES).unwrap_or(u32::MAX),
            })
            .await;
        let entries = match listing {
            Ok(Response::Listing {
                entries,
                truncated: false,
            }) => entries,
            // More entries than one listing answers, or an entry ghostd
            // cannot read (a directory readable but not searchable): what
            // it holds is not known.
            Ok(Response::Listing {
                truncated: true, ..
            }) => bail!(
                "the listing of {} on the target is incomplete (more entries than a sync lists, or an entry ghostd cannot read), so the sync does not know what it holds",
                shown(&path)
            ),
            Ok(other) => return Err(unexpected(&other)),
            Err(error) if base.is_empty() && is_remote(&error, ErrorKind::NotFound) => {
                return Ok(tree);
            }
            Err(error) => {
                return Err(error.context(format!(
                    "cannot list {} on the target, so the sync does not know what it holds",
                    shown(&path)
                )));
            }
        };
        pending.extend(tree.add(&base, &entries)?);
    }
    Ok(tree)
}

/// Whether the remote `path` is not there: a sync down removes a local
/// file only when ghostd says so, whatever its listing showed.
async fn remote_absent(via: Via<'_>, path: &[u8]) -> Result<bool> {
    match stat(via, path, false).await {
        Ok(_) => Ok(false),
        Err(error) if is_remote(&error, ErrorKind::NotFound) => Ok(true),
        Err(error) => Err(error.context(format!(
            "cannot see whether {} is on the target, so the sync does not remove its local copy",
            shown(path)
        ))),
    }
}

/// Whether the local `path` is not there, as [`remote_absent`] the other
/// way round.
fn local_absent(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            Ok(true)
        }
        Err(error) => Err(error).with_context(|| format!("inspect {}", path.display())),
    }
}

/// Whether a directory between `root` and the file `relative` names is a
/// local symlink: a sync down never writes through one.
fn through_local_link(root: &Path, relative: &[u8]) -> Result<bool> {
    let mut path = root.to_path_buf();
    let mut components: Vec<&[u8]> = relative.split(|byte| *byte == b'/').collect();
    components.pop();
    for component in components {
        path.push(OsStr::from_bytes(component));
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() => return Ok(true),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => {
                return Err(error).with_context(|| format!("inspect {}", path.display()));
            }
        }
    }
    Ok(false)
}

fn join_remote(root: &[u8], relative: &[u8]) -> Vec<u8> {
    let mut path = root.to_vec();
    if !path.is_empty() && !path.ends_with(b"/") {
        path.push(b'/');
    }
    path.extend_from_slice(relative);
    path
}

fn join_local(root: &Path, relative: &[u8]) -> PathBuf {
    root.join(OsStr::from_bytes(relative))
}

/// Makes `remote_dir` hold what `local_dir` holds (`Up`) or the other way
/// round (`Down`): lists both sides, compares each file's size and then its
/// SHA-256, and copies only the files that differ, on a connection of its
/// own. With `delete`, files of the destination that the source lacks are
/// removed. Symlinks and special files are left out; directories are made
/// as files need them.
pub(crate) async fn sync(
    pool: &Pool,
    direction: Direction,
    local_dir: &Path,
    remote_dir: &[u8],
    delete: bool,
) -> Result<SyncReport> {
    let bulk = pool.bulk().await?;
    let via = Via::Bulk(&bulk);
    let mut report = SyncReport::default();
    let (local, local_skipped) = match direction {
        Direction::Up => local_tree(local_dir)?,
        Direction::Down if local_dir.exists() => local_tree(local_dir)?,
        Direction::Down => (BTreeMap::new(), 0),
    };
    let remote = remote_tree(via, remote_dir).await?;
    let (source, destination) = match direction {
        Direction::Up => {
            report.skipped = local_skipped;
            (&local, &remote.files)
        }
        Direction::Down => {
            report.skipped = remote.skipped;
            (&remote.files, &local)
        }
    };
    report.files = source.len() as u64;
    for (relative, entry) in source {
        let local_path = join_local(local_dir, relative);
        let remote_path = join_remote(remote_dir, relative);
        if direction == Direction::Down && through_local_link(local_dir, relative)? {
            report.skipped += 1;
            continue;
        }
        let same = match destination.get(relative) {
            Some(other) if other.size == entry.size => {
                let (_, local_digest) = local_sha256(&local_path)?;
                let (_, remote_digest) = remote_hash(via, &remote_path).await?;
                local_digest == remote_digest
            }
            _ => false,
        };
        if same {
            report.unchanged += 1;
            continue;
        }
        let copied = match direction {
            Direction::Up => {
                upload(
                    pool,
                    Some(&bulk),
                    &local_path,
                    &remote_path,
                    Some(entry.mode),
                    true,
                )
                .await?
            }
            Direction::Down => {
                if let Some(parent) = local_path.parent() {
                    fs::create_dir_all(parent)
                        .with_context(|| format!("create {}", parent.display()))?;
                }
                let copied = download(pool, Some(&bulk), &remote_path, &local_path).await?;
                let _ = fs::set_permissions(&local_path, fs::Permissions::from_mode(entry.mode));
                copied
            }
        };
        report.copied += 1;
        report.bytes_copied += copied.size;
    }
    if delete {
        // A file goes only when the source side says it is not there, not
        // only because a listing did not show it.
        for relative in destination
            .keys()
            .filter(|path| !source.contains_key(*path))
        {
            let local_path = join_local(local_dir, relative);
            let remote_path = join_remote(remote_dir, relative);
            match direction {
                Direction::Up => {
                    if !local_absent(&local_path)? {
                        report.kept += 1;
                        continue;
                    }
                    bulk.call(Request::FileRemove {
                        path: remote_path,
                        recursive: false,
                    })
                    .await?;
                }
                Direction::Down => {
                    if !remote_absent(via, &remote_path).await? {
                        report.kept += 1;
                        continue;
                    }
                    fs::remove_file(&local_path)
                        .with_context(|| format!("remove {}", local_path.display()))?;
                }
            }
            report.deleted += 1;
        }
    }
    Ok(report)
}
