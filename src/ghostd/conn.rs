//! Connections to a target's ghostd: one spawned `ssh … ghostd stdio` (or
//! a local `ghostd stdio`) each, pooled per target.
//!
//! Short calls (an exec, a job's or a file's metadata, an edit, a search)
//! share the pool's first connection; a bulk transfer takes a connection of
//! its own, at most [`MAX_CONNECTIONS`] in all, and gives it back for reuse
//! when it is done. A dead connection is dropped and the next call opens
//! another.
//!
//! # The host check
//!
//! ghostd 0.2.0 (protocol version 2) has a host ID, made once and kept in
//! its state. A connection that agrees on version 2 names the ID ghost
//! learned for the target with every request, so a ghostd with another ID
//! answers `HostMismatch` and runs nothing; without a learned ID, the
//! connection asks it (`Identify`) and keeps it (trust on first use). A
//! mismatch on an instance is put to the API: the same instance at the same
//! address was reinstalled or its ghostd state is new, so its new ID is
//! kept; another address is connected to. Either way the request, which ran
//! nowhere, is sent once more, never twice. An `ssh://` or `local` target
//! has no one to ask, so a mismatch is refused until `ghost ghostd forget`.
//! A version 1 ghostd (0.1.1) cannot be checked: on a target ghost knows no
//! host ID of, its requests run as before and the results say `host_check:
//! false`; on one it knows an ID of, which answered as a ghostd that checks
//! IDs before, a version 1 answer is put to the API or refused as a
//! mismatch is. A failed lookup forgets nothing, so the host ID ghost knows
//! stays expected until the API answers.

use std::fmt::Write as _;
use std::{
    cell::RefCell,
    future::Future,
    process::Stdio,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Result, anyhow, bail};
use ghostd_client::{ClientError, Connection};
use ghostd_protocol::{
    MAX_FRAME, v1,
    v2::{self, ErrorKind, HostId},
};
use rand_core::{OsRng, RngCore as _};
use tokio::{
    io::AsyncReadExt as _,
    process::{Child, Command},
    sync::{Notify, OwnedSemaphorePermit, Semaphore},
};

use super::target::{Endpoint, NOT_INSTALLED, NOT_INSTALLED_STATUS, Resolved, Resolver, Target};

/// The most connections a pool keeps to one target.
pub(crate) const MAX_CONNECTIONS: usize = 4;

/// A transfer larger than this takes a connection of its own.
pub(crate) const BULK_THRESHOLD: u64 = 1024 * 1024;

/// How much of `ssh`'s stderr is kept for error messages.
const STDERR_KEPT: usize = 4096;

/// How long opening a connection may take, SSH's handshake and ghostd's
/// hello together.
const OPEN_TIMEOUT: Duration = Duration::from_mins(1);

/// How long after an instance was looked up a failed connection to it
/// looks it up again (an address-changing move, a new port forward).
const LOOK_UP_AGAIN_AFTER: Duration = Duration::from_mins(1);

/// What a wait's or a session read's call is given beyond its own timeout
/// before the connection counts as lost.
pub(crate) const CALL_MARGIN: Duration = Duration::from_secs(30);

/// The ghostd version that checks host IDs and has sessions, waits and the
/// machine's state.
pub(crate) const HOST_CHECK_VERSION: &str = "0.2.0";

tokio::task_local! {
    /// The notices of the tool call that runs (see [`collecting`]).
    static NOTICES: RefCell<Vec<String>>;
}

/// Says something the user should know about a call (a host ID ghost
/// learned anew, a target that moved): into the result of the MCP tool
/// call that runs ([`collecting`]), else on stderr.
pub(crate) fn notice(text: &str) {
    let kept = NOTICES
        .try_with(|notices| notices.borrow_mut().push(text.to_owned()))
        .is_ok();
    if !kept {
        crate::notice(&format!("ghost: {text}"));
    }
}

/// Runs `work`, keeping the [`notice`]s it gives for its result.
pub(crate) async fn collecting<F: Future>(work: F) -> (F::Output, Vec<String>) {
    NOTICES
        .scope(RefCell::new(Vec::new()), async {
            let output = work.await;
            let notices = NOTICES.with(RefCell::take);
            (output, notices)
        })
        .await
}

/// ghostd answered a request with an error.
#[derive(Debug)]
pub(crate) struct RemoteError {
    pub(crate) error: v2::Error,
}

impl std::fmt::Display for RemoteError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} ({})",
            self.error.message,
            kind_name(self.error.kind)
        )
    }
}

impl std::error::Error for RemoteError {}

/// The error kind's name, as ghostd's protocol documentation spells it.
pub(crate) fn kind_name(kind: ErrorKind) -> &'static str {
    match kind {
        ErrorKind::NotFound => "NotFound",
        ErrorKind::PermissionDenied => "PermissionDenied",
        ErrorKind::AlreadyExists => "AlreadyExists",
        ErrorKind::InvalidArgument => "InvalidArgument",
        ErrorKind::TooLarge => "TooLarge",
        ErrorKind::Conflict => "Conflict",
        ErrorKind::Busy => "Busy",
        ErrorKind::Io => "Io",
        ErrorKind::Unsupported => "Unsupported",
        ErrorKind::Internal => "Internal",
        ErrorKind::HostMismatch => "HostMismatch",
    }
}

/// Whether `error` is ghostd's answer of `kind`.
pub(crate) fn is_remote(error: &anyhow::Error, kind: ErrorKind) -> bool {
    error
        .downcast_ref::<RemoteError>()
        .is_some_and(|remote| remote.error.kind == kind)
}

/// A connection to ghostd and the process that carries it.
pub(crate) struct Link {
    connection: Connection,
    child: Mutex<Child>,
    #[cfg(test)]
    pid: Option<u32>,
    dead: AtomicBool,
}

impl Link {
    /// Whether the connection can still carry calls.
    pub(crate) fn alive(&self) -> bool {
        if self.dead.load(Ordering::Relaxed) {
            return false;
        }
        let exited = self
            .child
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .try_wait()
            .map_or(true, |status| status.is_some());
        if exited {
            self.dead.store(true, Ordering::Relaxed);
        }
        !exited
    }

    /// The process ID of the spawned `ssh` (or local `ghostd stdio`).
    #[cfg(test)]
    pub(crate) fn pid(&self) -> Option<u32> {
        self.pid
    }

    /// Marks the connection as not to be used again: it is closed once the
    /// pool lets go of it.
    pub(crate) fn discard(&self) {
        self.dead.store(true, Ordering::Relaxed);
    }

    pub(crate) fn server_version(&self) -> &str {
        self.connection.server_version()
    }

    pub(crate) fn protocol_version(&self) -> u32 {
        self.connection.version()
    }

    /// Whether ghostd checks the expected host ID (protocol version 2).
    pub(crate) fn host_check(&self) -> bool {
        self.connection.host_check()
    }

    /// The host ID every request on this connection names.
    #[cfg(test)]
    pub(crate) fn expected_host(&self) -> Option<HostId> {
        self.connection.expected_host()
    }

    fn set_expected_host(&self, host: Option<HostId>) {
        self.connection.set_expected_host(host);
    }

    /// The daemon's identity, asked without naming an expected host ID.
    async fn identify(&self) -> Result<v2::Identity, CallError> {
        match self.call_raw(v2::Request::Identify, None, None).await? {
            v2::Response::Identity(identity) => Ok(identity),
            other => Err(CallError::Request(format!(
                "ghostd answered Identify with an unexpected {other:?}"
            ))),
        }
    }

    /// One call naming the connection's expected host ID, without retries.
    async fn call(
        &self,
        request: v2::Request,
        timeout: Option<Duration>,
    ) -> Result<v2::Response, CallError> {
        let expected = self.connection.expected_host();
        self.call_raw(request, expected, timeout).await
    }

    /// One call naming `expected` as the host ID, without retries. A
    /// request too large for one frame is refused here, before anything is
    /// sent: the connection stays. With `timeout`, a call that is not
    /// answered in time counts as a lost connection, which is dropped.
    async fn call_raw(
        &self,
        request: v2::Request,
        expected: Option<HostId>,
        timeout: Option<Duration>,
    ) -> Result<v2::Response, CallError> {
        if let Err(error) = check_size(&request) {
            return Err(CallError::Request(error));
        }
        let call = self.connection.call_expecting(request, expected);
        let answered = if let Some(timeout) = timeout {
            let Ok(answered) = tokio::time::timeout(timeout, call).await else {
                self.dead.store(true, Ordering::Relaxed);
                return Err(CallError::Lost(format!(
                    "no answer within {} s",
                    timeout.as_secs()
                )));
            };
            answered
        } else {
            call.await
        };
        match answered {
            Ok(response) => Ok(response),
            Err(ClientError::Remote(error)) => match (error.kind, expected) {
                (ErrorKind::HostMismatch, Some(expected)) => Err(CallError::Mismatch {
                    expected,
                    message: error.message,
                }),
                _ => Err(CallError::Remote(error)),
            },
            Err(ClientError::Unsupported(_)) => {
                Err(CallError::TooOld(self.server_version().to_owned()))
            }
            // Only the encoding of the request says this, before sending.
            Err(ClientError::Protocol(message)) if message.starts_with("unencodable message") => {
                Err(CallError::Request(format!(
                    "the request cannot be encoded: {message}"
                )))
            }
            Err(error) => {
                self.dead.store(true, Ordering::Relaxed);
                Err(CallError::Lost(error.to_string()))
            }
        }
    }
}

/// What a frame's header and the request's ID and expected host add to the
/// request.
const FRAME_OVERHEAD: usize = 64;

/// The bytes `request` takes in its frame, encoded as ghostd's protocol
/// encodes it.
pub(crate) fn encoded_size(request: &v2::Request) -> usize {
    postcard::experimental::serialized_size(request).unwrap_or(usize::MAX)
}

/// Refuses a request that does not fit in one frame, naming its size and
/// the limit.
pub(crate) fn check_size(request: &v2::Request) -> Result<(), String> {
    let size = encoded_size(request);
    if size.saturating_add(FRAME_OVERHEAD) > MAX_FRAME {
        return Err(format!(
            "the request takes {} bytes, more than the {} bytes ({} MiB) one request to ghostd carries",
            size,
            MAX_FRAME - FRAME_OVERHEAD,
            MAX_FRAME >> 20
        ));
    }
    Ok(())
}

enum CallError {
    Remote(v2::Error),
    /// The daemon's host ID is not the one the request named: nothing ran.
    Mismatch {
        expected: HostId,
        message: String,
    },
    /// The connection dropped before the answer.
    Lost(String),
    /// The request is newer than the connection's protocol version; ghostd's
    /// version.
    TooOld(String),
    /// The request was refused before it was sent (too large); the
    /// connection is fine.
    Request(String),
}

impl CallError {
    /// The error of a call that is not tried again.
    fn into_error(self, label: &str, request: &v2::Request) -> anyhow::Error {
        match self {
            Self::Remote(error) => RemoteError { error }.into(),
            Self::TooOld(version) => too_old(label, &version, request),
            Self::Request(message) => anyhow!(message),
            Self::Mismatch { message, .. } => anyhow!(
                "ghostd on {label} answers another host ID than the one ghost expects: {message}"
            ),
            Self::Lost(reason) => lost_change(label, request, &reason),
        }
    }
}

/// The error of a change that was cut off by a lost connection and is not
/// sent again.
fn lost_change(label: &str, request: &v2::Request, reason: &str) -> anyhow::Error {
    match request {
        v2::Request::SessionSend { session_id, .. } => anyhow!(
            "the connection to {label} was lost ({reason}); the input may or may not have been typed into session {session_id}, and it is not sent again: read the session to see"
        ),
        v2::Request::SessionSignal { session_id, .. } => anyhow!(
            "the connection to {label} was lost ({reason}); the signal may or may not have reached session {session_id}"
        ),
        v2::Request::SessionResize { session_id, .. }
        | v2::Request::SessionClose { session_id, .. } => anyhow!(
            "the connection to {label} was lost ({reason}); session {session_id} may or may not have changed"
        ),
        v2::Request::V1(request) => anyhow!(
            "the connection to {label} was lost ({reason}); {} may or may not have changed",
            changed_path(request)
        ),
        _ => anyhow!("the connection to {label} was lost ({reason})"),
    }
}

/// Spawns `endpoint`'s command and opens a ghostd connection over it.
async fn open(label: &str, endpoint: &Endpoint) -> Result<Link> {
    let argv = endpoint.argv();
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    if let Endpoint::Local { env, .. } = endpoint {
        command.envs(env.iter().map(|(name, value)| (name, value)));
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn().map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            match endpoint {
                Endpoint::Local { program, .. } => anyhow!(
                    "ghostd is not installed on local: {} is not found (set GHOSTD_BIN or put ghostd on PATH)",
                    program.display()
                ),
                Endpoint::Ssh { .. } => anyhow!("cannot run ssh: it is not installed"),
            }
        } else {
            anyhow!("cannot run {}: {error}", argv[0].to_string_lossy())
        }
    })?;
    #[cfg(test)]
    let pid = child.id();
    let (Some(stdin), Some(stdout), Some(mut stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        return Err(anyhow!("the spawned command has no pipes"));
    };
    let tail = Arc::new(Mutex::new(Vec::new()));
    let kept = Arc::clone(&tail);
    // Keeps the last bytes of stderr; it never waits for the end, since a
    // persisting SSH master may hold stderr open.
    tokio::spawn(async move {
        let mut buffer = vec![0u8; 4096];
        while let Ok(read) = stderr.read(&mut buffer).await {
            if read == 0 {
                break;
            }
            let mut tail = kept
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            tail.extend_from_slice(&buffer[..read]);
            if tail.len() > STDERR_KEPT {
                let cut = tail.len() - STDERR_KEPT;
                tail.drain(..cut);
            }
        }
    });
    let opened = tokio::time::timeout(OPEN_TIMEOUT, Connection::from_io(stdout, stdin)).await;
    let error = match opened {
        Ok(Ok(connection)) => {
            return Ok(Link {
                connection,
                child: Mutex::new(child),
                #[cfg(test)]
                pid,
                dead: AtomicBool::new(false),
            });
        }
        Ok(Err(error)) => Some(error),
        Err(_) => None,
    };
    // Give the command a moment to exit and say why.
    let status = tokio::time::timeout(Duration::from_secs(2), child.wait())
        .await
        .ok()
        .and_then(Result::ok);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let stderr_text = {
        let tail = tail
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        String::from_utf8_lossy(&tail).trim().to_owned()
    };
    let _ = child.start_kill();
    if stderr_text.contains(NOT_INSTALLED)
        || (status.and_then(|status| status.code()) == Some(NOT_INSTALLED_STATUS)
            && !matches!(endpoint, Endpoint::Local { .. }))
    {
        return Err(anyhow!(
            "ghostd is not installed on {label}: ghost ghostd install {label}"
        ));
    }
    if let Some(plain) = without_refused_mux(endpoint, &stderr_text) {
        // The SSH master refused this session (sshd's MaxSessions): this
        // one connection goes on its own.
        return Box::pin(open(label, &plain)).await;
    }
    let shown = crate::escape_control(&stderr_text).into_owned();
    let mut message = match error {
        None => format!(
            "cannot reach ghostd on {label} ({}): no answer within {} s",
            endpoint.describe(),
            OPEN_TIMEOUT.as_secs()
        ),
        Some(ClientError::Refused {
            update: "ghostd", ..
        }) => {
            return Err(too_old_to_reach(label));
        }
        Some(ClientError::NoHello { reason, .. }) => format!(
            "cannot reach ghostd on {label} ({}): no ghostd hello ({reason})",
            endpoint.describe()
        ),
        Some(error) => format!(
            "cannot reach ghostd on {label} ({}): {}",
            endpoint.describe(),
            crate::escape_control(&error.to_string())
        ),
    };
    if !shown.is_empty() {
        message.push_str(match endpoint {
            Endpoint::Ssh { .. } => "; ssh said: ",
            Endpoint::Local { .. } => "; it said: ",
        });
        message.push_str(&shown);
    }
    if let Endpoint::Ssh {
        host_keys: Some(keys),
        ..
    } = endpoint
        && stderr_text.contains("HOST IDENTIFICATION HAS CHANGED")
    {
        let accept = if keys.known_hosts.is_some() {
            format!("`ghost ghostd forget {label}` accepts the new key")
        } else {
            // ghost's own file could not be made: SSH filed the alias in the
            // user's known hosts, which `forget` does not touch.
            format!("`ssh-keygen -R {}` accepts the new key", keys.alias)
        };
        let _ = write!(
            message,
            ". The host key of the instance {label} changed since ghost first saw it (it is kept per instance, not per address): check that the instance was reinstalled or its SSH keys were replaced, and {accept} on the next connection"
        );
    }
    Err(anyhow!(message))
}

/// Whether `ssh`'s stderr says its multiplexing master refused a session
/// (sshd's `MaxSessions` reached, or another mux failure).
pub(crate) fn mux_refused(stderr: &str) -> bool {
    stderr.contains("Session open refused by peer")
        || stderr.contains("mux_client")
        || stderr.contains("muxclient")
        || stderr.contains("MaxSessions")
}

/// `endpoint` without SSH multiplexing, when it multiplexes and `stderr`
/// says the master refused the session.
pub(crate) fn without_refused_mux(endpoint: &Endpoint, stderr: &str) -> Option<Endpoint> {
    match endpoint {
        Endpoint::Ssh {
            control_path: Some(_),
            ..
        } if mux_refused(stderr) => Some(endpoint.without_mux()),
        _ => None,
    }
}

/// The error of a request too new for ghostd on `label`.
fn too_old(label: &str, version: &str, request: &v2::Request) -> anyhow::Error {
    if request.min_version() >= v2::VERSION {
        anyhow!(
            "this needs ghostd {HOST_CHECK_VERSION} or later, and ghostd on {label} is {}: update it with `ghost ghostd install {label}`",
            crate::escape_control(version)
        )
    } else {
        too_old_to_reach(label)
    }
}

fn too_old_to_reach(label: &str) -> anyhow::Error {
    anyhow!("ghostd on {label} is too old for this: update it with `ghost ghostd install {label}`")
}

/// A fresh job ID as ghostd's retry contract has the client choose it: `j`
/// and 16 random lowercase hex digits.
pub(crate) fn fresh_job_id() -> String {
    format!("j{:016x}", OsRng.next_u64())
}

/// A fresh session ID, as a job's: `s` and 16 random lowercase hex digits.
pub(crate) fn fresh_session_id() -> String {
    format!("s{:016x}", OsRng.next_u64())
}

/// Gives an exec, a job start or a session start its own ID when it has
/// none, so that sending it again after a lost answer takes the first one
/// up instead of starting a second.
fn give_id(request: &mut v2::Request) {
    match request {
        v2::Request::V1(v1::Request::Exec(spec) | v1::Request::JobStart(spec))
            if spec.job_id.is_none() =>
        {
            spec.job_id = Some(fresh_job_id());
        }
        v2::Request::SessionStart(spec) if spec.session_id.is_none() => {
            spec.session_id = Some(fresh_session_id());
        }
        _ => {}
    }
}

/// Whether sending `request` again after a lost answer is safe: reads, and
/// an exec, a job start or a session start under its own ID, which ghostd
/// takes up instead of starting a second run. Typing into a session,
/// signalling, resizing and closing one are never sent again.
pub(crate) fn retry_safe(request: &v2::Request) -> bool {
    match request {
        v2::Request::V1(request) => retry_safe_v1(request),
        v2::Request::SessionStart(spec) => spec.session_id.is_some(),
        v2::Request::Identify
        | v2::Request::SessionRead { .. }
        | v2::Request::SessionList
        | v2::Request::SessionLogRead { .. }
        | v2::Request::Wait(_)
        | v2::Request::MachineState => true,
        v2::Request::SessionSend { .. }
        | v2::Request::SessionResize { .. }
        | v2::Request::SessionSignal { .. }
        | v2::Request::SessionClose { .. } => false,
    }
}

fn retry_safe_v1(request: &v1::Request) -> bool {
    match request {
        v1::Request::Exec(spec) | v1::Request::JobStart(spec) => spec.job_id.is_some(),
        v1::Request::Ping
        | v1::Request::JobList { .. }
        | v1::Request::JobStatus { .. }
        | v1::Request::JobWait { .. }
        | v1::Request::JobLogRead { .. }
        | v1::Request::JobStop { .. }
        | v1::Request::FileStat { .. }
        | v1::Request::FileRead { .. }
        | v1::Request::FileWrite { .. }
        | v1::Request::FileList { .. }
        | v1::Request::FileSearch { .. }
        | v1::Request::FileHash { .. } => true,
        v1::Request::JobSignal { .. }
        | v1::Request::JobRemove { .. }
        | v1::Request::UploadBegin { .. }
        | v1::Request::UploadChunk { .. }
        | v1::Request::UploadEnd { .. }
        | v1::Request::UploadAbort { .. }
        | v1::Request::FileEdit { .. }
        | v1::Request::FileRemove { .. }
        | v1::Request::FileRename { .. }
        | v1::Request::FileMkdir { .. } => false,
    }
}

/// How long the client waits for the answer to `request`: a wait's and a
/// session read's own timeout and [`CALL_MARGIN`], so that a long wait is
/// never cut short; other requests wait as long as the connection lives.
pub(crate) fn call_timeout(request: &v2::Request) -> Option<Duration> {
    match request {
        v2::Request::Wait(spec) => Some(Duration::from_millis(spec.timeout_ms) + CALL_MARGIN),
        v2::Request::SessionRead { wait_ms, .. } => {
            Some(Duration::from_millis(*wait_ms) + CALL_MARGIN)
        }
        _ => None,
    }
}

/// What a request that is not retried changes, for the error after a lost
/// connection.
fn changed_path(request: &v1::Request) -> String {
    let path = match request {
        v1::Request::FileEdit { path, .. }
        | v1::Request::FileRemove { path, .. }
        | v1::Request::FileMkdir { path, .. }
        | v1::Request::UploadBegin { path, .. }
        | v1::Request::FileWrite { path, .. } => path.clone(),
        v1::Request::FileRename { from, to, .. } => {
            let mut both = from.clone();
            both.extend_from_slice(b" -> ");
            both.extend_from_slice(to);
            both
        }
        v1::Request::JobSignal { job_id, .. } | v1::Request::JobRemove { job_id } => {
            format!("job {job_id}").into_bytes()
        }
        _ => b"the upload".to_vec(),
    };
    crate::escape_control(&String::from_utf8_lossy(&path)).into_owned()
}

/// A connection and its share of the pool's cap.
struct Held {
    link: Arc<Link>,
    permit: OwnedSemaphorePermit,
}

#[derive(Default)]
struct State {
    /// The connection short calls share.
    short: Option<Held>,
    /// Connections a bulk transfer gave back.
    idle: Vec<Held>,
}

/// The host ID a pool's connections expect.
#[derive(Clone, Debug)]
struct KnownHost {
    /// Its key in the cache (`None` for a fixed endpoint).
    key: Option<String>,
    id: HostId,
    /// It is in the cache file, so its absence there means it was
    /// forgotten.
    stored: bool,
}

/// What the last connection's hello said.
#[derive(Clone, Debug)]
struct Hello {
    host_check: bool,
    ghostd_version: String,
}

/// The connections to one target.
pub(crate) struct Pool {
    label: String,
    source: Source,
    state: Mutex<State>,
    permits: Arc<Semaphore>,
    /// Woken when a bulk connection is given back.
    returned: Notify,
    /// Only one short connection is opened at a time.
    opening_short: tokio::sync::Mutex<()>,
    /// [`LOOK_UP_AGAIN_AFTER`], shorter in tests.
    look_up_again_after: Duration,
    /// The host ID its connections name.
    host: Mutex<Option<KnownHost>>,
    /// One host mismatch is worked out at a time, and a first contact
    /// waits for it.
    recovering: tokio::sync::Mutex<()>,
    /// Counts the mismatches worked out for an instance.
    generation: AtomicU64,
    hello: Mutex<Option<Hello>>,
}

enum Source {
    Target {
        target: Target,
        user: Option<String>,
        resolver: Arc<Resolver>,
        /// The last resolution and when it was made.
        resolved: tokio::sync::Mutex<Option<(Resolved, Instant)>>,
    },
    /// A fixed endpoint (tests); its host ID is kept in memory only.
    #[cfg_attr(not(test), allow(dead_code))]
    Endpoint(Endpoint),
}

/// A connection held for one bulk transfer, given back to the pool when
/// dropped.
pub(crate) struct Bulk<'a> {
    pool: &'a Pool,
    /// The connection; replaced when it drops under a call that is sent
    /// again.
    link: Mutex<Arc<Link>>,
    /// Its share of the pool's cap, kept across a replacement.
    permit: Option<OwnedSemaphorePermit>,
}

impl Bulk<'_> {
    pub(crate) fn link(&self) -> Arc<Link> {
        Arc::clone(
            &self
                .link
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    /// A call on this connection, as [`Pool::call`] makes it on the shared
    /// one: a request that is safe to send again is sent once more on a new
    /// connection of its own when this one drops before the answer, and a
    /// request the host check refused is sent once more when the pool
    /// worked the mismatch out.
    pub(crate) async fn call(&self, request: v1::Request) -> Result<v1::Response> {
        match self.call2(v2::Request::V1(request)).await? {
            v2::Response::V1(response) => Ok(response),
            other => Err(anyhow!(
                "ghostd answered a version 1 request with {other:?}"
            )),
        }
    }

    pub(crate) async fn call2(&self, mut request: v2::Request) -> Result<v2::Response> {
        give_id(&mut request);
        let label = &self.pool.label;
        let retry = retry_safe(&request);
        let timeout = call_timeout(&request);
        let mut lost: Option<String> = None;
        let mut mismatched = false;
        loop {
            let link = self.link();
            let error = match link.call(request.clone(), timeout).await {
                Ok(response) => return Ok(response),
                Err(error) => error,
            };
            match error {
                CallError::Mismatch { expected, message } => {
                    if mismatched {
                        bail!(again_mismatched(label, &message));
                    }
                    mismatched = true;
                    self.pool.recover(&link, expected, &message).await?;
                    link.discard();
                }
                CallError::Lost(reason) if retry => {
                    if let Some(first) = lost {
                        bail!("the connection to {label} was lost twice ({first}; then {reason})");
                    }
                    lost = Some(reason);
                }
                error => return Err(error.into_error(label, &request)),
            }
            let fresh = Arc::new(self.pool.open_link().await.map_err(|error| match &lost {
                Some(reason) => anyhow!(
                    "the connection to {label} was lost ({reason}) and could not be opened again: {error:#}"
                ),
                None => error,
            })?);
            *self
                .link
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = fresh;
        }
    }
}

impl Drop for Bulk<'_> {
    fn drop(&mut self) {
        let link = self.link();
        if let Some(permit) = self.permit.take()
            && link.alive()
        {
            self.pool.state().idle.push(Held { link, permit });
            self.pool.returned.notify_waiters();
        }
    }
}

/// The error of a request refused by the host check a second time.
fn again_mismatched(label: &str, message: &str) -> String {
    format!(
        "ghostd on {label} answered another host ID than expected twice, so ghost stops; nothing was run: {message}"
    )
}

/// The notice of an instance the API has elsewhere than ghost reached it:
/// at another address, or a name that now stands for another instance.
/// `resent`: the request is sent there once more.
fn moved_notice(label: &str, old: &Resolved, fresh: &Resolved, resent: bool) -> String {
    let then = if resent {
        "so ghost connected there and sent the request again"
    } else {
        "so ghost connects there"
    };
    match (old.instance_id, fresh.instance_id) {
        (Some(before), Some(now)) if before != now => format!(
            "{label} now names instance {now} (it named {before}), which the API has at {}, {then}",
            fresh.endpoint.describe()
        ),
        _ => format!(
            "{label} moved: the API has it at {} (it was {}), {then}",
            fresh.endpoint.describe(),
            old.endpoint.describe()
        ),
    }
}

/// A connection or a permit to open one.
enum Lease {
    Idle(Held),
    New(OwnedSemaphorePermit),
}

impl Pool {
    /// A pool for `target`, named `label` in messages.
    pub(crate) fn new(
        label: &str,
        target: Target,
        user: Option<String>,
        resolver: Arc<Resolver>,
    ) -> Self {
        Self::with_source(
            label,
            Source::Target {
                target,
                user,
                resolver,
                resolved: tokio::sync::Mutex::new(None),
            },
        )
    }

    /// A pool for a fixed endpoint.
    #[cfg(test)]
    pub(crate) fn for_endpoint(label: &str, endpoint: Endpoint) -> Self {
        Self::with_source(label, Source::Endpoint(endpoint))
    }

    fn with_source(label: &str, source: Source) -> Self {
        Self {
            label: label.to_owned(),
            source,
            state: Mutex::new(State::default()),
            permits: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            returned: Notify::new(),
            opening_short: tokio::sync::Mutex::new(()),
            look_up_again_after: LOOK_UP_AGAIN_AFTER,
            host: Mutex::new(None),
            recovering: tokio::sync::Mutex::new(()),
            generation: AtomicU64::new(0),
            hello: Mutex::new(None),
        }
    }

    /// This pool, looking an instance up again after a failed connection
    /// once `after` passed since the last lookup (tests).
    #[cfg(test)]
    pub(crate) fn looking_up_again_after(mut self, after: Duration) -> Self {
        self.look_up_again_after = after;
        self
    }

    /// The target as its commands name it.
    pub(crate) fn label(&self) -> &str {
        &self.label
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn known(&self) -> std::sync::MutexGuard<'_, Option<KnownHost>> {
        self.host
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Whether the target's ghostd checks host IDs, once a connection
    /// said so: `false` for a version 1 ghostd.
    pub(crate) fn host_check(&self) -> Option<bool> {
        self.hello
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .map(|hello| hello.host_check)
    }

    /// What results say when the target's ghostd cannot check host IDs.
    pub(crate) fn host_check_note(&self) -> Option<String> {
        let hello = self
            .hello
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()?;
        (!hello.host_check).then(|| {
            format!(
                "ghostd on {label} is {}: update it (ghost ghostd install {label}) to check the machine's identity",
                crate::escape_control(&hello.ghostd_version),
                label = self.label
            )
        })
    }

    /// The target's resolution, made on first use. An instance whose
    /// address came from the cache and whose host ID ghost does not know
    /// yet is looked up through the API before the first contact, so that
    /// the host ID ghost then learns is the one of the address the API
    /// gives.
    async fn resolved(&self) -> Result<Option<Resolved>> {
        let Source::Target {
            target,
            user,
            resolver,
            resolved,
        } = &self.source
        else {
            return Ok(None);
        };
        let mut resolved = resolved.lock().await;
        if let Some((resolved, _)) = &*resolved {
            return Ok(Some(resolved.clone()));
        }
        let mut fresh = resolver.resolve(target, user.as_deref(), false).await?;
        if fresh.cached && self.known_host(Some(&fresh.host_key)).is_none() {
            fresh = resolver.resolve(target, user.as_deref(), true).await?;
        }
        *resolved = Some((fresh.clone(), Instant::now()));
        Ok(Some(fresh))
    }

    /// The endpoint connections go to, resolved on first use.
    pub(crate) async fn endpoint(&self) -> Result<Endpoint> {
        match &self.source {
            Source::Endpoint(endpoint) => Ok(endpoint.clone()),
            Source::Target { .. } => Ok(self
                .resolved()
                .await?
                .map(|resolved| resolved.endpoint)
                .expect("a target resolves")),
        }
    }

    /// The key of the target's host ID in the cache; `None` for a fixed
    /// endpoint.
    async fn host_key(&self) -> Result<Option<String>> {
        Ok(self.resolved().await?.map(|resolved| resolved.host_key))
    }

    /// Looks the target up through the API again now (`--refresh`, an MCP
    /// tool's `refresh`); connections to an address it no longer has are
    /// let go of. Only instances are looked up.
    pub(crate) async fn refresh(&self) -> Result<()> {
        let Source::Target {
            target: target @ Target::Instance(_),
            user,
            resolver,
            resolved,
        } = &self.source
        else {
            return Ok(());
        };
        let fresh = resolver.resolve(target, user.as_deref(), true).await?;
        let mut resolved = resolved.lock().await;
        let changed = resolved.as_ref().is_some_and(|(current, _)| {
            current.endpoint != fresh.endpoint || current.host_key != fresh.host_key
        });
        *resolved = Some((fresh, Instant::now()));
        drop(resolved);
        if changed {
            self.reset();
        }
        Ok(())
    }

    /// The host ID known for `key`: the pool's own, else the cache's.
    fn known_host(&self, key: Option<&str>) -> Option<HostId> {
        let mut known = self.known();
        if let Some(host) = &*known
            && host.key.as_deref() == key
        {
            return Some(host.id);
        }
        let (Some(key), Source::Target { resolver, .. }) = (key, &self.source) else {
            return None;
        };
        let id = resolver.host_id(key)?;
        *known = Some(KnownHost {
            key: Some(key.to_owned()),
            id,
            stored: true,
        });
        Some(id)
    }

    /// Keeps `id` as the host ID of `key`, in the cache too.
    fn learn(&self, key: Option<&str>, id: HostId) {
        let stored = match (key, &self.source) {
            (Some(key), Source::Target { resolver, .. }) => resolver.store_host_id(key, id),
            _ => false,
        };
        *self.known() = Some(KnownHost {
            key: key.map(str::to_owned),
            id,
            stored,
        });
    }

    /// The host ID of `key` as it is now: the cache's, which another call,
    /// another ghost or `ghost ghostd forget` may have changed since a
    /// request was sent; the pool's own without a cache, or when it could
    /// not be written there.
    fn current_host(&self, key: Option<&str>) -> Option<HostId> {
        let mut known = self.known();
        if let (Some(key), Source::Target { resolver, .. }) = (key, &self.source)
            && resolver.has_cache()
        {
            if let Some(id) = resolver.host_id(key) {
                *known = Some(KnownHost {
                    key: Some(key.to_owned()),
                    id,
                    stored: true,
                });
                return Some(id);
            }
            let unwritten = known
                .as_ref()
                .is_some_and(|host| host.key.as_deref() == Some(key) && !host.stored);
            if !unwritten {
                // Forgotten.
                *known = None;
                return None;
            }
        }
        known
            .as_ref()
            .filter(|host| host.key.as_deref() == key)
            .map(|host| host.id)
    }

    /// Makes `link` name the host ID ghost knows for the target, asking
    /// ghostd its ID and keeping it when ghost knows none (trust on first
    /// use). A version 1 ghostd cannot be checked ([`Pool::check_unidentified`]).
    /// `false` when a host mismatch was worked out since `generation`, while
    /// the link was opened: it may go to an address the API no longer gives,
    /// so it is not trusted and another is opened.
    async fn check_host(&self, link: &Link, generation: u64) -> Result<bool> {
        *self
            .hello
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Hello {
            host_check: link.host_check(),
            ghostd_version: link.server_version().to_owned(),
        });
        if !link.host_check() {
            return self.check_unidentified(link, generation).await;
        }
        let key = self.host_key().await?;
        let id = if let Some(id) = self.known_host(key.as_deref()) {
            id
        } else {
            // A first contact waits for a mismatch being worked out, which
            // forgets the host ID once the API has the instance elsewhere,
            // and trusts no link opened before it ended.
            let _one = self.recovering.lock().await;
            if self.generation.load(Ordering::SeqCst) != generation {
                return Ok(false);
            }
            let key = self.host_key().await?;
            if let Some(id) = self.known_host(key.as_deref()) {
                id
            } else {
                let identity = link
                    .identify()
                    .await
                    .map_err(|error| error.into_error(&self.label, &v2::Request::Identify))?;
                self.learn(key.as_deref(), identity.host_id);
                identity.host_id
            }
        };
        link.set_expected_host(Some(id));
        Ok(true)
    }

    /// A version 1 ghostd cannot say its host ID. Without a host ID ghost
    /// knows for the target, it is used unchecked. With one, the target
    /// answered as a ghostd that checks host IDs before, so this is likely
    /// another machine, or ghostd there was replaced by an older one: an
    /// instance is put to the API as a host mismatch is ([`Pool::recover`]),
    /// and an `ssh://` or `local` target is refused until `ghost ghostd
    /// forget` or an update. Nothing was sent on `link` yet. `false` as
    /// [`Pool::check_host`] answers it, also when the API has the instance
    /// at another address, which is connected to instead.
    async fn check_unidentified(&self, link: &Link, generation: u64) -> Result<bool> {
        let _one = self.recovering.lock().await;
        if self.generation.load(Ordering::SeqCst) != generation {
            return Ok(false);
        }
        let key = self.host_key().await?;
        let Some(known) = self.known_host(key.as_deref()) else {
            return Ok(true);
        };
        let label = &self.label;
        let version = crate::escape_control(link.server_version()).into_owned();
        let Source::Target {
            target: Target::Instance(_),
            resolver,
            resolved,
            ..
        } = &self.source
        else {
            if self.current_host(key.as_deref()).is_none() {
                // Forgotten (`ghost ghostd forget`): used unchecked.
                return Ok(true);
            }
            bail!(
                "ghostd on {label} is {version}, which cannot say its host ID, but ghost knows {label} as host {known}: it is another machine, or ghostd there was replaced by an older one. Nothing was run. `ghost ghostd install {label}` updates it, and ghost then checks the host ID again; `ghost ghostd forget {label}` uses it unchecked."
            );
        };
        let why = format!(
            "ghostd on {label} is {version}, which cannot say its host ID, though ghost knows {label} as host {known}"
        );
        let (old, fresh) = self.look_up_again(&why).await?;
        resolver.forget_host(&old.host_key);
        *self.known() = None;
        let same = fresh.instance_id == old.instance_id && fresh.endpoint == old.endpoint;
        if same {
            notice(&format!(
                "ghostd on {label} is {version}, which cannot say its host ID (ghost knew {label} as host {known}): the API still has this instance at {}, so it was reinstalled with an older ghostd or ghostd there was replaced; ghost runs it unchecked: update it (ghost ghostd install {label}) to check the machine's identity again",
                fresh.endpoint.describe()
            ));
        } else {
            notice(&moved_notice(label, &old, &fresh, false));
        }
        *resolved.lock().await = Some((fresh, Instant::now()));
        if same {
            return Ok(true);
        }
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.reset();
        Ok(false)
    }

    /// Looks the instance up through the API again after its ghostd
    /// answered otherwise than ghost expects (`why`): the resolution the
    /// pool had and the API's. Nothing is forgotten before the API answers:
    /// the host ID ghost knows stays expected. When the API does not
    /// answer, the pool lets go of its connections and its resolution, so
    /// that the next call resolves the target again before it trusts any
    /// host ID, and the error says that nothing was run.
    async fn look_up_again(&self, why: &str) -> Result<(Resolved, Resolved)> {
        let label = &self.label;
        let Source::Target {
            target,
            user,
            resolver,
            resolved,
        } = &self.source
        else {
            bail!("{why}, and ghost has no API to ask about {label}, so nothing was run");
        };
        let old = resolved
            .lock()
            .await
            .as_ref()
            .map(|(resolved, _)| resolved.clone())
            .ok_or_else(|| anyhow!("{label} is not resolved"))?;
        match resolver.resolve(target, user.as_deref(), true).await {
            Ok(fresh) => Ok((old, fresh)),
            Err(error) => {
                *resolved.lock().await = None;
                self.reset();
                Err(anyhow!(
                    "{why}, and looking {label} up again failed, so nothing was run: {error:#}"
                ))
            }
        }
    }

    /// Works a host mismatch out: `link` answered that its ghostd's host ID
    /// is not `expected`, and ran nothing. `Ok` when the request may be
    /// sent once more: another call learned the host ID expected now, a
    /// `ghost ghostd forget` dropped the one of an `ssh://` or `local`
    /// target, or the API explained the change of an instance. The pool's
    /// connections are then let go of, so the next one names the host ID
    /// expected now. An error otherwise.
    ///
    /// An instance's host ID that is no longer in the cache (forgotten by
    /// `ghost ghostd forget`, or by a rename or delete in another ghost) is
    /// no reason to trust whatever answers: the API is asked.
    async fn recover(&self, link: &Link, expected: HostId, message: &str) -> Result<()> {
        let _one = self.recovering.lock().await;
        let key = self.host_key().await?;
        let current = self.current_host(key.as_deref());
        let label = &self.label;
        let Source::Target {
            target: Target::Instance(_),
            resolver,
            resolved,
            ..
        } = &self.source
        else {
            if current != Some(expected) {
                self.reset();
                return Ok(());
            }
            let actual = match link.identify().await {
                Ok(identity) => identity.host_id.to_string(),
                Err(_) => "another one".to_owned(),
            };
            bail!(
                "ghostd on {label} answers with host ID {actual}, but ghost knows {label} as host {expected}: it is another machine, or this machine's ghostd state is new (reinstalled or reset). Nothing was run. If the change is expected, `ghost ghostd forget {label}` accepts the new host ID on the next connection."
            );
        };
        if current.is_some_and(|current| current != expected) {
            // Another call worked a mismatch out meanwhile, with the API.
            self.reset();
            return Ok(());
        }
        let why = format!("ghostd on {label} answers another host ID than before ({message})");
        let (old, fresh) = self.look_up_again(&why).await?;
        resolver.forget_host(&old.host_key);
        *self.known() = None;
        if fresh.instance_id == old.instance_id && fresh.endpoint == old.endpoint {
            // The same instance at the same address: reinstalled, or its
            // ghostd state is new.
            let identity = link.identify().await.map_err(|error| {
                error
                    .into_error(label, &v2::Request::Identify)
                    .context(format!("ask ghostd on {label} for its new host ID"))
            })?;
            self.learn(Some(&fresh.host_key), identity.host_id);
            notice(&format!(
                "ghostd on {label} has a new host ID, {} (it was {expected}): the API still has this instance at {}, so it was reinstalled or its ghostd state is new; ghost keeps the new ID and sent the request again",
                identity.host_id,
                fresh.endpoint.describe()
            ));
        } else {
            notice(&moved_notice(label, &old, &fresh, true));
        }
        *resolved.lock().await = Some((fresh, Instant::now()));
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.reset();
        Ok(())
    }

    /// Opens a connection and makes it name the target's host ID. When it
    /// fails for an instance, the instance is looked up again, once, and
    /// the connection opened again if its address changed: always when the
    /// address came from the cache (which is dropped), else when the last
    /// lookup is more than [`LOOK_UP_AGAIN_AFTER`] old, so that a long MCP
    /// session follows a move without asking the API on every failure.
    async fn open_link(&self) -> Result<Link> {
        let mut tries = 0;
        loop {
            let generation = self.generation.load(Ordering::SeqCst);
            let link = self.open_unchecked().await?;
            if self.check_host(&link, generation).await? {
                return Ok(link);
            }
            link.discard();
            tries += 1;
            if tries == 3 {
                bail!(
                    "the host ID of {} changed while ghost connected, three times",
                    self.label
                );
            }
        }
    }

    async fn open_unchecked(&self) -> Result<Link> {
        let endpoint = self.endpoint().await?;
        let error = match open(&self.label, &endpoint).await {
            Ok(link) => return Ok(link),
            Err(error) => error,
        };
        let Source::Target {
            target: target @ Target::Instance(_),
            user,
            resolver,
            resolved,
        } = &self.source
        else {
            return Err(error);
        };
        let mut resolved = resolved.lock().await;
        match resolved.as_ref() {
            // Another call looked it up again meanwhile.
            Some((current, _)) if current.endpoint != endpoint => {
                let endpoint = current.endpoint.clone();
                drop(resolved);
                return open(&self.label, &endpoint).await;
            }
            Some((
                Resolved {
                    cached: true,
                    instance_id: Some(instance_id),
                    ..
                },
                _,
            )) => resolver.forget_address(*instance_id),
            Some((_, looked_up)) if looked_up.elapsed() < self.look_up_again_after => {
                return Err(error);
            }
            _ => {}
        }
        let fresh = match resolver.resolve(target, user.as_deref(), true).await {
            Ok(fresh) => fresh,
            Err(lookup) => {
                return Err(anyhow!(
                    "{error:#}; looking {} up again failed too: {lookup:#}",
                    self.label
                ));
            }
        };
        let changed = fresh.endpoint != endpoint;
        let endpoint = fresh.endpoint.clone();
        *resolved = Some((fresh, Instant::now()));
        drop(resolved);
        if changed {
            open(&self.label, &endpoint).await
        } else {
            Err(error)
        }
    }

    /// Lets go of the pool's connections, so that the next call opens a new
    /// one: after an install, to reach the binary just installed, and
    /// after a host mismatch. A call still running on one finishes on it.
    pub(crate) fn reset(&self) {
        let mut state = self.state();
        if let Some(held) = &state.short {
            held.link.discard();
        }
        state.idle.clear();
    }

    /// An idle connection that is still alive, dropping dead ones.
    fn take_idle(&self) -> Option<Held> {
        let mut state = self.state();
        while let Some(held) = state.idle.pop() {
            if held.link.alive() {
                return Some(held);
            }
        }
        None
    }

    /// An idle connection, or a permit to open one; waits while every
    /// connection is busy.
    async fn lease(&self) -> Result<Lease> {
        loop {
            let notified = self.returned.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(held) = self.take_idle() {
                return Ok(Lease::Idle(held));
            }
            if let Ok(permit) = Arc::clone(&self.permits).try_acquire_owned() {
                return Ok(Lease::New(permit));
            }
            tokio::select! {
                permit = Arc::clone(&self.permits).acquire_owned() => {
                    return Ok(Lease::New(permit?));
                }
                () = &mut notified => {}
            }
        }
    }

    /// The connection short calls share, opened when there is none.
    pub(crate) async fn short(&self) -> Result<Arc<Link>> {
        if let Some(link) = self.live_short() {
            return Ok(link);
        }
        let _opening = self.opening_short.lock().await;
        if let Some(link) = self.live_short() {
            return Ok(link);
        }
        let held = match self.lease().await? {
            Lease::Idle(held) => held,
            Lease::New(permit) => Held {
                link: Arc::new(self.open_link().await?),
                permit,
            },
        };
        let link = Arc::clone(&held.link);
        self.state().short = Some(held);
        Ok(link)
    }

    fn live_short(&self) -> Option<Arc<Link>> {
        let mut state = self.state();
        match &state.short {
            Some(held) if held.link.alive() => Some(Arc::clone(&held.link)),
            Some(_) => {
                // Dropping it frees its permit.
                state.short = None;
                None
            }
            None => None,
        }
    }

    /// A connection of its own for a bulk transfer.
    pub(crate) async fn bulk(&self) -> Result<Bulk<'_>> {
        let held = match self.lease().await? {
            Lease::Idle(held) => held,
            Lease::New(permit) => Held {
                link: Arc::new(self.open_link().await?),
                permit,
            },
        };
        Ok(Bulk {
            pool: self,
            link: Mutex::new(held.link),
            permit: Some(held.permit),
        })
    }

    /// A short call of version 1. Reads, and an exec or job start (given a
    /// job ID here when it has none), are sent again once on a new
    /// connection when the first drops before the answer; a change that is
    /// not idempotent is not, and says it may or may not have happened. A
    /// request the host check refused, which ran nowhere, is sent once more
    /// when the mismatch is worked out ([`Pool::recover`]).
    pub(crate) async fn call(&self, request: v1::Request) -> Result<v1::Response> {
        match self.call2(v2::Request::V1(request)).await? {
            v2::Response::V1(response) => Ok(response),
            other => Err(anyhow!(
                "ghostd answered a version 1 request with {other:?}"
            )),
        }
    }

    /// A short call of either version, as [`Pool::call`] makes it; a
    /// version 2 request on a version 1 ghostd says it needs ghostd
    /// [`HOST_CHECK_VERSION`].
    pub(crate) async fn call2(&self, mut request: v2::Request) -> Result<v2::Response> {
        give_id(&mut request);
        let retry = retry_safe(&request);
        let timeout = call_timeout(&request);
        let mut lost: Option<String> = None;
        let mut mismatched = false;
        loop {
            let link = self.short().await.map_err(|error| match &lost {
                Some(reason) => anyhow!(
                    "the connection to {} was lost ({reason}) and could not be opened again: {error:#}",
                    self.label
                ),
                None => error,
            })?;
            let error = match link.call(request.clone(), timeout).await {
                Ok(response) => return Ok(response),
                Err(error) => error,
            };
            match error {
                CallError::Mismatch { expected, message } => {
                    if mismatched {
                        bail!(again_mismatched(&self.label, &message));
                    }
                    mismatched = true;
                    self.recover(&link, expected, &message).await?;
                }
                CallError::Lost(reason) if retry => {
                    if let Some(first) = lost {
                        bail!(
                            "the connection to {} was lost twice ({first}; then {reason})",
                            self.label
                        );
                    }
                    lost = Some(reason);
                }
                error => return Err(error.into_error(&self.label, &request)),
            }
        }
    }

    /// How many connections the pool holds (tests).
    #[cfg(test)]
    pub(crate) fn connections(&self) -> usize {
        let state = self.state();
        usize::from(state.short.is_some()) + state.idle.len()
    }
}
