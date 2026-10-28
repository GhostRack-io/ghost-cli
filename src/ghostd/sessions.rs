//! What ghostd 0.2.0 added, for `ghost ghostd` and `ghost mcp`: sessions
//! (programs on a PTY of their own that outlive the connection, read as a
//! screen of text), waits for a condition on the machine, and the machine's
//! state in one answer. A version 1 ghostd has none of them: the calls say
//! that they need ghostd 0.2.0.

use anyhow::{Result, anyhow, bail};
use ghostd_protocol::v1::{self, JobState, Stream};
use ghostd_protocol::v2::{
    self, Condition, Key, LogSource, NamedKey, Proto, Screen, SessionEnd, SessionInfo, SessionSpec,
    Until, WaitSpec,
};
use schemars::JsonSchema;
use serde::Serialize;

use super::conn::Pool;

/// The longest a session read waits for its condition.
pub(crate) const MAX_READ_WAIT_MS: u64 = 60_000;

/// The longest a wait waits.
pub(crate) const MAX_WAIT_SECONDS: u64 = 300;

/// A wait's timeout when none is given.
pub(crate) const DEFAULT_WAIT_SECONDS: u64 = 60;

/// The most lines above the screen a read answers.
pub(crate) const MAX_SCROLLBACK: u32 = 1000;

fn unexpected(response: &v2::Response) -> anyhow::Error {
    anyhow!("ghostd answered with an unexpected {response:?}")
}

/// A named key, as people write it: `Enter`, `Tab`, `Esc`, `Backspace`,
/// `Up`, `PageDown`, `F5`, `Ctrl-C`, `Alt-x` (case does not matter, `-` or
/// `+` after Ctrl and Alt).
pub(crate) fn parse_key(name: &str) -> Result<NamedKey> {
    let lower = name.trim().to_ascii_lowercase();
    let modified = |prefixes: &[&str]| {
        prefixes.iter().find_map(|prefix| {
            lower.strip_prefix(prefix).and_then(|rest| {
                let mut chars = rest.chars();
                match (chars.next(), chars.next()) {
                    (Some(character), None) => Some(character),
                    _ => None,
                }
            })
        })
    };
    if let Some(character) = modified(&["ctrl-", "ctrl+", "c-", "^"]) {
        if character.is_ascii_lowercase() || matches!(character, '[' | '\\' | ']' | '^' | '_') {
            return Ok(NamedKey::Ctrl(character));
        }
        bail!("{name:?}: Ctrl goes with a letter, [, \\, ], ^ or _");
    }
    // Alt keeps the character's case: Alt-x and Alt-X differ.
    let original = name.trim();
    for prefix in ["alt-", "alt+", "m-"] {
        if lower.starts_with(prefix) {
            let rest = &original[prefix.len()..];
            let mut chars = rest.chars();
            if let (Some(character), None) = (chars.next(), chars.next()) {
                return Ok(NamedKey::Alt(character));
            }
        }
    }
    Ok(match lower.as_str() {
        "enter" | "return" => NamedKey::Enter,
        "tab" => NamedKey::Tab,
        "escape" | "esc" => NamedKey::Escape,
        "backspace" => NamedKey::Backspace,
        "delete" | "del" => NamedKey::Delete,
        "up" => NamedKey::Up,
        "down" => NamedKey::Down,
        "left" => NamedKey::Left,
        "right" => NamedKey::Right,
        "home" => NamedKey::Home,
        "end" => NamedKey::End,
        "pageup" | "pgup" => NamedKey::PageUp,
        "pagedown" | "pgdn" => NamedKey::PageDown,
        "insert" | "ins" => NamedKey::Insert,
        "f1" => NamedKey::F1,
        "f2" => NamedKey::F2,
        "f3" => NamedKey::F3,
        "f4" => NamedKey::F4,
        "f5" => NamedKey::F5,
        "f6" => NamedKey::F6,
        "f7" => NamedKey::F7,
        "f8" => NamedKey::F8,
        "f9" => NamedKey::F9,
        "f10" => NamedKey::F10,
        "f11" => NamedKey::F11,
        "f12" => NamedKey::F12,
        _ => bail!(
            "{name:?} is not a key this knows: Enter, Tab, Escape, Backspace, Delete, Up, Down, Left, Right, Home, End, PageUp, PageDown, Insert, F1-F12, Ctrl-<letter>, Alt-<character>"
        ),
    })
}

/// One thing to type: text as it is, or a named key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Input {
    Text(String),
    Key(String),
}

/// The keys of `inputs`, in their order.
pub(crate) fn keys(inputs: &[Input]) -> Result<Vec<Key>> {
    inputs
        .iter()
        .map(|input| match input {
            Input::Text(text) => Ok(Key::Text(text.clone())),
            Input::Key(name) => parse_key(name).map(Key::Named),
        })
        .collect()
}

/// Starts a session; answers its ID. Its ID is chosen here, so that a start
/// sent again after a lost connection takes the first one up.
pub(crate) async fn start(pool: &Pool, mut spec: SessionSpec) -> Result<String> {
    if spec.session_id.is_none() {
        spec.session_id = Some(super::conn::fresh_session_id());
    }
    match pool.call2(v2::Request::SessionStart(spec)).await? {
        v2::Response::SessionStarted { session_id } => Ok(session_id),
        other => Err(unexpected(&other)),
    }
}

/// Types `input` into a session; never sent twice.
pub(crate) async fn send(pool: &Pool, session_id: &str, input: Vec<Key>) -> Result<()> {
    if input.is_empty() {
        bail!("nothing to type: give text or keys");
    }
    done(
        pool.call2(v2::Request::SessionSend {
            session_id: session_id.to_owned(),
            input,
        })
        .await?,
    )
}

/// A session's screen, waiting up to `wait_ms` (at most 60 s) for `until`.
pub(crate) async fn read(
    pool: &Pool,
    session_id: &str,
    wait_ms: u64,
    until: Option<Until>,
    scrollback_lines: u32,
) -> Result<Screen> {
    match pool
        .call2(v2::Request::SessionRead {
            session_id: session_id.to_owned(),
            wait_ms: wait_ms.min(MAX_READ_WAIT_MS),
            until,
            scrollback_lines: scrollback_lines.min(MAX_SCROLLBACK),
        })
        .await?
    {
        v2::Response::Screen(screen) => Ok(screen),
        other => Err(unexpected(&other)),
    }
}

pub(crate) async fn list(pool: &Pool) -> Result<Vec<SessionInfo>> {
    match pool.call2(v2::Request::SessionList).await? {
        v2::Response::Sessions(sessions) => Ok(sessions),
        other => Err(unexpected(&other)),
    }
}

pub(crate) async fn close(
    pool: &Pool,
    session_id: &str,
    grace_ms: Option<u64>,
) -> Result<SessionInfo> {
    match pool
        .call2(v2::Request::SessionClose {
            session_id: session_id.to_owned(),
            grace_ms,
        })
        .await?
    {
        v2::Response::Session(info) => Ok(info),
        other => Err(unexpected(&other)),
    }
}

pub(crate) async fn resize(pool: &Pool, session_id: &str, cols: u16, rows: u16) -> Result<()> {
    done(
        pool.call2(v2::Request::SessionResize {
            session_id: session_id.to_owned(),
            cols,
            rows,
        })
        .await?,
    )
}

pub(crate) async fn signal(pool: &Pool, session_id: &str, signal: i32) -> Result<()> {
    done(
        pool.call2(v2::Request::SessionSignal {
            session_id: session_id.to_owned(),
            signal,
        })
        .await?,
    )
}

fn done(response: v2::Response) -> Result<()> {
    match response {
        v2::Response::V1(v1::Response::Done) => Ok(()),
        other => Err(unexpected(&other)),
    }
}

/// What a wait saw.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct WaitView {
    /// The condition held before the timeout.
    pub(crate) met: bool,
    pub(crate) elapsed_ms: u64,
    /// What it saw last, for people.
    pub(crate) detail: String,
}

/// Waits on the machine for `condition`, at most `timeout_seconds` (at most
/// 300); the client waits 30 s longer for the answer.
pub(crate) async fn wait(
    pool: &Pool,
    condition: Condition,
    timeout_seconds: u64,
    interval_ms: Option<u64>,
) -> Result<WaitView> {
    let timeout_ms = timeout_seconds.min(MAX_WAIT_SECONDS).saturating_mul(1000);
    match pool
        .call2(v2::Request::Wait(WaitSpec {
            condition,
            timeout_ms,
            interval_ms,
        }))
        .await?
    {
        v2::Response::Waited {
            met,
            elapsed_ms,
            detail,
        } => Ok(WaitView {
            met,
            elapsed_ms,
            detail: crate::escape_control(&detail).into_owned(),
        }),
        other => Err(unexpected(&other)),
    }
}

/// The condition of a wait, from its parts; exactly one must be given.
#[derive(Clone, Debug, Default)]
pub(crate) struct ConditionParts {
    pub(crate) port: Option<u16>,
    pub(crate) host: Option<String>,
    pub(crate) http: Option<String>,
    pub(crate) status: Option<u16>,
    pub(crate) file_exists: Option<String>,
    pub(crate) file_contains: Option<String>,
    pub(crate) job_output: Option<String>,
    pub(crate) session_output: Option<String>,
    pub(crate) regex: Option<String>,
    pub(crate) stream: Option<Stream>,
    pub(crate) process_gone: Option<u32>,
    pub(crate) job_finished: Option<String>,
    pub(crate) session_exited: Option<String>,
}

impl ConditionParts {
    /// The one condition the parts name; `regex` goes with `file_contains`,
    /// `job_output` and `session_output`, `host` with `port`, `status` with
    /// `http`, `stream` with `job_output`.
    pub(crate) fn condition(self) -> Result<Condition> {
        let given = [
            self.port.is_some(),
            self.http.is_some(),
            self.file_exists.is_some(),
            self.file_contains.is_some(),
            self.job_output.is_some(),
            self.session_output.is_some(),
            self.process_gone.is_some(),
            self.job_finished.is_some(),
            self.session_exited.is_some(),
        ]
        .iter()
        .filter(|given| **given)
        .count();
        if given != 1 {
            bail!(
                "give exactly one condition: port, http, file_exists, file_contains, job_output, session_output, process_gone, job_finished or session_exited"
            );
        }
        let needs_regex = self.file_contains.is_some()
            || self.job_output.is_some()
            || self.session_output.is_some();
        if self.regex.is_some() && !needs_regex {
            bail!("regex goes with file_contains, job_output or session_output");
        }
        if self.host.is_some() && self.port.is_none() {
            bail!("host goes with port");
        }
        if self.status.is_some() && self.http.is_none() {
            bail!("status goes with http");
        }
        if self.stream.is_some() && self.job_output.is_none() {
            bail!("stream goes with job_output");
        }
        let regex = || {
            self.regex
                .clone()
                .ok_or_else(|| anyhow!("give the regex to look for"))
        };
        if let Some(port) = self.port {
            return Ok(Condition::PortOpen {
                host: self.host,
                port,
            });
        }
        if let Some(url) = self.http {
            if !url.starts_with("http://") {
                bail!(
                    "{url:?}: a wait asks http:// URLs only (no TLS); for https://, wait for the port"
                );
            }
            return Ok(Condition::HttpStatus {
                url,
                status: self.status,
            });
        }
        if let Some(path) = self.file_exists {
            return Ok(Condition::FileExists {
                path: path.into_bytes(),
            });
        }
        if let Some(path) = &self.file_contains {
            return Ok(Condition::FileContains {
                path: path.clone().into_bytes(),
                regex: regex()?,
            });
        }
        if let Some(job_id) = &self.job_output {
            return Ok(Condition::LogMatches {
                source: LogSource::Job(job_id.clone()),
                stream: self.stream.unwrap_or(Stream::Stdout),
                regex: regex()?,
                from_offset: None,
            });
        }
        if let Some(session_id) = &self.session_output {
            return Ok(Condition::LogMatches {
                source: LogSource::Session(session_id.clone()),
                stream: Stream::Stdout,
                regex: regex()?,
                from_offset: None,
            });
        }
        if let Some(pid) = self.process_gone {
            return Ok(Condition::ProcessGone {
                pid,
                start_time: None,
            });
        }
        if let Some(job_id) = self.job_finished {
            return Ok(Condition::JobFinished { job_id });
        }
        if let Some(session_id) = self.session_exited {
            return Ok(Condition::SessionExited { session_id });
        }
        unreachable!("one condition is given")
    }
}

/// A session as results show it.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct SessionView {
    pub(crate) session_id: String,
    pub(crate) name: Option<String>,
    /// The first four arguments, at most 200 characters.
    pub(crate) command: String,
    /// `running`, `exited`, `signaled` or `lost` (its program's state).
    pub(crate) state: String,
    pub(crate) exit_code: Option<i32>,
    pub(crate) signal: Option<i32>,
    /// Nothing it started is left and its final screen is written.
    pub(crate) finished: bool,
    pub(crate) pid: Option<u32>,
    pub(crate) cols: u16,
    pub(crate) rows: u16,
    /// Milliseconds since the Unix epoch.
    pub(crate) started_at_ms: u64,
    pub(crate) ended_at_ms: Option<u64>,
    /// Every byte of output it produced.
    pub(crate) output_bytes: u64,
}

impl From<&SessionInfo> for SessionView {
    fn from(info: &SessionInfo) -> Self {
        let (state, exit_code, signal) = match info.state {
            JobState::Running => ("running", None, None),
            JobState::Exited { code } => ("exited", Some(code), None),
            JobState::Signaled { signal } => ("signaled", None, Some(signal)),
            JobState::Lost => ("lost", None, None),
        };
        Self {
            session_id: info.session_id.clone(),
            name: info
                .name
                .as_deref()
                .map(|name| crate::escape_control(name).into_owned()),
            command: crate::escape_control(&info.argv_summary).into_owned(),
            state: state.to_owned(),
            exit_code,
            signal,
            finished: info.finished,
            pid: info.pid,
            cols: info.cols,
            rows: info.rows,
            started_at_ms: info.started_at_ms,
            ended_at_ms: info.ended_at_ms,
            output_bytes: info.output_total,
        }
    }
}

/// A session's screen as results show it.
#[derive(Clone, Debug, Default, Serialize, JsonSchema)]
pub(crate) struct ScreenView {
    pub(crate) session_id: String,
    /// The screen's rows, joined with line breaks, without trailing spaces.
    pub(crate) text: String,
    /// The cursor's row and column, from 0.
    pub(crate) cursor_row: u16,
    pub(crate) cursor_col: u16,
    pub(crate) cols: u16,
    pub(crate) rows: u16,
    /// The title the program set.
    pub(crate) title: String,
    /// A full-screen program (vi, less, top) uses the alternate screen.
    pub(crate) alternate_screen: bool,
    /// The lines above the screen, oldest first, when asked for.
    pub(crate) scrollback: Option<String>,
    /// The program has exited.
    pub(crate) exited: bool,
    pub(crate) exit_code: Option<i32>,
    pub(crate) signal: Option<i32>,
    /// Bumped on every output and resize: give it as `since` to wait for
    /// what comes next.
    pub(crate) changed_since: u64,
    /// Whether `until` held when it answered (absent without one).
    pub(crate) until_met: Option<bool>,
    /// The scrollback or the text was cut to fit in one result (the
    /// scrollback's oldest lines first).
    pub(crate) truncated: bool,
}

/// `text` without its first bytes, so that it takes at most `cap` bytes,
/// cut at a character; answers whether it cut.
fn keep_end(text: &mut String, cap: usize) -> bool {
    if text.len() <= cap {
        return false;
    }
    let mut start = text.len() - cap;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    text.drain(..start);
    true
}

/// `text` cut to at most `cap` bytes at a character; answers whether it
/// cut.
fn keep_start(text: &mut String, cap: usize) -> bool {
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

impl ScreenView {
    /// The view of `screen`, its text and scrollback within `cap` bytes
    /// together (counted as JSON at most doubles them: each is capped at
    /// half of `cap`'s share).
    pub(crate) fn new(session_id: &str, screen: Screen, cap: usize) -> Self {
        let (exit_code, signal) = match screen.exited {
            Some(SessionEnd::Exited { code }) => (Some(code), None),
            Some(SessionEnd::Signaled { signal }) => (None, Some(signal)),
            None => (None, None),
        };
        // JSON escapes can double a text: each part gets a quarter.
        let share = cap / 4;
        let mut text = screen.text;
        let mut truncated = keep_start(&mut text, share);
        let scrollback = screen.scrollback.map(|mut scrollback| {
            truncated |= keep_end(&mut scrollback, share);
            scrollback
        });
        Self {
            session_id: session_id.to_owned(),
            text,
            cursor_row: screen.cursor.0,
            cursor_col: screen.cursor.1,
            cols: screen.cols,
            rows: screen.rows,
            title: crate::escape_control(&screen.title).into_owned(),
            alternate_screen: screen.alternate_screen,
            scrollback,
            exited: screen.exited.is_some(),
            exit_code,
            signal,
            changed_since: screen.changed_since,
            until_met: screen.until_met,
            truncated,
        }
    }

    /// The screen's text for a terminal: each line with its control
    /// characters escaped, so a program's output never drives the reader's
    /// terminal.
    pub(crate) fn printable(&self) -> String {
        let lines = |text: &str| {
            text.split('\n')
                .map(|line| crate::escape_control(line).into_owned())
                .collect::<Vec<_>>()
                .join("\n")
        };
        match &self.scrollback {
            Some(scrollback) if !scrollback.is_empty() => {
                format!("{}\n{}", lines(scrollback), lines(&self.text))
            }
            _ => lines(&self.text),
        }
    }
}

/// The machine's state as results show it.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct MachineView {
    pub(crate) hostname: String,
    /// The distribution, as /etc/os-release names it.
    pub(crate) os: String,
    pub(crate) kernel: String,
    pub(crate) arch: String,
    pub(crate) uptime_seconds: u64,
    /// The load averages over 1, 5 and 15 minutes.
    pub(crate) load: [f32; 3],
    pub(crate) cpus: u32,
    pub(crate) memory: MemoryView,
    pub(crate) disks: Vec<DiskView>,
    /// Listening TCP and UDP sockets; the process is known for the user's
    /// own.
    pub(crate) listening: Vec<ListeningView>,
    /// systemd's failed units; absent without systemd.
    pub(crate) failing_units: Option<Vec<String>>,
    /// The kernel's last messages at err or worse.
    pub(crate) kernel_errors: Vec<String>,
    /// The journal's last messages at err or worse.
    pub(crate) journal_errors: Vec<String>,
    /// What could not be read, and why.
    pub(crate) notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[allow(clippy::struct_field_names)] // the unit, as JSON
pub(crate) struct MemoryView {
    pub(crate) total_bytes: u64,
    pub(crate) available_bytes: u64,
    pub(crate) swap_total_bytes: u64,
    pub(crate) swap_free_bytes: u64,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct DiskView {
    pub(crate) mount: String,
    pub(crate) fs: String,
    pub(crate) device: String,
    pub(crate) total_bytes: u64,
    pub(crate) free_bytes: u64,
    /// As df counts it.
    pub(crate) used_percent: u8,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct ListeningView {
    /// `tcp` or `udp`.
    pub(crate) proto: String,
    pub(crate) address: String,
    pub(crate) port: u16,
    pub(crate) pid: Option<u32>,
    pub(crate) process: Option<String>,
}

fn shown(text: &str) -> String {
    crate::escape_control(text).into_owned()
}

fn all_shown(lines: &[String]) -> Vec<String> {
    lines.iter().map(|line| shown(line)).collect()
}

impl From<&v2::Machine> for MachineView {
    fn from(machine: &v2::Machine) -> Self {
        Self {
            hostname: shown(&machine.hostname),
            os: shown(&machine.os),
            kernel: shown(&machine.kernel),
            arch: shown(&machine.arch),
            uptime_seconds: machine.uptime_s,
            load: [machine.load.0, machine.load.1, machine.load.2],
            cpus: machine.cpus,
            memory: MemoryView {
                total_bytes: machine.memory.total,
                available_bytes: machine.memory.available,
                swap_total_bytes: machine.memory.swap_total,
                swap_free_bytes: machine.memory.swap_free,
            },
            disks: machine
                .disks
                .iter()
                .map(|disk| DiskView {
                    mount: shown(&disk.mount),
                    fs: shown(&disk.fs),
                    device: shown(&disk.device),
                    total_bytes: disk.total,
                    free_bytes: disk.free,
                    used_percent: disk.used_pct,
                })
                .collect(),
            listening: machine
                .listening
                .iter()
                .map(|listening| ListeningView {
                    proto: match listening.proto {
                        Proto::Tcp => "tcp",
                        Proto::Udp => "udp",
                    }
                    .to_owned(),
                    address: shown(&listening.address),
                    port: listening.port,
                    pid: listening.pid,
                    process: listening.process.as_deref().map(shown),
                })
                .collect(),
            failing_units: machine.failing_units.as_deref().map(all_shown),
            kernel_errors: all_shown(&machine.kernel_errors),
            journal_errors: all_shown(&machine.journal_errors),
            notes: all_shown(&machine.notes),
        }
    }
}

pub(crate) async fn machine(pool: &Pool) -> Result<MachineView> {
    match pool.call2(v2::Request::MachineState).await? {
        v2::Response::Machine(machine) => Ok(MachineView::from(&*machine)),
        other => Err(unexpected(&other)),
    }
}

fn gib(bytes: u64) -> String {
    #[allow(clippy::cast_precision_loss)]
    let value = bytes as f64 / (1024.0 * 1024.0 * 1024.0);
    format!("{value:.1} GiB")
}

impl MachineView {
    /// A summary in a few lines, for `ghost ghostd state` and a tool's
    /// summary.
    pub(crate) fn summary(&self) -> String {
        let used = self
            .memory
            .total_bytes
            .saturating_sub(self.memory.available_bytes);
        format!(
            "{} ({}, {} {}), up {} h, load {:.2} {:.2} {:.2} on {} CPU(s), memory {} of {} used, {} disk(s), {} listening socket(s), {} failing unit(s), {} kernel and {} journal error(s)",
            self.hostname,
            self.os,
            self.kernel,
            self.arch,
            self.uptime_seconds / 3600,
            self.load[0],
            self.load[1],
            self.load[2],
            self.cpus,
            gib(used),
            gib(self.memory.total_bytes),
            self.disks.len(),
            self.listening.len(),
            self.failing_units.as_ref().map_or(0, Vec::len),
            self.kernel_errors.len(),
            self.journal_errors.len()
        )
    }

    /// The readable form of `ghost ghostd state`.
    pub(crate) fn readable(&self) -> String {
        use std::fmt::Write as _;
        let mut text = String::new();
        let _ = writeln!(text, "{}", self.hostname);
        let _ = writeln!(
            text,
            "  os       {} ({} {})",
            self.os, self.kernel, self.arch
        );
        let _ = writeln!(
            text,
            "  uptime   {} h {} min",
            self.uptime_seconds / 3600,
            self.uptime_seconds % 3600 / 60
        );
        let _ = writeln!(
            text,
            "  load     {:.2} {:.2} {:.2} on {} CPU(s)",
            self.load[0], self.load[1], self.load[2], self.cpus
        );
        let _ = writeln!(
            text,
            "  memory   {} available of {}, swap {} free of {}",
            gib(self.memory.available_bytes),
            gib(self.memory.total_bytes),
            gib(self.memory.swap_free_bytes),
            gib(self.memory.swap_total_bytes)
        );
        for disk in &self.disks {
            let _ = writeln!(
                text,
                "  disk     {} {}% used, {} free of {} ({} on {})",
                disk.mount,
                disk.used_percent,
                gib(disk.free_bytes),
                gib(disk.total_bytes),
                disk.fs,
                disk.device
            );
        }
        for listening in &self.listening {
            let _ = writeln!(
                text,
                "  listen   {} {}:{}{}",
                listening.proto,
                listening.address,
                listening.port,
                listening
                    .process
                    .as_ref()
                    .map(|process| format!(" {process}"))
                    .unwrap_or_default()
            );
        }
        match &self.failing_units {
            Some(units) if !units.is_empty() => {
                let _ = writeln!(text, "  failing  {}", units.join(", "));
            }
            Some(_) => {
                let _ = writeln!(text, "  failing  none");
            }
            None => {}
        }
        for (kind, lines) in [
            ("kernel", &self.kernel_errors),
            ("journal", &self.journal_errors),
        ] {
            for line in lines {
                let _ = writeln!(text, "  {kind:<8} {line}");
            }
        }
        for note in &self.notes {
            let _ = writeln!(text, "  note     {note}");
        }
        text.trim_end().to_owned()
    }
}
