//! ghostd, the daemon on an instance for AI agents to work on it: `ghost
//! x` runs a program there, `ghost ghostd` installs and inspects it and
//! moves files, and `ghost mcp` serves its tools to an MCP client over
//! stdio. All of them reach ghostd over the user's own SSH (or, for the
//! target `local`, this machine's `ghostd stdio`).

mod channel;
mod conn;
mod install;
mod mcp;
mod ops;
mod sessions;
mod target;
#[cfg(test)]
mod tests;
mod x;

use std::{
    io::Write as _,
    path::PathBuf,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
use clap::{Args, Subcommand, ValueEnum};
use ghostd_protocol::{
    v1::{Request, Response, Stream},
    v2,
};
use serde_json::{Value, json};

pub(crate) use mcp::McpArgs;
pub(crate) use target::{
    data_file, forget_instance, forget_name, forget_rescue_host_key, remember_rescue_host_key,
    rescue_ssh_command,
};
pub(crate) use x::XArgs;

use conn::Pool;
use ops::{JobView, Via};
use sessions::{Input, ScreenView, SessionView};
use target::{Resolver, parse_target};

use crate::{Cli, OutputFormat, Terminal};

/// For clap: a target, kept as typed so messages name it as the user did.
pub(crate) fn check_target(value: &str) -> Result<String, String> {
    parse_target(value).map(|_| value.to_owned())
}

/// The target of a `ghost ghostd` command.
#[derive(Args, Clone)]
pub(crate) struct TargetArgs {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    #[arg(value_parser = check_target)]
    target: String,

    /// The user to log in as over SSH (an instance's default is root).
    #[arg(long, value_parser = target::parse_user)]
    user: Option<String>,

    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours: a rename, or a new
    /// instance of the name, made elsewhere (the website, another device)
    /// is seen then.
    #[arg(long)]
    refresh: bool,
}

impl TargetArgs {
    async fn pool(&self, cli: &Cli) -> Result<Pool> {
        let target = parse_target(&self.target).map_err(anyhow::Error::msg)?;
        let resolver = Arc::new(Resolver::new(
            &cli.globals.api_url,
            cli.globals.seed_file.clone(),
            true,
        ));
        let pool = Pool::new(&self.target, target, self.user.clone(), resolver);
        if self.refresh {
            pool.refresh().await?;
        }
        Ok(pool)
    }
}

/// Says on stderr that the target's ghostd cannot check the machine's
/// identity, when it is a version 1 ghostd.
pub(crate) fn note_unchecked(pool: &Pool) {
    if let Some(note) = pool.host_check_note() {
        crate::notice(&format!("ghost: {note}"));
    }
}

#[derive(Subcommand)]
pub(crate) enum GhostdCommand {
    /// Install or update ghostd on a target.
    ///
    /// By default the ghostd release channel's current release: ghost
    /// checks its signature and SHA-256, then copies it over SSH (the
    /// target needs only sh, uname and sha256sum; x86-64 only).
    /// --from-source builds it on the target instead. Updating is
    /// installing again: a running ghostd daemon is stopped, the next
    /// connection starts the new binary, and its jobs keep running.
    /// Installing the release that is there already replaces nothing and
    /// leaves its daemon running.
    #[command(
        after_help = "Examples:\n  ghost ghostd install web-1\n  ghost ghostd install ssh://me@example.com --from-source --ref v0.2.0"
    )]
    Install {
        #[command(flatten)]
        target: TargetArgs,
        /// Build ghostd on the target from its public repository instead
        /// (needs a C compiler there; installs Rust for the user when
        /// missing; any machine ghostd builds for).
        #[arg(long)]
        from_source: bool,
        /// With --from-source, the tag, branch or commit to build (default:
        /// the latest tag); implies --from-source.
        #[arg(long = "ref", value_name = "REF", value_parser = install::parse_ref)]
        reference: Option<String>,
    },
    /// Whether ghostd answers on a target, and whether the release channel
    /// has another version.
    Status {
        #[command(flatten)]
        target: TargetArgs,
    },
    /// List, follow and stop jobs on a target.
    Job {
        #[command(subcommand)]
        command: GhostdJobCommand,
    },
    /// Copy a local file to a target (its SHA-256 checked).
    Put {
        #[command(flatten)]
        target: TargetArgs,
        /// The local file.
        local: PathBuf,
        /// The path on the target (relative to the home directory).
        remote: String,
        /// The mode of the written file in octal (default: an existing
        /// file's, else 644).
        #[arg(long, value_parser = ops::parse_mode)]
        mode: Option<u32>,
    },
    /// Copy a file from a target to a local file (its SHA-256 checked).
    Get {
        #[command(flatten)]
        target: TargetArgs,
        /// The path on the target (relative to the home directory).
        remote: String,
        /// The local file.
        local: PathBuf,
    },
    /// Start, type into, read and close sessions: programs on a terminal of
    /// their own that outlive the command (a REPL, an installer that asks
    /// questions). Needs ghostd 0.2.0.
    Session {
        #[command(subcommand)]
        command: GhostdSessionCommand,
    },
    /// Wait on a target for a port, a URL, a file, a job, a session or a
    /// process (exit 0 when it held, 1 when the timeout came first). Needs
    /// ghostd 0.2.0.
    #[command(
        after_help = "Examples:\n  ghost ghostd wait web-1 --port 8080\n  ghost ghostd wait web-1 --http http://127.0.0.1:8080/health --timeout 120\n  ghost ghostd wait web-1 --file /srv/app/ready\n  ghost ghostd wait web-1 --job JOB_ID --matches 'listening on'"
    )]
    Wait(WaitArgs),
    /// The machine's state: OS, uptime, load, memory, disks, listening
    /// ports, failing units and the last kernel and journal errors. Needs
    /// ghostd 0.2.0.
    State {
        #[command(flatten)]
        target: TargetArgs,
    },
    /// Forget what ghost cached about a target: an instance's name and
    /// address, and the host ID learned for it (for every user), so that
    /// the next connection asks the API and learns the host ID again.
    ///
    /// After an `ssh://` or `local` target answered another host ID than
    /// before (another machine, or its ghostd state is new), this accepts
    /// the new one. Spell the target as you used it: `ssh://host` and
    /// `ssh://host:22` are two targets, and the host name's case is ignored.
    Forget {
        /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
        #[arg(value_parser = check_target)]
        target: String,
    },
}

#[derive(Subcommand)]
pub(crate) enum GhostdSessionCommand {
    /// Start a program on a terminal of its own and print the session's
    /// ID (default: the login shell).
    #[command(
        after_help = "Examples:\n  ghost ghostd session start web-1\n  ghost ghostd session start web-1 --name repl -- python3"
    )]
    Start {
        #[command(flatten)]
        target: TargetArgs,
        /// A name for the session, shown in `ghost ghostd session list`.
        #[arg(long)]
        name: Option<String>,
        /// The working directory (relative to the home directory).
        #[arg(long, value_name = "DIR")]
        cwd: Option<String>,
        /// Set a variable for the program (repeatable).
        #[arg(long, value_name = "NAME=VALUE", value_parser = parse_variable)]
        env: Vec<(String, String)>,
        /// The terminal's width (20 to 500, default 120).
        #[arg(long)]
        cols: Option<u16>,
        /// The terminal's height (5 to 200, default 40).
        #[arg(long)]
        rows: Option<u16>,
        /// The program and its arguments (default: the login shell).
        #[arg(last = true, value_name = "ARGV")]
        argv: Vec<String>,
    },
    /// Type into a session: --text and --key, repeated, in their order.
    /// What is typed is never sent twice: after a lost connection, read
    /// the session to see whether it arrived.
    #[command(
        after_help = "Examples:\n  ghost ghostd session send web-1 SESSION_ID --text 'echo hi' --key Enter\n  ghost ghostd session send web-1 SESSION_ID --key Ctrl-C"
    )]
    Send(SendArgs),
    /// Print a session's screen, waiting for a change, a regex or the
    /// program's end first when asked.
    Read {
        #[command(flatten)]
        target: TargetArgs,
        /// The session's ID, from `ghost ghostd session list`.
        session: String,
        /// Wait until the program writes something.
        #[arg(long, conflicts_with_all = ["until", "until_exited"])]
        until_changed: bool,
        /// Wait until this regex matches the screen.
        #[arg(long, value_name = "REGEX", conflicts_with = "until_exited")]
        until: Option<String>,
        /// Wait until the program exits.
        #[arg(long)]
        until_exited: bool,
        /// Wait at most this many seconds (at most 60, default 10).
        #[arg(long, value_name = "SECS")]
        wait: Option<u64>,
        /// Print this many lines above the screen too (at most 1000).
        #[arg(long, value_name = "LINES")]
        scrollback: Option<u32>,
    },
    /// The sessions, live and ended, newest first.
    List {
        #[command(flatten)]
        target: TargetArgs,
    },
    /// Hang a session up and stop everything it started; its last screen
    /// and output stay readable.
    Close {
        #[command(flatten)]
        target: TargetArgs,
        /// The session's ID, from `ghost ghostd session list`.
        session: String,
        /// Seconds between SIGHUP and SIGKILL.
        #[arg(long, value_name = "SECS")]
        grace: Option<u64>,
    },
}

fn parse_variable(value: &str) -> Result<(String, String), String> {
    match value.split_once('=') {
        Some((name, value)) if !name.is_empty() => Ok((name.to_owned(), value.to_owned())),
        _ => Err("must be NAME=VALUE".to_owned()),
    }
}

/// `ghost ghostd session send`'s flags, parsed by clap.
#[derive(Args)]
pub(crate) struct SendFlags {
    #[command(flatten)]
    target: TargetArgs,
    /// The session's ID, from `ghost ghostd session list`.
    session: String,
    /// Text to type as it is (repeatable).
    #[arg(long, value_name = "TEXT")]
    text: Vec<String>,
    /// A key to press (repeatable): Enter, Tab, Escape, Backspace, Delete,
    /// Up, Down, Left, Right, Home, End, `PageUp`, `PageDown`, Insert,
    /// F1-F12, Ctrl-<letter>, Alt-<character>.
    #[arg(long, value_name = "KEY")]
    key: Vec<String>,
}

/// `ghost ghostd session send`: its flags and what to type in the order
/// the command line gave it.
pub(crate) struct SendArgs {
    flags: SendFlags,
    input: Vec<Input>,
}

impl clap::FromArgMatches for SendArgs {
    fn from_arg_matches(matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
        let flags = SendFlags::from_arg_matches(matches)?;
        let mut input: Vec<(usize, Input)> = Vec::new();
        if let Some(indices) = matches.indices_of("text") {
            input.extend(
                indices
                    .zip(&flags.text)
                    .map(|(index, text)| (index, Input::Text(text.clone()))),
            );
        }
        if let Some(indices) = matches.indices_of("key") {
            input.extend(
                indices
                    .zip(&flags.key)
                    .map(|(index, key)| (index, Input::Key(key.clone()))),
            );
        }
        input.sort_by_key(|(index, _)| *index);
        Ok(Self {
            flags,
            input: input.into_iter().map(|(_, input)| input).collect(),
        })
    }

    fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches) -> Result<(), clap::Error> {
        *self = Self::from_arg_matches(matches)?;
        Ok(())
    }
}

impl Args for SendArgs {
    fn augment_args(command: clap::Command) -> clap::Command {
        SendFlags::augment_args(command)
    }

    fn augment_args_for_update(command: clap::Command) -> clap::Command {
        SendFlags::augment_args_for_update(command)
    }
}

/// `ghost ghostd wait`: one condition.
#[derive(Args)]
#[command(group(
    clap::ArgGroup::new("condition")
        .required(true)
        .args(["port", "http", "file", "job", "session", "pid"])
))]
#[command(group(clap::ArgGroup::new("output").args(["job", "session"])))]
pub(crate) struct WaitArgs {
    #[command(flatten)]
    target: TargetArgs,
    /// Until a TCP connection to this port succeeds.
    #[arg(long)]
    port: Option<u16>,
    /// With --port, the host to connect to (default 127.0.0.1).
    #[arg(long, requires = "port")]
    host: Option<String>,
    /// Until this http:// URL answers a GET with a 2xx or 3xx status.
    #[arg(long, value_name = "URL")]
    http: Option<String>,
    /// With --http, the status to wait for.
    #[arg(long, requires = "http")]
    status: Option<u16>,
    /// Until this file exists (relative to the home directory).
    #[arg(long, value_name = "PATH")]
    file: Option<String>,
    /// With --file, until its last 1 MiB matches this regex.
    #[arg(long, value_name = "REGEX", requires = "file")]
    contains: Option<String>,
    /// Until this job finishes.
    #[arg(long, value_name = "ID")]
    job: Option<String>,
    /// Until this session's program exits.
    #[arg(long, value_name = "ID")]
    session: Option<String>,
    /// With --job or --session, until output written after the wait began
    /// matches this regex (a job's stdout, or with --stream its stderr).
    #[arg(long, value_name = "REGEX", requires = "output")]
    matches: Option<String>,
    /// With --job --matches, the stream to look at.
    #[arg(long, value_enum, requires = "matches")]
    stream: Option<StreamArg>,
    /// Until no process with this ID runs.
    #[arg(long, value_name = "PID")]
    pid: Option<u32>,
    /// Give up after this many seconds (at most 300, default 60).
    #[arg(long, value_name = "SECS")]
    timeout: Option<u64>,
}

impl WaitArgs {
    fn condition(&self) -> Result<v2::Condition> {
        let mut parts = sessions::ConditionParts {
            port: self.port,
            host: self.host.clone(),
            http: self.http.clone(),
            status: self.status,
            process_gone: self.pid,
            ..sessions::ConditionParts::default()
        };
        match (&self.file, &self.contains) {
            (Some(path), Some(regex)) => {
                parts.file_contains = Some(path.clone());
                parts.regex = Some(regex.clone());
            }
            (Some(path), None) => parts.file_exists = Some(path.clone()),
            _ => {}
        }
        match (&self.job, &self.matches) {
            (Some(job), Some(regex)) => {
                parts.job_output = Some(job.clone());
                parts.regex = Some(regex.clone());
                parts.stream = self.stream.map(Stream::from);
            }
            (Some(job), None) => parts.job_finished = Some(job.clone()),
            _ => {}
        }
        match (&self.session, &self.matches) {
            (Some(session), Some(regex)) => {
                parts.session_output = Some(session.clone());
                parts.regex = Some(regex.clone());
            }
            (Some(session), None) => parts.session_exited = Some(session.clone()),
            _ => {}
        }
        parts.condition()
    }
}

#[derive(Subcommand)]
pub(crate) enum GhostdJobCommand {
    /// The jobs, newest first.
    List {
        #[command(flatten)]
        target: TargetArgs,
        /// Finished jobs too.
        #[arg(long)]
        all: bool,
        /// At most this many (default 100).
        #[arg(long)]
        limit: Option<u32>,
    },
    /// One job.
    Get {
        #[command(flatten)]
        target: TargetArgs,
        /// The job's ID, from `ghost ghostd job list`.
        job: String,
    },
    /// Wait for a job to finish.
    Wait {
        #[command(flatten)]
        target: TargetArgs,
        /// The job's ID, from `ghost ghostd job list`.
        job: String,
        /// Give up after this many seconds (default: wait until it finishes).
        #[arg(long, value_name = "SECS")]
        timeout: Option<u64>,
    },
    /// Write a job's output: its stdout to stdout and its stderr to stderr.
    Logs {
        #[command(flatten)]
        target: TargetArgs,
        /// The job's ID, from `ghost ghostd job list`.
        job: String,
        /// Only this stream.
        #[arg(long, value_enum)]
        stream: Option<StreamArg>,
        /// Keep writing new output until the job finishes.
        #[arg(long)]
        follow: bool,
    },
    /// Stop a job and everything it started.
    Stop {
        #[command(flatten)]
        target: TargetArgs,
        /// The job's ID, from `ghost ghostd job list`.
        job: String,
        /// Seconds between SIGTERM and SIGKILL.
        #[arg(long, value_name = "SECS")]
        grace: Option<u64>,
    },
    /// Remove a finished job and its logs.
    Remove {
        #[command(flatten)]
        target: TargetArgs,
        /// The job's ID, from `ghost ghostd job list`.
        job: String,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum StreamArg {
    Stdout,
    Stderr,
}

impl From<StreamArg> for Stream {
    fn from(stream: StreamArg) -> Self {
        match stream {
            StreamArg::Stdout => Self::Stdout,
            StreamArg::Stderr => Self::Stderr,
        }
    }
}

/// Runs the commands that write their own output and choose their own
/// exit code: `ghost x`, `ghost mcp`, `ghost ghostd job logs`, `ghost
/// ghostd wait`, `state` and `session read`. `None` for every other
/// command.
pub async fn run_direct(cli: &Cli) -> Option<u8> {
    let crate::Command::Ghostd { command } = &cli.command else {
        return match &cli.command {
            crate::Command::X(args) => Some(x::run(cli, args).await),
            crate::Command::Mcp(args) => Some(match mcp::serve(cli, args).await {
                Ok(()) => 0,
                Err(error) => {
                    crate::notice(&crate::render_error(&error, Terminal::stderr()));
                    1
                }
            }),
            _ => None,
        };
    };
    let ran = match command {
        GhostdCommand::Job {
            command:
                GhostdJobCommand::Logs {
                    target,
                    job,
                    stream,
                    follow,
                },
        } => logs(cli, target, job, *stream, *follow).await.map(|()| 0),
        GhostdCommand::Wait(args) => wait_command(cli, args).await,
        GhostdCommand::State { target } => state_command(cli, target).await,
        GhostdCommand::Session {
            command:
                GhostdSessionCommand::Read {
                    target,
                    session,
                    until_changed,
                    until,
                    until_exited,
                    wait,
                    scrollback,
                },
        } => {
            let until = if *until_changed {
                Some(v2::Until::Changed { since: None })
            } else if *until_exited {
                Some(v2::Until::Exited)
            } else {
                until.clone().map(v2::Until::Matches)
            };
            read_command(cli, target, session, until, *wait, *scrollback).await
        }
        _ => return None,
    };
    Some(match ran {
        Ok(code) => code,
        Err(error) => {
            crate::notice(&crate::render_error(&error, Terminal::stderr()));
            x::OWN_FAILURE
        }
    })
}

/// Prints `value` as JSON, or `readable` in the readable format.
fn print_result(cli: &Cli, value: &Value, readable: &str) {
    let format = cli.output_format();
    let text = if format == OutputFormat::Readable {
        readable.to_owned()
    } else {
        crate::render_output(value, format, Terminal::stdout())
    };
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{text}");
    let _ = stdout.flush();
}

/// `ghost ghostd wait`: 0 when the condition held, 1 when the timeout came
/// first.
async fn wait_command(cli: &Cli, args: &WaitArgs) -> Result<u8> {
    let condition = args.condition()?;
    let pool = args.target.pool(cli).await?;
    let waited = sessions::wait(
        &pool,
        condition,
        args.timeout.unwrap_or(sessions::DEFAULT_WAIT_SECONDS),
        None,
    )
    .await?;
    note_unchecked(&pool);
    let readable = format!(
        "{} after {} ms: {}",
        if waited.met { "met" } else { "not met" },
        waited.elapsed_ms,
        waited.detail
    );
    print_result(cli, &crate::to_value(&waited)?, &readable);
    Ok(u8::from(!waited.met))
}

/// `ghost ghostd state`.
async fn state_command(cli: &Cli, target: &TargetArgs) -> Result<u8> {
    let pool = target.pool(cli).await?;
    let machine = sessions::machine(&pool).await?;
    note_unchecked(&pool);
    print_result(cli, &crate::to_value(&machine)?, &machine.readable());
    Ok(0)
}

/// `ghost ghostd session read`: the screen's text, or the screen as JSON.
async fn read_command(
    cli: &Cli,
    target: &TargetArgs,
    session: &str,
    until: Option<v2::Until>,
    wait: Option<u64>,
    scrollback: Option<u32>,
) -> Result<u8> {
    let pool = target.pool(cli).await?;
    let wait_ms = match (&until, wait) {
        (_, Some(seconds)) => seconds.saturating_mul(1000),
        (Some(_), None) => 10_000,
        (None, None) => 0,
    };
    let screen = sessions::read(&pool, session, wait_ms, until, scrollback.unwrap_or(0)).await?;
    let view = ScreenView::new(session, screen, usize::MAX);
    print_result(cli, &crate::to_value(&view)?, &view.printable());
    Ok(0)
}

/// `ghost ghostd …`, but the commands [`run_direct`] runs.
pub(crate) async fn execute_ghostd(cli: &Cli, command: &GhostdCommand) -> Result<Value> {
    match command {
        GhostdCommand::Install {
            target,
            from_source,
            reference,
        } => {
            let pool = target.pool(cli).await?;
            let source = install_source(&cli.globals.api_url, *from_source, reference.clone());
            let installed = install::install(&pool, &source, |line| {
                crate::notice(line);
            })
            .await?;
            if let Some(note) = &installed.note {
                crate::notice(note);
            }
            crate::to_value(installed)
        }
        GhostdCommand::Status { target } => {
            let pool = target.pool(cli).await?;
            crate::to_value(status(&pool, Some(&cli.globals.api_url)).await?)
        }
        GhostdCommand::Put {
            target,
            local,
            remote,
            mode,
        } => {
            let pool = target.pool(cli).await?;
            let sent = ops::upload(&pool, None, local, &ops::bytes(remote), *mode, true).await?;
            note_unchecked(&pool);
            Ok(json!({
                "path": remote,
                "size": sent.size,
                "sha256": ops::hex(&sent.sha256),
            }))
        }
        GhostdCommand::Get {
            target,
            remote,
            local,
        } => {
            let pool = target.pool(cli).await?;
            let got = ops::download(&pool, None, &ops::bytes(remote), local).await?;
            note_unchecked(&pool);
            Ok(json!({
                "path": local,
                "size": got.size,
                "sha256": ops::hex(&got.sha256),
            }))
        }
        GhostdCommand::Job { command } => execute_job(cli, command).await,
        GhostdCommand::Session { command } => execute_session(cli, command).await,
        GhostdCommand::Forget { target } => {
            let parsed = parse_target(target).map_err(anyhow::Error::msg)?;
            let resolver =
                Resolver::new(&cli.globals.api_url, cli.globals.seed_file.clone(), false);
            let forgotten = resolver.forget_target(&parsed).await?;
            Ok(json!({ "target": target, "forgotten": forgotten }))
        }
        GhostdCommand::Wait(_) | GhostdCommand::State { .. } => {
            bail!("this command writes its own output")
        }
    }
}

async fn execute_session(cli: &Cli, command: &GhostdSessionCommand) -> Result<Value> {
    match command {
        GhostdSessionCommand::Start {
            target,
            name,
            cwd,
            env,
            cols,
            rows,
            argv,
        } => {
            let pool = target.pool(cli).await?;
            let spec = v2::SessionSpec {
                argv: (!argv.is_empty()).then(|| argv.iter().map(|arg| ops::bytes(arg)).collect()),
                env: env
                    .iter()
                    .map(|(name, value)| (ops::bytes(name), ops::bytes(value)))
                    .collect(),
                env_remove: Vec::new(),
                cwd: cwd.as_deref().map(ops::bytes),
                cols: *cols,
                rows: *rows,
                session_id: None,
                name: name.clone(),
            };
            let session_id = sessions::start(&pool, spec).await?;
            note_unchecked(&pool);
            Ok(json!({ "session_id": session_id }))
        }
        GhostdSessionCommand::Send(args) => {
            let keys = sessions::keys(&args.input)?;
            let pool = args.flags.target.pool(cli).await?;
            sessions::send(&pool, &args.flags.session, keys).await?;
            note_unchecked(&pool);
            Ok(json!({ "sent": args.flags.session }))
        }
        GhostdSessionCommand::List { target } => {
            let pool = target.pool(cli).await?;
            let sessions = sessions::list(&pool).await?;
            note_unchecked(&pool);
            crate::to_value(sessions.iter().map(SessionView::from).collect::<Vec<_>>())
        }
        GhostdSessionCommand::Close {
            target,
            session,
            grace,
        } => {
            let pool = target.pool(cli).await?;
            let info = sessions::close(
                &pool,
                session,
                grace.map(|seconds| seconds.saturating_mul(1000)),
            )
            .await?;
            note_unchecked(&pool);
            crate::to_value(SessionView::from(&info))
        }
        GhostdSessionCommand::Read { .. } => {
            bail!("ghost ghostd session read writes its own output")
        }
    }
}

async fn execute_job(cli: &Cli, command: &GhostdJobCommand) -> Result<Value> {
    match command {
        GhostdJobCommand::List { target, all, limit } => {
            let pool = target.pool(cli).await?;
            let jobs = match pool
                .call(Request::JobList {
                    include_finished: *all,
                    limit: limit.unwrap_or(0),
                })
                .await?
            {
                Response::Jobs(jobs) => jobs,
                other => return Err(ops::unexpected(&other)),
            };
            note_unchecked(&pool);
            crate::to_value(jobs.iter().map(JobView::from).collect::<Vec<_>>())
        }
        GhostdJobCommand::Get { target, job } => {
            let pool = target.pool(cli).await?;
            let info = ops::job_info(
                Via::Short(&pool),
                Request::JobStatus {
                    job_id: job.clone(),
                },
            )
            .await?;
            note_unchecked(&pool);
            crate::to_value(JobView::from(&info))
        }
        GhostdJobCommand::Wait {
            target,
            job,
            timeout,
        } => {
            let pool = target.pool(cli).await?;
            let info = wait(&pool, job, timeout.map(Duration::from_secs)).await?;
            note_unchecked(&pool);
            crate::to_value(JobView::from(&info))
        }
        GhostdJobCommand::Stop { target, job, grace } => {
            let pool = target.pool(cli).await?;
            let info = ops::job_info(
                Via::Short(&pool),
                Request::JobStop {
                    job_id: job.clone(),
                    grace_ms: grace.map(|seconds| seconds.saturating_mul(1000)),
                },
            )
            .await?;
            note_unchecked(&pool);
            crate::to_value(JobView::from(&info))
        }
        GhostdJobCommand::Remove { target, job } => {
            let pool = target.pool(cli).await?;
            pool.call(Request::JobRemove {
                job_id: job.clone(),
            })
            .await?;
            note_unchecked(&pool);
            Ok(json!({ "removed": job }))
        }
        GhostdJobCommand::Logs { .. } => bail!("ghost ghostd job logs writes its own output"),
    }
}

/// Waits for a job to finish, in waits of at most 60 s, up to `limit`.
pub(crate) async fn wait(
    pool: &Pool,
    job: &str,
    limit: Option<Duration>,
) -> Result<ghostd_protocol::v1::JobInfo> {
    let started = Instant::now();
    loop {
        let left = limit.map(|limit| limit.saturating_sub(started.elapsed()));
        let wait = left.map_or(Duration::from_mins(1), |left| {
            left.min(Duration::from_mins(1))
        });
        let info = ops::job_info(
            Via::Short(pool),
            Request::JobWait {
                job_id: job.to_owned(),
                timeout_ms: u64::try_from(wait.as_millis()).unwrap_or(60_000),
            },
        )
        .await?;
        if info.finished || left.is_some_and(|left| left.is_zero()) {
            return Ok(info);
        }
        if limit.is_some_and(|limit| started.elapsed() >= limit) {
            return Ok(info);
        }
    }
}

/// The install `ghost ghostd install` and `ghostd_install` run: the
/// channel's release, or with `from_source` (or a ref, which implies it) a
/// build from source.
pub(crate) fn install_source(
    api_url: &str,
    from_source: bool,
    reference: Option<String>,
) -> install::Source {
    if from_source || reference.is_some() {
        install::Source::Source { reference }
    } else {
        install::Source::Channel {
            api_url: api_url.to_owned(),
        }
    }
}

/// What `ghost ghostd status` and `ghostd_status` report.
#[derive(Clone, Debug, serde::Serialize, schemars::JsonSchema)]
pub(crate) struct StatusView {
    pub(crate) target: String,
    /// Where the connection goes: user@host:port, or local.
    pub(crate) endpoint: String,
    /// ghostd's program version, from its hello.
    pub(crate) ghostd_version: String,
    /// The protocol version both sides agreed on.
    pub(crate) protocol_version: u32,
    /// The time of one request and its answer.
    pub(crate) latency_ms: f64,
    /// The ghostd release channel's current release.
    pub(crate) channel_release: Option<String>,
    /// The ghostd version of that release.
    pub(crate) channel_ghostd_version: Option<String>,
    /// Whether the version that answers differs from the channel's (not
    /// known when the channel names none).
    pub(crate) update_available: Option<bool>,
    /// The command that updates it, when it differs.
    pub(crate) update: Option<String>,
    /// Why the channel's release is not known (no channel, or it cannot be
    /// read); ghostd itself answered.
    pub(crate) channel_error: Option<String>,
    /// Whether ghostd checks the machine's identity: every request names
    /// the host ID ghost learned for the target, and a machine with another
    /// one runs nothing (ghostd 0.2.0 and later).
    pub(crate) host_check: bool,
    /// Why it does not, for a ghostd too old to.
    pub(crate) host_check_note: Option<String>,
    /// ghostd's host ID (32 hex digits), made once and kept in its state.
    pub(crate) host_id: Option<String>,
    /// The machine's host name, `/etc/machine-id` and boot ID, as ghostd
    /// answers them.
    pub(crate) hostname: Option<String>,
    pub(crate) machine_id: Option<String>,
    pub(crate) boot_id: Option<String>,
    /// What ghost noticed on the way (MCP results; the command says it on
    /// stderr).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) notice: Option<String>,
}

pub(crate) async fn status(pool: &Pool, api_url: Option<&str>) -> Result<StatusView> {
    let link = pool.short().await?;
    let started = Instant::now();
    pool.call(Request::Ping).await?;
    let latency = started.elapsed();
    let ghostd_version = crate::escape_control(link.server_version()).into_owned();
    let mut view = StatusView {
        target: pool.label().to_owned(),
        endpoint: pool.endpoint().await?.describe(),
        ghostd_version,
        protocol_version: link.protocol_version(),
        latency_ms: (latency.as_secs_f64() * 1000.0 * 10.0).round() / 10.0,
        channel_release: None,
        channel_ghostd_version: None,
        update_available: None,
        update: None,
        channel_error: None,
        host_check: link.host_check(),
        host_check_note: pool.host_check_note(),
        host_id: None,
        hostname: None,
        machine_id: None,
        boot_id: None,
        notice: None,
    };
    if link.host_check() {
        match pool.call2(v2::Request::Identify).await? {
            v2::Response::Identity(identity) => {
                let shown = |text: &str| crate::escape_control(text).into_owned();
                view.host_id = Some(identity.host_id.to_string());
                view.hostname = Some(shown(&identity.hostname));
                view.machine_id = identity.machine_id.as_deref().map(shown);
                view.boot_id = identity.boot_id.as_deref().map(shown);
            }
            other => {
                return Err(anyhow::anyhow!(
                    "ghostd answered Identify with an unexpected {other:?}"
                ));
            }
        }
    }
    if let Some(api_url) = api_url {
        match channel_release(api_url, CHANNEL_STATUS_WAIT).await {
            Ok(manifest) => view.compare(&manifest),
            Err(error) => {
                view.channel_error =
                    Some(crate::escape_control(&format!("{error:#}")).into_owned());
            }
        }
    }
    Ok(view)
}

/// How long a status waits for the release channel (the API's
/// `/v1/releases` and the manifest together): ghostd answered already, so a
/// channel that does not answer is only a `channel_error`.
pub(crate) const CHANNEL_STATUS_WAIT: Duration = Duration::from_secs(5);

/// The channel's current release for a status, from the backend at
/// `api_url`, within `wait`. The manifest may come from the CDN's cache.
pub(crate) async fn channel_release(api_url: &str, wait: Duration) -> Result<channel::Manifest> {
    let read = async { channel::current(&channel::source(api_url, false).await?, false).await };
    tokio::time::timeout(wait, read).await.map_err(|_| {
        anyhow::anyhow!(
            "the release channel did not answer within {} s",
            wait.as_secs_f64()
        )
    })?
}

impl StatusView {
    /// Says whether the version that answers is the channel's `manifest`.
    pub(crate) fn compare(&mut self, manifest: &channel::Manifest) {
        self.channel_release = Some(manifest.version.clone());
        self.channel_ghostd_version
            .clone_from(&manifest.ghostd_version);
        self.update_available = manifest
            .ghostd_version
            .as_deref()
            .map(|version| version != self.ghostd_version);
        self.update = (self.update_available == Some(true))
            .then(|| format!("ghost ghostd install {}", self.target));
    }
}

/// `ghost ghostd job logs`: the job's output so far, and with `follow`
/// what comes until it finishes.
async fn logs(
    cli: &Cli,
    target: &TargetArgs,
    job: &str,
    stream: Option<StreamArg>,
    follow: bool,
) -> Result<()> {
    let pool = target.pool(cli).await?;
    let streams: &[Stream] = match stream {
        Some(StreamArg::Stdout) => &[Stream::Stdout],
        Some(StreamArg::Stderr) => &[Stream::Stderr],
        None => &[Stream::Stdout, Stream::Stderr],
    };
    // A followed log keeps a connection of its own.
    let bulk = if follow {
        Some(pool.bulk().await?)
    } else {
        None
    };
    let via = bulk.as_ref().map_or(Via::Short(&pool), Via::Bulk);
    let mut positions = vec![None::<u64>; streams.len()];
    loop {
        let mut ended = true;
        for (stream, position) in streams.iter().zip(positions.iter_mut()) {
            let from = match position {
                Some(position) => *position,
                None => {
                    // Start at the oldest byte the log still keeps.
                    ops::log_slice(via, job, *stream, None, 0)
                        .await?
                        .first_available
                }
            };
            let mut sink = match stream {
                Stream::Stdout => x::StdSink::Stdout,
                Stream::Stderr => x::StdSink::Stderr,
            };
            let (total, done) = ops::copy_log(via, job, *stream, from, None, &mut sink).await?;
            sink.flush().context("write the output")?;
            *position = Some(total.max(from));
            ended &= done;
        }
        if !follow || ended {
            return Ok(());
        }
        // Wait for it to finish or for a second, whichever comes first;
        // the next pass reads what came meanwhile, the last of it once it
        // finished.
        ops::job_info(
            via,
            Request::JobWait {
                job_id: job.to_owned(),
                timeout_ms: 1000,
            },
        )
        .await?;
    }
}
