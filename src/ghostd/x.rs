//! `ghost x`: run a program on a target through ghostd, for agents without
//! MCP. It replaces `ssh host 'cmd'` without any quoting: the arguments
//! travel as bytes, the program's stdout and stderr come back byte for byte
//! and ghost exits with the program's code.

use std::{
    ffi::OsString,
    io::{Read as _, Write},
    os::unix::ffi::{OsStrExt as _, OsStringExt as _},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context as _, Result, bail};
use clap::Args;
use ghostd_protocol::v1::{ExecResult, ExecSpec, Outcome, Program, Stream};
use serde_json::json;

use super::{
    conn::Pool,
    ops::{self, MAX_INLINE, Via},
    target::{Resolver, parse_target},
};
use crate::{Cli, OutputFormat, Terminal};

/// ghost's own failures: the error is on stderr.
pub(crate) const OWN_FAILURE: u8 = 255;

/// A timeout, as `timeout(1)` exits.
pub(crate) const TIMED_OUT: u8 = 124;

/// A program that could not be started, as a shell exits for it.
pub(crate) const FAILED_TO_START: u8 = 127;

#[derive(Args)]
#[allow(clippy::struct_excessive_bools)] // its flags
#[command(
    after_help = "Examples:\n  ghost x web-1 -- ls -la /etc\n  ghost x web-1 --cwd /srv/app -- git status\n  ghost x ssh://me@example.com:2222 --script ./deploy.sh -- --fast\n  ghost x web-1 --detach -- ./server --port 8080"
)]
pub(crate) struct XArgs {
    /// The target: an instance ID or name, ssh://[user@]host[:port], or local.
    #[arg(value_parser = super::check_target)]
    target: String,

    /// The user to log in as over SSH (an instance's default is root).
    #[arg(long, value_parser = super::target::parse_user)]
    user: Option<String>,

    /// Look an instance up through the API first, instead of using the
    /// name and address cached for up to 24 hours: a rename, or a new
    /// instance of the name, made elsewhere (the website, another device)
    /// is seen then.
    #[arg(long)]
    refresh: bool,

    /// The working directory (relative to the home directory).
    #[arg(long, value_name = "DIR")]
    cwd: Option<OsString>,

    /// Set a variable for the program (repeatable).
    #[arg(long, value_name = "NAME=VALUE", value_parser = parse_env)]
    env: Vec<(OsString, OsString)>,

    /// Remove a variable from the program's environment (repeatable).
    #[arg(long, value_name = "NAME")]
    unset: Vec<OsString>,

    /// Run it through the user's login shell (for PATH set in ~/.profile).
    #[arg(long)]
    login: bool,

    /// Stop it after this many seconds (default 120).
    #[arg(long, value_name = "SECS")]
    timeout: Option<u64>,

    /// Leave it running as a job when the timeout comes.
    #[arg(long)]
    keep_on_timeout: bool,

    /// Give the program this file as its stdin.
    #[arg(long, value_name = "FILE", conflicts_with = "stdin")]
    stdin_file: Option<PathBuf>,

    /// Give the program ghost's own stdin (read whole first, up to 8 MiB).
    #[arg(long)]
    stdin: bool,

    /// Run this local script file (its #! line, else /bin/sh); the
    /// arguments after -- are its arguments.
    #[arg(long, value_name = "FILE")]
    script: Option<PathBuf>,

    /// Start it as a job that outlives the command and print its ID.
    #[arg(long)]
    detach: bool,

    /// With --detach: the job's name.
    #[arg(long, requires = "detach")]
    name: Option<String>,

    /// The program and its arguments (or the script's arguments).
    #[arg(last = true, value_name = "ARGV")]
    argv: Vec<OsString>,
}

fn parse_env(value: &str) -> Result<(OsString, OsString), String> {
    match value.split_once('=') {
        Some((name, value)) if !name.is_empty() => Ok((name.into(), value.into())),
        _ => Err("must be NAME=VALUE".to_owned()),
    }
}

/// The exit code `ghost x` ends with for `outcome`.
pub(crate) fn exit_code(outcome: &Outcome) -> u8 {
    match outcome {
        Outcome::Exited { code } => u8::try_from(code & 0xff).unwrap_or(OWN_FAILURE),
        Outcome::Signaled { signal } => {
            u8::try_from(128 + (*signal).clamp(0, 127)).unwrap_or(OWN_FAILURE)
        }
        Outcome::TimedOut { .. } => TIMED_OUT,
        Outcome::FailedToStart { .. } => FAILED_TO_START,
    }
}

/// The request's program, stdin and environment.
fn spec(args: &XArgs) -> Result<ExecSpec> {
    let arguments: Vec<Vec<u8>> = args
        .argv
        .iter()
        .map(|arg| arg.as_bytes().to_vec())
        .collect();
    let program = match &args.script {
        Some(path) => {
            let body = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
            if body.len() > MAX_INLINE {
                bail!("{} is larger than 8 MiB", path.display());
            }
            Program::Script {
                body,
                interpreter: None,
                args: arguments,
            }
        }
        None if arguments.is_empty() => {
            bail!("name the program after --, as in `ghost x TARGET -- ls -la`, or give --script")
        }
        None => Program::Argv(arguments),
    };
    let stdin = if args.stdin {
        let mut data = Vec::new();
        std::io::stdin()
            .take(MAX_INLINE as u64 + 1)
            .read_to_end(&mut data)
            .context("read stdin")?;
        if data.len() > MAX_INLINE {
            bail!("stdin holds more than 8 MiB; copy it with `ghost ghostd put` first");
        }
        Some(data)
    } else if let Some(path) = &args.stdin_file {
        let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        if data.len() > MAX_INLINE {
            bail!(
                "{} is larger than 8 MiB; copy it with `ghost ghostd put` first",
                path.display()
            );
        }
        Some(data)
    } else {
        None
    };
    let spec = ExecSpec {
        program,
        stdin,
        env: args
            .env
            .iter()
            .map(|(name, value)| (name.clone().into_vec(), value.clone().into_vec()))
            .collect(),
        env_remove: args
            .unset
            .iter()
            .map(|name| name.as_bytes().to_vec())
            .collect(),
        env_clear: false,
        cwd: args.cwd.as_ref().map(|cwd| cwd.as_bytes().to_vec()),
        login: args.login,
        timeout_ms: args.timeout.map(|seconds| seconds.saturating_mul(1000)),
        output_cap: None,
        keep_on_timeout: args.keep_on_timeout,
        name: args.name.clone(),
        job_id: None,
    };
    ops::check_spec_size(&spec).map_err(|error| {
        anyhow::anyhow!(
            "{error}; copy stdin with `ghost ghostd put` first and give the program its path"
        )
    })?;
    Ok(spec)
}

/// Runs `ghost x` and answers its exit code; ghost's own failures are
/// written to stderr and answered 255.
pub(crate) async fn run(cli: &Cli, args: &XArgs) -> u8 {
    let resolver = Arc::new(Resolver::new(
        &cli.globals.api_url,
        cli.globals.seed_file.clone(),
        true,
    ));
    let target = match parse_target(&args.target) {
        Ok(target) => target,
        Err(error) => return failed(&anyhow::anyhow!(error)),
    };
    let pool = Pool::new(&args.target, target, args.user.clone(), resolver);
    if args.refresh
        && let Err(error) = pool.refresh().await
    {
        return failed(&error);
    }
    let ran = run_on(&pool, args, cli.output_format()).await;
    super::note_unchecked(&pool);
    match ran {
        Ok(code) => code,
        Err(error) => failed(&error),
    }
}

fn failed(error: &anyhow::Error) -> u8 {
    crate::notice(&crate::render_error(error, Terminal::stderr()));
    OWN_FAILURE
}

async fn run_on(pool: &Pool, args: &XArgs, format: OutputFormat) -> Result<u8> {
    let spec = spec(args)?;
    if args.detach {
        let job_id = ops::job_start(pool, spec).await?;
        let output = if format == OutputFormat::Readable {
            job_id
        } else {
            crate::render_output(&json!({ "job_id": job_id }), format, Terminal::stdout())
        };
        print_line(&output);
        return Ok(0);
    }
    let result = ops::exec(pool, spec).await?;
    if format != OutputFormat::Readable {
        let mut value = result_json(&result);
        if let (Some(object), Some(checked)) = (value.as_object_mut(), pool.host_check()) {
            object.insert("host_check".to_owned(), checked.into());
        }
        print_line(&crate::render_output(&value, format, Terminal::stdout()));
        return Ok(exit_code(&result.outcome));
    }
    write_full(pool, &result, Stream::Stdout, &mut StdSink::Stdout).await?;
    write_full(pool, &result, Stream::Stderr, &mut StdSink::Stderr).await?;
    match &result.outcome {
        Outcome::TimedOut { killed: false } => crate::notice(&format!(
            "ghost: timed out; the program still runs as job {} (ghost ghostd job wait|logs|stop {} {})",
            result.job_id,
            pool.label(),
            result.job_id
        )),
        Outcome::TimedOut { killed: true } => {
            crate::notice("ghost: timed out; the program was stopped");
        }
        Outcome::FailedToStart { message } => crate::notice(&format!(
            "ghost: the program could not be started: {}",
            crate::escape_control(message)
        )),
        Outcome::Exited { .. } | Outcome::Signaled { .. } => {}
    }
    Ok(exit_code(&result.outcome))
}

/// Writes all of a stream: what came before the answer's last bytes from
/// the job's log, then those bytes.
pub(crate) async fn write_full(
    pool: &Pool,
    result: &ExecResult,
    stream: Stream,
    sink: &mut (dyn Write + Send),
) -> Result<()> {
    let output = match stream {
        Stream::Stdout => &result.stdout,
        Stream::Stderr => &result.stderr,
    };
    if output.offset > 0 {
        ops::copy_log(
            Via::Short(pool),
            &result.job_id,
            stream,
            0,
            Some(output.offset),
            sink,
        )
        .await?;
    }
    sink.write_all(&output.data).context("write the output")?;
    sink.flush().context("write the output")
}

/// The result as `--json` prints it.
pub(crate) fn result_json(result: &ExecResult) -> serde_json::Value {
    let (exit_code, signal, timed_out, still_running, failed_to_start) = match &result.outcome {
        Outcome::Exited { code } => (Some(*code), None, false, false, None),
        Outcome::Signaled { signal } => (None, Some(*signal), false, false, None),
        Outcome::TimedOut { killed } => (None, None, true, !killed, None),
        Outcome::FailedToStart { message } => (None, None, false, false, Some(message.clone())),
    };
    let mut value = json!({
        "job_id": result.job_id,
        "exit_code": exit_code,
        "signal": signal,
        "timed_out": timed_out,
        "still_running": still_running,
        "failed_to_start": failed_to_start,
        "stopped": result.stopped,
        "duration_ms": result.duration_ms,
    });
    for (name, output) in [("stdout", &result.stdout), ("stderr", &result.stderr)] {
        if let (Some(object), serde_json::Value::Object(fields)) =
            (value.as_object_mut(), ops::output_json(name, output))
        {
            object.extend(fields);
        }
    }
    value
}

fn print_line(text: &str) {
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{text}");
    let _ = stdout.flush();
}

/// ghost's stdout or stderr; a reader that stopped reading (a closed pipe)
/// gets nothing more, and the program's code is still the exit code.
pub(crate) enum StdSink {
    Stdout,
    Stderr,
}

impl Write for StdSink {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let written = match self {
            Self::Stdout => std::io::stdout().lock().write_all(data),
            Self::Stderr => std::io::stderr().lock().write_all(data),
        };
        match written {
            Err(error) if error.kind() != std::io::ErrorKind::BrokenPipe => Err(error),
            _ => Ok(data.len()),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let flushed = match self {
            Self::Stdout => std::io::stdout().lock().flush(),
            Self::Stderr => std::io::stderr().lock().flush(),
        };
        match flushed {
            Err(error) if error.kind() != std::io::ErrorKind::BrokenPipe => Err(error),
            _ => Ok(()),
        }
    }
}
