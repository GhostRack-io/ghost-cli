//! `ghost ghostd install`: installs or updates ghostd on a target, by
//! default from the backend's ghostd release channel, with `--from-source`
//! by building it there from its public repository's `install.sh`.
//!
//! From the channel, ghost itself checks the release (the manifest's
//! signature under the release key `/v1/releases` names, the archive's
//! SHA-256) and takes `ghostd` out of the archive; the target only runs
//! `uname -sm`, then a fixed script that receives the binary on its stdin,
//! checks its SHA-256 again, puts it in place, runs `ghostd setup` and
//! stops a daemon that runs the old binary. It needs nothing but `sh`,
//! `uname` and `sha256sum` there, and no access to the CDN.
//!
//! Every command run on the target is fixed text; what varies (the git
//! ref, or the release, its commit and the binary's SHA-256) is validated
//! and travels as the script's positional arguments, never inside the
//! script text.

use std::{
    ffi::OsString,
    process::Stdio,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, anyhow, bail};
use ghostd_protocol::v1::Request;
use schemars::JsonSchema;
use serde::Serialize;
use tokio::{
    io::{AsyncBufReadExt as _, BufReader},
    process::Command,
    sync::mpsc,
};

use super::{
    channel::{self, lowercase_hex},
    conn::{Pool, without_refused_mux},
    target::Endpoint,
};

/// The script that installs a given ref from source: `$1` is the ref. It
/// downloads install.sh with curl, else wget (Alpine has busybox wget), to
/// a file first, so that a failed download fails the install.
pub(crate) const INSTALL_REF_SCRIPT: &str = r#"t=$(mktemp) || exit 1; if command -v curl >/dev/null 2>&1; then curl -fsSL -o "$t" "https://raw.githubusercontent.com/gigahost-apps/ghostd/$1/install.sh"; else wget -q -O "$t" "https://raw.githubusercontent.com/gigahost-apps/ghostd/$1/install.sh"; fi && sh "$t" --ref "$1"; r=$?; rm -f "$t"; exit $r"#;

/// The script that installs install.sh's own default (the latest tag, else
/// main) from source, fetched from main.
pub(crate) const INSTALL_DEFAULT_SCRIPT: &str = r#"t=$(mktemp) || exit 1; if command -v curl >/dev/null 2>&1; then curl -fsSL -o "$t" "https://raw.githubusercontent.com/gigahost-apps/ghostd/main/install.sh"; else wget -q -O "$t" "https://raw.githubusercontent.com/gigahost-apps/ghostd/main/install.sh"; fi && sh "$t"; r=$?; rm -f "$t"; exit $r"#;

/// The command that names the target's machine; the channel builds
/// x86-64 only.
pub(crate) const ARCH_COMMAND: &str = "uname -sm";

/// The script that installs a channel release whose binary arrives on its
/// stdin: `$1` is the release, `$2` its commit, `$3` the binary's SHA-256.
/// It installs under `/usr/local` as root, else under `$HOME/.local`, as
/// the channel's install script does, writes a temporary `.ghostd.$$` (one
/// per process, so that two installs at once do not share it), checks its
/// SHA-256, moves it over `ghostd`, runs `ghostd setup`, records the
/// release as the channel's install script does (`lib/gigahost/ghostd-release`:
/// the release and the binary's SHA-256, which that script checks against
/// the binary before it calls the release installed) and stops a daemon
/// that still runs the old binary (its jobs keep running), never failing
/// the install over that.
///
/// When the binary in place already is this one, it is left alone (its
/// stdin is read and dropped), `ghostd setup` and the record run again,
/// and a running daemon is stopped only when it answers with another
/// version than this binary's (it runs an older one, whose stop failed
/// before): installing the release that is there drops no connection.
pub(crate) const CHANNEL_INSTALL_SCRIPT: &str = concat!(
    r#"set -eu; "#,
    r#"if [ "$(id -u)" -eq 0 ]; then p=/usr/local; else p="$HOME/.local"; fi; "#,
    r#"b="$p/bin/ghostd"; "#,
    r#"if [ -f "$b" ] && s=$(sha256sum "$b") && [ "${s%% *}" = "$3" ]; then same=1; cat >/dev/null; "#,
    r#"echo "ghostd install: release $1 is already installed at $b" >&2; "#,
    r#"else same=0; mkdir -p "$p/bin"; n="$p/bin/.ghostd.$$"; cat >"$n"; "#,
    r#"s=$(sha256sum "$n"); "#,
    r#"if [ "${s%% *}" != "$3" ]; then rm -f "$n"; echo "ghostd install: the binary received does not match its SHA-256; nothing was installed" >&2; exit 1; fi; "#,
    r#"chmod 755 "$n"; mv -f "$n" "$b"; "#,
    r#"echo "ghostd install: installed $b (release $1)" >&2; fi; "#,
    r#""$b" setup --origin channel --ref "$1" --commit "$2"; "#,
    r#"mkdir -p "$p/lib/gigahost" && echo "$1 $3" >"$p/lib/gigahost/ghostd-release" || echo "ghostd install: could not record release $1 under $p/lib/gigahost" >&2; "#,
    r#"j=$("$b" status 2>/dev/null) || j=; "#,
    r#"case $j in *running?:true*) "#,
    r#"d=$(printf "%s" "$j" | sed -e "s/.*daemon_version.:.//" -e "s/[^0-9A-Za-z.+-].*//"); "#,
    r#"v=$(printf "%s" "$j" | sed -e "s/.*[^_]version.:.//" -e "s/[^0-9A-Za-z.+-].*//"); "#,
    r#"if [ "$same" = 1 ] && [ -n "$v" ] && [ "$d" = "$v" ]; then echo "ghostd install: the running ghostd daemon runs ghostd $v already, so it keeps running" >&2; "#,
    r#"elif "$b" stop >/dev/null 2>&1; then echo "ghostd install: stopped the running ghostd daemon: the next connection starts the new one (jobs keep running)" >&2; "#,
    r#"else echo "ghostd install: could not stop the running ghostd daemon: run ghostd stop for the new binary to take effect" >&2; fi;; "#,
    r#"esac"#,
);

/// What the channel install says when the binary in place already is the
/// release's.
pub(crate) const ALREADY_INSTALLED: &str = "is already installed at";

/// The arguments of `sh` that install a channel release: `-c SCRIPT`, then
/// `sh` and the validated release, commit and SHA-256 (`$0` to `$3`).
pub(crate) fn channel_arguments(version: &str, commit: &str, sha256: &str) -> Result<Vec<String>> {
    if !gigahost_client_api::release::is_release_version(version) {
        bail!("the release version {version:?} has an invalid format");
    }
    if !lowercase_hex(commit, 40) {
        bail!("the release commit {commit:?} has an invalid format");
    }
    if !lowercase_hex(sha256, 64) {
        bail!("the SHA-256 {sha256:?} has an invalid format");
    }
    Ok(vec![
        "-c".to_owned(),
        CHANNEL_INSTALL_SCRIPT.to_owned(),
        "sh".to_owned(),
        version.to_owned(),
        commit.to_owned(),
        sha256.to_owned(),
    ])
}

/// A git ref to build: 1 to 100 of `A-Z a-z 0-9 . _ / -`, not starting with
/// `-` and without `..`.
pub(crate) fn valid_ref(value: &str) -> Result<(), String> {
    let allowed =
        |byte: u8| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'/' | b'-');
    if value.is_empty() || value.len() > 100 {
        return Err("a ref is 1 to 100 characters".to_owned());
    }
    if !value.bytes().all(allowed) {
        return Err("a ref holds only letters, digits and . _ / -".to_owned());
    }
    if value.starts_with('-') || value.contains("..") {
        return Err("a ref neither starts with - nor holds ..".to_owned());
    }
    Ok(())
}

/// For clap: a `--ref` value.
pub(crate) fn parse_ref(value: &str) -> Result<String, String> {
    valid_ref(value).map(|()| value.to_owned())
}

/// The arguments of `sh` that run the install: `-c SCRIPT` and, for a
/// ref, `sh REF` (`$0` and `$1`).
pub(crate) fn sh_arguments(reference: Option<&str>) -> Result<Vec<String>> {
    match reference {
        Some(reference) => {
            valid_ref(reference).map_err(anyhow::Error::msg)?;
            Ok(vec![
                "-c".to_owned(),
                INSTALL_REF_SCRIPT.to_owned(),
                "sh".to_owned(),
                reference.to_owned(),
            ])
        }
        None => Ok(vec!["-c".to_owned(), INSTALL_DEFAULT_SCRIPT.to_owned()]),
    }
}

/// The command line the target's login shell runs over SSH: `sh -c
/// '<script>' sh <ref>`, the script in single quotes (it holds none) and
/// the validated ref as a separate word.
pub(crate) fn remote_command(reference: Option<&str>) -> Result<String> {
    Ok(shell_line(&sh_arguments(reference)?))
}

/// [`remote_command`] for a channel release.
pub(crate) fn channel_command(version: &str, commit: &str, sha256: &str) -> Result<String> {
    Ok(shell_line(&channel_arguments(version, commit, sha256)?))
}

/// `sh -c '<script>' <words>` from `sh`'s arguments: the script holds no
/// single quote and the words are validated plain words.
fn shell_line(arguments: &[String]) -> String {
    let mut command = String::from("sh -c '");
    command.push_str(&arguments[1]);
    command.push('\'');
    for argument in &arguments[2..] {
        command.push(' ');
        command.push_str(argument);
    }
    command
}

/// What an install reports.
#[derive(Clone, Debug, Serialize, JsonSchema)]
pub(crate) struct Installed {
    pub(crate) target: String,
    /// Where it came from: `channel` (the release channel's release) or
    /// `source` (built on the target).
    pub(crate) origin: String,
    /// The channel release installed, for `channel`.
    pub(crate) release: Option<String>,
    /// The ghostd that answers now, by its hello.
    pub(crate) ghostd_version: String,
    pub(crate) protocol_version: u32,
    /// The version the install built, as its `ghostd setup` reported it.
    pub(crate) built_version: Option<String>,
    /// The target had this release's binary already: nothing was replaced,
    /// and a daemon that runs it kept running (its connections too).
    pub(crate) unchanged: bool,
    /// A ghostd daemon that ran during the install still answers, with the
    /// binary it started from (the install stops it, so this is the case
    /// only when that failed): the new one takes effect after `ghostd stop`
    /// on the target (its jobs keep running, and the next connection starts
    /// the daemon again).
    pub(crate) restart_needed: bool,
    /// What to do about it, for people.
    pub(crate) note: Option<String>,
    pub(crate) seconds: u64,
}

/// What an install's output says, besides its progress.
#[derive(Clone, Debug, Default)]
pub(crate) struct InstallNotes {
    /// The version `ghostd setup` reported (its one line of JSON).
    pub(crate) version: Option<String>,
    /// The install found a ghostd daemon running at its end, which it
    /// could not stop.
    pub(crate) daemon_runs: bool,
    /// The channel install found this release's binary in place.
    pub(crate) unchanged: bool,
}

/// What install.sh said before v0.1.1 when a daemon ran at its end.
pub(crate) const DAEMON_RUNS: &str = "a ghostd daemon runs";

/// What the installs say when a running daemon would not stop.
pub(crate) const DAEMON_NOT_STOPPED: &str = "could not stop the running ghostd daemon";

impl InstallNotes {
    /// Takes in one line of the install's output.
    pub(crate) fn observe(&mut self, line: &str) {
        if line.contains(DAEMON_RUNS) || line.contains(DAEMON_NOT_STOPPED) {
            self.daemon_runs = true;
        }
        if line.starts_with("ghostd install: release ") && line.contains(ALREADY_INSTALLED) {
            self.unchanged = true;
        }
        let line = line.trim();
        if line.starts_with('{')
            && let Ok(serde_json::Value::Object(summary)) = serde_json::from_str(line)
            && summary.contains_key("binary")
            && let Some(version) = summary.get("version").and_then(serde_json::Value::as_str)
        {
            self.version = Some(crate::escape_control(version).into_owned());
        }
    }
}

/// How to install.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Source {
    /// The channel's current release, from the backend at this API URL.
    Channel { api_url: String },
    /// Built on the target from the repository, at this ref or install.sh's
    /// default.
    Source { reference: Option<String> },
}

/// Installs or updates ghostd on `pool`'s target from `source`, passing
/// each line of progress to `output`, then checks with a hello on a new
/// connection that ghostd answers.
pub(crate) async fn install(
    pool: &Pool,
    source: &Source,
    mut output: impl FnMut(&str) + Send,
) -> Result<Installed> {
    let started = Instant::now();
    match source {
        Source::Source { reference } => {
            let reference = reference.as_deref();
            let remote = remote_command(reference)?;
            let local = sh_arguments(reference)?;
            let notes = run(pool, &remote, &local, None, &mut output).await?;
            check(pool, &notes, "source", None, started).await
        }
        Source::Channel { api_url } => {
            let release = channel::fetch(&channel::source(api_url, true).await?).await?;
            let manifest = &release.manifest;
            output(&format!(
                "ghost: release {} of the ghostd channel (ghostd {}, commit {}) checked: the manifest's signature and the archive's SHA-256",
                manifest.version,
                manifest
                    .ghostd_version
                    .as_deref()
                    .unwrap_or("of an unnamed version"),
                manifest.commit
            ));
            install_release(pool, &release, &mut output, started).await
        }
    }
}

/// Installs a verified channel `release` on `pool`'s target: `uname -sm`
/// first (x86-64 only), then the fixed script with the binary on its
/// stdin, then the check.
pub(crate) async fn install_release(
    pool: &Pool,
    release: &channel::Release,
    output: &mut (dyn FnMut(&str) + Send),
    started: Instant,
) -> Result<Installed> {
    let manifest = &release.manifest;
    let machine = machine(pool).await?;
    if machine != "Linux x86_64" {
        bail!(
            "the ghostd channel has Linux x86_64 builds only, and {} is {machine}: build it there with `ghost ghostd install {} --from-source`",
            pool.label(),
            pool.label()
        );
    }
    let remote = channel_command(&manifest.version, &manifest.commit, &release.binary_sha256)?;
    let local = channel_arguments(&manifest.version, &manifest.commit, &release.binary_sha256)?;
    let notes = run(pool, &remote, &local, Some(&release.binary), output).await?;
    check(
        pool,
        &notes,
        "channel",
        Some(manifest.version.clone()),
        started,
    )
    .await
}

/// `sh` on the target: over SSH the login shell runs `remote`, locally
/// `sh` gets `local` as its arguments.
fn command(endpoint: &Endpoint, remote: &str, local: &[String]) -> Command {
    match endpoint {
        Endpoint::Ssh { .. } => {
            let mut argv = endpoint.ssh_prefix();
            argv.push(OsString::from(remote));
            let mut command = Command::new(&argv[0]);
            command.args(&argv[1..]);
            command
        }
        Endpoint::Local { env, .. } => {
            let mut command = Command::new("sh");
            command.args(local);
            command.envs(env.iter().map(|(name, value)| (name, value)));
            command
        }
    }
}

/// The target's system and machine, as `uname -sm` names them.
pub(crate) async fn machine(pool: &Pool) -> Result<String> {
    let local = ["-c".to_owned(), ARCH_COMMAND.to_owned()];
    let mut endpoint = pool.endpoint().await?;
    let mut fell_back = false;
    loop {
        let output = tokio::time::timeout(
            Duration::from_mins(1),
            command(&endpoint, ARCH_COMMAND, &local)
                .stdin(Stdio::null())
                .kill_on_drop(true)
                .output(),
        )
        .await
        .map_err(|_| anyhow!("{} did not say its machine within a minute", pool.label()))?
        .with_context(|| format!("run uname -sm on {}", pool.label()))?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        if !output.status.success() {
            if !fell_back && let Some(plain) = without_refused_mux(&endpoint, &stderr) {
                endpoint = plain;
                fell_back = true;
                continue;
            }
            bail!(
                "cannot run uname -sm on {} ({}): {}",
                pool.label(),
                output.status,
                crate::escape_control(stderr.trim())
            );
        }
        // The last line: a login shell's startup files may print before.
        let stdout = String::from_utf8_lossy(&output.stdout);
        let machine = stdout
            .lines()
            .map(str::trim)
            .rfind(|line| !line.is_empty())
            .unwrap_or_default();
        return Ok(crate::escape_control(machine).into_owned());
    }
}

/// Runs an install command on `pool`'s target, with `stdin` as its input,
/// passing each line it prints to `output`; what the output said. A
/// session the SSH master refused runs again without multiplexing (it ran
/// nothing then).
async fn run(
    pool: &Pool,
    remote: &str,
    local: &[String],
    stdin: Option<&[u8]>,
    output: &mut (dyn FnMut(&str) + Send),
) -> Result<InstallNotes> {
    let endpoint = pool.endpoint().await?;
    match run_on(pool, &endpoint, remote, local, stdin, &mut *output).await {
        Err(Refused::Mux(stderr)) => {
            if let Some(plain) = without_refused_mux(&endpoint, &stderr) {
                return run_on(pool, &plain, remote, local, stdin, output)
                    .await
                    .map_err(Refused::into_error);
            }
            Err(Refused::Mux(stderr).into_error())
        }
        result => result.map_err(Refused::into_error),
    }
}

/// How a run failed.
enum Refused {
    /// ssh's multiplexing master refused the session: its stderr.
    Mux(String),
    Other(anyhow::Error),
}

impl Refused {
    fn into_error(self) -> anyhow::Error {
        match self {
            Self::Mux(stderr) => anyhow!(
                "ssh refused the session: {}",
                crate::escape_control(stderr.trim())
            ),
            Self::Other(error) => error,
        }
    }
}

impl From<anyhow::Error> for Refused {
    fn from(error: anyhow::Error) -> Self {
        Self::Other(error)
    }
}

async fn run_on(
    pool: &Pool,
    endpoint: &Endpoint,
    remote: &str,
    local: &[String],
    stdin: Option<&[u8]>,
    mut output: impl FnMut(&str) + Send,
) -> Result<InstallNotes, Refused> {
    let mut command = command(endpoint, remote, local);
    command
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command
        .spawn()
        .with_context(|| format!("run the install on {}", pool.label()))?;
    let writer = match (stdin, child.stdin.take()) {
        (Some(data), Some(mut pipe)) => {
            let data = data.to_vec();
            Some(tokio::spawn(async move {
                use tokio::io::AsyncWriteExt as _;
                let written = pipe.write_all(&data).await;
                drop(pipe);
                written
            }))
        }
        _ => None,
    };
    let (sender, mut lines) = mpsc::channel::<String>(64);
    for output in [
        child
            .stdout
            .take()
            .map(|out| Box::new(out) as Box<dyn tokio::io::AsyncRead + Send + Unpin>),
        child
            .stderr
            .take()
            .map(|err| Box::new(err) as Box<dyn tokio::io::AsyncRead + Send + Unpin>),
    ]
    .into_iter()
    .flatten()
    {
        let sender = sender.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(output).split(b'\n');
            while let Ok(Some(text)) = reader.next_segment().await {
                let text = String::from_utf8_lossy(&text).trim_end().to_owned();
                if sender.send(text).await.is_err() {
                    return;
                }
            }
        });
    }
    drop(sender);
    let mut last = Vec::new();
    let mut all = String::new();
    let mut notes = InstallNotes::default();
    let mut keep = |text: String| {
        notes.observe(&text);
        if all.len() < 4096 {
            all.push_str(&text);
            all.push('\n');
        }
        let text = crate::escape_control(&text).into_owned();
        output(&text);
        last.push(text);
        if last.len() > 5 {
            last.remove(0);
        }
    };
    // A persisting SSH master may hold the output open after the command
    // ended, so the end is the command's exit, not the output's.
    let status = loop {
        tokio::select! {
            Some(text) = lines.recv() => keep(text),
            status = child.wait() => break status,
        }
    }
    .with_context(|| format!("wait for the install on {}", pool.label()))?;
    while let Ok(Some(text)) = tokio::time::timeout(Duration::from_secs(1), lines.recv()).await {
        keep(text);
    }
    if let Some(writer) = writer {
        // A target that stopped reading (it failed first) is told by the
        // status below.
        let _ = writer.await;
    }
    if !status.success() {
        if status.code() == Some(255) && super::conn::mux_refused(&all) {
            return Err(Refused::Mux(all));
        }
        return Err(Refused::Other(anyhow!(
            "the install on {} failed ({status}); it ended with: {}",
            pool.label(),
            last.join(" / ")
        )));
    }
    Ok(notes)
}

/// After an install: a new connection's hello says which ghostd answers,
/// and whether a daemon that ran during the install still runs the old
/// binary.
pub(crate) async fn check(
    pool: &Pool,
    notes: &InstallNotes,
    origin: &str,
    release: Option<String>,
    started: Instant,
) -> Result<Installed> {
    // A connection opened before the install reached the daemon of then.
    pool.reset();
    let link = pool
        .short()
        .await
        .map_err(|error| anyhow!("the install ran, but ghostd does not answer: {error:#}"))?;
    pool.call(Request::Ping).await?;
    let ghostd_version = crate::escape_control(link.server_version()).into_owned();
    let restart_needed = notes.daemon_runs
        || notes
            .version
            .as_deref()
            .is_some_and(|installed| installed != ghostd_version);
    let note = restart_needed.then(|| {
        format!(
            "ghostd {ghostd_version} still answers on {}: its daemon ran during the install and keeps the binary it started from{}. Run `ghostd stop` there to start the new one (jobs keep running; the next connection starts the daemon again)",
            pool.label(),
            notes
                .version
                .as_deref()
                .map(|version| format!(" (installed: {version})"))
                .unwrap_or_default()
        )
    });
    Ok(Installed {
        target: pool.label().to_owned(),
        origin: origin.to_owned(),
        release,
        ghostd_version,
        protocol_version: link.protocol_version(),
        built_version: notes.version.clone(),
        unchanged: notes.unchanged,
        restart_needed,
        note,
        seconds: started.elapsed().as_secs(),
    })
}
