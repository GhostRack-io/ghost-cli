//! Targets: the machine ghostd runs on, as every command and tool names it,
//! and the command that reaches its `ghostd stdio`.
//!
//! Nothing a user, an agent or an API answer supplies ever reaches a shell
//! string: the command run on the far side is [`REMOTE_COMMAND`], a
//! constant, and the host, user and port only become separate `ssh`
//! arguments after they are validated.

use std::{
    collections::HashMap,
    ffi::OsString,
    fs,
    io::Write as _,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail};
use ghostrack_client_api::{
    api::GetInstance,
    website::{GatewayTier, InstanceKind, InstanceState, InstanceView},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{InstanceReference, InstanceUse, api::ApiClient};

/// The one command run on the far side of an SSH connection: it starts the
/// installed `ghostd stdio` by its full path, since a non-login `ssh host
/// cmd` may not have `~/.local/bin` on `PATH`. It holds no user data, ever,
/// and only single quotes, so a fish or csh login shell passes it to `sh`
/// unchanged.
pub(crate) const REMOTE_COMMAND: &str = r#"sh -c 'for g in "$HOME/.local/bin/ghostd" /usr/local/bin/ghostd; do [ -x "$g" ] && exec "$g" stdio --client ghost; done; echo "ghostd is not installed" >&2; exit 127'"#;

/// What [`REMOTE_COMMAND`] says when neither binary is there.
pub(crate) const NOT_INSTALLED: &str = "ghostd is not installed";

/// The exit status of [`REMOTE_COMMAND`] when ghostd is not installed.
pub(crate) const NOT_INSTALLED_STATUS: i32 = 127;

/// How long a name's instance ID and an instance's address are used from
/// the cache without asking the API.
pub(crate) const CACHE_LIFETIME: Duration = Duration::from_hours(24);

/// A target as a command or tool names it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Target {
    /// An instance of the account, by its ID or name.
    Instance(InstanceReference),
    /// `ssh://[user@]host[:port]`: any machine the user can reach.
    Ssh {
        user: Option<String>,
        host: String,
        port: Option<u16>,
    },
    /// `local`: this machine, without SSH.
    Local,
}

/// Parse a target: `local`, `ssh://[user@]host[:port]`, or an instance ID
/// or name.
pub(crate) fn parse_target(value: &str) -> Result<Target, String> {
    if value == "local" {
        return Ok(Target::Local);
    }
    if let Some(rest) = value.strip_prefix("ssh://") {
        return parse_ssh_target(rest);
    }
    crate::parse_instance_reference(value)
        .map(Target::Instance)
        .map_err(|_| {
            "must be an instance ID or name, ssh://[user@]host[:port], or local".to_owned()
        })
}

fn parse_ssh_target(rest: &str) -> Result<Target, String> {
    let rest = rest.strip_suffix('/').unwrap_or(rest);
    let (user, hostport) = match rest.rsplit_once('@') {
        Some((user, hostport)) => (Some(user), hostport),
        None => (None, rest),
    };
    let (host, port) = if let Some(bracketed) = hostport.strip_prefix('[') {
        // An IPv6 address: [addr] or [addr]:port.
        let Some((address, after)) = bracketed.split_once(']') else {
            return Err("an IPv6 address must end with ]".to_owned());
        };
        if address.parse::<Ipv6Addr>().is_err() {
            return Err(format!("{address:?} is not an IPv6 address"));
        }
        let port = match after {
            "" => None,
            _ => Some(
                after
                    .strip_prefix(':')
                    .ok_or_else(|| "only :port may follow the ]".to_owned())?,
            ),
        };
        (address, port)
    } else {
        match hostport.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (hostport, None),
        }
    };
    let port = port.map(parse_port).transpose()?;
    if let Some(user) = user {
        valid_user(user)?;
    }
    valid_host(host)?;
    Ok(Target::Ssh {
        user: user.map(str::to_owned),
        host: host.to_owned(),
        port,
    })
}

fn parse_port(value: &str) -> Result<u16, String> {
    match value.parse::<u16>() {
        Ok(port) if port > 0 && value.bytes().all(|byte| byte.is_ascii_digit()) => Ok(port),
        _ => Err(format!("{value:?} is not a port")),
    }
}

/// Whether `c` may be in a host name or a user name: letters, digits, `.`,
/// `_` and `-`.
fn plain_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-')
}

/// A host for `ssh`: an IPv6 address, or a name or IPv4 address of letters,
/// digits, `.`, `_` and `-` that does not start with `-`. Nothing else: a
/// target may come from an agent, and an `ssh_config` `ProxyCommand` or
/// `Match exec` hands the host (`%h`) to a shell, which an OpenSSH before
/// 9.6 does without escaping it.
pub(crate) fn valid_host(host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err("the host is empty".to_owned());
    }
    if host.parse::<Ipv6Addr>().is_ok() {
        return Ok(());
    }
    if host.starts_with('-') {
        return Err(format!("the host {host:?} starts with -"));
    }
    if host.len() > 253 {
        return Err("the host is longer than 253 bytes".to_owned());
    }
    if let Some(bad) = host.chars().find(|c| !plain_name_char(*c)) {
        return Err(format!(
            "the host {host:?} holds {bad:?}: a host is letters, digits, . _ and -, or an IPv6 address in []"
        ));
    }
    Ok(())
}

/// A user name for `ssh -l`: letters, digits, `.`, `_` and `-`, not
/// starting with `-` (for the same reason as [`valid_host`]: `%u`).
pub(crate) fn valid_user(user: &str) -> Result<(), String> {
    if user.is_empty() {
        return Err("the user is empty".to_owned());
    }
    if user.starts_with('-') {
        return Err(format!("the user {user:?} starts with -"));
    }
    if user.len() > 64 {
        return Err("the user is longer than 64 bytes".to_owned());
    }
    if let Some(bad) = user.chars().find(|c| !plain_name_char(*c)) {
        return Err(format!(
            "the user {user:?} holds {bad:?}: a user is letters, digits, . _ and -"
        ));
    }
    Ok(())
}

/// For clap: a `--user` value.
pub(crate) fn parse_user(value: &str) -> Result<String, String> {
    valid_user(value).map(|()| value.to_owned())
}

/// Where a connection goes, once a target is resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Endpoint {
    Ssh {
        host: String,
        port: Option<u16>,
        user: Option<String>,
        /// The `ControlPath` of SSH's own multiplexing, for the commands
        /// that run once (`ghost x`, `ghost ghostd`); `None` for the MCP
        /// server's pool, whose point is separate TCP connections.
        control_path: Option<PathBuf>,
        /// How SSH files the host's key: per instance (an alias and
        /// ghost's own known hosts file) for an instance, so a new
        /// instance at an address another one had is a new name; `None`
        /// for an `ssh://` target, which keeps SSH's per-address way.
        host_keys: Option<HostKeys>,
    },
    /// `ghostd stdio` on this machine.
    Local {
        program: PathBuf,
        /// Variables set for it (tests give it its own directories).
        env: Vec<(OsString, OsString)>,
    },
}

/// Where and under which name SSH keeps an instance's host key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HostKeys {
    /// `HostKeyAlias`: `ghost-instance-<instance id>`.
    pub(crate) alias: String,
    /// `UserKnownHostsFile`: ghost's own file; `None` when no private
    /// directory could be made for it (SSH then files the alias in the
    /// user's own known hosts).
    pub(crate) known_hosts: Option<PathBuf>,
}

impl HostKeys {
    /// The host keys of the instance `instance_id`.
    pub(crate) fn of_instance(instance_id: Uuid) -> Self {
        Self {
            alias: instance_alias(instance_id),
            known_hosts: known_hosts_file().ok(),
        }
    }
}

/// The name an instance's host key is filed under.
pub(crate) fn instance_alias(instance_id: Uuid) -> String {
    format!("ghost-instance-{instance_id}")
}

impl Endpoint {
    /// The local endpoint: `GHOSTD_BIN`, else `ghostd` from `PATH`.
    pub(crate) fn local() -> Self {
        let program = std::env::var_os("GHOSTD_BIN")
            .filter(|value| !value.is_empty())
            .map_or_else(|| PathBuf::from("ghostd"), PathBuf::from);
        Self::Local {
            program,
            env: Vec::new(),
        }
    }

    /// This endpoint without SSH's multiplexing: its own connection.
    pub(crate) fn without_mux(&self) -> Self {
        match self {
            Self::Ssh {
                host,
                port,
                user,
                host_keys,
                ..
            } => Self::Ssh {
                host: host.clone(),
                port: *port,
                user: user.clone(),
                control_path: None,
                host_keys: host_keys.clone(),
            },
            Self::Local { .. } => self.clone(),
        }
    }

    /// The argv that reaches `ghostd stdio`.
    pub(crate) fn argv(&self) -> Vec<OsString> {
        match self {
            Self::Ssh { .. } => {
                let mut argv = self.ssh_prefix();
                argv.push(REMOTE_COMMAND.into());
                argv
            }
            Self::Local { program, .. } => vec![
                program.clone().into_os_string(),
                "stdio".into(),
                "--client".into(),
                "ghost".into(),
            ],
        }
    }

    /// `ssh` with its options and the host, before the remote command.
    /// Empty for [`Endpoint::Local`].
    pub(crate) fn ssh_prefix(&self) -> Vec<OsString> {
        let Self::Ssh {
            host,
            port,
            user,
            control_path,
            host_keys,
        } = self
        else {
            return Vec::new();
        };
        let mut argv: Vec<OsString> = [
            "ssh",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "StrictHostKeyChecking=accept-new",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        if let Some(path) = control_path {
            argv.extend(["-o".into(), "ControlMaster=auto".into()]);
            argv.extend(["-o".into(), "ControlPersist=600".into()]);
            let mut control = OsString::from("ControlPath=");
            control.push(path);
            argv.extend(["-o".into(), control]);
        }
        if let Some(keys) = host_keys {
            argv.extend(["-o".into(), format!("HostKeyAlias={}", keys.alias).into()]);
            // Plain text, so the alias's lines can be found to remove.
            argv.extend(["-o".into(), "HashKnownHosts=no".into()]);
            if let Some(file) = &keys.known_hosts {
                let mut option = OsString::from("UserKnownHostsFile=");
                option.push(file);
                argv.extend(["-o".into(), option]);
            }
        }
        if let Some(port) = port {
            argv.extend(["-p".into(), port.to_string().into()]);
        }
        if let Some(user) = user {
            argv.extend(["-l".into(), user.into()]);
        }
        argv.push("--".into());
        argv.push(host.into());
        argv
    }

    /// For people: `root@203.0.113.7:2222`, `local`.
    pub(crate) fn describe(&self) -> String {
        match self {
            Self::Ssh {
                host, port, user, ..
            } => {
                let mut text = String::new();
                if let Some(user) = user {
                    text.push_str(user);
                    text.push('@');
                }
                if host.contains(':') {
                    text.push('[');
                    text.push_str(host);
                    text.push(']');
                } else {
                    text.push_str(host);
                }
                if let Some(port) = port {
                    text.push(':');
                    text.push_str(&port.to_string());
                }
                text
            }
            Self::Local { .. } => "local".to_owned(),
        }
    }
}

/// The directory of SSH's control sockets: `$XDG_RUNTIME_DIR/ghost`, else
/// `$XDG_CACHE_HOME/ghost` (`~/.cache/ghost`), created 0700 and made 0700
/// when it is not.
pub(crate) fn control_directory() -> Result<PathBuf> {
    let base = absolute_env("XDG_RUNTIME_DIR").map_or_else(cache_home, Ok)?;
    let directory = base.join("ghost");
    private_directory(&directory)?;
    Ok(directory)
}

/// The `ControlPath` of SSH's multiplexing: `<control directory>/ssh-%C`.
pub(crate) fn control_path() -> Result<PathBuf> {
    Ok(control_directory()?.join("ssh-%C"))
}

/// ghost's data directory: `$XDG_DATA_HOME/ghost`, else
/// `~/.local/share/ghost`.
fn data_home() -> Result<PathBuf> {
    if let Some(path) = absolute_env("XDG_DATA_HOME") {
        return Ok(path);
    }
    let home = absolute_env("HOME").context("neither XDG_DATA_HOME nor HOME is set")?;
    Ok(home.join(".local").join("share"))
}

/// ghost's own known hosts file for instances,
/// `<data directory>/ghost/known_hosts`: the directory 0700, the file
/// created 0600.
pub(crate) fn known_hosts_file() -> Result<PathBuf> {
    known_hosts_file_in(&data_home()?)
}

/// The file `name` in ghost's data directory (`<data directory>/ghost`,
/// made 0700); it is not created.
pub(crate) fn data_file(name: &str) -> Result<PathBuf> {
    let directory = data_home()?.join("ghost");
    private_directory(&directory)?;
    Ok(directory.join(name))
}

/// [`known_hosts_file`] below the data directory `base`.
pub(crate) fn known_hosts_file_in(base: &Path) -> Result<PathBuf> {
    let directory = base.join("ghost");
    private_directory(&directory)?;
    let path = directory.join("known_hosts");
    fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(&path)
        .with_context(|| format!("create {}", path.display()))?;
    Ok(path)
}

/// Removes the lines of `alias` from the known hosts file at `path`;
/// answers how many it removed. A missing file holds none.
pub(crate) fn remove_known_host(path: &Path, alias: &str) -> usize {
    let Ok(text) = fs::read_to_string(path) else {
        return 0;
    };
    let mut removed = 0;
    let mut kept = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        // Entries are `[@marker] hosts keytype key`; hosts are comma
        // separated.
        let mut fields = line.split_whitespace();
        let mut hosts = fields.next().unwrap_or("");
        if hosts.starts_with('@') {
            hosts = fields.next().unwrap_or("");
        }
        if hosts.split(',').any(|host| host == alias) {
            removed += 1;
        } else {
            kept.push_str(line);
        }
    }
    if removed > 0 {
        let temporary = path.with_extension("tmp");
        let written = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)
            .and_then(|mut file| file.write_all(kept.as_bytes()))
            .and_then(|()| fs::rename(&temporary, path));
        if written.is_err() {
            let _ = fs::remove_file(&temporary);
            return 0;
        }
    }
    removed
}

/// The name the host key of an instance's rescue system is filed under: never the instance's own,
/// whose key stays as it was.
pub(crate) fn rescue_alias(instance_id: Uuid) -> String {
    format!("ghost-rescue-{instance_id}")
}

/// Files the host key of the rescue of `instance_id`, `host_key_public`
/// (`ssh-ed25519 AAAA…`, as the instance view gives it), in ghost's known
/// hosts file below the data directory `base`, in place of any line of
/// that rescue before: SSH then checks the rescue system's key in advance
/// (`StrictHostKeyChecking=yes`). Answers the file.
pub(crate) fn remember_rescue_host_key_in(
    base: &Path,
    instance_id: Uuid,
    host_key_public: &str,
) -> Result<PathBuf> {
    let mut words = host_key_public.split_ascii_whitespace();
    let (Some(algorithm), Some(key), None) = (words.next(), words.next(), words.next()) else {
        bail!("the rescue system's host key is not one key");
    };
    if !algorithm.starts_with("ssh-")
        || !key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+/=".contains(&byte))
    {
        bail!("the rescue system's host key is not an SSH public key");
    }
    let path = known_hosts_file_in(base)?;
    let alias = rescue_alias(instance_id);
    let line = format!("{alias} {algorithm} {key}\n");
    let text = fs::read_to_string(&path).unwrap_or_default();
    if text.lines().any(|known| format!("{known}\n") == line) {
        return Ok(path);
    }
    remove_known_host(&path, &alias);
    fs::OpenOptions::new()
        .append(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut file| file.write_all(line.as_bytes()))
        .with_context(|| format!("write {}", path.display()))?;
    Ok(path)
}

/// [`remember_rescue_host_key_in`] ghost's data directory.
pub(crate) fn remember_rescue_host_key(
    instance_id: Uuid,
    host_key_public: &str,
) -> Result<PathBuf> {
    remember_rescue_host_key_in(&data_home()?, instance_id, host_key_public)
}

/// Forgets the host key of the rescue of `instance_id`, once it ended.
pub(crate) fn forget_rescue_host_key(instance_id: Uuid) -> usize {
    data_home()
        .map(|home| home.join("ghost").join("known_hosts"))
        .map_or(0, |path| {
            remove_known_host(&path, &rescue_alias(instance_id))
        })
}

/// `value` as one word for a POSIX shell: as it is when it needs no
/// quotes, else in single quotes.
fn shell_word(value: &str) -> String {
    if !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_./=:@,+%".contains(&byte))
    {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', r"'\''"))
    }
}

/// The command that logs in to the rescue system of `instance` as root,
/// checking its host key, which ghost filed under [`rescue_alias`] in
/// `known_hosts`: `ssh -o HostKeyAlias=… -o StrictHostKeyChecking=yes -o
/// UserKnownHostsFile=… [-p PORT] root@ADDRESS`.
pub(crate) fn rescue_ssh_command(instance: &InstanceView, known_hosts: &Path) -> Result<String> {
    let address = rescue_address(instance)?;
    let port = if address.port == 22 {
        String::new()
    } else {
        format!(" -p {}", address.port)
    };
    let command = format!(
        "ssh -o HostKeyAlias={} -o StrictHostKeyChecking=yes -o UserKnownHostsFile={}{port} root@{}",
        rescue_alias(instance.instance_id),
        shell_word(&known_hosts.display().to_string()),
        address.address
    );
    Ok(command)
}

/// The address of `instance`'s SSH, as [`instance_address`] finds it, for
/// its rescue system.
fn rescue_address(instance: &InstanceView) -> Result<InstanceAddress> {
    let mut own = instance.clone();
    own.rescue = None;
    instance_address(&own)
}

/// Forgets the host key ghost keeps for the instance `instance_id`.
pub(crate) fn forget_host_keys(instance_id: Uuid) -> usize {
    data_home()
        .map(|home| home.join("ghost").join("known_hosts"))
        .map_or(0, |path| {
            remove_known_host(&path, &instance_alias(instance_id))
        })
}

fn absolute_env(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
}

fn cache_home() -> Result<PathBuf> {
    if let Some(path) = absolute_env("XDG_CACHE_HOME") {
        return Ok(path);
    }
    let home = absolute_env("HOME").context("neither XDG_CACHE_HOME nor HOME is set")?;
    Ok(home.join(".cache"))
}

/// Creates `directory` 0700 (its parents as the umask says), or makes an
/// existing one 0700. Refuses a symlink or a directory of another user.
fn private_directory(directory: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    match fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(directory)
    {
        Ok(()) => {}
        Err(error) => {
            return Err(error).with_context(|| format!("create {}", directory.display()));
        }
    }
    let metadata = fs::symlink_metadata(directory)
        .with_context(|| format!("inspect {}", directory.display()))?;
    if !metadata.is_dir() {
        bail!("{} is not a directory", directory.display());
    }
    if metadata.uid() != rustix_uid() {
        bail!("{} belongs to another user", directory.display());
    }
    if metadata.mode() & 0o777 != 0o700 {
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("make {} 0700", directory.display()))?;
    }
    Ok(())
}

fn rustix_uid() -> u32 {
    rustix::process::geteuid().as_raw()
}

/// An instance's SSH address as the API reports it, validated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct InstanceAddress {
    pub(crate) address: Ipv4Addr,
    pub(crate) port: u16,
}

/// The repository prefix of the platform's stock images
/// (ghostrack-io/container-images): an older backend's view of a
/// container instance does not name its stock image, and one of an image
/// from there may be one. This is a best guess, and it also applies to a
/// newer backend's view, where a missing `stock_image` reads as null: a
/// renter's own image from there is then tried over SSH instead of being
/// refused early.
const STOCK_IMAGE_REPOSITORIES: &str = "ghcr.io/gigahost-apps/";

/// Whether `instance` may answer SSH with the account's keys: a VM, or a
/// container instance of a stock image, whose init writes them. A
/// container of the renter's own image runs as it is and gets none.
fn answers_ssh(instance: &InstanceView) -> bool {
    if instance.kind != InstanceKind::Container {
        return true;
    }
    instance.container.as_ref().is_none_or(|container| {
        container.stock_image.is_some() || container.image.starts_with(STOCK_IMAGE_REPOSITORIES)
    })
}

/// The address of `instance`: its public IPv4 and, for a shared IP
/// instance (a slice of an address's ports), the public port that forwards
/// to its port 22; an instance with an address of its own has no forwards
/// and answers SSH on port 22 itself. A container instance of the renter's
/// own image is refused: it has no SSH of the platform's.
pub(crate) fn instance_address(instance: &InstanceView) -> Result<InstanceAddress> {
    let id = instance.instance_id;
    if matches!(instance.state, InstanceState::Deleted) {
        bail!("instance {id} is deleted");
    }
    // The rescue system runs no ghostd, and has a host key of its own, which `ghost instance get`
    // files for SSH: ghost's connections wait for the rescue's end.
    if let Some(rescue) = &instance.rescue {
        bail!(
            "instance {id} is in rescue: it runs the platform's rescue system (host key {}), which has no ghostd; `ghost instance get {id}` prints the SSH command that logs in to it, and `ghost instance rescue {id} --exit` ends the rescue",
            crate::escape_control(&rescue.host_key_fingerprint)
        );
    }
    if !answers_ssh(instance) {
        bail!(
            "this container instance has no SSH: instance {id} runs its image as it is, without the account's SSH keys, so ghost cannot reach it; `ghost instance logs {id}` shows what it writes, and a container instance of a stock image (`ghost catalog container-images`) is reached as a VM is"
        );
    }
    let Some(address) = &instance.public_ipv4 else {
        bail!("instance {id} has no public IPv4 address, so ghost cannot reach its SSH");
    };
    let address: Ipv4Addr = match address.parse::<IpAddr>() {
        Ok(IpAddr::V4(address)) => address,
        _ => bail!(
            "instance {id} reports {:?} as its public IPv4 address, which is not one",
            crate::escape_control(address)
        ),
    };
    let shared = !instance.port_forwards.is_empty()
        || instance.outgoing_ports.is_some()
        || instance.gateway_tier == Some(GatewayTier::SharedIp);
    if !shared {
        return Ok(InstanceAddress { address, port: 22 });
    }
    let Some(forward) = instance
        .port_forwards
        .iter()
        .find(|forward| forward.guest_port == 22)
    else {
        bail!(
            "instance {id} forwards no public port to its SSH port 22: `ghost instance ports {id}` lists and sets its ports"
        );
    };
    if forward.public_port == 0 {
        bail!("instance {id} reports port 0 for its SSH");
    }
    Ok(InstanceAddress {
        address,
        port: forward.public_port,
    })
}

/// The key a name is cached under: names match without regard to case.
fn folded(name: &str) -> String {
    name.to_ascii_lowercase()
}

/// The key of an instance's host ID: the instance and the user ghost logs
/// in as (another user's ghostd is another daemon, with its own ID).
pub(crate) fn instance_host_key(instance_id: Uuid, user: &str) -> String {
    format!("instance {instance_id} user {user}")
}

/// The start of the keys of an `ssh://` destination's host IDs, every user.
fn ssh_host_prefix(host: &str, port: Option<u16>) -> String {
    let port = port.map_or_else(|| "-".to_owned(), |port| port.to_string());
    let host = host.to_ascii_lowercase();
    format!("ssh {host} port {port} user ")
}

/// The key of an `ssh://` destination's host ID for `user` (`-`: the one
/// the SSH configuration chooses).
pub(crate) fn ssh_host_key(host: &str, port: Option<u16>, user: Option<&str>) -> String {
    format!("{}{}", ssh_host_prefix(host, port), user.unwrap_or("-"))
}

/// The key of the target `local`'s host ID.
pub(crate) const LOCAL_HOST_KEY: &str = "local";

/// Resolves targets to endpoints, instances through the API, and keeps what
/// it learns in one cache file, `$XDG_CACHE_HOME/ghost/ghostd-targets-v2.json`
/// (0600, replaced atomically under a lock on `ghostd-targets-v2.lock`
/// beside it; a missing or unreadable file is an empty cache), in a scope
/// per API URL and account key:
///
/// - `names`: an instance's name (case-folded) and the instance ID the API
///   answered for it;
/// - `instances`: an instance ID and its validated SSH address;
/// - `hosts`: the ghostd host ID learned for an endpoint (an instance ID,
///   an `ssh://` destination, `local`) and SSH user.
///
/// A name or an address younger than [`CACHE_LIFETIME`] is used without
/// asking the API, so `ghost x NAME` normally makes no API request; a
/// rename or a new instance of the name made elsewhere (the website,
/// another device) is seen only once the entry expires, or with `--refresh`
/// or `ghost ghostd forget`. Instance
/// IDs in the cache only ever come from the API's answers to this account,
/// so the cache cannot send a command to another account's instance. A host
/// ID never expires: it is what tells ghost that a name or an address now
/// reaches another machine, and only `ghost ghostd forget`, ghost's own
/// instance commands and a mismatch the API explains replace it.
pub(crate) struct Resolver {
    api_url: String,
    seed_file: Option<PathBuf>,
    /// The cache file; `None` keeps nothing (tests).
    cache_file: Option<PathBuf>,
    /// Whether the endpoints use SSH's multiplexing.
    multiplex: bool,
    /// The endpoint of the target `local` (tests give theirs directories
    /// of its own).
    #[cfg(test)]
    local: Option<Endpoint>,
    /// Endpoints that stand for instance addresses (tests reach a local
    /// ghostd as an instance).
    #[cfg(test)]
    addresses: Vec<(InstanceAddress, Endpoint)>,
}

/// A resolved target.
#[derive(Clone, Debug)]
pub(crate) struct Resolved {
    pub(crate) endpoint: Endpoint,
    /// The instance's address came from the cache, so a failed connection
    /// or a host mismatch drops it and asks the API.
    pub(crate) cached: bool,
    /// The instance the target resolved to.
    pub(crate) instance_id: Option<Uuid>,
    /// The key of the endpoint's host ID in the cache.
    pub(crate) host_key: String,
}

/// The cache file: one [`Scope`] per API URL and account key.
#[derive(Default, Serialize, Deserialize)]
struct CacheFile {
    #[serde(default)]
    scopes: HashMap<String, Scope>,
}

#[derive(Default, Serialize, Deserialize)]
struct Scope {
    #[serde(default)]
    names: HashMap<String, NameEntry>,
    #[serde(default)]
    instances: HashMap<Uuid, InstanceEntry>,
    #[serde(default)]
    hosts: HashMap<String, HostEntry>,
}

impl Scope {
    fn is_empty(&self) -> bool {
        self.names.is_empty() && self.instances.is_empty() && self.hosts.is_empty()
    }

    /// Drops what it holds about `instance_id`: the names that stand for
    /// it, its address and its host IDs. Answers how many entries went.
    fn forget_instance(&mut self, instance_id: Uuid) -> Forgotten {
        let names = self.names.len();
        self.names
            .retain(|_, entry| entry.instance_id != instance_id);
        let instances = usize::from(self.instances.remove(&instance_id).is_some());
        let prefix = format!("instance {instance_id} user ");
        let hosts = self.hosts.len();
        self.hosts.retain(|key, _| !key.starts_with(&prefix));
        Forgotten {
            names: names - self.names.len(),
            instances,
            hosts: hosts - self.hosts.len(),
        }
    }
}

#[derive(Clone, Copy, Serialize, Deserialize)]
struct NameEntry {
    instance_id: Uuid,
    resolved_at: u64,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
struct InstanceEntry {
    address: Ipv4Addr,
    port: u16,
    resolved_at: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct HostEntry {
    /// 32 hex digits.
    host_id: String,
    learned_at: u64,
}

/// What a forget dropped from the cache.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct Forgotten {
    /// Names that stood for the instance.
    pub(crate) names: usize,
    /// Instance addresses.
    pub(crate) instances: usize,
    /// Host IDs.
    pub(crate) hosts: usize,
}

impl std::ops::AddAssign for Forgotten {
    fn add_assign(&mut self, other: Self) {
        self.names += other.names;
        self.instances += other.instances;
        self.hosts += other.hosts;
    }
}

/// Whether an entry made at `at` is still used at `now`.
fn young(at: u64, now: u64) -> bool {
    now.checked_sub(at)
        .is_some_and(|age| age < CACHE_LIFETIME.as_secs())
}

/// The cache file's name. It is not the `ghostd-targets.json` of the ghost
/// releases before host IDs, which an older ghost still installed beside
/// this one reads as empty and would write back without the host IDs.
const CACHE_FILE: &str = "ghostd-targets-v2.json";

/// The cache file under the cache directory `home` (`~/.cache`).
pub(crate) fn cache_file_in(home: &Path) -> PathBuf {
    home.join("ghost").join(CACHE_FILE)
}

/// The default cache file, when there is a cache directory.
fn default_cache_file() -> Option<PathBuf> {
    cache_home().ok().map(|home| cache_file_in(&home))
}

/// The lock beside the cache file at `path`, held while it is changed.
pub(crate) fn cache_lock_path(path: &Path) -> PathBuf {
    path.with_extension("lock")
}

/// Serializes the changes of this process's cache file, so that two calls
/// of one MCP session never lose each other's entry; the lock file does it
/// between processes.
static CACHE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Makes each temporary file's name of its own.
static TEMPORARY: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn read_cache_file(path: Option<&Path>) -> CacheFile {
    path.and_then(|path| fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Changes the cache file at `path`, dropping the names and addresses that
/// expired; answers whether it was written. The read, the change and the
/// write hold an exclusive lock on [`cache_lock_path`], so that two ghost
/// processes (an MCP session and an agent's `ghost x`) never lose each
/// other's entry. A cache that cannot be written is only a cache, so a
/// failure is no error.
fn change_cache_file(path: &Path, change: impl FnOnce(&mut CacheFile)) -> bool {
    let _changing = CACHE_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(directory) = path.parent() else {
        return false;
    };
    if private_directory(directory).is_err() {
        return false;
    }
    let Ok(lock) = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(cache_lock_path(path))
    else {
        return false;
    };
    // Released when the file is closed, at the end.
    if lock.lock().is_err() {
        return false;
    }
    let mut cache = read_cache_file(Some(path));
    change(&mut cache);
    let now = now_seconds();
    for scope in cache.scopes.values_mut() {
        scope.names.retain(|_, entry| young(entry.resolved_at, now));
        scope
            .instances
            .retain(|_, entry| young(entry.resolved_at, now));
    }
    cache.scopes.retain(|_, scope| !scope.is_empty());
    let Ok(bytes) = serde_json::to_vec(&cache) else {
        return false;
    };
    let temporary = directory.join(format!(
        ".ghostd-targets-v2.{}.{}.tmp",
        std::process::id(),
        TEMPORARY.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let written = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)
        .and_then(|mut file| {
            file.write_all(&bytes)?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&temporary, path));
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written.is_ok()
}

/// Drops what the cache holds about `instance_id`, in every scope: the
/// names that stand for it, its address and its host IDs. ghost's own
/// commands that give an instance another name, another system or none
/// (rename, delete, reinstall, a restore, a creation from a backup) call
/// it once they succeeded, so the next `ghost x` asks the API.
pub(crate) fn forget_instance(instance_id: Uuid) {
    // Its host key too: a reinstalled guest has new keys.
    forget_host_keys(instance_id);
    if let Some(path) = default_cache_file() {
        forget_instance_in(&path, instance_id);
    }
}

/// Drops the cached instance `name` stands for, in every scope: `ghost
/// instance create` gives a new instance the name.
pub(crate) fn forget_name(name: &str) {
    if let Some(path) = default_cache_file()
        && path.exists()
    {
        change_cache_file(&path, |cache| {
            for scope in cache.scopes.values_mut() {
                scope.names.remove(&folded(name));
            }
        });
    }
}

/// [`forget_instance`] in the cache file at `path`.
pub(crate) fn forget_instance_in(path: &Path, instance_id: Uuid) -> Forgotten {
    let mut forgotten = Forgotten::default();
    if path.exists() {
        change_cache_file(path, |cache| {
            for scope in cache.scopes.values_mut() {
                forgotten += scope.forget_instance(instance_id);
            }
        });
    }
    forgotten
}

impl Resolver {
    pub(crate) fn new(api_url: &str, seed_file: Option<PathBuf>, multiplex: bool) -> Self {
        Self {
            api_url: api_url.to_owned(),
            seed_file,
            cache_file: default_cache_file(),
            multiplex,
            #[cfg(test)]
            local: None,
            #[cfg(test)]
            addresses: Vec::new(),
        }
    }

    /// The API instances are looked up with, which also names the ghostd
    /// release channel.
    pub(crate) fn api_url(&self) -> &str {
        &self.api_url
    }

    /// A resolver for tests: no cache, no API.
    #[cfg(test)]
    pub(crate) fn offline() -> Self {
        Self::for_tests("http://127.0.0.1:9", None, None)
    }

    /// A resolver for tests with the API, account key and cache file given.
    #[cfg(test)]
    pub(crate) fn for_tests(
        api_url: &str,
        seed_file: Option<PathBuf>,
        cache_file: Option<PathBuf>,
    ) -> Self {
        Self {
            api_url: api_url.to_owned(),
            seed_file,
            cache_file,
            multiplex: false,
            local: None,
            addresses: Vec::new(),
        }
    }

    /// This resolver, answering `endpoint` for the target `local` (tests).
    #[cfg(test)]
    pub(crate) fn with_local(mut self, endpoint: Endpoint) -> Self {
        self.local = Some(endpoint);
        self
    }

    /// This resolver, reaching an instance at `address` and `port` through
    /// `endpoint` (tests).
    #[cfg(test)]
    pub(crate) fn with_address(mut self, address: Ipv4Addr, port: u16, endpoint: Endpoint) -> Self {
        self.addresses
            .push((InstanceAddress { address, port }, endpoint));
        self
    }

    /// The endpoint of an instance's SSH address.
    fn instance_endpoint(
        &self,
        instance_id: Uuid,
        address: InstanceAddress,
        user: &str,
    ) -> Endpoint {
        #[cfg(test)]
        if let Some((_, endpoint)) = self.addresses.iter().find(|(at, _)| *at == address) {
            return endpoint.clone();
        }
        Endpoint::Ssh {
            host: address.address.to_string(),
            port: Some(address.port),
            user: Some(user.to_owned()),
            control_path: self.control(),
            host_keys: Some(HostKeys::of_instance(instance_id)),
        }
    }

    #[cfg_attr(not(test), allow(clippy::unused_self))]
    fn local_endpoint(&self) -> Endpoint {
        #[cfg(test)]
        if let Some(endpoint) = &self.local {
            return endpoint.clone();
        }
        Endpoint::local()
    }

    /// The `ControlPath` when multiplexing; without a private directory
    /// for its sockets, connections go without it.
    fn control(&self) -> Option<PathBuf> {
        if self.multiplex {
            control_path().ok()
        } else {
            None
        }
    }

    /// The cache's scope of the account: the API and the account's key.
    /// `None` without an account key.
    fn account_scope(&self) -> Result<Option<String>> {
        Ok(crate::account_identity(self.seed_file.as_deref())?
            .map(|identity| format!("{} account {}", self.api_url, identity.key_id)))
    }

    /// The scope host IDs are kept in: the account's, or without an
    /// account key (`ssh://` and `local` need none) one of the API's own.
    fn host_scope(&self) -> String {
        match self.account_scope() {
            Ok(Some(scope)) => scope,
            _ => format!("{} no account", self.api_url),
        }
    }

    fn read_cache(&self) -> CacheFile {
        read_cache_file(self.cache_file.as_deref())
    }

    /// Changes the cache; answers whether it was written.
    fn update_cache(&self, change: impl FnOnce(&mut CacheFile)) -> bool {
        match &self.cache_file {
            Some(path) => change_cache_file(path, change),
            None => false,
        }
    }

    /// Whether the resolver keeps a cache at all.
    pub(crate) fn has_cache(&self) -> bool {
        self.cache_file.is_some()
    }

    /// The endpoint of `target`, connecting as `user` when it is given (an
    /// instance's default is `root`). With `fresh`, an instance's name and
    /// address are asked of the API even when they are cached.
    pub(crate) async fn resolve(
        &self,
        target: &Target,
        user: Option<&str>,
        fresh: bool,
    ) -> Result<Resolved> {
        if let Some(user) = user {
            valid_user(user).map_err(anyhow::Error::msg)?;
        }
        match target {
            Target::Local => Ok(Resolved {
                endpoint: self.local_endpoint(),
                cached: false,
                instance_id: None,
                host_key: LOCAL_HOST_KEY.to_owned(),
            }),
            Target::Ssh {
                user: target_user,
                host,
                port,
            } => {
                let user = user.map(str::to_owned).or_else(|| target_user.clone());
                Ok(Resolved {
                    host_key: ssh_host_key(host, *port, user.as_deref()),
                    endpoint: Endpoint::Ssh {
                        host: host.clone(),
                        port: *port,
                        user,
                        control_path: self.control(),
                        host_keys: None,
                    },
                    cached: false,
                    instance_id: None,
                })
            }
            Target::Instance(reference) => {
                let (instance_id, address, cached) = self.instance(reference, fresh).await?;
                let user = user.unwrap_or("root");
                Ok(Resolved {
                    endpoint: self.instance_endpoint(instance_id, address, user),
                    cached,
                    instance_id: Some(instance_id),
                    host_key: instance_host_key(instance_id, user),
                })
            }
        }
    }

    /// The instance `reference` names and its address, and whether the
    /// address came from the cache. A cached name and address younger than
    /// [`CACHE_LIFETIME`] are used unless `fresh`; otherwise a name is
    /// looked up among the account's instances (one of them must have it)
    /// and the instance read, as without the cache, and what the API
    /// answers is stored.
    async fn instance(
        &self,
        reference: &InstanceReference,
        fresh: bool,
    ) -> Result<(Uuid, InstanceAddress, bool)> {
        let scope = self.account_scope()?;
        let now = now_seconds();
        let mut cached = match (&scope, fresh) {
            (Some(scope), false) => self.read_cache().scopes.remove(scope),
            _ => None,
        }
        .unwrap_or_default();
        let named = match reference {
            InstanceReference::Id(id) => Some(*id),
            InstanceReference::Name(name) => cached
                .names
                .get(&folded(name))
                .filter(|entry| young(entry.resolved_at, now))
                .map(|entry| entry.instance_id),
        };
        if let Some(id) = named
            && let Some(entry) = cached
                .instances
                .remove(&id)
                .filter(|entry| young(entry.resolved_at, now) && entry.port != 0)
        {
            let address = InstanceAddress {
                address: entry.address,
                port: entry.port,
            };
            return Ok((id, address, true));
        }
        let seed_file = self.seed_file.clone();
        let api = ApiClient::with_identity_loader(
            &self.api_url,
            Box::new(move || crate::account_identity(seed_file.as_deref())),
        )?;
        let instance_id = crate::resolve_instance(&api, reference, InstanceUse::Read).await?;
        let instance: InstanceView = api.read(&GetInstance { instance_id }, "").await?;
        let address = instance_address(&instance)?;
        let name = match reference {
            InstanceReference::Name(name) => Some(name.as_str()),
            InstanceReference::Id(_) => None,
        };
        self.store_instance(scope.as_deref(), instance_id, address, name);
        Ok((instance_id, address, false))
    }

    /// Stores an instance's address the API answered and, when it was
    /// named, the name; nothing without an account key.
    fn store_instance(
        &self,
        scope: Option<&str>,
        instance_id: Uuid,
        address: InstanceAddress,
        name: Option<&str>,
    ) {
        let Some(scope) = scope else {
            return;
        };
        let now = now_seconds();
        self.update_cache(|cache| {
            let scope = cache.scopes.entry(scope.to_owned()).or_default();
            scope.instances.insert(
                instance_id,
                InstanceEntry {
                    address: address.address,
                    port: address.port,
                    resolved_at: now,
                },
            );
            if let Some(name) = name {
                scope.names.insert(
                    folded(name),
                    NameEntry {
                        instance_id,
                        resolved_at: now,
                    },
                );
            }
        });
    }

    /// Forgets an instance's cached address, after a connection to it
    /// failed or it answered another host ID.
    pub(crate) fn forget_address(&self, instance_id: Uuid) {
        let Ok(Some(scope)) = self.account_scope() else {
            return;
        };
        self.update_cache(|cache| {
            if let Some(scope) = cache.scopes.get_mut(&scope) {
                scope.instances.remove(&instance_id);
            }
        });
    }

    /// The host ID learned for `key`.
    pub(crate) fn host_id(&self, key: &str) -> Option<ghostd_protocol::v2::HostId> {
        self.read_cache()
            .scopes
            .get(&self.host_scope())?
            .hosts
            .get(key)?
            .host_id
            .parse()
            .ok()
    }

    /// Keeps the host ID learned for `key`; answers whether it was
    /// written.
    pub(crate) fn store_host_id(&self, key: &str, host_id: ghostd_protocol::v2::HostId) -> bool {
        let scope = self.host_scope();
        let now = now_seconds();
        self.update_cache(|cache| {
            cache.scopes.entry(scope).or_default().hosts.insert(
                key.to_owned(),
                HostEntry {
                    host_id: host_id.to_string(),
                    learned_at: now,
                },
            );
        })
    }

    /// Forgets the host ID learned for `key`.
    pub(crate) fn forget_host(&self, key: &str) {
        let scope = self.host_scope();
        self.update_cache(|cache| {
            if let Some(scope) = cache.scopes.get_mut(&scope) {
                scope.hosts.remove(key);
            }
        });
    }

    /// `ghost ghostd forget`: drops what the cache holds about `target`,
    /// in every scope and for every user: an instance's names, address and
    /// host IDs, an `ssh://` destination's or `local`'s host IDs. A name
    /// that is not cached is looked up through the API to find its
    /// instance.
    pub(crate) async fn forget_target(&self, target: &Target) -> Result<Forgotten> {
        let Some(path) = self.cache_file.clone() else {
            return Ok(Forgotten::default());
        };
        let mut forgotten = Forgotten::default();
        match target {
            Target::Local => {
                change_cache_file(&path, |cache| {
                    for scope in cache.scopes.values_mut() {
                        forgotten.hosts +=
                            usize::from(scope.hosts.remove(LOCAL_HOST_KEY).is_some());
                    }
                });
            }
            Target::Ssh { host, port, .. } => {
                let prefix = ssh_host_prefix(host, *port);
                change_cache_file(&path, |cache| {
                    for scope in cache.scopes.values_mut() {
                        let before = scope.hosts.len();
                        scope.hosts.retain(|key, _| !key.starts_with(&prefix));
                        forgotten.hosts += before - scope.hosts.len();
                    }
                });
            }
            Target::Instance(InstanceReference::Id(id)) => {
                forgotten = forget_instance_in(&path, *id);
                forget_host_keys(*id);
            }
            Target::Instance(InstanceReference::Name(name)) => {
                let key = folded(name);
                let mut ids: Vec<Uuid> = self
                    .read_cache()
                    .scopes
                    .values()
                    .filter_map(|scope| scope.names.get(&key).map(|entry| entry.instance_id))
                    .collect();
                if ids.is_empty() {
                    let seed_file = self.seed_file.clone();
                    let api = ApiClient::with_identity_loader(
                        &self.api_url,
                        Box::new(move || crate::account_identity(seed_file.as_deref())),
                    )?;
                    let id = crate::resolve_instance(
                        &api,
                        &InstanceReference::Name(name.clone()),
                        InstanceUse::Read,
                    )
                    .await
                    .with_context(|| {
                        format!(
                            "the cache holds no instance named {name}, and looking it up failed"
                        )
                    })?;
                    ids.push(id);
                }
                ids.sort_unstable();
                ids.dedup();
                for id in ids {
                    forgotten += forget_instance_in(&path, id);
                    forget_host_keys(id);
                }
            }
        }
        Ok(forgotten)
    }
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}
