//! `ghost instance console`: the serial console of a VM instance through the system's `ssh`, in two
//! hops (item 195). The first goes to the console server of the API's deployment, its host key checked
//! strictly against the one this ghost was built with: the key comes from
//! `config/console-host-key.pub`, which a release fills (`scripts/check-console-host-key.sh` refuses a
//! release with the repository's placeholder); `--console-host-key` or `GHOST_CONSOLE_HOST_KEY` names
//! another deployment's. That server only relays (`ssh -W`, as `ProxyCommand`) to the second hop: the
//! console's own SSH server, which the agent of the instance's host runs, and which checks the login
//! itself against the keys the account key signed. Its host key is the host's own, which the instance
//! names (`console_host_key`); ghost keeps it the first time (under [`instance_alias`]) and refuses a
//! host that later shows another, with both fingerprints.
//!
//! Both keys go into a known hosts file of ghost's own (`console_known_hosts` in its data directory,
//! apart from the `ghost x` file): the console server's under the alias [`HOST_KEY_ALIAS`], written
//! each run, and the hosts' kept as they were learnt. `ssh` runs with that file alone,
//! `StrictHostKeyChecking=yes` and no key updates: a server with another key is refused, never
//! learned.

use std::{
    ffi::OsString, fmt::Write as _, fs, io::Write as _, os::unix::fs::OpenOptionsExt as _,
    path::Path,
};

use anyhow::{Context as _, Result, bail};
use ghostrack_client_api::{
    api::GetInstance,
    website::{InstanceKind, InstanceView},
};

use crate::{Cli, Command, InstanceCommand, InstanceUse, Terminal};

/// The console's host key this ghost was built with, one OpenSSH public key
/// line (`config/console-host-key.pub`).
pub(crate) const BUILT_IN_HOST_KEY: &str = include_str!("../config/console-host-key.pub");

/// What the repository's placeholder key holds where a key's blob goes.
pub(crate) const PLACEHOLDER: &str = "PLACEHOLDER";

/// The name the console's host key is filed under in ghost's known hosts.
pub(crate) const HOST_KEY_ALIAS: &str = "ghostrack-console";

/// The console server's port.
pub(crate) const CONSOLE_PORT: u16 = 2222;

/// The host key line's type and blob: `ssh-ed25519` and its base64, or why
/// it is none.
pub(crate) fn host_key(line: &str) -> Result<(String, String)> {
    let line = line
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .unwrap_or("");
    let mut fields = line.split_ascii_whitespace();
    let (Some(kind), Some(blob)) = (fields.next(), fields.next()) else {
        bail!("the console's host key is not an OpenSSH public key line");
    };
    if blob == PLACEHOLDER {
        bail!(
            "this ghost was built without the console's host key: give it with --console-host-key or GHOST_CONSOLE_HOST_KEY (the public docs list its fingerprint)"
        );
    }
    if !ghostrack_client_api::website::valid_ssh_public_key(&format!("{kind} {blob}")) {
        bail!("the console's host key is not an OpenSSH public key line");
    }
    Ok((kind.to_owned(), blob.to_owned()))
}

/// The console server for the API at `api_url`: `console.` and the API's
/// domain (the API's host without a leading `api.`), port 2222; or
/// `chosen`, HOST or HOST:PORT.
pub(crate) fn console_server(api_url: &str, chosen: Option<&str>) -> Result<(String, u16)> {
    if let Some(chosen) = chosen.map(str::trim).filter(|chosen| !chosen.is_empty()) {
        return Ok(match chosen.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') || host.ends_with(']') => (
                host.trim_start_matches('[')
                    .trim_end_matches(']')
                    .to_owned(),
                port.parse()
                    .with_context(|| format!("{chosen} names no port a console server has"))?,
            ),
            _ => (chosen.to_owned(), CONSOLE_PORT),
        });
    }
    let url = reqwest::Url::parse(api_url).with_context(|| format!("{api_url} is not a URL"))?;
    let Some(host) = url.host_str() else {
        bail!("{api_url} names no host; give the console's with --console-host");
    };
    let domain = host.strip_prefix("api.").unwrap_or(host);
    Ok((format!("console.{domain}"), CONSOLE_PORT))
}

/// The alias the console host key of instance `instance_id`'s host is kept under.
pub(crate) fn instance_alias(instance_id: uuid::Uuid) -> String {
    format!("ghostrack-instance-{instance_id}")
}

/// The SHA-256 fingerprint of the key `(kind, blob)`, as `ssh-keygen -l` shows it.
fn fingerprint((kind, blob): &(String, String)) -> String {
    ghostrack_client_api::website::ssh_public_key_fingerprint(&format!("{kind} {blob}"))
        .map_or_else(|| blob.clone(), |(_, fingerprint)| fingerprint)
}

/// Write the known hosts file at `path`: the console server's key `server` under
/// [`HOST_KEY_ALIAS`], and the console host key `host` of instance `instance_id`'s host under its
/// [`instance_alias`], kept as it was the first time: every host key learnt before stays. A host
/// whose key differs from the one kept is refused, with both fingerprints. The file is the
/// console's own, written whole each run, so it never loses a line `ghost x` learns into its file at
/// the same time.
pub(crate) fn write_known_hosts(
    path: &Path,
    server: &(String, String),
    instance_id: uuid::Uuid,
    host: &(String, String),
) -> Result<()> {
    let alias = instance_alias(instance_id);
    let existing = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(error) => {
            return Err(error).with_context(|| format!("read {}", path.display()));
        }
    };
    let mut kept: Vec<String> = Vec::new();
    let mut known = false;
    for line in existing.lines() {
        let mut fields = line.split_ascii_whitespace();
        let (Some(name), Some(kind), Some(blob)) = (fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if !name.starts_with("ghostrack-instance-") {
            continue;
        }
        if name == alias {
            let kept_key = (kind.to_owned(), blob.to_owned());
            if kept_key != *host {
                bail!(
                    "the console of instance {instance_id} shows another host key than the one kept for it: kept {}, shown {}. If its host was reinstalled, remove the line `{alias}` from {} and run this again; otherwise do not connect",
                    fingerprint(&kept_key),
                    fingerprint(host),
                    path.display()
                );
            }
            known = true;
        }
        kept.push(format!("{name} {kind} {blob}"));
    }
    if !known {
        kept.push(format!("{alias} {} {}", host.0, host.1));
    }
    let mut body = format!("{HOST_KEY_ALIAS} {} {}\n", server.0, server.1);
    for line in kept {
        body.push_str(&line);
        body.push('\n');
    }
    let temporary = path.with_extension("console-tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("create {}", temporary.display()))?;
    file.write_all(body.as_bytes())
        .and_then(|()| file.sync_all())
        .with_context(|| format!("write {}", temporary.display()))?;
    fs::rename(&temporary, path).with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

/// `text` as one word of `/bin/sh`, which runs `ProxyCommand`: single-quoted, and with `%` doubled,
/// as ssh expands its tokens in it first.
fn shell_word(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''").replace('%', "%%"))
}

/// The `ssh` options that check a server's key against `known_hosts` alone, under `alias`, and
/// forward nothing.
fn strict_options(alias: &str, known_hosts: &Path) -> Vec<String> {
    vec![
        format!("HostKeyAlias={alias}"),
        "StrictHostKeyChecking=yes".to_owned(),
        "UpdateHostKeys=no".to_owned(),
        "GlobalKnownHostsFile=none".to_owned(),
        format!("UserKnownHostsFile={}", known_hosts.display()),
        "CheckHostIP=no".to_owned(),
        // Only the guest's console is served: nothing to forward.
        "ForwardAgent=no".to_owned(),
        "ForwardX11=no".to_owned(),
        "ClearAllForwardings=yes".to_owned(),
    ]
}

/// The `ssh` that opens the console of instance `instance_id`: through the console server at
/// `host`, `port` (`ssh -W`, as `ProxyCommand`), to the console SSH server of the instance's host,
/// each checked against the known hosts file `known_hosts` alone.
pub(crate) fn ssh_argv(
    host: &str,
    port: u16,
    instance_id: uuid::Uuid,
    known_hosts: &Path,
) -> Vec<OsString> {
    let mut proxy = format!("ssh -p {port}");
    for option in strict_options(HOST_KEY_ALIAS, known_hosts) {
        proxy.push_str(" -o ");
        proxy.push_str(&shell_word(&option));
    }
    let _ = write!(proxy, " -l {instance_id} -W %h:%p -- {}", shell_word(host));
    let mut argv: Vec<OsString> = ["ssh", "-t", "-o"]
        .into_iter()
        .map(OsString::from)
        .collect();
    argv.push(format!("ProxyCommand={proxy}").into());
    for option in strict_options(&instance_alias(instance_id), known_hosts) {
        argv.push("-o".into());
        argv.push(option.into());
    }
    argv.push("-l".into());
    argv.push(instance_id.to_string().into());
    argv.push("--".into());
    argv.push(instance_id.to_string().into());
    argv
}

/// What `ghost instance console` says of a host whose agent has no console SSH server yet.
pub(crate) const AGENT_NEEDS_UPDATE: &str =
    "This host's agent needs an update before its console opens.";

/// Run `ghost instance console`: `None` for any other command; the exit
/// code otherwise, `ssh`'s own once it ran.
pub async fn run_console(cli: &Cli) -> Option<u8> {
    let Command::Instance {
        command:
            InstanceCommand::Console {
                instance_id,
                console_host,
                console_host_key,
            },
    } = &cli.command
    else {
        return None;
    };
    Some(
        match console(
            cli,
            instance_id,
            console_host.as_deref(),
            console_host_key.as_deref(),
        )
        .await
        {
            Ok(code) => code,
            Err(error) => {
                crate::notice(&crate::render_error(&error, Terminal::stderr()));
                1
            }
        },
    )
}

async fn console(
    cli: &Cli,
    reference: &crate::InstanceReference,
    console_host: Option<&str>,
    console_host_key: Option<&str>,
) -> Result<u8> {
    let key = host_key(console_host_key.unwrap_or(BUILT_IN_HOST_KEY))?;
    let (host, port) = console_server(&cli.globals.api_url, console_host)?;
    let api = crate::api_client(cli)?;
    let instance_id = crate::resolve_instance(&api, reference, InstanceUse::Read).await?;
    let instance: InstanceView = api.read(&GetInstance { instance_id }, "").await?;
    if instance.kind == InstanceKind::Container {
        bail!(
            "{} is a container instance, which has no serial console: `ghost instance logs {instance_id}` shows what its container wrote",
            instance.display_name()
        );
    }
    let Some(host_key_line) = instance.console_host_key.as_deref() else {
        bail!("{AGENT_NEEDS_UPDATE}");
    };
    let instance_key = host_key(host_key_line)
        .context("the instance's console host key is not an OpenSSH public key line")?;
    let known_hosts = crate::ghostd::data_file("console_known_hosts")?;
    write_known_hosts(&known_hosts, &key, instance_id, &instance_key)?;
    let argv = ssh_argv(&host, port, instance_id, &known_hosts);
    let status = tokio::process::Command::new(&argv[0])
        .args(&argv[1..])
        .status()
        .await
        .context("run ssh, which `ghost instance console` needs (OpenSSH's client)")?;
    Ok(status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHeHGO1Mp+d9SZrDhuNTitg9vmYCj0pZiw+EuZbKDbM0 ghostrack-console";

    #[test]
    fn the_placeholder_and_a_bad_line_are_no_host_key() {
        let error = host_key(BUILT_IN_HOST_KEY).map(drop);
        // A release fills the file; the repository holds the placeholder.
        if BUILT_IN_HOST_KEY.contains(PLACEHOLDER) {
            assert!(
                error
                    .unwrap_err()
                    .to_string()
                    .contains("built without the console's host key")
            );
        }
        assert!(host_key("ssh-ed25519").is_err());
        assert!(host_key("ssh-ed25519 !!! x").is_err());
        assert_eq!(
            host_key(KEY).unwrap(),
            (
                "ssh-ed25519".to_owned(),
                "AAAAC3NzaC1lZDI1NTE5AAAAIHeHGO1Mp+d9SZrDhuNTitg9vmYCj0pZiw+EuZbKDbM0".to_owned()
            )
        );
    }

    #[test]
    fn the_console_server_is_the_apis_domain_on_2222() {
        assert_eq!(
            console_server("https://api.ghostrack.io", None).unwrap(),
            ("console.ghostrack.io".to_owned(), 2222)
        );
        assert_eq!(
            console_server("http://127.0.0.1:8080", None).unwrap(),
            ("console.127.0.0.1".to_owned(), 2222)
        );
        assert_eq!(
            console_server("https://api.ghostrack.io", Some("localhost:2200")).unwrap(),
            ("localhost".to_owned(), 2200)
        );
        assert_eq!(
            console_server("https://api.ghostrack.io", Some("[::1]:2201")).unwrap(),
            ("::1".to_owned(), 2201)
        );
        assert_eq!(
            console_server("https://api.ghostrack.io", Some("console.example")).unwrap(),
            ("console.example".to_owned(), 2222)
        );
    }

    const HOST: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBB7b7LsNyXIwthNFYpb5kE4yvG1xtXbqPaDqeVSoYSf";
    const OTHER_HOST: &str =
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOTMfZnvvTUgUVWuRBFRyrdOfg4mqyHyPnB12e4eTSL4";

    #[test]
    fn the_known_hosts_keep_each_hosts_key_from_its_first_sight() {
        let directory = tempfile::tempdir().unwrap();
        let known_hosts = directory.path().join("console_known_hosts");
        fs::write(&known_hosts, "ghostrack-console ssh-ed25519 OLDKEY\n").unwrap();
        let (one, two) = (uuid::Uuid::from_u128(7), uuid::Uuid::from_u128(8));
        let server = host_key(KEY).unwrap();
        write_known_hosts(&known_hosts, &server, one, &host_key(HOST).unwrap()).unwrap();
        write_known_hosts(&known_hosts, &server, two, &host_key(OTHER_HOST).unwrap()).unwrap();
        // The same key again changes nothing.
        write_known_hosts(&known_hosts, &server, one, &host_key(HOST).unwrap()).unwrap();
        let written = fs::read_to_string(&known_hosts).unwrap();
        assert_eq!(
            written,
            format!(
                "ghostrack-console {}\nghostrack-instance-{one} {HOST}\nghostrack-instance-{two} {OTHER_HOST}\n",
                KEY.trim_end_matches(" ghostrack-console")
            )
        );
        // Another key for a host kept is refused, with both fingerprints,
        // and the file stays as it was.
        let error = write_known_hosts(&known_hosts, &server, one, &host_key(OTHER_HOST).unwrap())
            .unwrap_err()
            .to_string();
        let shown = |line: &str| {
            ghostrack_client_api::website::ssh_public_key_fingerprint(line)
                .unwrap()
                .1
        };
        assert!(error.contains(&shown(HOST)), "{error}");
        assert!(error.contains(&shown(OTHER_HOST)), "{error}");
        assert_eq!(fs::read_to_string(&known_hosts).unwrap(), written);
    }

    #[test]
    fn ssh_jumps_through_the_console_server_to_the_hosts_own() {
        let known_hosts = Path::new("/home/a user/.local/share/ghost/100%/console_known_hosts");
        let instance = uuid::Uuid::from_u128(7);
        let argv = ssh_argv("console.ghostrack.io", 2222, instance, known_hosts);
        let argv: Vec<String> = argv
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        let id = "00000000-0000-0000-0000-000000000007";
        let quoted_known =
            "'UserKnownHostsFile=/home/a user/.local/share/ghost/100%%/console_known_hosts'";
        let proxy = format!(
            "ProxyCommand=ssh -p 2222 -o 'HostKeyAlias=ghostrack-console' -o 'StrictHostKeyChecking=yes' -o 'UpdateHostKeys=no' -o 'GlobalKnownHostsFile=none' -o {quoted_known} -o 'CheckHostIP=no' -o 'ForwardAgent=no' -o 'ForwardX11=no' -o 'ClearAllForwardings=yes' -l {id} -W %h:%p -- 'console.ghostrack.io'"
        );
        let known = format!("UserKnownHostsFile={}", known_hosts.display());
        let alias = format!("HostKeyAlias=ghostrack-instance-{id}");
        let expected: Vec<&str> = vec![
            "ssh",
            "-t",
            "-o",
            &proxy,
            "-o",
            &alias,
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "GlobalKnownHostsFile=none",
            "-o",
            &known,
            "-o",
            "CheckHostIP=no",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ForwardX11=no",
            "-o",
            "ClearAllForwardings=yes",
            "-l",
            id,
            "--",
            id,
        ];
        assert_eq!(argv, expected);
        assert_eq!(shell_word("it's"), "'it'\\''s'");
    }

    /// A release refuses the repository's placeholder, and takes a real
    /// Ed25519 key (`scripts/check-console-host-key.sh`).
    #[test]
    fn a_release_refuses_the_placeholder_host_key() {
        let script =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/check-console-host-key.sh");
        let directory = tempfile::tempdir().unwrap();
        let check = |line: &str| {
            let file = directory.path().join("console-host-key.pub");
            fs::write(&file, line).unwrap();
            std::process::Command::new("bash")
                .arg(&script)
                .arg(&file)
                .output()
                .unwrap()
                .status
                .success()
        };
        assert!(!check("ssh-ed25519 PLACEHOLDER ghostrack-console\n"));
        assert!(!check(
            "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA== x\n"
        ));
        assert!(!check(""));
        assert!(check(&format!("{KEY}\n")));
    }
}
