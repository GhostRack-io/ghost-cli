//! `ghost instance console`: the serial console of a VM instance through the system's `ssh`, to the
//! console server of the API's deployment, its host key checked strictly against the one this ghost
//! was built with.  The key comes from `config/console-host-key.pub`, which a release fills
//! (`scripts/check-console-host-key.sh` refuses a release with the repository's placeholder);
//! `--console-host-key` or `GHOST_CONSOLE_HOST_KEY` names another deployment's. Before each run
//! ghost writes it into a known hosts file of its own (`console_known_hosts` in its data directory,
//! apart from the `ghost x` file) under the alias [`HOST_KEY_ALIAS`], and runs `ssh` with that file
//! alone, `StrictHostKeyChecking=yes` and no key updates: a server with another key is refused,
//! never learned.

use std::{ffi::OsString, fs, io::Write as _, os::unix::fs::OpenOptionsExt as _, path::Path};

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

/// Write the console's host key `(kind, blob)` as the only line of the
/// known hosts file at `path`, under [`HOST_KEY_ALIAS`]. The file is the
/// console's own, written whole each run, so it never loses a line
/// `ghost x` learns into its file at the same time.
pub(crate) fn write_known_host(path: &Path, (kind, blob): &(String, String)) -> Result<()> {
    let line = format!("{HOST_KEY_ALIAS} {kind} {blob}\n");
    let temporary = path.with_extension("console-tmp");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&temporary)
        .with_context(|| format!("create {}", temporary.display()))?;
    file.write_all(line.as_bytes())
        .and_then(|()| file.sync_all())
        .with_context(|| format!("write {}", temporary.display()))?;
    fs::rename(&temporary, path).with_context(|| format!("replace {}", path.display()))?;
    Ok(())
}

/// The `ssh` that opens the console of instance `instance_id` at `host`,
/// `port`, checking its key against the known hosts file `known_hosts`
/// alone.
pub(crate) fn ssh_argv(
    host: &str,
    port: u16,
    instance_id: uuid::Uuid,
    known_hosts: &Path,
) -> Vec<OsString> {
    let mut argv: Vec<OsString> = ["ssh", "-t", "-p"]
        .into_iter()
        .map(OsString::from)
        .collect();
    argv.push(port.to_string().into());
    for option in [
        format!("HostKeyAlias={HOST_KEY_ALIAS}"),
        "StrictHostKeyChecking=yes".to_owned(),
        "UpdateHostKeys=no".to_owned(),
        "GlobalKnownHostsFile=none".to_owned(),
        "CheckHostIP=no".to_owned(),
        // Only the guest's console is served: nothing to forward.
        "ForwardAgent=no".to_owned(),
        "ForwardX11=no".to_owned(),
        "ClearAllForwardings=yes".to_owned(),
    ] {
        argv.push("-o".into());
        argv.push(option.into());
    }
    argv.push("-o".into());
    let mut known = OsString::from("UserKnownHostsFile=");
    known.push(known_hosts.as_os_str());
    argv.push(known);
    argv.push("-l".into());
    argv.push(instance_id.to_string().into());
    argv.push("--".into());
    argv.push(host.into());
    argv
}

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
    let known_hosts = crate::ghostd::data_file("console_known_hosts")?;
    write_known_host(&known_hosts, &key)?;
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

    #[test]
    fn ssh_checks_the_built_in_key_strictly() {
        let directory = tempfile::tempdir().unwrap();
        let known_hosts = directory.path().join("console_known_hosts");
        fs::write(&known_hosts, "ghostrack-console ssh-ed25519 OLDKEY\n").unwrap();
        write_known_host(&known_hosts, &host_key(KEY).unwrap()).unwrap();
        let written = fs::read_to_string(&known_hosts).unwrap();
        assert_eq!(
            written,
            "ghostrack-console ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHeHGO1Mp+d9SZrDhuNTitg9vmYCj0pZiw+EuZbKDbM0\n"
        );
        let instance = uuid::Uuid::from_u128(7);
        let argv = ssh_argv("console.ghostrack.io", 2222, instance, &known_hosts);
        let argv: Vec<String> = argv
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        let expected_known = format!("UserKnownHostsFile={}", known_hosts.display());
        let expected: Vec<&str> = vec![
            "ssh",
            "-t",
            "-p",
            "2222",
            "-o",
            "HostKeyAlias=ghostrack-console",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "GlobalKnownHostsFile=none",
            "-o",
            "CheckHostIP=no",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ForwardX11=no",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            &expected_known,
            "-l",
            "00000000-0000-0000-0000-000000000007",
            "--",
            "console.ghostrack.io",
        ];
        assert_eq!(argv, expected);
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
