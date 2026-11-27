use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{Context as _, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::{io::AsyncWriteExt as _, process::Command};
use uuid::Uuid;

use super::{BuildArgs, CacheCredential, client, https_url, path};
use crate::ApiClient;

pub(super) const PUBLIC_KEY: &str =
    "cache.nixos.org-1:6NCHdD59X431o0gWypbMrAURkbJ16ZPMQFGspcDShjY=";

#[derive(Deserialize)]
struct Flake {
    path: PathBuf,
    revision: Option<String>,
    url: String,
    locked: LockedInput,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
struct LockedInput {
    #[serde(rename = "type")]
    kind: String,
    rev: Option<String>,
    nar_hash: Option<String>,
    rev_count: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PathInfo {
    pub nar_hash: String,
    pub nar_size: u64,
    pub references: BTreeSet<String>,
}

pub(super) struct Build {
    pub source: PathBuf,
    pub revision: Option<String>,
    pub root: String,
    pub closure: BTreeMap<String, PathInfo>,
    _roots: tempfile::TempDir,
}

pub(super) fn nix() -> Command {
    let mut command = Command::new("nix");
    command.args(["--extra-experimental-features", "nix-command flakes"]);
    command.kill_on_drop(true);
    command
}

pub(super) async fn run(command: &mut Command, operation: &str) -> Result<Vec<u8>> {
    let output = command
        .stderr(Stdio::inherit())
        .output()
        .await
        .with_context(|| format!("start {operation}"))?;
    ensure!(
        output.status.success(),
        "{operation} failed ({})",
        output.status
    );
    Ok(output.stdout)
}

pub(super) fn store_basename(path: &str) -> Option<&str> {
    let name = path.strip_prefix("/nix/store/")?;
    let (hash, suffix) = name.split_at_checked(32)?;
    let suffix = suffix.strip_prefix('-')?;
    (path.len() <= 255
        && !suffix.is_empty()
        && hash
            .bytes()
            .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte))
        && suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+._?=-".contains(&byte)))
    .then_some(name)
}

pub(super) async fn local(input: &BuildArgs) -> Result<Build> {
    ensure!(
        cfg!(all(target_os = "linux", target_arch = "x86_64")),
        "local NixOS builds require x86-64 Linux"
    );
    let name = &input.configuration;
    ensure!(
        !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte)),
        "invalid NixOS configuration name"
    );
    let directory = input
        .flake
        .canonicalize()
        .context("open the local flake directory")?;
    ensure!(
        directory.join("flake.lock").is_file() && directory.join("flake.nix").is_file(),
        "the flake directory needs flake.nix and flake.lock"
    );
    let lock = [
        "--no-write-lock-file",
        "--no-update-lock-file",
        "--no-use-registries",
    ];
    let metadata = resolve(&directory, ".", &lock).await?;
    let source = metadata
        .path
        .to_str()
        .context("non-UTF-8 Nix flake store path")?;
    ensure!(
        store_basename(source).is_some() && metadata.path.join("flake.lock").is_file(),
        "the locked flake snapshot has no valid store path or lock file"
    );
    let roots = tempfile::Builder::new()
        .prefix("ghost-nixos-roots-")
        .tempdir()?;
    let mut add_source_root = Command::new("nix-store");
    add_source_root
        .kill_on_drop(true)
        .args(["--realise", "--add-root"])
        .arg(roots.path().join("source"))
        .args(["--indirect", source]);
    run(&mut add_source_root, "protect the locked flake source").await?;
    let reference = if metadata.locked.kind == "git" {
        let url = reqwest::Url::parse(&metadata.url).context("read the resolved Git flake URL")?;
        let revision = metadata.locked.rev.as_deref();
        ensure!(
            revision.is_some()
                && revision == metadata.revision.as_deref()
                && url.scheme().starts_with("git+")
                && url
                    .query_pairs()
                    .any(|(key, value)| key == "rev" && Some(value.as_ref()) == revision)
                && metadata.locked.nar_hash.is_some(),
            "the Git flake is not pinned to a reproducible commit; commit its changes and try again"
        );
        let locked = resolve(&directory, &metadata.url, &lock).await?;
        ensure!(
            locked.path == metadata.path && locked.locked == metadata.locked,
            "the pinned Git revision resolves to different source; commit the flake and try again"
        );
        metadata.url.clone()
    } else {
        format!("path:{source}")
    };
    let installable =
        format!("{reference}#nixosConfigurations.\"{name}\".config.system.build.toplevel");
    let root = run(
        nix()
            .args([
                "build",
                "--print-out-paths",
                "--option",
                "system",
                "x86_64-linux",
                "--option",
                "builders",
                "",
            ])
            .arg("--out-link")
            .arg(roots.path().join("candidate"))
            .args(lock)
            .arg(installable),
        "nix build",
    )
    .await?;
    let root = String::from_utf8(root)?.trim().to_owned();
    ensure!(
        store_basename(&root).is_some()
            && Path::new(&root)
                .join("bin/switch-to-configuration")
                .is_file(),
        "Nix did not build one system closure"
    );
    let closure = closure(&root).await?;
    Ok(Build {
        source: metadata.path,
        revision: metadata.revision,
        root,
        closure,
        _roots: roots,
    })
}

async fn resolve(directory: &Path, reference: &str, lock: &[&str]) -> Result<Flake> {
    let output = run(
        nix()
            .args(["flake", "metadata", "--json"])
            .args(lock)
            .current_dir(directory)
            .arg(reference),
        "nix flake metadata",
    )
    .await?;
    serde_json::from_slice(&output).context("read Nix flake metadata")
}

async fn closure(root: &str) -> Result<BTreeMap<String, PathInfo>> {
    ensure!(store_basename(root).is_some(), "invalid system store path");
    let bytes = run(
        nix().args(["path-info", "--recursive", "--json", "--", root]),
        "nix path-info",
    )
    .await?;
    let paths: BTreeMap<String, PathInfo> =
        serde_json::from_slice(&bytes).context("read Nix closure metadata")?;
    ensure!(
        paths.contains_key(root)
            && paths.len() <= 100_000
            && paths.iter().all(|(path, info)| {
                store_basename(path).is_some()
                    && info
                        .references
                        .iter()
                        .all(|reference| paths.contains_key(reference))
            }),
        "invalid or oversized Nix closure"
    );
    Ok(paths)
}

pub(super) async fn diff(
    api: &ApiClient,
    instance: Uuid,
    prior: Option<&str>,
    candidate: &Build,
) -> Result<Value> {
    let candidate_paths: BTreeSet<_> = candidate.closure.keys().collect();
    let Some(prior) = prior else {
        return Ok(
            json!({"candidate_root":candidate.root, "active_root":null, "candidate_packages":candidate_paths, "candidate_service_units":units(&candidate.root)?.keys().collect::<Vec<_>>()}),
        );
    };
    ensure!(
        store_basename(prior).is_some(),
        "invalid active system store path"
    );
    if !Path::new(prior).exists() {
        fetch_previous(api, instance, prior).await?;
    }
    let previous = closure(prior).await?;
    let prior_paths: BTreeSet<_> = previous.keys().collect();
    let old_units = units(prior)?;
    let new_units = units(&candidate.root)?;
    let changed_units: BTreeSet<_> = old_units
        .keys()
        .chain(new_units.keys())
        .filter(|unit| old_units.get(*unit) != new_units.get(*unit))
        .collect();
    Ok(json!({"candidate_root":candidate.root, "active_root":prior,
        "added_packages":candidate_paths.difference(&prior_paths).collect::<Vec<_>>(),
        "removed_packages":prior_paths.difference(&candidate_paths).collect::<Vec<_>>(),
        "changed_service_units":changed_units,
    }))
}

fn units(root: &str) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut result = BTreeMap::new();
    for entry in fs::read_dir(Path::new(root).join("etc/systemd/system"))
        .context("read system service units")?
    {
        let entry = entry?;
        if entry.path().extension() == Some(OsStr::new("service")) {
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| anyhow::anyhow!("invalid systemd service name"))?;
            let contents =
                fs::read(entry.path()).with_context(|| format!("read systemd unit {name}"))?;
            result.insert(name, contents);
        }
    }
    Ok(result)
}

async fn fetch_previous(api: &ApiClient, instance: Uuid, root: &str) -> Result<()> {
    let value = api
        .app("nix", "GET", &path(instance, "cache"), None, None)
        .await?;
    let documents: CacheCredential =
        serde_json::from_value(value).context("invalid Nix cache credential")?;
    let url = https_url(&documents.url)?;
    let key_url = https_url(&documents.public_key_url)?;
    ensure!(
        url.origin() == key_url.origin()
            && key_url.path() == format!("{}/ghostrack-cache-key", url.path()),
        "Nix cache public key URL is outside the cache"
    );
    ensure!(
        documents.login == "ghost-cache"
            && documents
                .password
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"_-".contains(&byte)),
        "invalid Nix cache login"
    );
    let response = client()?
        .get(key_url)
        .basic_auth(&documents.login, Some(documents.password.as_str()))
        .timeout(Duration::from_secs(15))
        .send()
        .await?
        .error_for_status()?;
    ensure!(
        response
            .content_length()
            .is_some_and(|length| length <= 128),
        "invalid Nix cache public key size"
    );
    let public_key = response.text().await?;
    ensure!(
        public_key.starts_with("ghostrack-")
            && public_key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-:/+=".contains(&byte)),
        "invalid Nix cache public key"
    );
    let file = tempfile::NamedTempFile::new()?;
    let mut netrc = tokio::fs::File::from_std(file.reopen()?);
    netrc
        .write_all(
            format!(
                "machine {} login {} password {}\n",
                url.host_str().context("missing cache host")?,
                documents.login,
                documents.password.as_str()
            )
            .as_bytes(),
        )
        .await?;
    netrc.flush().await?;
    let status = nix()
        .args([
            "copy",
            "--from",
            url.as_str(),
            "--option",
            "require-sigs",
            "true",
            "--option",
            "substituters",
            "",
            "--option",
            "netrc-file",
        ])
        .arg(file.path())
        .args([
            "--option",
            "trusted-public-keys",
            &format!("{public_key} {PUBLIC_KEY}"),
            "--",
            root,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await?;
    ensure!(
        status.success(),
        "could not copy the active system from its signed cache"
    );
    Ok(())
}
