use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Read, Write as _},
    path::{Path, PathBuf},
    process::Stdio,
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use futures_util::{StreamExt as _, stream};
use reqwest::{Client, StatusCode, Url, header};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use tokio::{io::AsyncWriteExt as _, process::Command};
use tokio_util::io::ReaderStream;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::{
    build::{Build, PUBLIC_KEY, PathInfo, nix, store_basename},
    https_url,
};
use crate::{ApiClient, api::is_transient};

const MAX_SOURCE: u64 = 256 * 1024 * 1024;
const MAX_PRIVATE: u64 = 8 * 1024 * 1024 * 1024;
const MAX_MANIFEST: usize = 32 * 1024 * 1024;
const MAX_NARINFO: usize = 64 * 1024;
// Attempts after an unknown outcome or a retryable rejection.
const ATTEMPTS: u32 = 3;
// The location receives for up to two hours after the grant was checked,
// then publishes. The grant's lifetime does not bound a started upload.
const PUT_TIMEOUT: Duration = Duration::from_mins(150);
// How long an upload waits while the account's other uploads hold the
// location's slots for it.
const BUSY_WAIT: Duration = Duration::from_mins(10);
const BUSY_RETRY: Duration = Duration::from_secs(30);
const BUSY_RETRY_MAX: Duration = Duration::from_mins(1);

pub(super) struct Archive {
    pub manifest_sha256: String,
    pub source_sha256: String,
    file: PathBuf,
    root: String,
    _scratch: Option<tempfile::TempDir>,
}

/// The file names of an archive kept in a directory (`ghost nixos builder
/// build --out`): the v1 frame and its figures.
const ARCHIVE_FILE: &str = "generation.ghnupl";
const FIGURES_FILE: &str = "generation.json";

/// An archive's figures: what `ghost nixos builder build` prints and keeps
/// beside the archive.
#[derive(Clone, Debug, Deserialize, serde::Serialize, PartialEq, Eq)]
pub(super) struct Figures {
    pub root_path: String,
    pub manifest_sha256: String,
    pub source_sha256: String,
}

#[derive(Deserialize)]
pub(super) struct Grant {
    url: String,
    #[serde(deserialize_with = "super::password")]
    token: Zeroizing<String>,
    expires_at: u64,
}

#[derive(Deserialize)]
struct PublicationReceipt {
    generation_id: Uuid,
    root_path: String,
}

enum Sent {
    Published,
    Rejected(StatusCode),
    // The account's other uploads are in progress: retry after this long.
    Busy(Duration),
    Unknown,
}

struct Retries {
    failures: u32,
    busy_until: Instant,
}

impl Retries {
    fn new(now: Instant) -> Self {
        Self {
            failures: 0,
            busy_until: now + BUSY_WAIT,
        }
    }

    // The wait before the next attempt, or `None` once attempts run out.
    // Waiting for the account's other uploads uses no attempt while it lasts.
    fn after(&mut self, busy: Option<Duration>, now: Instant) -> Option<Duration> {
        if let Some(wait) = busy
            && now + wait <= self.busy_until
        {
            return Some(wait);
        }
        self.failures += 1;
        (self.failures < ATTEMPTS).then(|| Duration::from_secs(1 << (self.failures - 1)))
    }
}

fn retry_after(headers: &header::HeaderMap) -> Duration {
    headers
        .get(header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map_or(BUSY_RETRY, |seconds| {
            Duration::from_secs(seconds).clamp(Duration::from_secs(1), BUSY_RETRY_MAX)
        })
}

impl Archive {
    pub fn figures(&self) -> Figures {
        Figures {
            root_path: self.root.clone(),
            manifest_sha256: self.manifest_sha256.clone(),
            source_sha256: self.source_sha256.clone(),
        }
    }

    /// Keep the archive in `directory` with its figures, for a later
    /// [`Archive::open`] (the builder's send step).
    pub fn persist(self, directory: &Path) -> Result<Figures> {
        fs::create_dir_all(directory)?;
        let file = directory.join(ARCHIVE_FILE);
        if fs::rename(&self.file, &file).is_err() {
            fs::copy(&self.file, &file).context("keep the generation archive")?;
        }
        let figures = self.figures();
        fs::write(directory.join(FIGURES_FILE), serde_json::to_vec(&figures)?)?;
        Ok(figures)
    }

    /// The archive [`Archive::persist`] kept in `directory`.
    pub fn open(directory: &Path) -> Result<Self> {
        let figures: Figures = serde_json::from_slice(
            &fs::read(directory.join(FIGURES_FILE)).context("read the archive's figures")?,
        )
        .context("invalid archive figures")?;
        let file = directory.join(ARCHIVE_FILE);
        ensure!(file.is_file(), "the generation archive is missing");
        Ok(Self {
            manifest_sha256: figures.manifest_sha256,
            source_sha256: figures.source_sha256,
            file,
            root: figures.root_path,
            _scratch: None,
        })
    }

    /// Send the archive with `grant`, the generation's upload grant (no
    /// account key: a builder has the grant alone), with the same retries
    /// as [`Archive::upload`] while the grant is valid.
    pub async fn send_with(&self, client: &Client, grant: &Grant) -> Result<Uuid> {
        let url = https_url(&grant.url)?;
        let generation = url
            .path()
            .strip_prefix("/v1/nix/uploads/")
            .and_then(|id| Uuid::try_parse(id).ok())
            .context("Nix cache returned an unexpected upload path")?;
        let mut retries = Retries::new(Instant::now());
        loop {
            let mut busy = None;
            match self.send(client, generation, grant).await? {
                Sent::Published => return Ok(generation),
                Sent::Busy(wait) => busy = Some(wait),
                Sent::Rejected(status) => ensure!(
                    status.is_server_error() || status == StatusCode::REQUEST_TIMEOUT,
                    "Nix cache rejected generation {generation} ({status})"
                ),
                Sent::Unknown => {}
            }
            let Some(wait) = retries.after(busy, Instant::now()) else {
                ensure!(
                    busy.is_none(),
                    "Nix cache stayed busy with the account's other uploads; \
                     generation {generation} was not uploaded"
                );
                anyhow::bail!("upload outcome for generation {generation} is unknown")
            };
            tokio::time::sleep(wait).await;
        }
    }

    pub async fn upload(&self, api: &ApiClient, client: &Client, generation: Uuid) -> Result<()> {
        let target = format!("/cache/uploads/{generation}/credential");
        let mut retries = Retries::new(Instant::now());
        loop {
            let mut busy = None;
            let result = api.app("nix", "GET", &target, None, None).await;
            match result {
                Ok(value) => {
                    let grant: Grant =
                        serde_json::from_value(value).context("invalid Nix upload grant")?;
                    match self.send(client, generation, &grant).await? {
                        Sent::Published => return Ok(()),
                        Sent::Busy(wait) => busy = Some(wait),
                        Sent::Rejected(status) => ensure!(
                            status.is_server_error()
                                || matches!(
                                    status,
                                    StatusCode::REQUEST_TIMEOUT | StatusCode::UNAUTHORIZED
                                ),
                            "Nix cache rejected generation {generation} ({status})"
                        ),
                        Sent::Unknown => {}
                    }
                }
                Err(error)
                    if is_transient(&error)
                        || crate::api::rejection(&error)
                            .is_some_and(|error| error.status == 404) => {}
                Err(error) => return Err(error),
            }
            let Some(wait) = retries.after(busy, Instant::now()) else {
                ensure!(
                    busy.is_none(),
                    "Nix cache stayed busy with the account's other uploads; \
                     generation {generation} was not uploaded"
                );
                anyhow::bail!("upload outcome for generation {generation} is unknown")
            };
            tokio::time::sleep(wait).await;
        }
    }

    async fn send(&self, client: &Client, generation: Uuid, grant: &Grant) -> Result<Sent> {
        let url = https_url(&grant.url)?;
        ensure!(
            url.path() == format!("/v1/nix/uploads/{generation}"),
            "Nix cache returned an unexpected upload path"
        );
        let file = tokio::fs::File::open(&self.file).await?;
        let length = file.metadata().await?.len();
        // The grant must be valid when the upload starts, not until it ends.
        if grant.expires_at <= chrono::Utc::now().timestamp().unsigned_abs() {
            return Ok(Sent::Unknown);
        }
        let response = client
            .put(url)
            .bearer_auth(grant.token.as_str())
            .header(header::CONTENT_LENGTH, length)
            .body(reqwest::Body::wrap_stream(ReaderStream::new(file)))
            .timeout(PUT_TIMEOUT)
            .send()
            .await;
        let Ok(mut response) = response else {
            return Ok(Sent::Unknown);
        };
        let status = response.status();
        if status == StatusCode::TOO_MANY_REQUESTS {
            return Ok(Sent::Busy(retry_after(response.headers())));
        }
        if status != StatusCode::OK {
            return Ok(Sent::Rejected(status));
        }
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if body.len() + chunk.len() <= 4096 => {
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                _ => return Ok(Sent::Unknown),
            }
        }
        let Some(receipt) = serde_json::from_slice::<PublicationReceipt>(&body).ok() else {
            return Ok(Sent::Unknown);
        };
        Ok(
            if receipt.generation_id == generation && receipt.root_path == self.root {
                Sent::Published
            } else {
                Sent::Unknown
            },
        )
    }
}

pub(super) async fn prepare(
    client: &Client,
    candidate: &Build,
    idempotency_key: &str,
) -> Result<Archive> {
    prepare_from(client, candidate, idempotency_key, None).await
}

/// [`prepare`] with `source` as the generation's source archive, its bytes
/// kept as they are (a remote build packs the source the account uploaded).
pub(super) async fn prepare_with_source(
    client: &Client,
    candidate: &Build,
    idempotency_key: &str,
    source: &Path,
) -> Result<Archive> {
    prepare_from(client, candidate, idempotency_key, Some(source)).await
}

async fn prepare_from(
    client: &Client,
    candidate: &Build,
    idempotency_key: &str,
    given: Option<&Path>,
) -> Result<Archive> {
    let scratch = tempfile::Builder::new().prefix("ghost-nixos-").tempdir()?;
    let cache = scratch.path().join("cache");
    tokio::fs::create_dir(&cache).await?;
    let public = public_paths(client, &cache, candidate).await?;
    let private: Vec<_> = candidate
        .closure
        .iter()
        .filter(|(path, _)| !public.contains(*path))
        .collect();
    let expanded = private
        .iter()
        .try_fold(0_u64, |size, (_, info)| size.checked_add(info.nar_size));
    ensure!(
        expanded.is_some_and(|size| size <= MAX_PRIVATE),
        "private closure exceeds 8 GiB"
    );
    let key = scratch.path().join("syntax.key");
    let seed = Zeroizing::new(<[u8; 32]>::from(Sha256::digest(
        [
            b"ghostrack/nix/upload-syntax/v1\0".as_slice(),
            idempotency_key.as_bytes(),
        ]
        .concat(),
    )));
    let signing_key = SigningKey::from_bytes(&seed);
    let key_bytes = Zeroizing::new(signing_key.to_keypair_bytes());
    let mut encoded = Zeroizing::new(String::from("ghostrack-upload-1:"));
    STANDARD.encode_string(&key_bytes[..], &mut encoded);
    tokio::fs::write(&key, encoded.as_bytes()).await?;
    if !private.is_empty() {
        export(&cache, &key, &private).await?;
    }
    let source = scratch.path().join("source.tar.zst");
    stage_source(given, &source, &candidate.source).await?;
    let paths = private
        .into_iter()
        .map(|(path, _)| path.to_owned())
        .collect();
    let root = candidate.root.clone();
    tokio::task::spawn_blocking(move || pack(scratch, &cache, &source, paths, root)).await?
}

async fn export(cache: &Path, key: &Path, paths: &[(&String, &PathInfo)]) -> Result<()> {
    let mut url = Url::from_directory_path(cache)
        .map_err(|()| anyhow::anyhow!("invalid scratch cache path"))?;
    url.query_pairs_mut()
        .append_pair("compression", "zstd")
        .append_pair(
            "secret-key",
            key.to_str().context("invalid scratch key path")?,
        );
    let mut child = nix()
        .args(["copy", "--no-recursive", "--to", url.as_str(), "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .context("start native Nix binary cache export")?;
    let mut stdin = child.stdin.take().context("missing Nix export stdin")?;
    for (path, _) in paths {
        stdin.write_all(format!("{path}\n").as_bytes()).await?;
    }
    drop(stdin);
    let status = child.wait().await?;
    ensure!(
        status.success(),
        "native Nix binary cache export failed ({status})"
    );
    Ok(())
}

/// The generation's source archive at `destination`: `given` as it is, or
/// exported from the locked `source` tree.
async fn stage_source(given: Option<&Path>, destination: &Path, source: &Path) -> Result<()> {
    let Some(given) = given else {
        return export_source(destination, source).await;
    };
    let length = tokio::fs::copy(given, destination)
        .await
        .context("read the given source archive")?;
    ensure!(
        (1..=MAX_SOURCE).contains(&length),
        "flake source archive exceeds 256 MiB"
    );
    Ok(())
}

pub(super) async fn export_source(destination: &Path, source: &Path) -> Result<()> {
    let mut tar = Command::new("tar");
    tar.args([
        "--sort=name",
        "--mtime=@0",
        "--owner=0",
        "--group=0",
        "--numeric-owner",
        "--format=gnu",
        "--exclude=.git",
        "--zstd",
    ]);
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        if entry.file_type()?.is_symlink()
            && entry
                .file_name()
                .to_str()
                .is_some_and(|name| name == "result" || name.starts_with("result-"))
        {
            tar.arg(format!(
                "--exclude=./{}",
                entry.file_name().to_string_lossy()
            ));
        }
    }
    // Bound both the source traversal and the compressed output. The source
    // is the immutable snapshot already used by Nix to build this generation.
    let writer = File::create(destination)?;
    let mut child = tar
        .args(["-C"])
        .arg(source)
        .args(["-cf", "-", "."])
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .spawn()
        .context("start deterministic GNU tar with zstd")?;
    let stdout = child.stdout.take().context("missing tar output")?;
    let mut writer = tokio::fs::File::from_std(writer);
    let length = tokio::io::copy(
        &mut tokio::io::AsyncReadExt::take(stdout, MAX_SOURCE + 1),
        &mut writer,
    )
    .await?;
    ensure!(
        (1..=MAX_SOURCE).contains(&length),
        "flake source archive exceeds 256 MiB"
    );
    writer.flush().await?;
    let status = child.wait().await?;
    ensure!(status.success(), "source archive export failed ({status})");
    Ok(())
}

async fn public_paths(
    client: &Client,
    cache: &Path,
    candidate: &Build,
) -> Result<BTreeSet<String>> {
    let (name, key) = PUBLIC_KEY
        .split_once(':')
        .context("invalid public Nix cache key")?;
    let key = VerifyingKey::from_bytes(
        &STANDARD
            .decode(key)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid public Nix cache key"))?,
    )?;
    let mut results = stream::iter(
        candidate
            .closure
            .iter()
            .map(|(path, info)| check_public(client, (name, &key), path, info)),
    )
    .buffer_unordered(12);
    let mut public = BTreeSet::new();
    while let Some(record) = results.next().await {
        if let Some((path, hash, bytes)) = record {
            // Native Nix requires a narinfo for every reference when adding a
            // path to a binary cache. Seed only verified public narinfos and
            // package neither those metadata rows nor their archives.
            tokio::fs::write(cache.join(format!("{hash}.narinfo")), bytes).await?;
            public.insert(path.to_owned());
        }
    }
    Ok(public)
}

async fn check_public<'a>(
    client: &Client,
    (key_name, key): (&str, &VerifyingKey),
    path: &'a str,
    info: &PathInfo,
) -> Option<(&'a str, &'a str, Vec<u8>)> {
    let hash = store_basename(path)?.get(..32)?;
    let mut response = client
        .get(format!("https://cache.nixos.org/{hash}.narinfo"))
        .timeout(Duration::from_secs(8))
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_NARINFO as u64)
    {
        return None;
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.ok()? {
        if bytes.len() + chunk.len() > MAX_NARINFO {
            return None;
        }
        bytes.extend_from_slice(&chunk);
    }
    let text = std::str::from_utf8(&bytes).ok()?;
    let fields = fields(text)?;
    if text
        .lines()
        .filter(|line| line.starts_with("StorePath:"))
        .count()
        != 1
        || fields.get("StorePath").copied() != Some(path)
        || fields.get("NarSize")?.parse::<u64>().ok()? != info.nar_size
    {
        return None;
    }
    let hash = STANDARD
        .decode(info.nar_hash.strip_prefix("sha256-")?)
        .ok()?;
    let nar_hash = format!("sha256:{}", nix32(&hash));
    if fields.get("NarHash").copied() != Some(&nar_hash) {
        return None;
    }
    let references: BTreeSet<_> = fields
        .get("References")
        .copied()
        .unwrap_or_default()
        .split_ascii_whitespace()
        .map(|name| format!("/nix/store/{name}"))
        .collect();
    if references != info.references {
        return None;
    }
    let refs = references.into_iter().collect::<Vec<_>>().join(",");
    let message = format!("1;{path};{nar_hash};{};{refs}", info.nar_size);
    let signature_prefix = format!("Sig: {key_name}:");
    let signed = text
        .lines()
        .filter_map(|line| line.strip_prefix(&signature_prefix))
        .any(|signature| {
            STANDARD
                .decode(signature)
                .ok()
                .and_then(|sig| Signature::from_slice(&sig).ok())
                .is_some_and(|sig| key.verify_strict(message.as_bytes(), &sig).is_ok())
        });
    signed.then_some((path, store_basename(path)?.get(..32)?, bytes))
}

fn fields(text: &str) -> Option<BTreeMap<&str, &str>> {
    let mut fields = BTreeMap::new();
    for line in text.strip_suffix('\n')?.split('\n') {
        let (name, value) = line.split_once(": ")?;
        if name != "Sig" && fields.insert(name, value).is_some() {
            return None;
        }
    }
    Some(fields)
}

fn nix32(bytes: &[u8]) -> String {
    let alphabet = b"0123456789abcdfghijklmnpqrsvwxyz";
    (0..(bytes.len() * 8).div_ceil(5))
        .rev()
        .map(|digit| {
            let start = digit * 5;
            let index = start / 8;
            let shift = start % 8;
            let high = bytes.get(index + 1).copied().unwrap_or_default();
            let word = u16::from_le_bytes([bytes[index], high]);
            char::from(alphabet[usize::from((word >> shift) & 31)])
        })
        .collect()
}

fn pack(
    scratch: tempfile::TempDir,
    cache: &Path,
    source: &Path,
    paths: Vec<String>,
    root: String,
) -> Result<Archive> {
    let source_size = fs::metadata(source)?.len();
    let mut manifest = b"GHNUPL01".to_vec();
    manifest.extend_from_slice(&u32::try_from(paths.len())?.to_be_bytes());
    manifest.extend_from_slice(&source_size.to_be_bytes());
    let mut nars = Vec::with_capacity(paths.len());
    let mut wire = 0_u64;
    for path in paths {
        let hash = &store_basename(&path).context("invalid store path")?[..32];
        let raw = fs::read(cache.join(format!("{hash}.narinfo"))).context("read native narinfo")?;
        ensure!(raw.len() <= MAX_NARINFO, "native narinfo exceeds 64 KiB");
        let metadata = fields(std::str::from_utf8(&raw)?).context("invalid native narinfo")?;
        ensure!(
            metadata.get("StorePath").copied() == Some(&path),
            "native narinfo refers to a different path"
        );
        let url = *metadata
            .get("URL")
            .context("native narinfo has no archive URL")?;
        let basename = url
            .strip_prefix("nar/")
            .and_then(|url| url.strip_suffix(".nar.zst"))
            .context("native cache did not export zstd")?;
        ensure!(
            basename.len() == 52
                && basename
                    .bytes()
                    .all(|byte| b"0123456789abcdfghijklmnpqrsvwxyz".contains(&byte)),
            "invalid native NAR hash"
        );
        let nar = cache.join(url);
        let length = fs::metadata(&nar)?.len();
        ensure!(
            metadata
                .get("FileSize")
                .and_then(|size| size.parse::<u64>().ok())
                == Some(length)
                && length > 0
                && length < 4 * 1024 * 1024 * 1024,
            "invalid native NAR size"
        );
        wire = wire.checked_add(length).context("NAR size overflow")?;
        ensure!(
            wire <= MAX_PRIVATE,
            "compressed private closure exceeds 8 GiB"
        );
        manifest.push(1);
        manifest.extend_from_slice(&u32::try_from(raw.len())?.to_be_bytes());
        manifest.extend_from_slice(&raw);
        ensure!(
            manifest.len() <= MAX_MANIFEST,
            "generation upload manifest exceeds 32 MiB"
        );
        nars.push(nar);
    }
    let file = scratch.path().join("generation.ghnupl");
    let mut output = io::BufWriter::new(File::create(&file)?);
    output.write_all(&u32::try_from(manifest.len())?.to_be_bytes())?;
    output.write_all(&manifest)?;
    for nar in nars {
        io::copy(&mut File::open(nar)?, &mut output)?;
    }
    let mut source = File::open(source)?;
    let mut source_hash = Sha256::new();
    let mut bytes = vec![0_u8; 64 * 1024];
    loop {
        let count = source.read(&mut bytes)?;
        if count == 0 {
            break;
        }
        source_hash.update(&bytes[..count]);
        output.write_all(&bytes[..count])?;
    }
    output.flush()?;
    Ok(Archive {
        manifest_sha256: format!("{:x}", Sha256::digest(&manifest)),
        source_sha256: format!("{:x}", source_hash.finalize()),
        file,
        root,
        _scratch: Some(scratch),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_busy_location_is_waited_for_without_using_attempts() {
        let start = Instant::now();
        let mut retries = Retries::new(start);
        let busy = Some(Duration::from_secs(30));
        // Ten minutes of 30-second waits for the account's other uploads.
        for wait in 0..20 {
            let now = start + Duration::from_secs(30 * wait);
            assert_eq!(retries.after(busy, now), busy, "wait {wait}");
        }
        // Past the wait the busy answers count as failed attempts.
        let late = start + BUSY_WAIT;
        assert_eq!(retries.after(busy, late), Some(Duration::from_secs(1)));
        assert_eq!(retries.after(None, late), Some(Duration::from_secs(2)));
        assert_eq!(retries.after(None, late), None);
    }

    #[test]
    fn retry_after_is_bounded() {
        let headers = |value: Option<&'static str>| {
            let mut headers = header::HeaderMap::new();
            if let Some(value) = value {
                headers.insert(header::RETRY_AFTER, header::HeaderValue::from_static(value));
            }
            headers
        };
        for (value, seconds) in [
            (Some("30"), 30),
            (Some("0"), 1),
            (Some("3600"), 60),
            (Some("soon"), 30),
            (None, 30),
        ] {
            assert_eq!(
                retry_after(&headers(value)),
                Duration::from_secs(seconds),
                "{value:?}"
            );
        }
        // The location may receive for two hours after the grant expires.
        assert!(PUT_TIMEOUT > Duration::from_hours(2));
    }

    #[tokio::test]
    async fn a_given_source_keeps_its_bytes_and_its_digest() -> Result<()> {
        let given_dir = tempfile::tempdir()?;
        let given = given_dir.path().join("source.tar.zst");
        let bytes: Vec<u8> = (0..70_000_u32).map(|index| (index % 253) as u8).collect();
        fs::write(&given, &bytes)?;
        let scratch = tempfile::tempdir()?;
        let cache = scratch.path().join("cache");
        fs::create_dir(&cache)?;
        let staged = scratch.path().join("source.tar.zst");
        stage_source(Some(&given), &staged, Path::new("/nonexistent")).await?;
        let root = "/nix/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-system".to_owned();
        let archive = pack(scratch, &cache, &staged, Vec::new(), root.clone())?;
        assert_eq!(
            archive.source_sha256,
            format!("{:x}", Sha256::digest(&bytes))
        );
        let packed = fs::read(&archive.file)?;
        assert!(
            packed.ends_with(&bytes),
            "the source bytes are the archive's tail"
        );
        // Kept in a directory and opened again, the figures are the same.
        let out = tempfile::tempdir()?;
        let figures = archive.persist(out.path())?;
        assert_eq!(figures.root_path, root);
        let opened = Archive::open(out.path())?;
        assert_eq!(opened.figures(), figures);
        assert_eq!(fs::read(&opened.file)?, packed);
        Ok(())
    }

    #[test]
    fn nix32_matches_native_path_info_and_narinfo() {
        let sri = "U7b3jkqghFJKf6Ds1Sf1eRkEw+vHoGW8etwddO6UF4k=";
        let expected = "128pjkp787fwgay6b867xg1h86brylkxbv50gx5551509a7ggdjk";
        assert_eq!(nix32(&STANDARD.decode(sri).unwrap()), expected);
    }
}

#[cfg(test)]
mod native_tests {
    use super::*;
    use crate::nixos::{BuildArgs, build};

    #[tokio::test]
    #[ignore = "requires the disposable native Git flake, Nix, GNU tar and zstd"]
    async fn a_locked_git_build_and_its_archive_use_the_same_source() -> Result<()> {
        let flake = PathBuf::from(
            std::env::var_os("GHOSTRACK_NIX_FIXTURE")
                .context("set GHOSTRACK_NIX_FIXTURE to the disposable Git flake")?,
        );
        let revision = build::run(
            Command::new("git")
                .args(["rev-parse", "HEAD"])
                .current_dir(&flake),
            "read fixture commit",
        )
        .await?;
        let revision = std::str::from_utf8(&revision)?.trim();
        let input = BuildArgs {
            instance: Uuid::nil(),
            flake,
            configuration: "proof".into(),
        };
        let candidate = build::local(&input).await?;
        assert_eq!(candidate.revision.as_deref(), Some(revision));
        let root = Path::new(&candidate.root);
        assert_eq!(fs::read_to_string(root.join("revision"))?, revision);
        assert_eq!(
            fs::read_to_string(root.join("source"))?,
            candidate.source.to_str().unwrap()
        );
        assert_eq!(fs::read_to_string(root.join("rev-count"))?, "1");

        let scratch = tempfile::tempdir()?;
        let archive = scratch.path().join("source.tar.zst");
        export_source(&archive, &candidate.source).await?;
        let archived = build::run(
            Command::new("tar")
                .arg("--zstd")
                .arg("-xOf")
                .arg(&archive)
                .arg("./flake.nix"),
            "read archived fixture source",
        )
        .await?;
        assert_eq!(archived, fs::read(input.flake.join("flake.nix"))?);
        assert_eq!(archived, fs::read(candidate.source.join("flake.nix"))?);

        let dirty = scratch.path().join("dirty");
        build::run(
            Command::new("git")
                .args(["clone", "--quiet", "--no-local"])
                .arg(&input.flake)
                .arg(&dirty),
            "clone disposable dirty fixture",
        )
        .await?;
        fs::write(dirty.join("tracked.txt"), "edited")?;
        let error = build::local(&BuildArgs {
            flake: dirty,
            ..input
        })
        .await
        .err()
        .context("dirty Git source was accepted")?;
        assert!(
            error.to_string().contains("commit its changes"),
            "{error:#}"
        );
        Ok(())
    }
}
