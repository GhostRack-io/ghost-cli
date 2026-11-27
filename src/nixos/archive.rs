use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Read, Write as _},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
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

pub(super) struct Archive {
    pub manifest_sha256: String,
    pub source_sha256: String,
    file: PathBuf,
    root: String,
    _scratch: tempfile::TempDir,
}

#[derive(Deserialize)]
struct Grant {
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

impl Archive {
    pub async fn upload(&self, api: &ApiClient, client: &Client, generation: Uuid) -> Result<()> {
        let target = format!("/cache/uploads/{generation}/credential");
        for attempt in 0..3 {
            let result = api.app("nix", "GET", &target, None, None).await;
            match result {
                Ok(value) => {
                    let grant: Grant =
                        serde_json::from_value(value).context("invalid Nix upload grant")?;
                    if let Some(status) = self.send(client, generation, &grant).await? {
                        if status == StatusCode::OK {
                            return Ok(());
                        }
                        ensure!(
                            status.is_server_error()
                                || matches!(
                                    status,
                                    StatusCode::REQUEST_TIMEOUT
                                        | StatusCode::UNAUTHORIZED
                                        | StatusCode::TOO_MANY_REQUESTS
                                ),
                            "Nix cache rejected generation {generation} ({status})"
                        );
                    }
                }
                Err(error)
                    if is_transient(&error)
                        || crate::api::rejection(&error)
                            .is_some_and(|error| error.status == 404) => {}
                Err(error) => return Err(error),
            }
            tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
        }
        anyhow::bail!("upload outcome for generation {generation} is unknown")
    }

    async fn send(
        &self,
        client: &Client,
        generation: Uuid,
        grant: &Grant,
    ) -> Result<Option<StatusCode>> {
        let url = https_url(&grant.url)?;
        ensure!(
            url.path() == format!("/v1/nix/uploads/{generation}"),
            "Nix cache returned an unexpected upload path"
        );
        let file = tokio::fs::File::open(&self.file).await?;
        let length = file.metadata().await?.len();
        let seconds = grant
            .expires_at
            .saturating_sub(chrono::Utc::now().timestamp().unsigned_abs());
        if seconds == 0 {
            return Ok(None);
        }
        let response = client
            .put(url)
            .bearer_auth(grant.token.as_str())
            .header(header::CONTENT_LENGTH, length)
            .body(reqwest::Body::wrap_stream(ReaderStream::new(file)))
            .timeout(Duration::from_secs(seconds.min(900)))
            .send()
            .await;
        let Ok(mut response) = response else {
            return Ok(None);
        };
        let status = response.status();
        if status != StatusCode::OK {
            return Ok(Some(status));
        }
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) if body.len() + chunk.len() <= 4096 => {
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                _ => return Ok(None),
            }
        }
        let Some(receipt) = serde_json::from_slice::<PublicationReceipt>(&body).ok() else {
            return Ok(None);
        };
        Ok(
            (receipt.generation_id == generation && receipt.root_path == self.root)
                .then_some(status),
        )
    }
}

pub(super) async fn prepare(
    client: &Client,
    candidate: &Build,
    idempotency_key: &str,
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
    export_source(&source, &candidate.source).await?;
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

async fn export_source(destination: &Path, source: &Path) -> Result<()> {
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
        _scratch: scratch,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nix32_matches_native_path_info_and_narinfo() {
        let sri = "U7b3jkqghFJKf6Ds1Sf1eRkEw+vHoGW8etwddO6UF4k=";
        let expected = "128pjkp787fwgay6b867xg1h86brylkxbv50gx5551509a7ggdjk";
        assert_eq!(nix32(&STANDARD.decode(sri).unwrap()), expected);
    }
}
