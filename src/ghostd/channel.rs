//! The ghostd release channel as `ghost` reads it: the backend's
//! `/v1/releases` names the release key and the channel's manifest; the
//! manifest's Ed25519 signature is checked over the canonical release object
//! ([`SignedReleaseManifest::signed_bytes`]), then the archive's
//! SHA-256, and only then is `ghostd` taken out of it, in memory. Nothing
//! reaches a target before all of that passed.

use std::{io::Read as _, time::Duration};

use anyhow::{Context as _, Result, anyhow, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ghostrack_client_api::{
    api::GetReleaseChannels,
    release::{SignedReleaseManifest, is_release_version},
    website::ReleaseChannelsView,
};
use reqwest::Url;
use sha2::{Digest as _, Sha256};

use crate::api::ApiClient;

/// The maximum manifest size accepted by this client.
pub(crate) const MAX_MANIFEST_BYTES: usize = 64 * 1024;

/// The most a release archive may take, compressed.
pub(crate) const MAX_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;

/// The most the `ghostd` member may take.
pub(crate) const MAX_BINARY_BYTES: u64 = 64 * 1024 * 1024;

/// The most every other member may take.
const MAX_TEXT_MEMBER_BYTES: u64 = 1024 * 1024;

/// The archive's members, each exactly once, nothing else.
pub(crate) const MEMBERS: [&str; 4] = ["VERSION", "ghostd", "LICENSE-MIT", "LICENSE-APACHE"];

/// The source install, for the machines the channel has no build for.
pub(crate) const SOURCE_INSTALL_HINT: &str = "--from-source";

/// Where the channel is: its manifest and the key that signs it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ChannelSource {
    pub(crate) manifest_url: String,
    pub(crate) public_key_pem: String,
}

/// What a verified manifest names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Manifest {
    /// The release, `YYYYMMDDTHHMMSSZ-` and 12 hex digits of its commit.
    pub(crate) version: String,
    /// The ghostd commit it was built from (40 lowercase hex).
    pub(crate) commit: String,
    /// The archive's SHA-256 (64 lowercase hex).
    pub(crate) sha256: String,
    pub(crate) archive_url: String,
    /// ghostd's own version (`ghostd --version`), when the manifest names
    /// it.
    pub(crate) ghostd_version: Option<String>,
}

/// A verified release: its manifest and the `ghostd` binary.
pub(crate) struct Release {
    pub(crate) manifest: Manifest,
    pub(crate) binary: Vec<u8>,
    /// The binary's SHA-256 (64 lowercase hex), which the target checks.
    pub(crate) binary_sha256: String,
}

/// The ghostd channel the backend at `api_url` names; with `retry`, a read
/// that gets no answer is tried again as the CLI's reads are.
pub(crate) async fn source(api_url: &str, retry: bool) -> Result<ChannelSource> {
    let mut api = ApiClient::with_identity_loader(api_url, Box::new(|| Ok(None)))?;
    if !retry {
        api = api.with_read_retry_delays(&[]);
    }
    let channels: ReleaseChannelsView = api
        .read(&GetReleaseChannels, "")
        .await
        .context("read the release channels")?;
    source_of(&channels, api_url)
}

/// The ghostd channel in `channels`, or why there is none.
pub(crate) fn source_of(channels: &ReleaseChannelsView, api_url: &str) -> Result<ChannelSource> {
    let Some(public_key_pem) = channels.release_public_key_pem.clone() else {
        bail!(
            "the backend at {api_url} names no release key, so no channel release can be checked; install from source with {SOURCE_INSTALL_HINT}"
        );
    };
    let Some(channel) = &channels.ghostd else {
        bail!(
            "the backend at {api_url} offers no ghostd release channel; install from source with {SOURCE_INSTALL_HINT}"
        );
    };
    Ok(ChannelSource {
        manifest_url: channel.manifest_url.clone(),
        public_key_pem,
    })
}

/// The Ed25519 key of a PEM `SubjectPublicKeyInfo`.
pub(crate) fn verifying_key(pem: &str) -> Result<ed25519_dalek::VerifyingKey> {
    const SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    let pem = pem.trim();
    let lines: Vec<&str> = pem.lines().map(str::trim).collect();
    if lines.len() < 3
        || lines.first() != Some(&"-----BEGIN PUBLIC KEY-----")
        || lines.last() != Some(&"-----END PUBLIC KEY-----")
    {
        bail!("the release key is not a PEM public key");
    }
    let der = STANDARD
        .decode(lines[1..lines.len() - 1].concat())
        .map_err(|_| anyhow!("the release key is not a PEM public key"))?;
    if der.len() != SPKI_PREFIX.len() + 32 || der[..SPKI_PREFIX.len()] != SPKI_PREFIX {
        bail!("the release key is not an Ed25519 public key");
    }
    let key: [u8; 32] = der[SPKI_PREFIX.len()..]
        .try_into()
        .map_err(|_| anyhow!("the release key is not an Ed25519 public key"))?;
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .map_err(|_| anyhow!("the release key is not an Ed25519 public key"))
}

/// Whether `value` is `length` lowercase hex digits.
pub(crate) fn lowercase_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Whether `url` may be fetched: HTTPS, or plain HTTP to a literal IP (a
/// test backend's channel).
fn fetchable(url: &str) -> Result<Url> {
    let parsed = Url::parse(url).with_context(|| format!("read the URL {url}"))?;
    match parsed.scheme() {
        "https" => Ok(parsed),
        "http"
            if parsed
                .host_str()
                .is_some_and(crate::api::is_literal_ip_host) =>
        {
            Ok(parsed)
        }
        _ => bail!("{url} is not an HTTPS URL"),
    }
}

/// The manifest in `body`, when its signature verifies under `key_pem` and
/// its keys are well formed. A manifest read over plain HTTP may name an
/// archive over plain HTTP, as the install script allows.
pub(crate) fn verify_manifest(body: &[u8], key_pem: &str, manifest_url: &str) -> Result<Manifest> {
    use ed25519_dalek::Verifier as _;

    let key = verifying_key(key_pem)?;
    let manifest: SignedReleaseManifest =
        serde_json::from_slice(body).context("the release manifest is not a manifest")?;
    let signature = STANDARD
        .decode(&manifest.signature)
        .map_err(|_| anyhow!("the release manifest signature is not valid base64"))?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| anyhow!("the release manifest signature is invalid; refusing the release"))?;
    key.verify(
        &manifest.signed_bytes(),
        &ed25519_dalek::Signature::from_bytes(&signature),
    )
    .map_err(|_| anyhow!("the release manifest signature is invalid; refusing the release"))?;
    // Signed from here on: the keys of the whole release object.
    let version = manifest.release.version()?.to_owned();
    if !is_release_version(&version) {
        bail!("the release version has an invalid format");
    }
    let sha256 = manifest.release.sha256()?.to_owned();
    if !lowercase_hex(&sha256, 64) {
        bail!("the release archive SHA-256 is invalid");
    }
    let archive_url = manifest.release.archive_url()?.to_owned();
    let plain_http = manifest_url.starts_with("http://");
    if !(archive_url.starts_with("https://") || plain_http && archive_url.starts_with("http://"))
        || archive_url.len() > 1024
        || archive_url
            .chars()
            .any(|character| character.is_whitespace() || character.is_control())
    {
        bail!("the release archive URL must use HTTPS");
    }
    let object: serde_json::Value =
        serde_json::from_slice(body).context("the release manifest is not a manifest")?;
    let release = &object["release"];
    let commit = release["commit"]
        .as_str()
        .ok_or_else(|| anyhow!("the release manifest names no commit"))?
        .to_owned();
    if !lowercase_hex(&commit, 40) {
        bail!("the release commit has an invalid format");
    }
    let ghostd_version = release["ghostd_version"]
        .as_str()
        .filter(|text| {
            !text.is_empty()
                && text.len() <= 64
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b".-+".contains(&byte))
        })
        .map(str::to_owned);
    Ok(Manifest {
        version,
        commit,
        sha256,
        archive_url,
        ghostd_version,
    })
}

/// The longest a manifest download may take: it is at most 64 KiB.
const MANIFEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest an archive download may take.
const ARCHIVE_TIMEOUT: Duration = Duration::from_mins(10);

fn http_client(https_only: bool, timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(format!("ghost/{}", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(10))
        .timeout(timeout)
        .https_only(https_only)
        .redirect(reqwest::redirect::Policy::limited(5))
        .build()
        .context("build HTTP client")
}

/// The body at `url`, refused when it is larger than `maximum` bytes.
async fn download(client: &reqwest::Client, url: &str, maximum: usize) -> Result<Vec<u8>> {
    let mut response = client
        .get(url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .with_context(|| format!("download {url}"))?;
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        bail!("{url} is larger than {maximum} bytes");
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .with_context(|| format!("download {url}"))?
    {
        if body.len() + chunk.len() > maximum {
            bail!("{url} is larger than {maximum} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The channel's current verified manifest. With `fresh` (an install),
/// a unique query prevents a cache from returning an older manifest;
/// a status read may use a cached response.
pub(crate) async fn current(source: &ChannelSource, fresh: bool) -> Result<Manifest> {
    let mut url = fetchable(&source.manifest_url)?;
    let client = http_client(url.scheme() == "https", MANIFEST_TIMEOUT)?;
    if fresh {
        url.query_pairs_mut().append_pair(
            "install",
            &format!(
                "{}-{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |since| since.as_secs()),
                std::process::id()
            ),
        );
    }
    let body = download(&client, url.as_str(), MAX_MANIFEST_BYTES)
        .await
        .context("download the release manifest")?;
    verify_manifest(&body, &source.public_key_pem, &source.manifest_url)
}

/// The channel's current release: its manifest verified, its archive
/// downloaded and checked against the manifest's SHA-256, and `ghostd`
/// taken out of it.
pub(crate) async fn fetch(source: &ChannelSource) -> Result<Release> {
    let manifest = current(source, true).await?;
    let url = fetchable(&manifest.archive_url)?;
    let client = http_client(url.scheme() == "https", ARCHIVE_TIMEOUT)?;
    let archive = download(&client, url.as_str(), MAX_ARCHIVE_BYTES)
        .await
        .context("download the release archive")?;
    release_from(manifest, &archive)
}

/// The release in `archive`, which `manifest` names: its SHA-256 checked
/// first, then its members.
pub(crate) fn release_from(manifest: Manifest, archive: &[u8]) -> Result<Release> {
    let digest = super::ops::hex(&Sha256::digest(archive));
    if digest != manifest.sha256 {
        bail!("the release archive SHA-256 does not match the signed manifest");
    }
    let binary = extract(archive, &manifest.version)?;
    let binary_sha256 = super::ops::hex(&Sha256::digest(&binary));
    Ok(Release {
        manifest,
        binary,
        binary_sha256,
    })
}

/// The `ghostd` member of a release archive (a gzip-compressed tar), read
/// in memory. Only the [`MEMBERS`] are accepted, each once, as plain files
/// with plain names, within their sizes; `VERSION` must name `version`.
/// Links, directories, long-name and extended headers, and anything else
/// a tar may hold are refused.
pub(crate) fn extract(archive: &[u8], version: &str) -> Result<Vec<u8>> {
    // The members and the tar's headers: a bound on what is decompressed.
    let limit = MAX_BINARY_BYTES + 4 * MAX_TEXT_MEMBER_BYTES;
    let mut tar = Vec::new();
    flate2::read::GzDecoder::new(archive)
        .take(limit + 1)
        .read_to_end(&mut tar)
        .context("the release archive is not a gzip file")?;
    if tar.len() as u64 > limit {
        bail!("the release archive holds more than a release takes");
    }
    let mut found: [Option<&[u8]>; MEMBERS.len()] = [None; MEMBERS.len()];
    let mut position = 0;
    loop {
        let Some(header) = tar.get(position..position + 512) else {
            bail!("the release archive ends inside a tar header");
        };
        if header.iter().all(|byte| *byte == 0) {
            break;
        }
        let member = read_header(header)?;
        let index = MEMBERS
            .iter()
            .position(|name| name.as_bytes() == member.name)
            .ok_or_else(|| anyhow!("the release archive contains unexpected paths"))?;
        let maximum = if MEMBERS[index] == "ghostd" {
            MAX_BINARY_BYTES
        } else {
            MAX_TEXT_MEMBER_BYTES
        };
        if member.size > maximum {
            bail!("{} in the release archive is too large", MEMBERS[index]);
        }
        if found[index].is_some() {
            bail!(
                "the release archive holds {} more than once",
                MEMBERS[index]
            );
        }
        let start = position + 512;
        let size = usize::try_from(member.size).context("a member's size")?;
        let data = tar
            .get(start..start + size)
            .ok_or_else(|| anyhow!("the release archive ends inside {}", MEMBERS[index]))?;
        found[index] = Some(data);
        position = start + size.div_ceil(512) * 512;
    }
    let [Some(version_file), Some(binary), Some(_), Some(_)] = found else {
        bail!("the release archive contains unexpected paths");
    };
    let named = std::str::from_utf8(version_file).unwrap_or_default();
    if named.trim_end_matches(['\r', '\n']) != version {
        bail!("the release archive version differs from its signed manifest");
    }
    Ok(binary.to_vec())
}

struct Header<'a> {
    name: &'a [u8],
    size: u64,
}

/// One tar header: a plain file with a plain name, its checksum right.
fn read_header(header: &[u8]) -> Result<Header<'_>> {
    let field = |range: std::ops::Range<usize>| {
        let bytes = &header[range];
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(bytes.len());
        &bytes[..end]
    };
    let octal = |bytes: &[u8]| -> Result<u64> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| anyhow!("the release archive has a malformed tar header"))?
            .trim_matches(|character: char| character == ' ' || character == '\0');
        if text.is_empty() || !text.bytes().all(|byte| (b'0'..=b'7').contains(&byte)) {
            bail!("the release archive has a malformed tar header");
        }
        u64::from_str_radix(text, 8)
            .map_err(|_| anyhow!("the release archive has a malformed tar header"))
    };
    let stored = octal(field(148..156))?;
    let sum: u64 = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum();
    if sum != stored {
        bail!("the release archive has a tar header with a wrong checksum");
    }
    // A regular file only: no link, directory, device, long name or
    // extended header.
    if !matches!(header[156], b'0' | 0) {
        bail!("the release archive contains unexpected paths");
    }
    // A POSIX header may carry a name prefix: none is expected.
    if &header[257..263] == b"ustar\0" && !field(345..500).is_empty() {
        bail!("the release archive contains unexpected paths");
    }
    let size = octal(field(124..136))?;
    Ok(Header {
        name: field(0..100),
        size,
    })
}
