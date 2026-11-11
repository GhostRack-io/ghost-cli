//! A hosted backup on this machine (`ghost backup download` and `ghost
//! backup decrypt`): the encrypted file fetched with its download link,
//! resumed where an earlier run stopped, and checked against its size and
//! SHA-256; then decrypted offline with the account key into a sparse raw
//! disk image, every record and the manifest authenticated
//! (`ghostrack-backup-format`, the restore's own decoder).
//!
//! Beside `FILE`, a download keeps `FILE.part` while it runs and
//! `FILE.link.json`, the link it was charged for, so a rerun resumes with
//! the same link until it expires. Once the file is whole and checked it
//! becomes `FILE`, the link file goes, and `FILE.key.json` holds the key
//! file decrypting needs.

use std::{
    fs,
    io::{BufRead, Read as _, Write},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ghostrack_backup_format::{SparseFile, StreamRestoreInput, decode_stream};
use ghostrack_client_api::website::{BACKUP_KEY_FILE_FORMAT, BackupKeyFile};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

/// What a download keeps beside its file while it runs: the link it was
/// charged for, so a rerun resumes with it while it works.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SavedLink {
    pub url: String,
    pub expires_at: DateTime<Utc>,
    pub etag: String,
    pub key: BackupKeyFile,
}

/// How long before its end a saved link is no longer used: a download that
/// starts then could not finish with it.
const LINK_MARGIN: chrono::TimeDelta = chrono::TimeDelta::minutes(10);

/// How many times a download resumes after a failed request in one run.
const ATTEMPTS: u32 = 5;

/// `FILE` with `suffix` appended to its name: `FILE.part`, `FILE.key.json`.
pub fn beside(file: &Path, suffix: &str) -> PathBuf {
    let mut name = file.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// The link a previous run of the download of `backup_id` to `file` kept,
/// if it is still good for a while.
pub fn saved_link(file: &Path, backup_id: Uuid, now: DateTime<Utc>) -> Option<SavedLink> {
    let text = fs::read(beside(file, ".link.json")).ok()?;
    let link: SavedLink = serde_json::from_slice(&text).ok()?;
    (link.key.backup_id == backup_id && link.expires_at - LINK_MARGIN > now).then_some(link)
}

/// Keep `link` beside `file` for a rerun, readable by its owner alone: it
/// fetches the backup until it expires.
pub fn save_link(file: &Path, link: &SavedLink) -> Result<()> {
    write_private(
        &beside(file, ".link.json"),
        &serde_json::to_vec_pretty(link)?,
    )
}

/// Write `bytes` to `path`, replacing it, readable by the owner alone.
fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("write {}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("write {}", path.display()))
}

/// Ask whether to go ahead with `question`, which names the charge: yes
/// with `--yes`; otherwise on a terminal the answer typed (`y` or `yes`),
/// and off one a refusal that says to repeat the command with `--yes`.
pub fn consent(
    question: &str,
    yes: bool,
    terminal: bool,
    input: &mut impl BufRead,
    output: &mut impl Write,
) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    if !terminal {
        bail!("{question} Repeat with --yes to go ahead.");
    }
    write!(output, "{question} [y/N] ")?;
    output.flush()?;
    let mut answer = String::new();
    input.read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

/// Fetch the object `link` names into `part`, resuming after what it holds
/// already (a ranged request that must match the object's entity tag), and
/// again after a failed request, up to [`ATTEMPTS`] times. `progress` is
/// told the bytes held after each piece.
pub async fn fetch(
    link: &SavedLink,
    part: &Path,
    mut progress: impl FnMut(u64, u64),
) -> Result<()> {
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(30))
        .read_timeout(Duration::from_mins(2))
        .no_gzip()
        .no_zstd()
        .build()
        .context("build the download client")?;
    let total = link.key.size_bytes;
    let mut failures = 0;
    loop {
        let held = fs::metadata(part).map_or(0, |metadata| metadata.len());
        if held == total {
            return Ok(());
        }
        if held > total {
            bail!(
                "{} is larger than the backup; remove it and download again",
                part.display()
            );
        }
        match fetch_from(&client, link, part, held, &mut progress).await {
            Ok(()) => {}
            Err(error) if failures + 1 < ATTEMPTS && !is_final(&error) => {
                failures += 1;
                tokio::time::sleep(Duration::from_secs(1 << failures)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

/// A refusal no retry changes: the link expired or the object changed.
#[derive(Debug)]
struct Final(String);

impl std::fmt::Display for Final {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for Final {}

fn is_final(error: &anyhow::Error) -> bool {
    error.downcast_ref::<Final>().is_some()
}

/// One request: the object from `held` on, appended to `part`.
async fn fetch_from(
    client: &reqwest::Client,
    link: &SavedLink,
    part: &Path,
    held: u64,
    progress: &mut impl FnMut(u64, u64),
) -> Result<()> {
    use tokio::io::AsyncWriteExt as _;

    let total = link.key.size_bytes;
    let mut request = client.get(&link.url);
    if held > 0 {
        request = request
            .header(reqwest::header::RANGE, format!("bytes={held}-"))
            .header(reqwest::header::IF_MATCH, quoted(&link.etag));
    }
    let mut response = request.send().await.context("request the backup")?;
    let status = response.status();
    let start = match status {
        reqwest::StatusCode::PARTIAL_CONTENT => held,
        // The whole object: what the part holds is written again.
        reqwest::StatusCode::OK => 0,
        reqwest::StatusCode::FORBIDDEN | reqwest::StatusCode::UNAUTHORIZED => {
            return Err(Final(format!(
                "the download link was refused ({status}): it may have expired; run the command again for a new link"
            ))
            .into());
        }
        reqwest::StatusCode::PRECONDITION_FAILED => {
            return Err(Final(
                "the backup's file changed since the download started; remove the partial file and download again"
                    .to_owned(),
            )
            .into());
        }
        reqwest::StatusCode::NOT_FOUND => {
            return Err(Final("the backup's file is gone".to_owned()).into());
        }
        _ => bail!("the download answered {status}"),
    };
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(part)
        .await
        .with_context(|| format!("open {}", part.display()))?;
    file.set_len(start).await?;
    let mut written = start;
    {
        use tokio::io::AsyncSeekExt as _;
        file.seek(std::io::SeekFrom::Start(start)).await?;
    }
    while let Some(chunk) = response.chunk().await.context("read the download")? {
        written += chunk.len() as u64;
        if written > total {
            bail!("the download is larger than the backup");
        }
        file.write_all(&chunk).await?;
        progress(written, total);
    }
    file.sync_all().await?;
    if written < total {
        bail!("the download ended after {written} of {total} bytes");
    }
    Ok(())
}

fn quoted(etag: &str) -> String {
    let etag = etag.trim_matches('"');
    format!("\"{etag}\"")
}

/// Check that `path` is the file the key file describes: its size and its
/// SHA-256.
pub fn verify(path: &Path, key: &BackupKeyFile) -> Result<()> {
    let size = fs::metadata(path)
        .with_context(|| format!("inspect {}", path.display()))?
        .len();
    if size != key.size_bytes {
        bail!(
            "{} holds {size} bytes; the backup has {}",
            path.display(),
            key.size_bytes
        );
    }
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let sha256 = hex(&digest.finalize());
    if sha256 != key.sha256 {
        bail!(
            "{}'s SHA-256 is {sha256}, not the backup's {}",
            path.display(),
            key.sha256
        );
    }
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// The download's end: `part` becomes `file`, its key file is written
/// beside it, and the saved link goes.
pub fn finish(file: &Path, part: &Path, key: &BackupKeyFile) -> Result<PathBuf> {
    let key_file = beside(file, ".key.json");
    let mut text = serde_json::to_vec_pretty(key)?;
    text.push(b'\n');
    write_private(&key_file, &text)?;
    fs::rename(part, file)
        .with_context(|| format!("move {} to {}", part.display(), file.display()))?;
    match fs::remove_file(beside(file, ".link.json")) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("remove the saved download link"),
    }
    Ok(key_file)
}

/// Read a key file.
pub fn read_key_file(path: &Path) -> Result<BackupKeyFile> {
    let text = fs::read(path).with_context(|| {
        format!(
            "read the key file {}; `ghost backup download` saves it beside the backup",
            path.display()
        )
    })?;
    let key: BackupKeyFile = serde_json::from_slice(&text)
        .with_context(|| format!("{} is not a backup key file", path.display()))?;
    if key.format != BACKUP_KEY_FILE_FORMAT {
        bail!(
            "{} is a key file of format {:?}, which this release of ghost does not read",
            path.display(),
            key.format
        );
    }
    Ok(key)
}

/// The account keys that may open a backup, in the order they are tried:
/// the one `--recovery-seed-file` names alone, or else the account key and
/// the earlier ones kept beside it when it was replaced
/// (`<name>.replaced-<time>`).
pub fn seed_candidates(seed_file: &Path, recovery_seed_file: Option<&Path>) -> Vec<PathBuf> {
    if let Some(path) = recovery_seed_file {
        return vec![path.to_owned()];
    }
    let mut candidates = vec![seed_file.to_owned()];
    let (Some(directory), Some(name)) = (seed_file.parent(), seed_file.file_name()) else {
        return candidates;
    };
    let directory = if directory.as_os_str().is_empty() {
        Path::new(".")
    } else {
        directory
    };
    let mut prefix = name.to_os_string();
    prefix.push(".replaced-");
    let prefix = prefix.to_string_lossy().into_owned();
    if let Ok(entries) = fs::read_dir(directory) {
        let mut kept: Vec<PathBuf> = entries
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
            .map(|entry| directory.join(entry.file_name()))
            .collect();
        // The newest first: the latest move's.
        kept.sort();
        kept.reverse();
        candidates.extend(kept);
    }
    candidates
}

/// The account key among `candidates` whose recovery key the backup is
/// wrapped to, or why none is.
pub fn recovery_key_for(
    key: &BackupKeyFile,
    candidates: &[PathBuf],
) -> Result<crate::keys::RecoveryKeyPair> {
    for path in candidates {
        let Ok(seed) = crate::keys::load_seed(path) else {
            continue;
        };
        let recovery = crate::keys::recovery_key_pair(&seed)?;
        if URL_SAFE_NO_PAD.encode(recovery.fingerprint) == key.recipient_key_fingerprint {
            return Ok(recovery);
        }
    }
    let set = key
        .recovery_key_epoch
        .map_or_else(String::new, |epoch| format!(" of key set {epoch}"));
    Err(crate::typed_refusal(
        crate::RECOVERY_KEY_MISMATCH,
        format!(
            "backup {} is encrypted to the recovery key{set} (fingerprint {}), which none of the account keys tried has ({}); pass the account key the backup was made with as --recovery-seed-file",
            key.backup_id,
            crate::escape_control(&key.recipient_key_fingerprint),
            candidates
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ),
    ))
}

/// What a decryption wrote.
#[derive(Debug, Serialize)]
pub struct Decrypted {
    pub file: PathBuf,
    pub disk_bytes: u64,
    pub format: &'static str,
    /// The container's version, 1 or 2.
    pub container_version: u8,
}

/// Decrypt the backup `file` described by `key` with `recovery` into the
/// raw disk image `output`, sparse: it is written as `output.partial`,
/// which becomes `output` only once every record and the manifest are
/// authenticated. With `qcow2`, the image is then converted by `qemu-img`.
pub fn decrypt(
    file: &Path,
    key: &BackupKeyFile,
    recovery: &crate::keys::RecoveryKeyPair,
    output: &Path,
    qcow2: bool,
) -> Result<Decrypted> {
    if qcow2 && !qemu_img_present() {
        bail!(
            "--qcow2 converts with qemu-img, which is not installed here; decrypt to a raw image, or install qemu-img (package qemu-utils or qemu-img)"
        );
    }
    if output.exists() {
        bail!(
            "{} exists already; choose another output or remove it",
            output.display()
        );
    }
    let size = fs::metadata(file)
        .with_context(|| format!("inspect {}", file.display()))?
        .len();
    if size != key.size_bytes {
        bail!(
            "{} holds {size} bytes; the backup has {}",
            file.display(),
            key.size_bytes
        );
    }
    let fingerprint: [u8; 32] = URL_SAFE_NO_PAD
        .decode(&key.recipient_key_fingerprint)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .context("the key file's recipient_key_fingerprint is not 32 bytes of base64url")?;
    let wrapped = URL_SAFE_NO_PAD
        .decode(&key.wrapped_data_key)
        .context("the key file's wrapped_data_key is not base64url")?;
    let data_key =
        crate::keys::open_backup_data_key(recovery, key.instance_id, key.backup_id, &wrapped)?;
    let raw = if qcow2 {
        beside(output, ".raw.partial")
    } else {
        beside(output, ".partial")
    };
    let destination = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&raw)
        .with_context(|| format!("create {}", raw.display()))?;
    let mut source = std::io::BufReader::with_capacity(
        1024 * 1024,
        fs::File::open(file).with_context(|| format!("open {}", file.display()))?,
    );
    let mut sparse = SparseFile::new(destination);
    let decoded = decode_stream(
        &mut source,
        &mut sparse,
        &StreamRestoreInput {
            instance_id: key.instance_id,
            backup_id: key.backup_id,
            disk_bytes: key.disk_bytes,
            recipient_key_fingerprint: &fingerprint,
            data_key: &data_key,
        },
    )
    .and_then(|digest| {
        sparse.finish()?;
        // Nothing may follow the footer.
        let mut rest = [0_u8; 1];
        if source.read(&mut rest)? != 0 {
            bail!("the backup has bytes after its footer");
        }
        Ok(digest)
    });
    let digest = match decoded {
        Ok(digest) => digest,
        Err(error) => {
            let _ = fs::remove_file(&raw);
            return Err(error.context(format!("decrypt {}", file.display())));
        }
    };
    if qcow2 {
        let converted = std::process::Command::new("qemu-img")
            .args(["convert", "-f", "raw", "-O", "qcow2"])
            .arg(&raw)
            .arg(output)
            .status();
        let _ = fs::remove_file(&raw);
        match converted {
            Ok(status) if status.success() => {}
            Ok(status) => {
                // A partial image must not make the rerun refuse.
                let _ = fs::remove_file(output);
                bail!("qemu-img convert failed ({status})")
            }
            Err(error) => return Err(error).context("run qemu-img convert"),
        }
    } else {
        fs::rename(&raw, output)
            .with_context(|| format!("move {} to {}", raw.display(), output.display()))?;
    }
    Ok(Decrypted {
        file: output.to_owned(),
        disk_bytes: key.disk_bytes,
        format: if qcow2 { "qcow2" } else { "raw" },
        container_version: digest.format,
    })
}

fn qemu_img_present() -> bool {
    std::process::Command::new("qemu-img")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// A server of one object, as a presigned URL serves it: `GET` of the
/// whole object or of `Range: bytes=N-`, which must name the object's
/// entity tag in `If-Match`. With `cut_first`, its first answer stops
/// halfway, as a dropped connection does. It records each request's head.
#[cfg(test)]
pub(crate) async fn object_server(
    bytes: Vec<u8>,
    etag: &'static str,
    cut_first: bool,
) -> (String, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://{}/backups/object.ghb?X-Amz-Signature=00",
        listener.local_addr().unwrap()
    );
    let heads = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = heads.clone();
    tokio::spawn(async move {
        let mut first = cut_first;
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).await.unwrap_or(0);
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
            }
            let head = String::from_utf8_lossy(&request).to_ascii_lowercase();
            log.lock().unwrap().push(head.clone());
            let start = head
                .lines()
                .find_map(|line| line.strip_prefix("range: bytes="))
                .and_then(|range| range.trim().trim_end_matches('-').parse::<usize>().ok());
            let answer = match start {
                Some(_) if !head.contains(&format!("if-match: \"{etag}\"")) => {
                    b"HTTP/1.1 412 Precondition Failed\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_vec()
                }
                Some(start) => {
                    let mut answer = format!(
                        "HTTP/1.1 206 Partial Content\r\ncontent-length: {}\r\ncontent-range: bytes {start}-{}/{}\r\nconnection: close\r\n\r\n",
                        bytes.len() - start,
                        bytes.len() - 1,
                        bytes.len()
                    )
                    .into_bytes();
                    answer.extend_from_slice(&bytes[start..]);
                    answer
                }
                None => {
                    let mut answer = format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\netag: \"{etag}\"\r\nconnection: close\r\n\r\n",
                        bytes.len()
                    )
                    .into_bytes();
                    let sent = if first { bytes.len() / 2 } else { bytes.len() };
                    first = false;
                    answer.extend_from_slice(&bytes[..sent]);
                    answer
                }
            };
            let _ = stream.write_all(&answer).await;
            let _ = stream.shutdown().await;
        }
    });
    (url, heads)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The fixed containers of the backup format's crate, which the hosts'
    /// encoder wrote, and their description.
    pub(crate) fn fixture() -> (serde_json::Value, Vec<u8>, Vec<u8>) {
        let description = serde_json::from_str(include_str!(
            "../crates/backup-format/fixtures/backups.json"
        ))
        .unwrap();
        (
            description,
            include_bytes!("../crates/backup-format/fixtures/backup-v2.ghb").to_vec(),
            include_bytes!("../crates/backup-format/fixtures/backup-v1.ghb").to_vec(),
        )
    }

    /// The key file of a fixture container, as the backend answers it.
    pub(crate) fn fixture_key(container: &[u8]) -> BackupKeyFile {
        let (description, _, _) = fixture();
        let text = |name: &str| description[name].as_str().unwrap().to_owned();
        BackupKeyFile {
            format: BACKUP_KEY_FILE_FORMAT.to_owned(),
            backup_id: text("backup_id").parse().unwrap(),
            instance_id: text("instance_id").parse().unwrap(),
            disk_bytes: description["disk_bytes"].as_u64().unwrap(),
            size_bytes: container.len() as u64,
            sha256: hex(&Sha256::digest(container)),
            recipient_key_fingerprint: text("recovery_key_fingerprint_b64url"),
            wrapped_data_key: text("wrapped_data_key_b64url"),
            recovery_key_epoch: Some(1),
        }
    }

    #[test]
    fn the_charge_is_accepted_with_yes_or_an_answer_and_never_off_a_terminal() {
        let question = "Downloading backup b (4 MiB) costs $0.01, as restoring it does.";
        let ask = |yes: bool, terminal: bool, typed: &str| {
            let mut asked = Vec::new();
            let answer = consent(
                question,
                yes,
                terminal,
                &mut std::io::Cursor::new(typed.as_bytes()),
                &mut asked,
            );
            (
                answer.map_err(|error| error.to_string()),
                String::from_utf8(asked).unwrap(),
            )
        };
        assert_eq!(ask(true, false, ""), (Ok(true), String::new()));
        let (refused, asked) = ask(false, false, "y\n");
        assert_eq!(
            refused.unwrap_err(),
            format!("{question} Repeat with --yes to go ahead.")
        );
        assert_eq!(asked, "");
        assert_eq!(
            ask(false, true, "y\n"),
            (Ok(true), format!("{question} [y/N] "))
        );
        assert_eq!(ask(false, true, "YES\n").0, Ok(true));
        for no in ["\n", "n\n", "", "yep\n"] {
            assert_eq!(ask(false, true, no).0, Ok(false), "{no:?}");
        }
    }

    /// A download cut short resumes from where its file ends, with the
    /// object's entity tag, and the file is then the backup.
    #[tokio::test]
    async fn a_cut_download_resumes_where_it_stopped() {
        let (_, container, _) = fixture();
        let (url, heads) = object_server(container.clone(), "etag-1", true).await;
        let directory = tempfile::tempdir().unwrap();
        let part = directory.path().join("backup.ghb.part");
        let link = SavedLink {
            url,
            expires_at: Utc::now() + chrono::TimeDelta::hours(24),
            etag: "etag-1".to_owned(),
            key: fixture_key(&container),
        };
        let mut seen = Vec::new();
        fetch(&link, &part, |held, _| seen.push(held))
            .await
            .unwrap();
        assert_eq!(fs::read(&part).unwrap(), container);
        verify(&part, &link.key).unwrap();
        let heads = heads.lock().unwrap().clone();
        assert_eq!(heads.len(), 2, "{heads:?}");
        assert!(!heads[0].contains("range:"));
        let half = container.len() / 2;
        assert!(
            heads[1].contains(&format!("range: bytes={half}-")),
            "{}",
            heads[1]
        );
        assert!(heads[1].contains("if-match: \"etag-1\""));
        assert_eq!(seen.last().copied(), Some(container.len() as u64));
        // A file that is not the backup is refused.
        let mut wrong = container.clone();
        wrong[100] ^= 1;
        fs::write(&part, &wrong).unwrap();
        assert!(
            verify(&part, &link.key)
                .unwrap_err()
                .to_string()
                .contains("SHA-256")
        );
    }

    /// The link a run kept is used again by the next while it works, for
    /// its backup only.
    #[test]
    fn a_saved_link_is_used_again_until_shortly_before_it_expires() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("backup.ghb");
        let (_, container, _) = fixture();
        let key = fixture_key(&container);
        let now = Utc::now();
        let link = SavedLink {
            url: "https://storage.example/b".to_owned(),
            expires_at: now + chrono::TimeDelta::hours(1),
            etag: "e".to_owned(),
            key: key.clone(),
        };
        save_link(&file, &link).unwrap();
        assert!(saved_link(&file, key.backup_id, now).is_some());
        assert!(saved_link(&file, Uuid::now_v7(), now).is_none());
        assert!(saved_link(&file, key.backup_id, now + chrono::TimeDelta::minutes(55)).is_none());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(beside(&file, ".link.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
