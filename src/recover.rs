//! `ghost provider host recover-backups` (item 322): a lost host's local
//! backups, found in its backup pools attached to a fresh system, uploaded
//! as they are stored, still encrypted, as the renters' hosted backups.
//!
//! Each backup the host's recovery lists as waiting or uploading is looked
//! for by its artifact's name in the directories given: a file pool's
//! directory (`ghb-<id>.ghb`, exactly the recorded size) or a volume
//! group's `/dev/<VG>` (`ghb-<id>`, at least the recorded size, of which
//! only the recorded size is read). Its header must name the backup, and a
//! pre-pass hashes it: an artifact whose SHA-256 is not the recorded one
//! is damaged and skipped, so no broken artifact is uploaded. Then its
//! upload begins, or resumes past the parts committed already, a part at a
//! time, and completes with that SHA-256. Nothing is ever written to the
//! pools.

use std::{
    fs::File,
    io::{Read, Seek as _, SeekFrom},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context as _, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use ghostrack_backup_format::{HEADER_BYTES, parse_header};
use ghostrack_client_api::{
    hypervisor::StorageBackend,
    website::{
        BackupRecoveryState, PresignedHeaderView, RecoverHostBackupRequest, RecoverHostBackupView,
        RecoverableBackupView,
    },
};
use md5::{Digest as _, Md5};
use sha2::Sha256;
use uuid::Uuid;

/// How many times one request of an upload is tried before the backup
/// fails; a rerun resumes it.
pub const ATTEMPTS: u32 = 5;

/// An artifact found for a backup.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Found {
    pub path: PathBuf,
}

/// The backups to upload, in order: one whose upload a run began first
/// (the backend takes one at a time), then the waiting ones as listed.
#[must_use]
pub fn to_upload(backups: &[RecoverableBackupView]) -> Vec<&RecoverableBackupView> {
    let uploading = backups
        .iter()
        .filter(|backup| backup.state == BackupRecoveryState::Uploading);
    let waiting = backups
        .iter()
        .filter(|backup| backup.state == BackupRecoveryState::Waiting);
    uploading.chain(waiting).collect()
}

/// The first of `directories` that holds the backup's artifact.
#[must_use]
pub fn find(directories: &[PathBuf], backup: &RecoverableBackupView) -> Option<Found> {
    directories
        .iter()
        .map(|directory| directory.join(&backup.artifact_name))
        .find(|path| path.exists())
        .map(|path| Found { path })
}

/// Whether a missing artifact may only be an inactive logical volume:
/// the backup was in a thin pool and a `/dev/<VG>` directory was given.
#[must_use]
pub fn may_need_activation(directories: &[PathBuf], backup: &RecoverableBackupView) -> bool {
    backup.pool_backend == StorageBackend::LvmThin
        && directories
            .iter()
            .any(|directory| directory.starts_with("/dev"))
}

/// Open the artifact at `path` and check its size: a file pool's artifact
/// is exactly `size_bytes` long, a logical volume at least that; only the
/// first `size_bytes` are the artifact.
///
/// # Errors
///
/// An artifact that cannot be opened or measured, and one of the wrong
/// size ([`Skip::Damaged`] through its message).
pub fn open_artifact(path: &Path, backup: &RecoverableBackupView) -> Result<File> {
    let mut file = File::open(path).with_context(|| format!("open {}", path.display()))?;
    // A block device's metadata says 0; its end says its size.
    let length = file
        .seek(SeekFrom::End(0))
        .with_context(|| format!("measure {}", path.display()))?;
    file.seek(SeekFrom::Start(0))?;
    let fits = match backup.pool_backend {
        StorageBackend::PreallocatedFile => length == backup.size_bytes,
        _ => length >= backup.size_bytes,
    };
    if !fits {
        bail!(
            "{} is {length} bytes, but the backup is {} bytes",
            path.display(),
            backup.size_bytes
        );
    }
    Ok(file)
}

/// The artifact's header and SHA-256, of its first `size_bytes` alone:
/// the pre-pass. `progress` hears the bytes read so far.
///
/// # Errors
///
/// A read that fails, an artifact shorter than the backup, and a header
/// that does not name the backup.
pub fn prepass(
    artifact: &mut impl Read,
    backup: &RecoverableBackupView,
    mut progress: impl FnMut(u64),
) -> Result<(Vec<u8>, String)> {
    let mut reader = artifact.take(backup.size_bytes);
    let mut header = vec![0_u8; HEADER_BYTES];
    reader
        .read_exact(&mut header)
        .context("read the artifact's header")?;
    let parsed = parse_header(&header)?;
    if parsed.backup_id != backup.backup_id {
        bail!("its header names backup {}", parsed.backup_id);
    }
    let mut digest = Sha256::new();
    sha2::Digest::update(&mut digest, &header);
    let mut read = header.len() as u64;
    let mut buffer = vec![0_u8; 4 * 1024 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        sha2::Digest::update(&mut digest, &buffer[..count]);
        read += count as u64;
        progress(read);
    }
    if read != backup.size_bytes {
        bail!("it ends after {read} of {} bytes", backup.size_bytes);
    }
    Ok((header, hex(&sha2::Digest::finalize(digest))))
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut text, byte| {
        let _ = write!(text, "{byte:02x}");
        text
    })
}

/// What a recovery upload calls: the backend's steps and the presigned
/// PUT of a part, which answers the part's `ETag`.
pub trait Recovery {
    fn step(
        &self,
        backup_id: Uuid,
        request: &RecoverHostBackupRequest,
    ) -> impl Future<Output = Result<RecoverHostBackupView>>;
    fn put(
        &self,
        url: &str,
        headers: &[PresignedHeaderView],
        body: Vec<u8>,
    ) -> impl Future<Output = Result<String>>;
    /// Whether a failed call may succeed when repeated.
    fn transient(&self, error: &anyhow::Error) -> bool;
    /// Wait before the next attempt.
    fn pause(&self, attempt: u32) -> impl Future<Output = ()>;
}

/// Repeat `call` while it fails transiently, [`ATTEMPTS`] times at most.
async fn retried<T, F: Future<Output = Result<T>>>(
    recovery: &impl Recovery,
    mut call: impl FnMut() -> F,
) -> Result<T> {
    let mut attempt = 1;
    loop {
        match call().await {
            Ok(value) => return Ok(value),
            Err(error) if attempt < ATTEMPTS && recovery.transient(&error) => {
                recovery.pause(attempt).await;
                attempt += 1;
            }
            Err(error) => return Err(error),
        }
    }
}

/// Upload the artifact `artifact` of `backup`, whose header and SHA-256
/// the pre-pass read: begin or resume, the parts S3 does not have yet in
/// order, then complete. `progress` hears the bytes uploaded or found
/// uploaded so far. Its expiry as the renter's hosted backup.
///
/// # Errors
///
/// A refusal of the backend's, a read that fails, and a request that keeps
/// failing.
pub async fn upload(
    recovery: &impl Recovery,
    backup: &RecoverableBackupView,
    artifact: &mut File,
    header: &[u8],
    sha256: &str,
    mut progress: impl FnMut(u64),
) -> Result<DateTime<Utc>> {
    let begin = RecoverHostBackupRequest::Begin {
        header: URL_SAFE_NO_PAD.encode(header),
    };
    let RecoverHostBackupView::Begun {
        part_bytes,
        part_count,
        committed,
    } = retried(recovery, || recovery.step(backup.backup_id, &begin)).await?
    else {
        bail!("the backend did not begin the upload");
    };
    let parts = plan_parts(backup.size_bytes, part_bytes, part_count)?;
    let mut sent: u64 = parts
        .iter()
        .filter(|part| committed.contains(&part.number))
        .map(|part| part.size_bytes)
        .sum();
    progress(sent);
    for part in parts
        .iter()
        .filter(|part| !committed.contains(&part.number))
    {
        let body = read_part(artifact, part)?;
        let content_md5 = URL_SAFE_NO_PAD.encode(Md5::digest(&body));
        let authorize = RecoverHostBackupRequest::AuthorizePart {
            part_number: part.number,
            size_bytes: part.size_bytes,
            content_md5,
        };
        let etag = retried(recovery, || async {
            let RecoverHostBackupView::PartAuthorized { url, headers, .. } =
                recovery.step(backup.backup_id, &authorize).await?
            else {
                bail!("the backend did not authorize part {}", part.number);
            };
            recovery.put(&url, &headers, body.clone()).await
        })
        .await
        .with_context(|| format!("upload part {}", part.number))?;
        let commit = RecoverHostBackupRequest::CommitPart {
            part_number: part.number,
            etag,
        };
        retried(recovery, || recovery.step(backup.backup_id, &commit)).await?;
        sent += part.size_bytes;
        progress(sent);
    }
    let complete = RecoverHostBackupRequest::Complete {
        sha256: sha256.to_owned(),
    };
    match retried(recovery, || recovery.step(backup.backup_id, &complete)).await? {
        RecoverHostBackupView::Completed { expires_at } => Ok(expires_at),
        _ => bail!("the backend did not complete the upload"),
    }
}

/// One part of an upload: its number, where it starts and its exact size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Part {
    pub number: u32,
    pub offset: u64,
    pub size_bytes: u64,
}

/// The parts of an artifact of `size_bytes` in parts of `part_bytes`, the
/// last the rest, as the backend laid them out.
///
/// # Errors
///
/// A layout that does not cover the artifact in `part_count` parts.
pub fn plan_parts(size_bytes: u64, part_bytes: u64, part_count: u32) -> Result<Vec<Part>> {
    if part_bytes == 0 || size_bytes.div_ceil(part_bytes) != u64::from(part_count) {
        bail!("the backend's part layout does not fit the backup");
    }
    Ok((1..=part_count)
        .map(|number| {
            let offset = u64::from(number - 1) * part_bytes;
            Part {
                number,
                offset,
                size_bytes: (size_bytes - offset).min(part_bytes),
            }
        })
        .collect())
}

fn read_part(artifact: &mut File, part: &Part) -> Result<Vec<u8>> {
    artifact.seek(SeekFrom::Start(part.offset))?;
    let mut body = vec![0_u8; usize::try_from(part.size_bytes)?];
    artifact
        .read_exact(&mut body)
        .with_context(|| format!("read part {}", part.number))?;
    Ok(body)
}

/// A backup's progress line: `ghb-…  12.3 / 80.0 GiB  4.1 MB/s`.
#[must_use]
#[allow(clippy::cast_precision_loss, reason = "a progress line's figures")]
pub fn progress_line(name: &str, done: u64, total: u64, rate_bytes_per_second: f64) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    format!(
        "{name}  {:.1} / {:.1} GiB  {:.1} MB/s",
        done as f64 / GIB,
        total as f64 / GIB,
        rate_bytes_per_second / 1_000_000.0
    )
}

/// The rate of a stage that moved `bytes` since `started`.
#[must_use]
#[allow(clippy::cast_precision_loss, reason = "a progress line's figures")]
pub fn rate(bytes: u64, started: Instant) -> f64 {
    let seconds = started.elapsed().as_secs_f64();
    if seconds > 0.0 {
        bytes as f64 / seconds
    } else {
        0.0
    }
}

/// How long to wait before attempt `attempt + 1`: 2, 4, 8, 16 seconds.
#[must_use]
pub fn backoff(attempt: u32) -> Duration {
    Duration::from_secs(1_u64 << attempt.min(4))
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::BTreeMap, io::Write as _};

    use super::*;

    fn backup(id: Uuid, backend: StorageBackend, size_bytes: u64) -> RecoverableBackupView {
        let simple = id.simple().to_string();
        RecoverableBackupView {
            backup_id: id,
            artifact_name: match backend {
                StorageBackend::PreallocatedFile => format!("ghb-{simple}.ghb"),
                _ => format!("ghb-{simple}"),
            },
            pool_external_id: "pool".to_owned(),
            pool_backend: backend,
            size_bytes,
            sha256: String::new(),
            state: BackupRecoveryState::Waiting,
            parts_committed: None,
            part_count: None,
        }
    }

    /// An artifact of `size_bytes`: a header naming `id`, then bytes that
    /// count up.
    fn artifact(id: Uuid, size_bytes: usize) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(size_bytes);
        bytes.extend_from_slice(b"GHBKP002");
        bytes.extend_from_slice(id.as_bytes());
        bytes.extend_from_slice(&8_u64.to_be_bytes());
        bytes.extend_from_slice(&(4_u64 * 1024 * 1024).to_be_bytes());
        bytes.extend_from_slice(&[7; 32]);
        bytes.extend_from_slice(&[8; 16]);
        bytes.extend_from_slice(&80_u16.to_be_bytes());
        bytes.extend_from_slice(&[9; 80]);
        let mut next = 0_u8;
        while bytes.len() < size_bytes {
            bytes.push(next);
            next = next.wrapping_add(1);
        }
        bytes
    }

    fn sha(bytes: &[u8]) -> String {
        hex(&sha2::Digest::finalize(
            <Sha256 as sha2::Digest>::new_with_prefix(bytes),
        ))
    }

    #[test]
    fn artifacts_are_found_in_a_file_pool_and_a_volume_group() {
        let files = tempfile::tempdir().unwrap();
        let group = tempfile::tempdir().unwrap();
        let in_file = backup(Uuid::now_v7(), StorageBackend::PreallocatedFile, 300);
        let in_group = backup(Uuid::now_v7(), StorageBackend::LvmThin, 300);
        let missing = backup(Uuid::now_v7(), StorageBackend::LvmThin, 300);
        std::fs::write(files.path().join(&in_file.artifact_name), [0; 300]).unwrap();
        // A file standing in for the logical volume's device node.
        std::fs::write(group.path().join(&in_group.artifact_name), [0; 300]).unwrap();
        let directories = vec![files.path().to_owned(), group.path().to_owned()];
        assert_eq!(
            find(&directories, &in_file).unwrap().path,
            files
                .path()
                .join(format!("ghb-{}.ghb", in_file.backup_id.simple()))
        );
        assert_eq!(
            find(&directories, &in_group).unwrap().path,
            group
                .path()
                .join(format!("ghb-{}", in_group.backup_id.simple()))
        );
        assert!(find(&directories, &missing).is_none());
        assert!(!may_need_activation(&directories, &missing));
        assert!(may_need_activation(&[PathBuf::from("/dev/vg1")], &missing));
        assert!(!may_need_activation(&[PathBuf::from("/dev/vg1")], &in_file));
    }

    #[test]
    fn a_file_is_exactly_its_size_and_a_volume_at_least_and_read_to_it() {
        let directory = tempfile::tempdir().unwrap();
        let id = Uuid::now_v7();
        let bytes = artifact(id, 1000);
        let path = directory.path().join("artifact");
        std::fs::write(&path, &bytes).unwrap();
        let mut exact = backup(id, StorageBackend::PreallocatedFile, 1000);
        assert!(open_artifact(&path, &exact).is_ok());
        exact.size_bytes = 900;
        assert!(
            open_artifact(&path, &exact).is_err(),
            "a file pool's artifact is exact"
        );
        // A volume larger than the artifact: only its first bytes are read.
        let mut volume = backup(id, StorageBackend::LvmThin, 900);
        let mut file = open_artifact(&path, &volume).unwrap();
        volume.sha256 = sha(&bytes[..900]);
        let (header, digest) = prepass(&mut file, &volume, |_| {}).unwrap();
        assert_eq!(header, bytes[..HEADER_BYTES]);
        assert_eq!(digest, volume.sha256);
        volume.size_bytes = 1001;
        assert!(
            open_artifact(&path, &volume).is_err(),
            "a volume holds the artifact whole"
        );
    }

    #[test]
    fn a_prepass_reads_the_header_and_hashes_the_artifact() {
        let id = Uuid::now_v7();
        let bytes = artifact(id, 5000);
        let mut view = backup(id, StorageBackend::PreallocatedFile, 5000);
        let mut seen = 0;
        let (_, digest) = prepass(&mut bytes.as_slice(), &view, |read| seen = read).unwrap();
        assert_eq!(digest, sha(&bytes));
        assert_eq!(seen, 5000);
        // A damaged artifact hashes to another digest, which the command
        // reports and skips.
        let mut damaged = bytes.clone();
        damaged[4000] ^= 1;
        let (_, other) = prepass(&mut damaged.as_slice(), &view, |_| {}).unwrap();
        assert_ne!(other, digest);
        // Another backup's artifact, and one cut short.
        let other_id = artifact(Uuid::now_v7(), 5000);
        assert!(prepass(&mut other_id.as_slice(), &view, |_| {}).is_err());
        view.size_bytes = 6000;
        assert!(prepass(&mut bytes.as_slice(), &view, |_| {}).is_err());
    }

    #[test]
    fn the_parts_cover_the_artifact_the_last_the_rest() {
        let parts = plan_parts(250, 100, 3).unwrap();
        assert_eq!(
            parts,
            [
                Part {
                    number: 1,
                    offset: 0,
                    size_bytes: 100
                },
                Part {
                    number: 2,
                    offset: 100,
                    size_bytes: 100
                },
                Part {
                    number: 3,
                    offset: 200,
                    size_bytes: 50
                },
            ]
        );
        assert!(plan_parts(250, 100, 2).is_err());
        assert!(plan_parts(250, 0, 3).is_err());
    }

    #[test]
    fn the_progress_line_names_the_artifact_its_figures_and_rate() {
        assert_eq!(
            progress_line("ghb-0190", 13_207_024_435, 85_899_345_920, 4_100_000.0),
            "ghb-0190  12.3 / 80.0 GiB  4.1 MB/s"
        );
        assert_eq!(backoff(1), Duration::from_secs(2));
        assert_eq!(backoff(9), Duration::from_secs(16));
    }

    #[test]
    fn uploading_backups_go_first() {
        let mut first = backup(Uuid::now_v7(), StorageBackend::LvmThin, 1);
        let mut second = backup(Uuid::now_v7(), StorageBackend::LvmThin, 1);
        let mut done = backup(Uuid::now_v7(), StorageBackend::LvmThin, 1);
        second.state = BackupRecoveryState::Uploading;
        done.state = BackupRecoveryState::Recovered;
        first.state = BackupRecoveryState::Waiting;
        let list = [first.clone(), second.clone(), done];
        let order: Vec<Uuid> = to_upload(&list).iter().map(|b| b.backup_id).collect();
        assert_eq!(order, [second.backup_id, first.backup_id]);
    }

    /// A backend and a bucket in memory: parts committed before the run,
    /// and every step and PUT it hears.
    struct Mock {
        committed: Vec<u32>,
        part_bytes: u64,
        part_count: u32,
        puts: RefCell<BTreeMap<u32, Vec<u8>>>,
        steps: RefCell<Vec<String>>,
        /// PUTs that fail once, transiently, before they succeed.
        flaky: RefCell<Vec<u32>>,
    }

    impl Recovery for Mock {
        async fn step(
            &self,
            _: Uuid,
            request: &RecoverHostBackupRequest,
        ) -> Result<RecoverHostBackupView> {
            Ok(match request {
                RecoverHostBackupRequest::Begin { .. } => {
                    self.steps.borrow_mut().push("begin".to_owned());
                    RecoverHostBackupView::Begun {
                        part_bytes: self.part_bytes,
                        part_count: self.part_count,
                        committed: self.committed.clone(),
                    }
                }
                RecoverHostBackupRequest::AuthorizePart { part_number, .. } => {
                    self.steps
                        .borrow_mut()
                        .push(format!("authorize {part_number}"));
                    RecoverHostBackupView::PartAuthorized {
                        part_number: *part_number,
                        url: format!("https://bucket/{part_number}"),
                        headers: Vec::new(),
                        expires_at: Utc::now(),
                    }
                }
                RecoverHostBackupRequest::CommitPart { part_number, etag } => {
                    self.steps
                        .borrow_mut()
                        .push(format!("commit {part_number} {etag}"));
                    RecoverHostBackupView::PartCommitted {
                        part_number: *part_number,
                    }
                }
                RecoverHostBackupRequest::Complete { sha256 } => {
                    self.steps.borrow_mut().push(format!("complete {sha256}"));
                    RecoverHostBackupView::Completed {
                        expires_at: DateTime::UNIX_EPOCH,
                    }
                }
                RecoverHostBackupRequest::Abort => RecoverHostBackupView::Aborted,
            })
        }

        async fn put(&self, url: &str, _: &[PresignedHeaderView], body: Vec<u8>) -> Result<String> {
            let number: u32 = url.rsplit('/').next().unwrap().parse().unwrap();
            let mut flaky = self.flaky.borrow_mut();
            if let Some(at) = flaky.iter().position(|part| *part == number) {
                flaky.remove(at);
                bail!("transient");
            }
            self.puts.borrow_mut().insert(number, body);
            Ok(format!("etag-{number}"))
        }

        fn transient(&self, error: &anyhow::Error) -> bool {
            error.to_string() == "transient"
        }

        async fn pause(&self, _: u32) {}
    }

    #[tokio::test]
    async fn a_rerun_resumes_past_the_committed_parts() {
        let id = Uuid::now_v7();
        let bytes = artifact(id, 250);
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("artifact");
        File::create(&path).unwrap().write_all(&bytes).unwrap();
        let view = backup(id, StorageBackend::PreallocatedFile, 250);
        let mock = Mock {
            committed: vec![1],
            part_bytes: 100,
            part_count: 3,
            puts: RefCell::default(),
            steps: RefCell::default(),
            flaky: RefCell::new(vec![3]),
        };
        let mut file = open_artifact(&path, &view).unwrap();
        let (header, digest) = prepass(&mut file, &view, |_| {}).unwrap();
        let mut heard = Vec::new();
        upload(&mock, &view, &mut file, &header, &digest, |sent| {
            heard.push(sent);
        })
        .await
        .unwrap();
        let puts = mock.puts.into_inner();
        assert_eq!(puts.keys().copied().collect::<Vec<_>>(), [2, 3]);
        assert_eq!(puts[&2], bytes[100..200]);
        assert_eq!(puts[&3], bytes[200..]);
        assert_eq!(
            mock.steps.into_inner(),
            [
                "begin".to_owned(),
                "authorize 2".to_owned(),
                "commit 2 etag-2".to_owned(),
                // The failed PUT is authorized again.
                "authorize 3".to_owned(),
                "authorize 3".to_owned(),
                "commit 3 etag-3".to_owned(),
                format!("complete {digest}"),
            ]
        );
        assert_eq!(heard, [100, 200, 250]);
    }
}
