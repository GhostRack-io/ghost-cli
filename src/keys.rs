use std::{
    fs::{self, OpenOptions},
    io::{Read as _, Write as _},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use hpke::{
    Deserializable as _, Kem as _, OpModeR, OpModeS, Serializable as _, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256, single_shot_open, single_shot_seal,
};
use rand_core::{OsRng, RngCore as _};
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

const SEED_PREFIX: &[u8] = b"gigahost-account-seed-v1:";
const DERIVATION_SALT: &[u8] = b"GIGAHOST-ACCOUNT-SEED-V1";
const AUTHENTICATION_KEY_LABEL: &[u8] = b"account-authentication-ed25519-v1";
const RECOVERY_KEY_LABEL: &[u8] = b"backup-recovery-x25519-v1";
const BILLING_KEY_LABEL: &[u8] = b"billing-authorization-ed25519-v1";

type RecoveryPrivateKey = <X25519HkdfSha256 as hpke::Kem>::PrivateKey;

pub struct RecoveryKeyPair {
    private_key: RecoveryPrivateKey,
    pub public_key: [u8; 32],
    pub fingerprint: [u8; 32],
}

pub struct AuthenticationIdentity {
    signing_key: SigningKey,
    pub public_key: [u8; 32],
    pub key_id: String,
    pub deposit_memo: String,
}

impl AuthenticationIdentity {
    pub fn sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
        use ed25519_dalek::Signer as _;

        self.signing_key.sign(message)
    }
}

#[derive(Serialize)]
pub struct KeySummary {
    pub derivation: &'static str,
    pub deposit_memo: String,
    pub authentication_public_key: String,
    pub authentication_key_id: String,
    pub recovery_public_key: String,
    pub recovery_key_fingerprint: String,
    pub billing_verifying_key: String,
    pub billing_key_fingerprint: String,
}

/// Larger than any valid seed file, which is about 70 bytes.
const MAXIMUM_SEED_FILE_BYTES: usize = 256;

pub fn generate_seed(path: &Path) -> Result<KeySummary> {
    let (parent, file_name) = seed_location(path)?;
    let refusal = || {
        format!(
            "create account key file {} (refusing to overwrite)",
            path.display()
        )
    };
    if fs::symlink_metadata(path).is_ok() {
        bail!("{}: the file already exists", refusal());
    }
    let mut seed = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(seed.as_mut());

    // Write a private temporary file beside the seed and hard-link it into
    // place: a failed or interrupted write never leaves a partial seed that
    // blocks the next attempt, and the link refuses an existing seed.
    let temporary = write_temporary(&parent, &file_name, &seed)?;
    let linked = fs::hard_link(&temporary, path).with_context(refusal);
    let _ = fs::remove_file(&temporary);
    linked?;
    sync_directory(&parent);
    key_summary(&seed)
}

/// What [`import_seed`] did with the seed file.
#[derive(Debug, PartialEq, Eq)]
pub enum ImportOutcome {
    /// There was no seed file; the key is in it now.
    Imported,
    /// The seed file already held this key; nothing was written.
    AlreadyImported,
    /// The seed file held another key, or one that could not be read,
    /// which is kept at `previous` beside it; this key is in it now.
    Replaced { previous: PathBuf },
}

/// The error code of an import refused because the seed file holds
/// another key, or one it cannot read, and `--replace` was not given.
pub const ACCOUNT_KEY_EXISTS: &str = "account_key_exists";

/// The most names `.replaced-<time>`, `-2`, … `-10` an import with
/// `replace` tries for the key it keeps.
const KEPT_NAME_ATTEMPTS: u32 = 10;

/// Put `seed` in the seed file at `path`, as [`generate_seed`] writes one:
/// `0600`, in missing directories created for the owner alone, through a
/// temporary file beside it. An existing file is never overwritten
/// silently: one that holds `seed` is left as it is; one that holds
/// another key, or that [`load_seed`] refuses, is refused with
/// [`ACCOUNT_KEY_EXISTS`] unless `replace`, which first keeps it as
/// `<name>.replaced-<UTC time>` beside it (also `0600`) and then renames
/// the new file over it, so the old key is at `path` or at the kept name
/// whatever fails. A symbolic link or anything but a regular file at
/// `path` is never replaced.
pub fn import_seed(path: &Path, seed: &[u8; 32], replace: bool) -> Result<ImportOutcome> {
    let (parent, file_name) = seed_location(path)?;
    let found = match fs::symlink_metadata(path) {
        Ok(found) => found,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let temporary = write_temporary(&parent, &file_name, seed)?;
            let linked = fs::hard_link(&temporary, path);
            let _ = fs::remove_file(&temporary);
            return match linked {
                Ok(()) => {
                    sync_directory(&parent);
                    Ok(ImportOutcome::Imported)
                }
                // Another `ghost` created the seed meanwhile: it is kept,
                // and running the import again compares it.
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    Err(key_exists(path, "was created while this key was imported").into())
                }
                Err(error) => Err(anyhow::Error::new(error)
                    .context(format!("create account key file {}", path.display()))),
            };
        }
        Err(error) => {
            return Err(anyhow::Error::new(error)
                .context(format!("inspect account key {}", path.display())));
        }
    };
    let reason = match load_seed(path) {
        Ok(existing) if *existing == *seed => return Ok(ImportOutcome::AlreadyImported),
        Ok(_) => "holds a different account key".to_owned(),
        Err(error) => format!("cannot be read: {error:#}"),
    };
    if found.file_type().is_symlink() {
        bail!(
            "account key file {} is a symbolic link, which is never replaced; move it away to import this key",
            path.display()
        );
    }
    if !found.file_type().is_file() {
        bail!(
            "account key {} is not a regular file, which is never replaced; move it away to import this key",
            path.display()
        );
    }
    if !replace {
        return Err(key_exists(path, &reason).into());
    }
    let kept = keep_previous(path, &parent, &file_name, &replaced_suffix())?;
    let still = |what: String| {
        format!(
            "{what}; the previous account key is still at {} and also kept at {}",
            path.display(),
            kept.display()
        )
    };
    let temporary = write_temporary(&parent, &file_name, seed)
        .with_context(|| still("import failed".to_owned()))?;
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(anyhow::Error::new(error).context(still(format!(
            "replace account key file {}",
            path.display()
        ))));
    }
    sync_directory(&parent);
    Ok(ImportOutcome::Replaced { previous: kept })
}

/// The refusal of an import over the seed file at `path`, which `reason`.
fn key_exists(path: &Path, reason: &str) -> crate::Refusal {
    crate::Refusal {
        code: ACCOUNT_KEY_EXISTS,
        message: format!(
            "{} {reason}; keep it, or pass --replace to keep it as {} and import this one",
            path.display(),
            kept_name(path, &replaced_suffix(), 1).display()
        ),
    }
}

/// The time part of a kept seed's name, `.replaced-<UTC time>`.
fn replaced_suffix() -> String {
    format!(".replaced-{}", chrono::Utc::now().format("%Y%m%dT%H%M%SZ"))
}

/// The `attempt`th name tried for the seed at `path` kept with `suffix`:
/// `account.seed.replaced-<time>`, then `-2`, `-3`, ….
fn kept_name(path: &Path, suffix: &str, attempt: u32) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    if attempt > 1 {
        name.push(format!("-{attempt}"));
    }
    path.with_file_name(name)
}

/// Keep the seed file at `path` under a new `.replaced-<time>` name in
/// `parent` by a second hard link, which never overwrites a file of that
/// name, and make it the owner's alone. The seed stays at `path` too.
fn keep_previous(
    path: &Path,
    parent: &Path,
    file_name: &std::ffi::OsStr,
    suffix: &str,
) -> Result<PathBuf> {
    for attempt in 1..=KEPT_NAME_ATTEMPTS {
        let kept = parent.join(kept_name(Path::new(file_name), suffix, attempt));
        match fs::hard_link(path, &kept) {
            Ok(()) => {
                // A link is the same file: its mode is the seed's, which
                // `--replace` may be replacing for being readable by others.
                // Only a regular file is changed, never a link's target.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    if fs::symlink_metadata(&kept).is_ok_and(|kept| kept.file_type().is_file()) {
                        fs::set_permissions(&kept, fs::Permissions::from_mode(0o600))
                            .with_context(|| {
                                format!(
                                    "make the kept account key {} private; the previous account key is still at {}",
                                    kept.display(),
                                    path.display()
                                )
                            })?;
                    }
                }
                return Ok(kept);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(anyhow::Error::new(error).context(format!(
                    "keep the previous account key {} as {}",
                    path.display(),
                    kept.display()
                )));
            }
        }
    }
    bail!(
        "keep the previous account key {}: {} names are taken already",
        path.display(),
        KEPT_NAME_ATTEMPTS
    )
}

/// The directory and file name of the seed file at `path`, creating the
/// missing directories. Only the owner may enter a directory this creates,
/// whatever the umask allows: others could otherwise rename or replace the
/// seed. A directory that exists keeps its mode.
fn seed_location(path: &Path) -> Result<(PathBuf, std::ffi::OsString)> {
    let file_name = path
        .file_name()
        .context("account key file path must name a file")?;
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let mut directories = fs::DirBuilder::new();
    directories.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        directories.mode(0o700);
    }
    directories
        .create(parent)
        .with_context(|| format!("create account key directory {}", parent.display()))?;
    Ok((parent.to_owned(), file_name.to_owned()))
}

/// Write `seed` as a seed file's text to a new private temporary file
/// `.<name>.<uuid>.tmp` in `parent`, synced, and return its path. A failed
/// write leaves no temporary file.
fn write_temporary(parent: &Path, file_name: &std::ffi::OsStr, seed: &[u8; 32]) -> Result<PathBuf> {
    let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(seed));
    let mut temporary_name = std::ffi::OsString::from(".");
    temporary_name.push(file_name);
    temporary_name.push(format!(".{}.tmp", Uuid::now_v7()));
    let temporary = parent.join(temporary_name);
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .with_context(|| format!("create temporary account key file {}", temporary.display()))?;
    let written = file
        .write_all(SEED_PREFIX)
        .and_then(|()| file.write_all(encoded.as_bytes()))
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
        .with_context(|| format!("write account key file {}", temporary.display()));
    drop(file);
    if let Err(error) = written {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(temporary)
}

/// Make a new directory entry in `directory` durable; not every platform
/// can open or sync a directory, and the seed itself is already synced.
fn sync_directory(directory: &Path) {
    let _ = fs::File::open(directory).and_then(|directory| directory.sync_all());
}

pub fn load_seed(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let file = open_seed_file(path)?;
    // Reserve the whole bound up front so reading never reallocates and
    // leaves an unzeroized copy of the seed behind.
    let mut contents = Zeroizing::new(Vec::with_capacity(MAXIMUM_SEED_FILE_BYTES));
    file.take(MAXIMUM_SEED_FILE_BYTES as u64)
        .read_to_end(&mut contents)
        .with_context(|| format!("read account key {}", path.display()))?;
    parse_seed(&contents)
}

/// The seed of a seed file's text. Surrounding ASCII whitespace is no part
/// of the key: a seed file saved from a pasted line by any editor (a
/// `\r\n`, a space, no newline) loads, as the website's `seed.js` reads the
/// same text.
pub fn parse_seed(contents: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let encoded = contents
        .trim_ascii()
        .strip_prefix(SEED_PREFIX)
        .context("account key has an unsupported format")?;
    let decoded = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded)
            .context("account key is not valid unpadded base64url")?,
    );
    let seed: [u8; 32] = decoded
        .as_slice()
        .try_into()
        .context("account key must encode exactly 32 bytes")?;
    Ok(Zeroizing::new(seed))
}

/// The seed of a key given to `ghost key import`: [`parse_seed`] of at
/// most [`MAXIMUM_SEED_FILE_BYTES`], with its words, after refusing an
/// empty input and a longer one, which is no account key.
pub fn parse_imported_seed(input: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if input.len() > MAXIMUM_SEED_FILE_BYTES {
        bail!("the input is longer than an account key ({MAXIMUM_SEED_FILE_BYTES} bytes at most)");
    }
    if input.trim_ascii().is_empty() {
        bail!("no account key was given");
    }
    parse_seed(input)
}

/// Read at most one byte more than [`MAXIMUM_SEED_FILE_BYTES`] with
/// `read`, into a buffer allocated once and zeroized when dropped, up to
/// the end of the input, or with `line` up to its first line feed. The
/// extra byte lets [`parse_imported_seed`] refuse a longer input.
fn read_bounded(
    mut read: impl FnMut(&mut [u8]) -> std::io::Result<usize>,
    line: bool,
) -> std::io::Result<Zeroizing<Vec<u8>>> {
    let mut buffer = Zeroizing::new(vec![0_u8; MAXIMUM_SEED_FILE_BYTES + 1]);
    let mut filled = 0;
    while filled < buffer.len() {
        let read = match read(&mut buffer[filled..]) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        filled += read;
        if line && buffer[filled - read..filled].contains(&b'\n') {
            break;
        }
    }
    buffer.truncate(filled);
    Ok(buffer)
}

/// The key in the file at `path`, as given to `ghost key import --from`:
/// a plain open, since a downloaded file is often readable by others and
/// may lie anywhere; at most [`MAXIMUM_SEED_FILE_BYTES`] and one more.
pub fn read_key_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let mut file =
        fs::File::open(path).with_context(|| format!("read account key {}", path.display()))?;
    read_bounded(|buffer| file.read(buffer), false)
        .with_context(|| format!("read account key {}", path.display()))
}

/// The key on standard input when it is no terminal, up to its end.
pub fn read_key_stdin() -> Result<Zeroizing<Vec<u8>>> {
    read_bounded(read_stdin, false).context("read the account key from standard input")
}

/// The key pasted as one line on the terminal that standard input is, with
/// the echo off: `prompt` is printed on standard error first, and the line
/// feed the hidden input swallowed after it.
#[cfg(unix)]
pub fn read_key_hidden(prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut stderr = std::io::stderr();
    let read = {
        // Echo is off from before the prompt until the line is read, and
        // back on, whatever the read returned, before anything else.
        let _hidden = hidden_input()?;
        let _ = write!(stderr, "{prompt}");
        let _ = stderr.flush();
        read_bounded(read_stdin, true)
    };
    let _ = writeln!(stderr);
    read.context("read the account key from the terminal")
}

/// The key pasted as one line on the console that standard input is, with
/// the echo off: `prompt` is printed on standard error first. Turning the
/// echo off takes `SetConsoleMode`, which is `unsafe` and which this
/// workspace forbids in its own code, so `rpassword` reads the line; its
/// text is zeroized when dropped, and at most [`MAXIMUM_SEED_FILE_BYTES`]
/// and one more of it are kept for [`parse_imported_seed`]. Unlike on
/// unix, the rest of a paste of several lines stays in the console's input
/// for the shell to read after ghost: dropping it takes
/// `FlushConsoleInputBuffer`, `unsafe` as well.
#[cfg(windows)]
pub fn read_key_hidden(prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut stderr = std::io::stderr();
    let _ = write!(stderr, "{prompt}");
    let _ = stderr.flush();
    let read = rpassword::read_password().map(Zeroizing::new);
    // The console's own handling of Enter already ends the prompt's line;
    // only a read that ended without one (end of input) needs it here.
    if matches!(&read, Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof) {
        let _ = writeln!(stderr);
    }
    let line = read.context("read the account key from the terminal")?;
    let bytes = line.as_bytes();
    let kept = bytes.len().min(MAXIMUM_SEED_FILE_BYTES + 1);
    let mut key = Zeroizing::new(Vec::with_capacity(kept));
    key.extend_from_slice(&bytes[..kept]);
    Ok(key)
}

/// No echo to turn off is known on another platform: a key is not read
/// from its terminal, where it would be shown.
#[cfg(not(any(unix, windows)))]
pub fn read_key_hidden(_prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
    bail!(
        "a pasted account key cannot be read with the echo off here; pass the file with --from FILE, or pipe the key on standard input"
    )
}

/// Read standard input straight from its file descriptor: the standard
/// library's buffer would keep a copy of the key that nothing zeroizes.
#[cfg(unix)]
fn read_stdin(buffer: &mut [u8]) -> std::io::Result<usize> {
    rustix::io::read(std::io::stdin(), buffer).map_err(std::io::Error::from)
}

/// Read standard input. Without `unsafe`, which this workspace forbids,
/// there is no raw handle to read here; a read at least as large as the
/// standard library's buffer (8 KiB) goes around that buffer, so no copy
/// of the key is left in it.
#[cfg(not(unix))]
fn read_stdin(buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut large = Zeroizing::new(vec![0_u8; 16 * 1024]);
    let read = std::io::stdin().lock().read(&mut large)?;
    let copied = read.min(buffer.len());
    buffer[..copied].copy_from_slice(&large[..copied]);
    Ok(copied)
}

/// The terminal's echo, turned off while this lives and restored when it
/// is dropped, on every return. An interrupt (Ctrl-C) while it is off ends
/// the process without the drop and can leave echo off, as with other
/// password prompts; `stty echo` or `reset` turns it on again.
///
/// Both changes drop the input not read yet, as `sudo` does: before the
/// prompt, what was typed ahead; after the line, the rest of a paste of
/// several lines or of one longer than a key, which the shell would
/// otherwise read when ghost ends, run as a command and keep in its
/// history, the key among it.
#[cfg(unix)]
struct HiddenInput {
    saved: rustix::termios::Termios,
}

#[cfg(unix)]
fn hidden_input() -> Result<HiddenInput> {
    use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};

    let stdin = std::io::stdin();
    let saved = tcgetattr(&stdin).context("read the terminal's settings")?;
    let mut hidden = saved.clone();
    // Canonical mode and signals stay: the line is read whole, and Ctrl-C
    // still interrupts.
    hidden.local_modes.remove(LocalModes::ECHO);
    tcsetattr(&stdin, OptionalActions::Flush, &hidden).context("turn the terminal's echo off")?;
    Ok(HiddenInput { saved })
}

#[cfg(unix)]
impl Drop for HiddenInput {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(
            std::io::stdin(),
            rustix::termios::OptionalActions::Flush,
            &self.saved,
        );
    }
}

pub fn key_summary(seed: &[u8; 32]) -> Result<KeySummary> {
    let authentication = authentication_identity(seed)?;
    let recovery = recovery_key_pair(seed)?;
    let billing_material = derive_material(seed, BILLING_KEY_LABEL)?;
    let billing = SigningKey::from_bytes(&billing_material);
    let billing_public = billing.verifying_key().to_bytes();
    let billing_fingerprint: [u8; 32] = Sha256::digest(billing_public).into();
    Ok(KeySummary {
        derivation: "hkdf-sha256/gigahost-account-seed-v1",
        deposit_memo: authentication.deposit_memo,
        authentication_public_key: URL_SAFE_NO_PAD.encode(authentication.public_key),
        authentication_key_id: authentication.key_id,
        recovery_public_key: URL_SAFE_NO_PAD.encode(recovery.public_key),
        recovery_key_fingerprint: URL_SAFE_NO_PAD.encode(recovery.fingerprint),
        billing_verifying_key: URL_SAFE_NO_PAD.encode(billing_public),
        billing_key_fingerprint: URL_SAFE_NO_PAD.encode(billing_fingerprint),
    })
}

pub fn authentication_identity(seed: &[u8; 32]) -> Result<AuthenticationIdentity> {
    let material = derive_material(seed, AUTHENTICATION_KEY_LABEL)?;
    let signing_key = SigningKey::from_bytes(&material);
    let public_key = signing_key.verifying_key().to_bytes();
    Ok(AuthenticationIdentity {
        signing_key,
        public_key,
        key_id: ghostrack_client_api::account_auth::auth_key_id(&public_key),
        deposit_memo: ghostrack_client_api::account_auth::deposit_memo(&public_key),
    })
}

pub fn sign_billing_authorization(
    seed: &[u8; 32],
    message: &[u8],
) -> Result<ed25519_dalek::Signature> {
    use ed25519_dalek::Signer as _;

    let material = derive_material(seed, BILLING_KEY_LABEL)?;
    Ok(SigningKey::from_bytes(&material).sign(message))
}

pub fn recovery_key_pair(seed: &[u8; 32]) -> Result<RecoveryKeyPair> {
    let material = derive_material(seed, RECOVERY_KEY_LABEL)?;
    let (private_key, public_key) = X25519HkdfSha256::derive_keypair(material.as_ref());
    let public_key: [u8; 32] = public_key
        .to_bytes()
        .as_slice()
        .try_into()
        .context("derived recovery public key has an unexpected length")?;
    Ok(RecoveryKeyPair {
        private_key,
        public_key,
        fingerprint: Sha256::digest(public_key).into(),
    })
}

pub struct BackupRewrapTarget<'a> {
    pub source_instance_id: Uuid,
    pub destination_instance_id: Uuid,
    pub backup_id: Uuid,
    pub restore_job_id: Uuid,
    pub destination_public_key: &'a str,
    pub destination_key_fingerprint: &'a str,
}

pub fn rewrap_backup_data_key(
    keys: &RecoveryKeyPair,
    target: &BackupRewrapTarget<'_>,
    wrapped_data_key: &str,
) -> Result<String> {
    rewrap_with(
        keys,
        target,
        wrapped_data_key,
        |destination, aad, data_key| {
            single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
                &OpModeS::Base,
                destination,
                RESTORE_DATA_KEY_INFO,
                data_key,
                aad,
            )
        },
    )
}

/// The HPKE info of a backup's data key wrapped to the recovery key, and
/// of the same key rewrapped to a restore's destination.
const BACKUP_DATA_KEY_INFO: &[u8] = b"GIGAHOST-BACKUP-DATA-KEY-V1";
const RESTORE_DATA_KEY_INFO: &[u8] = b"GIGAHOST-RESTORE-DATA-KEY-V1";

/// [`rewrap_backup_data_key`] with `seal`, which seals the opened data key
/// (its third argument) to the destination's public key with the restore's
/// AAD: with the system's randomness for a restore, a fixed one for the
/// vectors other clients reproduce
/// (`crates/client-api/fixtures/backup-key-vectors.json`).
fn rewrap_with(
    keys: &RecoveryKeyPair,
    target: &BackupRewrapTarget<'_>,
    wrapped_data_key: &str,
    seal: impl FnOnce(
        &<X25519HkdfSha256 as hpke::Kem>::PublicKey,
        &[u8],
        &[u8],
    ) -> Result<
        (<X25519HkdfSha256 as hpke::Kem>::EncappedKey, Vec<u8>),
        hpke::HpkeError,
    >,
) -> Result<String> {
    let wrapped = decode_base64url(wrapped_data_key, "wrapped backup data key")?;
    if wrapped.len() != 80 {
        bail!("wrapped backup data key must be exactly 80 bytes");
    }
    let encapsulated = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&wrapped[..32])
        .context("wrapped backup data key has an invalid encapsulation")?;
    let data_key = Zeroizing::new(
        single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &keys.private_key,
            &encapsulated,
            BACKUP_DATA_KEY_INFO,
            &wrapped[32..],
            &backup_wrap_aad(
                target.source_instance_id,
                target.backup_id,
                &keys.fingerprint,
            ),
        )
        .map_err(|_| anyhow::anyhow!("backup key could not be opened with this account key"))?,
    );
    if data_key.len() != 32 {
        bail!("opened backup data key has an invalid length");
    }

    let destination_public = decode_base64url_32(
        target.destination_public_key,
        "destination restore public key",
    )?;
    let destination_fingerprint = decode_base64url_32(
        target.destination_key_fingerprint,
        "destination restore key fingerprint",
    )?;
    let calculated_fingerprint: [u8; 32] = Sha256::digest(destination_public).into();
    if calculated_fingerprint != destination_fingerprint {
        bail!("destination restore public key does not match its fingerprint");
    }
    let destination = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(&destination_public)
        .context("destination restore public key is invalid")?;
    let (encapsulation, ciphertext) = seal(
        &destination,
        &restore_wrap_aad(
            target.destination_instance_id,
            target.backup_id,
            target.restore_job_id,
            &destination_fingerprint,
        ),
        data_key.as_ref(),
    )
    .context("wrap backup data key to the destination hypervisor")?;
    let mut rewrapped = encapsulation.to_bytes().to_vec();
    rewrapped.extend_from_slice(&ciphertext);
    Ok(URL_SAFE_NO_PAD.encode(rewrapped))
}

fn derive_material(seed: &[u8; 32], label: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let hkdf = Hkdf::<Sha256>::new(Some(DERIVATION_SALT), seed);
    let mut output = Zeroizing::new([0_u8; 32]);
    hkdf.expand(label, output.as_mut())
        .map_err(|_| anyhow::anyhow!("account key derivation failed"))?;
    Ok(output)
}

fn decode_base64url(value: &str, label: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(value)
        .with_context(|| format!("{label} is not valid unpadded base64url"))
}

fn decode_base64url_32(value: &str, label: &str) -> Result<[u8; 32]> {
    decode_base64url(value, label)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} must encode exactly 32 bytes"))
}

fn backup_wrap_aad(instance_id: Uuid, backup_id: Uuid, fingerprint: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(31 + 16 + 16 + 32);
    aad.extend_from_slice(b"GIGAHOST-BACKUP-WRAP-V1");
    aad.extend_from_slice(instance_id.as_bytes());
    aad.extend_from_slice(backup_id.as_bytes());
    aad.extend_from_slice(fingerprint);
    aad
}

fn restore_wrap_aad(
    instance_id: Uuid,
    backup_id: Uuid,
    restore_job_id: Uuid,
    fingerprint: &[u8; 32],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + 16 + 16 + 16 + 32);
    aad.extend_from_slice(b"GIGAHOST-BACKUP-RESTORE-WRAP-V1");
    aad.extend_from_slice(instance_id.as_bytes());
    aad.extend_from_slice(backup_id.as_bytes());
    aad.extend_from_slice(restore_job_id.as_bytes());
    aad.extend_from_slice(fingerprint);
    aad
}

/// Wrap `data_key` to the account's recovery key the way a hosted backup
/// stores it, so tests can hand the CLI a backup it can rewrap.
#[cfg(test)]
pub(crate) fn wrap_backup_data_key(
    recovery: &RecoveryKeyPair,
    instance_id: Uuid,
    backup_id: Uuid,
    data_key: &[u8; 32],
) -> String {
    let recipient = <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(&recovery.public_key)
        .expect("recovery public key");
    let (encapsulation, ciphertext) =
        single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::Base,
            &recipient,
            b"GIGAHOST-BACKUP-DATA-KEY-V1",
            data_key,
            &backup_wrap_aad(instance_id, backup_id, &recovery.fingerprint),
        )
        .expect("seal the backup data key");
    let mut envelope = encapsulation.to_bytes().to_vec();
    envelope.extend_from_slice(&ciphertext);
    URL_SAFE_NO_PAD.encode(envelope)
}

/// Open the seed file, refusing a symbolic link, anything but a regular
/// file, and a file other users can access. The checks apply to the opened
/// file: the path is inspected without following links, and the opened file
/// must be that same file, so swapping in a link between the check and the
/// open is caught.
#[cfg(unix)]
fn open_seed_file(path: &Path) -> Result<fs::File> {
    use std::os::unix::fs::MetadataExt as _;

    let linked = fs::symlink_metadata(path)
        .with_context(|| format!("inspect account key {}", path.display()))?;
    if linked.file_type().is_symlink() {
        bail!("account key file must not be a symbolic link");
    }
    if !linked.file_type().is_file() {
        bail!("account key {} is not a regular file", path.display());
    }
    let file =
        fs::File::open(path).with_context(|| format!("read account key {}", path.display()))?;
    let opened = file
        .metadata()
        .with_context(|| format!("inspect account key {}", path.display()))?;
    if (opened.dev(), opened.ino()) != (linked.dev(), linked.ino()) {
        bail!(
            "account key file {} was replaced while it was opened",
            path.display()
        );
    }
    if opened.mode() & 0o077 != 0 {
        bail!(
            "account key file {} is accessible by group or other users; run chmod 600",
            path.display()
        );
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_seed_file(path: &Path) -> Result<fs::File> {
    fs::File::open(path).with_context(|| format!("read account key {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_keys_are_deterministic_and_purpose_separated() {
        let seed = [7_u8; 32];
        let first = key_summary(&seed).unwrap();
        let second = key_summary(&seed).unwrap();
        assert_eq!(
            serde_json::to_value(first).unwrap(),
            serde_json::to_value(second).unwrap()
        );
        let value = serde_json::to_value(key_summary(&seed).unwrap()).unwrap();
        assert_ne!(value["recovery_public_key"], value["billing_verifying_key"]);
        assert_eq!(value["deposit_memo"].as_str().unwrap().len(), 16);
        assert_eq!(value["authentication_key_id"].as_str().unwrap().len(), 16);
    }

    #[test]
    fn generated_seed_round_trips_without_being_returned() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("account.seed");
        let generated = generate_seed(&path).unwrap();
        let loaded = load_seed(&path).unwrap();
        assert_eq!(
            serde_json::to_value(generated).unwrap(),
            serde_json::to_value(key_summary(&loaded).unwrap()).unwrap()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(generate_seed(&path).is_err());
    }

    /// The directories generation creates are the owner's alone, as with
    /// `mkdir -m 700`, even under a umask that lets the group write; one
    /// that exists keeps its mode.
    #[cfg(unix)]
    #[test]
    fn seed_directories_are_created_for_the_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("config");
        generate_seed(&config.join("ghost").join("account.seed")).unwrap();
        for created in [config.clone(), config.join("ghost")] {
            let mode = fs::metadata(&created).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "{}", created.display());
        }
        let shared = directory.path().join("shared");
        fs::create_dir(&shared).unwrap();
        fs::set_permissions(&shared, fs::Permissions::from_mode(0o755)).unwrap();
        generate_seed(&shared.join("account.seed")).unwrap();
        let mode = fs::metadata(&shared).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn seed_generation_publishes_only_a_complete_seed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("nested").join("account.seed");
        generate_seed(&path).unwrap();
        let original = fs::read(&path).unwrap();
        let error = generate_seed(&path)
            .err()
            .expect("an existing seed is kept");
        assert!(
            error.to_string().contains("refusing to overwrite"),
            "{error:#}"
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        let entries = fs::read_dir(path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(
            entries,
            ["account.seed"],
            "no temporary file is left behind"
        );
    }

    #[cfg(unix)]
    #[test]
    fn seed_loader_checks_the_opened_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let error = load_seed(directory.path()).unwrap_err();
        assert!(
            error.to_string().contains("not a regular file"),
            "{error:#}"
        );
        let path = directory.path().join("account.seed");
        generate_seed(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let error = load_seed(&path).unwrap_err();
        assert!(error.to_string().contains("chmod 600"), "{error:#}");
    }

    #[cfg(unix)]
    #[test]
    fn seed_loader_rejects_symbolic_links() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("account.seed");
        let link = directory.path().join("linked.seed");
        generate_seed(&path).unwrap();
        symlink(&path, &link).unwrap();
        assert!(
            load_seed(&link)
                .unwrap_err()
                .to_string()
                .contains("symbolic link")
        );
    }

    /// A seed file's text other than the one generation writes still
    /// loads when only surrounding ASCII whitespace differs: a `\r\n`,
    /// spaces, a tab, no newline at all.
    #[test]
    fn seed_loader_ignores_surrounding_whitespace() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("account.seed");
        let seed = [7_u8; 32];
        let line = format!("gigahost-account-seed-v1:{}", URL_SAFE_NO_PAD.encode(seed));
        for text in [
            format!("{line}\n"),
            format!("{line}\r\n"),
            line.clone(),
            format!("  {line} \t\r\n\n"),
            format!("\n{line}\n"),
        ] {
            write_private(&path, text.as_bytes());
            assert_eq!(*load_seed(&path).unwrap(), seed, "{text:?}");
        }
        for text in [
            format!("{line}x\n"),
            format!("{line}=\n"),
            line.replace("gigahost", "Gigahost"),
            format!("{line} {line}"),
        ] {
            write_private(&path, text.as_bytes());
            assert!(load_seed(&path).is_err(), "{text:?}");
        }
    }

    /// The words every refusal of a malformed key has, `load_seed`'s,
    /// for the texts given to an import.
    #[test]
    fn imported_keys_are_parsed_as_seed_files_are() {
        let file: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        for entry in file["vectors"].as_array().unwrap() {
            let text = entry["seed_file"].as_str().unwrap();
            let line = text.trim_end();
            for given in [
                text.to_owned(),
                format!("{line}\r\n"),
                format!("  {line}  "),
                line.to_owned(),
            ] {
                assert_eq!(
                    hex(parse_imported_seed(given.as_bytes()).unwrap().as_ref()),
                    entry["seed_hex"].as_str().unwrap(),
                    "{given:?}"
                );
            }
        }
        let encoded =
            |bytes: &[u8]| format!("gigahost-account-seed-v1:{}", URL_SAFE_NO_PAD.encode(bytes));
        let refused = |given: &[u8]| parse_imported_seed(given).unwrap_err().to_string();
        assert_eq!(
            refused(encoded(&[7; 32]).replace("gigahost", "Gigahost").as_bytes()),
            "account key has an unsupported format"
        );
        assert_eq!(
            refused(format!("{}!", encoded(&[7; 32])).as_bytes()),
            "account key is not valid unpadded base64url"
        );
        for length in [31, 33] {
            assert_eq!(
                refused(encoded(&vec![7; length]).as_bytes()),
                "account key must encode exactly 32 bytes"
            );
        }
        for empty in [&b""[..], b" \r\n"] {
            assert_eq!(refused(empty), "no account key was given");
        }
        let mut long = encoded(&[7; 32]).into_bytes();
        long.resize(MAXIMUM_SEED_FILE_BYTES + 1, b' ');
        assert!(refused(&long).contains("longer than an account key"));
        long.truncate(MAXIMUM_SEED_FILE_BYTES);
        assert_eq!(*parse_imported_seed(&long).unwrap(), [7; 32]);
        // A seed file's words are the same through `load_seed`.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("account.seed");
        write_private(&path, format!("{}!", encoded(&[7; 32])).as_bytes());
        assert_eq!(
            load_seed(&path).unwrap_err().to_string(),
            "account key is not valid unpadded base64url"
        );
    }

    /// The bounded reader stops at a line feed for a terminal's line, and
    /// at one byte past the bound otherwise.
    #[test]
    fn key_input_is_read_within_its_bound() {
        let mut given: &[u8] = b"first\nsecond\n";
        let read = read_bounded(|buffer| given.read(buffer), true).unwrap();
        assert_eq!(read.as_slice(), b"first\nsecond\n");
        let mut chunks = [&b"first\n"[..], b"second\n"].into_iter();
        let read = read_bounded(
            |buffer| {
                let chunk = chunks.next().unwrap_or_default();
                buffer[..chunk.len()].copy_from_slice(chunk);
                Ok(chunk.len())
            },
            true,
        )
        .unwrap();
        assert_eq!(read.as_slice(), b"first\n");
        let long = vec![b'a'; 4096];
        let mut given = long.as_slice();
        let read = read_bounded(|buffer| given.read(buffer), false).unwrap();
        assert_eq!(read.len(), MAXIMUM_SEED_FILE_BYTES + 1);
    }

    fn mode(path: &Path) -> u32 {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::symlink_metadata(path).unwrap().permissions().mode() & 0o777
        }
        #[cfg(not(unix))]
        {
            let _ = path;
            0o600
        }
    }

    fn names(directory: &Path) -> Vec<String> {
        let mut names = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        names.sort();
        names
    }

    fn seed_text(seed: &[u8; 32]) -> String {
        format!(
            "gigahost-account-seed-v1:{}\n",
            URL_SAFE_NO_PAD.encode(seed)
        )
    }

    #[test]
    fn an_imported_key_is_written_as_generated_ones_are() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join("config")
            .join("ghost")
            .join("account.seed");
        assert_eq!(
            import_seed(&path, &[7; 32], false).unwrap(),
            ImportOutcome::Imported
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), seed_text(&[7; 32]));
        assert_eq!(mode(&path), 0o600);
        #[cfg(unix)]
        for created in [
            directory.path().join("config"),
            path.parent().unwrap().to_owned(),
        ] {
            assert_eq!(mode(&created), 0o700, "{}", created.display());
        }
        assert_eq!(names(path.parent().unwrap()), ["account.seed"]);
        // The website's keys, from the shared vectors, inspect to the
        // vectors' identities.
        let file: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        for entry in file["vectors"].as_array().unwrap() {
            let destination = directory
                .path()
                .join(format!("{}.seed", entry["name"].as_str().unwrap()));
            let seed =
                parse_imported_seed(entry["seed_file"].as_str().unwrap().as_bytes()).unwrap();
            import_seed(&destination, &seed, false).unwrap();
            let summary = key_summary(&load_seed(&destination).unwrap()).unwrap();
            assert_eq!(
                summary.authentication_key_id,
                entry["authentication_key_id"]
            );
            assert_eq!(summary.deposit_memo, entry["deposit_memo"]);
            assert_eq!(
                summary.billing_verifying_key,
                entry["billing_public_key_b64url"]
            );
            assert_eq!(
                summary.recovery_public_key,
                entry["recovery_public_key_b64url"]
            );
            assert_eq!(
                summary.recovery_key_fingerprint,
                entry["recovery_key_fingerprint_b64url"]
            );
        }
    }

    #[test]
    fn an_existing_seed_is_never_overwritten_silently() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("account.seed");
        import_seed(&path, &[7; 32], false).unwrap();
        let before = fs::metadata(&path).unwrap();
        assert_eq!(
            import_seed(&path, &[7; 32], false).unwrap(),
            ImportOutcome::AlreadyImported
        );
        assert_eq!(
            import_seed(&path, &[7; 32], true).unwrap(),
            ImportOutcome::AlreadyImported
        );
        let after = fs::metadata(&path).unwrap();
        assert_eq!(after.modified().unwrap(), before.modified().unwrap());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            assert_eq!(after.ino(), before.ino());
        }
        let error = import_seed(&path, &[8; 32], false).unwrap_err();
        let refusal = error.downcast_ref::<crate::Refusal>().unwrap();
        assert_eq!(refusal.code, ACCOUNT_KEY_EXISTS);
        assert!(
            refusal.message.contains("holds a different account key"),
            "{error:#}"
        );
        assert!(refusal.message.contains("--replace"), "{error:#}");
        assert!(
            refusal.message.contains("account.seed.replaced-"),
            "{error:#}"
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), seed_text(&[7; 32]));
        assert_eq!(names(directory.path()), ["account.seed"]);
    }

    #[test]
    fn a_replaced_seed_is_kept_beside_the_new_one() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("account.seed");
        import_seed(&path, &[7; 32], false).unwrap();
        let ImportOutcome::Replaced { previous } = import_seed(&path, &[8; 32], true).unwrap()
        else {
            panic!("the seed was replaced");
        };
        assert_eq!(fs::read_to_string(&path).unwrap(), seed_text(&[8; 32]));
        assert_eq!(fs::read_to_string(&previous).unwrap(), seed_text(&[7; 32]));
        assert_eq!(previous.parent().unwrap(), directory.path());
        let name = previous.file_name().unwrap().to_str().unwrap().to_owned();
        let time = name.strip_prefix("account.seed.replaced-").unwrap();
        assert_eq!(time.len(), "20261019T120000Z".len(), "{name}");
        assert!(time.ends_with('Z'), "{name}");
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&previous), 0o600);
        // A second replacement in the same second takes the next name.
        let ImportOutcome::Replaced { previous: second } =
            import_seed(&path, &[9; 32], true).unwrap()
        else {
            panic!("the seed was replaced");
        };
        assert_eq!(fs::read_to_string(&second).unwrap(), seed_text(&[8; 32]));
        assert_eq!(fs::read_to_string(&previous).unwrap(), seed_text(&[7; 32]));
        let names = names(directory.path());
        assert_eq!(names.len(), 3, "no temporary file is left: {names:?}");
        assert_ne!(second, previous);
    }

    #[test]
    fn the_kept_name_takes_the_next_free_suffix() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("account.seed");
        import_seed(&path, &[7; 32], false).unwrap();
        let suffix = ".replaced-20261019T120000Z";
        assert_eq!(
            kept_name(&path, suffix, 1),
            directory
                .path()
                .join("account.seed.replaced-20261019T120000Z")
        );
        assert_eq!(
            kept_name(&path, suffix, 3),
            directory
                .path()
                .join("account.seed.replaced-20261019T120000Z-3")
        );
        // The first free name is taken; when all are, nothing is kept.
        for attempt in 1..KEPT_NAME_ATTEMPTS {
            write_private(&kept_name(&path, suffix, attempt), b"taken");
        }
        let name = std::ffi::OsStr::new("account.seed");
        assert_eq!(
            keep_previous(&path, directory.path(), name, suffix).unwrap(),
            kept_name(&path, suffix, KEPT_NAME_ATTEMPTS)
        );
        let error = keep_previous(&path, directory.path(), name, suffix).unwrap_err();
        assert!(
            format!("{error:#}").contains("names are taken"),
            "{error:#}"
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), seed_text(&[7; 32]));
        assert_eq!(
            fs::read_to_string(kept_name(&path, suffix, KEPT_NAME_ATTEMPTS)).unwrap(),
            seed_text(&[7; 32])
        );
    }

    /// A seed file `load_seed` refuses is refused with its reason, and only
    /// `--replace` replaces it; a link or a directory never is.
    #[cfg(unix)]
    #[test]
    fn an_unreadable_seed_is_replaced_only_when_asked() {
        use std::os::unix::fs::{PermissionsExt as _, symlink};

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("account.seed");
        import_seed(&path, &[7; 32], false).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let error = import_seed(&path, &[7; 32], false).unwrap_err();
        assert_eq!(
            error.downcast_ref::<crate::Refusal>().unwrap().code,
            ACCOUNT_KEY_EXISTS
        );
        assert!(format!("{error:#}").contains("chmod 600"), "{error:#}");
        assert_eq!(mode(&path), 0o644);
        let ImportOutcome::Replaced { previous } = import_seed(&path, &[7; 32], true).unwrap()
        else {
            panic!("the seed was replaced");
        };
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(&previous), 0o600);

        let target = directory.path().join("target.seed");
        let link = directory.path().join("linked.seed");
        import_seed(&target, &[7; 32], false).unwrap();
        symlink(&target, &link).unwrap();
        for replace in [false, true] {
            let error = import_seed(&link, &[8; 32], replace).unwrap_err();
            assert!(format!("{error:#}").contains("symbolic link"), "{error:#}");
            assert!(
                fs::symlink_metadata(&link)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(fs::read_to_string(&target).unwrap(), seed_text(&[7; 32]));
        }
        let folder = directory.path().join("folder.seed");
        fs::create_dir(&folder).unwrap();
        for replace in [false, true] {
            let error = import_seed(&folder, &[8; 32], replace).unwrap_err();
            assert!(
                format!("{error:#}").contains("not a regular file"),
                "{error:#}"
            );
            assert!(folder.is_dir());
        }
        let names = names(directory.path());
        assert!(
            names.iter().all(|name| !name.starts_with('.')),
            "no temporary file is left: {names:?}"
        );
        assert_eq!(names.len(), 5, "{names:?}");
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        let _ = fs::remove_file(path);
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        options.open(path).unwrap().write_all(bytes).unwrap();
    }

    /// The account key vectors every client reproduces byte for byte.
    const VECTORS: &str = include_str!("../crates/client-api/fixtures/account-seed-vectors.json");

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
    }

    /// One vector: the seed file's text, the three materials, the public
    /// keys, their fingerprints, the key ID and deposit memo, and one
    /// request signed with the authentication key, all computed here.
    fn vector(name: &str, seed: [u8; 32], request: &VectorRequest) -> serde_json::Value {
        use ghostrack_client_api::account_auth::{RequestSignatureInput, canonical_request};

        let authentication_material = derive_material(&seed, AUTHENTICATION_KEY_LABEL).unwrap();
        let billing_material = derive_material(&seed, BILLING_KEY_LABEL).unwrap();
        let recovery_material = derive_material(&seed, RECOVERY_KEY_LABEL).unwrap();
        let authentication = authentication_identity(&seed).unwrap();
        let billing = SigningKey::from_bytes(&billing_material)
            .verifying_key()
            .to_bytes();
        let recovery = recovery_key_pair(&seed).unwrap();
        let summary = key_summary(&seed).unwrap();
        assert_eq!(summary.authentication_key_id, authentication.key_id);
        assert_eq!(
            summary.billing_verifying_key,
            URL_SAFE_NO_PAD.encode(billing)
        );
        let nonce: Uuid = request.nonce.parse().unwrap();
        let canonical = canonical_request(&RequestSignatureInput {
            auth_key_id: &authentication.key_id,
            timestamp_unix_ms: request.timestamp_unix_ms,
            nonce,
            method: request.method,
            target: request.target,
            body: request.body.as_bytes(),
            idempotency_key: request.idempotency_key,
        });
        let signature = authentication.sign(&canonical);
        // The verifier the backend runs accepts it.
        ed25519_dalek::VerifyingKey::from_bytes(&authentication.public_key)
            .unwrap()
            .verify_strict(&canonical, &signature)
            .unwrap();
        let fingerprint = |key: &[u8]| URL_SAFE_NO_PAD.encode(Sha256::digest(key));
        serde_json::json!({
            "name": name,
            "seed_hex": hex(&seed),
            "seed_file": format!(
                "{}{}\n",
                std::str::from_utf8(SEED_PREFIX).unwrap(),
                URL_SAFE_NO_PAD.encode(seed)
            ),
            "authentication_material_hex": hex(authentication_material.as_ref()),
            "billing_material_hex": hex(billing_material.as_ref()),
            "recovery_material_hex": hex(recovery_material.as_ref()),
            "authentication_public_key_b64url": URL_SAFE_NO_PAD.encode(authentication.public_key),
            "billing_public_key_b64url": URL_SAFE_NO_PAD.encode(billing),
            "recovery_private_key_hex": hex(&recovery.private_key.to_bytes()),
            "recovery_public_key_b64url": URL_SAFE_NO_PAD.encode(recovery.public_key),
            "authentication_key_fingerprint_b64url": fingerprint(&authentication.public_key),
            "billing_key_fingerprint_b64url": summary.billing_key_fingerprint,
            "recovery_key_fingerprint_b64url": summary.recovery_key_fingerprint,
            "authentication_key_id": authentication.key_id,
            "deposit_memo": authentication.deposit_memo,
            "request": {
                "method": request.method,
                "target": request.target,
                "body": request.body,
                "timestamp_unix_ms": request.timestamp_unix_ms,
                "nonce": request.nonce,
                "idempotency_key": request.idempotency_key,
                "canonical": String::from_utf8(canonical).unwrap(),
                "signature_b64url": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            },
        })
    }

    struct VectorRequest {
        method: &'static str,
        target: &'static str,
        body: &'static str,
        timestamp_unix_ms: i64,
        nonce: &'static str,
        idempotency_key: Option<&'static str>,
    }

    /// Every vector of the file, computed from this module and the
    /// shared signing primitives.
    fn vectors() -> serde_json::Value {
        let random: [u8; 32] = Sha256::digest(b"gigahost account seed vector 3").into();
        serde_json::json!({
            "description": "Fixed vectors of the account key (src/keys.rs): the seed file's text, the HKDF-SHA-256 materials, the Ed25519 and X25519 (RFC 9180 DeriveKeyPair) keys, their SHA-256 fingerprints, the key ID, the deposit memo and a request signed with the authentication key. Every client that reads an account key or signs a request reproduces them byte for byte. Regenerate with `cargo test -p ghost -- --ignored write_account_seed_vectors`.",
            "vectors": [
                vector("zero", [0; 32], &VectorRequest {
                    method: "POST",
                    target: "/api/mut/v1/account/activate",
                    body: "{\"terms_accepted\":true}",
                    timestamp_unix_ms: 1_767_225_600_000,
                    nonce: "019b7cb4-6800-7000-8000-000000000001",
                    idempotency_key: None,
                }),
                vector("sevens", [7; 32], &VectorRequest {
                    method: "POST",
                    target: "/api/mut/v1/account/login",
                    body: "",
                    timestamp_unix_ms: 1_767_225_600_001,
                    nonce: "019b7cb4-6801-7abc-9def-0123456789ab",
                    idempotency_key: None,
                }),
                vector("random", random, &VectorRequest {
                    method: "PUT",
                    target: "/api/mut/v1/provider/payout-address",
                    body: "{\"address\":\"xch1example\"}",
                    timestamp_unix_ms: 1_767_225_600_002,
                    nonce: "019b7cb4-6802-7fff-bfff-ffffffffffff",
                    idempotency_key: Some("browser-0123456789abcdef"),
                }),
            ],
        })
    }

    #[test]
    fn the_account_seed_vectors_are_what_this_code_computes() {
        let file: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        assert_eq!(
            file,
            vectors(),
            "regenerate with `cargo test -p ghost -- --ignored write_account_seed_vectors`"
        );
        // The seed file's text loads as its seed.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("account.seed");
        for entry in file["vectors"].as_array().unwrap() {
            write_private(&path, entry["seed_file"].as_str().unwrap().as_bytes());
            assert_eq!(
                hex(load_seed(&path).unwrap().as_ref()),
                entry["seed_hex"].as_str().unwrap()
            );
        }
    }

    #[test]
    #[ignore = "writes crates/client-api/fixtures/account-seed-vectors.json"]
    fn write_account_seed_vectors() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("crates/client-api/fixtures/account-seed-vectors.json");
        let mut text = serde_json::to_string_pretty(&vectors()).unwrap();
        text.push('\n');
        fs::write(path, text).unwrap();
    }

    #[test]
    fn backup_key_is_opened_and_rewrapped_to_the_destination() {
        let instance_id = Uuid::now_v7();
        let destination_instance_id = Uuid::now_v7();
        let backup_id = Uuid::now_v7();
        let restore_job_id = Uuid::now_v7();
        let recovery = recovery_key_pair(&[19_u8; 32]).unwrap();
        let recipient =
            <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(&recovery.public_key).unwrap();
        let data_key = [23_u8; 32];
        let (source_encapsulation, source_ciphertext) =
            single_shot_seal::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
                &OpModeS::Base,
                &recipient,
                b"GIGAHOST-BACKUP-DATA-KEY-V1",
                &data_key,
                &backup_wrap_aad(instance_id, backup_id, &recovery.fingerprint),
            )
            .unwrap();
        let mut source_envelope = source_encapsulation.to_bytes().to_vec();
        source_envelope.extend_from_slice(&source_ciphertext);

        let (destination_secret, destination_public) = X25519HkdfSha256::gen_keypair();
        let destination_public: [u8; 32] =
            destination_public.to_bytes().as_slice().try_into().unwrap();
        let destination_fingerprint: [u8; 32] = Sha256::digest(destination_public).into();
        let rewrapped = rewrap_backup_data_key(
            &recovery,
            &BackupRewrapTarget {
                source_instance_id: instance_id,
                destination_instance_id,
                backup_id,
                restore_job_id,
                destination_public_key: &URL_SAFE_NO_PAD.encode(destination_public),
                destination_key_fingerprint: &URL_SAFE_NO_PAD.encode(destination_fingerprint),
            },
            &URL_SAFE_NO_PAD.encode(source_envelope),
        )
        .unwrap();
        let rewrapped = URL_SAFE_NO_PAD.decode(rewrapped).unwrap();
        let encapsulated =
            <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&rewrapped[..32]).unwrap();
        let opened = single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            &destination_secret,
            &encapsulated,
            b"GIGAHOST-RESTORE-DATA-KEY-V1",
            &rewrapped[32..],
            &restore_wrap_aad(
                destination_instance_id,
                backup_id,
                restore_job_id,
                &destination_fingerprint,
            ),
        )
        .unwrap();
        assert_eq!(opened, data_key);
    }

    /// Randomness that hands out its 32 bytes once: the ephemeral key's
    /// input keying material of one HPKE seal (`gen_keypair_with_rng` reads
    /// that much and derives the key pair from it, RFC 9180's
    /// `DeriveKeyPair`), so the seal is fixed.
    struct Once(Option<[u8; 32]>);

    impl hpke::rand_core::TryRng for Once {
        type Error = std::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            unreachable!("a seal asks for the ephemeral key's bytes only")
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            unreachable!("a seal asks for the ephemeral key's bytes only")
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            dst.copy_from_slice(&self.0.take().expect("one seal"));
            Ok(())
        }
    }

    impl hpke::rand_core::TryCryptoRng for Once {}

    fn digest(label: &str) -> [u8; 32] {
        Sha256::digest(label.as_bytes()).into()
    }

    fn id(text: &str) -> Uuid {
        text.parse().unwrap()
    }

    /// Hosted restore vectors: the billing authorization of the `sevens`
    /// account vector, its message and signature, the approval request bodies,
    /// and a key rewrap with fixed IDs and fixed randomness.
    fn backup_key_vectors() -> serde_json::Value {
        use ghostrack_client_api::{
            account_auth::{
                BackupBillingAuthorizationInput, canonical_backup_billing_authorization,
            },
            website::{
                BillingAuthorization, CreateInstanceRequest, GatewayTier, InstanceSource,
                RestoreBackupRequest, backup_byte_charge,
            },
        };

        let seed = [7_u8; 32];
        let source_instance_id = id("019b7cb4-6800-7000-8000-0000000000a1");
        let backup_id = id("019b7cb4-6800-7000-8000-0000000000a2");
        let destination_instance_id = id("019b7cb4-6800-7000-8000-0000000000a3");
        let restore_job_id = id("019b7cb4-6800-7000-8000-0000000000a4");
        let intent_id = id("019b7cb4-6800-7000-8000-0000000000a5");
        let size_bytes = 11_811_160_064_u64;
        let restore_charge_microusd_per_gib = 2000;
        let pricing_revision = 3;
        let (_, maximum_charge_microusd) =
            backup_byte_charge(size_bytes, restore_charge_microusd_per_gib).unwrap();
        let idempotency_key = format!("browser-intent-{intent_id}");
        let message = canonical_backup_billing_authorization(&BackupBillingAuthorizationInput {
            operation: "restore_backup",
            instance_id: source_instance_id,
            backup_id: Some(backup_id),
            destination: "gigahost_s3",
            pricing_revision,
            maximum_charge_microusd,
            idempotency_key: &idempotency_key,
        });
        let signature = sign_billing_authorization(&seed, &message).unwrap();
        let billing_public =
            SigningKey::from_bytes(&derive_material(&seed, BILLING_KEY_LABEL).unwrap())
                .verifying_key();
        billing_public.verify_strict(&message, &signature).unwrap();
        let authorization = BillingAuthorization {
            pricing_revision,
            maximum_charge_microusd,
            signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
        };
        let restore_body = serde_json::to_string(&RestoreBackupRequest {
            billing_authorization: Some(authorization.clone()),
            accepted_charge: None,
        })
        .unwrap();
        // As `ghost account approve` makes it from a `create_from_backup`
        // request: no SSH keys, cloud-init, name or startup command.
        let create_body = serde_json::to_string(&CreateInstanceRequest {
            offering_id: "of2_F95QS_EuMsVz4IG5EulOew".to_owned(),
            source: Some(InstanceSource::Backup {
                backup_id,
                billing_authorization: Some(authorization),
                accepted_charge: None,
            }),
            container: None,
            gateway_tier: Some(GatewayTier::SharedIp),
            gateway_location: None,
            ssh_public_keys: Vec::new(),
            cloud_init: None,
            hostname: Some("old-api".to_owned()),
            name: None,
            startup_command: None,
            ssh_key_ids: None,
            tags: None,
        })
        .unwrap();

        let recovery = recovery_key_pair(&seed).unwrap();
        let data_key = digest("gigahost backup data key vector");
        let source_ikm = digest("gigahost backup wrap ephemeral vector");
        let source_aad = backup_wrap_aad(source_instance_id, backup_id, &recovery.fingerprint);
        let recipient =
            <X25519HkdfSha256 as hpke::Kem>::PublicKey::from_bytes(&recovery.public_key).unwrap();
        let (source_encapsulation, source_ciphertext) =
            hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
                &OpModeS::Base,
                &recipient,
                BACKUP_DATA_KEY_INFO,
                &data_key,
                &source_aad,
                &mut Once(Some(source_ikm)),
            )
            .unwrap();
        let mut wrapped = source_encapsulation.to_bytes().to_vec();
        wrapped.extend_from_slice(&source_ciphertext);
        let wrapped = URL_SAFE_NO_PAD.encode(wrapped);

        let destination_ikm = digest("gigahost restore destination key vector");
        let (destination_secret, destination_public) =
            X25519HkdfSha256::derive_keypair(&destination_ikm);
        let destination_public = destination_public.to_bytes();
        let destination_fingerprint: [u8; 32] = Sha256::digest(destination_public).into();
        let ephemeral_ikm = digest("gigahost restore wrap ephemeral vector");
        let target = BackupRewrapTarget {
            source_instance_id,
            destination_instance_id,
            backup_id,
            restore_job_id,
            destination_public_key: &URL_SAFE_NO_PAD.encode(destination_public),
            destination_key_fingerprint: &URL_SAFE_NO_PAD.encode(destination_fingerprint),
        };
        let mut ephemeral = Once(Some(ephemeral_ikm));
        let envelope = rewrap_with(
            &recovery,
            &target,
            &wrapped,
            |destination, aad, data_key| {
                hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
                    &OpModeS::Base,
                    destination,
                    RESTORE_DATA_KEY_INFO,
                    data_key,
                    aad,
                    &mut ephemeral,
                )
            },
        )
        .unwrap();
        let restore_aad = restore_wrap_aad(
            destination_instance_id,
            backup_id,
            restore_job_id,
            &destination_fingerprint,
        );
        // The destination opens it, and a rewrap with the system's
        // randomness differs but opens to the same key.
        let open = |envelope: &str| {
            let bytes = URL_SAFE_NO_PAD.decode(envelope).unwrap();
            single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
                &OpModeR::Base,
                &destination_secret,
                &<X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&bytes[..32]).unwrap(),
                RESTORE_DATA_KEY_INFO,
                &bytes[32..],
                &restore_aad,
            )
            .unwrap()
        };
        assert_eq!(open(&envelope), data_key);
        let random = rewrap_backup_data_key(&recovery, &target, &wrapped).unwrap();
        assert_ne!(random, envelope);
        assert_eq!(open(&random), data_key);

        serde_json::json!({
            "description": "Fixed vectors of a hosted backup's restore (src/keys.rs): the billing authorization the account key of the vector sevens of account-seed-vectors.json signs for it, with the bodies `ghost account approve` sends it in, and one rewrap of the backup's data key from the account's recovery key to a restore's destination, HPKE base mode with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and ChaCha20-Poly1305, its ephemeral keys derived from the fixed input keying material given (RFC 9180 DeriveKeyPair). Every client that approves a hosted restore reproduces them byte for byte. Regenerate with `cargo test -p ghost -- --ignored write_backup_key_vectors`.",
            "seed_hex": hex(&seed),
            "billing": {
                "operation": "restore_backup",
                "instance_id": source_instance_id,
                "backup_id": backup_id,
                "destination": "gigahost_s3",
                "size_bytes": size_bytes,
                "restore_charge_microusd_per_gib": restore_charge_microusd_per_gib,
                "pricing_revision": pricing_revision,
                "maximum_charge_microusd": maximum_charge_microusd,
                "idempotency_key": idempotency_key,
                "message": String::from_utf8(message).unwrap(),
                "billing_public_key_b64url": URL_SAFE_NO_PAD.encode(billing_public.to_bytes()),
                "signature_b64url": URL_SAFE_NO_PAD.encode(signature.to_bytes()),
                "restore_body": restore_body,
                "create_body": create_body,
            },
            "rewrap": {
                "source_instance_id": source_instance_id,
                "backup_id": backup_id,
                "destination_instance_id": destination_instance_id,
                "restore_job_id": restore_job_id,
                "recovery_public_key_b64url": URL_SAFE_NO_PAD.encode(recovery.public_key),
                "recovery_key_fingerprint_b64url": URL_SAFE_NO_PAD.encode(recovery.fingerprint),
                "data_key_hex": hex(&data_key),
                "source_ephemeral_ikm_hex": hex(&source_ikm),
                "source_aad_hex": hex(&source_aad),
                "wrapped_data_key_b64url": wrapped,
                "destination_ikm_hex": hex(&destination_ikm),
                "destination_private_key_hex": hex(&destination_secret.to_bytes()),
                "destination_public_key_b64url": URL_SAFE_NO_PAD.encode(destination_public),
                "destination_key_fingerprint_b64url": URL_SAFE_NO_PAD.encode(destination_fingerprint),
                "ephemeral_ikm_hex": hex(&ephemeral_ikm),
                "restore_aad_hex": hex(&restore_aad),
                "envelope_b64url": envelope,
            },
        })
    }

    const BACKUP_KEY_VECTORS: &str =
        include_str!("../crates/client-api/fixtures/backup-key-vectors.json");

    #[test]
    fn the_backup_key_vectors_are_what_this_code_computes() {
        let file: serde_json::Value = serde_json::from_str(BACKUP_KEY_VECTORS).unwrap();
        assert_eq!(
            file,
            backup_key_vectors(),
            "regenerate with `cargo test -p ghost -- --ignored write_backup_key_vectors`"
        );
        // The vectors' account key is the account key vectors' `sevens`.
        let seeds: serde_json::Value = serde_json::from_str(VECTORS).unwrap();
        let sevens = seeds["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|vector| vector["name"] == "sevens")
            .unwrap();
        assert_eq!(file["seed_hex"], sevens["seed_hex"]);
        assert_eq!(
            file["billing"]["billing_public_key_b64url"],
            sevens["billing_public_key_b64url"]
        );
        assert_eq!(
            file["rewrap"]["recovery_key_fingerprint_b64url"],
            sevens["recovery_key_fingerprint_b64url"]
        );
    }

    #[test]
    #[ignore = "writes crates/client-api/fixtures/backup-key-vectors.json"]
    fn write_backup_key_vectors() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("crates/client-api/fixtures/backup-key-vectors.json");
        let mut text = serde_json::to_string_pretty(&backup_key_vectors()).unwrap();
        text.push('\n');
        fs::write(path, text).unwrap();
    }
}
