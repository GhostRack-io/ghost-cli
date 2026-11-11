//! The encrypted container of a backup, as a restore reads it.
//!
//! A container is a header (the magic, the backup's ID, the disk's size,
//! the chunk size, the recipient key's fingerprint, the nonce prefix and
//! the wrapped data key), one record per 4 MiB chunk of the disk
//! (XChaCha20-Poly1305 under the data key, zstd-compressed when that is
//! smaller; in version 2 a chunk of zeros carries no payload), an encrypted
//! manifest of the records and a footer. [`decode_stream`] authenticates
//! every record and the manifest as it writes the disk.
//!
//! The data key is wrapped with HPKE (X25519, HKDF-SHA256, ChaCha20-Poly1305)
//! to the account's recovery key, which only the account's seed holds
//! ([`open_data_key`]), and a restore's copy to its destination host's key
//! ([`unwrap_job_data_key`]).
//!
//! The encoder is the host's; the items it shares with the decoder are
//! public here so the two cannot drift apart.

use std::{
    fs::File,
    io::{Read, Seek as _, SeekFrom, Write as _},
    sync::OnceLock,
};

use anyhow::{Context, Result, bail};
use chacha20poly1305::{
    KeyInit as _, XChaCha20Poly1305, XNonce,
    aead::{Aead as _, Payload},
};
use hpke::{
    Deserializable as _, OpModeR, aead::ChaCha20Poly1305 as HpkeChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256, single_shot_open,
};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Version 1 hashes every plaintext byte twice and stores zero chunks like
/// data. It is still restored, but no longer written.
pub const MAGIC_V1: &[u8; 8] = b"GHBKP001";
pub const MAGIC_V2: &[u8; 8] = b"GHBKP002";
pub const MANIFEST_MAGIC: &[u8; 8] = b"GHMNF001";
pub const FOOTER_MAGIC: &[u8; 8] = b"GHBEND01";
pub const FLAG_ZSTD: u8 = 1;
/// An all-zero chunk (version 2): no payload, only the authentication tag of
/// an empty message, whose associated data binds the chunk's index, length
/// and this flag.
pub const FLAG_ZERO: u8 = 2;
/// Version 2's plaintext digest is SHA-256 over this prefix and then each
/// chunk's big-endian index and length and its SHA-256, so each plaintext
/// byte is hashed once and a zero chunk not at all.
pub const PLAINTEXT_DIGEST_V2_PREFIX: &[u8] = b"GHBKP-PLAINTEXT-V2\0";
pub const HEADER_FIXED_BYTES: usize = 8 + 16 + 8 + 8 + 32 + 16 + 2;
/// The plaintext size of every chunk but the last.
pub const CHUNK_BYTES: usize = 4 * 1024 * 1024;
/// [`CHUNK_BYTES`] as the header records it.
pub const PLAINTEXT_CHUNK_BYTES: u64 = CHUNK_BYTES as u64;
/// A wrapped data key: the 32-byte HPKE encapsulation, then the sealed
/// 32-byte key and its 16-byte tag.
pub const WRAPPED_DATA_KEY_BYTES: usize = 80;
/// The HPKE info of a backup's data key wrapped to the recovery key.
pub const BACKUP_DATA_KEY_INFO: &[u8] = b"GIGAHOST-BACKUP-DATA-KEY-V1";
/// The HPKE info of the same key rewrapped to a restore's destination.
pub const RESTORE_DATA_KEY_INFO: &[u8] = b"GIGAHOST-RESTORE-DATA-KEY-V1";
/// The plaintext of a zero chunk.
static ZERO_CHUNK: [u8; CHUNK_BYTES] = [0; CHUNK_BYTES];

/// Where a restore writes the disk it decodes, from the disk's first byte
/// on and in order.
pub trait RestoreWrite {
    /// Write the next `bytes` of the disk.
    ///
    /// # Errors
    ///
    /// The destination's.
    fn write_data(&mut self, bytes: &[u8]) -> std::io::Result<()>;
    /// The next `len` bytes of the disk are zero. A destination that reads
    /// zeros there already moves past them without writing.
    ///
    /// # Errors
    ///
    /// The destination's.
    fn write_zeroes(&mut self, len: u64) -> std::io::Result<()>;
}

/// A disk in memory takes zeros as bytes.
impl RestoreWrite for Vec<u8> {
    fn write_data(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.extend_from_slice(bytes);
        Ok(())
    }

    fn write_zeroes(&mut self, len: u64) -> std::io::Result<()> {
        let len = usize::try_from(len).map_err(std::io::Error::other)?;
        self.resize(self.len() + len, 0);
        Ok(())
    }
}

/// Decodes and verifies a container without keeping its disk.
impl RestoreWrite for std::io::Sink {
    fn write_data(&mut self, _: &[u8]) -> std::io::Result<()> {
        Ok(())
    }

    fn write_zeroes(&mut self, _: u64) -> std::io::Result<()> {
        Ok(())
    }
}

/// The plaintext digest a restore checked against the backup's manifest, and
/// its format: 1 is the SHA-256 of the whole disk, 2 the chunk-list digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PlaintextDigest {
    pub sha256: [u8; 32],
    pub format: u8,
}

/// What the restore expects of a container: the backup it is, the size of
/// its disk, the recipient key it is wrapped to and the opened data key.
pub struct StreamRestoreInput<'a> {
    pub instance_id: Uuid,
    pub backup_id: Uuid,
    pub disk_bytes: u64,
    pub recipient_key_fingerprint: &'a [u8; 32],
    pub data_key: &'a [u8; 32],
}

/// The manifest, encrypted after the records.
#[derive(serde::Deserialize, serde::Serialize)]
pub struct EncryptedManifest {
    pub format_version: u8,
    pub backup_id: Uuid,
    pub instance_id: Uuid,
    pub plaintext_size_bytes: u64,
    pub plaintext_sha256: [u8; 32],
    pub chunks: Vec<ManifestChunk>,
}

/// One record as the manifest lists it.
#[derive(Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct ManifestChunk {
    pub index: u32,
    pub virtual_offset: u64,
    pub plaintext_len: u32,
    pub encoded_len: u32,
    pub compression: u8,
    pub plaintext_sha256: [u8; 32],
}

/// Version 2's plaintext digest, fed each chunk's digest in stream order.
pub struct ChunkListDigest(Sha256);

impl Default for ChunkListDigest {
    fn default() -> Self {
        Self::new()
    }
}

impl ChunkListDigest {
    pub fn new() -> Self {
        let mut digest = Sha256::new();
        digest.update(PLAINTEXT_DIGEST_V2_PREFIX);
        Self(digest)
    }

    pub fn update(&mut self, index: u32, plaintext_len: u32, chunk_sha256: &[u8; 32]) {
        self.0.update(index.to_be_bytes());
        self.0.update(plaintext_len.to_be_bytes());
        self.0.update(chunk_sha256);
    }

    pub fn finish(self) -> [u8; 32] {
        self.0.finalize().into()
    }
}

/// Whether a chunk holds only zeros, compared 16 bytes at a time.
///
/// # Panics
///
/// Never: every exact chunk of 16 bytes converts to a word.
pub fn is_zero(bytes: &[u8]) -> bool {
    let mut words = bytes.chunks_exact(16);
    words
        .by_ref()
        .all(|word| u128::from_ne_bytes(word.try_into().expect("a 16-byte word")) == 0)
        && words.remainder().iter().all(|byte| *byte == 0)
}

/// The SHA-256 of `len` zero bytes. Every chunk but the last is full size,
/// so that digest is computed once.
///
/// # Panics
///
/// When `len` exceeds [`CHUNK_BYTES`].
pub fn zero_chunk_sha256(len: usize) -> [u8; 32] {
    static FULL_CHUNK: OnceLock<[u8; 32]> = OnceLock::new();
    let digest = || Sha256::digest(&ZERO_CHUNK[..len]).into();
    if len == CHUNK_BYTES {
        *FULL_CHUNK.get_or_init(digest)
    } else {
        digest()
    }
}

/// Decode an encrypted container from a sequential reader directly into the
/// restored disk, so restoring a backup never requires an intermediate raw
/// volume. Zero chunks, and chunks of an older container that hold only
/// zeros, reach the destination as zero ranges.
///
/// Every record and the manifest are authenticated, and the manifest must
/// list exactly the records read; the destination has the whole disk only
/// once this returns `Ok`.
///
/// # Errors
///
/// A container that is not the one `input` describes, a record or manifest
/// that does not authenticate or match, and the reader's or destination's
/// failures.
pub fn decode_stream(
    source: &mut impl Read,
    destination: &mut impl RestoreWrite,
    input: &StreamRestoreInput<'_>,
) -> Result<PlaintextDigest> {
    let magic = read_array::<8>(source, "backup magic")?;
    let format_version = match &magic {
        MAGIC_V1 => 1,
        MAGIC_V2 => 2,
        _ => bail!("encrypted backup has an unsupported container magic"),
    };
    let encoded_backup_id = Uuid::from_bytes(read_array::<16>(source, "backup ID")?);
    let encoded_disk_bytes = u64::from_be_bytes(read_array::<8>(source, "disk size")?);
    let chunk_bytes = u64::from_be_bytes(read_array::<8>(source, "chunk size")?);
    let encoded_fingerprint = read_array::<32>(source, "recipient fingerprint")?;
    let nonce_prefix = read_array::<16>(source, "nonce prefix")?;
    let wrapped_len = usize::from(u16::from_be_bytes(read_array::<2>(
        source,
        "wrapped-key length",
    )?));
    if encoded_backup_id != input.backup_id
        || encoded_disk_bytes != input.disk_bytes
        || chunk_bytes != PLAINTEXT_CHUNK_BYTES
        || encoded_fingerprint != *input.recipient_key_fingerprint
        || wrapped_len != WRAPPED_DATA_KEY_BYTES
    {
        bail!("encrypted backup header does not match the restore command");
    }
    let mut wrapped_data_key = vec![0_u8; wrapped_len];
    source.read_exact(&mut wrapped_data_key)?;
    let mut header = Vec::with_capacity(HEADER_FIXED_BYTES + wrapped_len);
    header.extend_from_slice(&magic);
    header.extend_from_slice(encoded_backup_id.as_bytes());
    header.extend_from_slice(&encoded_disk_bytes.to_be_bytes());
    header.extend_from_slice(&chunk_bytes.to_be_bytes());
    header.extend_from_slice(&encoded_fingerprint);
    header.extend_from_slice(&nonce_prefix);
    header.extend_from_slice(&u16::try_from(wrapped_len)?.to_be_bytes());
    header.extend_from_slice(&wrapped_data_key);
    let header_digest: [u8; 32] = Sha256::digest(&header).into();
    let cipher = XChaCha20Poly1305::new(input.data_key.into());
    let expected_chunks = u32::try_from(input.disk_bytes.div_ceil(PLAINTEXT_CHUNK_BYTES))
        .context("backup has too many chunks")?;
    // Version 1 hashes the whole plaintext stream, version 2 the chunk list.
    let mut stream_digest = Sha256::new();
    let mut chunk_list_digest = ChunkListDigest::new();
    let mut manifest_chunks = Vec::with_capacity(usize::try_from(expected_chunks)?);
    let mut virtual_offset = 0_u64;
    for expected_index in 0..expected_chunks {
        let index = u32::from_be_bytes(read_array::<4>(source, "chunk index")?);
        let plaintext_len = u32::from_be_bytes(read_array::<4>(source, "chunk plaintext length")?);
        let encoded_len = u32::from_be_bytes(read_array::<4>(source, "chunk encoded length")?);
        let flags = read_array::<1>(source, "chunk flags")?[0];
        let expected_plaintext_len = u32::try_from(
            input
                .disk_bytes
                .checked_sub(virtual_offset)
                .context("chunk offset exceeds disk size")?
                .min(PLAINTEXT_CHUNK_BYTES),
        )?;
        let valid_encoding = match flags {
            0 => encoded_len == plaintext_len,
            FLAG_ZSTD => encoded_len > 0 && encoded_len <= plaintext_len,
            FLAG_ZERO => format_version >= 2 && encoded_len == 0,
            _ => false,
        };
        if index != expected_index || plaintext_len != expected_plaintext_len || !valid_encoding {
            bail!("encrypted backup contains an invalid chunk descriptor");
        }
        let mut ciphertext = vec![0_u8; usize::try_from(encoded_len)? + 16];
        source.read_exact(&mut ciphertext)?;
        let aad = chunk_aad(&header_digest, index, plaintext_len, encoded_len, flags);
        let encoded = cipher
            .decrypt(
                XNonce::from_slice(&record_nonce(&nonce_prefix, u64::from(index))),
                Payload {
                    msg: &ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow::anyhow!("authenticate encrypted backup chunk"))?;
        let chunk_len = usize::try_from(plaintext_len)?;
        let chunk_digest = if flags == FLAG_ZERO {
            destination.write_zeroes(u64::from(plaintext_len))?;
            zero_chunk_sha256(chunk_len)
        } else {
            let plaintext = if flags == FLAG_ZSTD {
                zstd::bulk::decompress(&encoded, chunk_len).context("decompress backup chunk")?
            } else {
                encoded
            };
            if plaintext.len() != chunk_len {
                bail!("decompressed backup chunk has an invalid plaintext length");
            }
            if format_version == 1 {
                stream_digest.update(&plaintext);
            }
            if is_zero(&plaintext) {
                destination.write_zeroes(u64::from(plaintext_len))?;
            } else {
                destination.write_data(&plaintext)?;
            }
            Sha256::digest(&plaintext).into()
        };
        chunk_list_digest.update(index, plaintext_len, &chunk_digest);
        manifest_chunks.push(ManifestChunk {
            index,
            virtual_offset,
            plaintext_len,
            encoded_len,
            compression: flags,
            plaintext_sha256: chunk_digest,
        });
        virtual_offset = virtual_offset
            .checked_add(u64::from(plaintext_len))
            .context("restore virtual offset overflow")?;
    }
    if &read_array::<8>(source, "manifest magic")? != MANIFEST_MAGIC {
        bail!("encrypted backup manifest marker is missing");
    }
    let manifest_len = u32::from_be_bytes(read_array::<4>(source, "manifest length")?);
    let maximum_manifest = u64::from(expected_chunks)
        .checked_mul(256)
        .and_then(|value| value.checked_add(1024))
        .context("manifest size bound overflow")?;
    if u64::from(manifest_len) > maximum_manifest {
        bail!("encrypted backup manifest exceeds its structural bound");
    }
    let mut manifest_ciphertext = vec![0_u8; usize::try_from(manifest_len)? + 16];
    source.read_exact(&mut manifest_ciphertext)?;
    let mut manifest_aad = Vec::with_capacity(32 + MANIFEST_MAGIC.len() + 4);
    manifest_aad.extend_from_slice(&header_digest);
    manifest_aad.extend_from_slice(MANIFEST_MAGIC);
    manifest_aad.extend_from_slice(&manifest_len.to_be_bytes());
    let manifest = cipher
        .decrypt(
            XNonce::from_slice(&record_nonce(&nonce_prefix, u64::MAX)),
            Payload {
                msg: &manifest_ciphertext,
                aad: &manifest_aad,
            },
        )
        .map_err(|_| anyhow::anyhow!("authenticate encrypted backup manifest"))?;
    let manifest: EncryptedManifest =
        serde_json::from_slice(&manifest).context("decode encrypted backup manifest")?;
    let plaintext_sha256: [u8; 32] = if format_version == 1 {
        stream_digest.finalize().into()
    } else {
        chunk_list_digest.finish()
    };
    if manifest.format_version != format_version
        || manifest.backup_id != input.backup_id
        || manifest.instance_id != input.instance_id
        || manifest.plaintext_size_bytes != input.disk_bytes
        || manifest.plaintext_sha256 != plaintext_sha256
        || manifest.chunks != manifest_chunks
    {
        bail!("encrypted backup manifest does not match the restored artifact");
    }
    if &read_array::<8>(source, "footer magic")? != FOOTER_MAGIC
        || u32::from_be_bytes(read_array::<4>(source, "footer chunks")?) != expected_chunks
        || u64::from_be_bytes(read_array::<8>(source, "footer size")?) != input.disk_bytes
    {
        bail!("encrypted backup footer does not match the restored artifact");
    }
    Ok(PlaintextDigest {
        sha256: plaintext_sha256,
        format: format_version,
    })
}

/// Open a restore's data key: the backup's key rewrapped to the
/// destination host's key for one restore job.
///
/// # Errors
///
/// An envelope of the wrong size, an invalid key, and an envelope that does
/// not open for this job.
pub fn unwrap_job_data_key(
    instance_id: Uuid,
    backup_id: Uuid,
    restore_job_id: Uuid,
    destination_key_fingerprint: &[u8; 32],
    destination_wrapped_data_key: &[u8],
    destination_secret_key: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    if destination_wrapped_data_key.len() != WRAPPED_DATA_KEY_BYTES {
        bail!("restore data-key envelope must be exactly 80 bytes");
    }
    let private_key =
        <X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(destination_secret_key)
            .context("restore destination private key is invalid")?;
    let encapsulated = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(
        &destination_wrapped_data_key[..32],
    )
    .context("restore data-key encapsulation is invalid")?;
    let aad = restore_wrap_aad(
        instance_id,
        backup_id,
        restore_job_id,
        destination_key_fingerprint,
    );
    let plaintext = single_shot_open::<HpkeChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
        &OpModeR::Base,
        &private_key,
        &encapsulated,
        RESTORE_DATA_KEY_INFO,
        &destination_wrapped_data_key[32..],
        &aad,
    )
    .map_err(|_| anyhow::anyhow!("open job-bound restore data key"))?;
    let data_key: [u8; 32] = plaintext
        .try_into()
        .map_err(|_| anyhow::anyhow!("restore data key is not 32 bytes"))?;
    Ok(Zeroizing::new(data_key))
}

/// Open a backup's data key as the backup stores it, wrapped to the
/// account's recovery key, with that key's private half (the seed's).
/// `recovery_key_fingerprint` is the SHA-256 of the recovery public key,
/// as the container's header names it.
///
/// # Errors
///
/// An envelope of the wrong size or encapsulation, and one that does not
/// open with this key for this backup.
pub fn open_data_key(
    recovery_private_key: &<X25519HkdfSha256 as hpke::Kem>::PrivateKey,
    recovery_key_fingerprint: &[u8; 32],
    instance_id: Uuid,
    backup_id: Uuid,
    wrapped_data_key: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    if wrapped_data_key.len() != WRAPPED_DATA_KEY_BYTES {
        bail!("wrapped backup data key must be exactly 80 bytes");
    }
    let encapsulated =
        <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&wrapped_data_key[..32])
            .context("wrapped backup data key has an invalid encapsulation")?;
    let plaintext = Zeroizing::new(
        single_shot_open::<HpkeChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            recovery_private_key,
            &encapsulated,
            BACKUP_DATA_KEY_INFO,
            &wrapped_data_key[32..],
            &wrap_aad(instance_id, backup_id, recovery_key_fingerprint),
        )
        .map_err(|_| anyhow::anyhow!("backup key could not be opened with this account key"))?,
    );
    let data_key: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("opened backup data key has an invalid length"))?;
    Ok(Zeroizing::new(data_key))
}

/// The associated data of a backup's data key wrapped to the recovery key.
pub fn wrap_aad(instance_id: Uuid, backup_id: Uuid, fingerprint: &[u8; 32]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32 + 16 + 16 + 32);
    aad.extend_from_slice(b"GIGAHOST-BACKUP-WRAP-V1");
    aad.extend_from_slice(instance_id.as_bytes());
    aad.extend_from_slice(backup_id.as_bytes());
    aad.extend_from_slice(fingerprint);
    aad
}

/// The associated data of the same key rewrapped to a restore's destination.
pub fn restore_wrap_aad(
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

/// The associated data of one record: the header's digest and the record's
/// descriptor.
pub fn chunk_aad(
    header_digest: &[u8; 32],
    index: u32,
    plaintext_len: u32,
    encoded_len: u32,
    flags: u8,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(45);
    aad.extend_from_slice(header_digest);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&plaintext_len.to_be_bytes());
    aad.extend_from_slice(&encoded_len.to_be_bytes());
    aad.push(flags);
    aad
}

/// The nonce of record `index`; the manifest's is index `u64::MAX`.
pub fn record_nonce(prefix: &[u8; 16], index: u64) -> [u8; 24] {
    let mut nonce = [0_u8; 24];
    nonce[..16].copy_from_slice(prefix);
    nonce[16..].copy_from_slice(&index.to_be_bytes());
    nonce
}

fn read_array<const N: usize>(reader: &mut impl Read, description: &str) -> Result<[u8; N]> {
    let mut value = [0_u8; N];
    reader
        .read_exact(&mut value)
        .with_context(|| format!("read encrypted backup {description}"))?;
    Ok(value)
}

/// A sparse raw disk image in a file: data is written where it belongs and
/// zeros are skipped, so they stay holes in a file that starts empty.
/// [`SparseFile::finish`] gives the file its full size, the zeros at its
/// end included.
pub struct SparseFile {
    file: File,
    offset: u64,
}

impl SparseFile {
    /// Write the disk into `file`, which must be empty.
    pub const fn new(file: File) -> Self {
        Self { file, offset: 0 }
    }

    /// Set the file's size to the disk's and flush it to its storage.
    ///
    /// # Errors
    ///
    /// The file system's.
    pub fn finish(self) -> std::io::Result<File> {
        self.file.set_len(self.offset)?;
        self.file.sync_all()?;
        Ok(self.file)
    }
}

impl RestoreWrite for SparseFile {
    fn write_data(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        self.file.seek(SeekFrom::Start(self.offset))?;
        self.file.write_all(bytes)?;
        self.offset += bytes.len() as u64;
        Ok(())
    }

    fn write_zeroes(&mut self, len: u64) -> std::io::Result<()> {
        self.offset = self
            .offset
            .checked_add(len)
            .ok_or_else(|| std::io::Error::other("disk offset overflow"))?;
        Ok(())
    }
}
