//! The decoder against the fixed containers the host's encoder wrote
//! (`fixtures/`).

use std::{fs::File, io::Cursor};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ghostrack_backup_format::{
    HEADER_FIXED_BYTES, SparseFile, StreamRestoreInput, WRAPPED_DATA_KEY_BYTES, decode_stream,
    open_data_key,
};
use hpke::{Kem as _, kem::X25519HkdfSha256};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

struct Fixture {
    instance_id: Uuid,
    backup_id: Uuid,
    disk_bytes: u64,
    disk_sha256: Vec<u8>,
    fingerprint: [u8; 32],
    wrapped_data_key: Vec<u8>,
    data_key: [u8; 32],
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).unwrap())
        .collect()
}

fn fixture() -> Fixture {
    let file: serde_json::Value =
        serde_json::from_str(include_str!("../fixtures/backups.json")).unwrap();
    let text = |name: &str| file[name].as_str().unwrap().to_owned();
    Fixture {
        instance_id: text("instance_id").parse().unwrap(),
        backup_id: text("backup_id").parse().unwrap(),
        disk_bytes: file["disk_bytes"].as_u64().unwrap(),
        disk_sha256: hex(&text("disk_sha256_hex")),
        fingerprint: URL_SAFE_NO_PAD
            .decode(text("recovery_key_fingerprint_b64url"))
            .unwrap()
            .try_into()
            .unwrap(),
        wrapped_data_key: URL_SAFE_NO_PAD
            .decode(text("wrapped_data_key_b64url"))
            .unwrap(),
        data_key: hex(&text("data_key_hex")).try_into().unwrap(),
    }
}

fn container(version: u8) -> Vec<u8> {
    match version {
        1 => include_bytes!("../fixtures/backup-v1.ghb").to_vec(),
        _ => include_bytes!("../fixtures/backup-v2.ghb").to_vec(),
    }
}

fn decode(container: &[u8], fixture: &Fixture, data_key: &[u8; 32]) -> anyhow::Result<Vec<u8>> {
    let mut disk = Vec::new();
    decode_stream(
        &mut Cursor::new(container),
        &mut disk,
        &StreamRestoreInput {
            instance_id: fixture.instance_id,
            backup_id: fixture.backup_id,
            disk_bytes: fixture.disk_bytes,
            recipient_key_fingerprint: &fixture.fingerprint,
            data_key,
        },
    )?;
    Ok(disk)
}

/// The recovery key of the `sevens` account seed vector, as the seed
/// derives it.
fn recovery_private_key() -> <X25519HkdfSha256 as hpke::Kem>::PrivateKey {
    let file: serde_json::Value = serde_json::from_str(include_str!(
        "../../client-api/fixtures/account-seed-vectors.json"
    ))
    .unwrap();
    let sevens = file["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|vector| vector["name"] == "sevens")
        .unwrap();
    let material = hex(sevens["recovery_material_hex"].as_str().unwrap());
    X25519HkdfSha256::derive_keypair(&material).0
}

#[test]
fn version_2_and_version_1_containers_decode_to_the_disk() {
    let fixture = fixture();
    for (version, format) in [(2, 2), (1, 1)] {
        let mut disk = Vec::new();
        let digest = decode_stream(
            &mut Cursor::new(container(version)),
            &mut disk,
            &StreamRestoreInput {
                instance_id: fixture.instance_id,
                backup_id: fixture.backup_id,
                disk_bytes: fixture.disk_bytes,
                recipient_key_fingerprint: &fixture.fingerprint,
                data_key: &fixture.data_key,
            },
        )
        .unwrap();
        assert_eq!(digest.format, format);
        assert_eq!(disk.len() as u64, fixture.disk_bytes);
        assert_eq!(Sha256::digest(&disk).as_slice(), fixture.disk_sha256);
    }
}

#[test]
fn the_seeds_recovery_key_opens_the_data_key() {
    let fixture = fixture();
    let data_key = open_data_key(
        &recovery_private_key(),
        &fixture.fingerprint,
        fixture.instance_id,
        fixture.backup_id,
        &fixture.wrapped_data_key,
    )
    .unwrap();
    assert_eq!(*data_key, fixture.data_key);
    // Bound to its backup and instance.
    for (instance_id, backup_id) in [
        (fixture.backup_id, fixture.backup_id),
        (fixture.instance_id, fixture.instance_id),
    ] {
        assert!(
            open_data_key(
                &recovery_private_key(),
                &fixture.fingerprint,
                instance_id,
                backup_id,
                &fixture.wrapped_data_key,
            )
            .is_err()
        );
    }
    // Another key does not open it.
    let (other, _) = X25519HkdfSha256::derive_keypair(&[9; 32]);
    assert!(
        open_data_key(
            &other,
            &fixture.fingerprint,
            fixture.instance_id,
            fixture.backup_id,
            &fixture.wrapped_data_key,
        )
        .is_err()
    );
}

#[test]
fn a_corrupted_record_is_refused() {
    let fixture = fixture();
    for version in [2, 1] {
        let original = container(version);
        // A byte of the first record's ciphertext, after its 13-byte
        // descriptor; a byte of the manifest, and of the footer.
        let first_record = HEADER_FIXED_BYTES + WRAPPED_DATA_KEY_BYTES + 13;
        for at in [first_record + 5, original.len() - 40, original.len() - 1] {
            let mut corrupted = original.clone();
            corrupted[at] ^= 0x01;
            assert!(
                decode(&corrupted, &fixture, &fixture.data_key).is_err(),
                "version {version}, byte {at}"
            );
        }
        // A container cut short.
        assert!(decode(&original[..original.len() - 1], &fixture, &fixture.data_key).is_err());
    }
}

#[test]
fn a_wrong_data_key_is_refused() {
    let fixture = fixture();
    let mut wrong = fixture.data_key;
    wrong[0] ^= 0x80;
    for version in [2, 1] {
        let error = decode(&container(version), &fixture, &wrong).unwrap_err();
        assert!(error.to_string().contains("authenticate"), "{error:#}");
    }
}

#[test]
fn zero_chunks_are_holes_in_the_sparse_output() {
    let fixture = fixture();
    let directory = tempfile::tempdir().unwrap();
    for version in [2, 1] {
        let path = directory.path().join(format!("disk-v{version}.raw"));
        let mut sparse = SparseFile::new(File::create_new(&path).unwrap());
        decode_stream(
            &mut Cursor::new(container(version)),
            &mut sparse,
            &StreamRestoreInput {
                instance_id: fixture.instance_id,
                backup_id: fixture.backup_id,
                disk_bytes: fixture.disk_bytes,
                recipient_key_fingerprint: &fixture.fingerprint,
                data_key: &fixture.data_key,
            },
        )
        .unwrap();
        sparse.finish().unwrap();
        let disk = std::fs::read(&path).unwrap();
        assert_eq!(Sha256::digest(&disk).as_slice(), fixture.disk_sha256);
        // The 4 MiB zero chunk takes no blocks: what is allocated is the
        // two data chunks, rounded up to the file system's blocks. Only
        // Unix reports a file's blocks; the CLI's CI also tests on Windows.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt as _;
            let allocated = std::fs::metadata(&path).unwrap().blocks() * 512;
            assert!(
                allocated <= fixture.disk_bytes - 4 * 1024 * 1024 + 64 * 1024,
                "version {version}: {allocated} bytes allocated"
            );
        }
    }
}
