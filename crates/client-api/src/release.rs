use serde::{Deserialize, Serialize};

/// Whether `version` is a release version: `YYYYMMDDTHHMMSSZ-` and twelve
/// lowercase hex characters, which sort chronologically as text.
#[must_use]
pub fn is_release_version(version: &str) -> bool {
    let bytes = version.as_bytes();
    bytes.len() == 29
        && bytes[..8].iter().all(u8::is_ascii_digit)
        && bytes[8] == b'T'
        && bytes[9..15].iter().all(u8::is_ascii_digit)
        && bytes[15] == b'Z'
        && bytes[16] == b'-'
        && bytes[17..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

/// A signed platform release manifest as published in `manifest.json`.
/// [`Self::verify`] checks `signature` over the canonical `release` object.
/// The signature covers every release key, including keys a later version adds.
/// Keys beside `release` and `signature` are unsigned and are not retained.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SignedReleaseManifest {
    pub release: ReleaseManifest,
    /// Ed25519 signature over the canonical release object, standard base64.
    pub signature: String,
}

/// The keys of a release object every release reads: the immutable archive
/// URL, its lowercase hex SHA-256, and the version, `YYYYMMDDTHHMMSSZ-` and
/// twelve hex characters of the binaries' digest.
const RELEASE_KEYS: [&str; 3] = ["archive_url", "sha256", "version"];

/// The published `release` object, including the keys this build reads
/// ([`Self::archive_url`], [`Self::sha256`], [`Self::version`]) and any
/// additional keys, which remain covered by the signature.
///
/// JSON serialization preserves the object; other formats use named fields
/// and retain additional keys as compact JSON.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseManifest(serde_json::Map<String, serde_json::Value>);

impl ReleaseManifest {
    /// A release object of the three keys every release reads.
    #[must_use]
    pub fn new(archive_url: &str, sha256: &str, version: &str) -> Self {
        Self(
            RELEASE_KEYS
                .into_iter()
                .zip([archive_url, sha256, version])
                .map(|(key, value)| (key.to_owned(), serde_json::Value::from(value)))
                .collect(),
        )
    }

    /// The release object as published.
    #[must_use]
    pub const fn object(&self) -> &serde_json::Map<String, serde_json::Value> {
        &self.0
    }

    /// The release object as published, to change: for tests and tools.
    pub const fn object_mut(&mut self) -> &mut serde_json::Map<String, serde_json::Value> {
        &mut self.0
    }

    /// The release's version.
    ///
    /// # Errors
    ///
    /// When the object has no `version`, or not as text.
    pub fn version(&self) -> Result<&str, ReleaseManifestError> {
        self.text("version")
    }

    /// The HTTPS URL of the release's archive.
    ///
    /// # Errors
    ///
    /// When the object has no `archive_url`, or not as text.
    pub fn archive_url(&self) -> Result<&str, ReleaseManifestError> {
        self.text("archive_url")
    }

    /// The archive's lowercase hex SHA-256.
    ///
    /// # Errors
    ///
    /// When the object has no `sha256`, or not as text.
    pub fn sha256(&self) -> Result<&str, ReleaseManifestError> {
        self.text("sha256")
    }

    fn text(&self, key: &'static str) -> Result<&str, ReleaseManifestError> {
        self.0
            .get(key)
            .and_then(serde_json::Value::as_str)
            .ok_or(ReleaseManifestError::MissingKey(key))
    }
}

/// Named-field serialization of [`ReleaseManifest`].
#[derive(Deserialize, Serialize)]
#[serde(rename = "ReleaseManifest")]
struct ReleaseFields {
    archive_url: String,
    sha256: String,
    version: String,
    /// Absent from a build that knows only the three keys.
    #[serde(default)]
    later_keys: LaterReleaseKeys,
}

/// Additional release keys, serialized as compact JSON; an empty string
/// represents no additional keys.
#[derive(Default)]
struct LaterReleaseKeys(serde_json::Map<String, serde_json::Value>);

impl Serialize for LaterReleaseKeys {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;

        let text = if self.0.is_empty() {
            String::new()
        } else {
            serde_json::to_string(&self.0).map_err(S::Error::custom)?
        };
        serializer.serialize_newtype_struct("ReleaseManifestLaterKeys", &text)
    }
}

impl<'de> Deserialize<'de> for LaterReleaseKeys {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Keys;

        impl<'de> serde::de::Visitor<'de> for Keys {
            type Value = LaterReleaseKeys;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("the later keys of a release object, as JSON")
            }

            fn visit_newtype_struct<D: serde::Deserializer<'de>>(
                self,
                deserializer: D,
            ) -> Result<LaterReleaseKeys, D::Error> {
                use serde::de::Error as _;

                let text = String::deserialize(deserializer)?;
                if text.is_empty() {
                    return Ok(LaterReleaseKeys::default());
                }
                serde_json::from_str(&text)
                    .map(LaterReleaseKeys)
                    .map_err(D::Error::custom)
            }
        }

        deserializer.deserialize_newtype_struct("ReleaseManifestLaterKeys", Keys)
    }
}

impl Serialize for ReleaseManifest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::Error as _;

        if serializer.is_human_readable() {
            return self.0.serialize(serializer);
        }
        let text = |key| self.text(key).map(str::to_owned).map_err(S::Error::custom);
        ReleaseFields {
            archive_url: text("archive_url")?,
            sha256: text("sha256")?,
            version: text("version")?,
            later_keys: LaterReleaseKeys(
                self.0
                    .iter()
                    .filter(|(key, _)| !RELEASE_KEYS.contains(&key.as_str()))
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
            ),
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ReleaseManifest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        if deserializer.is_human_readable() {
            return serde_json::Map::deserialize(deserializer).map(Self);
        }
        let fields = ReleaseFields::deserialize(deserializer)?;
        let mut object = fields.later_keys.0;
        for (key, value) in
            RELEASE_KEYS
                .into_iter()
                .zip([fields.archive_url, fields.sha256, fields.version])
        {
            if object
                .insert(key.to_owned(), serde_json::Value::String(value))
                .is_some()
            {
                return Err(D::Error::custom(format_args!(
                    "a release object's later keys name {key}"
                )));
            }
        }
        Ok(Self(object))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ReleaseManifestError {
    #[error("release manifest has no {0} as text")]
    MissingKey(&'static str),
    #[error("release version has an invalid format")]
    InvalidVersion,
    #[error("release archive URL must use HTTPS")]
    InvalidArchiveUrl,
    #[error("release archive SHA-256 is invalid")]
    InvalidSha256,
    #[error("release manifest signature is malformed")]
    MalformedSignature,
    #[error("release manifest signature is invalid")]
    InvalidSignature,
}

/// `value` as `jq -c --sort-keys` prints it: no spaces, an object's keys in
/// the order of their bytes, a string's quotes, backslashes and control
/// characters (and DEL) escaped as jq escapes them, the rest of its text as
/// it is. Numbers are printed as `serde_json` reads them, which matches jq
/// of every version for integers of at most 2^53 in magnitude, the only
/// numbers a release object may hold.
fn write_canonical_json(value: &serde_json::Value, out: &mut String) {
    use serde_json::Value;
    use std::fmt::Write as _;

    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
        Value::Number(number) => {
            let _ = write!(out, "{number}");
        }
        Value::String(text) => write_canonical_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_canonical_json(item, out);
            }
            out.push(']');
        }
        Value::Object(object) => write_canonical_object(object, out),
    }
}

fn write_canonical_object(object: &serde_json::Map<String, serde_json::Value>, out: &mut String) {
    let mut keys: Vec<&String> = object.keys().collect();
    keys.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    out.push('{');
    for (index, key) in keys.into_iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        write_canonical_string(key, out);
        out.push(':');
        write_canonical_json(&object[key], out);
    }
    out.push('}');
}

fn write_canonical_string(text: &str, out: &mut String) {
    use std::fmt::Write as _;

    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\u{0}'..='\u{1f}' | '\u{7f}' => {
                let _ = write!(out, "\\u{:04x}", u32::from(character));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

impl SignedReleaseManifest {
    /// Check the manifest's shape: the three keys every release reads, each
    /// well formed. Other keys of the release object are a later release's.
    ///
    /// # Errors
    ///
    /// Returns the first rule the manifest breaks.
    pub fn validate(&self) -> Result<(), ReleaseManifestError> {
        if !is_release_version(self.release.version()?) {
            return Err(ReleaseManifestError::InvalidVersion);
        }
        let archive_url = self.release.archive_url()?;
        if !archive_url.starts_with("https://")
            || archive_url.len() > 1024
            || archive_url
                .chars()
                .any(|character| character.is_whitespace() || character.is_control())
        {
            return Err(ReleaseManifestError::InvalidArchiveUrl);
        }
        let sha256 = self.release.sha256()?;
        if sha256.len() != 64
            || !sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ReleaseManifestError::InvalidSha256);
        }
        Ok(())
    }

    /// The bytes the signature covers: the whole release object, including
    /// additional keys, sorted and without spaces, newline-terminated, as
    /// `jq -cS '.release'` prints it. Every verifier checks the whole object.
    #[must_use]
    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut text = String::new();
        write_canonical_object(&self.release.0, &mut text);
        text.push('\n');
        text.into_bytes()
    }

    /// Check the shape and the signature against the release public key.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid manifest or signature.
    pub fn verify(
        &self,
        verifying_key: &ed25519_dalek::VerifyingKey,
    ) -> Result<(), ReleaseManifestError> {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use ed25519_dalek::Verifier as _;

        self.validate()?;
        let signature = STANDARD
            .decode(&self.signature)
            .map_err(|_| ReleaseManifestError::MalformedSignature)?;
        let signature: [u8; 64] = signature
            .try_into()
            .map_err(|_| ReleaseManifestError::MalformedSignature)?;
        verifying_key
            .verify(
                &self.signed_bytes(),
                &ed25519_dalek::Signature::from_bytes(&signature),
            )
            .map_err(|_| ReleaseManifestError::InvalidSignature)
    }
}

#[cfg(test)]
mod release_tests {
    use super::*;

    fn plain_manifest() -> SignedReleaseManifest {
        SignedReleaseManifest {
            release: ReleaseManifest::new(
                "https://cdn.example/platform/a.tar.gz",
                &"ab".repeat(32),
                "20260926T120000Z-0123456789ab",
            ),
            signature: String::new(),
        }
    }

    /// A release object with keys a later release adds: nested, of every
    /// kind of value, and with text jq escapes.
    fn later_release() -> ReleaseManifest {
        serde_json::from_value(serde_json::json!({
            "version": "20260926T120000Z-0123456789ab",
            "sha256": "ab".repeat(32),
            "archive_url": "https://cdn.example/platform/a.tar.gz",
            "notes": {
                "zeta": [1, -2, 9_007_199_254_740_991_i64, true, false, null, {"b": "", "a": []}],
                "Alpha": "quote \" backslash \\ slash / tab \t newline \n return \r feed \u{c} back \u{8}",
                "control": "\u{1} \u{1f} \u{7f} \u{80} é ü ✓ 😀 \u{2028}",
                "": {},
                "a b": "x",
                "ä": 1,
                "A": 2,
            },
            "min_agent": 3,
        }))
        .unwrap()
    }

    #[test]
    fn manifests_are_validated_and_signed_over_the_canonical_release_object() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use ed25519_dalek::{Signer as _, SigningKey};

        let key = SigningKey::from_bytes(&[3; 32]);
        let mut manifest = plain_manifest();
        assert_eq!(
            String::from_utf8(manifest.signed_bytes()).unwrap(),
            "{\"archive_url\":\"https://cdn.example/platform/a.tar.gz\",\"sha256\":\"abababababababababababababababababababababababababababababababab\",\"version\":\"20260926T120000Z-0123456789ab\"}\n"
        );
        manifest.signature = STANDARD.encode(key.sign(&manifest.signed_bytes()).to_bytes());
        manifest.verify(&key.verifying_key()).expect("valid");
        let other = SigningKey::from_bytes(&[4; 32]);
        assert!(matches!(
            manifest.verify(&other.verifying_key()),
            Err(ReleaseManifestError::InvalidSignature)
        ));
        let mut tampered = manifest.clone();
        tampered
            .release
            .object_mut()
            .insert("sha256".to_owned(), "cd".repeat(32).into());
        assert!(tampered.verify(&key.verifying_key()).is_err());
        let mut bad_version = manifest.clone();
        bad_version
            .release
            .object_mut()
            .insert("version".to_owned(), "v1".into());
        assert!(matches!(
            bad_version.validate(),
            Err(ReleaseManifestError::InvalidVersion)
        ));
        // Each of the three keys is there as text.
        for key in ["archive_url", "sha256", "version"] {
            let mut missing = manifest.clone();
            missing.release.object_mut().remove(key);
            assert!(
                matches!(missing.validate(), Err(ReleaseManifestError::MissingKey(named)) if named == key),
                "{key}"
            );
            let mut mistyped = manifest.clone();
            mistyped
                .release
                .object_mut()
                .insert(key.to_owned(), serde_json::json!(["x"]));
            assert!(
                matches!(mistyped.validate(), Err(ReleaseManifestError::MissingKey(named)) if named == key),
                "{key}"
            );
        }
        assert!(is_release_version("20260926T120000Z-0123456789ab"));
        assert!(!is_release_version("20260926T120000Z-0123456789AB"));
    }

    /// A key a later release adds to the release object is signed with the
    /// rest: the manifest verifies, the key is kept, and changing it breaks
    /// the signature.
    #[test]
    fn a_later_key_of_the_release_object_is_signed_and_kept() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use ed25519_dalek::{Signer as _, SigningKey};

        let key = SigningKey::from_bytes(&[3; 32]);
        let mut manifest = SignedReleaseManifest {
            release: later_release(),
            signature: String::new(),
        };
        manifest.signature = STANDARD.encode(key.sign(&manifest.signed_bytes()).to_bytes());
        manifest.verify(&key.verifying_key()).expect("valid");
        assert_eq!(
            manifest.release.version().unwrap(),
            "20260926T120000Z-0123456789ab"
        );
        // JSON serialization keeps the whole release object.
        let json = serde_json::to_string(&manifest).unwrap();
        let read: SignedReleaseManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(read, manifest);
        read.verify(&key.verifying_key())
            .expect("valid as read back");
        // Named-field serialization keeps it too.
        let bytes = postcard::to_stdvec(&manifest).unwrap();
        let read: SignedReleaseManifest = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(read, manifest);
        read.verify(&key.verifying_key()).expect("valid as carried");
        let plain = plain_manifest();
        let read: SignedReleaseManifest =
            postcard::from_bytes(&postcard::to_stdvec(&plain).unwrap()).unwrap();
        assert_eq!(read, plain);
        let mut changed = manifest.clone();
        changed
            .release
            .object_mut()
            .insert("min_agent".to_owned(), serde_json::json!(4));
        assert!(matches!(
            changed.verify(&key.verifying_key()),
            Err(ReleaseManifestError::InvalidSignature)
        ));
        let mut dropped = manifest;
        dropped.release.object_mut().remove("notes");
        assert!(matches!(
            dropped.verify(&key.verifying_key()),
            Err(ReleaseManifestError::InvalidSignature)
        ));
    }

    /// The signed bytes match `jq -cS '.release'`, including keys a later
    /// release adds.
    #[test]
    fn the_signed_bytes_are_what_jq_prints() {
        use std::io::Write as _;

        let manifest = SignedReleaseManifest {
            release: later_release(),
            signature: "c2ln".to_owned(),
        };
        // The manifest as a publisher writes it, keys in any order.
        let published = format!(
            r#"{{"signature":"c2ln","release":{}}}"#,
            serde_json::to_string(&manifest.release).unwrap()
        );
        let mut jq = std::process::Command::new("jq");
        #[cfg(windows)]
        jq.arg("--binary");
        let child = jq
            .args(["-cS", ".release"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn();
        let Ok(mut child) = child else {
            eprintln!("skipping: jq is not installed");
            return;
        };
        child
            .stdin
            .take()
            .unwrap()
            .write_all(published.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8(manifest.signed_bytes()).unwrap(),
            String::from_utf8(output.stdout).unwrap()
        );
    }
}
