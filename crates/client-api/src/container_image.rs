//! A container image reference: `[REGISTRY/]REPOSITORY[:TAG]` or
//! `[REGISTRY/]REPOSITORY@sha256:HEX`, normalized as Docker normalizes it.

use std::{fmt, str::FromStr};

/// Docker Hub's registry, where a reference without a registry points.
pub const DOCKER_HUB: &str = "registry-1.docker.io";
/// The longest reference taken, as given.
pub const MAXIMUM_IMAGE_REFERENCE_BYTES: usize = 512;
/// The longest registry and repository together, as Docker's references.
const MAXIMUM_NAME_BYTES: usize = 255;
/// The longest tag, as the OCI distribution grammar has it.
const MAXIMUM_TAG_BYTES: usize = 128;
/// The tag a reference without a tag or digest names, as Docker's.
pub const DEFAULT_TAG: &str = "latest";

/// What a reference pins: a tag, resolved to a digest at instance creation,
/// or the digest of a manifest or index.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum ImagePin {
    Tag(String),
    Digest([u8; 32]),
}

/// A parsed container image reference.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ImageReference {
    /// A host with an optional port, lowercase: `registry-1.docker.io`.
    pub registry: String,
    /// The repository's path: `library/nginx`.
    pub repository: String,
    pub pin: ImagePin,
}

/// Why a text is not an image reference.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct InvalidImageReference(String);

impl ImageReference {
    /// The digest it pins, when it names one.
    #[must_use]
    pub const fn digest(&self) -> Option<&[u8; 32]> {
        match &self.pin {
            ImagePin::Digest(digest) => Some(digest),
            ImagePin::Tag(_) => None,
        }
    }

    /// The same image pinned by `digest`.
    #[must_use]
    pub fn pinned(&self, digest: [u8; 32]) -> Self {
        Self {
            registry: self.registry.clone(),
            repository: self.repository.clone(),
            pin: ImagePin::Digest(digest),
        }
    }
}

impl FromStr for ImageReference {
    type Err = InvalidImageReference;

    fn from_str(reference: &str) -> Result<Self, Self::Err> {
        let invalid =
            |why: &str| InvalidImageReference(format!("the image reference {reference:?} {why}"));
        if reference.len() > MAXIMUM_IMAGE_REFERENCE_BYTES {
            return Err(InvalidImageReference(format!(
                "an image reference has at most {MAXIMUM_IMAGE_REFERENCE_BYTES} bytes"
            )));
        }
        let (name, digest) = match reference.split_once('@') {
            Some((name, digest)) => (
                name,
                Some(parse_digest(digest).ok_or_else(|| {
                    invalid("has no SHA-256 digest of 64 lowercase hex digits after its @")
                })?),
            ),
            None => (reference, None),
        };
        // A tag follows the last colon after the last slash; a colon
        // before it is a registry's port.
        let (name, tag) = match name.rsplit_once(':') {
            Some((before, tag)) if !tag.contains('/') => (before, Some(tag)),
            _ => (name, None),
        };
        if digest.is_some() && tag.is_some() {
            return Err(invalid(
                "names both a tag and a digest: give one, REPOSITORY:TAG or REPOSITORY@sha256:HEX",
            ));
        }
        if let Some(tag) = tag
            && !valid_tag(tag)
        {
            return Err(invalid(
                "has no valid tag: up to 128 letters, digits, _, . and -, not starting with . or -",
            ));
        }
        // Docker's rule: the first component is the registry when it looks
        // like a host (a dot or a port), is `localhost`, or has an
        // uppercase letter, which no repository has.
        let (registry, repository) = match name.split_once('/') {
            Some((first, rest))
                if first.contains(['.', ':'])
                    || first == "localhost"
                    || first
                        .chars()
                        .any(|character| character.is_ascii_uppercase()) =>
            {
                (first.to_ascii_lowercase(), rest.to_owned())
            }
            _ => (DOCKER_HUB.to_owned(), name.to_owned()),
        };
        if !valid_registry(&registry) {
            return Err(invalid("names no valid registry host"));
        }
        let registry = match registry.as_str() {
            "docker.io" | "index.docker.io" => DOCKER_HUB.to_owned(),
            _ => registry,
        };
        let repository = if registry == DOCKER_HUB && !repository.contains('/') {
            format!("library/{repository}")
        } else {
            repository
        };
        if repository.len() + registry.len() + 1 > MAXIMUM_NAME_BYTES
            || !repository.split('/').all(valid_path_component)
        {
            return Err(invalid(
                "names no valid repository: lowercase letters, digits and separators",
            ));
        }
        let pin = match (digest, tag) {
            (Some(digest), _) => ImagePin::Digest(digest),
            (None, Some(tag)) => ImagePin::Tag(tag.to_owned()),
            (None, None) => ImagePin::Tag(DEFAULT_TAG.to_owned()),
        };
        Ok(Self {
            registry,
            repository,
            pin,
        })
    }
}

impl fmt::Display for ImageReference {
    /// The canonical form: `REGISTRY/REPOSITORY:TAG` or
    /// `REGISTRY/REPOSITORY@sha256:HEX`, which reads back as itself.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.pin {
            ImagePin::Tag(tag) => write!(formatter, "{}/{}:{tag}", self.registry, self.repository),
            ImagePin::Digest(digest) => write!(
                formatter,
                "{}/{}@{}",
                self.registry,
                self.repository,
                digest_string(digest)
            ),
        }
    }
}

/// `sha256:` and the digest's 64 lowercase hex digits.
#[must_use]
pub fn digest_string(digest: &[u8; 32]) -> String {
    use std::fmt::Write as _;

    let mut text = String::with_capacity(71);
    text.push_str("sha256:");
    for byte in digest {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

/// The digest of `sha256:HEX`, 64 lowercase hex digits; no other
/// algorithm.
#[must_use]
pub fn parse_digest(text: &str) -> Option<[u8; 32]> {
    let hex = text.strip_prefix("sha256:")?;
    if hex.len() != 64 {
        return None;
    }
    let mut digest = [0_u8; 32];
    for (byte, pair) in digest.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
        let nibble = |digit: u8| match digit {
            b'0'..=b'9' => Some(digit - b'0'),
            b'a'..=b'f' => Some(digit - b'a' + 10),
            _ => None,
        };
        *byte = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Some(digest)
}

/// A tag, as the OCI distribution grammar has it:
/// `[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`.
fn valid_tag(tag: &str) -> bool {
    let bytes = tag.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAXIMUM_TAG_BYTES
        && (bytes[0].is_ascii_alphanumeric() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

/// A host name or IPv4 address with an optional port.
fn valid_registry(registry: &str) -> bool {
    let (host, port) = match registry.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (registry, None),
    };
    if let Some(port) = port
        && !(port.bytes().all(|digit| digit.is_ascii_digit())
            && port.parse::<u16>().is_ok_and(|port| port > 0))
    {
        return false;
    }
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

/// A component of a repository's path, as the OCI distribution grammar has
/// it: `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*`.
fn valid_path_component(component: &str) -> bool {
    let bytes = component.as_bytes();
    let alphanumeric = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    if bytes.is_empty() || !alphanumeric(bytes[0]) || !alphanumeric(bytes[bytes.len() - 1]) {
        return false;
    }
    let mut index = 0;
    while index < bytes.len() {
        if alphanumeric(bytes[index]) {
            index += 1;
            continue;
        }
        let separator_start = index;
        while index < bytes.len() && !alphanumeric(bytes[index]) {
            index += 1;
        }
        let separator = &component[separator_start..index];
        let valid =
            matches!(separator, "." | "_" | "__") || separator.bytes().all(|byte| byte == b'-');
        if !valid {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEX: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    #[test]
    fn references_are_normalised_as_docker_normalises_them() {
        for (reference, registry, repository) in [
            ("nginx", DOCKER_HUB, "library/nginx"),
            ("docker.io/nginx", DOCKER_HUB, "library/nginx"),
            ("index.docker.io/library/nginx", DOCKER_HUB, "library/nginx"),
            ("bitnami/redis", DOCKER_HUB, "bitnami/redis"),
            ("ghcr.io/owner/app", "ghcr.io", "owner/app"),
            ("ghcr.io/app", "ghcr.io", "app"),
            ("localhost/app", "localhost", "app"),
            ("localhost:5000/a/b/c", "localhost:5000", "a/b/c"),
            ("Registry.Example/app", "registry.example", "app"),
            ("quay.io/a.b_c__d--e/f-g", "quay.io", "a.b_c__d--e/f-g"),
            ("10.0.0.1:443/app", "10.0.0.1:443", "app"),
        ] {
            let pinned: ImageReference = format!("{reference}@sha256:{HEX}")
                .parse()
                .unwrap_or_else(|error| panic!("{reference}: {error}"));
            assert_eq!(pinned.registry, registry, "{reference}");
            assert_eq!(pinned.repository, repository, "{reference}");
            assert_eq!(
                pinned.digest().map(digest_string),
                Some(format!("sha256:{HEX}"))
            );
            assert_eq!(
                pinned.to_string(),
                format!("{registry}/{repository}@sha256:{HEX}")
            );
            let tagged: ImageReference = format!("{reference}:1.27-alpine")
                .parse()
                .unwrap_or_else(|error| panic!("{reference}: {error}"));
            assert_eq!(tagged.pin, ImagePin::Tag("1.27-alpine".to_owned()));
            assert_eq!(
                tagged.to_string(),
                format!("{registry}/{repository}:1.27-alpine")
            );
            let plain: ImageReference = reference.parse().unwrap();
            assert_eq!(plain.pin, ImagePin::Tag("latest".to_owned()), "{reference}");
            for parsed in [pinned, tagged, plain] {
                assert_eq!(
                    parsed.to_string().parse::<ImageReference>().unwrap(),
                    parsed,
                    "the canonical form reads back as itself"
                );
            }
        }
    }

    #[test]
    fn a_tag_resolves_to_the_same_image_pinned() {
        let tagged: ImageReference = "nginx:1.27".parse().unwrap();
        let pinned = tagged.pinned([7; 32]);
        assert_eq!(pinned.registry, DOCKER_HUB);
        assert_eq!(pinned.repository, "library/nginx");
        assert_eq!(pinned.digest(), Some(&[7; 32]));
    }

    #[test]
    fn anything_but_a_tag_or_a_sha256_digest_is_refused() {
        let upper = HEX.to_ascii_uppercase();
        for reference in [
            String::new(),
            format!("nginx:1.27@sha256:{HEX}"),
            format!("ghcr.io/owner/app:v1@sha256:{HEX}"),
            format!("nginx@sha512:{HEX}"),
            format!("nginx@sha256:{upper}"),
            format!("nginx@sha256:{}", &HEX[1..]),
            format!("nginx@sha256:{HEX}0"),
            format!("nginx@{HEX}"),
            format!("@sha256:{HEX}"),
            format!("Nginx@sha256:{HEX}"),
            format!("ghcr.io/Owner/app@sha256:{HEX}"),
            format!("ghcr.io//app@sha256:{HEX}"),
            format!("ghcr.io/app/@sha256:{HEX}"),
            format!("ghcr.io/-app@sha256:{HEX}"),
            format!("ghcr.io/a...b@sha256:{HEX}"),
            format!("ghcr.io/a@b@sha256:{HEX}"),
            format!("gh_cr.io/app@sha256:{HEX}"),
            format!("ghcr.io:0/app@sha256:{HEX}"),
            format!("ghcr.io:99999/app@sha256:{HEX}"),
            format!("ghcr.io:/app@sha256:{HEX}"),
            format!("ghcr.io/{}@sha256:{HEX}", "a".repeat(250)),
            format!("ghcr.io/../etc@sha256:{HEX}"),
            "nginx:".to_owned(),
            "nginx:.hidden".to_owned(),
            "nginx:-dash".to_owned(),
            "nginx:a b".to_owned(),
            format!("nginx:{}", "a".repeat(129)),
            "ghcr.io/app:v1:v2".to_owned(),
            format!("ghcr.io/{}", "a/".repeat(300)),
        ] {
            assert!(
                reference.parse::<ImageReference>().is_err(),
                "{reference} is refused"
            );
        }
        assert!(
            format!("nginx:{}", "a".repeat(128))
                .parse::<ImageReference>()
                .is_ok()
        );
    }
}
