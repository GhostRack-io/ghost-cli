//! The website password's shared rules: its alphabet and length, how a
//! client draws one, the Ed25519 key pair derived from it, and the message a
//! login signs. Every client reproduces the same derivation and signature.
//!
//! Passwords are generated rather than chosen: 16 characters, uniform over
//! [`ALPHABET`]'s 61 symbols, about 95 bits. This entropy is essential to the
//! fast [`signing_key`] derivation. User-chosen or shorter passwords require
//! a slow, memory-hard derivation such as Argon2id instead.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use rand_core::CryptoRngCore;
use sha2::Sha256;

/// The characters a password is drawn from, in this order: `A`–`Z` but
/// `I` and `O`, `a`–`z` but `l` and `o`, `2`–`9`, and `-` `.` `!` `?`
/// `@`. Every phone keyboard has them on its first two pages, and none is
/// easy to confuse with another when read.
pub const ALPHABET: &[u8; 61] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789-.!?@";

/// The characters of a password.
pub const LENGTH: usize = 16;

/// The largest multiple of the alphabet's size a byte holds (4 × 61):
/// a byte below it chooses a character uniformly, one at or above it is
/// drawn again.
const UNBIASED_BYTES: u8 = 244;

/// The salt's fixed label; the account alias follows it.
const SALT_LABEL: &[u8] = b"GIGAHOST-WEBSITE-PASSWORD-V1\0";
/// What HKDF's output is for.
const KEY_INFO: &[u8] = b"website-login-ed25519-v1";
/// The first line of a login's signed message.
const LOGIN_DOMAIN: &str = "GIGAHOST-WEBSITE-PASSWORD-LOGIN-V1";

/// Draws a password from `rng`: [`LENGTH`] characters, each uniform over
/// [`ALPHABET`].
pub fn generate(rng: &mut impl CryptoRngCore) -> String {
    let mut password = String::with_capacity(LENGTH);
    let mut bytes = [0_u8; 32];
    while password.len() < LENGTH {
        rng.fill_bytes(&mut bytes);
        password = from_bytes(password, bytes);
    }
    password
}

/// `password` with characters chosen by `bytes` added, until it has
/// [`LENGTH`]: each byte below [`UNBIASED_BYTES`] chooses one, the others
/// are skipped.
fn from_bytes(mut password: String, bytes: impl IntoIterator<Item = u8>) -> String {
    for byte in bytes {
        if password.len() == LENGTH {
            break;
        }
        if byte < UNBIASED_BYTES {
            password.push(char::from(ALPHABET[usize::from(byte % 61)]));
        }
    }
    password
}

/// Whether `password` has [`LENGTH`] characters, all of [`ALPHABET`].
#[must_use]
pub fn is_well_formed(password: &str) -> bool {
    password.len() == LENGTH && password.bytes().all(|byte| ALPHABET.contains(&byte))
}

/// Whether `alias` is an account alias: `gh-` and eight characters of
/// lowercase base32 (`a`–`z`, `2`–`7`).
#[must_use]
pub fn is_account_alias(alias: &str) -> bool {
    alias.len() == 11
        && alias.starts_with("gh-")
        && alias
            .bytes()
            .skip(3)
            .all(|byte| matches!(byte, b'a'..=b'z' | b'2'..=b'7'))
}

/// The login key of `password` for the account `account_alias`: HKDF-SHA-256
/// with the salt [`SALT_LABEL`] ‖ the alias, the password's UTF-8 bytes as
/// the input key material and the info `website-login-ed25519-v1`, whose 32
/// bytes are the Ed25519 seed. It is fast on purpose, which only a
/// generated password of [`LENGTH`] characters makes safe (see the module).
///
/// # Panics
///
/// Never: 32 bytes is a valid HKDF-SHA-256 output length.
#[must_use]
pub fn signing_key(account_alias: &str, password: &str) -> SigningKey {
    let mut salt = Vec::with_capacity(SALT_LABEL.len() + account_alias.len());
    salt.extend_from_slice(SALT_LABEL);
    salt.extend_from_slice(account_alias.as_bytes());
    let mut seed = [0_u8; 32];
    Hkdf::<Sha256>::new(Some(&salt), password.as_bytes())
        .expand(KEY_INFO, &mut seed)
        .expect("32 bytes is a valid HKDF-SHA-256 output length");
    let key = SigningKey::from_bytes(&seed);
    seed.fill(0);
    key
}

/// What a login signs: the domain line, the account alias, the website's
/// origin exactly as a browser's `location.origin` gives it (scheme, host
/// and port, no trailing slash), and the challenge in base64url without
/// padding, one per line.
#[must_use]
pub fn login_message(account_alias: &str, origin: &str, challenge: &[u8; 32]) -> Vec<u8> {
    format!(
        "{LOGIN_DOMAIN}\n{account_alias}\n{origin}\n{}",
        URL_SAFE_NO_PAD.encode(challenge)
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer as _;

    /// The vectors every client must reproduce, as
    /// `fixtures/website-password-vectors.json` holds them for the
    /// website's script.
    const VECTORS: &str = include_str!("../fixtures/website-password-vectors.json");

    #[test]
    fn the_alphabet_has_61_characters_that_read_and_type_well() {
        let mut distinct = ALPHABET.to_vec();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(distinct.len(), 61);
        for confusable in b"IOlo01\"'`\\()[]{}<> " {
            assert!(
                !ALPHABET.contains(confusable),
                "{}",
                char::from(*confusable)
            );
        }
        assert_eq!(
            ALPHABET.iter().filter(|c| c.is_ascii_uppercase()).count(),
            24
        );
        assert_eq!(
            ALPHABET.iter().filter(|c| c.is_ascii_lowercase()).count(),
            24
        );
        assert_eq!(ALPHABET.iter().filter(|c| c.is_ascii_digit()).count(), 8);
    }

    #[test]
    fn a_password_has_16_characters_of_the_alphabet_and_differs_each_time() {
        let mut rng = rand_core::OsRng;
        let first = generate(&mut rng);
        let second = generate(&mut rng);
        for password in [&first, &second] {
            assert_eq!(password.chars().count(), LENGTH);
            assert!(is_well_formed(password), "{password}");
        }
        assert_ne!(first, second);
        assert!(!is_well_formed("Abcd-2345.efgh!"));
        assert!(!is_well_formed("Abcd-2345.efgh!0"));
    }

    /// A byte at or above 244 would favour the alphabet's first
    /// characters; it is skipped.
    #[test]
    fn bytes_that_would_bias_a_character_are_drawn_again() {
        let mut bytes = vec![244, 255, 250];
        bytes.extend(0..16);
        let password = from_bytes(String::new(), bytes);
        assert_eq!(password, "ABCDEFGHJKLMNPQR");
        // 243 is the last unbiased byte: 243 % 61 = 60, the last character.
        assert_eq!(from_bytes(String::new(), [243, 61, 122, 183]), "@AAA");
        assert_eq!(from_bytes(String::new(), [255; 64]), "");
    }

    #[test]
    fn an_alias_is_gh_and_eight_base32_characters() {
        assert!(is_account_alias("gh-abcdefgh"));
        assert!(is_account_alias("gh-4a2l3v67"));
        for invalid in [
            "gh-abcdefg",
            "gh-abcdefghi",
            "gh-ABCDEFGH",
            "gh-abcdef18",
            "xx-abcdefgh",
        ] {
            assert!(!is_account_alias(invalid), "{invalid}");
        }
    }

    #[test]
    fn the_derivation_and_the_login_message_match_the_fixed_vectors() {
        let vectors: serde_json::Value = serde_json::from_str(VECTORS).expect("the vectors");
        let text = |name: &str| vectors[name].as_str().expect(name).to_owned();
        let alias = text("account_alias");
        let password = text("password");
        let origin = text("origin");
        let challenge: [u8; 32] = hex(&text("challenge_hex")).try_into().expect("32 bytes");
        assert_eq!(challenge, [1; 32]);
        assert_eq!(URL_SAFE_NO_PAD.encode(challenge), text("challenge_b64url"));
        let key = signing_key(&alias, &password);
        assert_eq!(hex_string(&key.to_bytes()), text("seed_hex"));
        assert_eq!(
            hex_string(key.verifying_key().as_bytes()),
            text("public_key_hex")
        );
        let message = login_message(&alias, &origin, &challenge);
        assert_eq!(
            String::from_utf8(message.clone()).expect("text"),
            text("message")
        );
        assert_eq!(
            hex_string(&key.sign(&message).to_bytes()),
            text("signature_hex")
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
            text("public_key_b64url")
        );
        // The same password for another account is another key.
        assert_ne!(
            signing_key("gh-bbcdefgh", &password).verifying_key(),
            key.verifying_key()
        );
    }

    fn hex_string(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        bytes.iter().fold(String::new(), |mut text, byte| {
            let _ = write!(text, "{byte:02x}");
            text
        })
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex"))
            .collect()
    }
}
