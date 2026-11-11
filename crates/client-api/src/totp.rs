//! Two-factor codes (item 201): the parameters every authenticator app
//! reads (RFC 6238 with SHA-1, six digits, 30-second steps, a 20-byte
//! secret) and the forms a secret travels in. A client makes the secret,
//! shows it as an `otpauth://` URI and as base32 text, and sends it with
//! one current code to turn codes on (`EnableTotp`, signed with the
//! account key). Only the backend computes codes.

/// The secret's length in bytes.
pub const SECRET_BYTES: usize = 20;
/// The digits of a code.
pub const DIGITS: usize = 6;
/// The length of a step, in seconds.
pub const PERIOD_SECONDS: u64 = 30;
/// The issuer an authenticator app shows the account under.
pub const ISSUER: &str = "GhostRack";

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// `bytes` in base32 (RFC 4648), upper case and without padding, as
/// authenticator apps take a secret.
#[must_use]
pub fn encode_secret(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len().div_ceil(5) * 8);
    let mut buffer: u32 = 0;
    let mut bits = 0_u32;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            text.push(char::from(ALPHABET[((buffer >> bits) & 31) as usize]));
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        text.push(char::from(ALPHABET[((buffer << (5 - bits)) & 31) as usize]));
    }
    text
}

/// The secret a base32 text names: either case, spaces and padding
/// ignored; `None` for any other character or a length that is not a
/// whole number of bytes' worth.
#[must_use]
pub fn decode_secret(text: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::with_capacity(text.len() * 5 / 8);
    let mut buffer: u32 = 0;
    let mut bits = 0_u32;
    for character in text.chars().filter(|c| *c != ' ' && *c != '=') {
        let upper = character.to_ascii_uppercase();
        let value = ALPHABET.iter().position(|&a| char::from(a) == upper)?;
        buffer = (buffer << 5) | u32::try_from(value).ok()?;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push(u8::try_from((buffer >> bits) & 0xff).ok()?);
        }
        buffer &= (1 << bits) - 1;
    }
    // Leftover bits are padding, and zero in a canonical encoding.
    (bits < 5 && buffer == 0).then_some(bytes)
}

/// The `otpauth://` URI of `secret` (base32) for the account `label` (its
/// alias), which an authenticator app reads from a QR code.
#[must_use]
pub fn otpauth_uri(secret: &str, label: &str) -> String {
    format!(
        "otpauth://totp/{ISSUER}:{label}?secret={secret}&issuer={ISSUER}&algorithm=SHA1&digits={DIGITS}&period={PERIOD_SECONDS}"
    )
}

/// Whether `code` is six ASCII digits, as a code is sent.
#[must_use]
pub fn is_code(code: &str) -> bool {
    code.len() == DIGITS && code.bytes().all(|byte| byte.is_ascii_digit())
}

/// A code as typed, with the spaces and dashes apps group it with taken
/// out.
#[must_use]
pub fn normalize_code(typed: &str) -> String {
    typed
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648's test vectors, without padding, and back.
    #[test]
    fn base32_is_rfc_4648() {
        for (bytes, text) in [
            ("", ""),
            ("f", "MY"),
            ("fo", "MZXQ"),
            ("foo", "MZXW6"),
            ("foob", "MZXW6YQ"),
            ("fooba", "MZXW6YTB"),
            ("foobar", "MZXW6YTBOI"),
        ] {
            assert_eq!(encode_secret(bytes.as_bytes()), text);
            assert_eq!(decode_secret(text).as_deref(), Some(bytes.as_bytes()));
            assert_eq!(
                decode_secret(&text.to_lowercase()).as_deref(),
                Some(bytes.as_bytes())
            );
        }
        assert_eq!(
            decode_secret("MZXW 6YTB OI======").as_deref(),
            Some(&b"foobar"[..])
        );
        assert_eq!(decode_secret("MZXW1"), None, "1 is no base32");
        assert_eq!(decode_secret("MZ"), None, "non-zero leftover bits");
        let secret = [0xa5_u8; SECRET_BYTES];
        assert_eq!(encode_secret(&secret).len(), 32);
        assert_eq!(
            decode_secret(&encode_secret(&secret)).as_deref(),
            Some(&secret[..])
        );
    }

    #[test]
    fn the_uri_names_the_parameters_apps_read() {
        assert_eq!(
            otpauth_uri("JBSWY3DPEHPK3PXP", "gh-abcd2345"),
            "otpauth://totp/GhostRack:gh-abcd2345?secret=JBSWY3DPEHPK3PXP&issuer=GhostRack&algorithm=SHA1&digits=6&period=30"
        );
    }

    #[test]
    fn a_code_is_six_digits() {
        assert!(is_code("012345"));
        assert!(!is_code("12345"));
        assert!(!is_code("1234567"));
        assert!(!is_code("12345a"));
        assert!(!is_code("١٢٣٤٥٦"));
        assert_eq!(normalize_code(" 123 456 "), "123456");
        assert_eq!(normalize_code("123-456"), "123456");
    }
}
