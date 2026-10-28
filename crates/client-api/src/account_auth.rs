use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

pub const DEPOSIT_MEMO_LENGTH: usize = 16;
pub const AUTH_KEY_ID_LENGTH: usize = 16;
pub const AUTH_KEY_ID_HEADER: &str = "x-gigahost-auth-key-id";
pub const REQUEST_TIMESTAMP_HEADER: &str = "x-gigahost-timestamp";
pub const REQUEST_NONCE_HEADER: &str = "x-gigahost-request-nonce";
pub const REQUEST_SIGNATURE_HEADER: &str = "x-gigahost-signature";

const DEPOSIT_MEMO_DOMAIN: &[u8] = b"GIGAHOST-DEPOSIT-MEMO-V1\0";
const AUTH_KEY_ID_DOMAIN: &[u8] = b"GIGAHOST-AUTH-KEY-ID-V1\0";
const REQUEST_DOMAIN: &str = "GIGAHOST-ACCOUNT-REQUEST-V1";
const MIGRATION_DOMAIN: &str = "GIGAHOST-ACCOUNT-SEED-MIGRATION-V1";
const BACKUP_BILLING_DOMAIN: &str = "GIGAHOST-BACKUP-BILLING-AUTHORIZATION-V1";

pub fn deposit_memo(authentication_public_key: &[u8; 32]) -> String {
    short_identifier(DEPOSIT_MEMO_DOMAIN, authentication_public_key)
}

pub fn auth_key_id(authentication_public_key: &[u8; 32]) -> String {
    short_identifier(AUTH_KEY_ID_DOMAIN, authentication_public_key)
}

fn short_identifier(domain: &[u8], public_key: &[u8; 32]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(public_key);
    let digest = hasher.finalize();
    URL_SAFE_NO_PAD.encode(&digest[..12])
}

pub fn valid_short_identifier(value: &str) -> bool {
    value.len() == DEPOSIT_MEMO_LENGTH
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

pub struct RequestSignatureInput<'a> {
    pub auth_key_id: &'a str,
    pub timestamp_unix_ms: i64,
    pub nonce: Uuid,
    pub method: &'a str,
    pub target: &'a str,
    pub body: &'a [u8],
    pub idempotency_key: Option<&'a str>,
}

pub fn canonical_request(input: &RequestSignatureInput<'_>) -> Vec<u8> {
    let body_digest = URL_SAFE_NO_PAD.encode(Sha256::digest(input.body));
    format!(
        "{REQUEST_DOMAIN}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        input.auth_key_id,
        input.timestamp_unix_ms,
        input.nonce,
        input.method,
        input.target,
        body_digest,
        input.idempotency_key.unwrap_or_default(),
    )
    .into_bytes()
}

pub struct SeedMigrationInput<'a> {
    pub current_deposit_memo: &'a str,
    pub new_deposit_memo: &'a str,
    pub new_authentication_public_key: &'a str,
    pub new_billing_public_key: &'a str,
    pub new_recovery_public_key: &'a str,
}

pub fn canonical_seed_migration(input: &SeedMigrationInput<'_>) -> Vec<u8> {
    format!(
        "{MIGRATION_DOMAIN}\n{}\n{}\n{}\n{}\n{}",
        input.current_deposit_memo,
        input.new_deposit_memo,
        input.new_authentication_public_key,
        input.new_billing_public_key,
        input.new_recovery_public_key,
    )
    .into_bytes()
}

pub struct BackupBillingAuthorizationInput<'a> {
    pub operation: &'a str,
    pub instance_id: Uuid,
    pub backup_id: Option<Uuid>,
    pub destination: &'a str,
    pub pricing_revision: u64,
    pub maximum_charge_microusd: u64,
    pub idempotency_key: &'a str,
}

pub fn canonical_backup_billing_authorization(
    input: &BackupBillingAuthorizationInput<'_>,
) -> Vec<u8> {
    format!(
        "{BACKUP_BILLING_DOMAIN}\n{}\n{}\n{}\n{}\n{}\n{}\n{}",
        input.operation,
        input.instance_id,
        input
            .backup_id
            .map_or_else(String::new, |id| id.to_string()),
        input.destination,
        input.pricing_revision,
        input.maximum_charge_microusd,
        input.idempotency_key,
    )
    .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_url_safe_and_domain_separated() {
        let key = [7_u8; 32];
        let memo = deposit_memo(&key);
        let auth_key = auth_key_id(&key);
        assert_eq!(memo.len(), 16);
        assert_eq!(auth_key.len(), 16);
        assert_ne!(memo, auth_key);
        assert!(valid_short_identifier(&memo));
    }

    #[test]
    fn request_signature_binds_body_and_target() {
        let base = RequestSignatureInput {
            auth_key_id: "ponmlkjihgfedcba",
            timestamp_unix_ms: 1,
            nonce: Uuid::nil(),
            method: "POST",
            target: "/example",
            body: b"one",
            idempotency_key: Some("stable-key"),
        };
        let first = canonical_request(&base);
        let changed = canonical_request(&RequestSignatureInput {
            body: b"two",
            ..base
        });
        assert_ne!(first, changed);
    }

    #[test]
    fn backup_billing_authorization_binds_resource_price_and_retry_identity() {
        let base = BackupBillingAuthorizationInput {
            operation: "restore_backup",
            instance_id: Uuid::nil(),
            backup_id: Some(Uuid::from_u128(1)),
            destination: "gigahost_s3",
            pricing_revision: 7,
            maximum_charge_microusd: 42,
            idempotency_key: "stable-mutation-key",
        };
        assert_ne!(
            canonical_backup_billing_authorization(&base),
            canonical_backup_billing_authorization(&BackupBillingAuthorizationInput {
                maximum_charge_microusd: 43,
                ..base
            })
        );
        assert_ne!(
            canonical_backup_billing_authorization(&base),
            canonical_backup_billing_authorization(&BackupBillingAuthorizationInput {
                destination: "local",
                ..base
            })
        );
        assert_ne!(
            canonical_backup_billing_authorization(&base),
            canonical_backup_billing_authorization(&BackupBillingAuthorizationInput {
                pricing_revision: 8,
                ..base
            })
        );
    }
}
