use crate::compatibility::{known, known_option};
use crate::hypervisor::{
    CpuTier, GuestFirmware, GuestInitializationStatus, HostMode, ImageCacheState, PowerState,
    RestartPolicy, StorageBackend, StorageDeviceInventory,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ActivateAccountRequest {
    pub authentication_public_key: String,
    pub billing_public_key: String,
    pub recovery_public_key: String,
}

/// A trial claim, made (`CreateTrialClaim`): the browser opens
/// `claim_url` before `expires_at` to sign in with GitHub, and the client
/// polls the claim (`GetTrialClaim`) for the account it creates.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrialClaimView {
    /// 128 random bits, base64url: the claim's only name, spent once.
    pub claim_id: String,
    pub claim_url: String,
    pub expires_at: DateTime<Utc>,
}

/// Where a trial claim stands.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TrialClaimStatus {
    /// Waiting for the GitHub sign-in, or for GitHub's answer.
    Pending,
    /// The account was created.
    Created,
    /// The GitHub account was linked to the account (a link's claim).
    Linked,
    /// The claim was refused, for `reason`.
    Refused,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

/// What became of a trial claim (`GetTrialClaim`, and the answer of the
/// GitHub sign-in's return, `CompleteTrialClaim`).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TrialClaimStatusView {
    #[serde(deserialize_with = "known")]
    pub status: TrialClaimStatus,
    /// The account created, once it is; for a link's claim, from the
    /// start, the account it links to, which the claim's page names before
    /// the sign-in.
    #[serde(default)]
    pub account_alias: Option<String>,
    /// Why the claim was refused, when it was.
    #[serde(default)]
    pub reason: Option<String>,
    pub expires_at: DateTime<Utc>,
    /// GitHub's sign-in URL for the claim while it waits. Open `claim_url`
    /// to confirm the claim's purpose before signing in.
    #[serde(default)]
    pub authorize_url: Option<String>,
    /// What the GitHub sign-in is for: a new account, or a link to one. A
    /// backend older than the link answers none: a sign-up.
    #[serde(default, deserialize_with = "known")]
    pub purpose: GithubClaimPurpose,
    /// Whether the trial credit came with it: for a sign-up or a link only
    /// when trials are open and the GitHub account qualifies (old enough,
    /// never given the credit). A sign-up without it still creates the
    /// account, with a $0 balance.
    #[serde(default)]
    pub trial_credit: bool,
    /// Why a sign-up that created the account, or a link, came without the trial credit (trials
    /// closed, the GitHub account too young or given the credit before, the platform's credits of
    /// the hour all given), as a phrase. None otherwise, for a link to an account that had a trial,
    /// and from older backends that do not report the reason.
    #[serde(default)]
    pub trial_credit_refusal: Option<String>,
    /// The login name of the GitHub account the claim created the account
    /// with or linked, as GitHub named it at the sign-in, once it did: a
    /// claim's link is a bearer link, and its owner reads here whose GitHub
    /// account completed it. A backend older than the link answers none.
    #[serde(default)]
    pub github_login: Option<String>,
}

/// What the GitHub sign-in's return made of a claim (`CompleteTrialClaim`,
/// the website's own route): the claim as `GetTrialClaim` reads it and,
/// when this return created the account (a sign-up's claim), a website
/// session for it, which the website sets as a GitHub login's: the browser
/// that comes back from GitHub has just proved the GitHub account the new
/// account is linked to. A link's claim, a claim spent before and a backend
/// older than the session answer none. `GetTrialClaim` and
/// `GetGithubClaim`, which the clients poll, never carry it.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CompletedTrialClaimView {
    #[serde(flatten)]
    pub claim: TrialClaimStatusView,
    #[serde(default)]
    pub session: Option<RedeemLoginGrantResponse>,
}

/// What a GitHub sign-in's claim is for.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GithubClaimPurpose {
    /// A new account, made at sign-in.
    #[default]
    Signup,
    /// A link of the GitHub account to the account whose owner key signed
    /// the claim (`CreateGithubLink`).
    Link,
    /// A purpose of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

/// The GitHub account linked to the account (`GetAccount`): its login name
/// as last seen, and when it was linked.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountGithubView {
    pub login: String,
    pub linked_at: DateTime<Utc>,
}

/// What unlinking GitHub did (`UnlinkGithub`).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GithubUnlinked {
    /// Whether a GitHub account was linked and is unlinked now; false when
    /// none was.
    pub unlinked: bool,
    /// The website sessions a GitHub login began, which end with it.
    pub ended_sessions: u32,
}

/// A GitHub login's start (`StartGithubLogin`, public): GitHub's sign-in
/// URL, valid until `expires_at` (10 minutes). The website keeps `nonce` in
/// a cookie and sends it back with GitHub's return to prevent login CSRF.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GithubLoginStart {
    pub authorize_url: String,
    /// 16 random bytes in base64url without padding.
    pub nonce: String,
    pub expires_at: DateTime<Utc>,
}

/// GitHub's return to a login (`GithubLogin`, public): the OAuth `state`,
/// the code GitHub gave, and the nonce the browser kept.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GithubLoginRequest {
    pub state: String,
    pub code: String,
    pub nonce: String,
}

/// The length of a GitHub login's OAuth state (36 bytes in base64url),
/// which tells it from a claim's ID (22) when GitHub sends the browser
/// back.
pub const GITHUB_LOGIN_STATE_LENGTH: usize = 48;

/// The GitHub sign-in's return (`CompleteTrialClaim`): the claim's ID
/// (the OAuth `state` without the website's nonce), and the code GitHub
/// gave.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteTrialClaimRequest {
    pub state: String,
    pub code: String,
}

/// The account's trial, in its balance (`GetAccountBalance`).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountTrialView {
    /// What is left of the trial credit while it is live, which every
    /// charge draws first; 0 once it ended.
    pub credit_left_microusd: i64,
    pub expires_at: DateTime<Utc>,
    /// Whether the trial's limits hold: until a deposit lifts them.
    pub limited: bool,
    /// When the credit ended: expired, or ended by the operator.
    #[serde(default)]
    pub ended_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountView {
    pub account_alias: String,
    pub deposit_memo: String,
    pub key_epoch: u64,
    pub status: String,
    /// The account's website password, when one is set (`GetAccount`);
    /// `None` when none is, and in the answers of activation and of a move
    /// to another account key, which ends it.
    #[serde(default)]
    pub website_password: Option<WebsitePasswordView>,
    /// The GitHub account linked to it (`GetAccount`), if one is; `None`
    /// in the answers of activation and of a move to another account key.
    #[serde(default)]
    pub github: Option<AccountGithubView>,
    /// The operator's suspension of the account, while one holds
    /// (`GetAccount`); `None` otherwise, and from older backends.
    #[serde(default)]
    pub suspension: Option<AccountSuspensionView>,
}

/// Why the operator suspended an account: the facts and the rule they
/// break. A suspended account reads everything and changes nothing but
/// its support tickets, its notifications and its sessions.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccountSuspensionView {
    pub reason: String,
    pub rule: String,
    pub suspended_at: DateTime<Utc>,
}

/// Who sent a request: the account, its role and provider profile, the key
/// behind the request, and the website session it came with.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountSessionView {
    pub account_alias: String,
    /// Whether the account holds the operator role, which the operator
    /// endpoints require.
    pub is_operator: bool,
    /// The account's provider profile, when it has one.
    pub provider_id: Option<Uuid>,
    /// The key that signed the request, or for a website session the key
    /// whose login link began it.
    pub auth_key_id: String,
    /// The website session the request came with; `None` for a request
    /// signed with an account key, which has none.
    pub session: Option<WebsiteSessionView>,
    /// Whether the account is a trial whose limits hold (no deposit yet):
    /// it rents only 1 vCPU instances with a shared IP on the trial hosts.
    /// Absent from older backends.
    #[serde(default)]
    pub trial_limited: bool,
    /// The operator's suspension of the account, while one holds; absent
    /// otherwise, and from older backends.
    #[serde(default)]
    pub suspension: Option<AccountSuspensionView>,
}

/// A website session of the account.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebsiteSessionView {
    pub session_id: Uuid,
    pub created_at: DateTime<Utc>,
    /// When the session ends at the latest, unless it is revoked first: the
    /// end its login set, or sooner for the operator.
    pub expires_at: DateTime<Utc>,
    /// When it was last used, to the minute; the website's live updates do
    /// not count. `None` until its first use is recorded.
    #[serde(default)]
    pub last_used_at: Option<DateTime<Utc>>,
    /// When it ends unless it is used before then (the idle timeout).
    #[serde(default)]
    pub idle_expires_at: Option<DateTime<Utc>>,
}

/// A website session of the account that still works, as the account's
/// session list shows it.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ActiveSessionView {
    pub session_id: Uuid,
    pub created_at: DateTime<Utc>,
    /// When it ends at the latest, unless it is revoked first.
    pub expires_at: DateTime<Utc>,
    /// When it was last used, to the minute; the website's live updates do
    /// not count. `None` until its first use is recorded.
    pub last_used_at: Option<DateTime<Utc>>,
    /// When it ends unless it is used before then (the idle timeout).
    pub idle_expires_at: DateTime<Utc>,
    /// The account key whose login link began it, or which set the
    /// website password it began with.
    pub auth_key_id: String,
    /// Whether it is the session the request came with.
    pub current: bool,
    /// How it began: `link` (a login link), `password` (the website
    /// password) or `github` (a GitHub login). A backend older than the
    /// password answers none: `link`.
    #[serde(default = "link_origin")]
    pub origin: String,
}

/// The origin of a session a backend names none of: a login link, the
/// only way one began before the website password.
fn link_origin() -> String {
    "link".to_owned()
}

/// One rental of a provider's host, as its usage page names it.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderRentalView {
    pub instance_id: Uuid,
    pub hostname: String,
    pub state: String,
    pub vcpu_count: u32,
    pub memory_bytes: u64,
    pub root_disk_bytes: u64,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HistoryPage {
    pub items: Vec<serde_json::Value>,
    pub next_cursor: Option<String>,
    /// An instance's monthly projection, beside its renter's usage
    /// (`GetInstanceUsage`) and on no other page. Absent from older
    /// backends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection: Option<InstanceProjectionView>,
}

/// What a ledger transaction records, as each item of the account history
/// names it (`kind`) and the history's `kind` filter takes it.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[cfg_attr(feature = "clap", value(rename_all = "snake_case"))]
pub enum LedgerKind {
    Deposit,
    Usage,
    NetworkUsage,
    BackupStorage,
    GatewayCharge,
    /// A cloud rental's monthly charge for its address.
    AddressCharge,
    HostCreation,
    InstanceCreation,
    BackupCreation,
    BackupRestore,
    SlaCredit,
    Payout,
    Adjustment,
    ReservationHold,
    ReservationRelease,
    ReservationForfeit,
    Refund,
    /// A trial's credit, granted by the platform.
    TrialCredit,
    /// What was left of a trial's credit, taken back at its end.
    TrialExpiry,
    /// A closed account's balance, refunded as a payout.
    RenterRefund,
    /// A closed account's balance below the minimum refund, or above a
    /// withdrawal's cap, which is not paid out.
    RefundForfeit,
    /// A closed account's SLA credit, given back to its provider.
    SlaCreditReturn,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    #[cfg_attr(feature = "clap", value(skip))]
    Unknown,
}

/// What a website request asks the CLI to approve: the operations only the
/// seed can carry out, a hosted backup's restore over its instance or into
/// a new one, since only the seed's recovery key decrypts a hosted backup.
/// A website session does everything else itself.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BrowserOperation {
    RestoreBackup {
        instance_id: Uuid,
        backup_id: Uuid,
    },
    CreateFromBackup {
        offering_id: String,
        backup_id: Uuid,
        gateway_tier: Option<GatewayTier>,
        hostname: Option<String>,
        /// The new instance's name ([`InstanceView::name`]); its hostname
        /// when absent, as from a website of before.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        /// The new instance's tags ([`CreateInstanceRequest::tags`]); the
        /// backup's instance's when absent, as from a website of before.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tags: Option<Vec<String>>,
    },
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

/// A [`BrowserOperation`] as a website session asks for it: it refuses a
/// kind, a field and a gateway tier it does not know, as the request did
/// before `ghost` read the operation with a fallback.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrowserOperationInput {
    RestoreBackup {
        instance_id: Uuid,
        backup_id: Uuid,
    },
    CreateFromBackup {
        offering_id: String,
        backup_id: Uuid,
        #[serde(default, deserialize_with = "known_option")]
        gateway_tier: Option<GatewayTier>,
        hostname: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        tags: Option<Vec<String>>,
    },
}

impl From<BrowserOperationInput> for BrowserOperation {
    fn from(input: BrowserOperationInput) -> Self {
        match input {
            BrowserOperationInput::RestoreBackup {
                instance_id,
                backup_id,
            } => Self::RestoreBackup {
                instance_id,
                backup_id,
            },
            BrowserOperationInput::CreateFromBackup {
                offering_id,
                backup_id,
                gateway_tier,
                hostname,
                name,
                tags,
            } => Self::CreateFromBackup {
                offering_id,
                backup_id,
                gateway_tier,
                hostname,
                name,
                tags,
            },
        }
    }
}

/// Bind a browser operation intent to the job that carried it out.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CompleteOperationIntentRequest {
    pub job_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BrowserOperationView {
    pub intent_id: Uuid,
    pub operation: BrowserOperation,
    pub expires_at: DateTime<Utc>,
    pub started_job_id: Option<Uuid>,
    pub completed_job_id: Option<Uuid>,
    /// Why the backend refused the last attempt to carry the request out,
    /// while no job has started. Absent from older backends.
    #[serde(default)]
    pub refusal: Option<BrowserOperationRefusalView>,
}

/// The error the backend answered an attempt to carry out an approved
/// browser operation with, as the CLI got it.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BrowserOperationRefusalView {
    pub code: String,
    pub message: String,
    pub refused_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountActivationTerms {
    pub deposit_address: String,
    pub minimum_deposit_mmx_atomic: u64,
    pub minimum_confirmations: u32,
    /// Current public quote for funding/payout estimates. Missing on older servers.
    #[serde(default)]
    pub mmx_exchange_rate: Option<MmxExchangeRateView>,
    /// The trial credit a GitHub sign-up comes with while trials are open
    /// (when the GitHub account qualifies); none while they are closed,
    /// when a sign-up makes the account without credit, and from older
    /// servers.
    #[serde(default)]
    pub trial_credit_microusd: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MmxExchangeRateView {
    /// Exact decimal USD per whole MMX (also micro-USD per atomic MMX).
    pub usd_per_mmx: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LoginGrant {
    pub login_url: String,
    pub expires_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedeemLoginGrantRequest {
    pub token: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RedeemLoginGrantResponse {
    pub session_token: String,
    pub expires_at: DateTime<Utc>,
}

/// The account's website password, as the account sees it: when it was
/// set, and when it expires if the account chose an expiry. The password
/// itself is never stored; see [`crate::website_password`].
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebsitePasswordView {
    pub created_at: DateTime<Utc>,
    /// `None`: it does not expire.
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

/// Sets the account's website password, or replaces it
/// (`SetWebsitePassword`, signed with the account key): only the public key
/// the client derived from the password it generated
/// ([`crate::website_password::signing_key`]).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetWebsitePasswordRequest {
    /// The Ed25519 public key, 32 bytes in base64url without padding.
    pub public_key: String,
    /// Days until the password stops logging in, 1 to 3650; it never
    /// expires when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_in_days: Option<u32>,
}

/// The longest expiry a website password may have, in days (10 years).
pub const MAX_WEBSITE_PASSWORD_DAYS: u32 = 3650;

/// What removing the website password did (`RemoveWebsitePassword`).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct WebsitePasswordRemoved {
    /// Whether a password was set and is removed now; false when none was.
    pub removed: bool,
}

/// Asks for a password login's challenge (`CreatePasswordChallenge`,
/// public). Any well-formed alias gets one, whether an account has it or
/// not.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordChallengeRequest {
    pub account_alias: String,
}

/// A password login's opaque challenge: 32 bytes, single use, until
/// `expires_at` (60 seconds). A client signs the bytes as given.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PasswordChallenge {
    /// The 32 bytes in base64url without padding.
    pub challenge: String,
    pub expires_at: DateTime<Utc>,
}

/// Logs in with the website password (`PasswordLogin`, public): the
/// challenge and the signature of
/// [`crate::website_password::login_message`] over the alias, the website's
/// origin and the challenge, by the key derived from the password.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordLoginRequest {
    pub account_alias: String,
    /// The challenge as [`PasswordChallenge::challenge`] gave it.
    pub challenge: String,
    /// The Ed25519 signature, 64 bytes in base64url without padding.
    pub signature: String,
}

/// What a logout or a revocation of every website session ended.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SessionRevocationView {
    /// Active website sessions that no longer authenticate.
    pub revoked_sessions: u32,
    /// Unused login grants that can no longer be redeemed.
    pub cancelled_login_grants: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrateAccountSeedRequest {
    pub new_authentication_public_key: String,
    pub new_billing_public_key: String,
    pub new_recovery_public_key: String,
    pub new_key_signature: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountAuthKeyView {
    pub key_id: String,
    pub kind: String,
    pub label: String,
    pub capabilities: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

/// An SSH public key the account saved for new instances: the website
/// offers every saved key, checked, when an instance is rented or
/// reinstalled, and the CLI installs every saved key unless the keys are
/// named on its command line. The keys chosen are copied into the instance
/// when it is made, so a later change here changes no existing instance.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountSshKeyView {
    pub ssh_key_id: Uuid,
    /// The owner's name for it, such as the machine it belongs to.
    pub label: String,
    /// The OpenSSH public key line, as `authorized_keys` takes it.
    pub public_key: String,
    /// Its type, such as `ssh-ed25519`.
    pub key_type: String,
    /// Its SHA-256 fingerprint as `ssh-keygen -l` shows it:
    /// `SHA256:` and the base64 digest of the key blob, without padding.
    pub fingerprint: String,
    pub created_at: DateTime<Utc>,
}

/// Save an SSH public key in the account, under a label of its own.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AddAccountSshKeyRequest {
    pub label: String,
    pub public_key: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateHostEnrollmentTokenRequest {
    pub label: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostEnrollmentToken {
    pub token: String,
    pub expires_at: DateTime<Utc>,
}

/// The query of `GET /v1/catalog/offerings` (`ListOfferings`): catalog
/// filters and pagination. An unreadable value receives 400 `invalid_query`;
/// unknown parameters are ignored. Serialization omits absent fields and
/// keeps field order.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct OfferingFilters {
    /// A provider by its ID or its owner's account alias, in any case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// A location code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// A two-letter ISO country code, in any case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// A continent code (`AF`, `AN`, `AS`, `EU`, `NA`, `OC`, `SA`), in any
    /// case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continent: Option<String>,
    #[serde(
        default,
        deserialize_with = "known_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub mode: Option<HostMode>,
    /// Which address the list prices, orders by and offers: absent is
    /// [`IpChoice::Dedicated`]; [`IpChoice::Any`] lists every offering,
    /// and [`IpChoice::SharedReference`] every offering at the platform's
    /// shared IP price. The cursor `after` is the price of this choice.
    #[serde(
        default,
        deserialize_with = "known_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub ip: Option<IpChoice>,
    /// Which offerings by what they can be rented as: absent is
    /// [`KindChoice::Vm`], the offerings a VM can take, as every client of
    /// before reads the list; [`KindChoice::Container`] those a container
    /// instance can take; [`KindChoice::Any`] every offering.
    #[serde(
        default,
        deserialize_with = "known_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub kind: Option<KindChoice>,
    #[serde(
        default,
        deserialize_with = "known_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub cpu_tier: Option<CpuTier>,
    /// At least one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_vcpus: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_memory_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_root_disk_bytes: Option<u64>,
    /// At least one: only offerings of which this many instances can be
    /// rented now ([`OfferingView::available_instances`], with `host_id`
    /// that host's count).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_available: Option<u32>,
    /// The offerings of this host, each with the count of instances that
    /// host alone can admit ([`OfferingView::available_instances`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_id: Option<Uuid>,
    /// How many to list, 1 to [`OfferingFilters::MAXIMUM_LIMIT`] (that
    /// many without it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    /// Where the page starts: after the offering of this listed price and
    /// ID, the last one the page before listed, as `PRICE.ID`
    /// ([`OfferingFilters::after`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
}

impl OfferingFilters {
    /// The most offerings one page lists, and how many it lists without a
    /// `limit`.
    pub const MAXIMUM_LIMIT: usize = 500;

    /// No filter but the address: every offering, whichever address it
    /// has ([`IpChoice::Any`]). What a page reads that means all of a
    /// host's or a provider's offerings, narrowed by the filters it then
    /// sets: without `ip` a list holds the dedicated ones alone, so an
    /// offering that only has a shared IP would be missing.
    #[must_use]
    pub fn of_any_ip() -> Self {
        Self {
            ip: Some(IpChoice::Any),
            ..Self::default()
        }
    }

    /// The `after` of the page that follows the offering of `price` (its
    /// [`OfferingView::price_for`] of the [`OfferingFilters::ip`] asked
    /// for) and `id`.
    #[must_use]
    pub fn after(price: u64, id: &str) -> String {
        format!("{price}.{id}")
    }
}

/// Which kind of public address a catalog list prices and offers
/// ([`OfferingFilters::ip`]).
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[cfg_attr(feature = "clap", value(rename_all = "snake_case"))]
pub enum IpChoice {
    /// An address of the instance's own (a cloud host's address, a home
    /// offering's default gateway); the default.
    #[default]
    Dedicated,
    /// A slice of a shared address: a range of its ports.
    Shared,
    /// Either: every offering that has an address of one kind or the
    /// other, priced and ordered by its listed price
    /// ([`OfferingView::listed_price_microusd_per_month`]), as the catalog
    /// listed before this filter existed. For a reader that means all of
    /// a host's or a provider's offerings, a cloud offering whose hosts
    /// have no address left among them; the Capacity page and the CLI
    /// choose dedicated or shared.
    #[cfg_attr(feature = "clap", value(skip))]
    Any,
    /// Every offering, priced and ordered by the shared IP's cost, which the platform fixes
    /// ([`OfferingView::shared_ip_reference_microusd_per_month`]), also one that has no shared IP
    /// now: the website's Capacity list, whose renter then chooses the address on the offering's
    /// page. The strict list of the offerings that have a shared IP is [`IpChoice::Shared`]'s. Older
    /// backends refuse it with 400, as any value they do not know.
    #[cfg_attr(feature = "clap", value(skip))]
    SharedReference,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    #[cfg_attr(feature = "clap", value(skip))]
    Unknown,
}

/// What an instance is: a VM booting an operating system's image, or a container instance, a VM of
/// its own that boots the platform's kernel and init and runs a container image. An offering lists
/// which it can be rented as ([`OfferingView::kinds`]).
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[cfg_attr(feature = "clap", value(rename_all = "snake_case"))]
pub enum InstanceKind {
    /// What an instance of before is, and what a request that names no
    /// kind creates.
    #[default]
    Vm,
    Container,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    #[cfg_attr(feature = "clap", value(skip))]
    Unknown,
}

/// Which offerings a catalog list holds by what they can be rented as
/// ([`OfferingFilters::kind`]).
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[cfg_attr(feature = "clap", value(rename_all = "snake_case"))]
pub enum KindChoice {
    /// The offerings a VM can take; the default, so a client of before
    /// lists what it can rent.
    #[default]
    Vm,
    /// The offerings a container instance can take.
    Container,
    /// Every offering.
    Any,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    #[cfg_attr(feature = "clap", value(skip))]
    Unknown,
}

impl KindChoice {
    /// Whether an offering with `kinds` matches this choice. An offering
    /// without kinds is treated as a VM offering for compatibility.
    #[must_use]
    pub fn admits(self, kinds: &[InstanceKind]) -> bool {
        let has = |kind| kinds.contains(&kind) || (kinds.is_empty() && kind == InstanceKind::Vm);
        match self {
            Self::Vm => has(InstanceKind::Vm),
            Self::Container => has(InstanceKind::Container),
            Self::Any => true,
            Self::Unknown => false,
        }
    }
}

/// The query of `GET /v1/catalog/locations` (`ListLocations`), each field a
/// parameter of its name; as [`OfferingFilters`].
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct LocationFilters {
    /// A two-letter ISO country code, in any case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    /// A continent code, in any case.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continent: Option<String>,
    /// `true`: only the locations the catalog lists an offering in now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listed: Option<bool>,
}

/// The query of `GET /v1/account/notifications` (`ListNotifications`),
/// each field a parameter of its name: a page of the inbox. The backend
/// refuses a parameter it does not know (400, `invalid_query`); serialized,
/// absent fields are left out.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NotificationFilters {
    /// At most this many, 1 to 500 (a value outside is taken as the
    /// nearest); 100 by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u16>,
    /// Only notifications older than this one, to page back through the
    /// inbox.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub before: Option<Uuid>,
}

/// A period of the account's and a provider's totals: a UTC hour, day or
/// month.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TotalsPeriod {
    Hour,
    #[default]
    Day,
    Month,
}

impl TotalsPeriod {
    /// The period as the query names it.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Hour => "hour",
            Self::Day => "day",
            Self::Month => "month",
        }
    }
}

/// The query of `GET /v1/account/history/totals` (`AccountHistoryTotals`),
/// each field a parameter of its name: a page of the account's totals by
/// period, optionally of one instance or one kind of transaction, and
/// without a kind optionally without the reservations' holds and releases.
/// The backend refuses a parameter it does not know and a value it cannot
/// read (400, `invalid_query`); serialized, absent fields (and
/// `hide_reservations` when false) are left out, in the order of the
/// fields.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryTotalsQuery {
    pub period: TotalsPeriod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<Uuid>,
    #[serde(
        default,
        deserialize_with = "known_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub kind: Option<LedgerKind>,
    /// Where the page starts: the `next_cursor` of the page before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// How many, 1 to 200; 50 by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// `true`: without a `kind`, leaves out reservation hold and release
    /// totals (`reservation_hold`, `reservation_release`); forfeits stay.
    /// Ignored with a `kind`. False by default. Field order preserves the
    /// API's unknown-parameter diagnostic.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hide_reservations: bool,
    /// Leaves out totals whose credit or charge is less than this many
    /// microdollars. A filtered page may have fewer than `limit` items and still
    /// have a `next_cursor`. None or 0 includes every total.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_amount_microusd: Option<u64>,
}

/// The query of a page of a history the account reads newest first
/// (`AccountDeposits`, `AccountSlaCredits` and others), each field a
/// parameter of its name. The backend ignores a parameter it does not
/// know and refuses a value it cannot read (400, `invalid_query`);
/// serialized, absent fields are left out.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct PageQuery {
    /// Where the page starts: the `next_cursor` of the page before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// How many, 1 to 200; 50 by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// Instance IDs as a query parameter names several: separated by commas.
fn comma_separated(ids: &[Uuid]) -> String {
    ids.iter()
        .map(Uuid::to_string)
        .collect::<Vec<_>>()
        .join(",")
}

/// The query of `GET /v1/instances` (`ListInstances`), each field a
/// parameter of its name: a window of the account's instances in the order
/// `sort` and `order` give (the newest first by default), those that are
/// not deleted unless `state` asks for them, and those the filters keep;
/// or with `ids` those it names, deleted or not. The backend refuses a
/// parameter it does not know and a value it cannot read (400,
/// `invalid_query`), and `ids` beside any other; serialized, absent fields
/// are left out, in the order of the fields, and `state` and `tag` are
/// repeated once for each of their values (`state=running&state=stopped`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InstanceListQuery {
    /// The instances to read: 1 to 100 IDs separated by commas
    /// ([`InstanceListQuery::named`]).
    pub ids: Option<String>,
    /// How many, 1 to 500; 500 by default.
    pub limit: Option<u32>,
    /// Those listed after this one of the account, in the list's order.
    pub before: Option<Uuid>,
    /// Only the instances in these states, as stored: a running or stopped
    /// instance a restore is rebuilding is listed `provisioning` but kept
    /// by its stored state (`busy` finds it). Every state but deleted when
    /// empty.
    pub state: Vec<InstanceStateFilter>,
    /// Only those with a job under way (`true`), or without one (`false`):
    /// any job the instance's state shows (a creation, an upgrade, a restore, a
    /// backup, ...).
    pub busy: Option<bool>,
    /// Only those whose host is in this location (its code).
    pub location: Option<String>,
    /// Only those of this provider, by its alias, in any case.
    pub provider: Option<String>,
    /// Only those on home or on cloud hosts.
    pub mode: Option<HostModeFilter>,
    /// Only those whose root disk holds this catalog image, or that run
    /// this stock container image (its slug).
    pub image: Option<String>,
    /// Only those whose name (what the renter calls the instance, its
    /// hostname unless renamed) starts with this, in any case: 1 to 253
    /// letters, digits, hyphens and dots.
    pub name: Option<String>,
    /// Only those that carry every one of these tags ([`valid_tag`], at
    /// most [`MAXIMUM_TAG_FILTERS`]), repeated once for each.
    pub tag: Vec<String>,
    /// What the list is ordered by: the creation time by default; the
    /// price is the one it pays a month now ([`InstanceSort`]).
    pub sort: Option<InstanceSort>,
    /// Which way: the newest, costliest, largest or last name first by
    /// default.
    pub order: Option<SortOrder>,
}

impl InstanceListQuery {
    /// The fields in the order a query names them, as serde names them in
    /// its refusals.
    const FIELDS: &'static [&'static str] = &[
        "ids", "limit", "before", "state", "busy", "location", "provider", "mode", "image", "name",
        "tag", "sort", "order",
    ];

    /// The read of the instances `ids` names.
    #[must_use]
    pub fn named(ids: &[Uuid]) -> Self {
        Self {
            ids: Some(comma_separated(ids)),
            ..Self::default()
        }
    }

    /// Whether the query asks for anything but the newest current
    /// instances first: a filter or a sort an older backend refuses.
    #[must_use]
    pub fn narrowed(&self) -> bool {
        !self.state.is_empty()
            || self.busy.is_some()
            || self.location.is_some()
            || self.provider.is_some()
            || self.mode.is_some()
            || self.image.is_some()
            || self.name.is_some()
            || !self.tag.is_empty()
            || self.sort.is_some()
            || self.order.is_some()
    }
}

impl Serialize for InstanceListQuery {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(None)?;
        if let Some(ids) = &self.ids {
            map.serialize_entry("ids", ids)?;
        }
        if let Some(limit) = self.limit {
            map.serialize_entry("limit", &limit)?;
        }
        if let Some(before) = self.before {
            map.serialize_entry("before", &before)?;
        }
        for state in &self.state {
            map.serialize_entry("state", state)?;
        }
        if let Some(busy) = self.busy {
            map.serialize_entry("busy", &busy)?;
        }
        if let Some(location) = &self.location {
            map.serialize_entry("location", location)?;
        }
        if let Some(provider) = &self.provider {
            map.serialize_entry("provider", provider)?;
        }
        if let Some(mode) = self.mode {
            map.serialize_entry("mode", &mode)?;
        }
        if let Some(image) = &self.image {
            map.serialize_entry("image", image)?;
        }
        if let Some(name) = &self.name {
            map.serialize_entry("name", name)?;
        }
        for tag in &self.tag {
            map.serialize_entry("tag", tag)?;
        }
        if let Some(sort) = self.sort {
            map.serialize_entry("sort", &sort)?;
        }
        if let Some(order) = self.order {
            map.serialize_entry("order", &order)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for InstanceListQuery {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = InstanceListQuery;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct InstanceListQuery")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                // Each field once, but `state` and `tag`, which repeat; a parameter
                // it does not know is refused, as the list always did.
                fn once<T, E: serde::de::Error>(
                    slot: &mut Option<T>,
                    name: &'static str,
                    value: T,
                ) -> Result<(), E> {
                    if slot.is_some() {
                        return Err(E::duplicate_field(name));
                    }
                    *slot = Some(value);
                    Ok(())
                }
                let mut query = InstanceListQuery::default();
                while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
                    match key.as_ref() {
                        "ids" => once(&mut query.ids, "ids", map.next_value()?)?,
                        "limit" => once(&mut query.limit, "limit", map.next_value()?)?,
                        "before" => once(&mut query.before, "before", map.next_value()?)?,
                        "state" => query.state.push(map.next_value()?),
                        "busy" => once(&mut query.busy, "busy", map.next_value()?)?,
                        "location" => once(&mut query.location, "location", map.next_value()?)?,
                        "provider" => once(&mut query.provider, "provider", map.next_value()?)?,
                        "mode" => once(&mut query.mode, "mode", map.next_value()?)?,
                        "image" => once(&mut query.image, "image", map.next_value()?)?,
                        "name" => once(&mut query.name, "name", map.next_value()?)?,
                        "tag" => query.tag.push(map.next_value()?),
                        "sort" => once(&mut query.sort, "sort", map.next_value()?)?,
                        "order" => once(&mut query.order, "order", map.next_value()?)?,
                        other => {
                            return Err(serde::de::Error::unknown_field(
                                other,
                                InstanceListQuery::FIELDS,
                            ));
                        }
                    }
                }
                Ok(query)
            }
        }

        deserializer.deserialize_struct("InstanceListQuery", InstanceListQuery::FIELDS, Visitor)
    }
}

/// A state the account's instance list keeps (`state=` of
/// [`InstanceListQuery`]): each of an instance's states as stored.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[cfg_attr(feature = "clap", value(rename_all = "snake_case"))]
pub enum InstanceStateFilter {
    Running,
    Stopped,
    Provisioning,
    PendingPayment,
    Deleting,
    Failed,
    Deleted,
}

impl InstanceStateFilter {
    /// Every filter, in the order a list offers them.
    pub const ALL: [Self; 7] = [
        Self::Running,
        Self::Stopped,
        Self::Provisioning,
        Self::PendingPayment,
        Self::Deleting,
        Self::Failed,
        Self::Deleted,
    ];

    /// The filter that keeps an instance in `state`; none for a state of a
    /// newer release.
    #[must_use]
    pub const fn of(state: InstanceState) -> Option<Self> {
        match state {
            InstanceState::Running => Some(Self::Running),
            InstanceState::Stopped => Some(Self::Stopped),
            InstanceState::Provisioning => Some(Self::Provisioning),
            InstanceState::PendingPayment => Some(Self::PendingPayment),
            InstanceState::Deleting => Some(Self::Deleting),
            InstanceState::Failed => Some(Self::Failed),
            InstanceState::Deleted => Some(Self::Deleted),
            InstanceState::Unknown => None,
        }
    }

    /// The filter as a query parameter names it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Provisioning => "provisioning",
            Self::PendingPayment => "pending_payment",
            Self::Deleting => "deleting",
            Self::Failed => "failed",
            Self::Deleted => "deleted",
        }
    }
}

/// Which hosts the instances a list keeps are on (`mode=` of
/// [`InstanceListQuery`]), in [`crate::hypervisor::HostMode`]'s words: a
/// home host behind a gateway, or a cloud host.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostModeFilter {
    HomeGateway,
    CloudRouted,
}

impl HostModeFilter {
    /// The filter as a query parameter names it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HomeGateway => "home_gateway",
            Self::CloudRouted => "cloud_routed",
        }
    }
}

/// What the account's instance list is ordered by (`sort=` of [`InstanceListQuery`]): the creation
/// time; the price a month the instance pays now, as its `pricing.current` sums it (its base price
/// with the price changes in effect, a home instance's gateway base price and a cloud instance's
/// address price), which an account of more than [`MAXIMUM_PRICE_SORTED_INSTANCES`] current
/// instances is refused; the size (its vCPUs, then its RAM, then its root disk); or the name (what
/// the renter calls the instance, its hostname unless renamed), in any case, by its bytes. Ties
/// follow the sort's direction by the creation time, then the ID. Older releases sorted by the
/// base price the instance was rented at.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[cfg_attr(feature = "clap", value(rename_all = "snake_case"))]
pub enum InstanceSort {
    Age,
    Price,
    Size,
    Name,
}

/// The most current (not deleted) instances an account may have for
/// its list to be sorted by price ([`InstanceSort::Price`]).
pub const MAXIMUM_PRICE_SORTED_INSTANCES: u32 = 10_000;

impl InstanceSort {
    /// The sort as a query names it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Age => "age",
            Self::Price => "price",
            Self::Size => "size",
            Self::Name => "name",
        }
    }
}

/// The most bytes a name prefix of [`InstanceListQuery`] has: as many as
/// the longest name ([`valid_hostname`]).
pub const MAXIMUM_NAME_PREFIX_BYTES: usize = 253;

/// `prefix` as the instance list's name filter reads it: in lower case, 1
/// to [`MAXIMUM_NAME_PREFIX_BYTES`] letters, digits, hyphens and dots, the
/// characters of a name; None for anything else, which no name starts
/// with.
#[must_use]
pub fn name_prefix(prefix: &str) -> Option<String> {
    let prefix = prefix.to_ascii_lowercase();
    (!prefix.is_empty()
        && prefix.len() <= MAXIMUM_NAME_PREFIX_BYTES
        && prefix.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-' || byte == b'.'
        }))
    .then_some(prefix)
}

/// A provider of the account's instances, as the instance list's provider
/// filter offers it (`GET /v1/instances/providers`,
/// `ListInstanceProviders`): its alias, which the filter takes, and its
/// name.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InstanceProviderView {
    pub provider_id: Uuid,
    /// The provider's alias (its owner's account alias, `gh-…`).
    pub alias: String,
    pub name: String,
}

/// A location of the account's instances, as the instance list's
/// location filter offers it (`GET /v1/instances/locations`,
/// `ListInstanceLocations`): its code, which the filter takes, its name
/// and its country.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InstanceLocationView {
    pub location: String,
    pub display_name: String,
    pub country_code: String,
}

/// A system the account's instances run, as the instance list's system
/// filter offers it (`GET /v1/instances/systems`, `ListInstanceSystems`):
/// a catalog image on a VM's root disk or a stock image a container runs,
/// by its slug, which the filter takes, and its name (a stock image the
/// platform no longer lists by its slug).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InstanceSystemView {
    pub slug: String,
    pub display_name: String,
}

/// The query of `GET /v1/instances/{id}/usage` (`GetInstanceUsage`), each
/// field a parameter of its name: a page of one instance's readings at a
/// resolution. The backend ignores a parameter it does not know and
/// refuses a value it cannot read (400, `invalid_query`), a resolution it
/// does not have among them; serialized, absent fields are left out, in
/// the order of the fields.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct UsageQuery {
    /// `current` (the newest reading, while the instance runs and its
    /// host's metrics are live), `15m` (the default), `daily` (the first
    /// page led by today so far, `in_progress`) or `monthly` (each UTC
    /// month's days summed, today's included, at most 12 months a page).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<String>,
    /// Where the page starts: the `next_cursor` of the page before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// How many, 1 to 200; 50 by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

impl UsageQuery {
    /// The first page at `resolution`.
    #[must_use]
    pub fn at(resolution: &str) -> Self {
        Self {
            resolution: Some(resolution.to_owned()),
            ..Self::default()
        }
    }
}

/// The query of `GET /v1/instances/current-usage`
/// (`ListInstancesCurrentUsage`): the instances whose current reading to
/// read, 1 to 100 IDs separated by commas. The backend refuses a parameter
/// it does not know, and the query without `ids` (400, `invalid_query`).
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CurrentUsageQuery {
    pub ids: String,
}

impl CurrentUsageQuery {
    /// The read of the instances `ids` names.
    #[must_use]
    pub fn named(ids: &[Uuid]) -> Self {
        Self {
            ids: comma_separated(ids),
        }
    }
}

/// The query of `GET /v1/instances/{id}/console-log`
/// (`GetInstanceConsoleLog`). The backend refuses a parameter it does not
/// know and a value it cannot read (400, `invalid_query`); serialized, an
/// absent field is left out.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConsoleLogQuery {
    /// The most bytes of the end of the output to return, and of the end
    /// from before the boot: 1 to [`MAXIMUM_CONSOLE_LOG_BYTES`], which is
    /// the default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes: Option<usize>,
}

/// The query of `GET /v1/jobs` (`ListJobs`), each field a parameter of its
/// name: a page of the account's jobs, newest first, optionally of one
/// instance, in one state or of one kind. The backend refuses a parameter
/// it does not know and a value it cannot read (400, `invalid_query`);
/// serialized, absent fields are left out, in the order of the fields.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct JobListQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<JobStateFilter>,
    #[serde(
        default,
        deserialize_with = "known_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub kind: Option<JobKind>,
    /// Where the page starts: the `next_cursor` of the page before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// How many, 1 to 200; 50 by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// The query of `GET /v1/backups` (`ListBackups`), each field a parameter
/// of its name: a window of the account's backups in the order `sort` and
/// `order` give (the newest first by default), the deleted ones only when
/// asked for, optionally of one instance, in some states and kept in one
/// place. The backend ignores a parameter it does not know and refuses a
/// value it cannot read (400, `invalid_query`); serialized, absent fields
/// are left out, in the order of the fields, and `state` and `tag` are
/// repeated once for each of their values (`state=queued&state=failed`).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccountBackupListQuery {
    /// How many, 1 to 500; 500 by default.
    pub limit: Option<u32>,
    /// The deleted ones too, beside the others; `state` given overrides it.
    pub include_deleted: Option<bool>,
    /// Those listed after this one of the account, in the list's order.
    pub before: Option<Uuid>,
    /// Only the backups of this instance of the account.
    pub instance_id: Option<Uuid>,
    /// Only the backups in these states; every state but deleted when
    /// empty (and deleted too with `include_deleted`).
    pub state: Vec<BackupStateFilter>,
    /// Only the backups kept there.
    pub destination: Option<BackupDestinationFilter>,
    /// Only the backups of the instances that carry every one of these
    /// tags ([`valid_tag`], at most [`MAXIMUM_TAG_FILTERS`]), repeated once
    /// for each.
    pub tag: Vec<String>,
    /// What the list is ordered by: the creation time by default.
    pub sort: Option<BackupSort>,
    /// Which way: the newest, largest or costliest first by default.
    pub order: Option<SortOrder>,
}

impl AccountBackupListQuery {
    /// The fields in the order a query names them, as serde names them in
    /// its refusals.
    const FIELDS: &'static [&'static str] = &[
        "limit",
        "include_deleted",
        "before",
        "instance_id",
        "state",
        "destination",
        "tag",
        "sort",
        "order",
    ];
}

impl Serialize for AccountBackupListQuery {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap as _;
        let mut map = serializer.serialize_map(None)?;
        if let Some(limit) = self.limit {
            map.serialize_entry("limit", &limit)?;
        }
        if let Some(include_deleted) = self.include_deleted {
            map.serialize_entry("include_deleted", &include_deleted)?;
        }
        if let Some(before) = self.before {
            map.serialize_entry("before", &before)?;
        }
        if let Some(instance_id) = self.instance_id {
            map.serialize_entry("instance_id", &instance_id)?;
        }
        for state in &self.state {
            map.serialize_entry("state", state)?;
        }
        if let Some(destination) = self.destination {
            map.serialize_entry("destination", &destination)?;
        }
        for tag in &self.tag {
            map.serialize_entry("tag", tag)?;
        }
        if let Some(sort) = self.sort {
            map.serialize_entry("sort", &sort)?;
        }
        if let Some(order) = self.order {
            map.serialize_entry("order", &order)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for AccountBackupListQuery {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = AccountBackupListQuery;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct AccountBackupListQuery")
            }

            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error> {
                // Each field once, but `state` and `tag`, which repeat.
                fn once<T, E: serde::de::Error>(
                    slot: &mut Option<T>,
                    name: &'static str,
                    value: T,
                ) -> Result<(), E> {
                    if slot.is_some() {
                        return Err(E::duplicate_field(name));
                    }
                    *slot = Some(value);
                    Ok(())
                }
                let mut query = AccountBackupListQuery::default();
                while let Some(key) = map.next_key::<std::borrow::Cow<'de, str>>()? {
                    match key.as_ref() {
                        "limit" => once(&mut query.limit, "limit", map.next_value()?)?,
                        "include_deleted" => once(
                            &mut query.include_deleted,
                            "include_deleted",
                            map.next_value()?,
                        )?,
                        "before" => once(&mut query.before, "before", map.next_value()?)?,
                        "instance_id" => {
                            once(&mut query.instance_id, "instance_id", map.next_value()?)?;
                        }
                        "state" => query.state.push(map.next_value()?),
                        "destination" => {
                            once(&mut query.destination, "destination", map.next_value()?)?;
                        }
                        "tag" => query.tag.push(map.next_value()?),
                        "sort" => once(&mut query.sort, "sort", map.next_value()?)?,
                        "order" => once(&mut query.order, "order", map.next_value()?)?,
                        _ => {
                            map.next_value::<serde::de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(query)
            }
        }

        deserializer.deserialize_struct(
            "AccountBackupListQuery",
            AccountBackupListQuery::FIELDS,
            Visitor,
        )
    }
}

/// A state the account's backup list keeps (`state=` of
/// [`AccountBackupListQuery`]): each of a backup's states but the
/// transitional ones, which `in_progress` keeps together (staging,
/// uploading, restoring and deleting).
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[cfg_attr(feature = "clap", value(rename_all = "snake_case"))]
pub enum BackupStateFilter {
    Queued,
    InProgress,
    Available,
    Failed,
    Lost,
    Deleted,
}

impl BackupStateFilter {
    /// Every filter, in the order a list offers them.
    pub const ALL: [Self; 6] = [
        Self::Queued,
        Self::InProgress,
        Self::Available,
        Self::Failed,
        Self::Lost,
        Self::Deleted,
    ];

    /// The filter that keeps a backup in `state`; none for a state of a
    /// newer release.
    #[must_use]
    pub const fn of(state: BackupState) -> Option<Self> {
        match state {
            BackupState::Queued => Some(Self::Queued),
            BackupState::Staging
            | BackupState::Uploading
            | BackupState::Restoring
            | BackupState::Deleting => Some(Self::InProgress),
            BackupState::Available => Some(Self::Available),
            BackupState::Failed => Some(Self::Failed),
            BackupState::Lost => Some(Self::Lost),
            BackupState::Deleted => Some(Self::Deleted),
            BackupState::Unknown => None,
        }
    }

    /// The filter as a query names it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::InProgress => "in_progress",
            Self::Available => "available",
            Self::Failed => "failed",
            Self::Lost => "lost",
            Self::Deleted => "deleted",
        }
    }
}

/// Where the backups a list keeps are (`destination=` of
/// [`AccountBackupListQuery`]): hosted by Gigahost, or local on their
/// instance's host.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupDestinationFilter {
    Hosted,
    Local,
}

impl BackupDestinationFilter {
    /// The filter as a query names it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Hosted => "hosted",
            Self::Local => "local",
        }
    }
}

/// What the account's backup list is ordered by (`sort=` of
/// [`AccountBackupListQuery`]): the creation time, the size, or what the
/// backup's storage costs a month. A backup without a size yet comes after
/// the others by size or by cost, either way, newest first.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[cfg_attr(feature = "clap", value(rename_all = "snake_case"))]
pub enum BackupSort {
    Age,
    Size,
    Cost,
}

impl BackupSort {
    /// The sort as a query names it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Age => "age",
            Self::Size => "size",
            Self::Cost => "cost",
        }
    }
}

/// Which way a list is sorted (`order=`): ascending, the oldest, smallest
/// or cheapest first, or descending. Ties follow the same way.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SortOrder {
    Asc,
    Desc,
}

impl SortOrder {
    /// The order as a query names it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Asc => "asc",
            Self::Desc => "desc",
        }
    }

    /// The other way.
    #[must_use]
    pub const fn reversed(self) -> Self {
        match self {
            Self::Asc => Self::Desc,
            Self::Desc => Self::Asc,
        }
    }
}

/// The query of `GET /v1/instances/{id}/backups` (`ListInstanceBackups`):
/// the deleted backups are left out unless asked for. The backend ignores
/// a parameter it does not know and refuses a value it cannot read (400,
/// `invalid_query`); serialized, an absent field is left out.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackupListQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub include_deleted: Option<bool>,
}

/// The query of `GET /v1/provider/earnings/totals`
/// (`ProviderEarningsTotals`), each field a parameter of its name: a page
/// of what the account's providers earned each period, 50 periods a page,
/// ending at the newest with earnings before the cursor. The backend
/// refuses a parameter it does not know, the query without `period`, and
/// a value it cannot read (400, `invalid_query`); serialized, an absent
/// cursor is left out, after the period.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EarningsTotalsQuery {
    pub period: TotalsPeriod,
    /// Where the page starts: the `next_cursor` of the page before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

/// The query of `GET /v1/provider/hosts` (`ListProviderHosts`), each field
/// a parameter of its name: a window of the provider's hosts by label, or
/// with `ids` those it names, or with `for_pool` the hosts a pool may serve
/// (cloud hosts neither retired nor offline), at `location` when given.
/// The backend refuses a parameter it does not know and a value it cannot
/// read (400, `invalid_query`), `ids` beside any other, and `location`
/// without `for_pool`; serialized, absent fields are left out, in the
/// order of the fields.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderHostListQuery {
    /// The hosts to read: 1 to 100 IDs separated by commas
    /// ([`ProviderHostListQuery::named`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ids: Option<String>,
    /// How many, 1 to 1000; 1000 by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Those listed after this one of the provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Uuid>,
    /// Only the hosts a pool may serve.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub for_pool: Option<bool>,
    /// Of those, the hosts at this location.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
}

impl ProviderHostListQuery {
    /// The read of the hosts `ids` names.
    #[must_use]
    pub fn named(ids: &[Uuid]) -> Self {
        Self {
            ids: Some(comma_separated(ids)),
            ..Self::default()
        }
    }
}

/// The query of `GET /v1/provider/hosts/{id}/metrics`
/// (`GetProviderHostMetrics`) and of
/// `GET /v1/provider/hosts/{id}/instances/{instance}/usage`
/// (`GetProviderHostInstanceUsage`), each field a parameter of its name: a
/// page of the host's metrics, or of one rental's usage, at a resolution.
/// The backend ignores a parameter it does not know and refuses a value it
/// cannot read (400, `invalid_query`), a resolution it does not have among
/// them; serialized, absent fields are left out, in the order of the
/// fields.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostMetricsQuery {
    /// `current`, `15m` (the default), `daily` (the first page led by
    /// today so far, `in_progress`) or `monthly` (each UTC month's days
    /// summed, today's included, at most 12 months a page).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<String>,
    /// Where the page starts: the `next_cursor` of the page before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// How many, 1 to 200; 50 by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

impl HostMetricsQuery {
    /// The page at `resolution` from `cursor` (the first without one).
    #[must_use]
    pub fn at(resolution: &str, cursor: Option<&str>) -> Self {
        Self {
            resolution: Some(resolution.to_owned()),
            cursor: cursor.map(str::to_owned),
            limit: None,
        }
    }
}

/// The query of `GET /v1/provider/ip-pools` (`ListIpPools`): the pools
/// with every address, or with `addresses=false` only their counts. The
/// backend refuses a parameter it does not know and a value it cannot read
/// (400, `invalid_query`); serialized, an absent field is left out.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IpPoolListQuery {
    /// False: the pools with their counts, without their addresses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub addresses: Option<bool>,
}

impl IpPoolListQuery {
    /// The pools with their counts, without their addresses.
    #[must_use]
    pub const fn counts() -> Self {
        Self {
            addresses: Some(false),
        }
    }
}

/// The query of `GET /v1/provider/ip-pools/{id}` (`GetIpPool`): a window
/// of the pool's addresses. Unknown parameters, unreadable values and a
/// limit outside its range receive 400 `invalid_query`. Serialization omits
/// absent fields and preserves field order for the API's diagnostic.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IpPoolQuery {
    /// The addresses after this one, by address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<std::net::Ipv4Addr>,
    /// How many addresses, 1 to the most a pool holds (and so all of them
    /// by default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// The query of `GET /v1/provider/incidents` (`ListIncidents`), each field
/// a parameter of its name: the account's providers' incidents in triage
/// order, of one state and one severity when given. The backend refuses a
/// parameter it does not know and a value it cannot read (400,
/// `invalid_query`), a state or severity it does not know among them;
/// `limit` (100 by default) is held to 1 to 500. Serialized, absent fields
/// are left out, in the order of the fields.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentListQuery {
    #[serde(
        default,
        deserialize_with = "known_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub state: Option<ProviderIncidentState>,
    #[serde(
        default,
        deserialize_with = "known_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub severity: Option<ProviderIncidentSeverity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u16>,
}

/// The query of `GET /v1/support/tickets` (`ListTickets`): the account's
/// tickets, newest change first, or with `all` the support queue of every
/// account in its order (operators only; other accounts receive 403).
/// `state` filters by state; `limit` defaults to 100 and is held to 1 to 500.
/// Unknown parameters and unreadable values receive 400 `invalid_query`.
/// Serialization omits absent fields and false `all`, preserving field order
/// for the API's diagnostic.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TicketListQuery {
    #[serde(
        default,
        deserialize_with = "known_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub state: Option<SupportTicketState>,
    /// The queue of every account, for the operator.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub all: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u16>,
}

impl TicketListQuery {
    /// The support queue of every account, of `state` when given.
    #[must_use]
    pub const fn queue(state: Option<SupportTicketState>) -> Self {
        Self {
            state,
            all: true,
            limit: None,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct LocationView {
    pub location: String,
    pub display_name: String,
    pub country_code: String,
    pub continent_code: String,
    pub latitude: f64,
    pub longitude: f64,
}

/// One host's root pool drives, and its room for the offering, in an
/// offering's detail.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OfferingHostStorage {
    pub host_id: Uuid,
    pub storage_devices: Vec<StorageDeviceInventory>,
    /// How many instances of the offering this host alone could admit now,
    /// counted as [`OfferingView::available_instances`] is, which is the
    /// sum of these over the offering's hosts. At least one for a host the
    /// offering lists. Absent (0) from older backends.
    #[serde(default)]
    pub available_instances: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OfferingView {
    /// `of2_` and 22 base64url characters, naming this offering's exact
    /// terms. Capacity is checked again when an instance is created.
    pub offering_id: String,
    pub provider_id: Uuid,
    pub provider_name: String,
    /// The provider's short public name, its owner's account alias, such
    /// as `gh-abcdefgh`. Absent from older backends.
    #[serde(default)]
    pub provider_alias: String,
    pub host_mode: HostMode,
    pub location: String,
    pub location_name: String,
    pub country_code: String,
    pub continent_code: String,
    pub measured_latency_ms: Option<u32>,
    /// Best network test readings across the offering's hosts, or absent
    /// when no host has a current result.
    #[serde(default)]
    pub network: Option<NetworkTestSummaryView>,
    /// Hosts behind this offering, for the per-host network test detail view.
    #[serde(default)]
    pub host_ids: Vec<Uuid>,
    /// The distinct hardware of the hosts behind this offering, at most
    /// four. Only `GET /v1/catalog/offerings/{offering_id}` carries them;
    /// the list answers them empty and has `memory_profiles` instead.
    #[serde(default)]
    pub hardware_profiles: Vec<crate::hypervisor::HardwareDetails>,
    /// The memory of each hardware profile, in the same order: what the
    /// lists show of the hosts' RAM. Absent from older backends.
    #[serde(default)]
    pub memory_profiles: Vec<MemoryProfile>,
    #[serde(default)]
    pub cpu_benchmark: Option<CpuBenchmarkView>,
    #[serde(default)]
    pub provider_rating_millistars: Option<u32>,
    #[serde(default)]
    pub provider_review_count: u32,
    pub cpu_model: String,
    pub cpu_tier: CpuTier,
    pub vcpu_count: u32,
    pub memory_bytes: u64,
    pub root_disk_bytes: u64,
    /// What the offering can be rented as, a VM first: a VM where its size
    /// has the platform's minimum memory and root disk of a VM
    /// (`minimum_instance_memory_bytes`, `minimum_instance_disk_bytes`)
    /// and a tier a VM takes (every one but Shared 8x), a container
    /// instance where it has their minimums
    /// (`minimum_container_memory_bytes`, `minimum_container_disk_bytes`).
    /// The renter chooses; the host, size and prices are the same. Absent
    /// from older backends, whose offerings are all a VM's.
    #[serde(default)]
    pub kinds: Vec<InstanceKind>,
    /// What the offering is shown and created as unless the renter chooses
    /// otherwise: a container instance where it is one only, or where its
    /// memory is below `container_default_below_memory_bytes` or its root
    /// disk below `container_default_below_disk_bytes`; a VM otherwise.
    /// The API itself creates a VM where a request names no kind. Absent
    /// from older backends.
    #[serde(default)]
    pub default_kind: Option<InstanceKind>,
    pub root_storage_backend: StorageBackend,
    /// The levels of the Linux software RAID below the root storage.
    pub software_raid_levels: Vec<String>,
    /// The levels of the arrays of hardware RAID controllers below the root
    /// storage: `raid1`, or `raid` where the controller does not tell the
    /// level. Such an array is one of `storage_devices`, with the transport
    /// `raid`; the drives behind it are not listed.
    #[serde(default)]
    pub hardware_raid_levels: Vec<String>,
    /// The root pool's drives of the first host in `host_ids`. Every host
    /// behind this offering has drives of the same classes
    /// ([`StorageDeviceInventory::class`]), as many, and the same RAID
    /// levels; their models and sizes may differ, and
    /// `host_storage_devices` lists each host's.
    pub storage_devices: Vec<StorageDeviceInventory>,
    /// Each host's root pool drives, in the order of `host_ids`. Only
    /// `GET /v1/catalog/offerings/{offering_id}` carries them; the list
    /// answers them empty. Absent from older backends.
    #[serde(default)]
    pub host_storage_devices: Vec<OfferingHostStorage>,
    pub base_price_microusd_per_month: u64,
    pub full_utilization_price_microusd_per_month: u64,
    /// What a cloud offering's rental pays a month for its address of its
    /// own, beside its base price, or, where its hosts have no address left
    /// for it, for its shared IP (the `shared_ip` entry of
    /// `network_prices`); 0 for a home offering, whose rentals pay their
    /// gateway. Absent from older backends.
    #[serde(default)]
    pub address_microusd_per_month: u64,
    /// User-visible traffic rates. Cloud offerings contain an entry without
    /// a gateway tier, the provider's price, while an instance gets an
    /// address of its own, and an entry of the shared IP tier while it can
    /// share its host's address instead, whose monthly base is 0
    /// (the host's fixed price includes it; its traffic is the provider's); home
    /// offerings contain one entry for each selectable gateway tier, the
    /// tier's price.
    pub network_prices: Vec<NetworkPriceView>,
    /// For a home offering, the locations with a shared gateway that has
    /// room for a shared bandwidth instance, the closest to the host first,
    /// of which the instance's creation may choose one
    /// (`gateway_location`). Without a choice the preselected one is taken:
    /// the closest whose path from the host crosses no bottleneck. If none
    /// is preselected, shared bandwidth requires an explicit location.
    #[serde(default)]
    pub gateway_locations: Vec<GatewayLocationView>,
    /// For a home offering, the gateway tiers its location has that take
    /// no new instance now: high bandwidth while the gateway pool is at its
    /// instance quota, shared IP where gateways near that take slices have
    /// none free for an instance that names no location (one whose path
    /// crosses no bottleneck). They are not in `network_prices`. Absent
    /// from older backends.
    #[serde(default)]
    pub full_gateway_tiers: Vec<GatewayTier>,
    /// For an offering whose `network_prices` or `full_gateway_tiers` list
    /// the shared IP tier, the public ports a shared IP instance gets
    /// forwarded. Absent from older backends and otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared_ip_ports: Option<u16>,
    /// The monthly shared IP charge beside the offering's base price,
    /// even when `network_prices` does not currently list shared IP: 0 on a
    /// cloud host, where it is included; on a home host, the applicable gateway
    /// shared IP price. Used by the Capacity list ([`IpChoice::SharedReference`]).
    /// Absent from older backends.
    #[serde(default)]
    pub shared_ip_reference_microusd_per_month: Option<u64>,
    /// Which backups of this offering's root every host behind it has room
    /// for while no other backups, in progress or stored, hold that room;
    /// the renter cannot choose the host. Absent from older backends.
    #[serde(default)]
    pub backup_limits: Option<OfferingBackupLimitsView>,
    pub sla_target_basis_points: u32,
    pub sla_credit_multiplier: u32,
    /// Number of equivalent physical hosts that can currently admit this configuration.
    pub available_hosts: u32,
    /// How many instances of this offering the platform could admit now,
    /// one after the other, if nothing else were rented meanwhile: the sum
    /// over its hosts of the room each has for this size alone (CPU shares
    /// and RAM per NUMA node, the root pool once per host). A cloud host
    /// that lists the size only through an address of its own counts no
    /// more than its free addresses take, the last one kept for the largest
    /// size (so a smaller size has one address fewer); a shared IP's slices
    /// and a home location's gateway room are not counted. With the
    /// catalog's `host_id` filter it is that host's count alone. As fresh
    /// as the catalog's snapshot; admission still checks a host's room at
    /// creation. Absent (0) from older backends.
    #[serde(default)]
    pub available_instances: u32,
    /// Charged once from the unlocked balance when an instance is created
    /// from this offering, from an image or a backup, and refunded when the
    /// creation fails on the platform's side.
    #[serde(default)]
    pub instance_creation_charge_microusd: u64,
    /// Held, not charged, while an instance of this offering exists, with a
    /// month of a cloud offering's address price. A home instance also
    /// holds its gateway tier's monthly base charge.
    #[serde(default)]
    pub balance_reservation_microusd: u64,
    /// Whether a trial account whose limits hold may rent it: a 1 vCPU
    /// size with a shared IP on a host the operator lists for trials. The
    /// rental's admission decides; this tells the website to offer it.
    /// Absent from older backends.
    #[serde(default)]
    pub trial_eligible: bool,
    /// On a private host: only its provider and the accounts it allows see and rent it, so it is in
    /// no anonymous read; the catalog adds it to the reads of an account it allows, marked so.
    /// Absent (false) on every other offering, and from older backends.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub private: bool,
}

/// The memory modules of one hardware profile, identical ones grouped.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct MemoryProfile {
    /// Ordered by size, the largest first, then technology and speed.
    pub modules: Vec<MemoryModules>,
}

/// `count` memory modules of the same technology, size and speed.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct MemoryModules {
    pub count: u32,
    pub size_bytes: u64,
    /// As the host reports it: `DDR4`, or `Unknown`.
    pub technology: String,
    #[serde(default)]
    pub configured_speed_mts: Option<u32>,
}

impl MemoryProfile {
    /// The memory of a host's hardware report, identical modules counted.
    #[must_use]
    pub fn of(hardware: &crate::hypervisor::HardwareDetails) -> Self {
        let mut modules: Vec<MemoryModules> = Vec::new();
        for device in &hardware.memory_devices {
            match modules.iter_mut().find(|group| {
                group.size_bytes == device.size_bytes
                    && group.technology == device.technology
                    && group.configured_speed_mts == device.configured_speed_mts
            }) {
                Some(group) => group.count = group.count.saturating_add(1),
                None => modules.push(MemoryModules {
                    count: 1,
                    size_bytes: device.size_bytes,
                    technology: device.technology.clone(),
                    configured_speed_mts: device.configured_speed_mts,
                }),
            }
        }
        modules.sort_by(|left, right| {
            right
                .size_bytes
                .cmp(&left.size_bytes)
                .then_with(|| left.technology.cmp(&right.technology))
                .then_with(|| left.configured_speed_mts.cmp(&right.configured_speed_mts))
        });
        Self { modules }
    }
}

impl OfferingView {
    /// The memory of each hardware profile: `memory_profiles`, or when
    /// absent, derived from `hardware_profiles` for compatibility.
    #[must_use]
    pub fn memory_summary(&self) -> std::borrow::Cow<'_, [MemoryProfile]> {
        if self.memory_profiles.is_empty() {
            std::borrow::Cow::Owned(
                self.hardware_profiles
                    .iter()
                    .map(MemoryProfile::of)
                    .collect(),
            )
        } else {
            std::borrow::Cow::Borrowed(&self.memory_profiles)
        }
    }

    /// The gateway a new instance of this offering takes without a choice:
    /// for a home offering the shared gateway location chosen by default,
    /// or else the cheapest shared location, or else the cheapest gateway
    /// tier of an address of the rental's own (by their base charges, the
    /// first of equals); none for a cloud offering. The listed price and
    /// the traffic price a list shows are this gateway's. A shared IP,
    /// which has no address of its own, is never the default.
    #[must_use]
    pub fn default_gateway(&self) -> Option<DefaultGateway<'_>> {
        if self.host_mode != crate::hypervisor::HostMode::HomeGateway {
            return None;
        }
        self.gateway_locations
            .iter()
            .find(|place| place.preselected)
            .or_else(|| {
                self.gateway_locations
                    .iter()
                    .min_by_key(|place| place.gateway_base_charge_microusd_per_month)
            })
            .map(DefaultGateway::Location)
            .or_else(|| {
                self.network_prices
                    .iter()
                    .filter(|price| price.gateway_tier != Some(GatewayTier::SharedIp))
                    .min_by_key(|price| price.gateway_base_charge_microusd_per_month)
                    .map(DefaultGateway::Tier)
            })
    }

    /// The monthly base price of the gateway a new instance of this
    /// offering takes without a choice ([`Self::default_gateway`]);
    /// nothing for a cloud offering.
    #[must_use]
    pub fn default_gateway_base_microusd_per_month(&self) -> u64 {
        match self.default_gateway() {
            Some(DefaultGateway::Location(place)) => place.gateway_base_charge_microusd_per_month,
            Some(DefaultGateway::Tier(price)) => price.gateway_base_charge_microusd_per_month,
            None => 0,
        }
    }

    /// The monthly price the catalog lists and orders by: the base price
    /// with the default gateway's ([`Self::default_gateway_base_microusd_per_month`])
    /// or the address's.
    #[must_use]
    pub fn listed_price_microusd_per_month(&self) -> u64 {
        self.base_price_microusd_per_month
            .saturating_add(self.default_gateway_base_microusd_per_month())
            .saturating_add(self.address_microusd_per_month)
    }

    /// The monthly price with the address `choice` names, or none when the
    /// offering has no such address. Dedicated: the base price with a
    /// home offering's default gateway's base price, or a cloud
    /// offering's own address's; shared: with the shared IP's; any: the
    /// listed price ([`Self::listed_price_microusd_per_month`]), which an
    /// offering always has; shared reference: with the platform's shared
    /// IP price ([`IpChoice::SharedReference`]), which every offering
    /// has. Unknown has none.
    #[must_use]
    pub fn price_for(&self, choice: IpChoice) -> Option<u64> {
        self.address_for(choice)
            .map(|address| self.base_price_microusd_per_month.saturating_add(address))
    }

    /// [`Self::price_for`] at full CPU.
    #[must_use]
    pub fn full_price_for(&self, choice: IpChoice) -> Option<u64> {
        self.address_for(choice).map(|address| {
            self.full_utilization_price_microusd_per_month
                .saturating_add(address)
        })
    }

    /// The traffic price per TiB with the address `choice` names, as
    /// [`Self::default_traffic_microusd_per_tib`] for the dedicated one
    /// (and for any); the shared IP's is its own entry's, and the shared
    /// reference's that entry's where the offering has one, else the
    /// dedicated one's.
    #[must_use]
    pub fn traffic_for(&self, choice: IpChoice) -> Option<u64> {
        match choice {
            IpChoice::Dedicated => {
                self.address_for(choice)?;
                self.default_traffic_microusd_per_tib()
            }
            IpChoice::Any => self.default_traffic_microusd_per_tib(),
            IpChoice::Shared => self
                .shared_ip_price()
                .map(|price| price.combined_microusd_per_tib),
            IpChoice::SharedReference => self
                .traffic_for(IpChoice::Shared)
                .or_else(|| self.default_traffic_microusd_per_tib()),
            IpChoice::Unknown => None,
        }
    }

    /// The bandwidth limit of an instance with the address `choice` names:
    /// the shared IP's entry's for the shared one (and for the shared
    /// reference where the offering has one, else as for any); for the
    /// dedicated one (and for any) a cloud offering's own address's, and a
    /// home offering's default gateway's ([`Self::default_gateway`]; a
    /// shared gateway location is the shared bandwidth tier's). `None` from
    /// older backends, which send none.
    #[must_use]
    pub fn bandwidth_for(&self, choice: IpChoice) -> Option<BandwidthView> {
        match choice {
            IpChoice::Shared => self.shared_ip_price()?.bandwidth,
            IpChoice::SharedReference => self
                .bandwidth_for(IpChoice::Shared)
                .or_else(|| self.bandwidth_for(IpChoice::Any)),
            IpChoice::Dedicated | IpChoice::Any => match self.host_mode {
                crate::hypervisor::HostMode::CloudRouted => {
                    self.network_prices
                        .iter()
                        .find(|price| price.gateway_tier.is_none())
                        .or_else(|| self.network_prices.first())?
                        .bandwidth
                }
                crate::hypervisor::HostMode::HomeGateway => match self.default_gateway()? {
                    DefaultGateway::Location(_) => {
                        self.network_prices
                            .iter()
                            .find(|price| price.gateway_tier == Some(GatewayTier::SharedBandwidth))?
                            .bandwidth
                    }
                    DefaultGateway::Tier(price) => price.bandwidth,
                },
                crate::hypervisor::HostMode::Unknown => None,
            },
            IpChoice::Unknown => None,
        }
    }

    fn shared_ip_price(&self) -> Option<&NetworkPriceView> {
        self.network_prices
            .iter()
            .find(|price| price.gateway_tier == Some(GatewayTier::SharedIp))
    }

    /// The monthly charge of the address `choice` names, beside the base
    /// price.
    fn address_for(&self, choice: IpChoice) -> Option<u64> {
        match choice {
            IpChoice::Dedicated => match self.host_mode {
                crate::hypervisor::HostMode::HomeGateway => self
                    .default_gateway()
                    .map(|_| self.default_gateway_base_microusd_per_month()),
                crate::hypervisor::HostMode::CloudRouted => self
                    .network_prices
                    .iter()
                    .any(|price| price.gateway_tier.is_none())
                    .then_some(self.address_microusd_per_month),
                crate::hypervisor::HostMode::Unknown => None,
            },
            IpChoice::Shared => self
                .shared_ip_price()
                .map(|price| price.gateway_base_charge_microusd_per_month),
            IpChoice::Any => Some(
                self.default_gateway_base_microusd_per_month()
                    .saturating_add(self.address_microusd_per_month),
            ),
            // The platform's shared IP price; from an older backend, which
            // sends none, the shared IP's entry, else the listed price.
            IpChoice::SharedReference => self
                .shared_ip_reference_microusd_per_month
                .or_else(|| self.address_for(IpChoice::Shared))
                .or_else(|| self.address_for(IpChoice::Any)),
            IpChoice::Unknown => None,
        }
    }

    /// The price at full CPU with the default gateway's base price or the
    /// address's.
    #[must_use]
    pub fn listed_full_price_microusd_per_month(&self) -> u64 {
        self.full_utilization_price_microusd_per_month
            .saturating_add(self.default_gateway_base_microusd_per_month())
            .saturating_add(self.address_microusd_per_month)
    }

    /// The provider's own traffic rate per TiB of a home offering, which a
    /// shared gateway location's rate is added to: the shared bandwidth
    /// tier's combined rate less the rate of the location it was priced
    /// at (the preselected one, else the first); 0 without either.
    #[must_use]
    pub fn provider_traffic_microusd_per_tib(&self) -> u64 {
        let shared = self
            .network_prices
            .iter()
            .find(|price| price.gateway_tier == Some(GatewayTier::SharedBandwidth));
        let priced = self
            .gateway_locations
            .iter()
            .find(|place| place.preselected)
            .or_else(|| self.gateway_locations.first());
        match (shared, priced) {
            (Some(shared), Some(place)) => shared
                .combined_microusd_per_tib
                .saturating_sub(place.gateway_network_microusd_per_tib),
            _ => 0,
        }
    }

    /// The traffic price per TiB a list shows: a cloud offering's own
    /// (its price without a gateway tier, else its first), a home
    /// offering's through the gateway it takes without a choice
    /// ([`Self::default_gateway`]), as its listed price does; none when it
    /// has no price. The website's Capacity and `ghost catalog offerings`
    /// both show it, with no "from".
    #[must_use]
    pub fn default_traffic_microusd_per_tib(&self) -> Option<u64> {
        match self.host_mode {
            crate::hypervisor::HostMode::CloudRouted => self
                .network_prices
                .iter()
                .find(|price| price.gateway_tier.is_none())
                .or_else(|| self.network_prices.first())
                .map(|price| price.combined_microusd_per_tib),
            crate::hypervisor::HostMode::HomeGateway => match self.default_gateway()? {
                DefaultGateway::Location(place) => Some(
                    self.provider_traffic_microusd_per_tib()
                        .saturating_add(place.gateway_network_microusd_per_tib),
                ),
                DefaultGateway::Tier(price) => Some(price.combined_microusd_per_tib),
            },
            crate::hypervisor::HostMode::Unknown => None,
        }
    }
}

/// The gateway a new instance of a home offering takes without a choice
/// ([`OfferingView::default_gateway`]): a shared gateway location, or a
/// gateway tier where the offering lists no location.
#[derive(Clone, Copy, Debug)]
pub enum DefaultGateway<'a> {
    Location(&'a GatewayLocationView),
    Tier(&'a NetworkPriceView),
}

/// Whether every host of an offering, with nothing else in its pools, has
/// room for a backup of the offering's root: in a backup pool for the
/// artifact of a local backup, and in the root pool, beside the instance's
/// disk, for the copy-on-write space a backup of the running instance
/// needs. A stopped instance's hosted backup needs no room.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OfferingBackupLimitsView {
    pub local_running: bool,
    pub local_stopped: bool,
    pub hosted_running: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WriteProviderReviewRequest {
    pub expected_revision: u64,
    pub rating: u32,
    pub body: String,
}

/// A CPU score of the platform's single-thread suite: a host's best score of its last seven daily
/// runs, on a scale where the reference machine scores 1696. Runs of two hosts are never pooled.
/// The four fields before `suite` are required and always filled, because installed clients decode
/// them.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CpuBenchmarkView {
    /// A host's best score of its last seven daily runs. For an offering:
    /// the average of its measured hosts' best scores, rounded.
    pub single_thread_mark: u32,
    /// Approximate total figure for the size: the single-thread score
    /// scaled by its vCPUs, by the host's cores, then its SMT threads. On a
    /// view with no size (a provider's host page) it is the single-thread
    /// score.
    pub estimated_instance_mark: u64,
    /// The page that says how the score is measured.
    pub source_url: String,
    /// When the best run started (the newest of them, for an offering).
    pub measured_at: DateTime<Utc>,
    /// The suite that produced the score (`gh-st-3`); absent from older
    /// backends.
    #[serde(default)]
    pub suite: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NetworkPriceView {
    pub gateway_tier: Option<GatewayTier>,
    pub gateway_base_charge_microusd_per_month: u64,
    pub combined_microusd_per_tib: u64,
    /// The bandwidth limit of an instance of the offering's size with this
    /// choice. Absent from older backends.
    #[serde(default)]
    pub bandwidth: Option<BandwidthView>,
}

/// An instance's bandwidth limit, each direction.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BandwidthView {
    /// In Mbit/s; `None` when it is not limited.
    pub limit_mbit: Option<u32>,
}

/// A location a shared bandwidth or shared IP instance of a home offering
/// may be reached through: a shared gateway there has room for a shared
/// bandwidth instance.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct GatewayLocationView {
    pub location: String,
    pub location_name: String,
    pub country_code: String,
    /// The great-circle distance from the host, in kilometres.
    pub distance_km: u32,
    /// Traffic between the host and this location crosses a bottleneck, a
    /// congested or long-haul path; choose it knowingly.
    pub bottleneck: bool,
    /// Taken without a choice: the closest that crosses no bottleneck.
    pub preselected: bool,
    /// What a shared bandwidth instance pays for the gateway placement
    /// takes there: a month's base charge, and the traffic rate on top of
    /// the offering's provider rate. A move there takes these prices.
    /// Absent from older backends.
    #[serde(default)]
    pub gateway_base_charge_microusd_per_month: u64,
    #[serde(default)]
    pub gateway_network_microusd_per_tib: u64,
    /// The same for a shared IP instance placed there: the base charge and traffic rate of the
    /// gateway a slice would be taken on. Absent from older backends (0, and not full: show the
    /// offering's shared IP price).
    #[serde(default)]
    pub shared_ip_base_charge_microusd_per_month: u64,
    #[serde(default)]
    pub shared_ip_network_microusd_per_tib: u64,
    /// No gateway there has a free slice (or none takes slices): the
    /// shared IP tier cannot be placed at this location now. A location
    /// with a free slice but no room for shared bandwidth is not listed
    /// at all, and the tier itself is offered only where a location that
    /// crosses no bottleneck has a free slice.
    #[serde(default)]
    pub shared_ip_full: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateInstanceRequest {
    pub offering_id: String,
    /// What a VM's root disk holds at first: an image or a backup. Exactly
    /// one of it and `container` is given; a request of before always
    /// names it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<InstanceSource>,
    /// A container instance's image and how it runs: given instead of `source`, on an offering that
    /// lists `container` in its kinds. It takes no SSH keys, cloud-init or startup command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<CreateContainerRequest>,
    /// Required for home-hosted instances. For a cloud-routed instance,
    /// absent for an address of its own, or `shared_ip` to share its host's
    /// address (a slice of its ports) where the offering lists that tier.
    #[serde(default, deserialize_with = "known_option")]
    pub gateway_tier: Option<GatewayTier>,
    /// For a shared bandwidth or shared IP instance, the location of the
    /// shared gateway it is reached through, from the offering's
    /// `gateway_locations`; the preselected one without.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_location: Option<String>,
    pub ssh_public_keys: Vec<String>,
    pub cloud_init: Option<String>,
    /// RFC 1123 hostname. The backend generates one when omitted.
    pub hostname: Option<String>,
    /// The instance's name ([`InstanceView::name`]), by the rules of a
    /// hostname; the hostname when omitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// One-time shell program run by cloud-init on the guest's first boot.
    pub startup_command: Option<String>,
    /// Which of the account's saved SSH keys ([`AccountSshKeyView`]) are
    /// installed beside `ssh_public_keys`: absent, every saved key (the
    /// CLI's default; none for a backup source, whose system keeps its
    /// keys); given, those keys, which must be the account's, possibly
    /// none. The keys are copied into the instance when it is made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_key_ids: Option<Vec<Uuid>>,
    /// The new instance's tags ([`InstanceView::tags`], [`valid_tag`], at
    /// most [`MAXIMUM_INSTANCE_TAGS`], duplicates folded). Absent, an
    /// image's or a container's instance starts with none and a backup's
    /// with the tags its instance carries now; given, these, an empty list
    /// none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// The initial contents for a newly rented instance. Backup restoration is a
/// creation source, not an in-place mutation of the backup's original VM.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum InstanceSource {
    Image {
        image_id: Uuid,
    },
    Backup {
        backup_id: Uuid,
        /// Restore pricing is immutable on the backup, but the user still
        /// authorizes the byte-metered charge for this particular request:
        /// a request signed with the account key by the billing key's
        /// signature, a website session by the charge it accepted.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        billing_authorization: Option<BillingAuthorization>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        accepted_charge: Option<AcceptedCharge>,
    },
}

/// The most environment variables a container instance is given.
pub const MAXIMUM_CONTAINER_ENV_VARS: usize = 64;

/// The longest name of a container's environment variable.
pub const MAXIMUM_CONTAINER_ENV_NAME_BYTES: usize = 256;

/// The longest value of a container's environment variable.
pub const MAXIMUM_CONTAINER_ENV_VALUE_BYTES: usize = 32 << 10;

/// The most a container's environment takes, names and values together.
pub const MAXIMUM_CONTAINER_ENV_BYTES: usize = 64 << 10;

/// The most arguments of a container's entrypoint, and of its command.
pub const MAXIMUM_CONTAINER_ARGUMENTS: usize = 256;

/// The most an entrypoint's or a command's arguments take together.
pub const MAXIMUM_CONTAINER_ARGUMENT_BYTES: usize = 64 << 10;

/// The longest user and working directory of a container.
pub const MAXIMUM_CONTAINER_USER_BYTES: usize = 256;

/// The longest a stop waits for a container's process, in seconds.
pub const MAXIMUM_CONTAINER_STOP_TIMEOUT_SECONDS: u32 = 300;

/// The most paths of the renter's a container instance keeps across a
/// redeploy ([`CreateContainerRequest::volumes`]); the host adds the
/// images' own `VOLUME` paths, up to 64 in all.
pub const MAXIMUM_CONTAINER_VOLUMES: usize = 32;

/// The longest path a container instance keeps across a redeploy.
pub const MAXIMUM_CONTAINER_VOLUME_BYTES: usize = 4095;

/// The renter's paths a redeploy keeps, as the API takes them: each
/// absolute and normalised (no `.` or `..` component, no empty one, no
/// trailing slash), not `/` itself, of at most
/// [`MAXIMUM_CONTAINER_VOLUME_BYTES`] and without NUL, each once, at most
/// [`MAXIMUM_CONTAINER_VOLUMES`].
///
/// # Errors
///
/// Why the paths are refused, in the API's words.
pub fn validate_container_volumes(volumes: &[String]) -> Result<(), String> {
    if volumes.len() > MAXIMUM_CONTAINER_VOLUMES {
        return Err(format!(
            "container.volumes holds at most {MAXIMUM_CONTAINER_VOLUMES} paths"
        ));
    }
    for (index, path) in volumes.iter().enumerate() {
        let normalised = path.len() > 1
            && path.len() <= MAXIMUM_CONTAINER_VOLUME_BYTES
            && !path.contains('\0')
            && path.strip_prefix('/').is_some_and(|rest| {
                rest.split('/')
                    .all(|component| !matches!(component, "" | "." | ".."))
            });
        if !normalised {
            return Err(format!(
                "container.volumes path {index} must be an absolute, normalised path other than /, without . or .. components, empty components or a trailing slash, of at most {MAXIMUM_CONTAINER_VOLUME_BYTES} bytes"
            ));
        }
        if volumes[..index].contains(path) {
            return Err(format!("container.volumes names the path {index} twice"));
        }
    }
    Ok(())
}

/// A container instance's image and the renter's overrides of its config, as `docker run` takes
/// them.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateContainerRequest {
    /// `[REGISTRY/]REPOSITORY[:TAG]` or `[REGISTRY/]REPOSITORY@sha256:HEX`
    /// ([`crate::container_image::ImageReference`]); a tag is resolved to
    /// its digest when the instance is created, and the instance keeps
    /// that digest. Exactly one of it and `stock_image` is given.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// One of the platform's stock images by its slug (`GET /v1/catalog/container-images`), such as
    /// `debian-13`: it runs the distribution's own init system, so it takes no `entrypoint`,
    /// `command`, `user` or `workdir`, and needs SSH keys as a VM does (the request's
    /// `ssh_public_keys` and `ssh_key_ids`). Its restart policy is `on_failure` when none is named,
    /// its stop timeout 60 seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stock_image: Option<String>,
    /// Replaces the image's entrypoint, and clears its command unless
    /// `command` is given too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,
    /// Replaces the image's command.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    /// Each replaces the image's variable of its name, or is added. Kept
    /// encrypted, and never shown again.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<ContainerEnvVar>,
    /// Docker's `user[:group]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// An absolute path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    /// How long a stop waits for the process after its stop signal, 0 to
    /// 300 seconds; 10 when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_timeout_seconds: Option<u32>,
    /// What happens when the process exits by itself; `always` when
    /// absent.
    #[serde(
        default,
        deserialize_with = "known_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub restart_policy: Option<RestartPolicy>,
    /// The renter's paths a redeploy keeps, beside the `VOLUME` paths of
    /// the image the instance runs and of the one it moves to
    /// ([`validate_container_volumes`]); none when absent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub volumes: Vec<String>,
}

/// One environment variable of a container instance's process. Its value
/// is a secret: [`std::fmt::Debug`] does not show it.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerEnvVar {
    pub name: String,
    pub value: String,
}

impl std::fmt::Debug for ContainerEnvVar {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ContainerEnvVar")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

/// The longest slug of a stock image.
pub const MAXIMUM_STOCK_IMAGE_SLUG_BYTES: usize = 64;

/// Whether `slug` is a stock image's slug: 1 to
/// [`MAXIMUM_STOCK_IMAGE_SLUG_BYTES`] lowercase letters, digits, `.` and
/// `-`, starting with a letter or digit.
#[must_use]
pub fn is_stock_image_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= MAXIMUM_STOCK_IMAGE_SLUG_BYTES
        && slug
            .bytes()
            .next()
            .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && slug.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
}

/// What a container instance's request runs: an image of the renter's, or
/// one of the platform's stock images by its slug.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ContainerImageChoice {
    Image(crate::container_image::ImageReference),
    Stock(String),
}

impl CreateContainerRequest {
    /// The request's own checks, as the API refuses it: one image, a
    /// reference or a stock image's slug, and every bound; a stock image
    /// takes none of the overrides that would replace its init.
    ///
    /// # Errors
    ///
    /// Why the request is refused, in the API's words.
    pub fn validate(&self) -> Result<ContainerImageChoice, String> {
        let image = match (&self.image, &self.stock_image) {
            (Some(image), None) => ContainerImageChoice::Image(
                image
                    .parse::<crate::container_image::ImageReference>()
                    .map_err(|error| format!("container.image is invalid: {error}"))?,
            ),
            (None, Some(slug)) => {
                if !is_stock_image_slug(slug) {
                    return Err(format!(
                        "container.stock_image must be a stock image's slug, such as debian-13, of at most {MAXIMUM_STOCK_IMAGE_SLUG_BYTES} bytes"
                    ));
                }
                if self.entrypoint.is_some()
                    || self.command.is_some()
                    || self.user.is_some()
                    || self.workdir.is_some()
                {
                    return Err(
                        "container.stock_image runs the image's own init system: it takes no entrypoint, command, user or workdir"
                            .to_owned(),
                    );
                }
                ContainerImageChoice::Stock(slug.clone())
            }
            (None, None) => {
                return Err(
                    "container needs image, a reference, or stock_image, a stock image's slug"
                        .to_owned(),
                );
            }
            (Some(_), Some(_)) => {
                return Err("container takes image or stock_image, not both".to_owned());
            }
        };
        if self.env.len() > MAXIMUM_CONTAINER_ENV_VARS {
            return Err(format!(
                "container.env holds at most {MAXIMUM_CONTAINER_ENV_VARS} variables"
            ));
        }
        let mut names = std::collections::HashSet::new();
        let mut env_bytes = 0_usize;
        for variable in &self.env {
            let name = variable.name.as_bytes();
            if name.is_empty()
                || name.len() > MAXIMUM_CONTAINER_ENV_NAME_BYTES
                || !(name[0].is_ascii_alphabetic() || name[0] == b'_')
                || !name
                    .iter()
                    .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                return Err(format!(
                    "container.env names must be letters, digits and _, not starting with a digit, of at most {MAXIMUM_CONTAINER_ENV_NAME_BYTES} bytes"
                ));
            }
            if !names.insert(variable.name.as_str()) {
                return Err(format!(
                    "container.env names the variable {} twice",
                    variable.name
                ));
            }
            if variable.value.len() > MAXIMUM_CONTAINER_ENV_VALUE_BYTES
                || variable.value.contains('\0')
            {
                return Err(format!(
                    "container.env values have at most {MAXIMUM_CONTAINER_ENV_VALUE_BYTES} bytes and no NUL"
                ));
            }
            env_bytes = env_bytes
                .saturating_add(name.len())
                .saturating_add(variable.value.len());
        }
        if env_bytes > MAXIMUM_CONTAINER_ENV_BYTES {
            return Err(format!(
                "container.env takes at most {MAXIMUM_CONTAINER_ENV_BYTES} bytes, names and values together"
            ));
        }
        for (field, arguments) in [
            ("container.entrypoint", &self.entrypoint),
            ("container.command", &self.command),
        ] {
            let Some(arguments) = arguments else {
                continue;
            };
            let bytes = arguments.iter().fold(0_usize, |total, argument| {
                total.saturating_add(argument.len())
            });
            if arguments.len() > MAXIMUM_CONTAINER_ARGUMENTS
                || bytes > MAXIMUM_CONTAINER_ARGUMENT_BYTES
                || arguments.iter().any(|argument| argument.contains('\0'))
            {
                return Err(format!(
                    "{field} holds at most {MAXIMUM_CONTAINER_ARGUMENTS} arguments of {MAXIMUM_CONTAINER_ARGUMENT_BYTES} bytes together, and no NUL"
                ));
            }
        }
        if self.entrypoint.as_ref().is_some_and(Vec::is_empty)
            && self.command.as_ref().is_none_or(Vec::is_empty)
        {
            return Err(
                "container.entrypoint is empty and no command is given: the container would run nothing"
                    .to_owned(),
            );
        }
        if self.user.as_deref().is_some_and(|user| {
            user.is_empty()
                || user.len() > MAXIMUM_CONTAINER_USER_BYTES
                || user.contains(['\0', '\n', '\r', '/'])
        }) {
            return Err(format!(
                "container.user must be a user[:group] of 1 to {MAXIMUM_CONTAINER_USER_BYTES} bytes"
            ));
        }
        if self.workdir.as_deref().is_some_and(|workdir| {
            !workdir.starts_with('/')
                || workdir.len() > MAXIMUM_CONTAINER_USER_BYTES
                || workdir.contains('\0')
        }) {
            return Err(format!(
                "container.workdir must be an absolute path of at most {MAXIMUM_CONTAINER_USER_BYTES} bytes"
            ));
        }
        if self
            .stop_timeout_seconds
            .is_some_and(|seconds| seconds > MAXIMUM_CONTAINER_STOP_TIMEOUT_SECONDS)
        {
            return Err(format!(
                "container.stop_timeout_seconds is at most {MAXIMUM_CONTAINER_STOP_TIMEOUT_SECONDS}"
            ));
        }
        validate_container_volumes(&self.volumes)?;
        Ok(image)
    }
}

/// Refresh a custom container's saved image reference, optionally replacing
/// only its tag. Every setting, secret and allocation is preserved. A digest
/// stays pinned unless a tag is supplied. Stock images use the explicit
/// image and SSH key selection of [`RedeployInstanceRequest`] instead.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateInstanceRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
}

impl UpdateInstanceRequest {
    /// Check that a supplied value is a tag alone, using the image parser.
    ///
    /// # Errors
    /// Returns the tag's validation error.
    pub fn validate(&self) -> Result<(), String> {
        use crate::container_image::{ImagePin, ImageReference};
        if let Some(tag) = &self.tag {
            let parsed = format!("registry-1.docker.io/library/update:{tag}")
                .parse::<ImageReference>()
                .map_err(|_| "tag must be a tag alone: up to 128 letters, digits, _, . and -, not starting with . or -".to_owned())?;
            if parsed.pin != ImagePin::Tag(tag.clone()) {
                return Err("tag must be a tag alone, not an image reference or digest".to_owned());
            }
        }
        Ok(())
    }
}

/// Redeploy a container instance (`RedeployInstance`): it moves to another image, or another
/// version of its image, on its own root disk. Everything on the root but the kept paths is
/// replaced: the renter's `volumes` and the `VOLUME` paths of the image it runs and of the new one.
/// The host snapshots the root first and rolls back to it if the redeploy fails. Exactly one of
/// `image` and `stock_image`.  Each of the image's settings (`env` to `volumes`) keeps the
/// instance's current value when absent and replaces it when given (an empty list clears a list);
/// with `reset` an absent one takes a creation's default instead, and `clear` drops one of the
/// entrypoint, command, user and workdir alone for the new image's own. A stock image takes no
/// entrypoint, command, user or workdir: those of the current image are dropped when it moves to
/// one.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RedeployInstanceRequest {
    /// As [`CreateContainerRequest::image`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
    /// As [`CreateContainerRequest::stock_image`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stock_image: Option<String>,
    /// Replaces the environment; kept encrypted, and never shown again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<ContainerEnvVar>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workdir: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop_timeout_seconds: Option<u32>,
    #[serde(
        default,
        deserialize_with = "known_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub restart_policy: Option<RestartPolicy>,
    /// As [`CreateContainerRequest::volumes`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volumes: Option<Vec<String>>,
    /// For a stock image, as [`CreateInstanceRequest::ssh_public_keys`]:
    /// with the saved keys `ssh_key_ids` names, or every saved key of the
    /// account when it names none. A renter's image takes none.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_public_keys: Vec<String>,
    /// As [`CreateInstanceRequest::ssh_key_ids`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_key_ids: Option<Vec<Uuid>>,
    /// Absent settings take a creation's defaults instead of the
    /// instance's current values.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub reset: bool,
    /// The settings that take the new image's own instead of the current
    /// value; absent from older clients, which keep them. A setting named
    /// here and given is refused ([`Self::validate`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clear: Vec<RedeploySetting>,
}

/// A container setting a redeploy can drop for the new image's own
/// ([`RedeployInstanceRequest::clear`]). The backend receives it and no
/// client decodes it, so it has no `Unknown`: a name it does not know is
/// refused.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[cfg_attr(feature = "clap", value(rename_all = "snake_case"))]
pub enum RedeploySetting {
    Entrypoint,
    Command,
    User,
    Workdir,
}

impl RedeploySetting {
    /// The setting's name in a request.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Entrypoint => "entrypoint",
            Self::Command => "command",
            Self::User => "user",
            Self::Workdir => "workdir",
        }
    }
}

impl RedeployInstanceRequest {
    /// Refuse a setting both given and cleared.
    ///
    /// # Errors
    ///
    /// The refusal's words, which name the setting.
    pub fn validate(&self) -> Result<(), String> {
        for setting in &self.clear {
            let given = match setting {
                RedeploySetting::Entrypoint => self.entrypoint.is_some(),
                RedeploySetting::Command => self.command.is_some(),
                RedeploySetting::User => self.user.is_some(),
                RedeploySetting::Workdir => self.workdir.is_some(),
            };
            if given {
                return Err(format!(
                    "{} is both given and cleared; a redeploy takes one or the other",
                    setting.name()
                ));
            }
        }
        Ok(())
    }

    /// Whether the instance's `setting` goes on to the new image: not when
    /// it is cleared, the settings are reset or a stock image has none.
    fn keeps(&self, setting: RedeploySetting) -> bool {
        !self.reset && self.stock_image.is_none() && !self.clear.contains(&setting)
    }

    /// The container the instance runs after the redeploy, from what it
    /// runs now (`current`, its environment left out): the request's image
    /// and the settings it gives, the others `current`'s unless `reset`
    /// or, for the entrypoint, command, user and workdir, `clear`. A stock
    /// image keeps none of those. Its environment is the request's, empty when it gives
    /// none: the caller keeps the current one then.
    #[must_use]
    pub fn merged(&self, current: &CreateContainerRequest) -> CreateContainerRequest {
        let keep = !self.reset;
        CreateContainerRequest {
            image: self.image.clone(),
            stock_image: self.stock_image.clone(),
            entrypoint: self.entrypoint.clone().or_else(|| {
                current
                    .entrypoint
                    .clone()
                    .filter(|_| self.keeps(RedeploySetting::Entrypoint))
            }),
            command: self.command.clone().or_else(|| {
                current
                    .command
                    .clone()
                    .filter(|_| self.keeps(RedeploySetting::Command))
            }),
            env: self.env.clone().unwrap_or_default(),
            user: self.user.clone().or_else(|| {
                current
                    .user
                    .clone()
                    .filter(|_| self.keeps(RedeploySetting::User))
            }),
            workdir: self.workdir.clone().or_else(|| {
                current
                    .workdir
                    .clone()
                    .filter(|_| self.keeps(RedeploySetting::Workdir))
            }),
            stop_timeout_seconds: self
                .stop_timeout_seconds
                .or(current.stop_timeout_seconds.filter(|_| keep)),
            restart_policy: self
                .restart_policy
                .or(current.restart_policy.filter(|_| keep)),
            volumes: self.volumes.clone().unwrap_or_else(|| {
                if keep {
                    current.volumes.clone()
                } else {
                    Vec::new()
                }
            }),
        }
    }

    /// Whether the redeploy gives the instance a new environment: the one
    /// it names, or none with `reset`.
    #[must_use]
    pub fn replaces_env(&self) -> bool {
        self.env.is_some() || self.reset
    }
}

/// A command line names these as the API and the catalog do; the older
/// kebab-case spelling is still accepted.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[cfg_attr(feature = "clap", value(rename_all = "snake_case"))]
pub enum GatewayTier {
    /// A shared gateway in one of a few central regions, and a reserved
    /// public address of the rental's own.
    #[cfg_attr(feature = "clap", value(alias = "shared-bandwidth"))]
    SharedBandwidth,
    /// A gateway of the rental's own in the region nearest to its home
    /// host, whose address is the rental's.
    #[cfg_attr(feature = "clap", value(alias = "high-bandwidth"))]
    HighBandwidth,
    /// A slice of a shared gateway's own address: a range of its ports
    /// forwarded to the rental, each to a port the renter chooses, and a
    /// range its outgoing connections leave from. Older releases read it
    /// as [`Self::Unknown`].
    #[cfg_attr(feature = "clap", value(alias = "shared-ip"))]
    SharedIp,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    #[cfg_attr(feature = "clap", value(skip))]
    Unknown,
}

/// The most SSH public keys one instance request may carry.
pub const MAX_SSH_PUBLIC_KEYS: usize = 20;

/// The largest JSON body of a request that sets up a system (creating an
/// instance, a reinstall), as sent: cloud-init user data of the most it
/// may hold (1 MiB) grows when JSON escapes its line breaks, tabs, quotes
/// and backslashes, so a client checks the body it sends against this.
pub const MAX_INITIALIZATION_BODY_BYTES: usize = 1_200_000;

/// The longest SSH public key line an instance request may carry.
pub const MAX_SSH_PUBLIC_KEY_BYTES: usize = 16_384;

/// The OpenSSH public key types a guest's `authorized_keys` takes.
pub const SSH_PUBLIC_KEY_TYPES: [&str; 7] = [
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
];

/// Whether `value` is one OpenSSH public key line without options:
/// a type from [`SSH_PUBLIC_KEY_TYPES`], the standard-base64 key blob
/// starting with that type, and an optional comment.
#[must_use]
pub fn valid_ssh_public_key(value: &str) -> bool {
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    if value.len() > MAX_SSH_PUBLIC_KEY_BYTES
        || value != value.trim()
        || value.contains(['\r', '\n'])
    {
        return false;
    }
    let mut fields = value.split_ascii_whitespace();
    let (Some(algorithm), Some(encoded)) = (fields.next(), fields.next()) else {
        return false;
    };
    if !SSH_PUBLIC_KEY_TYPES.contains(&algorithm) {
        return false;
    }
    let Ok(blob) = STANDARD.decode(encoded) else {
        return false;
    };
    // The blob starts with the type again, as an SSH string: a big-endian
    // u32 length and the name. The key itself must follow it.
    let Some((length, rest)) = blob.split_first_chunk::<4>() else {
        return false;
    };
    let algorithm_length = u32::from_be_bytes(*length) as usize;
    rest.get(..algorithm_length) == Some(algorithm.as_bytes()) && rest.len() > algorithm_length
}

/// The type and the SHA-256 fingerprint of a public key line
/// [`valid_ssh_public_key`] accepts, the fingerprint as `ssh-keygen -l`
/// shows it (`SHA256:` and the unpadded base64 of the digest of the key
/// blob); `None` for a line it does not accept.
#[must_use]
pub fn ssh_public_key_fingerprint(value: &str) -> Option<(String, String)> {
    use base64::{
        Engine as _, engine::general_purpose::STANDARD, engine::general_purpose::STANDARD_NO_PAD,
    };
    use sha2::{Digest as _, Sha256};

    if !valid_ssh_public_key(value) {
        return None;
    }
    let mut fields = value.split_ascii_whitespace();
    let (algorithm, encoded) = (fields.next()?, fields.next()?);
    let blob = STANDARD.decode(encoded).ok()?;
    Some((
        algorithm.to_owned(),
        format!("SHA256:{}", STANDARD_NO_PAD.encode(Sha256::digest(&blob))),
    ))
}

/// Whether `value` is a guest hostname an instance request may carry:
/// a lowercase RFC 1123 name of at most 253 bytes, with dot-separated labels
/// of 1 to 63 letters, digits and hyphens starting and ending with a letter
/// or digit.
#[must_use]
pub fn valid_hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetPowerStateRequest {
    #[serde(deserialize_with = "known")]
    pub state: PowerState,
}

/// Upgrade an instance to a larger size of its host, in place.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpgradeInstanceRequest {
    /// An offering of the instance's host that is larger than the instance
    /// in some respect and smaller in none, as `ListInstanceUpgrades` lists
    /// them.
    pub offering_id: String,
}

/// A size the instance can be upgraded to: a larger offering of its host.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct InstanceUpgradeView {
    pub offering_id: String,
    pub cpu_tier: CpuTier,
    pub vcpu_count: u32,
    pub memory_bytes: u64,
    pub root_disk_bytes: u64,
    pub base_price_microusd_per_month: u64,
    pub full_utilization_price_microusd_per_month: u64,
    /// What the upgrade adds to the balance the instance holds; the
    /// balance must cover it.
    pub balance_reservation_increase_microusd: u64,
    /// Whether the instance's NUMA node and root pool have room for the
    /// size right now, beside what the instance holds already.
    pub available: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReinstallInstanceRequest {
    pub image_id: Uuid,
    pub ssh_public_keys: Vec<String>,
    pub cloud_init: Option<String>,
    pub hostname: Option<String>,
    pub startup_command: Option<String>,
    /// As [`CreateInstanceRequest::ssh_key_ids`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_key_ids: Option<Vec<Uuid>>,
}

/// Reset an instance's SSH access through cloud-init (`ResetInstanceAccess`): at the guest's next
/// boot, which the reset starts, a one-time part appends the keys to root's `authorized_keys`, lets
/// root in over SSH by key, applies the platform's network data again and, with `firewall`, stops
/// the guest's firewall for that boot. A VM only; a stopped one is started.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResetInstanceAccessRequest {
    /// The account's saved keys to install, as
    /// [`CreateInstanceRequest::ssh_key_ids`]: absent installs every saved
    /// key, empty none of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_key_ids: Option<Vec<Uuid>>,
    /// Keys to install besides the saved ones.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_public_keys: Vec<String>,
    /// Stop the guest's firewall (ufw, firewalld, nftables, iptables) for
    /// the boot; it starts again at the next.
    #[serde(default)]
    pub firewall: bool,
}

/// Boot an instance into the platform's rescue system (`RescueInstance`): root logs in over SSH
/// with these keys, by key only. A VM only.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RescueInstanceRequest {
    /// The account's saved keys root logs in with, as
    /// [`CreateInstanceRequest::ssh_key_ids`]: absent takes every saved
    /// key, empty none of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_key_ids: Option<Vec<Uuid>>,
    /// Keys besides the saved ones.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ssh_public_keys: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RotateGatewayKeysRequest {}

/// Give an instance another name ([`InstanceView::name`]). Only the
/// website and the CLI show it: the guest and its hostname stay as they
/// are.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RenameInstanceRequest {
    /// The new name, by the rules of a hostname ([`valid_hostname`]).
    pub name: String,
}

/// The most tags an instance carries ([`InstanceView::tags`]).
pub const MAXIMUM_INSTANCE_TAGS: usize = 20;

/// The longest tag, in bytes (each a character of [`valid_tag`]).
pub const MAXIMUM_TAG_BYTES: usize = 32;

/// The most tags a list's `tag` filter names.
pub const MAXIMUM_TAG_FILTERS: usize = 5;

/// What a tag is, in the API's words: the 400 of a tag that is none.
pub const TAG_RULE: &str = "a tag is 1 to 32 lowercase letters, digits, hyphens (-), underscores (_), dots (.) and colons (:), not . or .. alone";

/// Whether `tag` is valid: 1 to [`MAXIMUM_TAG_BYTES`] lowercase ASCII
/// letters, digits, `-`, `_`, `.` and `:` (`env:prod`, `team-a`), excluding
/// `.` and `..`. Other cases are refused rather than converted.
#[must_use]
pub fn valid_tag(tag: &str) -> bool {
    !tag.is_empty()
        && tag != "."
        && tag != ".."
        && tag.len() <= MAXIMUM_TAG_BYTES
        && tag.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_' | b'.' | b':')
        })
}

/// `tags` as a set: each checked by [`valid_tag`], duplicates folded,
/// sorted.
///
/// # Errors
///
/// The 400's words for the first that is no tag, naming `field`.
pub fn tag_set(field: &str, tags: &[String]) -> Result<Vec<String>, String> {
    if let Some(bad) = tags.iter().find(|tag| !valid_tag(tag)) {
        return Err(format!(
            "{field} holds {bad:?}, which is no tag: {TAG_RULE}"
        ));
    }
    let mut set = tags.to_vec();
    set.sort_unstable();
    set.dedup();
    Ok(set)
}

/// Add tags to an instance and remove others ([`InstanceView::tags`]),
/// which only its renter (and the operators) see: never its host, its
/// provider or a public read. A tag it has already is added again without
/// a change, one it lacks is removed without one; a tag named twice counts
/// once. The instance carries at most [`MAXIMUM_INSTANCE_TAGS`] after the
/// change.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TagInstanceRequest {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<String>,
}

/// One of the account's tags with how many of its instances that are not
/// deleted carry it (`GET /v1/instances/tags`, `ListInstanceTags`, at most
/// 500, the first by tag, and beside them the account's redundant tags
/// those leave out, at most 500 more, each with its count, 0 when no such
/// instance carries it): what the lists' tag filters offer.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InstanceTagView {
    pub tag: String,
    pub instance_count: u32,
    /// Whether the tag is redundant (`SetTagRedundant`): the account's
    /// instances that carry it are kept on different hosts. False from
    /// older backends.
    #[serde(default)]
    pub redundant: bool,
}

/// Mark an account's tag redundant or clear the flag (`SetTagRedundant`).
/// Instances carrying it must be on different hosts. Marking is refused
/// while two share a host; clearing is always allowed. Only the renter and
/// operators see the flag.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetTagRedundantRequest {
    pub redundant: bool,
}

#[allow(clippy::option_option)] // Presence distinguishes preserve, clear and set.
fn custom_hostname_patch<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Option<String>>, D::Error> {
    Option::<String>::deserialize(deserializer).map(Some)
}

/// Replace all the instance's app subdomains. Ports select existing public
/// forwards for shared IPv4, or guest service ports for dedicated IPv4.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetHttpProxyRequest {
    pub entries: Vec<HttpProxyEntry>,
}

/// Create one app domain, or update the active original named by `previous_subdomain`.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SaveHttpProxyEntryRequest {
    #[serde(default)]
    pub previous_subdomain: Option<String>,
    pub entry: HttpProxyEntry,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HttpProxyEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redirect_http_to_https: Option<bool>,
    #[serde(
        default,
        deserialize_with = "custom_hostname_patch",
        skip_serializing_if = "Option::is_none"
    )]
    pub custom_hostname: Option<Option<String>>,
    #[serde(
        default,
        deserialize_with = "custom_hostname_patch",
        skip_serializing_if = "Option::is_none"
    )]
    pub routing_hostname: Option<Option<String>>,
    #[serde(default, deserialize_with = "known_option")]
    pub protocol: Option<HttpProxyProtocol>,
    pub subdomain: String,
    pub port: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpProxyEntryView {
    #[serde(default = "crate::http_proxy::default_redirect_http_to_https")]
    pub redirect_http_to_https: bool,
    #[serde(default)]
    pub custom_hostname: Option<String>,
    #[serde(default)]
    pub routing_hostname: Option<String>,
    #[serde(default)]
    pub cname_target: Option<String>,
    /// Whether customer DNS setup is required; unknown on older servers.
    #[serde(default)]
    pub cname_setup_required: Option<bool>,
    #[serde(default)]
    pub protocol: HttpProxyProtocol,
    pub subdomain: String,
    pub port: u16,
    pub guest_port: Option<u16>,
    pub url: Option<String>,
    pub status: HttpProxyStatus,
    pub error: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HttpProxyProtocol {
    #[default]
    Http,
    Https,
    #[serde(rename = "https_terminated")]
    HttpsTerminated,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HttpProxyStatus {
    PendingDns,
    PendingCertificate,
    PendingNode,
    Active,
    Unavailable,
    Conflict,
    Retired,
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HttpProxyView {
    pub capacity: u32,
    /// Deprecated compatibility field; always None. History uses age retention.
    #[serde(default)]
    pub reservation_capacity: Option<u32>,
    pub node_domain: Option<String>,
    pub ready: bool,
    pub error: Option<String>,
    pub entries: Vec<HttpProxyEntryView>,
}

/// Change where ports of a shared IP instance's slice are forwarded to:
/// each named public port to the instance's port given; the others stay.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetPortForwardsRequest {
    /// At least one, each public port once, every one of the instance's
    /// slice ([`InstanceView::port_forwards`]).
    pub forwards: Vec<PortForwardChange>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PortForwardChange {
    pub public_port: u16,
    /// 1 to 65535.
    pub guest_port: u16,
}

/// One public port of a shared IP instance, TCP and UDP, and the port of
/// the instance it is forwarded to.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PortForwardView {
    pub public_port: u16,
    pub guest_port: u16,
}

/// `ports` ports in a row from `first_port`.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PortRangeView {
    pub first_port: u16,
    pub ports: u16,
}

impl PortRangeView {
    /// The last port of the range.
    #[must_use]
    pub fn last_port(&self) -> u16 {
        self.first_port.saturating_add(self.ports.saturating_sub(1))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ImageView {
    pub image_id: Uuid,
    pub slug: String,
    pub display_name: String,
    pub architecture: String,
    pub minimum_disk_bytes: u64,
    /// The least memory a size needs to run this image; 0 for none.
    #[serde(default)]
    pub minimum_memory_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InstanceView {
    pub instance_id: Uuid,
    pub offering_id: String,
    /// The backup this VM was created from, if any; an in-place restore
    /// shows in `last_restore` instead.
    pub restored_from_backup_id: Option<Uuid>,
    /// The guest's hostname as the platform last set it: at the creation
    /// or the last reinstall. The guest's owner may change it inside.
    pub hostname: String,
    /// What the renter calls the instance: preset from the hostname at the
    /// creation and changed with `RenameInstance`, by the rules of a
    /// hostname ([`valid_hostname`]). Only a name the website and the CLI
    /// show; it never reaches the guest. Empty from older backends, which
    /// [`InstanceView::display_name`] reads as the hostname.
    #[serde(default)]
    pub name: String,
    /// The renter's tags of the instance, sorted ([`valid_tag`], at most
    /// [`MAXIMUM_INSTANCE_TAGS`]): set at the creation and changed with
    /// `TagInstance`. Only the renter and the operators see them, never its
    /// host or provider. Empty from older backends.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Those of [`Self::tags`] that are redundant (`SetTagRedundant`),
    /// sorted: they keep the instance on another host than their other
    /// instances. Empty from older backends.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redundant_tags: Vec<String>,
    /// The catalog image the root disk now holds: the image of the creation
    /// or the last reinstall, or the image of the backup the instance was
    /// created from or last restored from.
    #[serde(default)]
    pub image: Option<ImageView>,
    #[serde(default)]
    pub provider_id: Option<Uuid>,
    #[serde(default)]
    pub provider_name: String,
    #[serde(default)]
    pub host_mode: Option<HostMode>,
    /// The location code of the instance's host.
    #[serde(default)]
    pub location: String,
    #[serde(default)]
    pub location_name: String,
    #[serde(default)]
    pub country_code: String,
    #[serde(default)]
    pub cpu_tier: Option<CpuTier>,
    #[serde(default)]
    pub vcpu_count: u32,
    #[serde(default)]
    pub memory_bytes: u64,
    pub root_disk_bytes: u64,
    #[serde(default)]
    pub firmware: Option<GuestFirmware>,
    /// `Provisioning` also while a restore rebuilds the root: from when its
    /// host begins to write the disk, with the guest stopped, until the
    /// restore has finished and started the guest again if it ran.
    pub state: InstanceState,
    pub desired_power_state: PowerState,
    /// Whether the instance still holds its host capacity, which deleting and
    /// reinstalling it need. A failed instance keeps it after a failed
    /// reinstall, and a failed creation only until its cleanup frees it.
    pub holds_capacity: bool,
    pub public_ipv4: Option<String>,
    pub gateway_tier: Option<GatewayTier>,
    /// The location of the gateway a home instance is reached through,
    /// once it is placed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_location: Option<String>,
    /// Whether a change of the gateway (`ChangeGateway`,
    /// `MoveGatewayLocation`) costs nothing now: the gateway is being taken
    /// out of service and the instance's owner was asked to move the
    /// instance off it (the notification `gateway_move_requested`), which is
    /// the platform's decision and not the renter's. Absent (false) for
    /// every other instance and from older backends.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub gateway_change_free: bool,
    /// For a shared IP instance, the ports of `public_ipv4` that are its,
    /// TCP and UDP, each with the port of the instance it is forwarded to,
    /// in the order of the public ports: a home instance's of its gateway's
    /// address, a cloud instance's of its host's (whose `gateway_tier` is
    /// absent). Changed with `SetPortForwards`. Empty for every other
    /// instance and from older backends.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub port_forwards: Vec<PortForwardView>,
    /// For a shared IP instance, the source ports of `public_ipv4` its
    /// outgoing connections leave from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outgoing_ports: Option<PortRangeView>,
    /// The traffic rate in effect: the provider's for a cloud instance, the
    /// gateway tier's for a home instance.
    pub network_microusd_per_tib: u64,
    /// The instance's bandwidth limit as applied: a cloud instance's on its
    /// host, a home instance's the lower of its gateway's and its host's.
    /// Absent from older backends.
    #[serde(default)]
    pub bandwidth: Option<BandwidthView>,
    /// Whether the instance may send mail straight to other mail servers
    /// (TCP port 25) and over SMTPS (465). It may not unless the operator
    /// lifted the block for the account on its owner's request through
    /// support; submission at a mail service (587) and the services' HTTPS
    /// APIs are open to every instance.
    #[serde(default)]
    pub outgoing_mail_allowed: bool,
    pub created_at: DateTime<Utc>,
    pub billing_started_at: Option<DateTime<Utc>>,
    /// When billing ends or ended: at the deletion, or earlier or ahead,
    /// such as at a provider's retirement deadline or when the account's
    /// balance ran out.
    #[serde(default)]
    pub billing_ended_at: Option<DateTime<Utc>>,
    /// When the instance was deleted.
    #[serde(default)]
    pub deleted_at: Option<DateTime<Utc>>,
    pub balance_reservation_microusd: u64,
    /// Provider-initiated termination notice, if this rental was active when
    /// its host entered planned retirement.
    pub provider_termination: Option<InstanceProviderTerminationView>,
    #[serde(default)]
    pub pricing: Option<InstancePricingView>,
    /// The newest pending or running job of the instance or its backups,
    /// such as a restore, while one runs; a backup's deletion, which runs
    /// beside the instance's other jobs, only when no other job runs.
    #[serde(default)]
    pub active_job: Option<InstanceActiveJobView>,
    /// The newest in-place restore of a backup that succeeded.
    #[serde(default)]
    pub last_restore: Option<InstanceRestoreView>,
    /// Which backups of this instance its host has room for, as offerings
    /// show them for their hosts: a local backup needs a backup pool that
    /// holds its artifact. Other backups on the host, in progress or stored
    /// there until deleted, can still leave too little room for one. Absent
    /// from older backends.
    #[serde(default)]
    pub backup_limits: Option<OfferingBackupLimitsView>,
    /// What cloud-init in the guest reported once it finished the guest's
    /// latest boot. Absent until a boot's cloud-init has finished, from a
    /// reinstall or restore until the new system's has, and for guests
    /// whose platform settings predate the report.
    #[serde(default)]
    pub guest_initialization: Option<GuestInitializationView>,
    /// The SLA the instance was rented with, which a provider's later SLA
    /// change does not touch. Absent from older backends.
    #[serde(default)]
    pub sla: Option<InstanceSlaView>,
    /// A VM or a container instance; a VM from older backends.
    #[serde(default)]
    pub kind: InstanceKind,
    /// A container instance's image and restart policy; absent for a VM.
    /// Its environment is never shown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<ContainerInstanceView>,
    /// The operator's hold on the instance, while one holds: it is stopped
    /// and stays so until the hold is released. Absent otherwise, and from
    /// older backends.
    #[serde(default)]
    pub hold: Option<InstanceHoldView>,
    /// The latest reset of the instance's SSH access and what the guest reported of it. Absent when
    /// there was none, and from older backends.
    #[serde(default)]
    pub access_reset: Option<AccessResetView>,
    /// The instance's rescue, once its rescue system started and until the rescue ends: it runs the
    /// platform's rescue system with its own disk attached, reached over SSH with the host key
    /// named here. Absent otherwise (a rescue still starting shows as its job), and from older
    /// backends.
    #[serde(default)]
    pub rescue: Option<RescueView>,
}

/// An instance's rescue (`RescueInstance`), once its rescue system has started.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RescueView {
    /// When the rescue system started.
    pub started_at: DateTime<Utc>,
    /// The rescue system's SSH host key, new for each rescue, as
    /// `known_hosts` takes it (`ssh-ed25519 AAAA...`).
    pub host_key_public: String,
    /// Its `SHA256:` fingerprint, as `ssh` prints it.
    pub host_key_fingerprint: String,
    /// The rescue system's release, such as `13.7-r1`.
    pub rescue_release: String,
}

/// Why the operator holds an instance: the facts and the rule they break.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InstanceHoldView {
    pub reason: String,
    pub rule: String,
    pub held_at: DateTime<Utc>,
}

/// What a container instance runs.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContainerInstanceView {
    /// The image as the instance was created with it, in its canonical
    /// form ([`crate::container_image::ImageReference`]): a tag or a
    /// digest.
    pub image: String,
    /// `REGISTRY/REPOSITORY@sha256:HEX`: the image's digest the host
    /// resolved and pinned; absent until the creation's pull.
    #[serde(default)]
    pub image_digest: Option<String>,
    /// Whether the image and the settings here may not be what the host
    /// runs: a redeploy's last attempt was never reported, and its host has
    /// not said yet which container it kept. False from older backends.
    #[serde(default)]
    pub image_unknown: bool,
    /// The slug of the platform's stock image the instance runs
    /// ([`CreateContainerRequest::stock_image`]), whose `image` is then
    /// that image pinned by its digest; absent for an image of the
    /// renter's, and from older backends.
    #[serde(default)]
    pub stock_image: Option<String>,
    #[serde(default)]
    pub restart_policy: RestartPolicy,
    /// The renter's paths a redeploy keeps ([`CreateContainerRequest::volumes`]);
    /// empty from older backends.
    #[serde(default)]
    pub volumes: Vec<String>,
    /// The renter's entrypoint, command, user and working directory
    /// ([`CreateContainerRequest`]'s), which a redeploy keeps unless it
    /// gives others; absent where the image's own apply (a stock image
    /// has none), and from older backends. Its environment is never shown.
    #[serde(default)]
    pub entrypoint: Option<Vec<String>>,
    #[serde(default)]
    pub command: Option<Vec<String>>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub workdir: Option<String>,
    /// Whether the container runs and how its process last ended, as its
    /// host last reported it; absent before its host has, and from older
    /// backends.
    #[serde(default)]
    pub status: Option<ContainerStatusView>,
}

/// A container instance's status as its host last reported it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContainerStatusView {
    pub state: ContainerState,
    /// When its host starts it again by its restart policy, while it backs
    /// off.
    #[serde(default)]
    pub restart_at: Option<DateTime<Utc>>,
    /// How often its host started it again by its restart policy since it
    /// was last started.
    pub restarts: u32,
    /// How its process last ended; absent before it ended once.
    #[serde(default)]
    pub last_exit: Option<ContainerExitView>,
    /// When the backend received the report.
    pub reported_at: DateTime<Utc>,
}

/// Whether a container instance's container runs.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerState {
    Running,
    /// Its process ended, and its host starts it again at the status's
    /// `restart_at`, by its restart policy.
    BackingOff,
    /// Off: stopped, or ended and not started again by its restart policy.
    Stopped,
    /// A state of a newer backend, which this release does not know.
    #[serde(other)]
    Unknown,
}

/// How a container instance's process last ended.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContainerExitView {
    /// Its exit code, when it exited by itself.
    #[serde(default)]
    pub code: Option<i32>,
    /// The signal that ended it.
    #[serde(default)]
    pub signal: Option<i32>,
    pub reason: ContainerExitCause,
    /// When its host learned of it.
    pub at: DateTime<Utc>,
}

/// Why a container instance's process last ended.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerExitCause {
    /// The process ended by itself.
    Exited,
    /// It ended after a stop command.
    Stopped,
    /// The init could not start it.
    Error,
    /// The creation's unpack boot put the image on the root disk.
    Unpacked,
    /// Its guest ended without the init's report: a crash, a panic, or a
    /// reboot or power-off by the process.
    Crashed,
    /// A stock image's init system powered off (`poweroff` inside it): the
    /// instance stays stopped whatever its restart policy.
    Poweroff,
    /// A stock image's init system rebooted (`reboot` inside it): its host
    /// started it again after 1 s.
    Reboot,
    /// A cause of a newer backend, which this release does not know.
    #[serde(other)]
    Unknown,
}

/// The init system a stock image runs.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StockImageInit {
    Systemd,
    /// `OpenRC`, under busybox init.
    Openrc,
    /// An init system of a newer backend, which this release does not know.
    #[serde(other)]
    Unknown,
}

/// One of the platform's stock images available for container instances.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct StockImage {
    /// `<name>-<version>`, such as `debian-13`: what a renter names it by.
    pub slug: String,
    pub display_name: String,
    /// `ghcr.io/gigahost-apps/<name>@sha256:HEX`: the image pinned by its
    /// digest.
    pub reference: String,
    pub init_system: StockImageInit,
    /// The signal on which its init system shuts down, 1 to 64.
    pub stop_signal: u8,
    /// The user whose `~/.ssh/authorized_keys` the instance's SSH keys go
    /// to.
    pub ssh_user: String,
    /// The least memory an instance of it is given.
    pub minimum_memory_bytes: u64,
    /// The x86-64 microarchitecture level its distribution is built for,
    /// 1 to 4, which its host's CPU must have.
    pub x86_64_level: u8,
}

/// A stock image a container instance may run (`ListContainerImages`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContainerImageView {
    /// What [`CreateContainerRequest::stock_image`] names.
    pub slug: String,
    pub display_name: String,
    /// The image pinned by its digest.
    pub reference: String,
    pub init_system: StockImageInit,
    /// An offering with less memory does not take it.
    pub minimum_memory_bytes: u64,
    /// The x86-64 level its host's CPU must have; only hosts that have it
    /// are given it.
    pub x86_64_level: u8,
}

impl From<&StockImage> for ContainerImageView {
    fn from(image: &StockImage) -> Self {
        Self {
            slug: image.slug.clone(),
            display_name: image.display_name.clone(),
            reference: image.reference.clone(),
            init_system: image.init_system,
            minimum_memory_bytes: image.minimum_memory_bytes,
            x86_64_level: image.x86_64_level,
        }
    }
}

/// The end of what a container instance's container wrote (its own output,
/// not the instance's serial console), as its host last sent it
/// (`GetInstanceLogs`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContainerLogView {
    /// What the container wrote since it was last started, by the platform
    /// or by its restart policy, at most its last 64 KiB, as text: bytes
    /// that are not UTF-8 read as U+FFFD. Empty before its host has sent
    /// any.
    pub tail: String,
    /// Whether older output precedes `tail`.
    pub truncated: bool,
    /// The end of what it wrote before its last start: the output that
    /// made it exit. Absent before its host has sent one.
    #[serde(default)]
    pub previous: Option<ContainerPreviousLogView>,
    /// When its host last sent it; null before it has.
    #[serde(default)]
    pub reported_at: Option<DateTime<Utc>>,
}

/// The end of what a container wrote before its last start.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContainerPreviousLogView {
    pub tail: String,
    pub truncated: bool,
}

/// An instance's SLA: the uptime target and the multiple of the base price
/// its downtime is credited at.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InstanceSlaView {
    pub target_basis_points: u32,
    pub credit_multiplier: u32,
}

impl InstanceView {
    /// The name the renter sees the instance by: its [`Self::name`], or
    /// its hostname where an older backend sent no name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        if self.name.is_empty() {
            &self.hostname
        } else {
            &self.name
        }
    }
}

/// The hardware an instance runs on, as its host's offering shows it:
/// the CPU, the memory modules and `PCIe` devices, the root disk's
/// storage and RAID, and the CPU's benchmark scaled to the instance.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InstanceHardwareView {
    pub instance_id: Uuid,
    /// Whether the catalog lists the instance's offering now, so another instance like it can be
    /// rented (`/offerings/{offering_id}`): to the account, a private host's too when its provider
    /// allows it.
    #[serde(default)]
    pub offering_listed: bool,
    pub cpu_model: String,
    #[serde(default)]
    pub cpu_benchmark: Option<CpuBenchmarkView>,
    pub hardware: crate::hypervisor::HardwareDetails,
    /// Absent where the host's root pool is not known.
    #[serde(default)]
    pub root_storage_backend: Option<StorageBackend>,
    #[serde(default)]
    pub software_raid_levels: Vec<String>,
    #[serde(default)]
    pub hardware_raid_levels: Vec<String>,
    #[serde(default)]
    pub storage_devices: Vec<StorageDeviceInventory>,
    /// The host, whose network tests `/hosts/{host_id}/network` lists, and
    /// its best current readings; absent without a current result.
    #[serde(default)]
    pub host_id: Option<Uuid>,
    #[serde(default)]
    pub network: Option<NetworkTestSummaryView>,
}

/// cloud-init's result for the latest boot of an instance's guest, as the
/// guest wrote it to its serial console.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct GuestInitializationView {
    pub status: GuestInitializationStatus,
    /// cloud-init's errors, then its recoverable errors, each behind its
    /// level (`error: `, `warning: `, `deprecated: `), briefly: at most 20
    /// of at most 300 characters.
    pub messages: Vec<String>,
    /// When the backend received the result.
    pub reported_at: DateTime<Utc>,
}

/// How long after the guest's boot with an access reset's part the view
/// waits for its report before it says the guest reported nothing.
pub const ACCESS_RESET_REPORT_WAIT_SECONDS: i64 = 10 * 60;

/// The latest reset of an instance's SSH access (`ResetInstanceAccess`).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct AccessResetView {
    pub job_id: Uuid,
    pub requested_at: DateTime<Utc>,
    /// Whether the reset stops the guest's firewall for its boot.
    pub firewall: bool,
    pub state: AccessResetState,
    /// When the guest booted with the reset's part; absent until then.
    #[serde(default)]
    pub booted_at: Option<DateTime<Utc>>,
    /// What each part of the reset did, as the guest reported it; absent
    /// until it has.
    #[serde(default)]
    pub steps: Option<AccessResetSteps>,
    /// When the backend received the guest's report.
    #[serde(default)]
    pub reported_at: Option<DateTime<Utc>>,
}

/// Where an access reset is.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessResetState {
    /// Requested, or booted and not reported yet.
    Pending,
    /// The guest reported what the reset did.
    Reported,
    /// The guest reported nothing within
    /// [`ACCESS_RESET_REPORT_WAIT_SECONDS`] of its boot (or of the request,
    /// when its host could not boot it): it has no cloud-init, has it
    /// turned off, or never reached its userspace.
    NotReached,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

/// What each part of an access reset did in the guest: `ok`, `failed: `
/// and why, or `skipped: ` and why, each at most 300 characters. A part
/// the guest did not report is absent; a report the backend could not read
/// says so ([`Self::unreadable`]).
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct AccessResetSteps {
    /// The guest's report did not read as the reset's part writes it, so
    /// what each part did is not known. Absent from one that read.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unreadable: bool,
    /// The keys appended to root's `authorized_keys`.
    #[serde(default)]
    pub keys: Option<String>,
    /// sshd's drop-in, its `Include`, and its restart.
    #[serde(default)]
    pub sshd: Option<String>,
    /// The seed's network data applied again.
    #[serde(default)]
    pub network: Option<String>,
    /// The guest's firewall stopped for the boot.
    #[serde(default)]
    pub firewall: Option<String>,
    /// What `sshd -t` said of the configuration.
    #[serde(default)]
    pub sshd_test: Option<String>,
}

/// The most of an instance's serial console output one read returns.
pub const MAXIMUM_CONSOLE_LOG_BYTES: usize = crate::hypervisor::MAXIMUM_CONSOLE_TAIL_BYTES;

/// The sessions of an instance's serial console its renter opened over SSH, the newest first, at
/// most [`MAXIMUM_LISTED_CONSOLE_SESSIONS`] of the last 90 days.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct InstanceConsoleSessionsView {
    pub instance_id: Uuid,
    pub sessions: Vec<InstanceConsoleSessionView>,
}

/// The most console sessions an instance's read lists.
pub const MAXIMUM_LISTED_CONSOLE_SESSIONS: usize = 50;

/// One session of an instance's serial console: who opened it from where,
/// with which key, and when and why it ended. No console byte.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct InstanceConsoleSessionView {
    pub session_id: Uuid,
    pub started_at: DateTime<Utc>,
    /// Null while the session is open.
    pub ended_at: Option<DateTime<Utc>>,
    /// The address the session's connection came from.
    pub source_address: String,
    /// The SHA256 fingerprint of the key it authenticated with, as
    /// `ssh-keygen -l` shows it.
    pub key_fingerprint: String,
    /// Why it ended, such as `disconnected`, `idle` or `taken_over`; null
    /// while it is open.
    pub end_reason: Option<String>,
}

/// The end of what an instance's guest wrote to its serial console, as its
/// host last sent it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct InstanceConsoleLogView {
    pub instance_id: Uuid,
    /// The instance's hostname, which names it to an operator reading it.
    #[serde(default)]
    pub hostname: String,
    /// The renter's tags of the instance ([`InstanceView::tags`]), which
    /// an operator reading it sees too. Empty from older backends.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// The output since the platform last started the guest, or all of it
    /// before the host noted such a start, as the guest wrote it, terminal
    /// escape sequences and all, as text: bytes that are not UTF-8 read as
    /// U+FFFD. Empty before the host has sent any.
    pub output: String,
    /// Whether older output of that boot, or of the log, precedes
    /// `output`: on the host, or beyond the bytes asked for.
    pub truncated: bool,
    /// When the host last sent the output; null before it has.
    pub updated_at: Option<DateTime<Utc>>,
    /// The end of what the guest wrote before the platform last started it
    /// anew, by a reset, a reboot, a stop and start, an upgrade, a
    /// reinstall or a restore, which the new boot's output would otherwise
    /// push out: a kernel panic that led to a reset, say. Null when the
    /// host has sent none.
    pub previous_boot: Option<PreviousBootConsoleView>,
}

/// The end of what an instance's guest wrote to its serial console before
/// the platform last started it anew.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PreviousBootConsoleView {
    /// As the view's `output`, at most the last bytes asked for.
    pub output: String,
    /// Whether older output of that boot, or of the log, precedes
    /// `output`: on the host, or beyond the bytes asked for.
    pub truncated: bool,
}

/// The line between the end of the boot before the platform last started
/// an instance's guest anew and the output since, where both are shown.
pub const CONSOLE_RESTART_LINE: &str = "--- the platform started the instance again here ---";

/// A console log for reading, as [`readable_console_output`] has each part,
/// without line breaks at its end: the end of the boot before the platform
/// last started the guest anew, when there is one, and
/// [`CONSOLE_RESTART_LINE`] before the output since.
#[must_use]
pub fn readable_console_log(console: &InstanceConsoleLogView) -> String {
    let output = readable_console_output(&console.output);
    let output = output.trim_end_matches('\n');
    match &console.previous_boot {
        Some(previous) => format!(
            "{}\n{CONSOLE_RESTART_LINE}\n{output}",
            readable_console_output(&previous.output).trim_end_matches('\n')
        ),
        None => output.to_owned(),
    }
}

/// Console output for reading: escape sequences, which color or move the
/// cursor on a terminal, and carriage returns are left out, and so is every
/// other control character but tabs and line breaks. A guest's output can
/// then neither restyle nor rewrite a terminal or page that shows it.
#[must_use]
pub fn readable_console_output(output: &str) -> String {
    let mut readable = String::with_capacity(output.len());
    let mut characters = output.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\n' | '\t' => readable.push(character),
            '\u{1b}' => match characters.next() {
                // A control sequence ends with a byte from @ to ~.
                Some('[') => {
                    for next in characters.by_ref() {
                        if ('@'..='~').contains(&next) {
                            break;
                        }
                    }
                }
                // An operating system command or a string ends with BEL or
                // with ESC \.
                Some(']' | 'P' | '^' | '_' | 'X') => {
                    while let Some(next) = characters.next() {
                        if next == '\u{7}' {
                            break;
                        }
                        if next == '\u{1b}' {
                            characters.next_if_eq(&'\\');
                            break;
                        }
                    }
                }
                // Another escape ends with its first character from 0 to ~,
                // after any from space to /, as ESC ( B does.
                Some(' '..='/') => {
                    for next in characters.by_ref() {
                        if !(' '..='/').contains(&next) {
                            break;
                        }
                    }
                }
                _ => {}
            },
            character if character.is_control() => {}
            character => readable.push(character),
        }
    }
    readable
}

/// A job running on an instance, as the instance lists it; read the job for
/// its steps and events.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InstanceActiveJobView {
    pub job_id: Uuid,
    pub kind: JobKind,
    pub state: JobState,
    pub current_step_key: Option<String>,
    pub progress_permyriad: u16,
    pub backup_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    /// Why the job waits in its host's queue, while it does, as
    /// [`JobView::waiting`]. Absent from older backends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting: Option<String>,
}

/// An in-place restore of a backup that succeeded.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InstanceRestoreView {
    pub backup_id: Uuid,
    pub job_id: Uuid,
    pub completed_at: DateTime<Utc>,
}

/// What a home instance's hosted gateway counted over the last hour and
/// the last day. For information only: billing counts just what the gateway
/// sends, into the tunnel toward the instance and out on its behalf, so
/// traffic the gateway dropped or could not deliver is never billed.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GatewayTrafficView {
    pub instance_id: Uuid,
    /// End of the newest gateway reading with statistics; null before the
    /// first.
    pub observed_until: Option<DateTime<Utc>>,
    pub last_hour: GatewayTrafficWindowView,
    pub last_day: GatewayTrafficWindowView,
}

/// Readings that ended within one window, summed.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GatewayTrafficWindowView {
    pub window_started_at: DateTime<Utc>,
    pub window_ended_at: DateTime<Utc>,
    /// From the internet to the instance's public address.
    pub inbound: GatewayTrafficDirectionView,
    /// From the instance toward the internet.
    pub outbound: GatewayTrafficDirectionView,
    /// Inbound packets the gateway sent into the tunnel that `WireGuard`
    /// discarded, as it does while the tunnel is down; bytes are not counted.
    pub inbound_tunnel_discarded_packets: u64,
}

/// One direction: what reached the gateway, what it passed on (into the
/// tunnel inbound, out to the internet outbound), and what its firewall
/// dropped. Anything else that arrived was lost on the way.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct GatewayTrafficDirectionView {
    pub arrived_bytes: u64,
    pub arrived_packets: u64,
    pub delivered_bytes: u64,
    pub delivered_packets: u64,
    pub dropped_bytes: u64,
    pub dropped_packets: u64,
}

/// The most Shared 1x vCPUs a compute price may be given for.
pub const MAXIMUM_COMPUTE_VCPUS: u32 = 16_777_216;

/// A host's compute earnings, kept exact as a fraction: `microusd_per_month`
/// earned per 30-day month for `vcpus` Shared 1x vCPUs, so one vCPU earns
/// `microusd_per_month / vcpus`. `vcpus` is 1 for a price per vCPU, or the
/// host's saleable vCPUs when a whole-host total was published. A size of
/// `v` vCPUs earns its share of it, which does not change when the host's
/// capacity grows.
///
/// Answers carry it, so it reads fields it does not know; a request gives
/// it as [`ComputeEarningsInput`].
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct ComputeEarnings {
    pub microusd_per_month: u64,
    pub vcpus: u32,
}

/// [`ComputeEarnings`] as a provider gives them in [`HostPricingInput`],
/// which refuses a field it does not know.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ComputeEarningsInput {
    pub microusd_per_month: u64,
    pub vcpus: u32,
}

impl From<ComputeEarningsInput> for ComputeEarnings {
    fn from(input: ComputeEarningsInput) -> Self {
        Self {
            microusd_per_month: input.microusd_per_month,
            vcpus: input.vcpus,
        }
    }
}

impl From<ComputeEarnings> for ComputeEarningsInput {
    fn from(earnings: ComputeEarnings) -> Self {
        Self {
            microusd_per_month: earnings.microusd_per_month,
            vcpus: earnings.vcpus,
        }
    }
}

/// What a provider earns from a host's rentals: every amount is the
/// provider's own, what reaches its balance. Renters pay more; the backend
/// works their prices out and the provider never sees them.
///
/// Only answers carry it ([`HostPricingInput`] is what a provider sends),
/// so it accepts fields it does not know: a client keeps reading the
/// answers of a backend that adds one. The compute earnings as kept are
/// beside it, in [`HostPricingView::compute_earnings`].
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct HostPricingValues {
    /// Previously earned per rental and 30-day month, whatever its size. Providers no
    /// longer set it, and it is 0 (the fixed price per instance is the platform's).
    /// Still answered for older clients.
    #[serde(default)]
    pub fixed_instance_earnings_microusd_per_month: u64,
    /// Earned per 30-day month for the whole host's compute at its saleable
    /// vCPUs now: derived from the compute earnings as kept, `N × C / D`
    /// rounded down to a micro-USD, so it grows with the host's capacity.
    /// Each rental earns its size's share.
    pub base_host_earnings_microusd_per_month: u64,
    /// Earned per TiB of a rental's traffic, in and out; 0 on a home host,
    /// whose renters pay their gateway for traffic.
    pub network_earnings_microusd_per_tib: u64,
    pub sla_target_basis_points: u32,
    /// Earned per rental and 30-day month for a cloud rental's address;
    /// 0 on a home host. Absent from older responses; omitted while 0 for
    /// compatibility with clients that reject unknown fields here.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub address_earnings_microusd_per_month: u64,
}

/// What a provider asks to earn on a host. The compute earnings come in one
/// of two forms, exactly one of them: `compute_earnings`, kept as given
/// (`vcpus` 1 for a price per vCPU), or
/// `base_host_earnings_microusd_per_month`, a total for the whole host,
/// which is kept with the host's saleable vCPUs at publication.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostPricingInput {
    /// Providers no longer set it: the fixed price per instance is the platform's. Left out, or 0
    /// from a client of before, it is taken; any other value is refused, so no provider believes it
    /// set a price it did not. Decoded for clients of before, and to go.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub fixed_instance_earnings_microusd_per_month: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compute_earnings: Option<ComputeEarningsInput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_host_earnings_microusd_per_month: Option<u64>,
    /// Earned per TiB of a rental's traffic, in and out; 0 on a home host.
    pub network_earnings_microusd_per_tib: u64,
    pub sla_target_basis_points: u32,
    /// Earned per rental and 30-day month for a cloud rental's address of
    /// its own; 0 on a home host. Left out, the host's address earnings
    /// stay as they are: a client built before them, which sends none,
    /// changes no address price, and a backend that does not know them
    /// still takes a request without them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address_earnings_microusd_per_month: Option<u64>,
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_zero(value: &u64) -> bool {
    *value == 0
}

/// The compute earnings of a [`HostPricingInput`], in the form it gives
/// them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComputeEarningsForm {
    /// Earned for a number of vCPUs, kept as given.
    ForVcpus(ComputeEarnings),
    /// The whole host's total, for its saleable vCPUs at publication.
    WholeHost(u64),
}

impl HostPricingInput {
    /// The compute earnings the input gives, or why it gives none: neither
    /// form or both, or earnings for no vCPU or more than
    /// [`MAXIMUM_COMPUTE_VCPUS`].
    ///
    /// # Errors
    ///
    /// What is wrong with the input, in words for the provider.
    pub const fn compute(&self) -> Result<ComputeEarningsForm, &'static str> {
        match (
            self.compute_earnings,
            self.base_host_earnings_microusd_per_month,
        ) {
            (Some(_), Some(_)) => {
                Err("give compute_earnings or base_host_earnings_microusd_per_month, not both")
            }
            (None, None) => Err(
                "give the compute earnings: compute_earnings (per vCPU) or base_host_earnings_microusd_per_month (for the whole host)",
            ),
            (Some(earnings), None) => {
                if earnings.vcpus == 0 || earnings.vcpus > MAXIMUM_COMPUTE_VCPUS {
                    Err("compute_earnings.vcpus must be 1 to 16777216")
                } else {
                    Ok(ComputeEarningsForm::ForVcpus(ComputeEarnings {
                        microusd_per_month: earnings.microusd_per_month,
                        vcpus: earnings.vcpus,
                    }))
                }
            }
            (None, Some(total)) => Ok(ComputeEarningsForm::WholeHost(total)),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateHostPricingRequest {
    /// Zero creates the first profile; subsequent updates compare revisions.
    pub expected_revision: u64,
    pub values: HostPricingInput,
    pub change_reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostPricingView {
    pub host_id: Uuid,
    pub revision: u64,
    pub values: HostPricingValues,
    /// When the provider last published the values.
    pub published_at: DateTime<Utc>,
    /// When the rentals that existed then earn them.
    pub existing_instances_effective_at: DateTime<Utc>,
    /// The compute earnings as published: per vCPU (`vcpus` 1), or the
    /// whole host's total for its saleable vCPUs then. None in older responses,
    /// whose `values` give only the whole-host total.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compute_earnings: Option<ComputeEarnings>,
    /// The host's saleable vCPUs now: its CPU limit per NUMA node times its
    /// allowed NUMA nodes. None as `compute_earnings`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saleable_vcpus: Option<u32>,
}

/// What one rental earns its provider at the prices in effect, as the
/// provider's rental list (`GET /v1/provider/hosts/{host_id}/instances`)
/// carries it in each item's `earnings`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RentalEarningsView {
    /// Earned per 30-day month while its host is up, whatever the guest's
    /// power state.
    pub base_microusd_per_month: u64,
    /// Earned per 30-day month at full CPU use; between the two in
    /// proportion to the CPU it uses.
    pub full_utilization_microusd_per_month: u64,
    /// Earned per TiB of its traffic, in and out; 0 on a home host.
    pub network_microusd_per_tib: u64,
    /// Earned per 30-day month for its address of its own (a cloud
    /// rental's). Absent from older backends.
    #[serde(default)]
    pub address_microusd_per_month: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct InstancePrices {
    pub base_price_microusd_per_month: u64,
    pub full_utilization_price_microusd_per_month: u64,
    pub provider_network_microusd_per_tib: u64,
    pub gateway_network_microusd_per_tib: u64,
    pub gateway_base_microusd_per_month: u64,
    /// The monthly price of a cloud rental's address. Absent from older
    /// backends.
    #[serde(default)]
    pub address_microusd_per_month: u64,
    /// Of the base price and the price at full CPU, the platform's fixed price per instance; the
    /// rest is the provider's. Absent from older backends, and left out while 0.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub platform_fixed_price_microusd_per_month: u64,
    /// The factor, in basis points, `provider_network_microusd_per_tib` carries: a cloud VM's with
    /// a shared IP pays its host's published rate times it, rounded up. Absent from older backends,
    /// and left out while 10 000 (the rate as published).
    #[serde(
        default = "default_shared_ip_traffic_multiplier",
        skip_serializing_if = "is_one_multiplier"
    )]
    pub shared_ip_traffic_multiplier_basis_points: u32,
}

impl InstancePrices {
    /// The host's published traffic rate in `provider_network_microusd_per_tib`,
    /// which carries [`Self::shared_ip_traffic_multiplier_basis_points`]:
    /// the rate `r` whose `ceil(r × factor / 10 000)` it is. A factor of at
    /// least 1 maps every rate to a different one, so it is found exactly
    /// as `floor(rate × 10 000 / factor)`.
    #[must_use]
    pub fn published_network_microusd_per_tib(&self) -> u64 {
        let factor = u128::from(self.shared_ip_traffic_multiplier_basis_points);
        if factor <= u128::from(SHARED_IP_TRAFFIC_MULTIPLIER_ONE) {
            return self.provider_network_microusd_per_tib;
        }
        u64::try_from(
            u128::from(self.provider_network_microusd_per_tib)
                * u128::from(SHARED_IP_TRAFFIC_MULTIPLIER_ONE)
                / factor,
        )
        .unwrap_or(u64::MAX)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PendingPriceChange {
    pub publication_id: Uuid,
    pub announced_at: DateTime<Utc>,
    pub effective_at: DateTime<Utc>,
    pub component: String,
    pub prices: InstancePrices,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InstancePricingView {
    pub current: InstancePrices,
    pub pending: Vec<PendingPriceChange>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InstanceProviderTerminationView {
    pub notice_id: Uuid,
    pub notice_created_at: DateTime<Utc>,
    pub deadline: DateTime<Utc>,
    pub state: ProviderTerminationState,
    pub deletion_job_id: Option<Uuid>,
    pub last_error: Option<String>,
    pub reason: Option<String>,
    pub emergency: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UserNotificationView {
    pub notification_id: Uuid,
    pub kind: String,
    pub title: String,
    pub message: String,
    pub instance_id: Option<Uuid>,
    pub host_id: Option<Uuid>,
    pub created_at: DateTime<Utc>,
    pub read_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetNotificationReadRequest {
    pub read: bool,
}

/// Marking every notification read: each one created up to `read_through`
/// counts as read from then, unless it is marked unread by itself later.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct NotificationsReadView {
    pub read_through: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderTerminationState {
    Scheduled,
    DeletionQueued,
    Completed,
    ActionRequired,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JobAccepted {
    pub job_id: Uuid,
    pub resource_id: Uuid,
    pub status_url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JobView {
    pub job_id: Uuid,
    pub kind: JobKind,
    pub state: JobState,
    pub resource_id: Uuid,
    pub progress_permyriad: u16,
    pub current_step_key: Option<String>,
    /// The progress of the step `current_step_key` names. Job progress is
    /// the mean of every step's, except that a step moving a whole disk, a
    /// backup's upload or a restore's writing, makes nine tenths of it.
    #[serde(default)]
    pub current_step_progress_permyriad: Option<u16>,
    /// The renter-visible results of each step, by step key.
    pub result: serde_json::Value,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub steps: Vec<JobStepView>,
    pub events: Vec<JobEventView>,
    /// Why the backup or restore waits in its host's queue, such as
    /// `waiting for the host's backup disk, which works on one backup or
    /// restore at a time; 1 ahead`. Absent when not waiting, for other jobs,
    /// and from older responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[cfg_attr(feature = "clap", value(rename_all = "snake_case"))]
pub enum JobKind {
    CreateInstance,
    SetPowerState,
    DeleteInstance,
    CreateBackup,
    RestoreBackup,
    DeleteBackup,
    ReinstallInstance,
    /// The renter gave the instance a larger size of its host.
    UpgradeInstance,
    RotateGatewayKeys,
    /// The operator moved a home rental to another hosted gateway.
    MoveGatewayLease,
    /// The platform changed an instance's bandwidth limit on its host (a
    /// cloud instance's, or a home instance's, which its gateway limits to
    /// the same rate), after a change of the limits, of its size or of its
    /// host's agent. Older releases read it as [`Self::Unknown`].
    TuneBandwidth,
    /// The renter moved a container instance to another image on its own
    /// root disk. Older releases read it as [`Self::Unknown`].
    RedeployContainerInstance,
    /// The renter reset a VM's SSH access through cloud-init. Older releases read it as
    /// [`Self::Unknown`].
    ResetInstanceAccess,
    /// The renter booted a VM into the platform's rescue system. Older releases read it as
    /// [`Self::Unknown`].
    RescueInstance,
    /// A VM's rescue ended: by the renter, by its stop or reset, or by a stop of the platform's.
    /// Older releases read it as [`Self::Unknown`].
    EndInstanceRescue,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    #[cfg_attr(feature = "clap", value(skip))]
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

/// What the account job list keeps: jobs in one state, or `active` ones,
/// pending or running.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[cfg_attr(feature = "clap", value(rename_all = "snake_case"))]
pub enum JobStateFilter {
    Pending,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Active,
}

/// One job of the account job list; its steps, events and results are read
/// with the job itself.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JobSummaryView {
    pub job_id: Uuid,
    pub kind: JobKind,
    pub state: JobState,
    /// As in [`JobView`]: the created instance for `create_instance`, else
    /// the backup when the job has one, else the instance.
    pub resource_id: Uuid,
    pub instance_id: Option<Uuid>,
    pub backup_id: Option<Uuid>,
    pub progress_permyriad: u16,
    pub current_step_key: Option<String>,
    pub current_step_progress_permyriad: Option<u16>,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// A page of the account job list, newest first.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JobPage {
    pub items: Vec<JobSummaryView>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JobStepView {
    pub step_id: Uuid,
    pub step_key: String,
    pub state: JobStepState,
    pub attempt: u32,
    pub maximum_attempts: u32,
    pub progress_permyriad: u16,
    pub error_code: Option<String>,
    pub error_message: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStepState {
    Pending,
    Leased,
    Running,
    Succeeded,
    Failed,
    RetryWait,
    Cancelled,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct JobEventView {
    pub event_id: u64,
    pub step_id: Option<Uuid>,
    /// The key of the step `step_id` names, as `steps` lists it.
    #[serde(default)]
    pub step_key: Option<String>,
    pub attempt: Option<u32>,
    pub state: Option<String>,
    pub progress_permyriad: Option<u16>,
    pub message: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceState {
    PendingPayment,
    Provisioning,
    Running,
    Stopped,
    Deleting,
    Deleted,
    Failed,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountBalanceView {
    /// Deposited spending credit available for new charges; never payable out.
    pub available_microusd: i64,
    /// Spending credit held for rentals and authorized operations.
    pub reserved_microusd: i64,
    /// Available plus reserved spending credit, excluding provider earnings.
    pub total_microusd: i64,
    /// Provider earnings after platform fees, including holds and payouts in flight.
    /// Can be negative after an SLA settlement; excludes all deposited funds.
    #[serde(default)]
    pub provider_earnings_microusd: i64,
    /// Earnings eligible for payout after holds, SLA restrictions and payouts in flight.
    #[serde(default)]
    pub available_payout_microusd: i64,
    pub funding_status: Option<AccountFundingView>,
    /// SLA credit, per provider whose outage earned it. It pays only that
    /// provider's charges, is never withdrawn, and is not part of the total.
    pub provider_credits: Vec<AccountProviderCreditView>,
    /// The account's trial, if it began as one. Its credit is not part of
    /// the total either. Absent from older backends.
    #[serde(default)]
    pub trial: Option<AccountTrialView>,
    /// What the account's services will cost in the coming 30 days at their current use: in the
    /// API's answer; absent from older backends, and from the website's top bar read, which does
    /// not work it out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub projection: Option<AccountProjectionView>,
    /// The account's protected balance: what a new rental, upgrade, backup or restore leaves of the
    /// available balance and a live trial's credit, kept for the instances already running. The
    /// account's own choice, never below the platform's minimum, or the platform's default. Absent
    /// from older backends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected_balance_microusd: Option<u64>,
    /// Whether the account chose its protected balance; false while it
    /// follows the platform's default. Absent from older backends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected_balance_chosen: Option<bool>,
}

/// The most an account's protected balance may be: $10,000.
pub const MAXIMUM_PROTECTED_BALANCE_MICROUSD: u64 = 10_000_000_000;

/// Set the account's protected balance (`SetProtectedBalance`): a value
/// between the platform's minimum and [`MAXIMUM_PROTECTED_BALANCE_MICROUSD`],
/// or none to follow the platform's default again.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetProtectedBalanceRequest {
    /// Required on the wire: a missing field is refused, `null` is the
    /// default.
    #[serde(deserialize_with = "Option::deserialize")]
    pub protected_balance_microusd: Option<u64>,
}

/// The account's protected balance and its bounds.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
pub struct ProtectedBalanceView {
    /// The protected balance in effect: the account's choice, never below
    /// the minimum, or the default.
    pub protected_balance_microusd: u64,
    /// Whether the account chose it; false while it follows the default.
    pub chosen: bool,
    /// The platform's default, which an account that did not choose follows.
    pub default_microusd: u64,
    /// The least it may be.
    pub minimum_microusd: u64,
    /// The most it may be.
    pub maximum_microusd: u64,
}

/// The account's monthly projection, by type of service: each row is the sum of its services'
/// projections ([`InstanceProjectionView`] for each instance, and each backup's), so an instance's
/// page and the billing page agree. A service's projection is its average daily charge over the
/// days it existed in the past 30 days (the current day included), times 30: a service started 3
/// days ago counts as if it had run 30 days at the rate of those 3. One with less than a day and no
/// charge yet counts its current monthly price; a backup counts its storage price, up to its expiry
/// when that is sooner, and an instance up to its billing's end (a host retirement's deadline).
/// Only recurring charges count (usage, network usage, gateway and address charges, backup
/// storage), and only services that have not ended (no deleted or failed instance, none whose
/// billing ended, no deleted backup).
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccountProjectionView {
    /// The instances' usage charges including CPU extra but without traffic,
    /// and their gateways' and addresses' monthly charges.
    pub instances_base_microusd: u64,
    /// CPU extra already included in `instances_base_microusd`; None when
    /// an older backend has not supplied the split.
    #[serde(default)]
    pub instances_cpu_microusd: Option<u64>,
    /// The instances' traffic: the provider's and the gateway's.
    pub traffic_microusd: u64,
    /// The storage of the backups kept on hosts.
    pub local_backups_microusd: u64,
    /// The storage of the backups Gigahost hosts.
    pub hosted_backups_microusd: u64,
    /// The four together.
    pub total_microusd: u64,
    /// How many whole days the available balance lasts at the total's
    /// daily rate when that is less than 30, with a live trial's credit
    /// paying first until it runs out or expires and each SLA credit
    /// paying its provider's services until it runs out; None when it
    /// lasts the 30 days, and while `funding_status` is open, which says
    /// when the balance runs out.
    #[serde(default)]
    pub days_balance_lasts: Option<u32>,
}

/// One instance's monthly projection, worked out as each service's is for
/// [`AccountProjectionView`]: its base charge, its traffic, and the storage of its local and hosted
/// backups. A deleted or failed instance has no base or traffic; its backups that are kept still
/// count.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct InstanceProjectionView {
    /// Its usage charges including CPU extra but without traffic, and its
    /// gateway's and address's monthly charges.
    pub base_microusd: u64,
    /// CPU extra already included in `base_microusd`; None when an older
    /// backend has not supplied the split.
    #[serde(default)]
    pub cpu_microusd: Option<u64>,
    /// Its traffic: the provider's, the gateway's and the host mesh's.
    pub traffic_microusd: u64,
    pub local_backups_microusd: u64,
    pub hosted_backups_microusd: u64,
    /// The four together.
    pub total_microusd: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountProviderCreditView {
    pub provider_id: Uuid,
    pub provider_display_name: String,
    pub balance_microusd: i64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountFundingState {
    Warning,
    Stopping,
    BackingUp,
    Pruning,
    DeletingInstances,
    BackupRetention,
    DeletingBackups,
    ActionRequired,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AccountFundingView {
    pub state: AccountFundingState,
    pub warning_started_at: DateTime<Utc>,
    pub projected_exhaustion_at: Option<DateTime<Utc>>,
    pub projected_daily_burn_microusd: u64,
    pub exhausted_at: Option<DateTime<Utc>>,
    pub cleanup_started_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
}

/// A provider's earnings. Every amount is the provider's own: what its
/// rentals earned it, and what a payout pays it.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderBalanceView {
    /// Earnings not paid out and not on their way: the balance less the
    /// payouts in flight, and never below zero.
    pub pending_payout_microusd: i64,
    /// What a payout request can take now: the pending earnings less those
    /// still held, and zero while `sla_settlement_pending`.
    pub available_payout_microusd: i64,
    /// Earnings still held for their rentals' SLA window (1, 5 or 20 days
    /// after they were earned), so that an outage's credit can come from
    /// them.
    pub held_microusd: i64,
    /// Payouts requested and not confirmed yet.
    pub on_the_way_microusd: i64,
    /// An outage of one of the provider's hosts is open or its credits are
    /// not settled yet: nothing can be paid out until they are.
    pub sla_settlement_pending: bool,
    /// The MMX address every payout goes to, or `None` until it is set with
    /// a signed CLI request.
    pub payout_address: Option<String>,
}

/// A payout always goes to the provider's payout address; a request cannot
/// name another one.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateProviderPayoutRequest {
    /// What to pay out, at most what is available. Omit to pay out
    /// everything available.
    pub amount_microusd: Option<u64>,
}

/// Set the address a provider's payouts go to. Only a request signed with
/// the account key may set it; a website session is refused.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetProviderPayoutAddressRequest {
    /// An MMX address controlled by the provider.
    pub address: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderPayoutAddressView {
    pub address: String,
    /// When the address last changed.
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderPayoutState {
    Queued,
    Preparing,
    Submitting,
    Submitted,
    Confirmed,
    /// Held for an operator to check what its transaction paid; its amount
    /// stays reserved.
    UnderReview,
    ActionRequired,
    Cancelled,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderPayoutView {
    pub payout_id: Uuid,
    pub destination_address: String,
    /// What the payout takes from the provider's earnings and pays it, in
    /// MMX at the exchange rate when it is prepared.
    pub amount_microusd: u64,
    pub amount_mmx_atomic: Option<u64>,
    pub state: ProviderPayoutState,
    pub chain_transaction_id: Option<String>,
    pub requested_at: DateTime<Utc>,
    pub submitted_at: Option<DateTime<Utc>>,
    pub confirmed_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub waiting_reason: Option<String>,
}

/// The best current network test readings of one host, or of the hosts
/// behind one offering. Each direction may be unknown on its own.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct NetworkTestSummaryView {
    pub best_download_bits_per_second: Option<u64>,
    /// The best download reading reached its server's limit; the value is that limit.
    pub best_download_at_limit: bool,
    pub best_upload_bits_per_second: Option<u64>,
    pub best_upload_at_limit: bool,
    pub lowest_latency_ms: Option<u32>,
    /// When the newest of the contributing readings was taken.
    pub measured_at: Option<DateTime<Utc>>,
    /// The name of the location of the test server each best reading was
    /// taken against. Absent from older backends.
    #[serde(default)]
    pub best_download_location_name: Option<String>,
    #[serde(default)]
    pub best_upload_location_name: Option<String>,
    #[serde(default)]
    pub lowest_latency_location_name: Option<String>,
}

/// One host's latest result against one test server.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostNetworkTestResultView {
    pub server: String,
    pub server_name: String,
    pub location: String,
    pub location_name: String,
    pub observed_at: DateTime<Utc>,
    pub latency_ms: Option<u32>,
    pub download_bits_per_second: Option<u64>,
    pub download_at_limit: bool,
    pub upload_bits_per_second: Option<u64>,
    pub upload_at_limit: bool,
}

/// The per-server detail behind a host's network summary.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostNetworkTestsView {
    pub host_id: Uuid,
    pub summary: NetworkTestSummaryView,
    pub results: Vec<HostNetworkTestResultView>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderReliabilityView {
    pub provider_id: Uuid,
    pub window_started_at: DateTime<Utc>,
    pub window_ended_at: DateTime<Utc>,
    pub observed_milliseconds: u64,
    pub online_milliseconds: u64,
    pub uptime_basis_points: Option<u32>,
    pub distinct_rented_instances: u32,
    pub abandoned_instances: u32,
    pub abandonment_basis_points: Option<u32>,
}

/// A provider profile's status. Only an active provider's hosts take
/// rentals and only its page is public.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStatus {
    Pending,
    Active,
    Suspended,
    Closed,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderHostView {
    pub host_id: Uuid,
    pub label: String,
    pub mode: HostMode,
    pub status: String,
    pub location: String,
    /// Provider-controlled admission gate. This does not stop existing guests
    /// or prevent the agent from completing already queued work.
    pub rentals_paused: bool,
    pub active_instance_count: u32,
    pub can_retire: bool,
    pub retired_at: Option<DateTime<Utc>>,
    pub retirement_notice: Option<HostRetirementNoticeView>,
    /// Best current network test readings, or absent without a current result.
    #[serde(default)]
    pub network: Option<NetworkTestSummaryView>,
    /// When one of its pools' addresses first answered through this cloud
    /// host. Until then it cannot resume admitting rentals. Always absent
    /// for a home host, whose rentals use the platform's gateways.
    pub public_path_verified_at: Option<DateTime<Utc>>,
    /// Why the last check through this unverified cloud host had no answer
    /// on any of its addresses.
    pub public_path_error: Option<String>,
    /// A check of addresses through this host is running now.
    pub public_path_checking: bool,
    /// When the host's last heartbeat arrived; absent before its first.
    #[serde(default)]
    pub last_heartbeat_at: Option<DateTime<Utc>>,
    /// What the host earns now, as its pricing read answers it; absent
    /// before its first publication.
    #[serde(default)]
    pub pricing: Option<HostPricingView>,
    /// The host's CPU model as its agent reported it; absent before its
    /// first inventory.
    #[serde(default)]
    pub cpu_model: Option<String>,
    /// The memory of all its NUMA nodes, and the capacity of all its
    /// storage pools (root disks and local backups).
    #[serde(default)]
    pub memory_bytes: u64,
    #[serde(default)]
    pub storage_bytes: u64,
    /// The memory installed: the sizes of the memory modules its hardware
    /// report lists, summed; 0 while it lists none.
    #[serde(default)]
    pub installed_memory_bytes: u64,
    /// The storage installed: the capacity of the disks below its storage
    /// pools, a disk that several pools share counted once; 0 while its
    /// inventory names none.
    #[serde(default)]
    pub installed_storage_bytes: u64,
    /// The release its agent reported last and where it stands in the
    /// support window: when the backend stops serving it, and whether it is
    /// below the oldest release the platform serves. Absent from a backend
    /// of before.
    #[serde(default)]
    pub release_support: Option<crate::support_window::ReleaseSupportView>,
    /// Its uptime window, the Uptime tab's 365-day period: back from now by
    /// 365 24-hour days, from its enrollment when later, to its retirement
    /// when retired (empty for a host enrolled this instant); and of it, the
    /// time it was down as the SLA counts it, excusing the platform's
    /// incidents as the credits do. Both 0 from a backend of before.
    #[serde(default)]
    pub uptime_window_milliseconds: u64,
    #[serde(default)]
    pub downtime_milliseconds: u64,
    /// Whether the host is private: only its provider and the accounts the provider allows place
    /// new instances on it, and no public read shows it. False from a backend of before.
    #[serde(default)]
    pub private: bool,
    /// Whether an agent release waits for the provider's approval
    /// ([`HostAgentUpdateView::pending_approval`]). False from a backend of
    /// before.
    #[serde(default)]
    pub agent_update_pending: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum ProviderIncidentSeverity {
    Info,
    Warning,
    Error,
    Critical,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    #[cfg_attr(feature = "clap", value(skip))]
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum ProviderIncidentState {
    Open,
    Acknowledged,
    Resolved,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    #[cfg_attr(feature = "clap", value(skip))]
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderIncidentView {
    pub incident_id: Uuid,
    pub provider_id: Uuid,
    pub fingerprint: String,
    pub kind: String,
    pub severity: ProviderIncidentSeverity,
    pub state: ProviderIncidentState,
    pub title: String,
    pub summary: String,
    pub recommended_action: Option<String>,
    /// Sanitized operational data only; renter initialization data and guest
    /// secrets are never included.
    pub context: serde_json::Value,
    pub host_id: Option<Uuid>,
    pub job_id: Option<Uuid>,
    pub cloud_ip_address_id: Option<Uuid>,
    /// The address `cloud_ip_address_id` names, and its pool, while they
    /// are there.
    pub cloud_ip_address: Option<IncidentAddressView>,
    pub first_occurred_at: DateTime<Utc>,
    pub last_occurred_at: DateTime<Utc>,
    pub occurrence_count: u64,
    pub acknowledged_at: Option<DateTime<Utc>>,
    pub resolved_at: Option<DateTime<Utc>>,
}

/// The address an incident is about, in its pool.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IncidentAddressView {
    pub address: String,
    pub pool_id: Uuid,
    pub pool_label: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetProviderIncidentStateRequest {
    #[serde(deserialize_with = "known")]
    pub state: ProviderIncidentState,
}

/// The query of `GET /v1/provider/uptime` (`GetProviderUptime`), each field
/// a parameter of its name: the uptime of the account's providers' hosts by
/// label, those after the host `after` names, `limit` of them (100 by
/// default, 1 to 200), or of the one host `host` names (which no
/// other parameter goes with). Retired hosts are left out unless `retired`
/// is true (a host `host` names is answered either way, and an `after`
/// naming a retired host is only a position). The backend refuses a
/// parameter it does not know and a value it cannot read (400,
/// `invalid_query`). Serialized, absent fields are left out, in the order
/// of the fields.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderUptimeQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u16>,
    /// Whether retired hosts are listed too (false when absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired: Option<bool>,
}

/// The query of `GET /v1/provider/outages` (`ListProviderOutages`), each
/// field a parameter of its name: the outages of the account's providers'
/// hosts, newest first, of one host when given, and those that started on
/// the UTC days `from` to `to` (both included) when given. The backend
/// refuses a parameter it does not know and a value it cannot read (400,
/// `invalid_query`), a `to` before the `from`, a `from` or `to` before
/// 2000-01-01 or after 9999-12-31, and a `cursor` that is not a page's
/// `next_cursor` and a `limit` out of 1 to 200 (50 by default).
/// Without `from` the last 365 days are listed, and without `to` the days up
/// to today.
/// Serialized, absent fields are left out, in the order of the fields.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderOutageListQuery {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<chrono::NaiveDate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<chrono::NaiveDate>,
    /// Where the page starts: the `next_cursor` of the page before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u16>,
}

/// The uptime of the providers' hosts over the last 30, 90 and 365 days
/// (`GetProviderUptime`), host by host in the order of their labels.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderUptimeView {
    pub hosts: Vec<HostUptimeView>,
    /// Whether hosts follow the last one listed (read again with
    /// `after`).
    #[serde(default)]
    pub more: bool,
}

/// One host's uptime in each period.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct HostUptimeView {
    pub host_id: Uuid,
    pub label: String,
    /// The uptime the host's provider promises its renters, in basis
    /// points (9 900 is 99.00 %).
    pub sla_target_basis_points: u32,
    /// When the host was retired; absent for a host that is not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired_at: Option<DateTime<Utc>>,
    /// The last 30, 90 and 365 days, in that order.
    pub periods: Vec<UptimePeriodView>,
}

/// A host's uptime over the last `days` days (from its enrollment when
/// that is later, to its retirement when retired), counted as the SLA
/// credits count it.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UptimePeriodView {
    pub days: u32,
    /// The time the host existed in the period.
    pub window_milliseconds: u64,
    /// The time it was down, in all.
    pub downtime_milliseconds: u64,
    /// Of it, the time the platform's fault excuses.
    pub excluded_milliseconds: u64,
    /// The rest of it, the downtime that counts against the host.
    pub counted_milliseconds: u64,
    /// The uptime that counts, in basis points, rounded down; none for an
    /// empty window.
    pub uptime_basis_points: Option<u32>,
    /// Whether that is below the host's target.
    pub below_target: bool,
    /// The SLA credits of the outages that started in the period: asked
    /// for, and settled so far.
    pub credits_requested_microusd: u64,
    pub credits_settled_microusd: u64,
    /// Whether an outage of the period is still to be settled, so its
    /// credits can still grow.
    pub credits_settling: bool,
}

/// One page of outages, newest first, with the totals of everything the
/// filters match (`ListProviderOutages`).
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderOutagePage {
    pub items: Vec<ProviderOutageView>,
    pub next_cursor: Option<String>,
    pub totals: ProviderOutageTotals,
}

/// What the outages the filters match came to, all pages together.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderOutageTotals {
    pub outages: u64,
    /// Their time, as an outage's own view has it, an ongoing one up to
    /// now.
    pub duration_milliseconds: u64,
    pub excluded_milliseconds: u64,
    pub counted_milliseconds: u64,
    pub credits_requested_microusd: u64,
    pub credits_settled_microusd: u64,
    /// How many of them are still to be settled.
    pub settling: u64,
}

/// One outage of a host.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderOutageView {
    pub outage_id: Uuid,
    pub host_id: Uuid,
    pub host_label: String,
    /// When the host was retired; absent for a host that is not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_retired_at: Option<DateTime<Utc>>,
    pub started_at: DateTime<Utc>,
    /// None while it lasts.
    pub ended_at: Option<DateTime<Utc>>,
    /// Its length, up to now while it lasts.
    pub duration_milliseconds: u64,
    /// `heartbeat_timeout`, `operator` or `maintenance`.
    pub reason: String,
    /// The part the platform's fault excuses.
    pub excluded_milliseconds: u64,
    /// The rest, which counts against the host.
    pub counted_milliseconds: u64,
    /// The rentals it touched: those billed on the host at any time in it.
    pub rentals: u32,
    pub credits_requested_microusd: u64,
    pub credits_settled_microusd: u64,
    /// Whether its credits are not final: it lasts, or its rentals are
    /// not all credited yet.
    pub settling: bool,
}

/// An outage with its rentals (`GetProviderOutage`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderOutageDetailView {
    pub outage: ProviderOutageView,
    /// The rentals it touched, each with the credit it was owed. A rental
    /// not credited yet is listed without one.
    pub rentals: Vec<ProviderOutageRentalView>,
    /// The incident it raised, while that still records this outage.
    pub incident_id: Option<Uuid>,
}

/// A rental an outage touched.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderOutageRentalView {
    pub instance_id: Uuid,
    /// The multiple of the base price its SLA credits (1, 5 or 20).
    pub credit_multiplier: u32,
    /// None before the rental is credited.
    pub credit: Option<ProviderOutageCreditView>,
}

/// The credit one rental was owed for an outage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ProviderOutageCreditView {
    /// The downtime that counted for the rental.
    pub outage_milliseconds: u64,
    pub requested_credit_microusd: u64,
    pub settled_credit_microusd: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[cfg_attr(feature = "clap", value(rename_all = "snake_case"))]
pub enum SupportTicketCategory {
    Account,
    Billing,
    Provisioning,
    Networking,
    #[cfg_attr(feature = "clap", value(alias = "backup-restore"))]
    BackupRestore,
    #[cfg_attr(feature = "clap", value(alias = "provider-host"))]
    ProviderHost,
    Abuse,
    Other,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    #[cfg_attr(feature = "clap", value(skip))]
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum SupportTicketPriority {
    Low,
    Normal,
    High,
    Urgent,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    #[cfg_attr(feature = "clap", value(skip))]
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum SupportTicketState {
    Open,
    Waiting,
    Resolved,
    Closed,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    #[cfg_attr(feature = "clap", value(skip))]
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum SupportWaitingOn {
    User,
    Support,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    #[cfg_attr(feature = "clap", value(skip))]
    Unknown,
}

/// What a ticket is about, as the backend shows it: a kind a newer backend
/// adds reads as [`Self::Unknown`], whatever it carries.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SupportTicketResource {
    Instance {
        instance_id: Uuid,
    },
    Backup {
        backup_id: Uuid,
    },
    LedgerTransaction {
        ledger_transaction_id: Uuid,
    },
    Host {
        host_id: Uuid,
    },
    ProviderIncident {
        provider_incident_id: Uuid,
    },
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

/// What a new ticket is about, as its request names it: the kinds and the
/// fields this backend knows, and nothing else.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SupportTicketResourceInput {
    Instance { instance_id: Uuid },
    Backup { backup_id: Uuid },
    LedgerTransaction { ledger_transaction_id: Uuid },
    Host { host_id: Uuid },
    ProviderIncident { provider_incident_id: Uuid },
}

impl From<SupportTicketResourceInput> for SupportTicketResource {
    fn from(input: SupportTicketResourceInput) -> Self {
        match input {
            SupportTicketResourceInput::Instance { instance_id } => Self::Instance { instance_id },
            SupportTicketResourceInput::Backup { backup_id } => Self::Backup { backup_id },
            SupportTicketResourceInput::LedgerTransaction {
                ledger_transaction_id,
            } => Self::LedgerTransaction {
                ledger_transaction_id,
            },
            SupportTicketResourceInput::Host { host_id } => Self::Host { host_id },
            SupportTicketResourceInput::ProviderIncident {
                provider_incident_id,
            } => Self::ProviderIncident {
                provider_incident_id,
            },
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SupportTicketSummaryView {
    pub ticket_id: Uuid,
    /// Short public alias for the requesting account. This is primarily useful
    /// in the operator queue and is not an authentication identifier.
    pub account_alias: String,
    pub category: SupportTicketCategory,
    pub priority: SupportTicketPriority,
    pub state: SupportTicketState,
    pub waiting_on: Option<SupportWaitingOn>,
    pub subject: String,
    pub resource: Option<SupportTicketResource>,
    pub message_count: u32,
    pub last_message_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
    pub closed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SupportTicketMessageView {
    pub message_id: Uuid,
    pub message_number: u32,
    pub author_role: String,
    pub body: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SupportTicketView {
    pub ticket: SupportTicketSummaryView,
    pub messages: Vec<SupportTicketMessageView>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateSupportTicketRequest {
    #[serde(deserialize_with = "known")]
    pub category: SupportTicketCategory,
    #[serde(deserialize_with = "known")]
    pub priority: SupportTicketPriority,
    pub subject: String,
    pub message: String,
    pub resource: Option<SupportTicketResourceInput>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AddSupportTicketMessageRequest {
    pub message: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetSupportTicketStateRequest {
    #[serde(deserialize_with = "known")]
    pub state: SupportTicketState,
    #[serde(default, deserialize_with = "known_option")]
    pub waiting_on: Option<SupportWaitingOn>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetHostRentalPauseRequest {
    pub paused: bool,
}

/// How a host takes new agent releases: on the provider's approval of each
/// one (`Manual`, the default) or from the operator's rollouts
/// (`Automatic`).
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentUpdatePolicy {
    #[default]
    Manual,
    Automatic,
    /// A policy of a newer backend.
    #[serde(other)]
    Unknown,
}

/// Where one attempt to update a host's agent is.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentUpdateState {
    PendingApproval,
    Approved,
    Ordered,
    Staged,
    Applying,
    Succeeded,
    RolledBack,
    Failed,
    Cancelled,
    /// A state of a newer backend.
    #[serde(other)]
    Unknown,
}

/// A weekly maintenance window in UTC, on the days of `days`: bit 0 is
/// Monday and bit 6 Sunday. It opens `start_minute` minutes after midnight
/// of each of them, and stays open for `minutes`, 60 to 1440; it may run
/// into the next day.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AgentUpdateWindow {
    pub days: u8,
    pub start_minute: u16,
    pub minutes: u16,
}

/// One attempt to update a host's agent.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct AgentUpdateAttemptView {
    pub update_id: Uuid,
    pub release: String,
    pub state: AgentUpdateState,
    /// The operator's rollout that asked for it, if one did.
    pub rollout_id: Option<Uuid>,
    pub failure_code: Option<String>,
    pub detail: Option<String>,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

/// A host's agent: what it runs, what it may take, and how it took it.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[expect(clippy::struct_excessive_bools, reason = "each is a fact of its own")]
pub struct HostAgentUpdateView {
    pub host_id: Uuid,
    /// The release its agent last reported.
    pub installed_release: Option<String>,
    /// Whether its agent can update itself.
    pub remote_updates: bool,
    /// Whether the host's own file refuses remote updates.
    pub locally_disabled: bool,
    /// The newest release of the hypervisor channel, when it is known.
    pub channel_release: Option<String>,
    /// The command that updates an agent that cannot update itself.
    pub install_command: Option<String>,
    /// Whether this backend's release channel cannot name one release, so
    /// that an approved attempt waits.
    pub named_release_unavailable: bool,
    pub policy: AgentUpdatePolicy,
    /// Whether a pause holds now.
    pub paused: bool,
    /// When it ends; none while it holds until it is lifted.
    pub paused_until: Option<DateTime<Utc>>,
    pub window: Option<AgentUpdateWindow>,
    /// Names the policy, pause and window of this answer, for
    /// [`SetAgentUpdatePolicyRequest::policy_revision`]; none from a backend
    /// of before.
    #[serde(default)]
    pub policy_revision: Option<String>,
    /// The attempt in progress.
    pub target: Option<AgentUpdateAttemptView>,
    /// The release that waits for the provider's approval.
    pub pending_approval: Option<String>,
    /// The newest attempt that failed or was rolled back.
    pub last_failure: Option<AgentUpdateAttemptView>,
    /// The newest attempts, at most 20, the newest first.
    pub history: Vec<AgentUpdateAttemptView>,
}

/// A host's update policy, whole (`SetHostAgentUpdatePolicy`).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetAgentUpdatePolicyRequest {
    #[serde(deserialize_with = "known")]
    pub policy: AgentUpdatePolicy,
    pub paused: bool,
    /// When a pause ends; none for a pause until it is lifted.
    #[serde(default)]
    pub paused_until: Option<DateTime<Utc>>,
    #[serde(default)]
    pub window: Option<AgentUpdateWindow>,
    /// The [`HostAgentUpdateView::policy_revision`] the rest was taken from:
    /// a host that no longer answers it refuses the change, for a page that
    /// stayed open. Left out, the change replaces what is there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_revision: Option<String>,
}

/// Approve one exact release for a host (`ApproveHostAgentUpdate`).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveAgentUpdateRequest {
    pub release: String,
}

/// Names the attempt to retry or cancel (`RetryHostAgentUpdate`,
/// `CancelHostAgentUpdate`).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentUpdateAttemptRequest {
    pub update_id: Uuid,
}

/// Make a host private or public again (`SetHostPrivate`).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetHostPrivateRequest {
    pub private: bool,
}

/// Whether a host is private, and what of accounts its provider does not allow is on it: their live
/// instances and local backups, which stay as they are while it is private (they run, reinstall,
/// upgrade in place and are billed as before; only new instances are refused). `GetHostPrivacy`
/// answers it before a change, so the provider sees what stays before it confirms; `SetHostPrivate`
/// after.
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct HostPrivacyView {
    pub host_id: Uuid,
    pub private: bool,
    /// The host's instances, not deleted or failed, of accounts the
    /// provider does not allow.
    pub kept_instances: u32,
    /// The local backups stored on the host, not deleted, of such accounts.
    pub kept_local_backups: u32,
}

/// An account a provider allows on its private hosts, as the provider added it, and what of it is
/// on those hosts: its live instances and local backups, which stay should the provider remove it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PrivateRenterView {
    pub account_alias: String,
    pub added_at: DateTime<Utc>,
    #[serde(default)]
    pub kept_instances: u32,
    #[serde(default)]
    pub kept_local_backups: u32,
}

/// Allow an account on the provider's private hosts, by its alias
/// (`AddPrivateRenter`).
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AddPrivateRenterRequest {
    pub alias: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleHostRetirementRequest {
    /// Server-timed notice period. Seven full days is the minimum.
    pub notice_period_days: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeclareHostEmergencyRequest {
    /// Provider-visible and renter-visible explanation. Never include secrets.
    pub reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ScheduleInstanceRetirementRequest {
    /// Seven full days is the minimum.
    pub notice_period_days: u32,
    pub reason: Option<String>,
}

/// The signed release channels a deployment offers for download: the
/// hypervisor agent, the CLI and ghostd. Each names its manifest and the install
/// script the backend serves for it; the one release public key verifies
/// every manifest. A channel is absent until the operator configures it.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReleaseChannelsView {
    pub release_public_key_pem: Option<String>,
    pub hypervisor: Option<ReleaseChannelView>,
    pub cli: Option<ReleaseChannelView>,
    /// ghostd, the daemon on an instance; absent from a backend of before.
    #[serde(default)]
    pub ghostd: Option<ReleaseChannelView>,
    /// The container machines' kernel; absent from a backend of before.
    #[serde(default)]
    pub kernel: Option<KernelChannelView>,
    /// The rescue system; absent from a backend of before.
    #[serde(default)]
    pub rescue: Option<RescueChannelView>,
}

/// The kernel release channel; it has no install script.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct KernelChannelView {
    pub manifest_url: String,
    /// The verified current kernel release (`6.18.57-gh1`); absent until
    /// a release is available.
    #[serde(default)]
    pub release: Option<String>,
}

/// The rescue release channel; it has no install script.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct RescueChannelView {
    pub manifest_url: String,
    /// The verified current rescue release (`13.4-r1`); absent until
    /// a release is available.
    #[serde(default)]
    pub release: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReleaseChannelView {
    pub manifest_url: String,
    /// The install script: `curl -fsSL URL | sudo sh` for the hypervisor
    /// agent, `curl -fsSL URL | sh` for the CLI and ghostd.
    pub install_url: String,
}

/// The provider's full host view: listing, latest heartbeat, hardware
/// and inventory, allocated and free capacity per NUMA node and storage
/// pool, and current host and rental resource usage.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderHostDetailView {
    pub host: ProviderHostView,
    /// The host's saleable vCPUs: its CPU limit per NUMA node times its
    /// allowed NUMA nodes, what a whole-host compute total is kept for.
    #[serde(default)]
    pub saleable_vcpus: u32,
    /// The memory the host gives a VM for each logical CPU it reserves.
    pub memory_bytes_per_cpu_core: u64,
    /// The root disk the host gives a VM for each logical CPU it reserves.
    /// 0 from a backend of before.
    #[serde(default)]
    pub root_storage_bytes_per_cpu_core: u64,
    /// What the host's rentals hold now of its capacity.
    #[serde(default)]
    pub rented: ProviderHostRentedView,
    /// The least memory the platform offers a new VM with.
    pub minimum_instance_memory_bytes: u64,
    /// The sizes the host would offer that have less memory than that and
    /// are not offered. A larger `memory_bytes_per_cpu_core`, which takes
    /// a new enrollment, brings them back.
    pub sizes_below_minimum_memory: Vec<HostSizeView>,
    /// The least root disk the platform offers a new VM with; 0 from a
    /// backend of before.
    #[serde(default)]
    pub minimum_instance_disk_bytes: u64,
    /// The least memory the platform offers a new container instance with
    /// (`minimum_container_memory_bytes`); 0 from a backend of before.
    #[serde(default)]
    pub minimum_container_memory_bytes: u64,
    /// The least root disk the platform offers a new container instance
    /// with (`minimum_container_disk_bytes`); 0 from a backend of before.
    #[serde(default)]
    pub minimum_container_disk_bytes: u64,
    /// The sizes the host would offer that have less root disk than that
    /// and are not offered (a size may be in both lists). A larger
    /// `root_storage_bytes_per_cpu_core`, which takes a new enrollment,
    /// brings them back.
    #[serde(default)]
    pub sizes_below_minimum_disk: Vec<HostSizeView>,
    /// The revisions of the host's capacity profile, the newest (the
    /// profile now) first, at most 100: revision 1 is the enrollment's,
    /// and each accepted increase adds one.
    #[serde(default)]
    pub capacity_revisions: Vec<HostCapacityRevisionView>,
    pub agent_version: String,
    pub heartbeat_interval_seconds: u32,
    pub inventory_revision: Option<Uuid>,
    pub inventory_collected_at: Option<DateTime<Utc>>,
    pub heartbeat: Option<ProviderHostHeartbeatView>,
    pub hardware: ProviderHostHardwareView,
    pub numa_nodes: Vec<ProviderHostNumaNodeView>,
    pub storage_pools: Vec<ProviderHostStoragePoolView>,
    /// The latest current metrics, in the shape of one `current` item of
    /// the host metrics page; absent before the first host sample.
    pub current: Option<serde_json::Value>,
    /// What the host's agent reported last of the catalog images it keeps
    /// downloaded ahead of demand; absent on a host that downloads an image
    /// only when a VM needs it.
    #[serde(default)]
    pub image_cache: Option<HostImageCacheView>,
}

/// What a host's rentals hold now of its capacity: every rental whose
/// capacity is reserved on it, running or stopped, until it is deleted.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProviderHostRentedView {
    /// The rentals.
    pub instance_count: u32,
    /// Their CPU, in thousandths of a vCPU of the host's saleable vCPUs: a
    /// VM of 2 vCPUs on half cores holds 1,000.
    pub cpu_millis: u64,
    /// Their sizes' RAM.
    pub memory_bytes: u64,
    /// Their root disks' sizes.
    pub root_disk_bytes: u64,
}

/// The image cache of a host that downloads the catalog's images ahead of
/// demand, as its agent reported it last.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct HostImageCacheView {
    pub reported_at: DateTime<Utc>,
    /// What the cached images take, and the most they may take
    /// (`image_cache_max_bytes`).
    pub cached_bytes: u64,
    pub limit_bytes: u64,
    /// The size of the cache's filesystem and what is free of it.
    pub filesystem_total_bytes: u64,
    pub filesystem_free_bytes: u64,
    /// The rate pre-downloads keep to.
    pub rate_bits_per_second: u64,
    /// Every image the agent keeps, in the order it downloads them.
    pub images: Vec<HostCachedImageView>,
}

/// A catalog image a host keeps downloaded, and what of it is there.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct HostCachedImageView {
    pub image_id: Uuid,
    /// The image's catalog slug; empty for an image the catalog does not
    /// know.
    pub slug: String,
    pub state: ImageCacheState,
    pub size_bytes: Option<u64>,
    /// What has arrived of a download under way.
    pub downloaded_bytes: u64,
    /// Why the image is left out, what its download waits for, or what
    /// failed last.
    pub reason: Option<String>,
}

/// One accepted revision of a host's capacity profile: the CPU limit per NUMA
/// node and the NUMA nodes. RAM and root storage per logical CPU stay as enrolled.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct HostCapacityRevisionView {
    pub revision: u32,
    pub accepted_at: DateTime<Utc>,
    /// Why the capacity was raised; absent for the enrollment's.
    pub reason: Option<String>,
    pub cpu_core_limit_per_numa_node: u32,
    pub allowed_numa_nodes: Vec<u32>,
}

/// A size of VM a host's capacity profile yields.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct HostSizeView {
    pub cpu_tier: CpuTier,
    pub vcpu_count: u32,
    pub memory_bytes: u64,
    /// 0 from a backend of before.
    #[serde(default)]
    pub root_disk_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProviderHostHeartbeatView {
    pub observed_at: DateTime<Utc>,
    pub received_at: DateTime<Utc>,
    pub health: String,
    pub agent_version: String,
    pub agent_uptime_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProviderHostHardwareView {
    pub cpu_architecture: Option<String>,
    pub cpu_vendor: Option<String>,
    pub cpu_model: Option<String>,
    pub socket_count: Option<u32>,
    pub physical_core_count: Option<u32>,
    pub logical_thread_count: Option<u32>,
    /// The host's own CPU score; none until it has run the suite, and absent from older backends.
    #[serde(default)]
    pub cpu_score: Option<CpuBenchmarkView>,
}

/// One NUMA node's saleable capacity and what rentals hold of it. CPU is
/// in thousandths of a logical CPU; memory excludes the host reservation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProviderHostNumaNodeView {
    pub node_index: u32,
    pub enabled: bool,
    pub physical_core_count: u32,
    pub logical_thread_count: u32,
    pub memory_bytes: u64,
    pub host_reserved_memory_bytes: u64,
    /// The nominal RAM the node sells to guests, which the rentals'
    /// `allocated_memory_bytes` count against: what the host does not keep
    /// (`memory_bytes` less `host_reserved_memory_bytes`) less the 0.5 % of
    /// it the VMs' memory-dependent overhead takes. 0 from a backend of
    /// before.
    #[serde(default)]
    pub guest_memory_bytes: u64,
    pub cpu_capacity_millis: u64,
    pub allocated_cpu_millis: u64,
    pub allocated_memory_bytes: u64,
    /// The maximum instances, VMs and containers together, on the node:
    /// no more than eight per logical CPU (one-vCPU Shared 8x shares), or four
    /// per logical CPU in older responses.
    #[serde(default)]
    pub instance_limit: u32,
    /// The rentals on the node; no more than `instance_limit`.
    pub allocated_instances: u32,
}

/// One storage pool's saleable capacity and what holds room in it: the
/// rentals' disks and the scratch of their backups in progress in a root
/// pool, the artifacts of local backups in a backup pool.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ProviderHostStoragePoolView {
    pub external_id: String,
    pub kind: String,
    pub backend: StorageBackend,
    pub enabled: bool,
    pub capacity_bytes: u64,
    pub host_reserved_bytes: u64,
    pub allocated_bytes: u64,
    pub software_raid_levels: Vec<String>,
    /// The levels of the arrays of hardware RAID controllers below the
    /// pool, as in an offering.
    #[serde(default)]
    pub hardware_raid_levels: Vec<String>,
    pub backing_devices: Vec<StorageDeviceInventory>,
    /// Whether the pool sits on rotating disks, as the host's agent reports: a backup pool on them
    /// works on one local backup or restore at a time. Absent when the agent does not say, and from
    /// older backends.
    #[serde(default)]
    pub rotational: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostRetirementNoticeView {
    pub notice_id: Uuid,
    pub notice_created_at: DateTime<Utc>,
    pub deadline: DateTime<Utc>,
    pub state: HostRetirementState,
    pub affected_instance_count: u32,
    pub pending_instance_count: u32,
    pub action_required_instance_count: u32,
    pub last_error: Option<String>,
    pub reason: Option<String>,
    pub emergency: bool,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostRetirementState {
    Scheduled,
    Terminating,
    ActionRequired,
    Completed,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum CloudIpPoolScope {
    Host,
    Account,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    #[cfg_attr(feature = "clap", value(skip))]
    Unknown,
}

/// Where a cloud address stands with its one-time check. Only a verified
/// address is ever assigned to a rental.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CloudIpVerification {
    /// Waiting to be checked through a host of its pool.
    Pending,
    /// A check holds it now, so no rental gets it meanwhile.
    Checking,
    /// Answered through `verified_host_id`.
    Verified,
    /// Did not answer; `verification_error` says how. It stays unassigned
    /// until the provider asks for another check and that one verifies it.
    Failed,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CloudIpAddressView {
    pub address_id: Uuid,
    pub address: String,
    pub gateway: Option<String>,
    pub prefix_length: u8,
    pub mac_address: Option<String>,
    pub status: String,
    pub verification: CloudIpVerification,
    pub verified_at: Option<DateTime<Utc>>,
    pub verified_host_id: Option<Uuid>,
    pub verification_error: Option<String>,
    /// When a check last finished with a result for this address.
    pub checked_at: Option<DateTime<Utc>>,
    /// While the address rests after its last rental, which it does for
    /// `cloud_ip_release_grace_seconds` after a rental that was reached at
    /// it: when it may go to a rental again. No rental gets it before.
    #[serde(default)]
    pub available_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// A pool's addresses counted, all of them, whichever an answer lists.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct CloudIpAddressCounts {
    /// Every address, removed ones too.
    pub total: u32,
    /// Those not removed.
    pub live: u32,
    /// Those a check verified.
    pub verified: u32,
    /// Those not removed whose check is still to come or runs.
    pub unchecked: u32,
    /// Those not removed whose last check failed.
    pub failed: u32,
    /// Those a rental holds or is being created with.
    pub in_use: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CloudIpPoolView {
    pub pool_id: Uuid,
    pub label: String,
    pub scope: CloudIpPoolScope,
    pub host_ids: Vec<Uuid>,
    /// Its addresses by address: every one, or the window a read asked
    /// for (`GET /v1/provider/ip-pools/{id}` with `after` and `limit`), or
    /// none (`GET /v1/provider/ip-pools?addresses=false`).
    pub addresses: Vec<CloudIpAddressView>,
    pub address_counts: CloudIpAddressCounts,
    /// Every host of the pool is retired and no rental or running check
    /// holds one of its addresses, so it can never admit a rental again and
    /// may be deleted to add its addresses to another pool.
    pub can_delete: bool,
    pub created_at: DateTime<Utc>,
    /// Set only in the answer to the pool's deletion; listings leave deleted
    /// pools out.
    pub deleted_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateCloudIpPoolRequest {
    pub label: String,
    #[serde(deserialize_with = "known")]
    pub scope: CloudIpPoolScope,
    pub host_ids: Vec<Uuid>,
}

/// Hand the pool of a retired host to the host that takes its place.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HandOverCloudIpPoolRequest {
    /// The host that gets the pool: one of the provider's cloud-routed
    /// hosts in the retired host's location.
    pub host_id: Uuid,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CloudIpAddressInput {
    pub address: String,
    pub gateway: Option<String>,
    pub prefix_length: u8,
    pub mac_address: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AddCloudIpAddressesRequest {
    pub addresses: Vec<CloudIpAddressInput>,
}

/// Every backup destination has a byte-metered creation charge, which the
/// request consents to: a request signed with the account key carries the
/// billing key's signature (`billing_authorization`), a website session the
/// charge its page showed (`accepted_charge`), never both.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CreateBackupRequest {
    #[serde(deserialize_with = "known")]
    pub destination: BackupDestinationKind,
    /// Unpadded base64url RFC 9180 X25519 public key, the seed's recovery
    /// key, so local and hosted artifacts share one portable encrypted
    /// format. A signed request carries it; for a website session, which
    /// leaves it out, the backend takes the account's current one.
    pub recipient_public_key: Option<String>,
    pub billing_authorization: Option<BillingAuthorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_charge: Option<AcceptedCharge>,
}

/// Every backup destination has a byte-metered restore charge, which the
/// request consents to as [`CreateBackupRequest`] does.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreBackupRequest {
    pub billing_authorization: Option<BillingAuthorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_charge: Option<AcceptedCharge>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BillingAuthorization {
    /// The creation of a backup signs the runtime configuration's revision,
    /// and a restore the revision recorded with the backup.
    pub pricing_revision: u64,
    pub maximum_charge_microusd: u64,
    /// Unpadded base64url Ed25519 signature by the account billing key.
    pub signature: String,
}

/// The charge of a paid backup operation as a website session accepted it:
/// the pricing revision and the most it costs, as the page showed them. The
/// backend refuses the operation when the prices changed since or the
/// operation costs more, and records the session's consent with the charge.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptedCharge {
    /// The creation of a backup accepts the runtime configuration's
    /// revision, and a restore the revision recorded with the backup.
    pub pricing_revision: u64,
    pub maximum_charge_microusd: u64,
}

/// What one kind of backup costs.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackupPrices {
    pub creation_charge_microusd_per_gib: u64,
    pub restore_charge_microusd_per_gib: u64,
    pub storage_charge_microusd_per_gib_month: u64,
}

/// The platform's backup prices, the same on every host. The creation of a
/// backup costs what is in effect when the backup is made, and the backup
/// keeps the restore and storage prices of that moment for its life.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BackupPricingView {
    /// The runtime configuration's revision, which the creation of a backup
    /// signs.
    pub pricing_revision: u64,
    /// A backup stored off its host, in the platform's object storage.
    pub hosted: BackupPrices,
    /// A backup stored on its instance's host, whose provider earns it.
    pub local: BackupPrices,
    pub billing_unit_bytes: u64,
    /// A backup is admitted while the balance, with the renter's credit at the provider for a local
    /// one and a live trial's credit, covers the creation of a backup as large as the volume and
    /// this much more: the protected balance. This read is public, so it is the platform's default;
    /// `GetAccountBalance` has the account's own. Installed clients decode it.
    pub balance_margin_microusd: u64,
}

/// The platform's own prices that the renting flow does not show, for the
/// docs and `ghost` (`GetPlatformPricing`).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PlatformPricingView {
    /// What the host mesh's traffic costs.
    pub mesh: MeshPricesView,
}

/// What a home instance pays per TiB it sends over the host mesh, to the platform over an internet
/// link (WAN mesh) and to its host's provider over a LAN link (LAN mesh); what it receives is free,
/// and so is what a cloud instance sends it beyond its own traffic price.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MeshPricesView {
    /// The WAN mesh price in effect.
    pub wan_mesh_microusd_per_tib: u64,
    /// The LAN mesh price in effect.
    pub lan_mesh_microusd_per_tib: u64,
    /// The changes announced and still to come, the soonest first: a raise
    /// takes effect 90 days after its notice.
    #[serde(default)]
    pub changes: Vec<MeshPriceChangeView>,
}

/// A path of the host mesh's traffic.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshPath {
    /// An internet link.
    WanMesh,
    /// A LAN link.
    LanMesh,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

/// A mesh price change announced and still to come.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MeshPriceChangeView {
    pub path: MeshPath,
    pub microusd_per_tib: u64,
    pub announced_at: DateTime<Utc>,
    pub effective_at: DateTime<Utc>,
}

/// The query of `GET /v1/instances/{id}/mesh-usage`
/// (`GetInstanceMeshUsage`), each field a parameter of its name: a page of
/// a home instance's host mesh traffic over one path at a resolution. The
/// backend ignores a parameter it does not know and refuses a value it
/// cannot read (400, `invalid_query`); serialized, absent fields are left
/// out, in the order of the fields.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct MeshUsageQuery {
    /// `wan_mesh` (the default: internet links) or `lan_mesh`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// `15m` (the default), `daily` or `monthly`, in UTC.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<String>,
    /// Where the page starts: the `next_cursor` of the page before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
    /// How many, 1 to 200; 50 by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
}

/// Where a link of the host mesh carries an instance's traffic now
/// ([`InstanceMeshLinkView::state`]).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshLinkState {
    /// Over the mesh: both hosts find each other up and send through it.
    OnMesh,
    /// Back on the gateways: the link is down, or not switched on yet.
    Gateways,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

/// Why an instance has no link of the host mesh
/// ([`InstanceMeshView::no_link_reason`]).
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshNoLinkReason {
    /// The host mesh is switched off on the platform.
    MeshOff,
    /// No instance the mesh would reach: none of the account's on another
    /// host it links, and no LAN neighbour.
    NoPeer,
    /// The instance's home host is behind a NAT the mesh cannot get
    /// through to another home host (it maps each destination apart, or is
    /// not known yet); its traffic keeps the gateways.
    HostNat,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

/// What a link carried in one period: the bytes the instance sent over it
/// (billed at the link's price; a cloud instance's in its usual traffic)
/// and received (free).
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct MeshTrafficView {
    pub sent_bytes: u64,
    pub received_bytes: u64,
}

/// One link of the host mesh an instance is part of: another instance its traffic reaches over a
/// link between their hosts.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InstanceMeshLinkView {
    /// A LAN link, or one across the internet.
    pub kind: LanLinkKind,
    /// The other end when it is the renter's own instance; none for
    /// another customer's, which is never named.
    #[serde(default)]
    pub peer_instance_id: Option<Uuid>,
    /// The renter's own instance's name; none for another customer's.
    #[serde(default)]
    pub peer_name: Option<String>,
    /// The external peer's current public address, without its identity.
    #[serde(default)]
    pub peer_public_ipv4: Option<String>,
    /// One for an active external peer; zero for the renter's own instance.
    /// Older servers may aggregate several external peers in one row.
    #[serde(default)]
    pub other_customers: u32,
    pub state: MeshLinkState,
    /// Since when the link is in its state; none when unknown.
    #[serde(default)]
    pub state_since: Option<DateTime<Utc>>,
    /// Since when the two hosts have this link.
    pub linked_since: DateTime<Utc>,
    /// What it carried this UTC month, today (UTC) and in the last 15
    /// minutes billed ([`InstanceMeshView::quarter_started_at`]).
    #[serde(default)]
    pub month: MeshTrafficView,
    #[serde(default)]
    pub day: MeshTrafficView,
    #[serde(default)]
    pub quarter: MeshTrafficView,
}

/// An instance's links of the host mesh (`GetInstanceMesh`): one per
/// instance its traffic reaches over a link the mesh bills over, another
/// customer's identified only by public address when traffic is nonzero,
/// with what each carried. Only the links the bill counts are listed, so the traffic is
/// the bill's.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InstanceMeshView {
    pub instance_id: Uuid,
    /// Whether the host mesh is switched on.
    pub mesh_enabled: bool,
    #[serde(default)]
    pub links: Vec<InstanceMeshLinkView>,
    /// More than 1,024 active external peers were available; own peers remain.
    #[serde(default)]
    pub other_peers_truncated: bool,
    /// Why there is no link, when there is none.
    #[serde(default)]
    pub no_link_reason: Option<MeshNoLinkReason>,
    /// The periods of the links' traffic: this UTC month's start, today's,
    /// and the last 15 minutes billed (none before the instance's first).
    pub month_started_at: DateTime<Utc>,
    pub day_started_at: DateTime<Utc>,
    #[serde(default)]
    pub quarter_started_at: Option<DateTime<Utc>>,
    /// The prices of what it sends, per TiB: over an internet link and over
    /// a LAN link (a home instance's; a cloud instance's is its own traffic
    /// price).
    pub prices: MeshPricesView,
}

/// One UTC day of a host's mesh traffic: what its instances sent and
/// received over internet (WAN) and LAN links, and what the LAN mesh earned
/// its provider that day.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostMeshDayView {
    pub usage_date: chrono::NaiveDate,
    pub wan_sent_bytes: u64,
    pub wan_received_bytes: u64,
    pub lan_sent_bytes: u64,
    pub lan_received_bytes: u64,
    pub lan_earned_microusd: u64,
}

/// How many of a host's links are of a kind and in a state.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostMeshLinkCountView {
    pub kind: LanLinkKind,
    pub state: LanLinkState,
    pub count: u32,
}

/// A host's mesh summary (`GetProviderHostMesh`): its days of the last 30
/// with traffic or earnings, newest first, and its links by kind and state.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostMeshPeerView {
    pub peer_host_id: Option<Uuid>,
    pub peer_host_label: Option<String>,
    pub peer_public_ipv4: Option<String>,
    pub kind: LanLinkKind,
    pub state: LanLinkState,
    pub linked_since: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct HostMeshView {
    pub host_id: Uuid,
    #[serde(default)]
    pub days: Vec<HostMeshDayView>,
    #[serde(default)]
    pub links: Vec<HostMeshLinkCountView>,
    #[serde(default)]
    pub peer_links: Vec<HostMeshPeerView>,
    #[serde(default)]
    pub peer_links_truncated: bool,
}

/// One host's mesh over the last 30 days, summed
/// ([`ProviderMeshView::hosts`]).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderHostMeshView {
    pub host_id: Uuid,
    pub host_label: String,
    pub wan_sent_bytes: u64,
    pub wan_received_bytes: u64,
    pub lan_sent_bytes: u64,
    pub lan_received_bytes: u64,
    pub lan_earned_microusd: u64,
    /// Its links over the internet and over a LAN, of any state.
    pub internet_links: u32,
    pub lan_links: u32,
}

/// The provider's hosts' mesh over the last 30 days, per host
/// (`ListProviderMesh`): those with traffic, earnings or a link, by label.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ProviderMeshView {
    /// The first day summed (UTC); today is the last.
    pub since: chrono::NaiveDate,
    #[serde(default)]
    pub hosts: Vec<ProviderHostMeshView>,
}

impl BackupPricingView {
    /// What a backup of `destination` costs; nothing for a destination of
    /// a newer release.
    #[must_use]
    pub const fn prices(&self, destination: BackupDestinationKind) -> Option<BackupPrices> {
        match destination {
            BackupDestinationKind::Local => Some(self.local),
            BackupDestinationKind::GigahostS3 => Some(self.hosted),
            BackupDestinationKind::Unknown => None,
        }
    }
}

pub const BACKUP_BILLING_UNIT_BYTES: u64 = 1024 * 1024;

/// Return `(billable_mebibytes, charge_microusd)` using MiB/GiB and rounding a
/// non-empty byte count and its final micro-USD charge upward.
pub fn backup_byte_charge(bytes: u64, price_microusd_per_gib: u64) -> Option<(u64, u64)> {
    if bytes == 0 || price_microusd_per_gib == 0 {
        return None;
    }
    let mebibytes = bytes.div_ceil(BACKUP_BILLING_UNIT_BYTES);
    let numerator = mebibytes.checked_mul(price_microusd_per_gib)?;
    Some((mebibytes, numerator.div_ceil(1024)))
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizeBackupRestoreRequest {
    /// Unpadded base64url SHA-256 of the job-bound destination public key.
    pub destination_key_fingerprint: String,
    /// Unpadded base64url HPKE encapsulated key plus encrypted backup data key.
    pub destination_wrapped_data_key: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupDestinationKind {
    Local,
    GigahostS3,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupPurpose {
    Regular,
    /// Automatic encrypted restoration source created before an
    /// insufficient-funds VM deletion.
    FinalRecovery,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BackupView {
    pub backup_id: Uuid,
    pub instance_id: Uuid,
    pub destination: BackupDestinationKind,
    pub status: BackupState,
    pub purpose: BackupPurpose,
    /// Present for a final recovery backup and stable after its VM is deleted.
    pub funding_lifecycle_id: Option<Uuid>,
    pub size_bytes: Option<u64>,
    /// Immutable restore terms recorded when this backup was created.
    pub restore_pricing_revision: u64,
    pub restore_charge_microusd_per_gib: u64,
    /// Immutable retained-storage rate recorded when this backup was created.
    pub storage_charge_microusd_per_gib_month: u64,
    /// What keeping the backup costs a month at that rate for its size, as
    /// storage is charged: its size in whole MiB, times the rate per GiB,
    /// over 1024, rounded up. None until its size is known, and from older
    /// backends. A deleted or lost backup is no longer charged: this stays
    /// what keeping it cost, which the account's list sorts it by
    /// (`sort=cost`), and the website and the CLI show no cost for it.
    #[serde(default)]
    pub storage_cost_microusd_per_month: Option<u64>,
    /// Unpadded base64url SHA-256 fingerprint for hosted backup recovery.
    pub recipient_key_fingerprint: Option<String>,
    /// Unpadded base64url HPKE-wrapped per-backup data key.
    pub wrapped_data_key: Option<String>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    /// The host a local backup is stored on, which an instance created from
    /// it must be placed on. Absent for a hosted backup.
    #[serde(default)]
    pub host_id: Option<Uuid>,
    /// The location of a local backup's host. Absent for a hosted backup.
    #[serde(default)]
    pub location: Option<String>,
    /// The backed-up root disk's size: the smallest root a restore or a new
    /// instance from this backup needs.
    #[serde(default)]
    pub disk_bytes: Option<u64>,
    /// The firmware the backed-up system boots with.
    #[serde(default)]
    pub firmware: Option<GuestFirmware>,
    /// The catalog image of the instance when the backup was taken.
    #[serde(default)]
    pub image_id: Option<Uuid>,
    #[serde(default)]
    pub image_slug: Option<String>,
    #[serde(default)]
    pub image_name: Option<String>,
    /// The hostname of the instance when the backup was taken.
    #[serde(default)]
    pub hostname: Option<String>,
    /// The hostname and state of the instance the backup was taken of now.
    #[serde(default)]
    pub instance_hostname: Option<String>,
    /// The name of the instance the backup was taken of now
    /// ([`InstanceView::name`]). Absent from older backends.
    #[serde(default)]
    pub instance_name: Option<String>,
    #[serde(default)]
    pub instance_state: Option<InstanceState>,
    /// Set while the backup cannot be restored because the pool of its host
    /// that holds its artifact is missing, from the inventory that dropped
    /// the pool until the host has verified the artifact after the pool's
    /// return.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable: Option<BackupUnavailabilityView>,
    /// When the backup was marked lost: its artifact was gone when its pool
    /// returned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lost_at: Option<DateTime<Utc>>,
    /// What the backed-up instance was: a VM or a container instance, and so what a restore or a
    /// new instance from the backup is. A VM from older backends.
    #[serde(default)]
    pub kind: InstanceKind,
    /// What a container instance ran when its backup was taken, which a
    /// new instance from the backup runs; absent for a VM's backup. Its
    /// environment is never shown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<BackupContainerView>,
    /// The schedule's rule that made the backup; absent for a backup made by hand, and from older
    /// backends.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<BackupScheduleOriginView>,
}

/// The rule of an instance's schedule a backup was made by.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackupScheduleOriginView {
    pub rule_id: Uuid,
    pub frequency: BackupScheduleFrequency,
    /// Whether the rule has been removed from the schedule since: its
    /// backups are then never deleted by the schedule.
    #[serde(default)]
    pub removed: bool,
}

/// How often a rule of a backup schedule makes a backup.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupScheduleFrequency {
    Daily,
    Weekly,
    Monthly,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

/// The most rules an instance's backup schedule has.
pub const MAXIMUM_BACKUP_SCHEDULE_RULES: usize = 4;

/// The latest day of the month a monthly rule may name, so every month has
/// it.
pub const LATEST_BACKUP_SCHEDULE_DAY: u8 = 28;

/// One rule of an instance's backup schedule, as it is set: where its
/// backups go, how often and when (in UTC) they are made, and how many of
/// them are kept. A weekly rule names its weekday (0 is Sunday) and only a
/// weekly one; a monthly rule its day of the month (1 to 28) and only a
/// monthly one. Each backup starts within the hour after the time, at an
/// offset that is the same for every rule of the instance.
///
/// A rule with an `id` (a live rule's `rule_id`, as the schedule's read
/// answers it) changes that rule in place: its frequency, time, day and
/// keep may change, its destination may not, and it keeps its backups. A
/// rule without one is a new rule.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupScheduleRuleInput {
    /// The live rule this one changes; none for a new rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    #[serde(deserialize_with = "known")]
    pub destination: BackupDestinationKind,
    #[serde(deserialize_with = "known")]
    pub frequency: BackupScheduleFrequency,
    /// The time of day in UTC, in minutes after midnight: 0 to 1439.
    pub minute_of_day: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weekday: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub day_of_month: Option<u8>,
    /// How many of the rule's backups to keep: once a new one has
    /// completed, the oldest beyond this are deleted.
    pub keep: u32,
}

/// Replace an instance's backup schedule (`SetBackupSchedule`): at most
/// [`MAXIMUM_BACKUP_SCHEDULE_RULES`] rules, whose keeps, with one more for
/// each rule, together fit the account's backups-per-instance limit; none
/// clears it. A rule naming a live rule's `id` changes that rule and keeps
/// its backups (a lower keep deletes its oldest beyond the new keep, as a
/// completed run does); a rule without one is new; the live rules the
/// request does not name are removed, and their backups stay until
/// deleted by hand.
/// Setting a schedule is the renter's consent to each run's charge, at the
/// prices in force when it runs.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SetBackupScheduleRequest {
    pub rules: Vec<BackupScheduleRuleInput>,
}

/// What a scheduled run did.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupScheduleRunResult {
    /// The run made its backup (`last_backup_id`), whose state says how
    /// it went.
    Created,
    /// The balance could not pay the run, which was skipped; the renter
    /// was notified.
    SkippedBalance,
    /// A limit or the instance's state refused the run, which was skipped;
    /// the message says why.
    Skipped,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

/// One live rule of an instance's backup schedule.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BackupScheduleRuleView {
    pub rule_id: Uuid,
    pub destination: BackupDestinationKind,
    pub frequency: BackupScheduleFrequency,
    pub minute_of_day: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weekday: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub day_of_month: Option<u8>,
    pub keep: u32,
    pub created_at: DateTime<Utc>,
    /// When the rule's next backup starts: its next time after the last
    /// run, plus the instance's offset within the hour.
    pub next_run_at: DateTime<Utc>,
    #[serde(default)]
    pub last_run_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_result: Option<BackupScheduleRunResult>,
    /// Why the last run was skipped, in the API's words.
    #[serde(default)]
    pub last_message: Option<String>,
    /// The backup the last run that made one made, and its state now.
    #[serde(default)]
    pub last_backup_id: Option<Uuid>,
    #[serde(default)]
    pub last_backup_status: Option<BackupState>,
    /// The rule's backups that hold storage now (neither failed nor
    /// deleted).
    #[serde(default)]
    pub backup_count: u32,
    /// Of those, the completed ones (available, or being restored from),
    /// which its keep counts: any beyond the keep are its oldest, which
    /// the scheduler deletes within a minute or so, after a lower keep or
    /// once a new backup has completed. A change that lowers the keep
    /// deletes `min(completed_count, keep) - new keep` of them.
    #[serde(default)]
    pub completed_count: u32,
}

/// A rule removed from an instance's backup schedule, and how many of its
/// backups stay: the schedule never deletes them.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RemovedBackupScheduleRuleView {
    pub rule_id: Uuid,
    pub destination: BackupDestinationKind,
    pub frequency: BackupScheduleFrequency,
    pub keep: u32,
    pub removed_at: DateTime<Utc>,
    /// Its backups that hold storage (neither failed nor deleted).
    pub backups_kept: u32,
}

/// An instance's backup schedule (`GetBackupSchedule`, and the answer of
/// `SetBackupSchedule`).
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct BackupScheduleView {
    pub instance_id: Uuid,
    /// The live rules, in the order they were made.
    pub rules: Vec<BackupScheduleRuleView>,
    /// The removed rules whose backups stay: in the answer to a change,
    /// those it removed; in a read, those of the latest removed that keep
    /// some.
    #[serde(default)]
    pub removed: Vec<RemovedBackupScheduleRuleView>,
    /// The account's backups-per-instance limit, which the rules' keeps,
    /// with one more for each rule, must fit together.
    #[serde(default)]
    pub maximum_backups: u32,
}

/// One of the account's instances that has backups, as the backup list's
/// instance filter offers it (`GET /v1/backups/instances`,
/// `ListBackupInstances`): a deleted instance too, whose backups outlive
/// it, by its name and hostname as they were when it was deleted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackupInstanceView {
    pub instance_id: Uuid,
    /// The instance's name now ([`InstanceView::name`]).
    pub name: String,
    pub hostname: String,
    pub state: InstanceState,
}

impl BackupInstanceView {
    /// The name the renter sees the instance by, as
    /// [`InstanceView::display_name`] gives it.
    #[must_use]
    pub fn display_name(&self) -> &str {
        if self.name.is_empty() {
            &self.hostname
        } else {
            &self.name
        }
    }
}

/// What a container instance ran when its backup was taken.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackupContainerView {
    /// The image as the instance was created with it, in its canonical
    /// form: a tag or a digest ([`ContainerInstanceView::image`]).
    pub image: String,
    /// `REGISTRY/REPOSITORY@sha256:HEX`: the digest the instance's host had
    /// pinned; absent when it never reported one.
    #[serde(default)]
    pub image_digest: Option<String>,
    /// The slug of the platform's stock image the instance ran; absent for
    /// an image of the renter's.
    #[serde(default)]
    pub stock_image: Option<String>,
    #[serde(default)]
    pub restart_policy: RestartPolicy,
    /// The renter's paths the instance kept across a redeploy, which a new
    /// instance from the backup keeps too; empty from older backends and
    /// for a backup taken before they were kept.
    #[serde(default)]
    pub volumes: Vec<String>,
}

/// Why a local backup cannot be restored now, and since when. Its storage
/// is not charged meanwhile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BackupUnavailabilityView {
    pub since: DateTime<Utc>,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BackupState {
    Queued,
    Staging,
    Uploading,
    Available,
    Restoring,
    Failed,
    Deleting,
    Deleted,
    /// A local backup whose artifact was gone when its host's backup pool
    /// came back. It cannot be restored and is no longer charged; it stays
    /// listed until its owner deletes it.
    Lost,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

/// A factor of 1 in basis points, used when no shared-address traffic multiplier applies.
pub const SHARED_IP_TRAFFIC_MULTIPLIER_ONE: u32 = 10_000;

const fn default_shared_ip_traffic_multiplier() -> u32 {
    SHARED_IP_TRAFFIC_MULTIPLIER_ONE
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_one_multiplier(value: &u32) -> bool {
    *value == SHARED_IP_TRAFFIC_MULTIPLIER_ONE
}

/// Move a shared bandwidth instance to a shared gateway at another
/// location, from its offering's `gateway_locations`: the instance gets a
/// new public address there.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MoveGatewayLocationRequest {
    pub gateway_location: String,
}

/// Change a home instance's gateway: its tier, its location from the catalog's `gateway_locations`
/// for a shared tier (for high bandwidth a location with an enabled Vultr region, or without one
/// the nearest to the host), or both; at least one of them, and at least one different from now.
/// Every change gives the instance a new public address and costs the instance creation charge.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChangeGatewayRequest {
    /// The tier to change to; absent keeps the instance's. A tier this
    /// release does not know is refused.
    #[serde(
        default,
        deserialize_with = "known_option",
        skip_serializing_if = "Option::is_none"
    )]
    pub tier: Option<GatewayTier>,
    /// The location to change to; absent keeps the instance's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway_location: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ErrorResponse {
    pub code: String,
    pub message: String,
    /// The request's ID, which the response's `x-request-id` header names
    /// too.
    pub request_id: Option<String>,
    /// The job a 409 concerns, when there is one: the job to wait for, and
    /// retry after, for `instance_provisioning`, `instance_deleting`,
    /// `instance_failed`, `operation_in_progress` and `backup_in_progress`;
    /// the restore job for `restore_already_authorized` and
    /// `restore_offer_expired`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub job_id: Option<Uuid>,
}

/// A component's state on the public status page, from the platform's own
/// data or an open notice of the operator's.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[cfg_attr(feature = "clap", value(rename_all = "snake_case"))]
pub enum ComponentState {
    Operational,
    /// Planned maintenance is in progress.
    UnderMaintenance,
    Degraded,
    PartialOutage,
    MajorOutage,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    #[cfg_attr(feature = "clap", value(skip))]
    Unknown,
}

impl ComponentState {
    /// How bad the state is, for the worst of several: operational 0,
    /// under maintenance 1, degraded 2, partial outage 3, major outage 4. A
    /// state of a newer release counts as degraded: it is not operational.
    #[must_use]
    pub const fn severity(self) -> u8 {
        match self {
            Self::Operational => 0,
            Self::UnderMaintenance => 1,
            Self::Degraded | Self::Unknown => 2,
            Self::PartialOutage => 3,
            Self::MajorOutage => 4,
        }
    }

    /// The worse of the two.
    #[must_use]
    pub const fn worst(self, other: Self) -> Self {
        if other.severity() > self.severity() {
            other
        } else {
            self
        }
    }
}

/// What part of the platform a status component reports on.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusComponentKind {
    /// The website and the API, which serve the status page itself.
    Api,
    /// Renting at one location: its hosts.
    Rentals,
    /// The shared gateways of home rentals at one location.
    HomeGateways,
    /// Crediting MMX deposits to accounts.
    Deposits,
    /// Paying providers out.
    Payouts,
    /// The platform's backup storage, shown when a status notice names it.
    HostedBackups,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

/// Why deposits or payouts are not operational.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StatusReason {
    /// The chain has not been read for deposits for a while.
    DepositsNotScanned,
    /// Deposits that arrived are waiting to be credited, such as for an
    /// exchange rate.
    DepositsWaitingForCredit,
    /// The operator paused payouts.
    PayoutsPaused,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

/// Whether a status notice is about an incident or planned maintenance.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum StatusNoticeKind {
    Incident,
    Maintenance,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    #[cfg_attr(feature = "clap", value(skip))]
    Unknown,
}

/// Where a status notice stands: an incident's investigating, identified,
/// monitoring and resolved, or a planned maintenance's scheduled, in
/// progress and completed.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[cfg_attr(feature = "clap", value(rename_all = "snake_case"))]
pub enum StatusNoticeState {
    Investigating,
    Identified,
    Monitoring,
    Resolved,
    Scheduled,
    InProgress,
    Completed,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    #[cfg_attr(feature = "clap", value(skip))]
    Unknown,
}

impl StatusNoticeState {
    /// The kind of notice the state belongs to.
    #[must_use]
    pub const fn kind(self) -> StatusNoticeKind {
        match self {
            Self::Investigating | Self::Identified | Self::Monitoring | Self::Resolved => {
                StatusNoticeKind::Incident
            }
            Self::Scheduled | Self::InProgress | Self::Completed => StatusNoticeKind::Maintenance,
            Self::Unknown => StatusNoticeKind::Unknown,
        }
    }

    /// Whether the notice is over: resolved or completed.
    #[must_use]
    pub const fn is_final(self) -> bool {
        matches!(self, Self::Resolved | Self::Completed)
    }
}

/// What the public status page shows: the overall state, every component
/// and the operator's notices. Nothing in it names a host, a provider or an
/// account.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PlatformStatusView {
    /// The worst state of any component.
    pub overall: ComponentState,
    pub components: Vec<StatusComponentView>,
    /// Open notices first, newest first, then those that ended in the last
    /// 90 days.
    pub notices: Vec<StatusNoticeView>,
    /// When the status data was calculated; responses may be 15 seconds old.
    pub generated_at: DateTime<Utc>,
}

/// One component of the status page.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StatusComponentView {
    /// Its key, which notices name: `api`, `rentals.<location>`,
    /// `home-gateways.<location>`, `deposits`, `payouts` or
    /// `hosted-backups`.
    pub component: String,
    pub kind: StatusComponentKind,
    /// The location of a rentals or home gateways component.
    pub location: Option<String>,
    pub location_name: Option<String>,
    /// Its state: an in-progress maintenance's, else what the platform's
    /// data says, made worse by any open incident that affects it.
    pub state: ComponentState,
    /// What the platform's own data says, before notices; `None` for a
    /// component the backend keeps no signal for, shown because a notice
    /// names it.
    pub automatic_state: Option<ComponentState>,
    /// For rentals, the hosts there that report, and for home gateways the
    /// shared gateways there that are healthy.
    pub healthy: Option<u32>,
    /// For rentals, the hosts listed there, and for home gateways the
    /// shared gateways that carry rentals there.
    pub total: Option<u32>,
    /// Why deposits or payouts are not operational.
    pub reason: Option<StatusReason>,
    /// The open notices that name it, scheduled maintenance included,
    /// newest first.
    pub notice_ids: Vec<Uuid>,
}

/// An incident or a planned maintenance the operator writes on the status
/// page, with its timed updates.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StatusNoticeView {
    pub notice_id: Uuid,
    pub kind: StatusNoticeKind,
    pub title: String,
    pub state: StatusNoticeState,
    /// What an open incident does to the components it names: degraded,
    /// partial or major outage. A maintenance's is under maintenance, from
    /// when it is in progress.
    pub impact: ComponentState,
    /// The keys of the components it affects.
    pub components: Vec<String>,
    /// When a planned maintenance is to begin and end.
    pub scheduled_start: Option<DateTime<Utc>>,
    pub scheduled_end: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    /// When it was resolved or completed.
    pub resolved_at: Option<DateTime<Utc>>,
    /// Newest first; the first one created it.
    pub updates: Vec<StatusNoticeUpdateView>,
}

/// One timed update of a status notice.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StatusNoticeUpdateView {
    pub update_id: Uuid,
    /// The notice's state from this update on.
    pub state: StatusNoticeState,
    pub message: String,
    pub created_at: DateTime<Utc>,
}

/// Where a pair of hosts meshes ([`HostMeshLinkCountView::kind`]).
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LanLinkKind {
    /// Two home hosts on one LAN.
    #[default]
    Lan,
    /// Two hosts across the internet that share running instances of one renter account, at least
    /// one of them a home host: only that account's instances reach each other over it.
    Internet,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

/// The state of a host mesh link ([`HostMeshLinkCountView::state`]).
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LanLinkState {
    /// The link has not yet been proven available in both directions.
    Candidate,
    /// The link has been proven available in both directions.
    Proven,
    /// The link is no longer available.
    Lost,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}
