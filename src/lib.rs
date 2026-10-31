//! The `ghost` command-line client as a library, so integration tests can
//! drive real commands in-process. The binary in `main.rs` only parses the
//! command line, calls [`execute`], and prints the result with
//! [`render_output`] or the failure with [`render_error`]. A result is
//! shown for reading unless `--json` or `--compact` asks for JSON.

mod api;
mod dispatch;
pub use dispatch::dispatch;
#[cfg(unix)]
mod console;
#[cfg(unix)]
mod ghostd;
mod keys;
mod pretty;

#[cfg(unix)]
pub use console::run_console;
#[cfg(unix)]
pub use ghostd::run_direct;
pub use pretty::Terminal;

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    fmt::Write as _,
    fs,
    io::Read as _,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::LazyLock,
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
pub use api::{Answered, ApiClient, MutationKey};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use clap::{Args, CommandFactory as _, FromArgMatches as _, Parser, Subcommand, ValueEnum};
use gigahost_client_api::{
    account_auth::{
        BackupBillingAuthorizationInput, SeedMigrationInput,
        canonical_backup_billing_authorization, canonical_seed_migration,
    },
    api::{
        AccountDeposits, AccountHistory, AccountSlaCredits, ActivateAccount, AddIpAddresses,
        AddPrivateRenter, AddTicketMessage, ApproveHostAgentUpdate, AuthorizeBackupRestore,
        CancelBackup, CancelHostAgentUpdate, ChangeGateway, CheckHostPublicPath, CheckIpAddress,
        CompleteOperationIntent, CreateBackup, CreateGithubLink, CreateGithubSignup,
        CreateHostEnrollmentToken, CreateInstance, CreateIpPool, CreateLoginGrant, CreatePayout,
        CreateTicket, DeclareHostEmergency, DeleteBackup, DeleteInstance, DeleteIpPool,
        EndInstanceRescue, GetAccount, GetAccountBalance, GetActivationTerms, GetBackup,
        GetBackupPricing, GetBackupSchedule, GetGithubClaim, GetHostAgentUpdate,
        GetHostNetworkTests, GetHostPricing, GetHostPrivacy, GetIncident, GetInstance,
        GetInstanceConsoleLog, GetInstanceGatewayTraffic, GetInstanceLogs, GetInstanceMesh,
        GetInstanceMeshUsage, GetInstanceUsage, GetJob, GetOffering, GetOperationIntent,
        GetProviderBalance, GetProviderHost, GetProviderHostInstanceUsage, GetProviderHostMetrics,
        GetProviderOutage, GetProviderReliability, GetProviderUptime, GetTicket, HandOverIpPool,
        ListAuthKeys, ListBackups, ListContainerImages, ListImages, ListIncidents,
        ListInstanceBackups, ListInstanceTags, ListInstanceUpgrades, ListInstances, ListIpPools,
        ListJobs, ListLocations, ListNotifications, ListOfferings, ListPayouts, ListPrivateRenters,
        ListProviderHosts, ListProviderOutages, ListProviderReviews, ListSessions, ListTickets,
        MigrateAccountSeed, MoveGatewayLocation, RedeployInstance, ReinstallInstance,
        RemoveIpAddress, RemovePrivateRenter, RemoveWebsitePassword, RenameInstance,
        RescueInstance, ResetInstanceAccess, RestoreBackup, RetireHost, RetryHostAgentUpdate,
        RevokeSession, RevokeSessions, RotateGatewayKeys, ScheduleHostRetirement,
        ScheduleInstanceRetirement, SetBackupSchedule, SetHostAgentUpdatePolicy, SetHostPrivate,
        SetHostRentalAdmission, SetIncidentState, SetInstancePower, SetPayoutAddress,
        SetPortForwards, SetTagRedundant, SetTicketState, SetWebsitePassword, TagInstance,
        UnlinkGithub, UpdateHostPricing, UpdateInstance, UpgradeInstance, WriteProviderReview,
    },
    hypervisor::{GuestInitializationStatus, HostMode, PowerState, RestartPolicy},
    website::{
        AccessResetState, AccountActivationTerms, AccountAuthKeyView, AccountBackupListQuery,
        AccountBalanceView, AccountGithubView, AccountProjectionView, AccountView,
        ActivateAccountRequest, ActiveSessionView, AddCloudIpAddressesRequest,
        AddPrivateRenterRequest, AddSupportTicketMessageRequest, AgentUpdateAttemptRequest,
        AgentUpdateAttemptView, AgentUpdatePolicy, AgentUpdateState, AgentUpdateWindow,
        ApproveAgentUpdateRequest, AuthorizeBackupRestoreRequest, BackupDestinationFilter,
        BackupDestinationKind, BackupPricingView, BackupScheduleFrequency, BackupScheduleRuleInput,
        BackupScheduleRuleView, BackupScheduleView, BackupSort, BackupStateFilter, BackupView,
        BillingAuthorization, ChangeGatewayRequest, CloudIpAddressInput, CloudIpPoolScope,
        CloudIpPoolView, ContainerEnvVar, ContainerImageView, ContainerLogView,
        CreateBackupRequest, CreateCloudIpPoolRequest, CreateContainerRequest,
        CreateHostEnrollmentTokenRequest, CreateInstanceRequest, CreateProviderPayoutRequest,
        CreateSupportTicketRequest, DeclareHostEmergencyRequest, GatewayTier, GatewayTrafficView,
        GithubUnlinked, HandOverCloudIpPoolRequest, HostAgentUpdateView, HostEnrollmentToken,
        HostModeFilter, HostPrivacyView, ImageView, InstanceConsoleLogView, InstanceKind,
        InstanceListQuery, InstanceMeshView, InstanceProjectionView, InstanceSort, InstanceSource,
        InstanceState, InstanceStateFilter, InstanceTagView, InstanceUpgradeView, InstanceView,
        IpChoice, JobAccepted, JobEventView, JobKind, JobPage, JobState, JobStateFilter,
        JobStepState, JobView, KindChoice, LedgerKind, LocationView, LoginGrant,
        MAX_SSH_PUBLIC_KEYS, MigrateAccountSeedRequest, MoveGatewayLocationRequest, OfferingView,
        PortForwardChange, PrivateRenterView, ProviderBalanceView, ProviderHostDetailView,
        ProviderHostView, ProviderIncidentSeverity, ProviderIncidentState, ProviderIncidentView,
        ProviderOutageDetailView, ProviderOutagePage, ProviderPayoutAddressView,
        ProviderPayoutView, ProviderReliabilityView, ProviderUptimeView, RedeployInstanceRequest,
        RedeploySetting, ReinstallInstanceRequest, RenameInstanceRequest, RescueInstanceRequest,
        ResetInstanceAccessRequest, RestoreBackupRequest, RotateGatewayKeysRequest,
        SSH_PUBLIC_KEY_TYPES, ScheduleHostRetirementRequest, ScheduleInstanceRetirementRequest,
        SessionRevocationView, SetAgentUpdatePolicyRequest, SetBackupScheduleRequest,
        SetHostPrivateRequest, SetHostRentalPauseRequest, SetPortForwardsRequest,
        SetPowerStateRequest, SetProviderIncidentStateRequest, SetProviderPayoutAddressRequest,
        SetSupportTicketStateRequest, SetTagRedundantRequest, SetWebsitePasswordRequest, SortOrder,
        SupportTicketCategory, SupportTicketPriority, SupportTicketResourceInput,
        SupportTicketState, SupportTicketSummaryView, SupportTicketView, SupportWaitingOn,
        TAG_RULE, TagInstanceRequest, TrialClaimStatus, TrialClaimStatusView, TrialClaimView,
        UpdateInstanceRequest, UpgradeInstanceRequest, UserNotificationView,
        WebsitePasswordRemoved, WebsitePasswordView, backup_byte_charge, readable_console_log,
        readable_console_output, valid_hostname, valid_ssh_public_key, valid_tag,
    },
    website_password,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

/// The help heading of the options every command takes.
const GLOBAL_OPTIONS: &str = "Global options";

/// Options shared by command frontends.
#[derive(Args)]
pub struct GlobalOptions {
    // Help names each option's environment variable without its value,
    // which it would print empty when the variable is not set.
    /// Backend API base URL.
    #[arg(
        long,
        global = true,
        env = "GHOST_API_URL",
        hide_env_values = true,
        default_value = "https://api.gigahost.cloud",
        help_heading = GLOBAL_OPTIONS
    )]
    api_url: String,

    /// Account key file. Defaults below `XDG_CONFIG_HOME`.
    #[arg(
        long,
        global = true,
        env = "GHOST_SEED_FILE",
        hide_env_values = true,
        help_heading = GLOBAL_OPTIONS
    )]
    seed_file: Option<PathBuf>,

    /// Older account key used only to decrypt a pre-migration hosted backup.
    #[arg(
        long,
        global = true,
        env = "GHOST_RECOVERY_SEED_FILE",
        hide_env_values = true,
        help_heading = GLOBAL_OPTIONS
    )]
    recovery_seed_file: Option<PathBuf>,

    /// Print the result as JSON instead of the form for reading.
    #[arg(long, global = true, help_heading = GLOBAL_OPTIONS)]
    json: bool,

    /// Print the result as JSON on one line, without job progress.
    #[arg(long, global = true, help_heading = GLOBAL_OPTIONS)]
    compact: bool,
}

#[derive(Parser)]
#[command(
    name = "ghost",
    version = version_text(),
    about = "Manage Gigahost instances, backups, jobs, and account keys"
)]
pub struct Cli {
    #[command(flatten)]
    globals: GlobalOptions,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate or inspect the single account key and its purpose-specific keys.
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// Browse public VM offerings and operating-system images; without a
    /// subcommand, list offerings as `ghost catalog offerings` does.
    #[command(args_conflicts_with_subcommands = true)]
    Catalog {
        #[command(subcommand)]
        command: Option<CatalogCommand>,
        /// The filters of `ghost catalog offerings`, for `ghost catalog`
        /// alone.
        #[command(flatten)]
        offerings: OfferingFilters,
    },
    /// Inspect account state.
    Account {
        #[command(subcommand)]
        command: AccountCommand,
    },
    /// Manage provider hosts, public IP addresses, and operational incidents.
    Provider {
        #[command(subcommand)]
        command: ProviderCommand,
    },
    /// Create and manage virtual machines.
    Instance {
        #[command(subcommand)]
        command: InstanceCommand,
    },
    /// Create, inspect, and restore backups.
    Backup {
        #[command(subcommand)]
        command: BackupCommand,
    },
    /// Inspect or follow asynchronous jobs.
    Job {
        #[command(subcommand)]
        command: JobCommand,
    },
    /// Open and manage account-authenticated support tickets.
    Support {
        #[command(subcommand)]
        command: SupportCommand,
    },
    /// Run a program on a target through ghostd: its output and exit code
    /// passed through, no quoting.
    ///
    /// The target is an instance ID or name, ssh://[user@]host[:port], or
    /// local. The arguments after -- are the program and its arguments,
    /// passed as they are without a shell; the program's stdout and stderr
    /// are written to ghost's byte for byte (all of it, also beyond what one
    /// answer carries) and ghost exits with its code: 128 + n for a signal,
    /// 124 for a timeout, 127 when it could not be started, 255 for ghost's
    /// own failures. A plain background process the program leaves (cmd &)
    /// is stopped when it ends; start a server with --detach.
    #[cfg(unix)]
    X(ghostd::XArgs),
    /// Install and inspect ghostd on a target, follow its jobs, copy files.
    #[cfg(unix)]
    Ghostd {
        #[command(subcommand)]
        command: ghostd::GhostdCommand,
    },
    /// Serve ghostd's tools to an MCP client over stdio.
    ///
    /// The tools run programs and jobs, read, write, edit and search files,
    /// and sync directories on targets (an instance ID or name,
    /// ssh://[user@]host[:port], or local) over the user's own SSH. An MCP
    /// client starts it, as in `claude mcp add ghost -- ghost mcp`. Local
    /// paths the tools take are relative to this command's working
    /// directory.
    #[cfg(unix)]
    Mcp(ghostd::McpArgs),
}

#[derive(Subcommand)]
enum KeyCommand {
    /// Create a new 256-bit account key without printing the secret.
    Generate {
        /// Destination; defaults to the global --seed-file path.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Print the public recovery and billing identities derived from the account key.
    Inspect,
    /// Put an account key made elsewhere (the website's account.seed, the
    /// line from a password manager, another machine's file) in the seed
    /// file, then show its identities and whether it has an account.
    ///
    /// The key is read from --from FILE; else, on a terminal, as a pasted
    /// line with the echo off; else from standard input. It goes to the
    /// global --seed-file path, or the default one, created 0600. A seed
    /// file that holds this key is left as it is; one that holds another
    /// key is refused unless --replace.
    Import {
        /// The file that holds the key, such as a downloaded account.seed.
        /// It is read, never moved or deleted.
        #[arg(long, value_name = "FILE")]
        from: Option<PathBuf>,
        /// Replace a seed file that holds another key, or one that cannot
        /// be read: it is kept beside it as <name>.replaced-<UTC time>.
        #[arg(long)]
        replace: bool,
    },
}

#[derive(Subcommand)]
enum CatalogCommand {
    /// Read a provider's spend-weighted rating and paginated reviews.
    Reviews {
        /// Provider ID, as an offering's `provider_id` shows it.
        provider_id: Uuid,
        #[command(flatten)]
        page: HistoryArgs,
    },
    /// List locations currently enabled for hosts and catalog filtering.
    Locations(LocationFilters),
    /// List currently schedulable offerings: sizes that can be rented as a
    /// VM, as a container instance, or as either.
    ///
    /// Every kind is listed unless `--kind` names one. The `kinds` column
    /// names what each can be rented as, the kind it is offered as by
    /// default first.
    Offerings(OfferingFilters),
    /// Show one listed offering in full: the hardware and storage of its
    /// hosts, their network test readings, and every price.
    Offering {
        /// Offering ID, from `ghost catalog offerings`.
        offering_id: String,
    },
    /// List enabled operating-system images, for VMs (`instance create
    /// --image`).
    Images,
    /// List the platform's stock images for container instances
    /// (`instance create --stock-image`): distributions that run their own
    /// init system and answer SSH with the account's keys, as a VM does.
    ContainerImages,
    /// Show a provider: its name, rating, completed-day uptime and
    /// abandonment record, and where it lists offerings.
    #[command(alias = "provider-reliability")]
    Provider {
        /// Provider ID or alias, as an offering's `provider_id` or
        /// `provider_alias` shows it, such as gh-abcdefgh.
        #[arg(value_name = "PROVIDER", value_parser = parse_provider)]
        provider: ProviderReference,
    },
    /// Show every test server's latest bandwidth and latency result for a listed host.
    #[command(alias = "host-network-tests")]
    NetworkTest {
        /// Host ID, from an offering's `host_ids`.
        host_id: Uuid,
    },
    /// Show whether the platform works, as the public status page does: each
    /// component's state and the operator's incidents and maintenance.
    Status,
}

#[derive(Args)]
struct LocationFilters {
    /// ISO 3166-1 alpha-2 country code, such as US or SG.
    #[arg(long, value_parser = parse_country_code)]
    country: Option<String>,
    /// Continent code: AF, AN, AS, EU, NA, OC, or SA, or XX for the
    /// development locations.
    #[arg(long, value_parser = parse_continent_code)]
    continent: Option<String>,
}

#[derive(Args, Clone)]
struct OfferingFilters {
    /// Only this kind of host: `home_gateway` hosts are reached through a
    /// hosted gateway, `cloud_routed` hosts through the provider's own
    /// public addresses.
    #[arg(long, value_enum)]
    mode: Option<HostMode>,
    /// Which address the list prices, orders by and offers: `dedicated`
    /// (an address of the instance's own; the default) or `shared` (a
    /// slice of a shared address, for instances that need no address of
    /// their own). An offering without that address is not listed.
    #[arg(long, value_enum)]
    ip: Option<IpChoice>,
    /// Only the offerings that can be rented as this: `vm`, `container`
    /// (a container instance), or `any`, the default (or, with
    /// `--for-backup`, the backup's kind).
    #[arg(long, value_enum)]
    kind: Option<KindChoice>,
    /// Only this location, a slug from `ghost catalog locations`.
    #[arg(long)]
    location: Option<String>,
    /// ISO 3166-1 alpha-2 country code, such as US or SG.
    #[arg(long, value_parser = parse_country_code)]
    country: Option<String>,
    /// Continent code: AF, AN, AS, EU, NA, OC, or SA, or XX for the
    /// development locations.
    #[arg(long, value_parser = parse_continent_code)]
    continent: Option<String>,
    /// Only this provider's offerings: its alias, such as gh-abcdefgh, or
    /// its ID, as an offering's `provider_alias` or `provider_id` shows it.
    #[arg(long, value_name = "PROVIDER", value_parser = parse_provider)]
    provider: Option<ProviderReference>,
    /// Only offerings with at least this many vCPUs.
    #[arg(long, alias = "minimum-vcpus", value_parser = clap::value_parser!(u32).range(1..))]
    min_vcpu: Option<u32>,
    /// Only offerings with at least this much memory, such as 4GiB or
    /// 512MiB; M, G and T stand for MiB, GiB and TiB, and a bare number is
    /// GiB.
    #[arg(long, value_name = "SIZE", value_parser = parse_size)]
    min_ram: Option<u64>,
    /// Only offerings with a root disk of at least this size, such as 50GiB
    /// or 1TiB; M, G and T stand for MiB, GiB and TiB, and a bare number is
    /// GiB.
    #[arg(long, value_name = "SIZE", value_parser = parse_size)]
    min_disk: Option<u64>,
    /// Only offerings of which at least this many instances can be rented
    /// now (the `available` column; each count assumes only that size is
    /// rented; with `--host`, or `--for-backup` of a backup kept on one
    /// host, a count is that host's room alone).
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..))]
    available: Option<u32>,
    #[command(flatten)]
    placement: OfferingPlacementFilters,
    /// List at most this many offerings, 1 to 500; 500 when left out.
    #[arg(long, value_parser = clap::value_parser!(u16).range(1..=500))]
    limit: Option<u16>,
    /// The next page: the offerings after this one, as a full page names
    /// it on standard error (its listed price, the base price plus a home
    /// offering's default gateway's base price or, with `--ip shared`, the
    /// shared IP's, and its ID, joined by a dot).
    #[arg(long, value_name = "PRICE.OFFERING_ID")]
    after: Option<String>,
}

/// Where an offering can place an instance.
#[derive(Args, Clone, Default)]
struct OfferingPlacementFilters {
    /// Only offerings that can place an instance on this host: a host from
    /// an offering's `host_ids`, or a local backup's `host_id`.
    #[arg(long, value_name = "HOST_ID")]
    host: Option<Uuid>,
    /// Only offerings that can create an instance from this backup: a root
    /// at least as large as the backup's disk, the backup's kind (VM or
    /// container) and, for a local backup, its host.
    #[arg(long, value_name = "BACKUP_ID")]
    for_backup: Option<Uuid>,
}

#[derive(Subcommand)]
enum AccountCommand {
    /// Inspect and approve a hosted backup's restore requested on the
    /// website, which only the account key can decrypt.
    Approve {
        /// Request ID, as the website shows it.
        intent_id: Uuid,
        /// Approve and run the request; without it the request is only shown.
        #[arg(long)]
        yes: bool,
    },
    /// Publish or update a review after paid usage with a provider.
    Review {
        /// Provider ID, as an offering's `provider_id` shows it.
        provider_id: Uuid,
        /// Stars from 1 to 5.
        #[arg(long)]
        rating: u32,
        /// Review text, 1 to 2000 bytes; it is published with your account alias.
        #[arg(long)]
        message: String,
        /// Revision of your current review of this provider, or 0 for a first
        /// review; each review response shows it.
        #[arg(long, default_value_t = 0)]
        expected_revision: u64,
    },
    /// Itemized posted ledger entries, newest first.
    History(LedgerHistoryArgs),
    /// Confirmed chain receipts and their credit status.
    Deposits(HistoryArgs),
    /// Downtime compensation, including any uncompensated shortfall.
    SlaCredits(HistoryArgs),
    /// Show the stable UI alias and current deposit memo.
    Show,
    /// Show the currently configured MMX activation terms.
    ActivationTerms,
    /// Activate a new account after its confirmed MMX deposits reach the minimum.
    Activate,
    /// Sign up with GitHub: sends a signed sign-up claim for this seed's keys, opens its
    /// link (valid 10 minutes) and waits for the account, which comes with the trial credit
    /// while trials are open and the GitHub account qualifies, and without credit otherwise.
    Signup {
        /// Sign up with GitHub, the only way to sign up without a deposit.
        #[arg(long, required = true)]
        github: bool,
        /// Print the claim and exit, without opening the link or waiting.
        #[arg(long)]
        no_wait: bool,
    },
    /// Link a GitHub account to this account, so `Log in with GitHub` on the website opens it:
    /// opens the claim's link (valid 10 minutes) and waits. The trial credit comes with the
    /// first link of a qualifying GitHub account.
    LinkGithub {
        /// Print the claim and exit, without opening the link or waiting.
        #[arg(long)]
        no_wait: bool,
    },
    /// Unlink the GitHub account; the website sessions a GitHub login began end with it.
    UnlinkGithub {
        /// Unlink and end those sessions; without it the command only says what it would do.
        #[arg(long)]
        yes: bool,
    },
    /// Read a GitHub sign-up's or link's claim once: pending, created or linked (the account's
    /// alias and the GitHub login) or refused (why).
    GithubStatus {
        /// The `claim_id` that `--no-wait` printed.
        claim_id: String,
    },
    /// Show spending credit, provider earnings, and earnings available for payout.
    Balance,
    /// The protected balance: what new rentals, upgrades, backups and restores leave of the
    /// available balance and a trial's credit, so the instances already running keep it to
    /// run on. $5 by default; their own charges are never stopped by it.
    Protection {
        #[command(subcommand)]
        command: ProtectionCommand,
    },
    /// List durable account and instance notifications, or mark them read.
    Notifications {
        #[command(subcommand)]
        command: Option<NotificationCommand>,
    },
    /// Create a short-lived one-time website login URL.
    Login,
    /// The website password logs in on the website without the CLI.
    SetPassword {
        /// Days until the password stops logging in, 1 to 3650; without it
        /// the password does not expire.
        #[arg(long, value_name = "DAYS", value_parser = clap::value_parser!(u32).range(1..=3650))]
        expires_in: Option<u32>,
        /// Write only the password to standard output, for a password manager.
        #[arg(long)]
        print: bool,
    },
    /// Turn website password login off, ending the website sessions the
    /// password began.
    RemovePassword,
    /// End every website session and cancel unused login URLs, such as after
    /// a lost device or a leaked link. Authentication keys and the website
    /// password are not affected: if the password was saved on a lost device,
    /// run `ghost account set-password` too.
    RevokeSessions,
    /// List the account's website sessions that still work, newest first:
    /// when each began, was last used and ends, and the key whose login URL
    /// began it.
    Sessions,
    /// End one website session, such as one a lost device holds.
    RevokeSession {
        /// Session ID, as `ghost account sessions` lists it.
        session_id: Uuid,
    },
    /// List this account's current and retired authentication keys.
    AuthKeys,
    /// The SSH public keys saved for new instances: `ghost instance create`
    /// and `reinstall` install every one unless --ssh-key or --ssh-key-file
    /// names the keys itself.
    SshKeys {
        #[command(subcommand)]
        command: SshKeyCommand,
    },
    /// Move the account to an independently generated replacement account key.
    MigrateSeed {
        /// The replacement account key, made with `ghost key generate --output FILE`.
        #[arg(long)]
        new_seed_file: PathBuf,
        /// Confirm that both account keys have been backed up and existing sessions will be revoked.
        #[arg(long)]
        yes: bool,
    },
    /// Create a short-lived, single-use hypervisor enrollment token.
    GetHostEnrollmentToken {
        /// Label stored with the token.
        #[arg(long, default_value = "hypervisor enrollment")]
        label: String,
    },
}

#[derive(Subcommand)]
enum ProtectionCommand {
    /// Keep this many dollars, such as 2 or 2.50: at least the platform's minimum ($1 by
    /// default), at most $10,000. It takes effect at once.
    Set {
        /// The amount in dollars, such as 2 or 2.50.
        #[arg(value_name = "USD", value_parser = parse_usd)]
        usd: u64,
    },
    /// Follow the platform's default again.
    Default,
}

#[derive(Subcommand)]
enum SshKeyCommand {
    /// The keys saved in the account, oldest first.
    List,
    /// Save a public key under a label, from a .pub file or as a line.
    Add {
        /// A name of your choosing, such as the machine the key belongs to.
        #[arg(long)]
        label: String,
        /// File of one OpenSSH public key line, such as `~/.ssh/id_ed25519.pub`.
        #[arg(
            long = "file",
            value_name = "FILE",
            required_unless_present = "key",
            conflicts_with = "key"
        )]
        file: Option<PathBuf>,
        /// The OpenSSH public key line itself.
        #[arg(long = "key", value_name = "PUBLIC_KEY", allow_hyphen_values = true)]
        key: Option<String>,
    },
    /// Forget a saved key; the instances it was copied into keep it.
    Remove {
        /// Key ID, as `ghost account ssh-keys list` shows it.
        ssh_key_id: Uuid,
    },
}

#[derive(Subcommand)]
enum NotificationCommand {
    /// Mark notifications read: those named, or every unread one.
    MarkRead {
        /// Notification IDs, as `ghost account notifications` lists them.
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        notification_ids: Vec<Uuid>,
        /// Mark every unread notification read.
        #[arg(long)]
        all: bool,
    },
    /// Mark a notification unread again.
    MarkUnread {
        /// Notification ID, as `ghost account notifications` lists it.
        notification_id: Uuid,
    },
}

#[derive(Subcommand)]
enum ProviderCommand {
    /// Show what you earn on a host: the prices you published, and from
    /// when existing rentals earn them.
    Pricing {
        /// Host ID, from `ghost provider hosts`.
        host_id: Uuid,
    },
    /// Publish what you earn on a host; new rentals earn it at once,
    /// existing ones after 90 days.
    SetPricing {
        /// Host ID, from `ghost provider hosts`.
        host_id: Uuid,
        /// The pricing revision this change replaces, from `ghost provider pricing`.
        #[arg(long)]
        expected_revision: u64,
        /// JSON file with what to earn: the compute earnings, either
        /// `compute_earnings` (per vCPU:
        /// `{"microusd_per_month": ..., "vcpus": 1}`) or
        /// `base_host_earnings_microusd_per_month` (the whole host, kept
        /// exact for its saleable vCPUs now), not both;
        /// `network_earnings_microusd_per_tib` (0 on a home host),
        /// `sla_target_basis_points` (9900, 9990 or 9999) and optionally
        /// `address_earnings_microusd_per_month` (a cloud host's, per
        /// rental's address and month; left out, the host's stay as they
        /// are; 0 on a home host). The `values` of `ghost --json provider
        /// pricing` are such a file, with the whole-host total. No fixed
        /// price per instance: it is the platform's, and a file that sets
        /// `fixed_instance_earnings_microusd_per_month` to anything but 0
        /// is refused.
        #[arg(long)]
        file: PathBuf,
        /// What a cloud host earns per rental's address and 30-day month,
        /// in micro-USD, in place of the file's
        /// `address_earnings_microusd_per_month`. Existing rentals pay it
        /// after the 90-day notice, new ones at once.
        #[arg(long = "address-earnings")]
        address_earnings_microusd: Option<u64>,
        /// Why the prices change, recorded with them.
        #[arg(long)]
        reason: String,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
    /// Show your earnings: not paid out yet, available to pay out now,
    /// still held for the SLA window, and on the way; and the payout
    /// address.
    Balance,
    /// Set the MMX address every payout goes to. Payouts not yet signed go
    /// there too. Only this signed command can set it, not the website.
    SetPayoutAddress {
        /// MMX address that receives payouts.
        address: String,
    },
    /// List recent provider payout requests and their chain status.
    Payouts,
    /// Request an MMX payout of earnings available now to the payout address.
    Payout {
        /// What to pay out, in micro-USD; omit to pay out everything available.
        #[arg(long)]
        amount_microusd: Option<u64>,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
    /// List your hosts: whether each takes rentals, when it was last
    /// seen, its hardware and prices. `ghost provider host <HOST_ID>` shows one
    /// in full.
    Hosts {
        /// Also list retired hosts, after the others.
        #[arg(long)]
        retired: bool,
    },
    /// Show one host in full, `ghost provider host <HOST_ID>`, or pause,
    /// resume, or retire it.
    #[command(args_conflicts_with_subcommands = true, arg_required_else_help = true)]
    Host {
        #[command(subcommand)]
        command: Option<ProviderHostCommand>,
        /// Host ID, from `ghost provider hosts`: show its heartbeat, health,
        /// hardware, inventory, allocated capacity, and current metrics.
        host_id: Option<Uuid>,
    },
    /// Schedule termination of one active rental with at least seven days notice.
    RetireInstance {
        /// The rental to terminate.
        instance_id: Uuid,
        /// Full days of notice before the rental is deleted; at least 7.
        #[arg(long, default_value_t = 7)]
        notice_days: u32,
        /// Reason given to the renter.
        #[arg(long)]
        reason: Option<String>,
        /// Confirm the scheduled deletion.
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
    /// List public IP pools, eligible hosts, addresses, and allocation states.
    ///
    /// The address a rental was reached at rests after the rental ended,
    /// an hour by default, until `available_at`, also when it is removed
    /// and added again: no rental gets it before.
    IpPools,
    /// Create public IP pools, or delete one whose every host is retired.
    IpPool {
        #[command(subcommand)]
        command: ProviderIpPoolCommand,
    },
    /// Add, check again, or safely remove public IP addresses.
    Ip {
        #[command(subcommand)]
        command: ProviderIpCommand,
    },
    /// List the actionable incident and warning inbox.
    Incidents {
        /// Only incidents in this state.
        #[arg(long, value_enum)]
        state: Option<ProviderIncidentState>,
        /// Only incidents of this severity.
        #[arg(long, value_enum)]
        severity: Option<ProviderIncidentSeverity>,
    },
    /// Inspect or update one provider incident.
    Incident {
        #[command(subcommand)]
        command: ProviderIncidentCommand,
    },
    /// Your hosts' uptime over the last 30, 90 and 365 days beside each
    /// host's SLA target: the downtime that counts, the part the
    /// platform's fault excuses and the SLA credits the outages cost. The
    /// hosts come by label, 100 at a time; when `more` is true, read the
    /// next with `--after` and the last host listed.
    Uptime {
        /// Only this host.
        #[arg(long, value_name = "HOST_ID", conflicts_with_all = ["after", "limit"])]
        host: Option<Uuid>,
        /// The hosts after this one, by label: the last of the page before.
        #[arg(long, value_name = "HOST_ID")]
        after: Option<Uuid>,
        /// How many hosts, 1 to 200 (100 by default).
        #[arg(long)]
        limit: Option<u16>,
        /// List retired hosts too; they are left out by default (a host named
        /// with `--host` is listed either way).
        #[arg(long)]
        retired: bool,
    },
    /// List the outages of your hosts, newest first, with the time that
    /// counts against the host, the part excused as the platform's, the
    /// rentals each touched and the SLA credits it cost, and the totals of
    /// all that match. Without `--from`, the last 365 days.
    Outages {
        /// Only this host.
        #[arg(long, value_name = "HOST_ID")]
        host: Option<Uuid>,
        /// Only outages that started on this UTC day or later (YYYY-MM-DD).
        #[arg(long, value_name = "DAY")]
        from: Option<chrono::NaiveDate>,
        /// Only outages that started on this UTC day or earlier (YYYY-MM-DD).
        #[arg(long, value_name = "DAY")]
        to: Option<chrono::NaiveDate>,
        /// The `next_cursor` of the page before.
        #[arg(long)]
        cursor: Option<String>,
        /// How many outages, 1 to 200 (50 by default).
        #[arg(long)]
        limit: Option<u16>,
    },
    /// One outage of your hosts with the rentals it touched, each with its
    /// credit, and the incident it raised.
    Outage {
        /// The outage's ID, from `ghost provider outages`.
        outage_id: Uuid,
    },
    /// List, allow or remove the accounts that may rent your private
    /// hosts besides your own (`ghost provider host private`).
    PrivateRenters {
        #[command(subcommand)]
        command: ProviderPrivateRentersCommand,
    },
    /// Show a host's agent updates, or change how it takes them.
    AgentUpdate {
        #[command(subcommand)]
        command: ProviderAgentUpdateCommand,
    },
}

#[derive(Subcommand)]
enum ProviderAgentUpdateCommand {
    /// Show the release installed and the one on its way, the policy, the
    /// window, any pause, the last failure and the newest attempts.
    Show {
        /// Host ID, from `ghost provider hosts`.
        host_id: Uuid,
    },
    /// Change the policy or the weekly window; what you leave out stays.
    Set {
        /// Host ID, from `ghost provider hosts`.
        host_id: Uuid,
        /// `manual` waits for your approval of each release; `automatic`
        /// takes the releases Gigahost rolls out.
        #[arg(long, value_enum)]
        policy: Option<AgentUpdatePolicyChoice>,
        /// The window's UTC days, such as `mon,thu`. Needs --start and
        /// --hours.
        #[arg(long, value_delimiter = ',', value_enum, requires_all = ["start", "hours"])]
        days: Vec<WindowDay>,
        /// When the window opens, UTC, as `HH:MM`.
        #[arg(long, value_parser = parse_window_start, requires = "days")]
        start: Option<u16>,
        /// How long the window stays open, 1 to 24 hours.
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..=24), requires = "days")]
        hours: Option<u16>,
        /// Update at any time.
        #[arg(long, conflicts_with_all = ["days", "start", "hours"])]
        clear_window: bool,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
    /// Hold updates on the host, until you resume them or until `--until`.
    Pause {
        /// Host ID, from `ghost provider hosts`.
        host_id: Uuid,
        /// When the pause ends, as `2026-11-30T12:00:00Z`.
        #[arg(long, value_name = "TIME")]
        until: Option<DateTime<Utc>>,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
    /// End a pause.
    Resume {
        /// Host ID, from `ghost provider hosts`.
        host_id: Uuid,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
    /// Approve one release for the host, once: the one that waits for your
    /// approval, or the channel's current one.
    Approve {
        /// Host ID, from `ghost provider hosts`.
        host_id: Uuid,
        /// The release, as `ghost provider agent-update show` names it.
        release: String,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
    /// Try the release of the last attempt again, after it failed or
    /// was rolled back.
    Retry {
        /// Host ID, from `ghost provider hosts`.
        host_id: Uuid,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
    /// Cancel the attempt on its way, unless it is being applied.
    Cancel {
        /// Host ID, from `ghost provider hosts`.
        host_id: Uuid,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
}

/// A policy `ghost provider agent-update set` can choose.
#[derive(Clone, Copy, ValueEnum)]
enum AgentUpdatePolicyChoice {
    Manual,
    Automatic,
}

impl From<AgentUpdatePolicyChoice> for AgentUpdatePolicy {
    fn from(choice: AgentUpdatePolicyChoice) -> Self {
        match choice {
            AgentUpdatePolicyChoice::Manual => Self::Manual,
            AgentUpdatePolicyChoice::Automatic => Self::Automatic,
        }
    }
}

/// A UTC day of a window, in the order of its bits: Monday is bit 0.
#[derive(Clone, Copy, ValueEnum)]
enum WindowDay {
    Mon,
    Tue,
    Wed,
    Thu,
    Fri,
    Sat,
    Sun,
}

/// A window's start, `HH:MM`, as minutes after midnight.
fn parse_window_start(value: &str) -> Result<u16, String> {
    value
        .split_once(':')
        .filter(|(hours, minutes)| hours.len() == 2 && minutes.len() == 2)
        .and_then(|(hours, minutes)| Some((hours.parse().ok()?, minutes.parse().ok()?)))
        .filter(|&(hours, minutes): &(u16, u16)| hours < 24 && minutes < 60)
        .map(|(hours, minutes)| hours * 60 + minutes)
        .ok_or_else(|| "expected a UTC time as HH:MM, such as 02:30".to_owned())
}

/// What `ghost provider agent-update set` changes.
struct AgentUpdateChange {
    policy: Option<AgentUpdatePolicy>,
    window: WindowChange,
}

/// What `ghost provider agent-update set` does to the window.
#[derive(Clone, Copy)]
enum WindowChange {
    Keep,
    Clear,
    Set(AgentUpdateWindow),
}

/// The window `days`, `start` and `hours` name, whole; None when they name
/// none. Clap requires them together.
fn named_window(
    days: &[WindowDay],
    start: Option<u16>,
    hours: Option<u16>,
) -> Option<AgentUpdateWindow> {
    (!days.is_empty()).then_some(AgentUpdateWindow {
        days: days
            .iter()
            .fold(0, |bits, &day| bits | (1_u8 << (day as u8))),
        start_minute: start?,
        minutes: hours? * 60,
    })
}

/// The whole policy the backend replaces, from the host's `view`: what the
/// caller leaves out stays as it is, and `paused` is `(paused, until)`
/// where it changes.
fn agent_update_policy_request(
    view: &HostAgentUpdateView,
    change: &AgentUpdateChange,
    paused: Option<(bool, Option<DateTime<Utc>>)>,
) -> Result<SetAgentUpdatePolicyRequest> {
    let policy = change.policy.unwrap_or(view.policy);
    if policy == AgentUpdatePolicy::Unknown {
        bail!("this host has a policy this ghost does not know; update ghost first");
    }
    let (paused, paused_until) = paused.unwrap_or((view.paused, view.paused_until));
    Ok(SetAgentUpdatePolicyRequest {
        policy,
        paused,
        paused_until,
        window: match change.window {
            WindowChange::Keep => view.window,
            WindowChange::Clear => None,
            WindowChange::Set(window) => Some(window),
        },
        // Read just now, and a retry under its key must send the same body.
        policy_revision: None,
    })
}

#[derive(Subcommand)]
enum ProviderPrivateRentersCommand {
    /// List the accounts you allow on your private hosts, each with its
    /// instances and local backups there. Your own account is always
    /// allowed and is not listed.
    List,
    /// Allow an account on your private hosts by its alias (at most 100).
    Add {
        /// The account's alias, as its owner sees it in `ghost account show`.
        alias: String,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
    /// Stop allowing an account: its new instances on your private hosts
    /// are refused; what it has there keeps running and is billed as
    /// before.
    Remove {
        /// The account's alias, from `ghost provider private-renters list`.
        alias: String,
        /// Confirm the removal while the account has instances or local
        /// backups on your private hosts.
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
}

#[derive(Subcommand)]
enum ProviderIncidentCommand {
    /// Show one incident with its evidence.
    Get {
        /// Incident ID, from `ghost provider incidents`.
        incident_id: Uuid,
    },
    /// Mark an incident as seen and being handled.
    Acknowledge {
        /// Incident ID, from `ghost provider incidents`.
        incident_id: Uuid,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
    /// Mark an incident as fixed.
    Resolve {
        /// Incident ID, from `ghost provider incidents`.
        incident_id: Uuid,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
}

#[derive(Subcommand)]
enum ProviderHostCommand {
    /// Show heartbeat, health, hardware, inventory, allocated capacity, and
    /// current metrics; `ghost provider host <HOST_ID>` without `get` does.
    #[command(hide = true)]
    Get {
        /// Host ID, from `ghost provider hosts`.
        host_id: Uuid,
    },
    /// Read the host's current metrics or paginated 15-minute/daily/monthly
    /// usage.
    Metrics {
        /// Host ID, from `ghost provider hosts`.
        host_id: Uuid,
        /// Current values, or 15-minute, daily or monthly (UTC, at most 12
        /// a page) intervals.
        #[arg(long, default_value = "15m", value_parser = ["current", "15m", "daily", "monthly"])]
        resolution: String,
        #[command(flatten)]
        page: HistoryArgs,
    },
    /// Read one rental's usage on this host at the renter's resolutions.
    InstanceUsage {
        /// Host ID, from `ghost provider hosts`.
        host_id: Uuid,
        /// A rental on that host.
        instance_id: Uuid,
        /// Current values, or 15-minute, daily or monthly (UTC, at most 12
        /// a page) intervals.
        #[arg(long, default_value = "15m", value_parser = ["current", "15m", "daily", "monthly"])]
        resolution: String,
        #[command(flatten)]
        page: HistoryArgs,
    },
    /// Stop admitting new rentals without affecting existing instances.
    Pause {
        /// Host ID, from `ghost provider hosts`.
        host_id: Uuid,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
    /// Allow this host to receive new rentals when it is otherwise healthy.
    /// A cloud-routed host first needs its public path verified.
    Resume {
        /// Host ID, from `ghost provider hosts`.
        host_id: Uuid,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
    /// Make the host private: only you and the accounts
    /// `ghost provider private-renters` lists start new instances on it,
    /// and no public read (the catalog, the status page) shows it. What is
    /// on it now stays.
    Private {
        /// Host ID, from `ghost provider hosts`.
        host_id: Uuid,
        /// Confirm while instances or local backups of accounts you do not
        /// allow are on the host; they stay.
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
    /// Make a private host public again: the catalog lists it at once.
    Public {
        /// Host ID, from `ghost provider hosts`.
        host_id: Uuid,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
    /// Check a cloud host's public path now; `ghost provider hosts` shows
    /// the result.
    CheckPath {
        /// Host ID, from `ghost provider hosts`.
        host_id: Uuid,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
    /// Give renters notice, then delete remaining VMs and retire the host.
    Retire {
        /// Host ID, from `ghost provider hosts`.
        host_id: Uuid,
        /// Full days before provider-initiated deletion begins (minimum 7).
        #[arg(long, default_value_t = 7)]
        notice_days: u32,
        /// Confirm the irreversible retirement schedule.
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
    /// Declare a physically unrecoverable host and immediately stop billing.
    Emergency {
        /// Host ID, from `ghost provider hosts`.
        host_id: Uuid,
        /// What happened to the host, recorded with the declaration.
        #[arg(long)]
        reason: String,
        /// Confirm that every rental on the host is abandoned now.
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
    /// Permanently retire an empty host enrollment while preserving history.
    Delete {
        /// Host ID, from `ghost provider hosts`.
        host_id: Uuid,
        /// Confirm permanent credential revocation and enrollment retirement.
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
}

#[derive(Subcommand)]
enum ProviderIpPoolCommand {
    /// Create a host- or account-scoped pool for cloud-routed hosts.
    Create {
        /// Name for the pool.
        #[arg(long)]
        label: String,
        /// host: one host uses the addresses; account: any listed host may.
        #[arg(long, value_enum)]
        scope: CloudIpPoolScope,
        /// Eligible host UUID; repeat for account-scoped pools.
        #[arg(long = "host", required = true)]
        host_ids: Vec<Uuid>,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
    /// Hand the pool of a retired host to the host that takes its place.
    ///
    /// A host's mode, location and capacity profile are fixed, so changing
    /// one means retiring the host and enrolling the machine again. Its new
    /// identity gets a pool with the label and every address of the old one
    /// without typing them again, and the old pool is deleted as `delete`
    /// does. Every address is checked again before a rental gets it. Only
    /// the pool of one host is handed over, and only to a cloud-routed host
    /// of yours in the same location.
    HandOver {
        /// Pool ID, from `ghost provider ip-pools`.
        pool_id: Uuid,
        /// The host that gets the pool, from `ghost provider hosts`.
        #[arg(long)]
        host: Uuid,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
    /// Delete a pool whose every host is retired, so its addresses can be
    /// added to another pool: the same addresses may be added to a pool of
    /// another host right after. Addresses a rental held stay disabled with
    /// the deleted pool for their history; any other is deleted.
    Delete {
        /// Pool ID, from `ghost provider ip-pools`.
        pool_id: Uuid,
        /// Confirm that the pool is gone for good.
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
}

#[derive(Subcommand)]
enum ProviderIpCommand {
    /// Add addresses or re-enable disabled addresses in an existing pool.
    Add {
        /// Pool ID, from `ghost provider ip-pools`.
        #[arg(long)]
        pool: Uuid,
        /// IPv4 address; repeat to add a batch with the same route settings.
        #[arg(long = "address", required = true)]
        addresses: Vec<Ipv4Addr>,
        /// Prefix length of the addresses' network, 0 to 32.
        #[arg(long, default_value_t = 32, value_parser = clap::value_parser!(u8).range(0..=32))]
        prefix_length: u8,
        /// Gateway the addresses route through; omit for the host's default.
        #[arg(long)]
        gateway: Option<Ipv4Addr>,
        /// Provider-issued virtual MAC required by some upstream networks.
        #[arg(long, value_parser = parse_mac_address)]
        mac_address: Option<String>,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
    /// Ask for another check of an address that failed its check. Only a
    /// verified address is ever assigned to a rental; `ip-pools` shows each
    /// address's verification and why a failed one failed.
    Check {
        /// Pool ID, from `ghost provider ip-pools`.
        #[arg(long)]
        pool: Uuid,
        /// The address to check again.
        #[arg(long)]
        address: Ipv4Addr,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
    /// Remove an unallocated address. One a rental held stays disabled for
    /// its audit history; any other is deleted.
    Remove {
        /// Pool ID, from `ghost provider ip-pools`.
        #[arg(long)]
        pool: Uuid,
        /// The address to remove.
        #[arg(long)]
        address: Ipv4Addr,
        /// Confirm that this address should no longer receive new rentals.
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        mutation: IdempotencyArgs,
    },
}

// The one `--idempotency-key` argument of every mutation that accepts it.
// A plain comment: a doc comment here would become the help text of every
// command that flattens it and has none of its own.
#[derive(Args)]
pub struct IdempotencyArgs {
    /// Stable key for safely retrying this mutation: 16 to 128 printable
    /// ASCII characters. Generated when omitted.
    ///
    /// A key is scoped to one kind of change and the resource it names, such
    /// as an instance or a backup, or your account for a creation. For 30
    /// days the same key and request get the first answer again, even for a
    /// VM deleted since; the same key with a different request is refused.
    #[arg(long, value_parser = parse_idempotency_key)]
    idempotency_key: Option<String>,
}

impl IdempotencyArgs {
    /// Whether a retry key was explicitly supplied.
    pub const fn has_key(&self) -> bool {
        self.idempotency_key.is_some()
    }
    /// The given key, or a fresh one for a first attempt.
    pub fn key(&self) -> MutationKey {
        let key = self
            .idempotency_key
            .clone()
            .unwrap_or_else(fresh_idempotency_key);
        MutationKey {
            retry: format!("--idempotency-key {key}"),
            key,
        }
    }
}

#[derive(Subcommand)]
enum InstanceCommand {
    /// Read current metrics or paginated 15-minute/daily/monthly usage. A
    /// home instance's traffic takes three paths: its gateway (the usage),
    /// and the host mesh's internet (WAN mesh) and LAN links, where what it
    /// sent is billed and what it received is free; all three by default,
    /// one with --path.
    Usage {
        /// Instance ID or name, from `ghost instance list`.
        #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
        instance_id: InstanceReference,
        /// Current values, or 15-minute, daily or monthly (UTC, at most 12
        /// a page) intervals. The mesh paths have no current values.
        #[arg(long, default_value = "15m", value_parser = ["current", "15m", "daily", "monthly"])]
        resolution: String,
        /// Only this path: the gateway's usage, or what the host mesh
        /// carried over internet (wan-mesh) or LAN (lan-mesh) links. Without
        /// it, the usage and the first page of each mesh path; --cursor
        /// then pages the usage.
        #[arg(long, value_enum)]
        path: Option<UsagePath>,
        #[command(flatten)]
        page: HistoryArgs,
    },
    /// List the instance's links of the host mesh: the kind, the other end
    /// (your own instance by name; another customer's on a LAN link is never
    /// named, only counted), whether it carries the traffic over the mesh
    /// or is back on the gateways and since when, and what it carried this
    /// month, today and in the last 15 minutes billed; or why it has none.
    Mesh {
        /// Instance ID or name, from `ghost instance list`.
        #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
        instance_id: InstanceReference,
    },
    /// Read what a home instance's hosted gateway counted over the last
    /// hour and day. Informational: billing never uses these figures.
    GatewayTraffic {
        /// Instance ID or name of a home instance.
        #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
        instance_id: InstanceReference,
    },
    /// List this account's instances, newest first; deleted ones only when
    /// a --state names them. Filter them by state, a job under way,
    /// location, provider, home or cloud, image, name and tags, and sort
    /// them by age, price, size or name.
    List {
        /// Only instances in this state; repeat it for several. Without
        /// one, every state but deleted.
        #[arg(long = "state", value_name = "STATE", value_enum)]
        states: Vec<InstanceStateFilter>,
        /// Only instances with any job under way (a creation, an upgrade, a
        /// restore, a backup, ...).
        #[arg(long)]
        busy: bool,
        /// Only instances whose host is in this location (its code).
        #[arg(long, value_name = "CODE")]
        location: Option<String>,
        /// Only instances of this provider, by its alias (gh-…).
        #[arg(long, value_name = "ALIAS")]
        provider: Option<String>,
        /// Only instances on home hosts.
        #[arg(long, conflicts_with = "cloud")]
        home: bool,
        /// Only instances on cloud hosts.
        #[arg(long)]
        cloud: bool,
        /// Only instances whose root disk holds this image, or that run
        /// this stock container image (its slug).
        #[arg(long, value_name = "SLUG")]
        image: Option<String>,
        /// Only instances whose name (as the list shows it, the hostname
        /// unless renamed) starts with this, in any case.
        #[arg(long, value_name = "PREFIX")]
        name: Option<String>,
        /// Only instances that carry this tag; repeat it for instances that
        /// carry every one named (at most 5).
        #[arg(long = "tag", value_name = "TAG", value_parser = parse_tag)]
        tags: Vec<String>,
        /// What to sort by: the creation time (the default), the price a
        /// month the instance pays now (its base price with the price
        /// changes in effect, a home instance's gateway and a cloud
        /// instance's address; for an account of at most 10,000 current
        /// instances), the size (vCPUs, then RAM, then disk) or the name.
        #[arg(long, value_name = "KEY", value_enum)]
        sort: Option<InstanceSort>,
        /// Oldest, cheapest, smallest or first name first.
        #[arg(long, conflicts_with = "desc")]
        asc: bool,
        /// Newest, costliest, largest or last name first (the default).
        #[arg(long)]
        desc: bool,
    },
    /// Get one instance.
    ///
    /// `guest_initialization` is what cloud-init in the guest reported once
    /// it finished the guest's latest boot: done, degraded (recoverable
    /// errors only) or error, with its messages. `access_reset` is the
    /// latest `ghost instance reset-access` and what the guest reported of
    /// it.
    Get {
        /// Instance ID or name, from `ghost instance list`.
        #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
        instance_id: InstanceReference,
    },
    /// Read the end of what the instance's guest wrote to its serial
    /// console.
    ///
    /// Read-only: what its host last sent, which it does within about ten
    /// seconds of the guest writing anything, at most the last 64 KiB.
    /// Once the platform has started the guest again, by a reset, a
    /// reboot, a stop and start, an upgrade, a reinstall or a restore, that
    /// is what the guest wrote since, and the end of what it wrote before,
    /// at most 64 KiB too, comes first, above a line that says so. The
    /// output is printed without the escape sequences that color a
    /// terminal; `--json` has it as the guest wrote it. A guest created
    /// before consoles were recorded has its console recorded from its
    /// next start.
    ConsoleLog {
        /// Instance ID or name, from `ghost instance list`.
        #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
        instance_id: InstanceReference,
        /// The most bytes of the end of the output to read, and of the end
        /// from before the last start, 1 to 65536.
        #[arg(long, default_value_t = 65_536, value_parser = clap::value_parser!(u32).range(1..=65_536))]
        bytes: u32,
    },
    /// Open the serial console of a VM instance, live, over SSH.
    ///
    /// Runs the system's `ssh` to the console server
    /// (`<instance ID>@console.<the API's domain>`, port 2222) with the
    /// account's SSH key that the agent or `~/.ssh` offers: one of the
    /// keys the account saved (`ghost account ssh-keys`). The server's
    /// host key is checked against the one this ghost was built with, never
    /// learned on first use. The session shows the console log's last
    /// screen, then the console as it runs; `Ctrl-]` then `?` shows its
    /// menu (disconnect, a break, a reset, a power cycle). The guest's own
    /// login prompt asks for a password set in the guest: the platform sets
    /// none. What the console shows also goes into the console log
    /// (`ghost instance console-log`), and its traffic passes through the
    /// host and its provider's agent. A container instance has none:
    /// `ghost instance logs` shows its output. One session per instance; a
    /// new one takes over, and an hour without input or output ends one.
    Console {
        /// Instance ID or name, from `ghost instance list`.
        #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
        instance_id: InstanceReference,
        /// The console server, as HOST or HOST:PORT; by default
        /// `console.` and the API's domain, port 2222.
        #[arg(long, env = "GHOST_CONSOLE_HOST", hide_env_values = true)]
        console_host: Option<String>,
        /// The console server's host key, one OpenSSH public key line, for
        /// a deployment other than the one this ghost was built for.
        #[arg(long, env = "GHOST_CONSOLE_HOST_KEY", hide_env_values = true)]
        console_host_key: Option<String>,
    },
    /// Read the end of what a container instance's container wrote, its
    /// process's standard output and error.
    ///
    /// Read-only: what its host last sent, at most the last 64 KiB written
    /// since the container was last started, by the platform or by its
    /// restart policy. The end of what it wrote before that start, the
    /// output that made it exit, comes first, under a heading. The output
    /// is printed without the escape sequences that color a terminal;
    /// `--json` has the API's view, as the container wrote it. A VM has no
    /// such logs: `ghost instance console-log` reads its console.
    Logs {
        /// Instance ID or name, from `ghost instance list`.
        #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
        instance_id: InstanceReference,
        /// Show only the end of what it wrote before its last start.
        #[arg(long)]
        previous: bool,
    },
    /// Reserve capacity and enqueue instance creation: a VM from an
    /// operating-system image (`--image`), a container instance from a
    /// container image (`--container`) or a stock image (`--stock-image`),
    /// or either from a backup (`--backup`).
    Create(Box<CreateInstanceArgs>),
    /// Enqueue a power transition.
    ///
    /// A stopped instance keeps its capacity and address and still pays its
    /// base price and metered traffic, only no CPU time; delete it to stop
    /// paying.
    Power(PowerArgs),
    /// Replace the root filesystem with a fresh operating-system image.
    ///
    /// The instance runs afterwards, also one that was stopped. The SSH keys
    /// are installed for root; the image's default user is not set up.
    Reinstall(ReinstallArgs),
    /// Reset a VM's SSH access through cloud-init, for a guest that still
    /// boots but whose sshd, keys, network or firewall keep you out.
    ///
    /// The instance restarts (a stopped one starts), and at that boot the
    /// platform's cloud-init settings run once, as root: they add the SSH
    /// keys to root's `authorized_keys`, keeping the ones there, let root in
    /// over SSH by key and restart sshd, and apply the platform's network
    /// settings again. --firewall also stops the guest's firewall for that
    /// boot only. The guest's report of each part appears in `ghost
    /// instance get` (`access_reset`). A guest without cloud-init, or that
    /// does not reach its userspace, reports nothing; a rescue boot is the
    /// way in then. Every saved key is installed unless --ssh-key or
    /// --ssh-key-file names others. A container instance is redeployed
    /// instead.
    ResetAccess(ResetAccessArgs),
    /// Boot a VM into the platform's rescue system, with its own disk
    /// attached, for a guest that does not boot or cannot be reached; or
    /// end the rescue with --exit.
    ///
    /// The instance restarts (a stopped one starts) into a Debian system
    /// that runs from memory, at the instance's own addresses. Its disk is
    /// /dev/vda, not mounted: `mount-guest` mounts it at /mnt with its
    /// fstab's filesystems, for `chroot /mnt`. Root logs in over SSH with
    /// the keys, by key only; every saved key unless --ssh-key or
    /// --ssh-key-file names others. The rescue system's host key is new
    /// each rescue: with --wait, ghost files it and prints the SSH command
    /// that checks it, as `ghost instance get` does once it started. While
    /// the rescue lasts the instance is billed as running, a backup,
    /// restore, upgrade, reinstall or gateway change is refused until its end, a
    /// reboot stays in the rescue, and a stop or a reset ends it. --exit
    /// boots the instance's own system again. A container instance is
    /// redeployed instead.
    Rescue(RescueArgs),
    /// Move a container instance to another image, or another version of
    /// its image, on its own root disk.
    ///
    /// Everything on the root disk is replaced but the paths it keeps: its
    /// volumes (--volume, or those it has) and the VOLUME paths of the
    /// image it runs and of the new one. The instance is stopped meanwhile
    /// and runs afterwards if it ran before; a redeploy that fails is
    /// rolled back to the instance as it was. Settings left out keep the
    /// instance's current ones, or a new instance's defaults with --reset.
    /// A redeploy is free.
    Redeploy(RedeployArgs),
    /// Update the saved custom container image, optionally choosing a new tag of
    /// the same repository. Keeps all settings, secrets and networking.
    /// Replaces the root outside kept paths; temporarily stops the instance.
    /// Digest references stay pinned unless --tag is given. Stock images use
    /// pinned platform releases: use `instance redeploy --stock-image` to
    /// select the image and SSH keys.
    Update(UpdateArgs),
    /// List the larger sizes of its host an instance can be upgraded to.
    ///
    /// Each is an offering of the host, larger than the instance in some
    /// respect and smaller in none, with whether the host has room for it
    /// now and what it adds to the balance the instance holds.
    Upgrades {
        /// Instance ID or name, from `ghost instance list`.
        #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
        instance_id: InstanceReference,
    },
    /// Upgrade an instance to a larger size of its host, in place.
    ///
    /// The guest is shut down, given the CPUs, memory and disk of the size,
    /// and started again if it ran; it keeps its disk contents, address and
    /// hostname. It pays the size's price from then on, as the catalog
    /// offers it now, and holds more of the balance, as `ghost instance
    /// upgrades` lists. A root
    /// filesystem grows into a larger disk on the next boot where cloud-init
    /// runs; grow it yourself on other systems.
    Upgrade(UpgradeArgs),
    /// Give an instance another name, which the website and `ghost` show.
    ///
    /// The name follows the rules of a hostname. Only the platform shows it:
    /// the guest and its hostname stay as they are, so no job runs.
    Rename(RenameArgs),
    /// Add tags to an instance, or remove some: your own labels to group
    /// and filter instances by (`ghost instance list --tag`).
    ///
    /// A tag is 1 to 32 lowercase letters, digits, `-`, `_`, `.` and `:`,
    /// such as env:prod or team-a; an instance carries at most 20. Only you
    /// and the platform's operators see them, never the instance's host or
    /// its provider, so no job runs. Adding a tag it has, or removing one it
    /// lacks, changes nothing. A reinstall, an upgrade, a restore and a
    /// gateway move keep them.
    ///
    /// `ghost instance tag redundant TAG on` marks a tag redundant: the
    /// instances that carry it are then never placed on the same host. An
    /// instance named redundant or help is named by its ID here.
    #[command(args_conflicts_with_subcommands = true, subcommand_negates_reqs = true)]
    Tag(TagArgs),
    /// List the account's tags, each with how many of its instances that
    /// are not deleted carry it and whether it is redundant: the first
    /// 500, by tag, and the redundant tags those leave out, such as one
    /// no instance carries (with 0).
    Tags,
    /// Replace a home instance's lost or compromised `WireGuard` key.
    ///
    /// The tunnel to the instance's gateway is down from the moment its host
    /// installs the new key until the gateway applies it: a few seconds, at
    /// most about half a minute. For a running instance the job then waits
    /// for a handshake with the new key; a stopped instance gets the key at
    /// its next start, and its job finishes once the gateway applied it.
    RotateGatewayKeys(RotateGatewayKeysArgs),
    /// Change a home VM's gateway: its tier between shared IP, shared bandwidth and high
    /// bandwidth, its location, or both.
    ///
    /// The locations are the offering's `gateway_locations` (`ghost catalog offering`) for a
    /// shared tier; high bandwidth gets a gateway of the VM's own, nearest to the host or at the
    /// location named, which Vultr takes a few minutes to create while the VM stays on its
    /// gateway. Every change gives the VM a new public address, leaves it unreachable for the
    /// seconds the change takes and costs the instance creation charge, so a change is never
    /// cheaper than renting anew; the quote shows the charge and the prices the new gateway takes
    /// from then on. To shared IP, the new slice's default ports are forwarded; from shared IP,
    /// every port of the new address is the VM's. Leaving high bandwidth retires the VM's gateway
    /// of its own. A failed change leaves the VM on its old gateway and refunds the charge.
    Gateway(GatewayArgs),
    /// Move a home VM to a gateway at another location, where it gets a new public address; an
    /// alias of `gateway --location`, with its charge (the instance creation charge). The
    /// locations are the offering's `gateway_locations`.
    GatewayLocation(GatewayLocationArgs),
    /// List where a shared IP VM's public ports go, or change it with `set`.
    ///
    /// A shared IP VM has a range of ports of its gateway's address, TCP
    /// and UDP, each forwarded to a port of the VM: by default the first to
    /// 22, every other to the same number. The gateway follows a change
    /// within a minute and drops the connections of a changed port. A move
    /// to another gateway gives the VM other ports, each going where the
    /// one in its place went.
    Ports(PortsArgs),
    /// Irreversibly enqueue instance deletion.
    Delete(DeleteArgs),
}

// What the instance runs is given explicitly, one of the four: no source
// is guessed, whichever kind its offering is offered as by default, and the
// usage error of none names them all.
#[derive(Args)]
#[command(group(
    clap::ArgGroup::new("source")
        .required(true)
        .args(["image", "backup", "container", "stock_image"])
))]
struct CreateInstanceArgs {
    /// Offering ID, from `ghost catalog offerings`.
    #[arg(long)]
    offering: String,
    /// Create a VM that installs this operating-system image: its slug,
    /// such as debian-13, or its ID, from `ghost catalog images`.
    #[arg(long, value_name = "IMAGE", value_parser = parse_image_reference)]
    image: Option<String>,
    /// Initialize the new instance from this backup instead of installing
    /// an image: a VM's backup makes a VM, a container instance's a
    /// container instance.
    #[arg(long, value_name = "BACKUP_ID")]
    backup: Option<Uuid>,
    #[command(flatten)]
    spec: ContainerArgs,
    /// How the VM is reached: required for home offerings; for a cloud
    /// offering omit it for an address of the VM's own, or give `shared_ip`
    /// to share the host's address where the offering lists it.
    ///
    /// `shared_bandwidth` shares a gateway in one of a few central regions
    /// with other VMs and has a public address of its own, every port of
    /// which reaches the VM. `high_bandwidth` has a gateway of its own in
    /// the region nearest to the host and a lower traffic rate; the VM's
    /// address is the gateway's, less port 27492, which the gateway keeps.
    /// `shared_ip` shares an address, a home VM's shared gateway's or a
    /// cloud VM's host's: a range of its
    /// ports (the offering's `shared_ip_ports`) reaches the VM, the first
    /// on port 22 (`ghost instance ports` changes where each goes), and its
    /// outgoing connections leave from a range of its own. No VM is faster
    /// than its home host's own connection, which its traffic also crosses.
    #[arg(long, value_enum)]
    gateway_tier: Option<GatewayTier>,
    /// For shared bandwidth and shared IP, the location of the shared gateway the VM is reached through,
    /// from the offering's `gateway_locations` (`ghost catalog offering`); without it the
    /// closest with room that crosses no bottleneck from the host. A location marked
    /// `bottleneck` is reached over a congested or long-haul path.
    #[arg(long)]
    gateway_location: Option<String>,
    /// OpenSSH public key line for root; repeat for multiple keys.
    // Armor starts with dashes: taken as a value, a private key given here
    // is refused by name, where clap would echo it as an unknown argument.
    #[arg(
        long = "ssh-key",
        value_name = "PUBLIC_KEY",
        allow_hyphen_values = true
    )]
    ssh_keys: Vec<String>,
    /// File of OpenSSH public keys, one per line, such as
    /// `~/.ssh/id_ed25519.pub`; repeat for multiple files.
    #[arg(long = "ssh-key-file", value_name = "FILE")]
    ssh_key_files: Vec<PathBuf>,
    /// cloud-init user data for the first boot: a #cloud-config YAML
    /// document, a script starting with #!, or a MIME multipart document.
    /// With --backup it runs once on the restored VM's first boot.
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with_all = ["startup_command", "startup_command_file"]
    )]
    cloud_init_file: Option<PathBuf>,
    /// RFC 1123 guest hostname; generated by the backend when omitted.
    #[arg(long, value_parser = parse_hostname)]
    hostname: Option<String>,
    /// The instance's name, which the website and `ghost` show, by the
    /// rules of a hostname; the hostname when omitted. It never reaches
    /// the guest.
    #[arg(long, value_parser = parse_hostname)]
    name: Option<String>,
    /// A tag of the new instance, your own label to group and filter
    /// instances by (1 to 32 lowercase letters, digits, `-`, `_`, `.` and
    /// `:`); repeat it for several, at most 20. With --backup and no --tag,
    /// the instance starts with the tags of the backup's instance.
    #[arg(long = "tag", value_name = "TAG", value_parser = parse_tag)]
    tags: Vec<String>,
    /// With --backup, start without the tags of the backup's instance.
    #[arg(long, conflicts_with = "tags")]
    no_tags: bool,
    /// One-time shell program run by cloud-init on first boot.
    #[arg(long)]
    startup_command: Option<String>,
    /// Read the one-time startup shell program from a UTF-8 file.
    #[arg(long, value_name = "FILE", conflicts_with = "startup_command")]
    startup_command_file: Option<PathBuf>,
    /// Maximum time to wait for a hosted restore-key offer from the selected hypervisor.
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..))]
    authorization_timeout_seconds: u64,
    #[command(flatten)]
    mutation: MutationArgs,
}

/// `--restart`: a container's [`RestartPolicy`].
#[derive(Clone, Copy, ValueEnum)]
enum RestartArg {
    Always,
    OnFailure,
    Never,
}

impl From<RestartArg> for RestartPolicy {
    fn from(value: RestartArg) -> Self {
        match value {
            RestartArg::Always => Self::Always,
            RestartArg::OnFailure => Self::OnFailure,
            RestartArg::Never => Self::Never,
        }
    }
}

/// A container instance's image and settings, as `instance create` and
/// `instance redeploy` take them.
#[derive(Args, Default)]
struct ContainerArgs {
    /// Run this container image: `[REGISTRY/]REPOSITORY[:TAG]` or
    /// `[REGISTRY/]REPOSITORY@sha256:HEX`, such as nginx:1.27 or
    /// ghcr.io/owner/app:v2. A tag is pinned to its digest when the
    /// instance is created or redeployed. The image runs as it is: it gets
    /// no SSH keys, cloud-init or startup command, and has no SSH unless it
    /// runs its own; `ghost instance logs` reads its output.
    #[arg(long, value_name = "IMAGE", value_parser = parse_container_image)]
    container: Option<String>,
    /// Run one of the platform's stock images: its slug, such as
    /// debian-13, from `ghost catalog container-images`. It runs the
    /// distribution's own init system and is reached over SSH with the
    /// keys given, as a VM is; of the container options it takes --env,
    /// --env-file, --restart and --volume.
    #[arg(long, value_name = "SLUG", value_parser = parse_stock_image)]
    stock_image: Option<String>,
    /// A container's environment variable, NAME=VALUE; repeat for more.
    /// One of a name given twice, here or in an --env-file, replaces the
    /// earlier. The values are kept encrypted and never shown again.
    #[arg(long = "env", value_name = "NAME=VALUE", allow_hyphen_values = true)]
    env: Vec<String>,
    /// File of a container's environment variables, NAME=VALUE lines;
    /// blank lines and lines starting with # are skipped, and the rest of a
    /// line after the first = is its value as it is. Repeat for more files;
    /// --env comes after them.
    #[arg(long = "env-file", value_name = "FILE")]
    env_files: Vec<PathBuf>,
    /// Replace the image's entrypoint (and its command, unless --command is
    /// given too): a JSON array of strings, such as
    /// `'["/app/server", "--port", "80"]'`, or a single word, such as
    /// /app/server. `[]` clears it.
    #[arg(long, value_name = "JSON_OR_WORD", allow_hyphen_values = true)]
    entrypoint: Option<String>,
    /// Replace the image's command, a JSON array of strings, such as
    /// `'["nginx", "-g", "daemon off;"]'`.
    #[arg(long, value_name = "JSON", allow_hyphen_values = true)]
    command: Option<String>,
    /// Run the container's process as this user: `user[:group]`, by name or
    /// number, as the image knows them.
    #[arg(long, value_name = "USER")]
    user: Option<String>,
    /// Run the container's process in this absolute directory.
    #[arg(long, value_name = "PATH")]
    workdir: Option<String>,
    /// How long a stop waits for the container's process after its stop
    /// signal before it is killed, 0 to 300 seconds; 10 when left out.
    #[arg(long, value_name = "SECONDS", value_parser = clap::value_parser!(u32).range(0..=300))]
    stop_timeout: Option<u32>,
    /// What happens when the container's process exits by itself: start it
    /// again (`always`, the default for --container), only when it failed
    /// (`on-failure`, the default for --stock-image), or leave the instance
    /// stopped (`never`).
    #[arg(long, value_enum, value_name = "POLICY")]
    restart: Option<RestartArg>,
    /// A path a redeploy keeps, such as /var/lib/app: absolute, without a
    /// trailing slash; repeat for more, at most 32. The VOLUME paths of the
    /// image the instance runs and of the one it moves to are kept too.
    #[arg(long = "volume", value_name = "PATH")]
    volumes: Vec<String>,
}

#[derive(Args)]
struct PowerArgs {
    /// Instance ID or name, from `ghost instance list`.
    #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
    instance_id: InstanceReference,
    /// The power state to reach, or a restart of a running instance.
    #[arg(value_enum)]
    state: PowerState,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
struct ReinstallArgs {
    /// Instance ID or name, from `ghost instance list`.
    #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
    instance_id: InstanceReference,
    /// Install this operating-system image: its slug, such as debian-13, or
    /// its ID, from `ghost catalog images`.
    #[arg(long, value_name = "IMAGE", value_parser = parse_image_reference)]
    image: String,
    /// OpenSSH public key line for root; repeat for multiple keys.
    // Armor starts with dashes: taken as a value, a private key given here
    // is refused by name, where clap would echo it as an unknown argument.
    #[arg(
        long = "ssh-key",
        value_name = "PUBLIC_KEY",
        allow_hyphen_values = true
    )]
    ssh_keys: Vec<String>,
    /// File of OpenSSH public keys, one per line, such as
    /// `~/.ssh/id_ed25519.pub`; repeat for multiple files.
    #[arg(long = "ssh-key-file", value_name = "FILE")]
    ssh_key_files: Vec<PathBuf>,
    /// cloud-init user data for the first boot: a #cloud-config YAML
    /// document, a script starting with #!, or a MIME multipart document.
    #[arg(
        long,
        value_name = "FILE",
        conflicts_with_all = ["startup_command", "startup_command_file"]
    )]
    cloud_init_file: Option<PathBuf>,
    /// RFC 1123 guest hostname; the instance keeps its hostname when
    /// omitted.
    #[arg(long, value_parser = parse_hostname)]
    hostname: Option<String>,
    /// One-time shell program run by cloud-init on first boot.
    #[arg(long)]
    startup_command: Option<String>,
    /// Read the one-time startup shell program from a UTF-8 file.
    #[arg(long, value_name = "FILE", conflicts_with = "startup_command")]
    startup_command_file: Option<PathBuf>,
    /// Confirm destruction of the current root filesystem.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
struct ResetAccessArgs {
    /// Instance ID or name, from `ghost instance list`.
    #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
    instance_id: InstanceReference,
    /// OpenSSH public key line to add for root; repeat for multiple keys.
    #[arg(
        long = "ssh-key",
        value_name = "PUBLIC_KEY",
        allow_hyphen_values = true
    )]
    ssh_keys: Vec<String>,
    /// File of OpenSSH public keys, one per line, such as
    /// `~/.ssh/id_ed25519.pub`; repeat for multiple files.
    #[arg(long = "ssh-key-file", value_name = "FILE")]
    ssh_key_files: Vec<PathBuf>,
    /// Also stop the guest's firewall (ufw, firewalld, nftables, iptables)
    /// for the boot; it starts again at the next.
    #[arg(long)]
    firewall: bool,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
struct RescueArgs {
    /// Instance ID or name, from `ghost instance list`.
    #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
    instance_id: InstanceReference,
    /// OpenSSH public key line root logs in with; repeat for multiple keys.
    #[arg(
        long = "ssh-key",
        value_name = "PUBLIC_KEY",
        allow_hyphen_values = true,
        conflicts_with = "exit"
    )]
    ssh_keys: Vec<String>,
    /// File of OpenSSH public keys, one per line, such as
    /// `~/.ssh/id_ed25519.pub`; repeat for multiple files.
    #[arg(long = "ssh-key-file", value_name = "FILE", conflicts_with = "exit")]
    ssh_key_files: Vec<PathBuf>,
    /// End the rescue: the instance boots its own system again.
    #[arg(long)]
    exit: bool,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
struct UpdateArgs {
    /// Instance ID or name, from `ghost instance list`.
    #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
    instance_id: InstanceReference,
    /// New tag of the saved registry/repository; omit to refresh its current reference.
    #[arg(long, value_name = "TAG")]
    tag: Option<String>,
    /// Confirm root replacement outside the kept paths.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
#[command(group(
    clap::ArgGroup::new("redeploy_image")
        .required(true)
        .args(["container", "stock_image"])
))]
struct RedeployArgs {
    /// Instance ID or name, from `ghost instance list`.
    #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
    instance_id: InstanceReference,
    #[command(flatten)]
    spec: ContainerArgs,
    /// Keep none of the instance's own paths, only the images' VOLUME
    /// paths.
    #[arg(long, conflicts_with = "volumes")]
    no_volumes: bool,
    /// Give every setting left out a new instance's default instead of the
    /// instance's current one: no environment, the image's entrypoint and
    /// command, no paths of its own.
    #[arg(long)]
    reset: bool,
    /// Drop this setting for the new image's own: entrypoint, command, user
    /// or workdir; repeat for several.
    #[arg(long, value_enum, value_name = "SETTING")]
    clear: Vec<RedeploySetting>,
    /// For --stock-image, an OpenSSH public key line for root; repeat for
    /// multiple keys. Without one, the keys saved in the account.
    #[arg(
        long = "ssh-key",
        value_name = "PUBLIC_KEY",
        allow_hyphen_values = true
    )]
    ssh_keys: Vec<String>,
    /// For --stock-image, a file of OpenSSH public keys, one per line;
    /// repeat for multiple files.
    #[arg(long = "ssh-key-file", value_name = "FILE")]
    ssh_key_files: Vec<PathBuf>,
    /// Confirm that everything on the root disk but the kept paths is
    /// replaced.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
struct UpgradeArgs {
    /// Instance ID or name, from `ghost instance list`.
    #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
    instance_id: InstanceReference,
    /// The offering of the size, from `ghost instance upgrades`.
    #[arg(long, value_name = "OFFERING")]
    offering: String,
    /// Confirm the shutdown and restart of the instance.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
struct RenameArgs {
    /// Instance ID or name, from `ghost instance list`.
    #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
    instance_id: InstanceReference,
    /// The new name: a lowercase RFC 1123 hostname.
    #[arg(value_parser = parse_hostname)]
    name: String,
    #[command(flatten)]
    idempotency: IdempotencyArgs,
}

#[derive(Args)]
struct TagArgs {
    #[command(subcommand)]
    command: Option<TagCommand>,
    /// Instance ID or name, from `ghost instance list`.
    #[arg(value_name = "INSTANCE", required = true, value_parser = parse_instance_reference)]
    instance_id: Option<InstanceReference>,
    /// Add the tags, or remove them.
    #[arg(value_enum, required = true)]
    action: Option<TagAction>,
    /// The tags, one or more.
    #[arg(value_name = "TAG", required = true, value_parser = parse_tag)]
    tags: Vec<String>,
    #[command(flatten)]
    idempotency: IdempotencyArgs,
}

#[derive(Subcommand)]
enum TagCommand {
    /// Mark one of the account's tags redundant, or clear the flag.
    ///
    /// The instances that carry a redundant tag are never placed on the
    /// same host: a new one goes to a host of its offering without another
    /// of them, or is refused when every host has one. They may still be of
    /// the same provider and location. Marking is refused while two of them
    /// share a host; clearing is always allowed. An instance with two
    /// redundant tags is kept apart from the instances of each.
    Redundant {
        /// The tag.
        #[arg(value_name = "TAG", value_parser = parse_tag)]
        tag: String,
        /// on marks it, off clears it.
        #[arg(value_enum)]
        state: Switch,
        #[command(flatten)]
        idempotency: IdempotencyArgs,
    },
}

/// What `ghost instance tag redundant` sets.
#[derive(Clone, Copy, ValueEnum)]
enum Switch {
    On,
    Off,
}

/// What `ghost instance tag` does with its tags.
#[derive(Clone, Copy, ValueEnum)]
enum TagAction {
    Add,
    Remove,
}

#[derive(Args)]
struct PortsArgs {
    /// Instance ID or name of a shared IP instance.
    #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
    instance_id: InstanceReference,
    #[command(subcommand)]
    action: Option<PortsAction>,
}

#[derive(Subcommand)]
enum PortsAction {
    /// Forward public ports of the VM to other ports of it; the others
    /// stay as they are.
    Set {
        /// `PUBLIC=GUEST`, such as `1020=22`: the VM's public port and the
        /// port of the VM it goes to (1 to 65535); repeat for more.
        #[arg(required = true, value_parser = parse_port_forward)]
        forwards: Vec<PortForwardChange>,
        #[command(flatten)]
        idempotency: IdempotencyArgs,
    },
}

#[derive(Args)]
struct RotateGatewayKeysArgs {
    /// Instance ID or name of a home instance.
    #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
    instance_id: InstanceReference,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
struct GatewayArgs {
    /// Instance ID or name of a home instance.
    #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
    instance_id: InstanceReference,
    /// The tier to change to, `shared-ip`, `shared-bandwidth` or `high-bandwidth`; without it
    /// the VM keeps its tier.
    #[arg(long, value_enum)]
    tier: Option<GatewayTier>,
    /// The location to change to, from the offering's `gateway_locations` for a shared tier;
    /// without it the VM keeps its location, or high bandwidth takes the one nearest to the
    /// host.
    #[arg(long)]
    location: Option<String>,
    /// Confirm that the change costs the instance creation charge and that the VM gets a new
    /// public address and is unreachable for the seconds the change takes.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
struct GatewayLocationArgs {
    /// Instance ID or name of a shared IP or shared bandwidth home instance.
    #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
    instance_id: InstanceReference,
    /// The location, from the offering's `gateway_locations`.
    location: String,
    /// Confirm that the move costs the instance creation charge and that the VM gets a new
    /// public address and is unreachable for the seconds its move takes.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
struct DeleteArgs {
    /// Instance ID or name, from `ghost instance list`.
    #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
    instance_id: InstanceReference,
    /// Confirm the irreversible deletion.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
struct MutationArgs {
    #[command(flatten)]
    idempotency: IdempotencyArgs,
    /// Poll until the asynchronous job reaches a terminal state.
    #[arg(long)]
    wait: bool,
    /// Poll interval used with --wait.
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..))]
    poll_seconds: u64,
    /// Set when `ghost account approve` runs this mutation for a website
    /// request: the key then belongs to that request, and repeating the
    /// approval retries it.
    #[arg(skip)]
    browser_intent: Option<Uuid>,
}

impl MutationArgs {
    pub fn key(&self) -> MutationKey {
        match self.browser_intent {
            Some(id) => MutationKey {
                key: format!("browser-intent-{id}"),
                retry: format!("`ghost account approve {id} --yes`"),
            },
            None => self.idempotency.key(),
        }
    }
}

/// The account history's page, and which of its entries to keep.
#[derive(Args)]
struct LedgerHistoryArgs {
    /// Only the entries of this instance: its charges, holds and refunds.
    /// Its ID, or the name of a current instance.
    #[arg(long, value_name = "INSTANCE", value_parser = parse_instance_reference)]
    instance: Option<InstanceReference>,
    /// Only entries of this kind of transaction.
    #[arg(long, value_enum)]
    kind: Option<LedgerKind>,
    #[command(flatten)]
    page: HistoryArgs,
}

/// A path of an instance's traffic (`ghost instance usage --path`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum UsagePath {
    /// Its gateway's: the usage.
    Gateway,
    /// The host mesh's internet links.
    WanMesh,
    /// The host mesh's LAN links.
    LanMesh,
}

impl UsagePath {
    /// The mesh path as the API names it; none for the gateway's.
    const fn mesh(self) -> Option<&'static str> {
        match self {
            Self::Gateway => None,
            Self::WanMesh => Some("wan_mesh"),
            Self::LanMesh => Some("lan_mesh"),
        }
    }
}

#[derive(Args)]
pub struct HistoryArgs {
    /// Continue after the previous page: its `next_cursor`.
    #[arg(long)]
    cursor: Option<String>,
    /// Most items to return, 1 to 200.
    #[arg(long, default_value_t=50, value_parser=clap::value_parser!(u32).range(1..=200))]
    limit: u32,
}
impl HistoryArgs {
    pub fn query(&self) -> String {
        self.query_after(&[])
    }

    /// `filters`, then this page's limit and cursor, as a query string.
    /// # Panics
    /// Panics only if the static query URL cannot be parsed.
    pub fn query_after(&self, filters: &[(&str, String)]) -> String {
        let mut url = reqwest::Url::parse("https://api.gigahost.cloud/").expect("static URL");
        let mut query = url.query_pairs_mut();
        for (name, value) in filters {
            query.append_pair(name, value);
        }
        query.append_pair("limit", &self.limit.to_string());
        if let Some(cursor) = &self.cursor {
            query.append_pair("cursor", cursor);
        }
        drop(query);
        url.query().unwrap_or_default().to_owned()
    }
}

#[derive(Subcommand)]
enum BackupCommand {
    /// List the account's backups, or one instance's, newest first;
    /// deleted ones only with --all. Filter them by state, by where they
    /// are kept and by their instances' tags, and sort them by age, size or
    /// monthly storage cost.
    List {
        /// Only this instance's backups: its ID or name, from `ghost
        /// instance list`.
        #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
        instance_id: Option<InstanceReference>,
        /// Also list deleted backups.
        #[arg(long)]
        all: bool,
        /// Only backups in this state; repeat it for several. A state
        /// given replaces --all: list `deleted` to see deleted ones.
        #[arg(long = "state", value_name = "STATE", value_enum)]
        states: Vec<BackupStateFilter>,
        /// Only backups hosted by Gigahost.
        #[arg(long, conflicts_with = "local")]
        hosted: bool,
        /// Only backups stored on their instance's host.
        #[arg(long)]
        local: bool,
        /// Only backups of instances that carry this tag; repeat it for
        /// instances that carry every one named (at most 5).
        #[arg(long = "tag", value_name = "TAG", value_parser = parse_tag)]
        tags: Vec<String>,
        /// What to sort by: the creation time (the default), the size, or
        /// what the backup's storage costs a month. Backups without a size
        /// yet come last by size or cost.
        #[arg(long, value_name = "KEY", value_enum)]
        sort: Option<BackupSort>,
        /// Oldest, smallest or cheapest first.
        #[arg(long, conflicts_with = "desc")]
        asc: bool,
        /// Newest, largest or costliest first (the default).
        #[arg(long)]
        desc: bool,
    },
    /// Show one backup, a deleted one too: its state, size, prices, key
    /// fingerprint, and the instance and image it was taken of.
    Get {
        /// Backup ID, from `ghost backup list`.
        backup_id: Uuid,
    },
    /// Enqueue a live local or encrypted hosted backup.
    Create(CreateBackupArgs),
    /// Cancel a backup that waits for its turn, at no charge. One its host
    /// has begun cannot be cancelled: delete it once it is available.
    Cancel(CancelBackupArgs),
    /// Restore a backup, locally rewrapping hosted-backup keys when needed.
    Restore(RestoreBackupArgs),
    /// Permanently delete a local or hosted backup.
    Delete(DeleteBackupArgs),
    /// Show, set or clear an instance's backup schedule: up to 4 rules,
    /// each making a local or hosted backup daily, weekly or monthly at a
    /// time in UTC and keeping its newest few.
    ///
    /// A rule's backup starts within the hour after its time, at an offset
    /// the same for every rule of the instance. Once one has completed, the
    /// rule's oldest beyond its keep are deleted; a failed run deletes
    /// nothing, and backups made by hand or by a removed rule are never
    /// deleted by the schedule. Each run is charged as a backup made by
    /// hand, at the prices when it runs; a run the balance cannot pay is
    /// skipped and you are notified. Hosted backups are encrypted to your
    /// account's recovery key, so a schedule needs no seed to run.
    Schedule {
        #[command(subcommand)]
        command: ScheduleCommand,
    },
}

#[derive(Subcommand)]
enum ScheduleCommand {
    /// Show the instance's schedule: its rules with their next run and last
    /// result, and the backups removed rules left.
    Show {
        /// Instance ID or name, from `ghost instance list`.
        #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
        instance_id: InstanceReference,
    },
    /// Replace the instance's schedule with the rules given.
    ///
    /// `ghost backup schedule set web-1 --rule daily:local:3 --rule
    /// weekly:hosted:2 --at 03:00 --weekday sun` backs web-1 up locally
    /// every day and keeps 3, and hosted every Sunday and keeps 2, both at
    /// 03:00 UTC. A rule may name its own time and day after it, so two
    /// rules can differ: `--rule daily:local:3@01:30 --rule
    /// monthly:hosted:6@04:00/1`. A rule changes a live rule of the
    /// schedule in place, which keeps its backups: the live rule equal to
    /// it in every field; else the one live rule left of its frequency,
    /// destination, time and day (its keep changes); else the one live
    /// rule left of its frequency and destination (its time, day and keep
    /// change). Each live rule is changed by one rule at most. Any other
    /// rule is new, and the live rules no rule changes are removed; their
    /// backups stay. A lower keep deletes the rule's oldest backups beyond
    /// it, which `set` names and does only with --yes. The keeps, with one
    /// more for each rule, fit the backups-per-instance limit.
    Set(ScheduleSetArgs),
    /// Remove every rule of the instance's schedule; its backups stay.
    Clear {
        /// Instance ID or name, from `ghost instance list`.
        #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
        instance_id: InstanceReference,
        #[command(flatten)]
        idempotency: IdempotencyArgs,
    },
}

#[derive(Args)]
struct ScheduleSetArgs {
    /// Instance ID or name, from `ghost instance list`.
    #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
    instance_id: InstanceReference,
    /// A rule, FREQUENCY:DESTINATION:KEEP: daily, weekly or monthly; local
    /// or hosted; how many of its backups to keep. Its own time and day may
    /// follow as @HH:MM and /DAY (a weekday for a weekly rule, such as sun,
    /// a day from 1 to 28 for a monthly one). Repeat it for up to 4 rules.
    #[arg(long = "rule", value_name = "RULE", required = true, value_parser = parse_schedule_rule)]
    rules: Vec<ScheduleRuleArg>,
    /// The time of day in UTC, HH:MM, of each rule that names none.
    #[arg(long, value_name = "HH:MM", value_parser = parse_clock)]
    at: Option<u16>,
    /// The weekday of each weekly rule that names none: sun, mon, tue,
    /// wed, thu, fri or sat.
    #[arg(long, value_name = "DAY", value_parser = parse_weekday)]
    weekday: Option<u8>,
    /// The day of the month, 1 to 28, of each monthly rule that names none.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u8).range(1..=28))]
    day: Option<u8>,
    /// Lower a rule's keep although that deletes its oldest backups beyond
    /// the new keep, which cannot be undone.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    idempotency: IdempotencyArgs,
}

/// One `--rule` of `ghost backup schedule set`, as typed.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ScheduleRuleArg {
    frequency: BackupScheduleFrequency,
    destination: BackupDestinationKind,
    keep: u32,
    at: Option<u16>,
    day: Option<String>,
}

/// `HH:MM` as minutes after midnight.
fn parse_clock(text: &str) -> Result<u16, String> {
    let (hours, minutes) = text
        .split_once(':')
        .ok_or_else(|| format!("{text:?} is no time; give HH:MM, such as 03:00"))?;
    match (hours.parse::<u16>(), minutes.parse::<u16>()) {
        (Ok(hours), Ok(minutes))
            if hours < 24 && minutes < 60 && text.len() - hours_len(text) == 3 =>
        {
            Ok(hours * 60 + minutes)
        }
        _ => Err(format!("{text:?} is no time; give HH:MM, such as 03:00")),
    }
}

/// The length of the hours of `HH:MM`, so the minutes are two digits.
fn hours_len(text: &str) -> usize {
    text.find(':').unwrap_or(text.len())
}

/// A weekday as `--weekday` takes it: sun to sat, or 0 (Sunday) to 6.
fn parse_weekday(text: &str) -> Result<u8, String> {
    const DAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
    const FULL: [&str; 7] = [
        "sunday",
        "monday",
        "tuesday",
        "wednesday",
        "thursday",
        "friday",
        "saturday",
    ];
    let lower = text.to_ascii_lowercase();
    DAYS.iter()
        .zip(FULL)
        .position(|(day, full)| lower == *day || lower == full)
        .and_then(|day| u8::try_from(day).ok())
        .or_else(|| lower.parse::<u8>().ok().filter(|day| *day <= 6))
        .ok_or_else(|| format!("{text:?} is no weekday; give sun, mon, tue, wed, thu, fri or sat"))
}

/// A `--rule`: `FREQUENCY:DESTINATION:KEEP[@HH:MM][/DAY]`.
fn parse_schedule_rule(text: &str) -> Result<ScheduleRuleArg, String> {
    let shape = || {
        format!(
            "{text:?} is no rule; give FREQUENCY:DESTINATION:KEEP, such as daily:local:3, optionally with @HH:MM and /DAY"
        )
    };
    let (head, day) = match text.split_once('/') {
        Some((head, day)) => (head, Some(day.to_owned())),
        None => (text, None),
    };
    let (head, at) = match head.split_once('@') {
        Some((head, at)) => (head, Some(parse_clock(at)?)),
        None => (head, None),
    };
    let mut parts = head.split(':');
    let (Some(frequency), Some(destination), Some(keep), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(shape());
    };
    let frequency = match frequency.to_ascii_lowercase().as_str() {
        "daily" => BackupScheduleFrequency::Daily,
        "weekly" => BackupScheduleFrequency::Weekly,
        "monthly" => BackupScheduleFrequency::Monthly,
        _ => {
            return Err(format!(
                "{frequency:?} is no frequency; give daily, weekly or monthly"
            ));
        }
    };
    let destination = match destination.to_ascii_lowercase().as_str() {
        "local" => BackupDestinationKind::Local,
        "hosted" | "gigahost_s3" => BackupDestinationKind::GigahostS3,
        _ => {
            return Err(format!(
                "{destination:?} is no destination; give local or hosted"
            ));
        }
    };
    let keep = keep
        .parse::<u32>()
        .ok()
        .filter(|keep| *keep >= 1)
        .ok_or_else(|| format!("{keep:?} is no keep; give how many backups to keep, 1 or more"))?;
    Ok(ScheduleRuleArg {
        frequency,
        destination,
        keep,
        at,
        day,
    })
}

/// The schedule `ghost backup schedule set` asks for: each rule with its
/// own time and day, or the flags' for those that name none.
fn schedule_request(args: &ScheduleSetArgs) -> Result<SetBackupScheduleRequest> {
    let mut rules = Vec::with_capacity(args.rules.len());
    for (index, rule) in args.rules.iter().enumerate() {
        let number = index + 1;
        let minute_of_day = rule.at.or(args.at).ok_or_else(|| {
            anyhow::anyhow!("rule {number} has no time: give --at HH:MM, or @HH:MM after the rule")
        })?;
        let (weekday, day_of_month) = match rule.frequency {
            BackupScheduleFrequency::Weekly => {
                let weekday = match &rule.day {
                    Some(day) => parse_weekday(day).map_err(|error| anyhow::anyhow!(error))?,
                    None => args.weekday.ok_or_else(|| {
                        anyhow::anyhow!(
                            "rule {number} is weekly: give --weekday DAY, or /DAY after the rule"
                        )
                    })?,
                };
                (Some(weekday), None)
            }
            BackupScheduleFrequency::Monthly => {
                let day = match &rule.day {
                    Some(day) => day
                        .parse::<u8>()
                        .ok()
                        .filter(|day| (1..=28).contains(day))
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "rule {number}'s day must be 1 to 28, which every month has"
                            )
                        })?,
                    None => args.day.ok_or_else(|| {
                        anyhow::anyhow!(
                            "rule {number} is monthly: give --day N, or /N after the rule"
                        )
                    })?,
                };
                (None, Some(day))
            }
            _ => {
                if rule.day.is_some() {
                    bail!("rule {number} is daily: it takes no /DAY");
                }
                (None, None)
            }
        };
        rules.push(BackupScheduleRuleInput {
            id: None,
            destination: rule.destination,
            frequency: rule.frequency,
            minute_of_day,
            weekday,
            day_of_month,
            keep: rule.keep,
        });
    }
    Ok(SetBackupScheduleRequest { rules })
}

/// Whether the live rule `live` is of the rule's destination and frequency.
fn same_kind(rule: &BackupScheduleRuleInput, live: &BackupScheduleRuleView) -> bool {
    live.destination == rule.destination && live.frequency == rule.frequency
}

/// Whether the live rule `live` is of the rule's kind and runs at its time
/// and day.
fn same_slot(rule: &BackupScheduleRuleInput, live: &BackupScheduleRuleView) -> bool {
    same_kind(rule, live)
        && live.minute_of_day == rule.minute_of_day
        && live.weekday == rule.weekday
        && live.day_of_month == rule.day_of_month
}

/// Whether a live rule is the one a rule of `ghost backup schedule set`
/// changes, in one of `carry_rule_ids`'s passes.
type RuleMatch = fn(&BackupScheduleRuleInput, &BackupScheduleRuleView) -> bool;

/// Carry the IDs of `schedule`'s live rules over to the `request`'s rules,
/// so `ghost backup schedule set` changes a rule in place, keeping its
/// backups, and the same `set` run again changes nothing. Each live rule
/// goes to one rule at most, in three passes over the rules still without
/// an ID: a live rule equal to the rule in every field (any of them, when
/// several are); else the one live rule left of the rule's slot (its kind,
/// time and day), whose keep changes; else the one live rule left of its
/// destination and frequency. Any other rule is new.
fn carry_rule_ids(request: &mut SetBackupScheduleRequest, schedule: &BackupScheduleView) {
    let mut taken: Vec<Uuid> = Vec::new();
    // Each with whether it takes a live rule only when one alone matches.
    let passes: [(RuleMatch, bool); 3] = [
        (
            |rule, live| same_slot(rule, live) && live.keep == rule.keep,
            false,
        ),
        (same_slot, true),
        (same_kind, true),
    ];
    for (matches, only_one) in passes {
        for rule in request.rules.iter_mut().filter(|rule| rule.id.is_none()) {
            let mut left = schedule
                .rules
                .iter()
                .filter(|live| !taken.contains(&live.rule_id) && matches(rule, live));
            let live = match (left.next(), left.next()) {
                (Some(live), None) => live,
                (Some(live), Some(_)) if !only_one => live,
                _ => continue,
            };
            taken.push(live.rule_id);
            rule.id = Some(live.rule_id);
        }
    }
}

/// A rule of `ghost backup schedule set` that lowers a live rule's keep
/// and so deletes some of its oldest backups.
#[derive(Debug)]
struct ScheduleDeletion<'a> {
    /// The rule's number, from 1, as the API's refusals count them.
    number: usize,
    live: &'a BackupScheduleRuleView,
    /// The new keep.
    keep: u32,
    /// How many of the live rule's oldest backups go: beyond those its
    /// retention deletes anyway, a completed backup over the old keep.
    deleted: u32,
}

/// What the `request` deletes, with the IDs `carry_rule_ids` gave it: each
/// rule that lowers a live rule's keep below its completed backups.
fn schedule_deletions<'a>(
    request: &SetBackupScheduleRequest,
    schedule: &'a BackupScheduleView,
) -> Vec<ScheduleDeletion<'a>> {
    request
        .rules
        .iter()
        .enumerate()
        .filter_map(|(index, rule)| {
            let live = schedule
                .rules
                .iter()
                .find(|live| Some(live.rule_id) == rule.id)?;
            let deleted = live
                .completed_count
                .min(live.keep)
                .saturating_sub(rule.keep);
            (deleted > 0).then_some(ScheduleDeletion {
                number: index + 1,
                live,
                keep: rule.keep,
                deleted,
            })
        })
        .collect()
}

/// Why `ghost backup schedule set` without `--yes` changes nothing: the
/// backups its lower keeps would delete.
fn schedule_deletion_refusal(deletions: &[ScheduleDeletion<'_>]) -> String {
    let each: Vec<String> = deletions
        .iter()
        .map(|deletion| {
            let deleted = deletion.deleted;
            format!(
                "rule {} lowers the keep of the {} {} rule from {} to {}, which deletes its {deleted} oldest backup{}",
                deletion.number,
                schedule_frequency_word(deletion.live.frequency),
                schedule_destination_word(deletion.live.destination),
                deletion.live.keep,
                deletion.keep,
                if deleted == 1 { "" } else { "s" }
            )
        })
        .collect();
    format!(
        "{}; backup deletion is irreversible; repeat with --yes",
        each.join("; ")
    )
}

/// A schedule's frequency as `--rule` names it.
const fn schedule_frequency_word(frequency: BackupScheduleFrequency) -> &'static str {
    match frequency {
        BackupScheduleFrequency::Daily => "daily",
        BackupScheduleFrequency::Weekly => "weekly",
        BackupScheduleFrequency::Monthly => "monthly",
        BackupScheduleFrequency::Unknown => "unknown",
    }
}

/// A backup destination as `--rule` names it.
const fn schedule_destination_word(destination: BackupDestinationKind) -> &'static str {
    match destination {
        BackupDestinationKind::Local => "local",
        BackupDestinationKind::GigahostS3 => "hosted",
        BackupDestinationKind::Unknown => "unknown",
    }
}

#[derive(Args)]
struct CreateBackupArgs {
    /// Instance ID or name, from `ghost instance list`.
    #[arg(value_name = "INSTANCE", value_parser = parse_instance_reference)]
    instance_id: InstanceReference,
    /// local keeps the backup on the instance's host; hosted encrypts it
    /// for your account and stores it off the host. Hosted uploads run at
    /// the host's backup upload limit (`backup_upload_rate_bps`, 32 Mbit/s
    /// by default, about 4 MB/s shared by the host's backups).
    #[arg(long, value_enum)]
    destination: BackupDestinationArg,
    /// Sign this pricing revision instead of the current one. A failed
    /// attempt's retry hint supplies it with --maximum-charge-microusd, so the
    /// retry matches the first request exactly even after a price change.
    #[arg(long, requires_all = ["maximum_charge_microusd", "idempotency_key"])]
    pricing_revision: Option<u64>,
    /// The maximum charge the first attempt signed; see --pricing-revision.
    #[arg(long, requires = "pricing_revision")]
    maximum_charge_microusd: Option<u64>,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
struct CancelBackupArgs {
    /// Backup ID, from `ghost backup list`.
    backup_id: Uuid,
    #[command(flatten)]
    mutation: IdempotencyArgs,
}

#[derive(Args)]
struct RestoreBackupArgs {
    /// Backup ID, from `ghost backup list`. It replaces the root filesystem
    /// of the instance it was taken of.
    #[arg(value_name = "BACKUP_ID")]
    first_id: Uuid,
    /// The backup ID of the older form, `INSTANCE_ID BACKUP_ID`, which is
    /// still accepted.
    #[arg(value_name = "LEGACY_BACKUP_ID", hide = true)]
    legacy_backup_id: Option<Uuid>,
    /// Confirm replacement of the instance's current root filesystem.
    #[arg(long)]
    yes: bool,
    /// Maximum time to wait for a hosted restore-key offer from the hypervisor.
    #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(1..))]
    authorization_timeout_seconds: u64,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
struct DeleteBackupArgs {
    /// Backup ID, from `ghost backup list`.
    #[arg(value_name = "BACKUP_ID")]
    first_id: Uuid,
    /// The backup ID of the older form, `INSTANCE_ID BACKUP_ID`, which is
    /// still accepted.
    #[arg(value_name = "LEGACY_BACKUP_ID", hide = true)]
    legacy_backup_id: Option<Uuid>,
    /// Confirm permanent deletion of the backup.
    #[arg(long)]
    yes: bool,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Subcommand)]
enum JobCommand {
    /// List the account's jobs, newest first, with their state and progress.
    List {
        /// Only this instance's jobs, including those of its backups. Its
        /// ID, or the name of a current instance.
        #[arg(long, value_name = "INSTANCE", value_parser = parse_instance_reference)]
        instance: Option<InstanceReference>,
        /// Only jobs in this state; `active` is pending or running.
        #[arg(long, value_enum)]
        state: Option<JobStateFilter>,
        /// Only jobs of this kind.
        #[arg(long, value_enum)]
        kind: Option<JobKind>,
        #[command(flatten)]
        page: HistoryArgs,
    },
    /// Read one durable job snapshot.
    Get {
        /// Job ID, as a mutation printed it.
        job_id: Uuid,
    },
    /// Poll and print the final durable job snapshot.
    Watch {
        /// Job ID, as a mutation printed it.
        job_id: Uuid,
        /// Poll interval.
        #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u64).range(1..))]
        poll_seconds: u64,
    },
}

#[derive(Subcommand)]
enum SupportCommand {
    /// List this account's tickets; operators may list the global queue.
    List {
        /// Only tickets in this state.
        #[arg(long, value_enum)]
        state: Option<SupportTicketState>,
        /// Every account's tickets (operators only).
        #[arg(long)]
        all: bool,
    },
    /// Show one ticket and its ordered message thread.
    Get {
        /// Ticket ID, from `ghost support list`.
        ticket_id: Uuid,
    },
    /// Create a ticket with an optional validated resource link.
    Create(CreateSupportTicketArgs),
    /// Add a message; an operator reply makes the ticket wait on the user.
    Reply(SupportReplyArgs),
    /// Change lifecycle state. Ordinary users may only open or close tickets.
    State(SupportStateArgs),
}

#[derive(Args)]
struct CreateSupportTicketArgs {
    /// What the ticket is about.
    #[arg(long, value_enum)]
    category: SupportTicketCategory,
    /// How urgent it is.
    #[arg(long, value_enum, default_value = "normal")]
    priority: SupportTicketPriority,
    /// One-line summary.
    #[arg(long)]
    subject: String,
    /// The first message.
    #[arg(
        long,
        required_unless_present = "message_file",
        conflicts_with = "message_file"
    )]
    message: Option<String>,
    /// Read the first message from a UTF-8 file.
    #[arg(long, value_name = "FILE", conflicts_with = "message")]
    message_file: Option<PathBuf>,
    /// Link the ticket to this instance: its ID, or the name of a current
    /// instance.
    #[arg(
        long,
        value_name = "INSTANCE",
        value_parser = parse_instance_reference,
        conflicts_with_all = ["backup", "ledger_transaction", "host", "provider_incident"]
    )]
    instance: Option<InstanceReference>,
    /// Link the ticket to this backup.
    #[arg(long, conflicts_with_all = ["instance", "ledger_transaction", "host", "provider_incident"])]
    backup: Option<Uuid>,
    /// Link the ticket to this ledger transaction: an entry's
    /// `transaction_id` in `ghost --json account history`.
    #[arg(long, conflicts_with_all = ["instance", "backup", "host", "provider_incident"])]
    ledger_transaction: Option<Uuid>,
    /// Link the ticket to this host of yours.
    #[arg(long, conflicts_with_all = ["instance", "backup", "ledger_transaction", "provider_incident"])]
    host: Option<Uuid>,
    /// Link the ticket to this provider incident.
    #[arg(long, conflicts_with_all = ["instance", "backup", "ledger_transaction", "host"])]
    provider_incident: Option<Uuid>,
    #[command(flatten)]
    mutation: IdempotencyArgs,
}

#[derive(Args)]
struct SupportReplyArgs {
    /// Ticket ID, from `ghost support list`.
    ticket_id: Uuid,
    /// The message.
    #[arg(
        long,
        required_unless_present = "message_file",
        conflicts_with = "message_file"
    )]
    message: Option<String>,
    /// Read the message from a UTF-8 file.
    #[arg(long, value_name = "FILE", conflicts_with = "message")]
    message_file: Option<PathBuf>,
    #[command(flatten)]
    mutation: IdempotencyArgs,
}

#[derive(Args)]
struct SupportStateArgs {
    /// Ticket ID, from `ghost support list`.
    ticket_id: Uuid,
    /// The new state.
    #[arg(value_enum)]
    state: SupportTicketState,
    /// Who the ticket waits on; required with the waiting state.
    #[arg(long, value_enum, required_if_eq("state", "waiting"))]
    waiting_on: Option<SupportWaitingOn>,
    #[command(flatten)]
    mutation: IdempotencyArgs,
}

#[derive(Clone, Copy, ValueEnum)]
enum BackupDestinationArg {
    Local,
    Hosted,
}

#[derive(Debug, Deserialize)]
struct RestoreKeyOffer {
    destination_public_key: String,
    destination_key_fingerprint: String,
    offer_expires_at: DateTime<Utc>,
}

/// How a command's result is printed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFormat {
    /// For reading: aligned, in tables, with colors on a terminal.
    Readable,
    /// Indented JSON, for `--json`.
    Json,
    /// JSON on one line, for `--compact`.
    CompactJson,
}

impl GlobalOptions {
    /// The form the caller asked for; `--compact` implies `--json`.
    #[must_use]
    pub const fn output_format(&self) -> OutputFormat {
        if self.compact {
            OutputFormat::CompactJson
        } else if self.json {
            OutputFormat::Json
        } else {
            OutputFormat::Readable
        }
    }
}

impl Cli {
    pub const fn output_format(&self) -> OutputFormat {
        self.globals.output_format()
    }
}
impl GlobalOptions {
    /// Build the shared signed transport.
    /// # Errors
    /// Fails if the API URL is invalid or the HTTP client cannot be constructed.
    pub fn api_client(&self) -> Result<ApiClient> {
        self.api_client_for_release(release())
    }
    /// Build the transport identifying this frontend release.
    /// # Errors
    /// Fails if the API URL or release header is invalid, or the HTTP client cannot be constructed.
    pub fn api_client_for_release(&self, release: &str) -> Result<ApiClient> {
        let seed_file = self.seed_file.clone();
        ApiClient::with_identity_loader_for_release(
            &self.api_url,
            Box::new(move || account_identity(seed_file.as_deref())),
            release,
        )
    }
}

/// What `ghost --version` prints after the name: the release the install
/// script recorded for this binary, or the crate version of a build that was
/// not installed from a release.
fn version_text() -> &'static str {
    static VERSION: LazyLock<String> = LazyLock::new(|| {
        std::env::current_exe()
            .ok()
            .and_then(|executable| installed_release(&executable))
            .unwrap_or_else(|| format!("{} (development build)", env!("CARGO_PKG_VERSION")))
    });
    &VERSION
}

/// The release this `ghost` names in every request, as `User-Agent` and
/// `X-Gigahost-Client` (`ghost/RELEASE`): the one the install script
/// recorded, or `dev` for a build that was not installed from a release.
/// The backend refuses a release below `minimum_cli_release` with a 426
/// `client_release_unsupported` that names the release to install.
pub(crate) fn release() -> &'static str {
    static RELEASE: LazyLock<String> = LazyLock::new(|| {
        std::env::current_exe()
            .ok()
            .and_then(|executable| installed_release(&executable))
            .unwrap_or_else(|| gigahost_client_api::support_window::DEVELOPMENT_RELEASE.to_owned())
    });
    &RELEASE
}

/// The release ID the install script wrote to
/// `PREFIX/lib/gigahost/cli-release` when it installed `PREFIX/bin/ghost`,
/// for the binary at `executable`. A release ID embeds the hash of the
/// built binary, so the binary cannot carry its own.
fn installed_release(executable: &Path) -> Option<String> {
    let prefix = executable.parent()?.parent()?;
    let recorded = fs::read_to_string(prefix.join("lib/gigahost/cli-release")).ok()?;
    let release = recorded.trim_end_matches(['\r', '\n']);
    is_release_id(release).then(|| release.to_owned())
}

/// Whether `value` is a release ID: a UTC timestamp and 12 hexadecimal
/// digits of the binaries' hash, such as `20260927T074123Z-3d98cd281141`.
fn is_release_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 29
        && bytes[..8].iter().all(u8::is_ascii_digit)
        && bytes[8] == b'T'
        && bytes[9..15].iter().all(u8::is_ascii_digit)
        && bytes[15..17] == *b"Z-"
        && bytes[17..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

/// The command line as `ghost` parses it. Every usage line is the one its
/// help shows: in an error, clap otherwise lists the options that were
/// typed, such as a wrapper's `--api-url`, as if the command required them.
#[must_use]
pub fn command() -> clap::Command {
    let mut command = Cli::command();
    command.build();
    with_help_usage(command)
}

fn with_help_usage(mut command: clap::Command) -> clap::Command {
    let usage = command.render_usage().to_string();
    let usage = usage.strip_prefix("Usage: ").unwrap_or(&usage).to_owned();
    let subcommands = command
        .get_subcommands()
        .map(|subcommand| subcommand.get_name().to_owned())
        .collect::<Vec<_>>();
    command = command.override_usage(usage);
    for name in subcommands {
        command = command.mut_subcommand(name, with_help_usage);
    }
    command
}

/// Parse the process's arguments, or print the help, version, or usage
/// error clap asks for and exit.
#[must_use]
pub fn parse() -> Cli {
    let mut command = command();
    command
        .try_get_matches_from_mut(std::env::args_os())
        .and_then(|mut matches| Cli::from_arg_matches_mut(&mut matches))
        .unwrap_or_else(|error| error.format(&mut command).exit())
}

/// Write one line to standard error, for progress and notices. Unlike
/// `eprintln!` it never panics: when nobody reads standard error any more,
/// the line is lost, not the command.
fn notice(line: &str) {
    use std::io::Write as _;
    let _ = writeln!(std::io::stderr().lock(), "{line}");
}

/// Run one parsed command against the configured backend and return its JSON
/// result.
///
/// # Errors
///
/// Returns the command's failure: unreadable account key or input files, backend
/// rejections, transport errors, or invalid arguments.
pub async fn execute(cli: &Cli) -> Result<Value> {
    match &cli.command {
        Command::Key {
            command: KeyCommand::Import { from, replace },
        } => execute_key_import(cli, from.as_deref(), *replace).await,
        Command::Key { command } => execute_key(cli, command),
        Command::Catalog { command, offerings } => {
            let api = api_client(cli)?;
            match command {
                Some(command) => execute_catalog(&api, command).await,
                None => execute_catalog(&api, &CatalogCommand::Offerings(offerings.clone())).await,
            }
        }
        Command::Account { command } => {
            let api = api_client(cli)?;
            execute_account(cli, &api, command).await
        }
        Command::Provider { command } => {
            let api = api_client(cli)?;
            execute_provider(&api, command).await
        }
        Command::Instance { command } => {
            let api = api_client(cli)?;
            execute_instance(cli, &api, command, !cli.globals.compact).await
        }
        Command::Backup { command } => {
            let api = api_client(cli)?;
            execute_backup(cli, &api, command).await
        }
        Command::Job { command } => {
            let api = api_client(cli)?;
            execute_job(&api, command, !cli.globals.compact).await
        }
        Command::Support { command } => {
            let api = api_client(cli)?;
            execute_support(&api, command).await
        }
        #[cfg(unix)]
        Command::Ghostd { command } => ghostd::execute_ghostd(cli, command).await,
        #[cfg(unix)]
        Command::X(_) | Command::Mcp(_) => {
            bail!("this command writes its own output: run it with ghost::run_direct")
        }
    }
}

/// Lines to print on standard error once `output`, the result of `cli`'s
/// command, is printed, so they are the last thing shown. After `instance
/// create --wait`: what cloud-init reported of the new guest's first boot,
/// which it waits for, and the address of the instance, which its job does
/// not carry; nothing for `--compact`, and nothing when the instance cannot
/// be read. After the readable `instance console-log`: when the output was
/// sent, and whether older output precedes each part.
pub async fn closing_notes(cli: &Cli, output: &Value) -> Vec<String> {
    if cli.output_format() == OutputFormat::Readable && hint_keys(&cli.command, output).is_some() {
        return result_hint_notes(&cli.command);
    }
    let Command::Instance { command } = &cli.command else {
        return Vec::new();
    };
    match command {
        InstanceCommand::Create(args) => {
            let created = output["state"] == "succeeded" && output["kind"] == "create_instance";
            let Some(instance_id) = output["resource_id"]
                .as_str()
                .and_then(|id| Uuid::parse_str(id).ok())
                .filter(|_| args.mutation.wait && created && !cli.globals.compact)
            else {
                return Vec::new();
            };
            let Ok(api) = api_client(cli) else {
                return Vec::new();
            };
            let Ok(instance) = api.read(&GetInstance { instance_id }, "").await else {
                return Vec::new();
            };
            // A container instance runs no cloud-init, which would never
            // report.
            if instance.kind == InstanceKind::Container {
                return created_container_notes(
                    &instance,
                    args.spec.stock_image.is_some(),
                    Terminal::stderr().colors,
                );
            }
            let instance = await_guest_initialization(
                &api,
                instance,
                Duration::from_secs(args.mutation.poll_seconds),
                GUEST_INITIALIZATION_WAIT,
            )
            .await;
            let mut notes = created_instance_note(&instance, Terminal::stderr().colors);
            notes.extend(guest_initialization_notes(&instance));
            notes
        }
        InstanceCommand::Logs { previous, .. } if cli.output_format() == OutputFormat::Readable => {
            serde_json::from_value::<ContainerLogView>(output.clone())
                .map(|logs| vec![container_log_note(&logs, *previous)])
                .unwrap_or_default()
        }
        InstanceCommand::ConsoleLog { .. } if cli.output_format() == OutputFormat::Readable => {
            serde_json::from_value::<InstanceConsoleLogView>(output.clone())
                .map(|console| vec![console_log_note(&console)])
                .unwrap_or_default()
        }
        InstanceCommand::Get { .. } if cli.output_format() == OutputFormat::Readable => {
            serde_json::from_value::<InstanceView>(output.clone())
                .map(|instance| {
                    let mut notes = access_reset_notes(&instance);
                    notes.extend(rescue_notes(&instance));
                    notes
                })
                .unwrap_or_default()
        }
        InstanceCommand::Rescue(args) if !args.exit && !cli.globals.compact => {
            let started = output["state"] == "succeeded" && output["kind"] == "rescue_instance";
            let instance_id = output["resource_id"]
                .as_str()
                .and_then(|id| Uuid::parse_str(id).ok());
            match instance_id.filter(|_| args.mutation.wait && started) {
                Some(instance_id) => {
                    let Ok(api) = api_client(cli) else {
                        return Vec::new();
                    };
                    api.read(&GetInstance { instance_id }, "")
                        .await
                        .map(|instance| rescue_notes(&instance))
                        .unwrap_or_default()
                }
                None if args.mutation.wait => Vec::new(),
                None => {
                    let reference = match &args.instance_id {
                        InstanceReference::Id(id) => id.to_string(),
                        InstanceReference::Name(name) => name.clone(),
                    };
                    vec![format!(
                        "Once the rescue system started, `ghost instance get {reference}` shows its host key and how to log in."
                    )]
                }
            }
        }
        InstanceCommand::ResetAccess(args) if !cli.globals.compact => {
            let reference = match &args.instance_id {
                InstanceReference::Id(id) => id.to_string(),
                InstanceReference::Name(name) => name.clone(),
            };
            vec![format!(
                "The guest reports what the reset did once it has booted with it: ghost instance get {reference}"
            )]
        }
        _ => Vec::new(),
    }
}

/// How long `instance create --wait` waits, after the creation ended with
/// the guest's kernel started, for cloud-init in the guest to report how
/// it ended the first boot. Most images report within a minute; a renter's
/// own user data can take longer.
const GUEST_INITIALIZATION_WAIT: Duration = Duration::from_mins(5);

/// `instance` once cloud-init in its guest has reported, or as it is when
/// it has not within `wait`, reading it every `interval`. A failed read is
/// retried until then.
async fn await_guest_initialization(
    api: &ApiClient,
    mut instance: InstanceView,
    interval: Duration,
    wait: Duration,
) -> InstanceView {
    if instance.guest_initialization.is_some() {
        return instance;
    }
    notice(&format!(
        "Waiting up to {} minutes for cloud-init in the guest to finish. Ctrl-C stops waiting, not the instance.",
        wait.as_secs().div_ceil(60)
    ));
    let deadline = tokio::time::Instant::now() + wait;
    while tokio::time::Instant::now() < deadline {
        tokio::time::sleep(interval.min(deadline - tokio::time::Instant::now())).await;
        if let Ok(read) = api
            .read(
                &GetInstance {
                    instance_id: instance.instance_id,
                },
                "",
            )
            .await
        {
            instance = read;
            if instance.guest_initialization.is_some() {
                break;
            }
        }
    }
    instance
}

/// What cloud-init reported of the guest's boot, warned about unless it
/// was done without anything to report, or that it has not reported.
fn guest_initialization_notes(instance: &InstanceView) -> Vec<String> {
    let id = instance.instance_id;
    let Some(result) = &instance.guest_initialization else {
        return vec![
            "cloud-init in the guest has not reported yet.".to_owned(),
            format!("To see its result once it has: ghost instance get {id}"),
        ];
    };
    let heading = match result.status {
        GuestInitializationStatus::Done => {
            return vec!["cloud-init in the guest is done.".to_owned()];
        }
        GuestInitializationStatus::Degraded => {
            "warning: cloud-init in the guest finished degraded, with recoverable errors."
        }
        GuestInitializationStatus::Error => "warning: cloud-init in the guest reported errors.",
        GuestInitializationStatus::Unknown => {
            "cloud-init in the guest reported a result this release of ghost does not know."
        }
    };
    let mut notes = vec![heading.to_owned()];
    notes.extend(
        result
            .messages
            .iter()
            .map(|message| format!("  - {}", escape_control(message))),
    );
    notes.push("To see more:".to_owned());
    notes.push("  In the guest: cloud-init status --long".to_owned());
    notes.push(format!(
        "  On your machine: ghost instance console-log {id}"
    ));
    notes
}

/// Forgets what ghost kept of the rescue of `instance_id` once it ends: its
/// host key, and the address ghost's connections reach it at.
fn forget_rescue(instance_id: Uuid) {
    #[cfg(unix)]
    {
        ghostd::forget_rescue_host_key(instance_id);
        ghostd::forget_instance(instance_id);
    }
    #[cfg(not(unix))]
    let _ = instance_id;
}

/// What `ghost instance get` and `ghost instance rescue --wait` tell of the instance's rescue,
/// while it lasts: its host key, which ghost files for SSH to check, the command that logs in, and
/// how to end it.
fn rescue_notes(instance: &InstanceView) -> Vec<String> {
    let Some(rescue) = &instance.rescue else {
        return Vec::new();
    };
    #[cfg(not(unix))]
    let _ = rescue;
    #[cfg(unix)]
    let login = ghostd::remember_rescue_host_key(instance.instance_id, &rescue.host_key_public)
        .and_then(|known_hosts| ghostd::rescue_ssh_command(instance, &known_hosts));
    #[cfg(not(unix))]
    let login: Result<String> = Err(anyhow::anyhow!("ghost files host keys on Unix only"));
    rescue_notes_with(instance, login)
}

/// [`rescue_notes`] with `login`, the SSH command, or why there is none.
fn rescue_notes_with(instance: &InstanceView, login: Result<String>) -> Vec<String> {
    let Some(rescue) = &instance.rescue else {
        return Vec::new();
    };
    let id = instance.instance_id;
    let mut notes = vec![
        format!(
            "The instance is in rescue: it runs the rescue system {} with its disk as /dev/vda; `mount-guest` mounts it at /mnt.",
            escape_control(&rescue.rescue_release)
        ),
        format!(
            "Rescue system's host key: {}",
            escape_control(&rescue.host_key_fingerprint)
        ),
    ];
    match login {
        Ok(command) => notes.push(format!("Log in: {command}")),
        Err(error) => notes.push(format!("warning: no SSH command: {error:#}")),
    }
    notes.push(format!("End the rescue: ghost instance rescue {id} --exit"));
    notes
}

/// What the guest reported of the instance's latest SSH access reset
/// (`ghost instance get`): each part's outcome, a warning for one that
/// failed, or that the guest reported nothing or a report the backend could
/// not read, when that is so.
fn access_reset_notes(instance: &InstanceView) -> Vec<String> {
    let Some(reset) = &instance.access_reset else {
        return Vec::new();
    };
    let requested = reset.requested_at.format("%Y-%m-%d %H:%M UTC");
    match reset.state {
        AccessResetState::Pending => vec![format!(
            "The SSH access reset of {requested} has no report from the guest yet."
        )],
        AccessResetState::NotReached => vec![
            format!("warning: the guest reported nothing of the SSH access reset of {requested}."),
            "It has no cloud-init, has it turned off, or did not reach its userspace; a rescue boot is the other way in.".to_owned(),
        ],
        AccessResetState::Reported => {
            let steps = reset.steps.clone().unwrap_or_default();
            if steps.unreadable {
                return vec![format!(
                    "warning: the guest's report of the SSH access reset of {requested} could not be read."
                )];
            }
            let parts = [
                ("keys", &steps.keys),
                ("sshd", &steps.sshd),
                ("sshd -t", &steps.sshd_test),
                ("network", &steps.network),
                ("firewall", &steps.firewall),
            ];
            let failed = parts
                .iter()
                .any(|(_, outcome)| outcome.as_deref().is_some_and(|text| text.starts_with("failed")));
            let mut notes = vec![if failed {
                format!("warning: the SSH access reset of {requested} failed in part:")
            } else {
                format!("The SSH access reset of {requested} ran in the guest:")
            }];
            notes.extend(parts.iter().filter_map(|(name, outcome)| {
                outcome
                    .as_deref()
                    .map(|text| format!("  {name}: {}", escape_control(text)))
            }));
            notes
        }
        AccessResetState::Unknown => vec![format!(
            "The SSH access reset of {requested} is in a state this release of ghost does not know."
        )],
    }
}

/// When the console output shown was sent, and whether older output
/// precedes each part: the end from before the platform last started the
/// guest again, when there is one, and the output since.
fn console_log_note(console: &InstanceConsoleLogView) -> String {
    let Some(updated_at) = console.updated_at else {
        return format!(
            "the host of instance {} has sent none of its console output yet: it does within about ten seconds of the guest writing any, and a guest created before consoles were recorded has it from its next start",
            console.instance_id
        );
    };
    let sent = format!(
        "the end of instance {}'s console output as its host sent it at {}",
        console.instance_id,
        updated_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );
    let left_out = |truncated: bool| {
        if truncated {
            " (older output left out)"
        } else {
            ""
        }
    };
    match &console.previous_boot {
        Some(previous) => format!(
            "{sent}: above the line, the end of what it wrote before the platform last started it again{}; below, what it wrote since{}",
            left_out(previous.truncated),
            left_out(console.truncated)
        ),
        None if console.truncated => format!("{sent}; older output precedes it"),
        None => sent,
    }
}

/// Where a new container instance can be reached and how to read its
/// output, as `instance create --wait` ends: a stock image (`stock`, or as
/// its view names it) over SSH as a VM, a renter's image at its address
/// only, as it answers no SSH of the platform's.
fn created_container_notes(instance: &InstanceView, stock: bool, colors: bool) -> Vec<String> {
    let id = instance.instance_id;
    let stock = stock
        || instance
            .container
            .as_ref()
            .is_some_and(|container| container.stock_image.is_some());
    let mut notes = if stock {
        created_instance_note(instance, colors)
    } else {
        let named = format!(
            "Container instance {id} ({}) is {}.",
            escape_control(instance.display_name()),
            instance_state_words(instance.state)
        );
        let mut rows = Vec::new();
        if let Some(address) = &instance.public_ipv4 {
            rows.push(QuoteRow::Fact(
                "Address",
                escape_control(address).into_owned(),
            ));
            if !instance.port_forwards.is_empty() {
                rows.push(QuoteRow::Fact(
                    "Ports",
                    format!("ghost instance ports {id}"),
                ));
            }
        }
        let mut lines = vec![named];
        if instance.public_ipv4.is_none() {
            lines.push("It has no public IPv4 address yet.".to_owned());
        }
        lines.extend(quote_block(&rows, colors));
        lines
    };
    notes.push(format!(
        "To read what its container writes: ghost instance logs {id}"
    ));
    notes
}

/// The heading above the end of what a container wrote before its last
/// start, in `instance logs`.
const CONTAINER_PREVIOUS_HEADING: &str = "--- before the container's last start ---";
/// The heading above what it wrote since, when the end from before is
/// shown.
const CONTAINER_SINCE_HEADING: &str = "--- since its last start ---";

/// A container's logs for reading, without the escape sequences that color
/// a terminal: the end of what it wrote before its last start under a
/// heading, when there is one, then what it wrote since under another;
/// `previous_only`, the end from before alone.
fn readable_container_log(logs: &ContainerLogView, previous_only: bool) -> String {
    let readable = |text: &str| {
        readable_console_output(text)
            .trim_end_matches('\n')
            .to_owned()
    };
    if previous_only {
        return logs
            .previous
            .as_ref()
            .map(|previous| readable(&previous.tail))
            .unwrap_or_default();
    }
    match &logs.previous {
        Some(previous) => format!(
            "{CONTAINER_PREVIOUS_HEADING}\n{}\n{CONTAINER_SINCE_HEADING}\n{}",
            readable(&previous.tail),
            readable(&logs.tail)
        ),
        None => readable(&logs.tail),
    }
}

/// When the container's output shown was sent, and whether older output
/// precedes each part.
fn container_log_note(logs: &ContainerLogView, previous_only: bool) -> String {
    let Some(reported_at) = logs.reported_at else {
        return "the container's host has sent none of its output yet".to_owned();
    };
    let sent = format!(
        "the end of the container's output as its host sent it at {}",
        reported_at.format("%Y-%m-%d %H:%M:%S UTC"),
    );
    let left_out = |truncated: bool| {
        if truncated {
            " (older output left out)"
        } else {
            ""
        }
    };
    match (&logs.previous, previous_only) {
        (None, true) => {
            "the container's host has sent none of what it wrote before its last start".to_owned()
        }
        (Some(previous), true) => format!(
            "{sent}: what it wrote before its last start{}",
            left_out(previous.truncated)
        ),
        (Some(previous), false) => format!(
            "{sent}: under the first heading, what it wrote before its last start{}; under the second, what it wrote since{}",
            left_out(previous.truncated),
            left_out(logs.truncated)
        ),
        (None, false) if logs.truncated => format!("{sent}; older output precedes it"),
        (None, false) => sent,
    }
}

/// Where a new instance can be reached, as `instance create --wait` ends.
fn created_instance_note(instance: &InstanceView, colors: bool) -> Vec<String> {
    let id = instance.instance_id;
    let named = format!(
        "Instance {id} ({}) is {}.",
        escape_control(instance.display_name()),
        instance_state_words(instance.state)
    );
    let ssh = instance
        .port_forwards
        .iter()
        .find(|forward| forward.guest_port == 22);
    let Some(address) = &instance.public_ipv4 else {
        return vec![named, "It has no public IPv4 address yet.".to_owned()];
    };
    let address = escape_control(address).into_owned();
    let mut rows = vec![QuoteRow::Fact("Address", address.clone())];
    if let Some(ssh) = ssh {
        rows.push(QuoteRow::Fact(
            "SSH",
            format!("ssh -p {} root@{address}", ssh.public_port),
        ));
        rows.push(QuoteRow::Fact(
            "Ports",
            format!("ghost instance ports {id}"),
        ));
    }
    let mut lines = vec![named];
    lines.extend(quote_block(&rows, colors));
    lines
}

/// Format a command result for `terminal`: for reading, or as JSON.
/// `serde_json` escapes C0 controls inside strings but passes DEL and the C1
/// range through, and C1 holds the 8-bit CSI and OSC introducers, so those
/// are written as `\u00XX` escapes too. They can only occur inside strings,
/// so the JSON stays valid and decodes to the same value.
#[must_use]
pub fn render_output(output: &Value, format: OutputFormat, terminal: Terminal) -> String {
    let text = match format {
        OutputFormat::Readable => return pretty::render(output, terminal),
        OutputFormat::Json => format!("{output:#}"),
        OutputFormat::CompactJson => output.to_string(),
    };
    if !text.chars().any(is_raw_json_control) {
        return text;
    }
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        if is_raw_json_control(character) {
            let _ = write!(escaped, "\\u{:04x}", u32::from(character));
        } else {
            escaped.push(character);
        }
    }
    escaped
}

const fn is_raw_json_control(character: char) -> bool {
    matches!(character, '\u{7f}'..='\u{9f}')
}

/// Format the result of `cli`'s command for `terminal` in the form it
/// asked for, as [`render_output`] does, except that a list shown for
/// reading is a [`Summary`]: one row per item, a table when it fits.
#[must_use]
pub fn render_result(cli: &Cli, output: &Value, terminal: Terminal) -> String {
    // `set-password --print` writes the password alone, in any format, for
    // a password manager to read.
    if let Command::Account {
        command: AccountCommand::SetPassword { print: true, .. },
    } = &cli.command
        && let Some(password) = output["password"].as_str()
    {
        return password.to_owned();
    }
    let format = cli.output_format();
    // A console's output is shown as the lines the guest wrote.
    if format == OutputFormat::Readable
        && let Command::Instance {
            command: InstanceCommand::ConsoleLog { .. },
        } = &cli.command
        && let Ok(console) = serde_json::from_value::<InstanceConsoleLogView>(output.clone())
    {
        return readable_console_log(&console);
    }
    // A container's logs are shown as the lines it wrote.
    if format == OutputFormat::Readable
        && let Command::Instance {
            command: InstanceCommand::Logs { previous, .. },
        } = &cli.command
        && let Ok(logs) = serde_json::from_value::<ContainerLogView>(output.clone())
    {
        return readable_container_log(&logs, *previous);
    }
    // A website request that is only shown reads as what approving does and
    // the command that approves it; the quote above went to standard error.
    if format == OutputFormat::Readable
        && let Command::Account {
            command: AccountCommand::Approve { .. },
        } = &cli.command
        && let (Some(notice), Some(command)) = (
            output["notice"].as_str(),
            output["approve_command"].as_str(),
        )
    {
        return format!(
            "{}\n{}  {}",
            escape_control(notice),
            pretty::paint_bold("To approve:", terminal.colors),
            escape_control(command)
        );
    }
    if format == OutputFormat::Readable
        && let Some(text) = readable_sections(&cli.command, output, terminal)
    {
        return text;
    }
    if format == OutputFormat::Readable
        && let Some(summary) = Summary::of(&cli.command, output)
    {
        let mut text = pretty::render_rows(
            &summary.columns,
            &summary.rows,
            summary.next_cursor.as_deref(),
            terminal,
        );
        if let Some(note) = summary.note {
            let _ = write!(text, "\n\n  {note}");
        }
        return text;
    }
    render_output(output, format, terminal)
}

/// A list command's result as it is shown for reading: for each item, the
/// columns that tell the items apart and say what they are, and the cursor
/// of the next page. An item's `get` command, or `--json`, shows all of it.
struct Summary {
    columns: Vec<&'static str>,
    rows: Vec<Value>,
    next_cursor: Option<String>,
    /// A line after the rows, such as what they leave out.
    note: Option<String>,
}

impl Summary {
    /// The summary of `command`'s result `output`, or `None` for a command
    /// that is not a list, or a result not in the shape it knows.
    fn of(command: &Command, output: &Value) -> Option<Self> {
        fn parsed<T: DeserializeOwned>(output: &Value) -> Option<T> {
            serde_json::from_value(output.clone()).ok()
        }
        match command {
            Command::Instance {
                command: InstanceCommand::List { .. },
            } => parsed(output).map(Self::instances),
            Command::Instance {
                command: InstanceCommand::Tags,
            } => parsed(output).map(Self::tags),
            Command::Backup {
                command: BackupCommand::List { .. },
            } => parsed(output).map(Self::backups),
            Command::Backup {
                command: BackupCommand::Schedule { .. },
            } => parsed(output).map(Self::backup_schedule),
            Command::Account {
                command: AccountCommand::History(_),
            } => parsed(output).map(Self::history),
            Command::Job {
                command: JobCommand::List { .. },
            } => parsed(output).map(Self::jobs),
            Command::Catalog {
                command: None,
                offerings: filters,
            }
            | Command::Catalog {
                command: Some(CatalogCommand::Offerings(filters)),
                ..
            } => parsed(output).map(|offerings| Self::offerings(offerings, filters.ip())),
            Command::Catalog {
                command: Some(CatalogCommand::Locations(_)),
                ..
            } => parsed(output).map(Self::locations),
            Command::Catalog {
                command: Some(CatalogCommand::ContainerImages),
                ..
            } => parsed(output).map(Self::container_images),
            Command::Provider {
                command: ProviderCommand::Hosts { retired },
            } => parsed(output).map(|hosts| Self::provider_hosts(hosts, *retired, Utc::now())),
            Command::Instance {
                command: InstanceCommand::Upgrades { .. },
            } => parsed(output).map(Self::upgrades),
            _ => None,
        }
    }

    /// Instances with the job running on one, such as a backup, when one
    /// has any: it takes no other job meanwhile. A container instance is
    /// marked by its kind, when there is one, and shows its image: a stock
    /// image's slug, or the reference of the renter's image.
    fn instances(instances: Vec<InstanceView>) -> Self {
        let mut columns = vec!["instance_id", "name"];
        if instances.iter().any(|instance| !instance.tags.is_empty()) {
            columns.push("tags");
        }
        columns.push("state");
        // A hold, when one is present.
        if instances.iter().any(|instance| instance.hold.is_some()) {
            columns.push("hold");
        }
        if instances
            .iter()
            .any(|instance| instance.active_job.is_some())
        {
            columns.push("job");
        }
        if instances
            .iter()
            .any(|instance| instance.kind != InstanceKind::Vm)
        {
            columns.push("kind");
        }
        columns.extend(["public_ipv4", "location", "image", "size"]);
        Self {
            columns,
            rows: instances
                .into_iter()
                .map(|instance| {
                    json!({
                        "instance_id": instance.instance_id,
                        "name": instance.display_name(),
                        "tags": instance.tags.join(", "),
                        // In rescue it shows as such.
                        "state": if instance.rescue.is_some()
                            && matches!(instance.state, InstanceState::Running | InstanceState::Stopped)
                        {
                            json!("rescue")
                        } else {
                            json!(instance.state)
                        },
                        "hold": instance.hold.as_ref().map(|_| "held by the operator"),
                        "job": instance.active_job.map(|job| format!(
                            "{} {}",
                            job_kind_words(job.kind),
                            percent_text(job.progress_permyriad)
                        )),
                        "kind": instance.kind,
                        "public_ipv4": instance.public_ipv4,
                        "location": instance.location,
                        "image": match (instance.image, instance.container) {
                            (Some(image), _) => Some(image.slug),
                            (None, Some(container)) if container.image_unknown => {
                                Some("unknown".to_owned())
                            }
                            (None, Some(container)) => {
                                Some(container.stock_image.unwrap_or(container.image))
                            }
                            (None, None) => None,
                        },
                        "size": size_text(
                            instance.vcpu_count,
                            instance.memory_bytes,
                            instance.root_disk_bytes,
                        ),
                    })
                })
                .collect(),
            next_cursor: None,
            note: None,
        }
    }

    /// The account's tags with how many instances carry each, and which
    /// are redundant.
    fn tags(tags: Vec<InstanceTagView>) -> Self {
        Self {
            columns: vec!["tag", "instance_count", "redundant"],
            rows: tags
                .into_iter()
                .map(|tag| {
                    json!({
                        "tag": tag.tag,
                        "instance_count": tag.instance_count,
                        "redundant": if tag.redundant { "yes" } else { "no" },
                    })
                })
                .collect(),
            next_cursor: None,
            note: None,
        }
    }

    /// An instance's backup schedule: a row per rule, and what removed
    /// rules left.
    fn backup_schedule(schedule: BackupScheduleView) -> Self {
        const DAYS: [&str; 7] = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"];
        let frequency = schedule_frequency_word;
        let destination = schedule_destination_word;
        let deleting = schedule
            .rules
            .iter()
            .filter(|rule| rule.completed_count > rule.keep)
            .map(|rule| {
                format!(
                    "the {} {} rule is deleting its {} oldest backup(s) beyond its keep of {}",
                    frequency(rule.frequency),
                    destination(rule.destination),
                    rule.completed_count - rule.keep,
                    rule.keep
                )
            });
        let left: Vec<String> = schedule
            .removed
            .iter()
            .filter(|removed| removed.backups_kept > 0)
            .map(|removed| {
                format!(
                    "a removed {} {} rule left {} backup(s), which the schedule never deletes",
                    frequency(removed.frequency),
                    destination(removed.destination),
                    removed.backups_kept
                )
            })
            .chain(deleting)
            .collect();
        Self {
            columns: vec![
                "rule_id",
                "when_utc",
                "destination",
                "keep",
                "backups",
                "next_run_at",
                "last_result",
            ],
            rows: schedule
                .rules
                .into_iter()
                .map(|rule| {
                    let at = format!(
                        "{:02}:{:02}",
                        rule.minute_of_day / 60,
                        rule.minute_of_day % 60
                    );
                    let when = match (rule.weekday, rule.day_of_month) {
                        (Some(day), _) => format!(
                            "weekly {} {at}",
                            DAYS.get(usize::from(day)).copied().unwrap_or("?")
                        ),
                        (None, Some(day)) => format!("monthly day {day} {at}"),
                        (None, None) => format!("{} {at}", frequency(rule.frequency)),
                    };
                    json!({
                        "rule_id": rule.rule_id,
                        "when_utc": when,
                        "destination": destination(rule.destination),
                        "keep": rule.keep,
                        "backups": rule.backup_count,
                        "next_run_at": rule.next_run_at,
                        "last_result": match (rule.last_result, rule.last_message) {
                            (Some(result), Some(message)) => json!(format!(
                                "{}: {message}",
                                serde_json::to_value(result)
                                    .ok()
                                    .and_then(|name| name.as_str().map(str::to_owned))
                                    .unwrap_or_default()
                            )),
                            (Some(result), None) => json!(result),
                            (None, _) => Value::Null,
                        },
                    })
                })
                .collect(),
            next_cursor: None,
            note: (!left.is_empty()).then(|| format!("{}.", left.join("; "))),
        }
    }

    /// Backups without their prices and keys: `name` is what their instance
    /// is called now, or, from a backend that does not send it, its
    /// hostname when the backup was taken or, for a backup that did not
    /// record it, now. A final recovery
    /// backup, made before a VM was deleted for an empty balance, is marked
    /// by its purpose. A container instance's backup is marked by its kind,
    /// when there is one, and shows the image it ran: a stock image's slug,
    /// or the reference of the renter's image.
    fn backups(backups: Vec<BackupView>) -> Self {
        use gigahost_client_api::website::{BackupPurpose, BackupState};
        // An available backup in a backup pool its host is missing is
        // unavailable, and says why.
        let unavailable = |backup: &BackupView| {
            (backup.status == BackupState::Available)
                .then(|| {
                    backup
                        .unavailable
                        .as_ref()
                        .map(|reason| reason.reason.clone())
                })
                .flatten()
        };
        let mut columns = vec!["backup_id", "name", "status"];
        if backups
            .iter()
            .any(|backup| backup.purpose != BackupPurpose::Regular)
        {
            columns.push("purpose");
        }
        if backups.iter().any(|backup| backup.kind != InstanceKind::Vm) {
            columns.push("kind");
        }
        columns.extend([
            "destination",
            "image",
            "size_bytes",
            "per_month_microusd",
            "created_at",
        ]);
        if backups.iter().any(|backup| unavailable(backup).is_some()) {
            columns.push("unavailable");
        }
        // The schedule's rule that made a backup.
        if backups.iter().any(|backup| backup.schedule.is_some()) {
            columns.push("schedule");
        }
        Self {
            columns,
            rows: backups
                .into_iter()
                .map(|backup| {
                    let reason = unavailable(&backup);
                    json!({
                        "backup_id": backup.backup_id,
                        "name": backup
                            .instance_name
                            .or(backup.hostname)
                            .or(backup.instance_hostname),
                        "status": if reason.is_some() {
                            json!("unavailable")
                        } else {
                            json!(backup.status)
                        },
                        "unavailable": reason,
                        "schedule": backup.schedule.as_ref().map(|origin| {
                            let frequency = serde_json::to_value(origin.frequency)
                                .ok()
                                .and_then(|name| name.as_str().map(str::to_owned))
                                .unwrap_or_default();
                            if origin.removed {
                                format!("{frequency} (removed)")
                            } else {
                                frequency
                            }
                        }),
                        "purpose": backup.purpose,
                        "kind": backup.kind,
                        "destination": backup.destination,
                        "image": match (backup.image_slug, backup.container) {
                            (Some(image), _) => Some(image),
                            (None, Some(container)) => {
                                Some(container.stock_image.unwrap_or(container.image))
                            }
                            (None, None) => None,
                        },
                        "size_bytes": backup.size_bytes,
                        // What its storage costs a month; from an older
                        // backend, worked out as the backend charges it.
                        // None for a deleted or lost backup, which costs
                        // nothing more, as the website shows it.
                        "per_month_microusd": if matches!(
                            backup.status,
                            BackupState::Deleted | BackupState::Lost
                        ) {
                            None
                        } else {
                            backup.storage_cost_microusd_per_month.or_else(|| {
                                backup.size_bytes.map(|size| {
                                    gigahost_client_api::website::backup_byte_charge(
                                        size,
                                        backup.storage_charge_microusd_per_gib_month,
                                    )
                                    .map_or(0, |(_, charge)| charge)
                                })
                            })
                        },
                        "created_at": backup.created_at,
                    })
                })
                .collect(),
            next_cursor: None,
            note: None,
        }
    }

    /// Ledger entries by the part of the balance they move: what is
    /// available, what instances hold, or credit at a provider. A hold
    /// moves an amount from the first to the second, and its release back.
    fn history(page: gigahost_client_api::website::HistoryPage) -> Self {
        Self {
            columns: vec![
                "posted_at",
                "kind",
                "account",
                "amount_microusd",
                "instance_id",
            ],
            rows: page
                .items
                .iter()
                .map(|entry| {
                    let account = match entry["account_kind"].as_str() {
                        Some("user_balance") => json!("available"),
                        Some("user_reserve") => json!("reserved"),
                        Some("user_provider_credit") => json!("credit"),
                        Some("user_trial_credit") => json!("trial"),
                        _ => entry["account_kind"].clone(),
                    };
                    json!({
                        "posted_at": entry["posted_at"],
                        "kind": entry["kind"],
                        "account": account,
                        "amount_microusd": entry["amount_microusd"],
                        "instance_id": entry["instance_id"],
                    })
                })
                .collect(),
            next_cursor: page.next_cursor,
            note: None,
        }
    }

    /// Jobs with the error code of those that failed, when any did.
    fn jobs(page: JobPage) -> Self {
        let mut columns = vec!["job_id", "kind", "state", "progress_permyriad"];
        if page.items.iter().any(|job| job.error_code.is_some()) {
            columns.push("error_code");
        }
        columns.push("created_at");
        Self {
            columns,
            rows: page
                .items
                .iter()
                .map(|job| {
                    json!({
                        "job_id": job.job_id,
                        "kind": job.kind,
                        "state": job.state,
                        "progress_permyriad": job.progress_permyriad,
                        "error_code": job.error_code,
                        "created_at": job.created_at,
                    })
                })
                .collect(),
            next_cursor: page.next_cursor,
            note: None,
        }
    }

    /// Offerings by where they are, their CPU, memory and disk, what they
    /// cost with the default gateway, and how many hosts have room for
    /// them, short enough for a table on a wide terminal; `ghost catalog
    /// offering` shows the hardware and network tests of one, and every
    /// gateway option's prices.
    fn offerings(offerings: Vec<OfferingView>, ip: IpChoice) -> Self {
        // The bandwidth column where the backend sends limits.
        let limited = offerings
            .iter()
            .any(|offering| offering.bandwidth_for(ip).is_some());
        // The private column where the account sees a private host's offering, which only its
        // provider and the accounts it allows see.
        let private = offerings.iter().any(|offering| offering.private);
        Self {
            columns: vec![
                "offering_id",
                "private",
                "provider",
                "location",
                "host_mode",
                "kinds",
                "cpu",
                "ram",
                "disk",
                "price_per_month",
                "network",
                "bandwidth",
                "available",
                "hosts",
            ]
            .into_iter()
            .filter(|column| {
                (limited || *column != "bandwidth") && (private || *column != "private")
            })
            .collect(),
            rows: offerings
                .into_iter()
                .map(|offering| {
                    let memory = pretty::binary_size(offering.memory_bytes);
                    json!({
                        "offering_id": offering.offering_id,
                        "private": offering.private.then_some("private"),
                        "provider": Some(&offering.provider_alias)
                            .filter(|alias| !alias.is_empty()),
                        "location": offering.location,
                        "host_mode": offering.host_mode,
                        "kinds": kinds_text(&offering),
                        "cpu": format!(
                            "{} {}",
                            gigahost_client_api::hypervisor::size_cpu_text(offering.vcpu_count),
                            short_cpu_model(&offering.cpu_model)
                        ),
                        "ram": match memory_technology(&offering) {
                            Some(technology) => format!("{memory} {technology}"),
                            None => memory,
                        },
                        "disk": disk_text(&offering),
                        // As the website lists it: the base price alone (a
                        // home offering's with its default gateway's), as
                        // the price at full CPU still leaves out traffic.
                        // With `--ip shared` it is the shared IP's.
                        "price_per_month": offering.price_for(ip).map(pretty::dollars),
                        // As the website lists it: a home offering's
                        // through its default gateway, with no "from".
                        "network": offering
                            .traffic_for(ip)
                            .map(|traffic| format!("{}/TiB", pretty::dollars(traffic))),
                        // The limit with that address, as the website shows
                        // it beside the traffic price.
                        "bandwidth": offering.bandwidth_for(ip).map(bandwidth_text),
                        // An older backend sends no count: a dash, not 0.
                        "available": if offering.available_instances == 0
                            && offering.available_hosts > 0
                        {
                            json!("—")
                        } else {
                            json!(offering.available_instances)
                        },
                        "hosts": offering.available_hosts,
                    })
                })
                .collect(),
            next_cursor: None,
            note: None,
        }
    }

    /// The sizes an instance may be upgraded to, as the catalog lists
    /// offerings: the size by its vCPUs alone (a CPU tier is no part of a
    /// size), RAM and disk, the monthly price and the price at full CPU,
    /// what the balance must hold more, and whether the host has room now.
    fn upgrades(upgrades: Vec<InstanceUpgradeView>) -> Self {
        Self {
            columns: vec![
                "offering_id",
                "cpu",
                "ram",
                "disk",
                "base_per_month",
                "full_cpu_per_month",
                "extra_hold",
                "available",
            ],
            rows: upgrades
                .into_iter()
                .map(|upgrade| {
                    json!({
                        "offering_id": upgrade.offering_id,
                        "cpu": gigahost_client_api::hypervisor::size_cpu_text(upgrade.vcpu_count),
                        "ram": pretty::binary_size(upgrade.memory_bytes),
                        "disk": pretty::binary_size(upgrade.root_disk_bytes),
                        "base_per_month": pretty::dollars(upgrade.base_price_microusd_per_month),
                        "full_cpu_per_month": pretty::dollars(
                            upgrade.full_utilization_price_microusd_per_month
                        ),
                        "extra_hold": pretty::dollars(upgrade.balance_reservation_increase_microusd),
                        "available": upgrade.available,
                    })
                })
                .collect(),
            next_cursor: None,
            note: None,
        }
    }

    /// A provider's hosts as the website's hosts table shows them: whether
    /// each takes new rentals, when its agent was last heard from, what it
    /// is and holds, and what it earns. Retired hosts come last, and only
    /// when `retired` asks for them.
    fn provider_hosts(hosts: Vec<ProviderHostView>, retired: bool, now: DateTime<Utc>) -> Self {
        let (mut current, old): (Vec<_>, Vec<_>) = hosts
            .into_iter()
            .partition(|host| host_admission(host) != "retired");
        let hidden = old.len();
        if retired {
            current.extend(old);
        }
        let rows = current
            .iter()
            .map(|host| {
                let values = host
                    .pricing
                    .as_ref()
                    .map(|pricing| &pricing.values)
                    .filter(|_| host_admission(host) != "retired");
                json!({
                    "host_id": host.host_id,
                    "label": host.label,
                    "state": host_admission(host),
                    "seen": host.last_heartbeat_at.map(|at| {
                        let seconds = (now - at).num_seconds().max(0).cast_unsigned();
                        format!("{} ago", pretty::duration(seconds))
                    }),
                    // A private host says so after its kind.
                    "type": format!(
                        "{}{}",
                        match host.mode {
                            HostMode::HomeGateway => "home",
                            HostMode::CloudRouted => "cloud",
                            HostMode::Unknown => "unknown",
                        },
                        if host.private { ", private" } else { "" }
                    ),
                    "location": host.location,
                    "vms": host.active_instance_count,
                    "cpu": host.cpu_model.as_deref().map(short_cpu_model),
                    "ram": installed_memory(host),
                    "disk": installed_storage(host),
                    "sla": values.map(|values| sla_text(values.sla_target_basis_points)),
                    "traffic_per_tib": values
                        .map(|values| values.network_earnings_microusd_per_tib)
                        .filter(|&earnings| earnings > 0)
                        .map(pretty::dollars),
                    "host_per_month": values
                        .map(|values| pretty::dollars(values.base_host_earnings_microusd_per_month)),
                })
            })
            .collect();
        Self {
            columns: vec![
                "host_id",
                "label",
                "state",
                "seen",
                "type",
                "location",
                "vms",
                "cpu",
                "ram",
                "disk",
                "sla",
                "traffic_per_tib",
                "host_per_month",
            ],
            rows,
            next_cursor: None,
            note: (!retired && hidden > 0).then(|| {
                format!(
                    "{hidden} retired host{} not listed; --retired lists {}",
                    if hidden == 1 { "" } else { "s" },
                    if hidden == 1 { "it" } else { "them" },
                )
            }),
        }
    }

    fn locations(locations: Vec<LocationView>) -> Self {
        Self {
            columns: vec!["location", "display_name", "country_code", "continent_code"],
            rows: locations
                .into_iter()
                .map(|location| {
                    json!({
                        "location": location.location,
                        "display_name": location.display_name,
                        "country_code": location.country_code,
                        "continent_code": location.continent_code,
                    })
                })
                .collect(),
            next_cursor: None,
            note: None,
        }
    }

    /// The stock images: the slug `--stock-image` takes, the least memory
    /// an offering needs for it, and the x86-64 level its host's CPU must
    /// have.
    fn container_images(images: Vec<ContainerImageView>) -> Self {
        Self {
            columns: vec![
                "slug",
                "display_name",
                "init_system",
                "minimum_memory",
                "cpu_level",
            ],
            rows: images
                .into_iter()
                .map(|image| {
                    json!({
                        "slug": image.slug,
                        "display_name": image.display_name,
                        "init_system": image.init_system,
                        "minimum_memory": pretty::binary_size(image.minimum_memory_bytes),
                        "cpu_level": format!("x86-64-v{}", image.x86_64_level),
                    })
                })
                .collect(),
            next_cursor: None,
            note: None,
        }
    }
}

/// What an offering can be rented as, as the offerings list shows it: the
/// kind it is offered as by default first, then the other, such as
/// `container, vm`. An offering of an older backend, which names no kinds,
/// is a VM's.
fn kinds_text(offering: &OfferingView) -> String {
    let mut kinds: Vec<InstanceKind> = if offering.kinds.is_empty() {
        vec![InstanceKind::Vm]
    } else {
        offering.kinds.clone()
    };
    if let Some(default) = offering.default_kind
        && let Some(position) = kinds.iter().position(|kind| *kind == default)
    {
        let default = kinds.remove(position);
        kinds.insert(0, default);
    }
    kinds
        .into_iter()
        .map(wire_name)
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

/// A size as an instance list shows it: "2 vCPU, 4 GiB RAM, 48 GiB disk",
/// its vCPUs alone, never the cores they share or their sharing tier.
fn size_text(vcpu_count: u32, memory_bytes: u64, root_disk_bytes: u64) -> String {
    format!(
        "{}, {} RAM, {} disk",
        gigahost_client_api::hypervisor::size_cpu_text(vcpu_count),
        pretty::binary_size(memory_bytes),
        pretty::binary_size(root_disk_bytes)
    )
}

/// What of accounts a provider does not allow stays on its private hosts,
/// in words ("2 instances and 1 local backup"); None for nothing.
fn kept_words(instances: u32, local_backups: u32) -> Option<String> {
    let count = |n: u32, one: &str, many: &str| {
        if n == 1 {
            format!("1 {one}")
        } else {
            format!("{n} {many}")
        }
    };
    match (instances, local_backups) {
        (0, 0) => None,
        (instances, 0) => Some(count(instances, "instance", "instances")),
        (0, backups) => Some(count(backups, "local backup", "local backups")),
        (instances, backups) => Some(format!(
            "{} and {}",
            count(instances, "instance", "instances"),
            count(backups, "local backup", "local backups")
        )),
    }
}

/// Whether a host takes new rentals, as the website's hosts table says it:
/// retired, enrolling, retiring (under a notice, or draining), offline,
/// degraded, checking (a cloud host whose public path is being checked),
/// unverified (one no check has verified yet), paused, or accepting. The
/// path comes before the pause: a new host starts paused, and a cloud host
/// cannot resume until its path is verified.
fn host_admission(host: &ProviderHostView) -> &str {
    let retiring = host.retirement_notice.as_ref().is_some_and(|notice| {
        notice.state != gigahost_client_api::website::HostRetirementState::Completed
    });
    let unverified = host.mode == HostMode::CloudRouted && host.public_path_verified_at.is_none();
    match host.status.as_str() {
        "retired" => "retired",
        _ if host.retired_at.is_some() => "retired",
        "enrolling" => "enrolling",
        "draining" => "retiring",
        _ if retiring => "retiring",
        "offline" => "offline",
        "degraded" => "degraded",
        "active" if unverified && host.public_path_checking => "checking",
        "active" if unverified => "unverified",
        "active" if host.rentals_paused => "paused",
        "active" => "accepting",
        other => other,
    }
}

/// The memory a host has installed, its modules summed, in whole GiB;
/// without modules listed, its NUMA nodes' memory; none before its first
/// inventory.
fn installed_memory(host: &ProviderHostView) -> Option<String> {
    const GIB: u64 = 1 << 30;
    if host.installed_memory_bytes > 0 {
        Some(format!(
            "{} GiB",
            host.installed_memory_bytes.saturating_add(GIB / 2) / GIB
        ))
    } else {
        (host.memory_bytes > 0).then(|| pretty::binary_size(host.memory_bytes))
    }
}

/// The storage a host has installed, the disks below its pools; without
/// disks named, its pools' capacity; none before its first inventory.
fn installed_storage(host: &ProviderHostView) -> Option<String> {
    [host.installed_storage_bytes, host.storage_bytes]
        .into_iter()
        .find(|&bytes| bytes > 0)
        .map(pretty::binary_size)
}

/// An SLA target in basis points as the tiers are named: "99.0%",
/// "99.9%", "99.99%", to the hundredth of a percent and with one decimal
/// at least.
fn sla_text(basis_points: u32) -> String {
    let whole = basis_points / 100;
    match basis_points % 100 {
        part if part % 10 == 0 => format!("{whole}.{}%", part / 10),
        part => format!("{whole}.{part:02}%"),
    }
}

/// A CPU model as a list names it, without the trademarks, the clock and
/// the words that say it is a processor: "Intel(R) Xeon(R) CPU E5-2683 v4
/// @ 2.10GHz" is "Intel Xeon E5-2683 v4", and "AMD Ryzen 9 5950X 16-Core
/// Processor" is "AMD Ryzen 9 5950X". `ghost catalog offering` has all of it.
fn short_cpu_model(model: &str) -> String {
    let model = model.split(" @ ").next().unwrap_or(model);
    let words: Vec<String> = model
        .split_whitespace()
        .map(|word| {
            ["(R)", "(r)", "(TM)", "(tm)"]
                .iter()
                .fold(word.to_owned(), |word, mark| word.replace(mark, ""))
        })
        .filter(|word| {
            !word.is_empty()
                && !matches!(word.as_str(), "CPU" | "Processor")
                && !word.ends_with("-Core")
        })
        .collect();
    if words.is_empty() {
        model.trim().to_owned()
    } else {
        words.join(" ")
    }
}

/// The root disk's size as a list writes it, the kinds of drive and the
/// RAID after it: "100 GiB `NVMe` raid 1". A hardware RAID hides its drives,
/// so only its level follows.
fn disk_text(offering: &OfferingView) -> String {
    let hardware =
        offering.software_raid_levels.is_empty() && !offering.hardware_raid_levels.is_empty();
    let mut parts = vec![pretty::binary_size(offering.root_disk_bytes)];
    if !hardware {
        parts.extend(gigahost_client_api::hypervisor::drive_kinds(
            &offering.storage_devices,
        ));
    }
    parts.extend(raid_text(offering));
    parts.join(" ")
}

/// The RAID below an offering's root storage as a list names it: its
/// software RAID levels, or without any its hardware RAID arrays' levels,
/// "raid 1" for `raid1`, and "raid" for an array whose controller does not
/// tell its level; `None` for a bare disk. Nested layers are listed
/// outermost first, as the host reports them.
fn raid_text(offering: &OfferingView) -> Option<String> {
    let levels = if offering.software_raid_levels.is_empty() {
        &offering.hardware_raid_levels
    } else {
        &offering.software_raid_levels
    };
    let levels: Vec<String> = levels
        .iter()
        .map(|level| match level.strip_prefix("raid") {
            Some(number) if !number.is_empty() => format!("raid {number}"),
            _ => level.clone(),
        })
        .collect();
    (!levels.is_empty()).then(|| escape_control(&levels.join(", ")).into_owned())
}

/// The memory technologies of an offering's hosts, such as "DDR4", or
/// "DDR4/DDR5" for hosts of both, or `None` where no host tells it.
fn memory_technology(offering: &OfferingView) -> Option<String> {
    let profiles = offering.memory_summary();
    let mut technologies: Vec<&str> = profiles
        .iter()
        .flat_map(|profile| &profile.modules)
        .map(|modules| modules.technology.trim())
        .filter(|technology| !technology.is_empty() && *technology != "Unknown")
        .collect();
    technologies.sort_unstable();
    technologies.dedup();
    (!technologies.is_empty()).then(|| escape_control(&technologies.join("/")).into_owned())
}

/// One way an instance of an offering reaches the internet, and what it
/// pays for it: a cloud offering's provider, or a home offering's gateway
/// of a tier, for a shared one at one of its `gateway_locations`.
struct NetworkOption<'a> {
    tier: Option<GatewayTier>,
    location: Option<&'a gigahost_client_api::website::GatewayLocationView>,
    base_microusd_per_month: u64,
    traffic_microusd_per_tib: u64,
    /// The bandwidth limit of the option, by its tier; none from a backend
    /// of before.
    bandwidth: Option<gigahost_client_api::website::BandwidthView>,
}

/// Every network option of `offering`. The catalog prices a shared gateway
/// at its preselected location among `network_prices`, and lists every
/// location a renter may choose with the gateway's own prices; a location's
/// traffic rate adds the provider's, which is the preselected shared price
/// without that location's gateway rate.
fn network_options(offering: &OfferingView) -> Vec<NetworkOption<'_>> {
    let shared = offering
        .network_prices
        .iter()
        .find(|price| price.gateway_tier == Some(GatewayTier::SharedBandwidth));
    let preselected = offering
        .gateway_locations
        .iter()
        .find(|location| location.preselected);
    let mut options = Vec::with_capacity(offering.network_prices.len());
    for price in &offering.network_prices {
        if price.gateway_tier == Some(GatewayTier::SharedBandwidth)
            && let Some((shared, preselected)) = shared.zip(preselected)
        {
            let provider = shared
                .combined_microusd_per_tib
                .saturating_sub(preselected.gateway_network_microusd_per_tib);
            options.extend(
                offering
                    .gateway_locations
                    .iter()
                    .map(|location| NetworkOption {
                        tier: price.gateway_tier,
                        location: Some(location),
                        base_microusd_per_month: location.gateway_base_charge_microusd_per_month,
                        traffic_microusd_per_tib: provider
                            .saturating_add(location.gateway_network_microusd_per_tib),
                        bandwidth: price.bandwidth,
                    }),
            );
        } else {
            // A cloud offering's own address costs its address price.
            let own_address =
                offering.host_mode == HostMode::CloudRouted && price.gateway_tier.is_none();
            options.push(NetworkOption {
                tier: price.gateway_tier,
                location: None,
                base_microusd_per_month: if own_address {
                    offering.address_microusd_per_month
                } else {
                    price.gateway_base_charge_microusd_per_month
                },
                traffic_microusd_per_tib: price.combined_microusd_per_tib,
                bandwidth: price.bandwidth,
            });
        }
    }
    options
}

/// A bandwidth limit as `ghost` writes it: `200 Mbit/s`, or `no limit`.
fn bandwidth_text(bandwidth: gigahost_client_api::website::BandwidthView) -> String {
    bandwidth
        .limit_mbit
        .map_or_else(|| "no limit".to_owned(), |mbit| format!("{mbit} Mbit/s"))
}

/// An offering's traffic prices: the provider's for a cloud offering, and
/// for a home offering each gateway tier's with the tier's monthly base.
/// A cloud offering's shared IP is included in its host's fixed price, so
/// `cloud` says "included" for it where a gateway's tier names a price.
fn network_prices_text(
    prices: &[gigahost_client_api::website::NetworkPriceView],
    cloud: bool,
) -> String {
    let rows = prices
        .iter()
        .map(|price| {
            let traffic = format!("{}/TiB", pretty::dollars(price.combined_microusd_per_tib));
            match price.gateway_tier {
                Some(tier) => {
                    let name = if tier == GatewayTier::Unknown {
                        gateway_tier_words(tier)
                    } else {
                        format!(
                            "{} (--gateway-tier {})",
                            gateway_tier_words(tier),
                            wire_name(tier)
                        )
                    };
                    let cost = if tier == GatewayTier::SharedIp && cloud {
                        format!("{traffic}, included")
                    } else {
                        format!(
                            "{traffic} + {}/month",
                            pretty::dollars(price.gateway_base_charge_microusd_per_month)
                        )
                    };
                    (name, cost)
                }
                None => (String::new(), traffic),
            }
        })
        .collect::<Vec<_>>();
    let width = rows
        .iter()
        .map(|(name, _)| name.chars().count())
        .max()
        .unwrap_or(0);
    rows.iter()
        .map(|(name, cost)| format!("  {name:<width$}  {cost}"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// An offering's network options as rows of a table: for a home offering
/// each gateway tier, a shared one at each location it may be placed at,
/// with its distance from the host and its prices; for a cloud offering
/// (`cloud`) its own address and its host's shared IP, each with its
/// monthly price.
fn network_option_rows(options: &[NetworkOption<'_>], cloud: bool) -> pretty::Section {
    // The bandwidth column where the backend sends limits.
    let limited = options.iter().any(|option| option.bandwidth.is_some());
    let columns = |columns: Vec<&'static str>| -> Vec<&'static str> {
        columns
            .into_iter()
            .filter(|column| limited || *column != "bandwidth")
            .collect()
    };
    if options.iter().all(|option| option.tier.is_none()) {
        return pretty::Section::Rows(
            columns(vec!["traffic_per_tib", "bandwidth"]),
            options
                .iter()
                .map(|option| {
                    json!({
                        "traffic_per_tib": pretty::dollars(option.traffic_microusd_per_tib),
                        "bandwidth": option.bandwidth.map(bandwidth_text),
                    })
                })
                .collect(),
        );
    }
    pretty::Section::Rows(
        columns(vec![
            "gateway_tier",
            "gateway_location",
            "location_name",
            "distance",
            "bottleneck",
            "base_per_month",
            "traffic_per_tib",
            "bandwidth",
        ]),
        options
            .iter()
            .map(|option| {
                let location = option.location;
                json!({
                    "gateway_tier": option.tier.map(gateway_tier_words),
                    "gateway_location": location.map_or_else(
                        // A shared IP is placed as shared bandwidth is,
                        // at --gateway-location or the default location; a
                        // cloud VM's address is its host's.
                        || if cloud {
                            if option.tier.is_some() { "host's address" } else { "own address" }.to_owned()
                        } else if option.tier == Some(GatewayTier::SharedIp) {
                            "default location".to_owned()
                        } else {
                            "nearest region".to_owned()
                        },
                        |location| location.location.clone(),
                    ),
                    "location_name": location.map(|location| if location.preselected {
                        format!("{} (default)", location.location_name)
                    } else {
                        location.location_name.clone()
                    }),
                    "distance": location.map(|location| format!("{} km", location.distance_km)),
                    "bottleneck": location.map(|location| location.bottleneck),
                    "base_per_month": if cloud && option.tier == Some(GatewayTier::SharedIp) {
                        "included".to_owned()
                    } else {
                        pretty::dollars(option.base_microusd_per_month)
                    },
                    "traffic_per_tib": pretty::dollars(option.traffic_microusd_per_tib),
                    "bandwidth": option.bandwidth.map(bandwidth_text),
                })
            })
            .collect(),
    )
}

/// A network test reading: its rate, with a `+` when it reached its test
/// server's limit, which the rate then is, and the location of the server.
fn reading_text(bits_per_second: Option<u64>, at_limit: bool, location: Option<&str>) -> Value {
    bits_per_second.map_or(Value::Null, |bits| {
        let limit = if at_limit { "+" } else { "" };
        let rate = format!("{}{limit}", pretty::bit_rate(bits));
        json!(located(rate, location))
    })
}

/// `text` with the location it was measured against after it, when known.
fn located(text: String, location: Option<&str>) -> String {
    match location {
        Some(location) => format!("{text} ({location})"),
        None => text,
    }
}

/// The best network test readings of a host or an offering, upload first.
fn network_summary_fields(
    summary: &gigahost_client_api::website::NetworkTestSummaryView,
) -> pretty::Section {
    pretty::Section::Fields(vec![
        (
            "upload",
            reading_text(
                summary.best_upload_bits_per_second,
                summary.best_upload_at_limit,
                summary.best_upload_location_name.as_deref(),
            ),
        ),
        (
            "download",
            reading_text(
                summary.best_download_bits_per_second,
                summary.best_download_at_limit,
                summary.best_download_location_name.as_deref(),
            ),
        ),
        (
            "latency",
            summary.lowest_latency_ms.map_or(Value::Null, |latency| {
                json!(located(
                    format!("{latency} ms"),
                    summary.lowest_latency_location_name.as_deref()
                ))
            }),
        ),
        ("measured_at", json!(summary.measured_at)),
    ])
}

/// The heading of a monthly projection's figures.
const PROJECTION_HEADING: &str = "projected_monthly_charges";

/// What a monthly projection is based on, as the website says it.
const PROJECTION_BASIS: &str = "the past 30 days of each service; new services count as if they \
                                had run the whole 30 days; one-time charges are not included";

/// How long the available balance lasts at a projection's rate.
fn days_text(days: u32) -> String {
    match days {
        0 => "less than a day at this rate".to_owned(),
        1 => "1 day at this rate".to_owned(),
        days => format!("{days} days at this rate"),
    }
}

/// A result shown for reading as a record and sections of its own rather
/// than as [`pretty::render`] shows its JSON, or `None` for a command whose
/// result has none, or one not in the shape it knows.
fn readable_sections(command: &Command, output: &Value, terminal: Terminal) -> Option<String> {
    // Results whose hints are shown apart: a hint is not a row of the
    // table. The hints go to standard error ([`result_hint_notes`]), or are
    // already said by a notice; `--json` keeps every key.
    if matches!(
        command,
        Command::Account {
            command: AccountCommand::ActivationTerms
        }
    ) {
        let mut fields = output.as_object()?.clone();
        if let Some(rate) = fields
            .get("mmx_exchange_rate")
            .filter(|rate| !rate.is_null())
        {
            let rate: gigahost_client_api::website::MmxExchangeRateView =
                serde_json::from_value(rate.clone()).ok()?;
            fields.insert(
                "mmx_exchange_rate".to_owned(),
                json!(format!(
                    "{} per MMX, until {}",
                    pretty::decimal_dollars(&escape_control(&rate.usd_per_mmx)),
                    rate.expires_at.format("%Y-%m-%d %H:%M:%S UTC")
                )),
            );
        }
        return Some(pretty::render(&Value::Object(fields), terminal));
    }
    if let Some(dropped) = hint_keys(command, output) {
        let mut fields = output.as_object()?.clone();
        for key in dropped {
            fields.remove(*key);
        }
        return Some(pretty::render(&Value::Object(fields), terminal));
    }
    if matches!(
        command,
        Command::Provider {
            command: ProviderCommand::AgentUpdate { .. }
        }
    ) {
        let view: HostAgentUpdateView = serde_json::from_value(output.clone()).ok()?;
        return Some(pretty::render(&agent_update_record(&view), terminal));
    }
    if let Command::Provider {
        command:
            ProviderCommand::Host {
                command: Some(ProviderHostCommand::Delete { .. }),
                ..
            },
    } = command
        && let (Some(label), Some(host_id)) = (
            output["host"]["label"].as_str(),
            output["host"]["host_id"].as_str(),
        )
    {
        return Some(
            [
                format!(
                    "Host {} ({}) deleted.",
                    escape_control(label),
                    escape_control(host_id)
                ),
                "Before enrolling it again:".to_owned(),
                "  1. Stop the hypervisor service on that host.".to_owned(),
                "  2. Run: gigahost-hypervisor reset-enrollment --config PATH --yes".to_owned(),
                "  3. Enroll it with a new token.".to_owned(),
            ]
            .join("\n"),
        );
    }
    if matches!(
        command,
        Command::Account {
            command: AccountCommand::Balance
        }
    ) {
        let mut fields = output.as_object()?.clone();
        for (wire, label) in [
            ("available_microusd", "available_spending_credit_microusd"),
            ("reserved_microusd", "reserved_spending_credit_microusd"),
            ("total_microusd", "total_spending_credit_microusd"),
        ] {
            if let Some(value) = fields.remove(wire) {
                fields.insert(label.to_owned(), value);
            }
        }
        // The projection by type, in that order, under a heading of its own.
        let projection = fields.remove("projection").and_then(|projection| {
            serde_json::from_value::<AccountProjectionView>(projection).ok()
        });
        let Some(projection) = projection else {
            return Some(pretty::render(&Value::Object(fields), terminal));
        };
        let mut rows = vec![
            (
                "instances_microusd",
                json!(projection.instances_base_microusd),
            ),
            ("traffic_microusd", json!(projection.traffic_microusd)),
            (
                "local_backups_microusd",
                json!(projection.local_backups_microusd),
            ),
            (
                "hosted_backups_microusd",
                json!(projection.hosted_backups_microusd),
            ),
            ("total_microusd", json!(projection.total_microusd)),
        ];
        if let Some(days) = projection.days_balance_lasts {
            rows.push(("balance_lasts", json!(days_text(days))));
        }
        rows.push(("basis", json!(PROJECTION_BASIS)));
        return Some(pretty::render_sections(
            &fields,
            &[(PROJECTION_HEADING, pretty::Section::Fields(rows))],
            terminal,
        ));
    }
    // An instance's usage, then its projection under a heading of its own.
    if matches!(
        command,
        Command::Instance {
            command: InstanceCommand::Usage { .. }
        }
    ) {
        let mut fields = output.as_object()?.clone();
        let projection =
            serde_json::from_value::<InstanceProjectionView>(fields.remove("projection")?).ok()?;
        let rows = vec![
            ("base_microusd", json!(projection.base_microusd)),
            ("traffic_microusd", json!(projection.traffic_microusd)),
            (
                "local_backups_microusd",
                json!(projection.local_backups_microusd),
            ),
            (
                "hosted_backups_microusd",
                json!(projection.hosted_backups_microusd),
            ),
            ("total_microusd", json!(projection.total_microusd)),
            ("basis", json!(PROJECTION_BASIS)),
        ];
        return Some(pretty::render_sections(
            &fields,
            &[(PROJECTION_HEADING, pretty::Section::Fields(rows))],
            terminal,
        ));
    }
    // An import reads as what it did, where, the account in one line (or
    // why there is none), and then the key's identities.
    if matches!(
        command,
        Command::Key {
            command: KeyCommand::Import { .. }
        }
    ) {
        let mut fields = output.as_object()?.clone();
        let result = match fields.get("result")?.as_str()? {
            "imported" => "imported".to_owned(),
            "already_imported" => "already imported: the seed file holds this key".to_owned(),
            "replaced" => format!(
                "replaced: the previous key is kept at {}",
                escape_control(fields.get("replaced_file")?.as_str()?)
            ),
            other => escape_control(other).into_owned(),
        };
        fields.insert("result".to_owned(), json!(result));
        fields.remove("replaced_file");
        let note = fields.remove("account_note");
        let account = match fields.get("account").filter(|account| !account.is_null()) {
            Some(account) => {
                let account: AccountView = serde_json::from_value(account.clone()).ok()?;
                json!(format!(
                    "{} ({})",
                    escape_control(&account.account_alias),
                    escape_control(&account.status)
                ))
            }
            None => note.unwrap_or(Value::Null),
        };
        fields.insert("account".to_owned(), account);
        return Some(pretty::render(&Value::Object(fields), terminal));
    }
    // The linked GitHub account reads as one line, `@login (linked DATE)`;
    // `--json` keeps the object, and none linked stays null (shown as `-`).
    if matches!(
        command,
        Command::Account {
            command: AccountCommand::Show
        }
    ) {
        let mut fields = output.as_object()?.clone();
        if let Some(github) = fields.get("github").filter(|github| !github.is_null()) {
            let github: AccountGithubView = serde_json::from_value(github.clone()).ok()?;
            fields.insert("github".to_owned(), json!(github_line(&github)));
        }
        return Some(pretty::render(&Value::Object(fields), terminal));
    }
    let Command::Catalog {
        command: Some(command),
        ..
    } = command
    else {
        return None;
    };
    match command {
        CatalogCommand::Offering { .. } => {
            let offering: OfferingView = serde_json::from_value(output.clone()).ok()?;
            let mut map = output.as_object()?.clone();
            map.remove("network_prices");
            map.remove("gateway_locations");
            // The hardware profiles show the memory the summary repeats.
            if !offering.hardware_profiles.is_empty() {
                map.remove("memory_profiles");
            }
            let mut sections = Vec::with_capacity(2);
            if let Some(network) = &offering.network {
                map.remove("network");
                sections.push(("network", network_summary_fields(network)));
            }
            sections.push((
                "network_prices",
                network_option_rows(
                    &network_options(&offering),
                    offering.host_mode == HostMode::CloudRouted,
                ),
            ));
            Some(pretty::render_sections(&map, &sections, terminal))
        }
        CatalogCommand::NetworkTest { .. } => {
            let tests: gigahost_client_api::website::HostNetworkTestsView =
                serde_json::from_value(output.clone()).ok()?;
            let mut map = serde_json::Map::new();
            map.insert("host_id".to_owned(), json!(tests.host_id));
            let rows = tests
                .results
                .iter()
                .map(|result| {
                    json!({
                        "upload": reading_text(
                            result.upload_bits_per_second,
                            result.upload_at_limit,
                            None,
                        ),
                        "download": reading_text(
                            result.download_bits_per_second,
                            result.download_at_limit,
                            None,
                        ),
                        "latency_ms": result.latency_ms,
                        "location": result.location,
                        "location_name": result.location_name,
                        "server": result.server,
                        "observed_at": result.observed_at,
                    })
                })
                .collect();
            let sections = [
                ("summary", network_summary_fields(&tests.summary)),
                (
                    "results",
                    pretty::Section::Rows(
                        vec![
                            "upload",
                            "download",
                            "latency_ms",
                            "location",
                            "location_name",
                            "server",
                            "observed_at",
                        ],
                        rows,
                    ),
                ),
            ];
            Some(pretty::render_sections(&map, &sections, terminal))
        }
        _ => None,
    }
}

/// Format a failed command's error chain like Rust prints an error returned
/// from `main`, with every message passed through [`escape_control`]: API
/// errors and job failures carry text from the backend and the provider's
/// hypervisor. A message spans lines where `ghost` words it so (a refusal
/// that lists the choices, one per line), so the line break stays and every
/// other control character is escaped, as [`escape_control_keeping_lines`]
/// does; a cause's later lines are indented with it. On a `terminal` with
/// colors the heading is red.
#[must_use]
pub fn render_error(error: &anyhow::Error, terminal: Terminal) -> String {
    let mut text = format!(
        "{} {}",
        pretty::paint_failure("Error:", terminal.colors),
        escape_control_keeping_lines(&error.to_string())
    );
    let causes = error.chain().skip(1).collect::<Vec<_>>();
    if causes.len() == 1 {
        let _ = write!(
            text,
            "\n\nCaused by:\n    {}",
            indent_lines(&causes[0].to_string(), "    ")
        );
    } else if !causes.is_empty() {
        text.push_str("\n\nCaused by:");
        for (index, cause) in causes.iter().enumerate() {
            let label = format!("{index}: ");
            let _ = write!(
                text,
                "\n    {label}{}",
                indent_lines(&cause.to_string(), &" ".repeat(4 + label.len()))
            );
        }
    }
    text
}

/// `text` with its control characters escaped but its line breaks kept
/// ([`escape_control_keeping_lines`]), every line after the first starting
/// with `indent`.
fn indent_lines(text: &str, indent: &str) -> String {
    escape_control_keeping_lines(text).replace('\n', &format!("\n{indent}"))
}

/// The code of a failure whose request got no answer, in [`error_output`].
const NO_RESPONSE: &str = "no_response";
/// The code of a restore or new VM `ghost` refuses because the seed it
/// has does not match the key a hosted backup was encrypted for.
const RECOVERY_KEY_MISMATCH: &str = "recovery_key_mismatch";

/// A command refused here, before its request is sent, for what the backend
/// would refuse it for: `code` is the backend's error code for that, which
/// `--json` prints as it prints a rejection's. What only `ghost` can tell,
/// as that a seed does not match the key a hosted backup was encrypted
/// for, which the backend never sees, has a code of `ghost`'s own:
/// [`RECOVERY_KEY_MISMATCH`].
#[derive(Debug)]
struct Refusal {
    code: &'static str,
    message: String,
}

/// Construct a refusal whose machine code is preserved by error rendering.
pub fn typed_refusal(code: &'static str, message: String) -> anyhow::Error {
    Refusal { code, message }.into()
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Refusal {}

/// Return a [`Refusal`] with the backend's error code `$code` and the
/// message the rest formats, as `bail!` returns an error.
macro_rules! refuse {
    ($code:expr, $($message:tt)+) => {
        return Err(typed_refusal($code, format!($($message)+)))
    };
}

/// What a command that failed after the backend accepted its job says of
/// the job, which goes on without it: `message` says how to follow or
/// resume it, and `--json` prints `job_id` in the error object.
#[derive(Debug)]
struct JobContext {
    job_id: Uuid,
    message: String,
}

impl std::fmt::Display for JobContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

/// A failed command's error as `--json` and `--compact` print it on
/// standard output, `{"error": {...}}`, for scripts, which never parse the
/// text. A request the backend refused has its `code`, the HTTP `status`,
/// the `job_id` of a job a conflict names, and the `request_id`; one
/// refused here for what the backend refuses has the backend's code for
/// that, and no status, and one refused for what only `ghost` can tell has
/// `ghost`'s own ([`Refusal`]); one that got no answer has the code
/// `no_response`; any other failure of the command itself, such as a file
/// it cannot read, has none. A command that failed after the backend
/// accepted its job, such as one that stopped waiting for it, has that
/// job's `job_id`.
/// `transient` says whether repeating the command, with the same
/// idempotency key, may succeed, and `message` is the error as the text
/// form prints it.
#[must_use]
pub fn error_output(error: &anyhow::Error) -> Value {
    let rejection = api::rejection(error);
    let code = rejection
        .as_ref()
        .and_then(|rejection| rejection.code)
        .or_else(|| error.downcast_ref::<Refusal>().map(|refusal| refusal.code))
        .or_else(|| api::got_no_response(error).then_some(NO_RESPONSE));
    let job_id = rejection
        .as_ref()
        .and_then(|rejection| rejection.job_id)
        .or_else(|| error.downcast_ref::<JobContext>().map(|job| job.job_id));
    json!({"error": {
        "code": code,
        "message": format!("{error:#}"),
        "status": rejection.as_ref().map(|rejection| rejection.status),
        "job_id": job_id,
        "request_id": rejection.as_ref().and_then(|rejection| rejection.request_id),
        "transient": api::is_transient(error),
    }})
}

/// Replace control characters with visible escapes such as `\u{1b}`, so a
/// server-supplied string cannot inject ANSI or OSC sequences into the
/// terminal. Job step messages come from the provider's hypervisor, so every
/// server-supplied string is passed through this before it is printed.
#[must_use]
pub fn escape_control(text: &str) -> Cow<'_, str> {
    escape_matching(text, char::is_control)
}

/// [`escape_control`] for a message that spans lines: the line feed stays,
/// as it injects no sequence, and every other control character, the
/// carriage return too, is escaped.
fn escape_control_keeping_lines(text: &str) -> Cow<'_, str> {
    escape_matching(text, |character| {
        character.is_control() && character != '\n'
    })
}

/// `text` with each character `escaped` accepts replaced by its visible
/// escape.
fn escape_matching(text: &str, escaped: impl Fn(char) -> bool) -> Cow<'_, str> {
    if !text.chars().any(&escaped) {
        return Cow::Borrowed(text);
    }
    let mut result = String::with_capacity(text.len());
    for character in text.chars() {
        if escaped(character) {
            result.extend(character.escape_default());
        } else {
            result.push(character);
        }
    }
    Cow::Owned(result)
}

/// The serde name of a protocol enum value, as the API expects it in a query.
fn wire_name(value: impl Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

/// How often a GitHub claim is read while it waits for the sign-in.
const GITHUB_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// The Terms of Service on the website, which a sign-up, an activation and a host's enrollment
/// agree to.
const TERMS_URL: &str = "https://gigahost.cloud/terms";

/// The line a sign-up or an activation prints before it sends anything:
/// activating agrees to the Terms and asks that the service starts at once,
/// as the website's activation step says.
fn signup_terms_line(action: &str) -> String {
    format!(
        "By {action} you agree to the Terms of Service and the Acceptable Use Policy, and ask that the service starts at once: {TERMS_URL}"
    )
}

/// The line a host enrollment token prints: the Terms' section for
/// providers applies to the host it enrolls.
fn provider_terms_line() -> String {
    format!(
        "Enrolling a host agrees to the Terms of Service, their section for providers included: {TERMS_URL}#providers"
    )
}

/// What a trial may rent, said once the trial is made and in `account show`.
const TRIAL_LIMITS: &str = "A trial rents instances of 1 vCPU with a shared IP on the platform's own hosts, sends no outgoing mail and cannot offer hosts; a deposit lifts these limits, and the trial credit still ends on its date.";

/// How long a GitHub claim lives, as the notice says: the longest the
/// backend lets a link wait for its GitHub sign-in.
const GITHUB_CLAIM_LIFETIME: Duration = Duration::from_mins(10);

/// How long after a claim's expiry the backend still finishes a sign-in
/// made just before it (the exchange with GitHub takes a moment), and
/// answers `refused` itself once the claim is past that.
const GITHUB_EXCHANGE_MARGIN: Duration = Duration::from_mins(2);

/// The most a claim is followed, counted from now on a clock that does not
/// jump: its expiry plus the exchange margin. The computer's clock may run
/// ahead of the backend's, which would cut that short, and the claim was
/// made a moment ago, so it is never less than a whole lifetime. The backend
/// answers `created` or `refused` before this, so it only ends a wait that
/// no answer would.
fn github_wait_limit(claim: &TrialClaimView, now: DateTime<Utc>) -> Duration {
    (claim.expires_at - now)
        .to_std()
        .unwrap_or_default()
        .max(GITHUB_CLAIM_LIFETIME)
        + GITHUB_EXCHANGE_MARGIN
}

/// The claim link to open in the browser, only when it is the website of
/// the API in use: an http or https link without a user name or password,
/// on the API's host or on a parent domain of it (`gigahost.cloud` for
/// `api.gigahost.cloud`), as the desktop app opens only the configured
/// website. The API chooses the link, so any other is printed for the
/// person to judge and never handed to the system, where a file link or a
/// registered protocol would start a program.
fn browser_link(link: &str, api_url: &str) -> Option<reqwest::Url> {
    let link = reqwest::Url::parse(link).ok()?;
    let api = reqwest::Url::parse(api_url).ok()?;
    if !matches!(link.scheme(), "http" | "https")
        || !link.username().is_empty()
        || link.password().is_some()
    {
        return None;
    }
    let same_host = link.host_str()? == api.host_str()?;
    // A parent domain is the website; it has a dot of its own, so a bare
    // top-level name is not one, and an address has no parent.
    let parent_domain = match (link.domain(), api.domain()) {
        (Some(link), Some(api)) => {
            link.contains('.')
                && api
                    .strip_suffix(link)
                    .is_some_and(|rest| rest.ends_with('.'))
        }
        _ => false,
    };
    (same_host || parent_domain).then_some(link)
}

/// Opens `link` in the browser if the system has a way to: it never fails,
/// the link was printed for the person to open. The link is handed over as
/// the parsed URL's text, which starts with its scheme, never with a `-`.
fn open_in_browser(link: &reqwest::Url) {
    let mut command = if cfg!(target_os = "macos") {
        std::process::Command::new("open")
    } else if cfg!(windows) {
        let mut command = std::process::Command::new("rundll32");
        command.arg("url.dll,FileProtocolHandler");
        command
    } else {
        std::process::Command::new("xdg-open")
    };
    let _ = command
        .arg(link.as_str())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

/// What a GitHub claim is for, as the commands name it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GithubClaimUse {
    Signup,
    Link,
}

impl GithubClaimUse {
    /// The command that makes a new claim, for the notices that say to run
    /// it again.
    fn command(self) -> &'static str {
        match self {
            Self::Signup => "ghost account signup --github",
            Self::Link => "ghost account link-github",
        }
    }

    fn noun(self) -> &'static str {
        match self {
            Self::Signup => "sign-up",
            Self::Link => "link",
        }
    }
}

/// Reads `claim` every `interval` until it is created or linked (the
/// answer), refused (an error), or `limit` passes ([`github_wait_limit`]).
/// The server's answer decides when the claim ends; passing its expiry on
/// this computer's clock does not stop a sign-in already in progress.
/// Transient transport or server failures and throttling are retried with
/// backoff; other failures, such as a missing claim, end the wait.
async fn await_github_claim(
    api: &ApiClient,
    claim: &TrialClaimView,
    use_of: GithubClaimUse,
    interval: Duration,
    limit: Duration,
) -> Result<TrialClaimStatusView> {
    let started = tokio::time::Instant::now();
    let mut pause = interval;
    let mut unread: Option<anyhow::Error> = None;
    loop {
        let reading = api
            .read(
                &GetGithubClaim {
                    claim_id: claim.claim_id.clone(),
                },
                "",
            )
            .await;
        match reading {
            Ok(
                status @ TrialClaimStatusView {
                    status: TrialClaimStatus::Created | TrialClaimStatus::Linked,
                    ..
                },
            ) => {
                if status.account_alias.is_none() {
                    bail!("the GitHub claim was finished without an account alias");
                }
                return Ok(status);
            }
            Ok(TrialClaimStatusView {
                status: TrialClaimStatus::Refused,
                reason,
                ..
            }) => bail!(
                "the {} was refused: {}",
                use_of.noun(),
                reason.as_deref().unwrap_or("the claim was refused")
            ),
            Ok(_) => {
                unread = None;
                pause = interval;
            }
            Err(error) if api::is_transient(&error) => {
                if unread.is_none() {
                    notice(&format!(
                        "could not read the GitHub claim ({}); the sign-in goes on, trying again",
                        escape_control(&format!("{error:#}"))
                    ));
                }
                unread = Some(error);
            }
            Err(error) => return Err(error),
        }
        if started.elapsed() >= limit {
            return Err(match unread {
                Some(error) => error.context(format!(
                    "the link expired while the backend could not be read; `ghost account show` says whether the {} went through, otherwise run `{}` again",
                    use_of.noun(),
                    use_of.command()
                )),
                None => anyhow::anyhow!("the link expired; run `{}` again", use_of.command()),
            });
        }
        tokio::time::sleep(pause).await;
        if unread.is_some() {
            pause = next_poll_retry_delay(pause, interval);
        }
    }
}

/// Prints a claim's link, opens it when it is the API's website, waits for
/// the sign-in and returns what became of the claim.
async fn follow_github_claim(
    cli: &Cli,
    api: &ApiClient,
    claim: &TrialClaimView,
    use_of: GithubClaimUse,
) -> Result<TrialClaimStatusView> {
    notice(&format!(
        "GitHub claim link: {}",
        escape_control(&claim.claim_url)
    ));
    notice("Open this link and sign in with GitHub within 10 minutes.");
    if let Some(link) = browser_link(&claim.claim_url, &cli.globals.api_url) {
        open_in_browser(&link);
    }
    let limit = github_wait_limit(claim, Utc::now());
    await_github_claim(api, claim, use_of, GITHUB_POLL_INTERVAL, limit).await
}

/// The credit's line for a finished claim, with why it did not come when
/// the backend says (a link past the platform's credits of the hour).
fn github_credit_notice(status: &TrialClaimStatusView) {
    if status.trial_credit {
        notice("The trial credit came with it.");
    } else if let Some(reason) = status.trial_credit_refusal.as_deref() {
        notice(&format!(
            "No trial credit came with it: {}.",
            escape_control(reason.trim_end_matches('.'))
        ));
    } else {
        notice("No trial credit came with it.");
    }
}

/// What a sign-up that made the account without the trial credit says:
/// why, and that a deposit to `deposit_memo` adds funds.
fn signup_without_credit(status: &TrialClaimStatusView, deposit_memo: &str) -> String {
    let reason = status
        .trial_credit_refusal
        .as_deref()
        .map_or_else(String::new, |reason| {
            format!(": {}", escape_control(reason.trim_end_matches('.')))
        });
    format!(
        "No trial credit{reason}.\nThe account starts with a $0 balance.\nTo add funds: make an MMX deposit with the deposit memo {}.\nTo see the deposit address: ghost account activation-terms",
        escape_control(deposit_memo)
    )
}

/// What a trial may rent, as the lines of a notice: a short list, then
/// what a deposit does. [`TRIAL_LIMITS`] says the same in one sentence for
/// the JSON result.
fn trial_limit_lines() -> String {
    [
        "A trial account:",
        "  rents instances of 1 vCPU only",
        "  rents with a shared IP, on the platform's own hosts only",
        "  sends no outgoing mail",
        "  cannot offer hosts",
        "A deposit lifts these limits.",
        "The trial credit still ends on its date.",
    ]
    .join("\n")
}

/// The GitHub login a finished claim names, as `@login`.
fn github_login_label(status: &TrialClaimStatusView) -> String {
    status.github_login.as_deref().map_or_else(
        || "a GitHub account".to_owned(),
        |login| format!("@{}", escape_control(login)),
    )
}

/// The account's linked GitHub account as one line for reading:
/// `@login (linked DATE)`.
fn github_line(github: &AccountGithubView) -> String {
    format!(
        "@{} (linked {})",
        escape_control(&github.login),
        github.linked_at.format("%Y-%m-%d")
    )
}

/// The keys of `output`, the result of `command`, that its text for reading
/// leaves out of the table because a notice says them or they are a hint:
/// the hint keys of `key generate`, `account set-password` and `account
/// migrate-seed`, and the refusal and deposit memo a sign-up notice said.
fn hint_keys(command: &Command, output: &Value) -> Option<&'static [&'static str]> {
    match command {
        Command::Key {
            command: KeyCommand::Generate { .. },
        }
        | Command::Account {
            command: AccountCommand::MigrateSeed { .. },
        } => Some(&["warning"]),
        Command::Account {
            command: AccountCommand::SetPassword { .. },
        } => Some(&["note"]),
        Command::Account {
            command: AccountCommand::Signup { .. },
        } if output["status"] == "created" => {
            if output["trial_credit"] == true {
                Some(&["trial_credit_refusal"])
            } else {
                Some(&["trial_credit_refusal", "deposit_memo"])
            }
        }
        _ => None,
    }
}

/// The hints of a result for reading, as lines for standard error: a
/// warning or note block after the table.
fn result_hint_notes(command: &Command) -> Vec<String> {
    let lines: &[&str] = match command {
        Command::Key {
            command: KeyCommand::Generate { .. },
        } => &[
            "warning: back up the account key file.",
            "Losing it makes encrypted hosted backups unrecoverable.",
        ],
        Command::Account {
            command: AccountCommand::SetPassword { .. },
        } => &[
            "note: the password is shown only this once.",
            "Keep it in a password manager.",
        ],
        Command::Account {
            command: AccountCommand::MigrateSeed { .. },
        } => &[
            "warning: the old account key is revoked for account authentication.",
            "To use the replacement: select it with --seed-file or GHOST_SEED_FILE.",
            "Keep the old account key while it protects any existing backups.",
        ],
        _ => &[],
    };
    lines.iter().map(|line| (*line).to_owned()).collect()
}

fn execute_key(cli: &Cli, command: &KeyCommand) -> Result<Value> {
    match command {
        KeyCommand::Generate { output } => {
            let path = output
                .clone()
                .or_else(|| cli.globals.seed_file.clone())
                .map_or_else(default_seed_path, Ok)?;
            let summary = keys::generate_seed(&path)?;
            Ok(json!({
                "seed_file": path,
                "warning": "Back up this file. Losing it makes encrypted hosted backups unrecoverable.",
                "keys": summary,
            }))
        }
        KeyCommand::Inspect => {
            let seed = load_account_seed(cli)?;
            serde_json::to_value(keys::key_summary(&seed)?).context("serialize key summary")
        }
        KeyCommand::Import { .. } => unreachable!("`execute` runs `key import` itself"),
    }
}

/// What `key import` prompts on a terminal before the hidden line.
const IMPORT_PROMPT: &str = "Paste the account key line (input hidden): ";

/// `ghost key import`: read the key from `from`, a hidden terminal line or
/// standard input, put it in the seed file `generate` would write, and
/// show its identities and, from the backend, its account. The import
/// stands whatever the account check answers: a key with no account yet,
/// or a backend out of reach, is a note, not a failure.
async fn execute_key_import(cli: &Cli, from: Option<&Path>, replace: bool) -> Result<Value> {
    use std::io::IsTerminal as _;

    let input = match from {
        Some(path) => keys::read_key_file(path)?,
        None if std::io::stdin().is_terminal() => keys::read_key_hidden(IMPORT_PROMPT)?,
        None => keys::read_key_stdin()?,
    };
    let seed = keys::parse_imported_seed(&input)?;
    drop(input);
    let path = cli
        .globals
        .seed_file
        .clone()
        .map_or_else(default_seed_path, Ok)?;
    let outcome = keys::import_seed(&path, &seed, replace)?;
    let summary = keys::key_summary(&seed)?;
    drop(seed);
    let mut output = json!({
        "seed_file": path,
        "result": match outcome {
            keys::ImportOutcome::Imported => "imported",
            keys::ImportOutcome::AlreadyImported => "already_imported",
            keys::ImportOutcome::Replaced { .. } => "replaced",
        },
        "keys": summary,
        "account": null,
    });
    if let keys::ImportOutcome::Replaced { previous } = &outcome {
        output["replaced_file"] = json!(previous);
    }
    // One attempt only: the key is in place, the account is only a part
    // of the answer, and the desktop gives the whole import 90 s, which
    // the reads' retries (three times the 30 s timeout) would outlast.
    let account = match api_client(cli) {
        Ok(api) => {
            api.with_read_retry_delays(&[])
                .read::<GetAccount>(&GetAccount, "")
                .await
        }
        Err(error) => Err(error),
    };
    match account {
        Ok(account) => output["account"] = to_value(account)?,
        Err(error) if api::rejection_code(&error) == Some("account_not_activated") => {
            output["account_note"] = json!(IMPORT_NO_ACCOUNT);
        }
        Err(error) => {
            output["account_note"] = json!(format!(
                "the account could not be checked: {}",
                escape_control(&format!("{error:#}"))
            ));
        }
    }
    if let Some(from) = from {
        output["note"] = json!(format!(
            "the file you imported from is still at {}; delete it if you keep the key elsewhere",
            from.display()
        ));
    }
    Ok(output)
}

/// The note of `key import` for a key the backend has no account for.
const IMPORT_NO_ACCOUNT: &str =
    "this key has no account yet: sign up with `ghost account signup --github`, or on the website";

async fn execute_catalog(api: &ApiClient, command: &CatalogCommand) -> Result<Value> {
    match command {
        CatalogCommand::Reviews { provider_id, page } => {
            api.read(
                &ListProviderReviews {
                    provider_id: *provider_id,
                },
                &page.query(),
            )
            .await
        }
        CatalogCommand::Locations(filters) => {
            // The server refuses a country or continent no location is in.
            let locations: Vec<LocationView> = api.read(&ListLocations, &filters.query()).await?;
            to_value(locations)
        }
        CatalogCommand::Offerings(filters) => {
            // The server filters before it cuts the list, as the website's
            // Capacity page asks it to, and refuses an unknown location, so
            // --for-backup reads the backup first.
            let backup: Option<BackupView> = match filters.placement.for_backup {
                Some(backup_id) => Some(api.read(&GetBackup { backup_id }, "").await?),
                None => None,
            };
            // Signed when there is an account key: the private hosts' offerings its providers allow
            // it are listed too.
            let offerings: Vec<OfferingView> = api
                .read_as_account(&ListOfferings, &filters.query(backup.as_ref())?)
                .await?;
            if let Some(after) = filters.next_page(&offerings) {
                notice(&format!(
                    "More offerings follow: add --after {after} for the next page."
                ));
            }
            to_value(offerings)
        }
        CatalogCommand::Offering { offering_id } => {
            check_offering_id(offering_id)?;
            let offering: OfferingView = api
                .read_as_account(
                    &GetOffering {
                        offering_id: offering_id.clone(),
                    },
                    "",
                )
                .await?;
            to_value(offering)
        }
        CatalogCommand::Images => {
            let images: Vec<ImageView> = api.read(&ListImages, "").await?;
            to_value(images)
        }
        CatalogCommand::ContainerImages => {
            let images: Vec<ContainerImageView> = api.read(&ListContainerImages, "").await?;
            to_value(images)
        }
        CatalogCommand::Status => {
            let status: gigahost_client_api::website::PlatformStatusView =
                api.read(&gigahost_client_api::api::GetStatus, "").await?;
            to_value(status)
        }
        CatalogCommand::Provider { provider } => {
            // An alias is known only from the offerings that show it, which the catalog finds by
            // it; a provider ID needs no lookup, and names a provider without listed offerings too.
            // Either reads the catalog by the provider, so none of its offerings is missing behind
            // 500 cheaper ones, and with any address (`ip=any`), so none that only has a shared IP
            // is missing. Signed when there is an account key, as the website's provider page is:
            // the private offerings its provider allows the account are listed too.
            let (provider_id, offerings) = match provider {
                ProviderReference::Id(provider_id) => (*provider_id, None),
                ProviderReference::Alias(alias) => {
                    let offerings: Vec<OfferingView> = api
                        .read_as_account(
                            &ListOfferings,
                            &format!("provider={alias}&ip=any&kind=any"),
                        )
                        .await?;
                    let Some(provider_id) = offerings.first().map(|offering| offering.provider_id)
                    else {
                        bail!(
                            "provider {alias} lists no offerings now; name it by its provider ID"
                        );
                    };
                    (provider_id, Some(offerings))
                }
            };
            let reliability = GetProviderReliability { provider_id };
            let reviews = ListProviderReviews { provider_id };
            let (reliability, reviews, offerings) = tokio::try_join!(
                api.read(&reliability, ""),
                api.read(&reviews, "limit=1"),
                async {
                    match offerings {
                        Some(offerings) => Ok(offerings),
                        // The catalog refuses a provider that is not active,
                        // which lists nothing.
                        None => match api
                            .read_as_account(
                                &ListOfferings,
                                &format!("provider={provider_id}&ip=any&kind=any"),
                            )
                            .await
                        {
                            Err(error)
                                if api::rejection(&error)
                                    .is_some_and(|rejection| rejection.status == 400) =>
                            {
                                Ok(Vec::new())
                            }
                            read => read,
                        },
                    }
                },
            )?;
            Ok(provider_record(
                provider_id,
                &reliability,
                &reviews,
                &offerings,
            ))
        }
        CatalogCommand::NetworkTest { host_id } => {
            let tests: gigahost_client_api::website::HostNetworkTestsView = api
                .read(&GetHostNetworkTests { host_id: *host_id }, "")
                .await?;
            to_value(tests)
        }
    }
}

/// A window for reading: `mon, thu 02:30 UTC for 4 h`.
fn agent_update_window_text(window: AgentUpdateWindow) -> String {
    const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
    let days: Vec<&str> = DAYS
        .iter()
        .enumerate()
        .filter(|(bit, _)| window.days & (1 << bit) != 0)
        .map(|(_, day)| *day)
        .collect();
    let (hours, minutes) = (window.minutes / 60, window.minutes % 60);
    format!(
        "{} {:02}:{:02} UTC for {}",
        days.join(", "),
        window.start_minute / 60,
        window.start_minute % 60,
        if minutes == 0 {
            format!("{hours} h")
        } else {
            format!("{hours} h {minutes} min")
        }
    )
}

/// One attempt for reading: its release, state and what it failed with.
fn agent_update_attempt_text(attempt: &AgentUpdateAttemptView) -> String {
    let mut text = format!("{} ({})", attempt.release, wire_name(attempt.state));
    if let Some(code) = &attempt.failure_code {
        let _ = write!(text, ": {code}");
    }
    if let Some(detail) = &attempt.detail {
        let _ = write!(text, ": {detail}");
    }
    text
}

/// A host's agent updates as `ghost provider agent-update` shows them: an
/// agent that cannot update itself says how to update it by hand. `--json`
/// keeps the API's answer.
fn agent_update_record(view: &HostAgentUpdateView) -> Value {
    let mut record = Map::new();
    let mut put = |key: &str, value: Value| {
        record.insert(key.to_owned(), value);
    };
    put("installed", json!(view.installed_release));
    if !view.remote_updates {
        put("update", json!("by hand"));
        put("install_command", json!(view.install_command));
    }
    if view.locally_disabled {
        put("remote_updates", json!("disabled on the host"));
    }
    if view.named_release_unavailable {
        put("channel", json!("names no single release: updates wait"));
    }
    put("channel_release", json!(view.channel_release));
    put(
        "target",
        json!(view.target.as_ref().map(agent_update_attempt_text)),
    );
    put("pending_approval", json!(view.pending_approval));
    put("policy", json!(wire_name(view.policy)));
    put("window", json!(view.window.map(agent_update_window_text)));
    put(
        "paused",
        match (view.paused, view.paused_until) {
            (false, _) => json!(false),
            (true, None) => json!(true),
            (true, Some(until)) => json!(format!("until {}", until.format("%Y-%m-%d %H:%M UTC"))),
        },
    );
    put(
        "last_failure",
        json!(view.last_failure.as_ref().map(agent_update_attempt_text)),
    );
    put(
        "history",
        view.history
            .iter()
            .map(|attempt| {
                json!({
                    "release": attempt.release,
                    "state": wire_name(attempt.state),
                    "failure_code": attempt.failure_code,
                    "created_at": attempt.created_at,
                    "finished_at": attempt.finished_at,
                })
            })
            .collect(),
    );
    Value::Object(record)
}

/// A provider as the catalog shows it: its name and the offerings it lists
/// now (the catalog's first 500 of that provider's), its rating
/// from its reviews' `summary`, and its `reliability`. A provider without
/// listed offerings has no name.
fn provider_record(
    provider_id: Uuid,
    reliability: &ProviderReliabilityView,
    reviews: &Value,
    offerings: &[OfferingView],
) -> Value {
    let listed: Vec<&OfferingView> = offerings
        .iter()
        .filter(|offering| offering.provider_id == provider_id)
        .collect();
    let mut hosts: Vec<Uuid> = listed
        .iter()
        .flat_map(|offering| offering.host_ids.iter().copied())
        .collect();
    hosts.sort_unstable();
    hosts.dedup();
    let mut locations: Vec<String> = listed
        .iter()
        .map(|offering| format!("{} ({})", offering.location, offering.location_name))
        .collect();
    locations.sort_unstable();
    locations.dedup();
    let mut host_modes: Vec<String> = listed
        .iter()
        .map(|offering| wire_name(offering.host_mode))
        .collect();
    host_modes.sort_unstable();
    host_modes.dedup();
    let mut reliability = json!(reliability);
    if let Some(map) = reliability.as_object_mut() {
        map.remove("provider_id");
    }
    let summary = &reviews["summary"];
    json!({
        "provider_id": provider_id,
        "name": listed.first().map(|offering| &offering.provider_name),
        "alias": listed
            .first()
            .map(|offering| &offering.provider_alias)
            .filter(|alias| !alias.is_empty()),
        "rating_millistars": summary["rating_millistars"],
        "review_count": summary["review_count"].as_u64().unwrap_or(0),
        "listed_offerings": listed.len(),
        "listed_hosts": hosts.len(),
        "host_modes": host_modes,
        "locations": locations,
        "reliability": reliability,
    })
}

/// Mark notifications read or unread. Marking is idempotent, so a repeat
/// needs no key.
async fn execute_notification(api: &ApiClient, command: &NotificationCommand) -> Result<Value> {
    use gigahost_client_api::{
        api::{MarkNotificationsRead, SetNotificationRead},
        website::{NotificationsReadView, SetNotificationReadRequest},
    };
    let set = async |notification_id: Uuid, read: bool| -> Result<UserNotificationView> {
        api.write(
            &SetNotificationRead { notification_id },
            &SetNotificationReadRequest { read },
            None,
        )
        .await
    };
    match command {
        NotificationCommand::MarkRead { all: true, .. } => {
            let marked: NotificationsReadView =
                api.write(&MarkNotificationsRead, &(), None).await?;
            to_value(marked)
        }
        NotificationCommand::MarkRead {
            notification_ids, ..
        } => {
            let mut marked = Vec::with_capacity(notification_ids.len());
            for notification_id in notification_ids {
                marked.push(set(*notification_id, true).await?);
            }
            to_value(marked)
        }
        NotificationCommand::MarkUnread { notification_id } => {
            to_value(set(*notification_id, false).await?)
        }
    }
}

/// The ID of `address` in the provider's pool `pool`.
async fn pool_address_id(api: &ApiClient, pool: Uuid, address: Ipv4Addr) -> Result<Uuid> {
    let pools: Vec<CloudIpPoolView> = api.read(&ListIpPools, "").await?;
    pools
        .iter()
        .find(|candidate| candidate.pool_id == pool)
        .and_then(|candidate| {
            candidate
                .addresses
                .iter()
                .find(|candidate| candidate.address == address.to_string())
        })
        .map(|candidate| candidate.address_id)
        .with_context(|| format!("address {address} was not found in pool {pool}"))
}

/// A host's agent updates. The API replaces a policy whole and names an
/// attempt by its ID, so each change reads the host first. A retry of a
/// command under its key names the same attempt and sends the same policy,
/// and gets the first answer again.
async fn execute_agent_update(
    api: &ApiClient,
    command: &ProviderAgentUpdateCommand,
) -> Result<Value> {
    const SAME: AgentUpdateChange = AgentUpdateChange {
        policy: None,
        window: WindowChange::Keep,
    };
    let read = async |host_id: Uuid| -> Result<HostAgentUpdateView> {
        api.read(&GetHostAgentUpdate { host_id }, "").await
    };
    let policy = async |host_id: Uuid,
                        change: AgentUpdateChange,
                        paused: Option<(bool, Option<DateTime<Utc>>)>,
                        mutation: &IdempotencyArgs|
           -> Result<Value> {
        let request = agent_update_policy_request(&read(host_id).await?, &change, paused)?;
        let view: HostAgentUpdateView = api
            .write_retryable(
                &SetHostAgentUpdatePolicy { host_id },
                &request,
                &mutation.key(),
            )
            .await?;
        to_value(view)
    };
    match command {
        ProviderAgentUpdateCommand::Show { host_id } => to_value(read(*host_id).await?),
        ProviderAgentUpdateCommand::Set {
            host_id,
            policy: choice,
            days,
            start,
            hours,
            clear_window,
            mutation,
        } => {
            let window = named_window(days, *start, *hours);
            if choice.is_none() && window.is_none() && !clear_window {
                bail!("name what to change: --policy, a window or --clear-window");
            }
            let change = AgentUpdateChange {
                policy: choice.map(Into::into),
                window: match window {
                    Some(window) => WindowChange::Set(window),
                    None if *clear_window => WindowChange::Clear,
                    None => WindowChange::Keep,
                },
            };
            policy(*host_id, change, None, mutation).await
        }
        ProviderAgentUpdateCommand::Pause {
            host_id,
            until,
            mutation,
        } => policy(*host_id, SAME, Some((true, *until)), mutation).await,
        ProviderAgentUpdateCommand::Resume { host_id, mutation } => {
            policy(*host_id, SAME, Some((false, None)), mutation).await
        }
        ProviderAgentUpdateCommand::Approve {
            host_id,
            release,
            mutation,
        } => {
            let view: HostAgentUpdateView = api
                .write_retryable(
                    &ApproveHostAgentUpdate { host_id: *host_id },
                    &ApproveAgentUpdateRequest {
                        release: release.clone(),
                    },
                    &mutation.key(),
                )
                .await?;
            to_value(view)
        }
        ProviderAgentUpdateCommand::Retry { host_id, mutation } => {
            let view = read(*host_id).await?;
            let update_id = retryable_attempt(&view, mutation.has_key())?;
            let view: HostAgentUpdateView = api
                .write_retryable(
                    &RetryHostAgentUpdate { host_id: *host_id },
                    &AgentUpdateAttemptRequest { update_id },
                    &mutation.key(),
                )
                .await?;
            to_value(view)
        }
        ProviderAgentUpdateCommand::Cancel { host_id, mutation } => {
            let view = read(*host_id).await?;
            let update_id = cancellable_attempt(&view, mutation.has_key())?;
            let view: HostAgentUpdateView = api
                .write_retryable(
                    &CancelHostAgentUpdate { host_id: *host_id },
                    &AgentUpdateAttemptRequest { update_id },
                    &mutation.key(),
                )
                .await?;
            to_value(view)
        }
    }
}

/// The attempt `ghost provider agent-update retry` names: the host's newest,
/// the only one the backend takes, once it failed or was rolled back; or, for
/// a retry under its key, the failure that command tried again, which a newer
/// attempt follows by then.
fn retryable_attempt(view: &HostAgentUpdateView, retrying: bool) -> Result<Uuid> {
    let Some(failed) = &view.last_failure else {
        bail!("no update of this host failed");
    };
    let newest = view.history.first().map(|attempt| attempt.update_id);
    if !retrying && newest != Some(failed.update_id) {
        bail!("the newest update of this host did not fail");
    }
    Ok(failed.update_id)
}

/// The attempt `ghost provider agent-update cancel` names: the one on its
/// way, or, for a retry under its key, the one that command cancelled.
fn cancellable_attempt(view: &HostAgentUpdateView, retrying: bool) -> Result<Uuid> {
    if let Some(target) = &view.target
        && target.state == AgentUpdateState::Applying
    {
        bail!("the update is being applied, so it cannot be cancelled");
    }
    view.target
        .as_ref()
        .or_else(|| {
            view.history
                .first()
                .filter(|attempt| retrying && attempt.state == AgentUpdateState::Cancelled)
        })
        .map(|attempt| attempt.update_id)
        .context("this host has no update on its way")
}

async fn execute_provider(api: &ApiClient, command: &ProviderCommand) -> Result<Value> {
    match command {
        ProviderCommand::Pricing { host_id } => {
            let mut pricing = api
                .read(&GetHostPricing { host_id: *host_id }, "")
                .await
                .and_then(to_value)?;
            // No fixed price per instance: a backend still answers it, as 0, for clients of before.
            if let Some(values) = pricing.get_mut("values").and_then(Value::as_object_mut)
                && values
                    .get("fixed_instance_earnings_microusd_per_month")
                    .and_then(Value::as_u64)
                    == Some(0)
            {
                values.remove("fixed_instance_earnings_microusd_per_month");
            }
            Ok(pricing)
        }
        ProviderCommand::SetPricing {
            host_id,
            expected_revision,
            file,
            address_earnings_microusd,
            reason,
            mutation,
        } => {
            let mut values = host_pricing_input(&read_text_file(file)?)?;
            if let Some(address) = address_earnings_microusd {
                values.address_earnings_microusd_per_month = Some(*address);
            }
            api.write_retryable(
                &UpdateHostPricing { host_id: *host_id },
                &gigahost_client_api::website::UpdateHostPricingRequest {
                    expected_revision: *expected_revision,
                    values,
                    change_reason: reason.clone(),
                },
                &mutation.key(),
            )
            .await
            .and_then(to_value)
        }
        ProviderCommand::Balance => {
            let balance: Option<ProviderBalanceView> = api.read(&GetProviderBalance, "").await?;
            to_value(balance)
        }
        ProviderCommand::SetPayoutAddress { address } => {
            // Setting the same address again changes nothing, so a retry
            // needs no idempotency key.
            let address: ProviderPayoutAddressView = api
                .write(
                    &SetPayoutAddress,
                    &SetProviderPayoutAddressRequest {
                        address: address.clone(),
                    },
                    None,
                )
                .await?;
            to_value(address)
        }
        ProviderCommand::Payouts => {
            let payouts: Vec<ProviderPayoutView> = api.read(&ListPayouts, "").await?;
            to_value(payouts)
        }
        ProviderCommand::Payout {
            amount_microusd,
            mutation,
        } => {
            let payout: ProviderPayoutView = api
                .write_retryable(
                    &CreatePayout,
                    &CreateProviderPayoutRequest {
                        amount_microusd: *amount_microusd,
                    },
                    &mutation.key(),
                )
                .await?;
            to_value(payout)
        }
        ProviderCommand::Hosts { .. } => {
            let hosts: Vec<ProviderHostView> = api.read(&ListProviderHosts, "").await?;
            to_value(hosts)
        }
        ProviderCommand::Host {
            command: None,
            host_id,
        } => {
            let Some(host_id) = *host_id else {
                bail!("name a host, `ghost provider host <HOST_ID>`, or a subcommand");
            };
            let host: ProviderHostDetailView = api.read(&GetProviderHost { host_id }, "").await?;
            to_value(host)
        }
        ProviderCommand::Host {
            command: Some(command),
            ..
        } => match command {
            ProviderHostCommand::Get { host_id } => {
                let host: ProviderHostDetailView =
                    api.read(&GetProviderHost { host_id: *host_id }, "").await?;
                to_value(host)
            }
            ProviderHostCommand::Metrics {
                host_id,
                resolution,
                page,
            } => api
                .read(
                    &GetProviderHostMetrics { host_id: *host_id },
                    &format!("resolution={resolution}&{}", page.query()),
                )
                .await
                .and_then(to_value),
            ProviderHostCommand::InstanceUsage {
                host_id,
                instance_id,
                resolution,
                page,
            } => api
                .read(
                    &GetProviderHostInstanceUsage {
                        host_id: *host_id,
                        instance_id: *instance_id,
                    },
                    &format!("resolution={resolution}&{}", page.query()),
                )
                .await
                .and_then(to_value),
            ProviderHostCommand::Pause { host_id, mutation }
            | ProviderHostCommand::Resume { host_id, mutation } => {
                let paused = matches!(command, ProviderHostCommand::Pause { .. });
                let host: ProviderHostView = api
                    .write_retryable(
                        &SetHostRentalAdmission { host_id: *host_id },
                        &SetHostRentalPauseRequest { paused },
                        &mutation.key(),
                    )
                    .await?;
                to_value(host)
            }
            ProviderHostCommand::Private {
                host_id,
                yes,
                mutation,
            } => {
                let privacy: HostPrivacyView =
                    api.read(&GetHostPrivacy { host_id: *host_id }, "").await?;
                if !privacy.private
                    && !yes
                    && let Some(kept) =
                        kept_words(privacy.kept_instances, privacy.kept_local_backups)
                {
                    bail!(
                        "{kept} of accounts you do not allow are on this host and stay there: they run, reinstall and are billed as before, and only their new instances are refused; repeat with --yes to make it private"
                    );
                }
                let privacy: HostPrivacyView = api
                    .write_retryable(
                        &SetHostPrivate { host_id: *host_id },
                        &SetHostPrivateRequest { private: true },
                        &mutation.key(),
                    )
                    .await?;
                to_value(privacy)
            }
            ProviderHostCommand::Public { host_id, mutation } => {
                let privacy: HostPrivacyView = api
                    .write_retryable(
                        &SetHostPrivate { host_id: *host_id },
                        &SetHostPrivateRequest { private: false },
                        &mutation.key(),
                    )
                    .await?;
                to_value(privacy)
            }
            ProviderHostCommand::CheckPath { host_id, mutation } => {
                let host: ProviderHostView = api
                    .write_retryable(
                        &CheckHostPublicPath { host_id: *host_id },
                        &(),
                        &mutation.key(),
                    )
                    .await?;
                to_value(host)
            }
            ProviderHostCommand::Delete {
                host_id,
                yes,
                mutation,
            } => {
                if !yes {
                    bail!(
                        "host deletion permanently retires its enrollment identity; repeat with --yes after all rentals are gone"
                    );
                }
                let host: ProviderHostView = api
                    .write_retryable(&RetireHost { host_id: *host_id }, &(), &mutation.key())
                    .await?;
                Ok(json!({
                    "host": host,
                    "next_step": "Stop the hypervisor service, then run `gigahost-hypervisor reset-enrollment --config PATH --yes` on that host before enrolling it again with a new token."
                }))
            }
            ProviderHostCommand::Retire {
                host_id,
                notice_days,
                yes,
                mutation,
            } => {
                if !yes {
                    bail!(
                        "noticed retirement will delete every remaining VM after the deadline; repeat with --yes"
                    );
                }
                if *notice_days < 7 {
                    refuse!(
                        "invalid_request",
                        "noticed retirement requires at least 7 full days"
                    );
                }
                let host: ProviderHostView = api
                    .write_retryable(
                        &ScheduleHostRetirement { host_id: *host_id },
                        &ScheduleHostRetirementRequest {
                            notice_period_days: *notice_days,
                        },
                        &mutation.key(),
                    )
                    .await?;
                to_value(host)
            }
            ProviderHostCommand::Emergency {
                host_id,
                reason,
                yes,
                mutation,
            } => {
                if !yes {
                    bail!(
                        "an emergency declaration immediately abandons every active rental and revokes the host; repeat with --yes"
                    );
                }
                let host: ProviderHostView = api
                    .write_retryable(
                        &DeclareHostEmergency { host_id: *host_id },
                        &DeclareHostEmergencyRequest {
                            reason: reason.clone(),
                        },
                        &mutation.key(),
                    )
                    .await?;
                to_value(host)
            }
        },
        ProviderCommand::PrivateRenters { command } => match command {
            ProviderPrivateRentersCommand::List => {
                let renters: Vec<PrivateRenterView> = api.read(&ListPrivateRenters, "").await?;
                to_value(renters)
            }
            ProviderPrivateRentersCommand::Add { alias, mutation } => {
                let renter: PrivateRenterView = api
                    .write_retryable(
                        &AddPrivateRenter,
                        &AddPrivateRenterRequest {
                            alias: alias.clone(),
                        },
                        &mutation.key(),
                    )
                    .await?;
                to_value(renter)
            }
            ProviderPrivateRentersCommand::Remove {
                alias,
                yes,
                mutation,
            } => {
                if !yes {
                    let renters: Vec<PrivateRenterView> = api.read(&ListPrivateRenters, "").await?;
                    if let Some(kept) = renters
                        .iter()
                        .find(|renter| renter.account_alias.eq_ignore_ascii_case(alias.trim()))
                        .and_then(|renter| {
                            kept_words(renter.kept_instances, renter.kept_local_backups)
                        })
                    {
                        bail!(
                            "{kept} of {alias} are on your private hosts and stay there: they run, reinstall and are billed as before, and only its new instances are refused; repeat with --yes to remove it"
                        );
                    }
                }
                let renter: PrivateRenterView = api
                    .write_retryable(
                        &RemovePrivateRenter {
                            alias: alias.trim().to_owned(),
                        },
                        &(),
                        &mutation.key(),
                    )
                    .await?;
                to_value(renter)
            }
        },
        ProviderCommand::AgentUpdate { command } => execute_agent_update(api, command)
            .await
            .map_err(|error| api::reword_conflict(error, "this host cannot take that update now")),
        ProviderCommand::RetireInstance {
            instance_id,
            notice_days,
            reason,
            yes,
            mutation,
        } => {
            if !yes {
                bail!(
                    "instance retirement schedules provider-initiated deletion; repeat with --yes"
                );
            }
            if *notice_days < 7 {
                refuse!(
                    "invalid_request",
                    "instance retirement requires at least 7 full days"
                );
            }
            let notice: gigahost_client_api::website::InstanceProviderTerminationView = api
                .write_retryable(
                    &ScheduleInstanceRetirement {
                        instance_id: *instance_id,
                    },
                    &ScheduleInstanceRetirementRequest {
                        notice_period_days: *notice_days,
                        reason: reason.clone(),
                    },
                    &mutation.key(),
                )
                .await?;
            to_value(notice)
        }
        ProviderCommand::IpPools => {
            let pools: Vec<CloudIpPoolView> = api.read(&ListIpPools, "").await?;
            to_value(pools)
        }
        ProviderCommand::IpPool { command } => match command {
            ProviderIpPoolCommand::Create {
                label,
                scope,
                host_ids,
                mutation,
            } => {
                let request = CreateCloudIpPoolRequest {
                    label: label.clone(),
                    scope: *scope,
                    host_ids: host_ids.clone(),
                };
                let pool: CloudIpPoolView = api
                    .write_retryable(&CreateIpPool, &request, &mutation.key())
                    .await?;
                to_value(pool)
            }
            ProviderIpPoolCommand::HandOver {
                pool_id,
                host,
                mutation,
            } => {
                let pool: CloudIpPoolView = api
                    .write_retryable(
                        &HandOverIpPool { pool_id: *pool_id },
                        &HandOverCloudIpPoolRequest { host_id: *host },
                        &mutation.key(),
                    )
                    .await?;
                to_value(pool)
            }
            ProviderIpPoolCommand::Delete {
                pool_id,
                yes,
                mutation,
            } => {
                if !yes {
                    bail!("pool deletion is permanent; repeat with --yes");
                }
                let pool: CloudIpPoolView = api
                    .write_retryable(&DeleteIpPool { pool_id: *pool_id }, &(), &mutation.key())
                    .await?;
                to_value(pool)
            }
        },
        ProviderCommand::Ip { command } => match command {
            ProviderIpCommand::Add {
                pool,
                addresses,
                prefix_length,
                gateway,
                mac_address,
                mutation,
            } => {
                let request = AddCloudIpAddressesRequest {
                    addresses: addresses
                        .iter()
                        .map(|address| CloudIpAddressInput {
                            address: address.to_string(),
                            gateway: gateway.map(|gateway| gateway.to_string()),
                            prefix_length: *prefix_length,
                            mac_address: mac_address.clone(),
                        })
                        .collect(),
                };
                let pool: CloudIpPoolView = api
                    .write_retryable(
                        &AddIpAddresses { pool_id: *pool },
                        &request,
                        &mutation.key(),
                    )
                    .await?;
                to_value(pool)
            }
            ProviderIpCommand::Check {
                pool,
                address,
                mutation,
            } => {
                let address_id = pool_address_id(api, *pool, *address).await?;
                let pool: CloudIpPoolView = api
                    .write_retryable(
                        &CheckIpAddress {
                            pool_id: *pool,
                            address_id,
                        },
                        &(),
                        &mutation.key(),
                    )
                    .await?;
                to_value(pool)
            }
            ProviderIpCommand::Remove {
                pool,
                address,
                yes,
                mutation,
            } => {
                if !yes {
                    bail!("IP removal stops future allocation; repeat with --yes");
                }
                let address_id = pool_address_id(api, *pool, *address).await?;
                let pool: CloudIpPoolView = api
                    .write_retryable(
                        &RemoveIpAddress {
                            pool_id: *pool,
                            address_id,
                        },
                        &(),
                        &mutation.key(),
                    )
                    .await?;
                to_value(pool)
            }
        },
        ProviderCommand::Incidents { state, severity } => {
            let mut parameters = Vec::new();
            if let Some(state) = state {
                parameters.push(format!("state={}", wire_name(state)));
            }
            if let Some(severity) = severity {
                parameters.push(format!("severity={}", wire_name(severity)));
            }
            let incidents: Vec<ProviderIncidentView> =
                api.read(&ListIncidents, &parameters.join("&")).await?;
            to_value(incidents)
        }
        ProviderCommand::Uptime {
            host,
            after,
            limit,
            retired,
        } => {
            let mut parameters = Vec::new();
            if let Some(host) = host {
                parameters.push(format!("host={host}"));
            }
            if let Some(after) = after {
                parameters.push(format!("after={after}"));
            }
            if let Some(limit) = limit {
                parameters.push(format!("limit={limit}"));
            }
            if *retired {
                parameters.push("retired=true".to_owned());
            }
            let uptime: ProviderUptimeView =
                api.read(&GetProviderUptime, &parameters.join("&")).await?;
            to_value(uptime)
        }
        ProviderCommand::Outages {
            host,
            from,
            to,
            cursor,
            limit,
        } => {
            let mut url = reqwest::Url::parse("https://api.gigahost.cloud/").expect("static URL");
            let mut query = url.query_pairs_mut();
            if let Some(host) = host {
                query.append_pair("host", &host.to_string());
            }
            if let Some(from) = from {
                query.append_pair("from", &from.to_string());
            }
            if let Some(to) = to {
                query.append_pair("to", &to.to_string());
            }
            if let Some(cursor) = cursor {
                query.append_pair("cursor", cursor);
            }
            if let Some(limit) = limit {
                query.append_pair("limit", &limit.to_string());
            }
            drop(query);
            let outages: ProviderOutagePage = api
                .read(&ListProviderOutages, url.query().unwrap_or_default())
                .await?;
            to_value(outages)
        }
        ProviderCommand::Outage { outage_id } => {
            let outage: ProviderOutageDetailView = api
                .read(
                    &GetProviderOutage {
                        outage_id: *outage_id,
                    },
                    "",
                )
                .await?;
            to_value(outage)
        }
        ProviderCommand::Incident { command } => match command {
            ProviderIncidentCommand::Get { incident_id } => {
                let incident: ProviderIncidentView = api
                    .read(
                        &GetIncident {
                            incident_id: *incident_id,
                        },
                        "",
                    )
                    .await?;
                to_value(incident)
            }
            ProviderIncidentCommand::Acknowledge {
                incident_id,
                mutation,
            }
            | ProviderIncidentCommand::Resolve {
                incident_id,
                mutation,
            } => {
                let state = if matches!(command, ProviderIncidentCommand::Acknowledge { .. }) {
                    ProviderIncidentState::Acknowledged
                } else {
                    ProviderIncidentState::Resolved
                };
                let incident: ProviderIncidentView = api
                    .write_retryable(
                        &SetIncidentState {
                            incident_id: *incident_id,
                        },
                        &SetProviderIncidentStateRequest { state },
                        &mutation.key(),
                    )
                    .await?;
                to_value(incident)
            }
        },
    }
}

/// A new website password for the account `account_alias`, drawn from
/// `rng`, and the request that sets it: only the public key derived from
/// it ([`gigahost_client_api::website_password::signing_key`]).
fn website_password_request(
    account_alias: &str,
    expires_in_days: Option<u32>,
    rng: &mut impl rand_core::CryptoRngCore,
) -> (String, SetWebsitePasswordRequest) {
    let password = website_password::generate(rng);
    let public_key = website_password::signing_key(account_alias, &password).verifying_key();
    (
        password,
        SetWebsitePasswordRequest {
            public_key: URL_SAFE_NO_PAD.encode(public_key.as_bytes()),
            expires_in_days,
        },
    )
}

async fn execute_account(cli: &Cli, api: &ApiClient, command: &AccountCommand) -> Result<Value> {
    match command {
        AccountCommand::Review {
            provider_id,
            rating,
            message,
            expected_revision,
        } => {
            api.write(
                &WriteProviderReview {
                    provider_id: *provider_id,
                },
                &gigahost_client_api::website::WriteProviderReviewRequest {
                    expected_revision: *expected_revision,
                    rating: *rating,
                    body: message.clone(),
                },
                Some(&*fresh_idempotency_key()),
            )
            .await
        }
        AccountCommand::Approve { intent_id, yes } => {
            approve_browser_operation(cli, api, *intent_id, *yes).await
        }
        AccountCommand::History(LedgerHistoryArgs {
            instance,
            kind,
            page,
        }) => {
            let instance =
                resolve_optional_instance(api, instance.as_ref(), InstanceUse::Read).await?;
            let filters = [
                ("instance_id", instance.map(|id| id.to_string())),
                ("kind", kind.map(wire_name)),
            ]
            .into_iter()
            .filter_map(|(name, value)| Some((name, value?)))
            .collect::<Vec<_>>();
            let page: gigahost_client_api::website::HistoryPage = api
                .read(&AccountHistory, &page.query_after(&filters))
                .await?;
            to_value(page)
        }
        AccountCommand::Deposits(page) | AccountCommand::SlaCredits(page) => {
            let query = page.query();
            let page = match command {
                AccountCommand::Deposits(_) => api.read(&AccountDeposits, &query).await?,
                _ => api.read(&AccountSlaCredits, &query).await?,
            };
            to_value(page)
        }
        AccountCommand::Show => {
            let account: AccountView = api.read(&GetAccount, "").await?;
            // `github` stays the object the API answers (`login`,
            // `linked_at`); only the readable form turns it into one line
            // ([`readable_sections`]).
            let mut shown = to_value(account)?;
            // A trial shows its credit and limits; the balance is only
            // read for them, so a failure to read it hides nothing else.
            if let Ok(AccountBalanceView {
                trial: Some(trial), ..
            }) = api.read::<GetAccountBalance>(&GetAccountBalance, "").await
                && let Some(fields) = shown.as_object_mut()
            {
                fields.insert("trial".to_owned(), to_value(&trial)?);
                if trial.limited {
                    fields.insert("trial_note".to_owned(), json!(TRIAL_LIMITS));
                }
            }
            Ok(shown)
        }
        AccountCommand::Signup { github: _, no_wait } => {
            let seed = load_account_seed(cli)?;
            let summary = keys::key_summary(&seed)?;
            notice(&signup_terms_line("signing up"));
            let request = ActivateAccountRequest {
                authentication_public_key: summary.authentication_public_key,
                billing_public_key: summary.billing_verifying_key,
                recovery_public_key: summary.recovery_public_key,
            };
            // A claim of a key replaces the one before it, so a repeated
            // command needs a key of its own.
            let claim: TrialClaimView = api
                .write(
                    &CreateGithubSignup,
                    &request,
                    Some(&*Uuid::now_v7().to_string()),
                )
                .await?;
            if *no_wait {
                return to_value(claim);
            }
            let status = follow_github_claim(cli, api, &claim, GithubClaimUse::Signup).await?;
            let trial = match api.read(&GetAccountBalance, "").await {
                Ok(AccountBalanceView { trial, .. }) => trial,
                Err(_) => None,
            };
            notice(&format!(
                "Account created, signed up with GitHub {}.",
                github_login_label(&status)
            ));
            if status.trial_credit {
                github_credit_notice(&status);
                notice(&trial_limit_lines());
                notice("To see what a trial can rent: ghost catalog offerings --ip shared");
            } else {
                notice(&signup_without_credit(&status, &summary.deposit_memo));
            }
            Ok(json!({
                "status": "created",
                "account_alias": status.account_alias,
                "github_login": status.github_login,
                "trial_credit": status.trial_credit,
                "trial_credit_refusal": status.trial_credit_refusal,
                "deposit_memo": summary.deposit_memo,
                "trial": trial,
            }))
        }
        AccountCommand::LinkGithub { no_wait } => {
            let claim: TrialClaimView = api
                .write(&CreateGithubLink, &(), Some(&*Uuid::now_v7().to_string()))
                .await?;
            if *no_wait {
                return to_value(claim);
            }
            let status = follow_github_claim(cli, api, &claim, GithubClaimUse::Link).await?;
            notice(&format!("Linked {}.", github_login_label(&status)));
            github_credit_notice(&status);
            Ok(json!({
                "status": "linked",
                "account_alias": status.account_alias,
                "github_login": status.github_login,
                "trial_credit": status.trial_credit,
                "trial_credit_refusal": status.trial_credit_refusal,
            }))
        }
        AccountCommand::UnlinkGithub { yes } => {
            if !yes {
                bail!(
                    "unlinking ends the website sessions a GitHub login began and stops `Log in with GitHub` for this account; repeat with --yes"
                );
            }
            let unlinked: GithubUnlinked = api
                .write(&UnlinkGithub, &(), Some(&*Uuid::now_v7().to_string()))
                .await?;
            if unlinked.unlinked {
                notice(&format!(
                    "Unlinked; {} GitHub session(s) ended.",
                    unlinked.ended_sessions
                ));
            } else {
                notice("No GitHub account was linked.");
            }
            to_value(unlinked)
        }
        AccountCommand::GithubStatus { claim_id } => {
            // The claim's name goes into the route's path: only what a
            // claim's name can be, so no other route is reached.
            if !(1..=64).contains(&claim_id.len())
                || !claim_id
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
            {
                bail!("a GitHub claim's ID is 1 to 64 letters, digits, - and _");
            }
            let status: TrialClaimStatusView = api
                .read(
                    &GetGithubClaim {
                        claim_id: claim_id.clone(),
                    },
                    "",
                )
                .await?;
            to_value(status)
        }
        AccountCommand::ActivationTerms => {
            let terms: AccountActivationTerms = api.read(&GetActivationTerms, "").await?;
            to_value(terms)
        }
        AccountCommand::Activate => {
            let seed = load_account_seed(cli)?;
            let summary = keys::key_summary(&seed)?;
            notice(&signup_terms_line("activating the account"));
            let request = ActivateAccountRequest {
                authentication_public_key: summary.authentication_public_key,
                billing_public_key: summary.billing_verifying_key,
                recovery_public_key: summary.recovery_public_key,
            };
            let account: AccountView = api
                .write(
                    &ActivateAccount,
                    &request,
                    Some(&*format!("activate:{}", summary.deposit_memo)),
                )
                .await?;
            to_value(account)
        }
        AccountCommand::Balance => {
            let balance: AccountBalanceView = api.read(&GetAccountBalance, "").await?;
            to_value(balance)
        }
        AccountCommand::Notifications { command: None } => {
            let notifications: Vec<UserNotificationView> = api.read(&ListNotifications, "").await?;
            to_value(notifications)
        }
        AccountCommand::Notifications {
            command: Some(command),
        } => execute_notification(api, command).await,
        AccountCommand::Login => {
            let grant: LoginGrant = api
                .write(&CreateLoginGrant, &(), Some(&*Uuid::now_v7().to_string()))
                .await?;
            to_value(grant)
        }
        AccountCommand::SetPassword { expires_in, .. } => {
            let account: AccountView = api.read(&GetAccount, "").await?;
            let (password, request) = website_password_request(
                &account.account_alias,
                *expires_in,
                &mut rand_core::OsRng,
            );
            // A retry sends the same key, which the backend takes as set.
            let set: WebsitePasswordView = api
                .write(
                    &SetWebsitePassword,
                    &request,
                    Some(&*Uuid::now_v7().to_string()),
                )
                .await?;
            Ok(json!({
                "account_alias": account.account_alias,
                "password": password,
                "created_at": set.created_at,
                "expires_at": set.expires_at,
                "note": "The password is shown only this once; keep it in a password manager.",
            }))
        }
        AccountCommand::RemovePassword => {
            let removed: WebsitePasswordRemoved =
                api.write(&RemoveWebsitePassword, &(), None).await?;
            to_value(removed)
        }
        AccountCommand::RevokeSessions => {
            let revocation: SessionRevocationView = api.write(&RevokeSessions, &(), None).await?;
            to_value(revocation)
        }
        AccountCommand::Sessions => {
            let sessions: Vec<ActiveSessionView> = api.read(&ListSessions, "").await?;
            to_value(sessions)
        }
        AccountCommand::RevokeSession { session_id } => {
            let revocation: SessionRevocationView = api
                .write(
                    &RevokeSession {
                        session_id: *session_id,
                    },
                    &(),
                    None,
                )
                .await?;
            to_value(revocation)
        }
        AccountCommand::AuthKeys => {
            let keys: Vec<AccountAuthKeyView> = api.read(&ListAuthKeys, "").await?;
            to_value(keys)
        }
        AccountCommand::Protection { command } => {
            let protected_balance_microusd = match command {
                ProtectionCommand::Set { usd } => Some(*usd),
                ProtectionCommand::Default => None,
            };
            let view: gigahost_client_api::website::ProtectedBalanceView = api
                .write(
                    &gigahost_client_api::api::SetProtectedBalance,
                    &gigahost_client_api::website::SetProtectedBalanceRequest {
                        protected_balance_microusd,
                    },
                    None,
                )
                .await?;
            to_value(view)
        }
        AccountCommand::SshKeys { command } => match command {
            SshKeyCommand::List => {
                let keys: Vec<gigahost_client_api::website::AccountSshKeyView> = api
                    .read(&gigahost_client_api::api::ListAccountSshKeys, "")
                    .await?;
                to_value(keys)
            }
            SshKeyCommand::Add { label, file, key } => {
                // Read and checked as --ssh-key and --ssh-key-file are: a
                // private key never leaves this machine.
                let keys = load_ssh_keys(
                    &key.iter().cloned().collect::<Vec<_>>(),
                    &file.iter().cloned().collect::<Vec<_>>(),
                )?;
                let [public_key] = keys.as_slice() else {
                    refuse!(
                        "invalid_request",
                        "give exactly one public key: a file holding one line, or --key"
                    );
                };
                let saved: gigahost_client_api::website::AccountSshKeyView = api
                    .write(
                        &gigahost_client_api::api::AddAccountSshKey,
                        &gigahost_client_api::website::AddAccountSshKeyRequest {
                            label: label.clone(),
                            public_key: public_key.clone(),
                        },
                        Some(&*Uuid::now_v7().to_string()),
                    )
                    .await?;
                to_value(saved)
            }
            SshKeyCommand::Remove { ssh_key_id } => {
                let removed: gigahost_client_api::website::AccountSshKeyView = api
                    .write(
                        &gigahost_client_api::api::RemoveAccountSshKey {
                            ssh_key_id: *ssh_key_id,
                        },
                        &(),
                        None,
                    )
                    .await?;
                to_value(removed)
            }
        },
        AccountCommand::MigrateSeed { new_seed_file, yes } => {
            if !yes {
                bail!(
                    "account key migration revokes all existing keys and sessions; back up both account keys and repeat with --yes"
                );
            }
            let old_seed = load_account_seed(cli)?;
            let old_identity = keys::authentication_identity(&old_seed)?;
            let new_seed = keys::load_seed(new_seed_file).with_context(|| {
                format!("load replacement account key {}", new_seed_file.display())
            })?;
            let new_identity = keys::authentication_identity(&new_seed)?;
            let summary = keys::key_summary(&new_seed)?;
            let canonical = canonical_seed_migration(&SeedMigrationInput {
                current_deposit_memo: &old_identity.deposit_memo,
                new_deposit_memo: &new_identity.deposit_memo,
                new_authentication_public_key: &summary.authentication_public_key,
                new_billing_public_key: &summary.billing_verifying_key,
                new_recovery_public_key: &summary.recovery_public_key,
            });
            let request = MigrateAccountSeedRequest {
                new_authentication_public_key: summary.authentication_public_key,
                new_billing_public_key: summary.billing_verifying_key,
                new_recovery_public_key: summary.recovery_public_key,
                new_key_signature: URL_SAFE_NO_PAD.encode(new_identity.sign(&canonical).to_bytes()),
            };
            let account: AccountView = api
                .write(
                    &MigrateAccountSeed,
                    &request,
                    Some(&*Uuid::now_v7().to_string()),
                )
                .await?;
            Ok(json!({
                "account": account,
                "replacement_seed_file": new_seed_file,
                "warning": "The old account key is revoked for account authentication. Select the replacement with --seed-file or GHOST_SEED_FILE; retain the old account key while it protects any existing backups."
            }))
        }
        AccountCommand::GetHostEnrollmentToken { label } => {
            notice(&provider_terms_line());
            let request = CreateHostEnrollmentTokenRequest {
                label: label.clone(),
            };
            let token: HostEnrollmentToken = api
                .write(
                    &CreateHostEnrollmentToken,
                    &request,
                    Some(&*Uuid::now_v7().to_string()),
                )
                .await?;
            to_value(token)
        }
    }
}

/// A website request of a kind a newer backend added.
const UNKNOWN_OPERATION: &str = "this website request is of a kind this release of ghost does not know; update ghost and approve it again";

async fn approve_browser_operation(
    cli: &Cli,
    api: &ApiClient,
    id: Uuid,
    yes: bool,
) -> Result<Value> {
    use gigahost_client_api::website::{BrowserOperation, BrowserOperationView};
    let intent: BrowserOperationView = api.read(&GetOperationIntent { id }, "").await?;
    if intent.completed_job_id.is_some() {
        return to_value(intent);
    }
    if matches!(intent.operation, BrowserOperation::Unknown) {
        refuse!("invalid_request", "{UNKNOWN_OPERATION}");
    }
    if intent.expires_at <= Utc::now() && intent.started_job_id.is_none() {
        refuse!(
            "invalid_request",
            "this website request has expired; create a new one on the website"
        );
    }
    if !yes {
        if !cli.globals.compact {
            quote_operation(api, id, &intent.operation).await?;
        }
        // The quote goes to standard error before this notice is read only
        // where the result is shown for reading; JSON is read by a program,
        // and `--compact` prints no quote at all.
        let notice = approval_notice(
            &intent.operation,
            cli.output_format() == OutputFormat::Readable,
        );
        return Ok(
            json!({"request":intent,"approve_command":format!("ghost account approve {id} --yes"),"notice":notice}),
        );
    }
    let mutation = MutationArgs {
        idempotency: IdempotencyArgs {
            idempotency_key: None,
        },
        wait: false,
        poll_seconds: 2,
        browser_intent: Some(id),
    };
    let result = if let Some(job_id) = intent.started_job_id {
        let job: JobView = api.read(&GetJob { job_id }, "").await?;
        let accepted = JobAccepted {
            job_id,
            resource_id: job.resource_id,
            status_url: format!("/v1/jobs/{job_id}"),
        };
        let (destination_instance_id, backup_id) = match &intent.operation {
            BrowserOperation::RestoreBackup {
                instance_id,
                backup_id,
            } => (*instance_id, *backup_id),
            BrowserOperation::CreateFromBackup { backup_id, .. } => (job.resource_id, *backup_id),
            BrowserOperation::Unknown => refuse!("invalid_request", "{UNKNOWN_OPERATION}"),
        };
        if !terminal(&job) {
            let backup: BackupView = api.read(&GetBackup { backup_id }, "").await?;
            // If the CLI exited after rewrapping, the durable job already owns its key.
            if backup.destination == BackupDestinationKind::GigahostS3
                && job.steps.iter().any(|step| {
                    step.step_key == "await_restore_authorization"
                        && step.state != gigahost_client_api::website::JobStepState::Succeeded
                })
            {
                let key = mutation.key();
                let (_, recovery) = backup_restore_credentials(cli, &backup, &key.key)?;
                authorize_hosted_restore(
                    api,
                    HostedRestoreAuthorization {
                        destination_instance_id,
                        backup: &backup,
                        accepted: &accepted,
                        recovery: recovery.as_ref().context("restore recovery key missing")?,
                        idempotency_key: &key.key,
                        poll_seconds: 2,
                        timeout_seconds: 300,
                    },
                )
                .await
                .with_context(|| JobContext {
                    job_id,
                    message: format!("resume this approval with {}", key.retry),
                })?;
            }
        }
        to_value(accepted)?
    } else {
        match intent.operation {
            BrowserOperation::RestoreBackup {
                instance_id,
                backup_id,
            } => {
                execute_backup(
                    cli,
                    api,
                    &BackupCommand::Restore(RestoreBackupArgs {
                        first_id: instance_id,
                        legacy_backup_id: Some(backup_id),
                        yes: true,
                        authorization_timeout_seconds: 300,
                        mutation,
                    }),
                )
                .await?
            }
            BrowserOperation::CreateFromBackup {
                offering_id,
                backup_id,
                gateway_tier,
                hostname,
                name,
                tags,
            } => {
                execute_instance(
                    cli,
                    api,
                    &InstanceCommand::Create(Box::new(CreateInstanceArgs {
                        offering: offering_id,
                        image: None,
                        backup: Some(backup_id),
                        spec: ContainerArgs::default(),
                        gateway_tier,
                        gateway_location: None,
                        ssh_keys: Vec::new(),
                        ssh_key_files: Vec::new(),
                        cloud_init_file: None,
                        hostname,
                        name,
                        no_tags: tags.as_ref().is_some_and(Vec::is_empty),
                        tags: tags.unwrap_or_default(),
                        startup_command: None,
                        startup_command_file: None,
                        authorization_timeout_seconds: 300,
                        mutation,
                    })),
                    !cli.globals.compact,
                )
                .await?
            }
            BrowserOperation::Unknown => refuse!("invalid_request", "{UNKNOWN_OPERATION}"),
        }
    };
    let job_id = result
        .get("job_id")
        .and_then(Value::as_str)
        .context("operation did not return a job ID")?;
    let _: BrowserOperationView = api
        .write(
            &CompleteOperationIntent { id },
            &gigahost_client_api::website::CompleteOperationIntentRequest {
                job_id: Uuid::parse_str(job_id).context("operation returned an invalid job ID")?,
            },
            Some(&*format!("browser-intent-complete-{id}")),
        )
        .await?;
    Ok(result)
}

/// What approving a website request for `operation` lets the host do
/// and charges, in one sentence. With `quote_above` the quote is on the
/// reader's screen above the sentence, and the sentence points at it;
/// otherwise (JSON for a program, or `--compact` with no quote) it names
/// the charges itself and tells the reader to inspect the request.
fn approval_notice(
    operation: &gigahost_client_api::website::BrowserOperation,
    quote_above: bool,
) -> &'static str {
    use gigahost_client_api::website::BrowserOperation;
    match (operation, quote_above) {
        (BrowserOperation::RestoreBackup { .. }, true) => {
            "Approving lets the host replace the instance's disk with the backup and charges what is shown above."
        }
        (BrowserOperation::RestoreBackup { .. }, false) => {
            "Approving lets the host replace the instance's disk with the backup and charges the backup restore, which is not refunded. Inspect the requested resources before approving."
        }
        (BrowserOperation::CreateFromBackup { .. }, true) => {
            "Approving lets the host create this instance and charges what is shown above."
        }
        (BrowserOperation::CreateFromBackup { .. }, false) => {
            "Approving lets the host create this instance from the backup and charges the creation fee and the backup restore now, then the monthly price while it exists. Inspect the requested resources before approving."
        }
        (BrowserOperation::Unknown, _) => UNKNOWN_OPERATION,
    }
}

/// The lines the approve screen shows for website request `intent_id` to
/// restore `backup_id` (`backup`) onto the instance `instance_id`, named
/// `name` where it could be read: what the request does, a blank line, the
/// block of rows and a blank line. The instance is shown by its ID alone
/// where it has no name.
fn restore_screen(
    intent_id: Uuid,
    backup_id: Uuid,
    backup: &BackupView,
    instance_id: Uuid,
    name: Option<&str>,
    colors: bool,
) -> Vec<String> {
    let name_text = name.map_or_else(
        || instance_id.to_string(),
        |name| escape_control(name).into_owned(),
    );
    let instance = name.map_or_else(
        || instance_id.to_string(),
        |_| format!("{name_text} ({instance_id})"),
    );
    let mut rows = vec![
        QuoteRow::Fact("Backup", backup_id.to_string()),
        QuoteRow::Fact("Instance", instance),
    ];
    if let Some(row) = restore_row(backup) {
        rows.push(QuoteRow::Gap);
        rows.push(row);
    }
    let mut lines = vec![
        format!(
            "Website request {intent_id}: restore backup {backup_id} onto {name_text}, replacing its disk"
        ),
        String::new(),
    ];
    lines.extend(quote_block(&rows, colors));
    lines.push(String::new());
    lines
}

/// Print what approving website request `intent_id` for `operation` does
/// and what it would cost.
async fn quote_operation(
    api: &ApiClient,
    intent_id: Uuid,
    operation: &gigahost_client_api::website::BrowserOperation,
) -> Result<()> {
    use gigahost_client_api::website::BrowserOperation;
    let colors = Terminal::stderr().colors;
    match operation {
        BrowserOperation::RestoreBackup {
            backup_id,
            instance_id,
        } => {
            let backup: BackupView = api
                .read(
                    &GetBackup {
                        backup_id: *backup_id,
                    },
                    "",
                )
                .await?;
            // The destination's name is for reading: an instance that
            // cannot be read now is shown by its ID.
            let instance = api
                .read(
                    &GetInstance {
                        instance_id: *instance_id,
                    },
                    "",
                )
                .await
                .ok()
                .map(|instance: InstanceView| instance.display_name().to_owned());
            for line in restore_screen(
                intent_id,
                *backup_id,
                &backup,
                *instance_id,
                instance.as_deref(),
                colors,
            ) {
                notice(&line);
            }
        }
        BrowserOperation::CreateFromBackup {
            offering_id,
            backup_id,
            gateway_tier,
            hostname,
            name,
            tags,
        } => {
            let backup: BackupView = api
                .read(
                    &GetBackup {
                        backup_id: *backup_id,
                    },
                    "",
                )
                .await?;
            notice(&format!(
                "Website request {intent_id}: create an instance from backup {backup_id}{}",
                name.as_deref()
                    .or(hostname.as_deref())
                    .map_or_else(String::new, |name| format!(
                        ", named {}",
                        escape_control(name)
                    ))
            ));
            match tags.as_deref() {
                Some([]) => notice("Without the tags of the backup's instance."),
                Some(tags) => notice(&format!("Tagged {}.", escape_control(&tags.join(", ")))),
                None => {}
            }
            notice("");
            quote_offering(api, offering_id, *gateway_tier, Some(&backup), None, None).await?;
        }
        BrowserOperation::Unknown => refuse!("invalid_request", "{UNKNOWN_OPERATION}"),
    }
    Ok(())
}

async fn execute_instance(
    cli: &Cli,
    api: &ApiClient,
    command: &InstanceCommand,
    show_progress: bool,
) -> Result<Value> {
    match command {
        InstanceCommand::Usage {
            instance_id,
            resolution,
            path,
            page,
        } => {
            let instance_id = resolve_instance(api, instance_id, InstanceUse::Read).await?;
            let mesh_page = |mesh: &'static str, page: &HistoryArgs| {
                let query = format!("path={mesh}&resolution={resolution}&{}", page.query());
                async move {
                    api.read(&GetInstanceMeshUsage { instance_id }, &query)
                        .await
                }
            };
            if let Some(mesh) = path.and_then(UsagePath::mesh) {
                if resolution == "current" {
                    bail!(
                        "the mesh paths have no current values: give --resolution 15m, daily or monthly"
                    );
                }
                return mesh_page(mesh, page).await.and_then(to_value);
            }
            let mut usage = to_value(
                api.read(
                    &GetInstanceUsage { instance_id },
                    &format!("resolution={resolution}&{}", page.query()),
                )
                .await?,
            )?;
            // All three paths: the mesh's first pages beside the usage.
            if path.is_none() && resolution != "current" {
                let first = HistoryArgs {
                    cursor: None,
                    limit: page.limit,
                };
                // A backend older than the mesh pages answers 404: the usage
                // still prints, without the mesh fields.
                let wan = mesh_page("wan_mesh", &first).await.ok();
                let lan = mesh_page("lan_mesh", &first).await.ok();
                if let (Some(fields), Some(wan), Some(lan)) = (usage.as_object_mut(), wan, lan) {
                    fields.insert("wan_mesh".to_owned(), to_value(wan)?);
                    fields.insert("lan_mesh".to_owned(), to_value(lan)?);
                }
            }
            Ok(usage)
        }
        InstanceCommand::Mesh { instance_id } => {
            let instance_id = resolve_instance(api, instance_id, InstanceUse::Read).await?;
            let mesh: InstanceMeshView = api.read(&GetInstanceMesh { instance_id }, "").await?;
            to_value(mesh)
        }
        InstanceCommand::GatewayTraffic { instance_id } => {
            let instance_id = resolve_instance(api, instance_id, InstanceUse::Read).await?;
            let traffic: GatewayTrafficView = api
                .read(&GetInstanceGatewayTraffic { instance_id }, "")
                .await?;
            to_value(traffic)
        }
        InstanceCommand::List {
            states,
            busy,
            location,
            provider,
            home,
            cloud,
            image,
            name,
            tags,
            sort,
            asc,
            desc,
        } => {
            let query = InstanceListQuery {
                state: states.clone(),
                busy: busy.then_some(true),
                location: location.clone(),
                provider: provider.clone(),
                mode: if *home {
                    Some(HostModeFilter::HomeGateway)
                } else if *cloud {
                    Some(HostModeFilter::CloudRouted)
                } else {
                    None
                },
                image: image.clone(),
                name: name.clone(),
                tag: tags.clone(),
                sort: *sort,
                order: if *asc {
                    Some(SortOrder::Asc)
                } else if *desc {
                    Some(SortOrder::Desc)
                } else {
                    None
                },
                ..InstanceListQuery::default()
            };
            let instances: Vec<InstanceView> = api
                .read(&ListInstances, &instance_list_query(&query))
                .await?;
            to_value(instances)
        }
        InstanceCommand::Get { instance_id } => {
            let instance_id = resolve_instance(api, instance_id, InstanceUse::Read).await?;
            let instance: InstanceView = api.read(&GetInstance { instance_id }, "").await?;
            to_value(instance)
        }
        InstanceCommand::Logs { instance_id, .. } => {
            let instance_id = resolve_instance(api, instance_id, InstanceUse::Read).await?;
            let logs: ContainerLogView = api.read(&GetInstanceLogs { instance_id }, "").await?;
            to_value(logs)
        }
        InstanceCommand::Console { .. } => {
            bail!("this command runs ssh itself: run it with ghost::run_console")
        }
        InstanceCommand::ConsoleLog { instance_id, bytes } => {
            let instance_id = resolve_instance(api, instance_id, InstanceUse::Read).await?;
            let console: InstanceConsoleLogView = api
                .read(
                    &GetInstanceConsoleLog { instance_id },
                    &format!("bytes={bytes}"),
                )
                .await?;
            to_value(console)
        }
        InstanceCommand::Create(args) => {
            // Every local check comes before the first request, so a private
            // key given by mistake is refused before anything is sent.
            let container = container_request(args)?;
            check_container_login(args)?;
            let ssh_public_keys = load_ssh_keys(&args.ssh_keys, &args.ssh_key_files)?;
            let cloud_init = args
                .cloud_init_file
                .as_deref()
                .map(load_user_data)
                .transpose()?;
            let startup_command = load_optional_text(
                args.startup_command.as_deref(),
                args.startup_command_file.as_deref(),
                "--startup-command-file",
            )?;
            if args.image.is_some() {
                require_login_material(
                    api,
                    &ssh_public_keys,
                    args.cloud_init_file.as_deref().zip(cloud_init.as_deref()),
                )
                .await?;
            }
            if args.spec.stock_image.is_some() {
                require_stock_image_keys(api, &ssh_public_keys).await?;
            }
            // A restored system keeps its keys and sshd settings, which the
            // platform's key and command parts would reset; the renter's own
            // user data runs as on any first boot.
            if args.backup.is_some() && (!ssh_public_keys.is_empty() || startup_command.is_some()) {
                refuse!(
                    "invalid_request",
                    "--ssh-key, --ssh-key-file, and startup commands cannot be used with --backup, whose system keeps its keys; put what the new VM needs in --cloud-init-file"
                );
            }
            let key = args.mutation.key();
            let mut hosted_recovery = None;
            let mut selected_backup = None;
            let source = if let Some(image) = &args.image {
                Some(InstanceSource::Image {
                    image_id: resolve_image(api, image).await?,
                })
            } else if let Some(backup_id) = args.backup {
                let backup: BackupView = api.read(&GetBackup { backup_id }, "").await?;
                ensure_backup_available(&backup, "used to create an instance")?;
                let (authorization, recovery) = backup_restore_credentials(cli, &backup, &key.key)?;
                hosted_recovery = recovery;
                selected_backup = Some(backup);
                Some(InstanceSource::Backup {
                    backup_id,
                    billing_authorization: Some(authorization),
                    accepted_charge: None,
                })
            } else {
                None
            };
            if show_progress {
                // A backup's kind is its instance's, which its view does not
                // tell: the backend checks the offering takes it.
                let kind = if container.is_some() {
                    Some(InstanceKind::Container)
                } else {
                    args.image.as_ref().map(|_| InstanceKind::Vm)
                };
                quote_offering(
                    api,
                    &args.offering,
                    args.gateway_tier,
                    selected_backup.as_ref(),
                    kind,
                    Some("Creating an instance:"),
                )
                .await?;
            }
            let request = CreateInstanceRequest {
                offering_id: args.offering.clone(),
                source,
                container,
                gateway_tier: args.gateway_tier,
                gateway_location: args.gateway_location.clone(),
                ssh_key_ids: named_keys_only(&ssh_public_keys),
                ssh_public_keys,
                cloud_init,
                hostname: args.hostname.clone(),
                name: args.name.clone(),
                startup_command,
                tags: if args.no_tags {
                    Some(Vec::new())
                } else {
                    (!args.tags.is_empty()).then(|| args.tags.clone())
                },
            };
            let accepted = accepted_job(
                api.write_retryable_answered(&CreateInstance, &request, &key)
                    .await?,
                show_progress,
            );
            // A cached name that stood for another instance now is this
            // one's too.
            #[cfg(unix)]
            {
                ghostd::forget_instance(accepted.resource_id);
                for name in [&args.name, &args.hostname].into_iter().flatten() {
                    ghostd::forget_name(name);
                }
            }
            if let (Some(backup), Some(recovery)) =
                (selected_backup.as_ref(), hosted_recovery.as_ref())
            {
                if show_progress {
                    notice(&restore_offer_notice(accepted.job_id));
                }
                authorize_hosted_restore(
                    api,
                    HostedRestoreAuthorization {
                        destination_instance_id: accepted.resource_id,
                        backup,
                        accepted: &accepted,
                        recovery,
                        idempotency_key: &key.key,
                        poll_seconds: args.mutation.poll_seconds,
                        timeout_seconds: args.authorization_timeout_seconds,
                    },
                )
                .await
                .with_context(|| JobContext {
                    job_id: accepted.job_id,
                    message: format!("resume this backup-based creation with {}", key.retry),
                })?;
            }
            mutation_result(api, accepted, &args.mutation, show_progress).await
        }
        InstanceCommand::Power(args) => {
            let instance_id = resolve_instance(api, &args.instance_id, InstanceUse::Change).await?;
            // A stop or a reset ends a rescue: only a note, an instance that cannot be read here
            // still changes its power.
            if matches!(args.state, PowerState::Stopped | PowerState::Reset)
                && let Ok(instance) = api.read(&GetInstance { instance_id }, "").await
                && instance.rescue.is_some()
            {
                notice(if args.state == PowerState::Stopped {
                    "The instance is in rescue: the stop ends the rescue, and the instance boots its own system at its next start."
                } else {
                    "The instance is in rescue: the reset ends the rescue and boots the instance's own system."
                });
                forget_rescue(instance_id);
            }
            let request = SetPowerStateRequest { state: args.state };
            let accepted: JobAccepted = api
                .write_retryable(
                    &SetInstancePower { instance_id },
                    &request,
                    &retried_by_id(args.mutation.key(), &args.instance_id, instance_id),
                )
                .await?;
            mutation_result(api, accepted, &args.mutation, show_progress).await
        }
        InstanceCommand::Reinstall(args) => {
            if !args.yes {
                bail!(
                    "reinstall destroys the current root filesystem and starts the instance if it is stopped; repeat with --yes"
                );
            }
            let instance_id = resolve_instance(api, &args.instance_id, InstanceUse::Change).await?;
            let ssh_public_keys = load_ssh_keys(&args.ssh_keys, &args.ssh_key_files)?;
            let cloud_init = args
                .cloud_init_file
                .as_deref()
                .map(load_user_data)
                .transpose()?;
            require_login_material(
                api,
                &ssh_public_keys,
                args.cloud_init_file.as_deref().zip(cloud_init.as_deref()),
            )
            .await?;
            let startup_command = load_optional_text(
                args.startup_command.as_deref(),
                args.startup_command_file.as_deref(),
                "--startup-command-file",
            )?;
            let image_id = resolve_image(api, &args.image).await?;
            // Only a note: an instance that cannot be read here is still
            // reinstalled, and the backend refuses what it must.
            let instance: Option<InstanceView> =
                api.read(&GetInstance { instance_id }, "").await.ok();
            if let Some(note) = instance.as_ref().and_then(reinstall_start_note) {
                notice(&note);
            }
            let accepted: JobAccepted = api
                .write_retryable(
                    &ReinstallInstance { instance_id },
                    &ReinstallInstanceRequest {
                        image_id,
                        ssh_key_ids: named_keys_only(&ssh_public_keys),
                        ssh_public_keys,
                        cloud_init,
                        hostname: args.hostname.clone(),
                        startup_command,
                    },
                    &retried_by_id(args.mutation.key(), &args.instance_id, instance_id),
                )
                .await?;
            #[cfg(unix)]
            ghostd::forget_instance(instance_id);
            mutation_result(api, accepted, &args.mutation, show_progress).await
        }
        InstanceCommand::ResetAccess(args) => {
            // A private key given by mistake is refused before anything is
            // sent.
            let ssh_public_keys = load_ssh_keys(&args.ssh_keys, &args.ssh_key_files)?;
            let instance_id = resolve_instance(api, &args.instance_id, InstanceUse::Change).await?;
            let accepted: JobAccepted = api
                .write_retryable(
                    &ResetInstanceAccess { instance_id },
                    &ResetInstanceAccessRequest {
                        ssh_key_ids: named_keys_only(&ssh_public_keys),
                        ssh_public_keys,
                        firewall: args.firewall,
                    },
                    &retried_by_id(args.mutation.key(), &args.instance_id, instance_id),
                )
                .await?;
            mutation_result(api, accepted, &args.mutation, show_progress).await
        }
        InstanceCommand::Rescue(args) if args.exit => {
            let instance_id = resolve_instance(api, &args.instance_id, InstanceUse::Change).await?;
            let accepted: JobAccepted = api
                .write_retryable(
                    &EndInstanceRescue { instance_id },
                    &(),
                    &retried_by_id(args.mutation.key(), &args.instance_id, instance_id),
                )
                .await?;
            forget_rescue(instance_id);
            mutation_result(api, accepted, &args.mutation, show_progress).await
        }
        InstanceCommand::Rescue(args) => {
            // A private key given by mistake is refused before anything is
            // sent.
            let ssh_public_keys = load_ssh_keys(&args.ssh_keys, &args.ssh_key_files)?;
            let instance_id = resolve_instance(api, &args.instance_id, InstanceUse::Change).await?;
            let accepted: JobAccepted = api
                .write_retryable(
                    &RescueInstance { instance_id },
                    &RescueInstanceRequest {
                        ssh_key_ids: named_keys_only(&ssh_public_keys),
                        ssh_public_keys,
                    },
                    &retried_by_id(args.mutation.key(), &args.instance_id, instance_id),
                )
                .await?;
            // Its address now answers with the rescue system: ghost's
            // connections read the instance anew.
            #[cfg(unix)]
            ghostd::forget_instance(instance_id);
            mutation_result(api, accepted, &args.mutation, show_progress).await
        }
        InstanceCommand::Update(args) => {
            let request = UpdateInstanceRequest {
                tag: args.tag.clone(),
            };
            request.validate().map_err(|message| Refusal {
                code: "invalid_request",
                message,
            })?;
            if !args.yes {
                bail!("{}", update_confirmation());
            }
            let instance_id = resolve_instance(api, &args.instance_id, InstanceUse::Change).await?;
            let accepted: JobAccepted = api
                .write_retryable(
                    &UpdateInstance { instance_id },
                    &request,
                    &retried_by_id(args.mutation.key(), &args.instance_id, instance_id),
                )
                .await?;
            #[cfg(unix)]
            ghostd::forget_instance(instance_id);
            let result = mutation_result(api, accepted, &args.mutation, show_progress).await?;
            if args.mutation.wait
                && show_progress
                && let Ok(instance) = api.read(&GetInstance { instance_id }, "").await
                && let Some(note) = redeployed_note(&instance)
            {
                notice(&note);
            }
            Ok(result)
        }
        InstanceCommand::Redeploy(args) => {
            // Every local check comes before the first request, so a
            // private key given by mistake is refused before anything is
            // sent.
            let request = redeploy_request(args)?;
            let instance_id = resolve_instance(api, &args.instance_id, InstanceUse::Change).await?;
            // Only for the words: an instance that cannot be read here is
            // still redeployed, and the backend refuses what it must.
            let instance: Option<InstanceView> =
                api.read(&GetInstance { instance_id }, "").await.ok();
            if !args.yes {
                bail!("{}", redeploy_confirmation(&request, instance.as_ref()));
            }
            if args.spec.stock_image.is_some() {
                require_stock_image_keys(api, &request.ssh_public_keys).await?;
            }
            let accepted: JobAccepted = api
                .write_retryable(
                    &RedeployInstance { instance_id },
                    &request,
                    &retried_by_id(args.mutation.key(), &args.instance_id, instance_id),
                )
                .await?;
            #[cfg(unix)]
            ghostd::forget_instance(instance_id);
            let result = mutation_result(api, accepted, &args.mutation, show_progress).await?;
            if args.mutation.wait
                && show_progress
                && let Ok(instance) = api.read(&GetInstance { instance_id }, "").await
                && let Some(note) = redeployed_note(&instance)
            {
                notice(&note);
            }
            Ok(result)
        }
        InstanceCommand::Upgrades { instance_id } => {
            let instance_id = resolve_instance(api, instance_id, InstanceUse::Read).await?;
            let upgrades: Vec<InstanceUpgradeView> =
                api.read(&ListInstanceUpgrades { instance_id }, "").await?;
            to_value(upgrades)
        }
        InstanceCommand::Upgrade(args) => {
            let instance_id = resolve_instance(api, &args.instance_id, InstanceUse::Change).await?;
            if !cli.globals.compact {
                quote_upgrade(api, instance_id, &args.offering).await;
            }
            if !args.yes {
                bail!(
                    "an upgrade shuts the instance down and starts it again.\nTo upgrade: ghost instance upgrade {} --offering {} --yes",
                    escape_control(&instance_reference_text(&args.instance_id)),
                    escape_control(&args.offering)
                );
            }
            let accepted: JobAccepted = api
                .write_retryable(
                    &UpgradeInstance { instance_id },
                    &UpgradeInstanceRequest {
                        offering_id: args.offering.clone(),
                    },
                    &retried_by_id(args.mutation.key(), &args.instance_id, instance_id),
                )
                .await?;
            mutation_result(api, accepted, &args.mutation, show_progress).await
        }
        InstanceCommand::Tag(TagArgs {
            command:
                Some(TagCommand::Redundant {
                    tag,
                    state,
                    idempotency,
                }),
            ..
        }) => {
            let flagged: InstanceTagView = api
                .write_retryable(
                    &SetTagRedundant { tag: tag.clone() },
                    &SetTagRedundantRequest {
                        redundant: matches!(state, Switch::On),
                    },
                    &idempotency.key(),
                )
                .await?;
            to_value(flagged)
        }
        InstanceCommand::Tag(args) => {
            let (Some(reference), Some(action)) = (&args.instance_id, args.action) else {
                bail!("name the instance, add or remove, and the tags");
            };
            let instance_id = resolve_instance(api, reference, InstanceUse::Change).await?;
            let request = match action {
                TagAction::Add => TagInstanceRequest {
                    add: args.tags.clone(),
                    remove: Vec::new(),
                },
                TagAction::Remove => TagInstanceRequest {
                    add: Vec::new(),
                    remove: args.tags.clone(),
                },
            };
            let instance: InstanceView = api
                .write_retryable(
                    &TagInstance { instance_id },
                    &request,
                    &retried_by_id(args.idempotency.key(), reference, instance_id),
                )
                .await?;
            to_value(instance)
        }
        InstanceCommand::Tags => {
            let tags: Vec<InstanceTagView> = api.read(&ListInstanceTags, "").await?;
            to_value(tags)
        }
        InstanceCommand::Rename(args) => {
            let instance_id = resolve_instance(api, &args.instance_id, InstanceUse::Change).await?;
            let instance: InstanceView = api
                .write_retryable(
                    &RenameInstance { instance_id },
                    &RenameInstanceRequest {
                        name: args.name.clone(),
                    },
                    &retried_by_id(args.idempotency.key(), &args.instance_id, instance_id),
                )
                .await?;
            #[cfg(unix)]
            {
                ghostd::forget_instance(instance_id);
                ghostd::forget_name(&args.name);
            }
            to_value(instance)
        }
        InstanceCommand::Ports(args) => {
            let used = if args.action.is_some() {
                InstanceUse::Change
            } else {
                InstanceUse::Read
            };
            let instance_id = resolve_instance(api, &args.instance_id, used).await?;
            let instance: InstanceView = match &args.action {
                None => api.read(&GetInstance { instance_id }, "").await?,
                Some(PortsAction::Set {
                    forwards,
                    idempotency,
                }) => {
                    api.write_retryable(
                        &SetPortForwards { instance_id },
                        &SetPortForwardsRequest {
                            forwards: forwards.clone(),
                        },
                        &retried_by_id(idempotency.key(), &args.instance_id, instance_id),
                    )
                    .await?
                }
            };
            if instance.port_forwards.is_empty() {
                bail!(
                    "instance {instance_id} has no shared IP: only a shared IP instance's ports are forwarded"
                );
            }
            Ok(port_forwards_output(&instance))
        }
        InstanceCommand::RotateGatewayKeys(args) => {
            let instance_id = resolve_instance(api, &args.instance_id, InstanceUse::Change).await?;
            let accepted: JobAccepted = api
                .write_retryable(
                    &RotateGatewayKeys { instance_id },
                    &RotateGatewayKeysRequest {},
                    &retried_by_id(args.mutation.key(), &args.instance_id, instance_id),
                )
                .await?;
            mutation_result(api, accepted, &args.mutation, show_progress).await
        }
        InstanceCommand::Gateway(args) => {
            if args.tier.is_none() && args.location.is_none() {
                bail!("name the gateway to change to: --tier, --location, or both");
            }
            if args.tier == Some(GatewayTier::Unknown) {
                bail!("choose shared-ip, shared-bandwidth or high-bandwidth");
            }
            let instance_id = resolve_instance(api, &args.instance_id, InstanceUse::Change).await?;
            let charge = if args.yes && cli.globals.compact {
                ChangeCharge::Unknown
            } else {
                quote_gateway_change(
                    api,
                    instance_id,
                    args.tier,
                    args.location.as_deref(),
                    !cli.globals.compact,
                    false,
                )
                .await
            };
            if !args.yes {
                bail!(
                    "{}\nTo change: ghost instance gateway {}{}{} --yes",
                    gateway_change_warning(charge),
                    escape_control(&instance_reference_text(&args.instance_id)),
                    args.tier.map_or_else(String::new, |tier| format!(
                        " --tier {}",
                        gateway_tier_words(tier).replace(' ', "-").to_lowercase()
                    )),
                    args.location
                        .as_deref()
                        .map_or_else(String::new, |location| format!(
                            " --location {}",
                            escape_control(location)
                        ))
                );
            }
            let accepted: JobAccepted = api
                .write_retryable(
                    &ChangeGateway { instance_id },
                    &ChangeGatewayRequest {
                        tier: args.tier,
                        gateway_location: args.location.clone(),
                    },
                    &retried_by_id(args.mutation.key(), &args.instance_id, instance_id),
                )
                .await?;
            mutation_result(api, accepted, &args.mutation, show_progress).await
        }
        InstanceCommand::GatewayLocation(args) => {
            let instance_id = resolve_instance(api, &args.instance_id, InstanceUse::Change).await?;
            let charge = if args.yes && cli.globals.compact {
                ChangeCharge::Unknown
            } else {
                quote_gateway_change(
                    api,
                    instance_id,
                    None,
                    Some(&args.location),
                    !cli.globals.compact,
                    true,
                )
                .await
            };
            if !args.yes {
                bail!(
                    "{}\nTo move: ghost instance gateway-location {} {} --yes",
                    gateway_change_warning(charge),
                    escape_control(&instance_reference_text(&args.instance_id)),
                    escape_control(&args.location)
                );
            }
            let accepted: JobAccepted = api
                .write_retryable(
                    &MoveGatewayLocation { instance_id },
                    &MoveGatewayLocationRequest {
                        gateway_location: args.location.clone(),
                    },
                    &retried_by_id(args.mutation.key(), &args.instance_id, instance_id),
                )
                .await?;
            mutation_result(api, accepted, &args.mutation, show_progress).await
        }
        InstanceCommand::Delete(args) => {
            if !args.yes {
                bail!("instance deletion is irreversible; repeat with --yes");
            }
            let instance_id = resolve_instance(api, &args.instance_id, InstanceUse::Change).await?;
            // Only a note: a backup list that cannot be read never stops the
            // deletion.
            let backups: Option<Vec<BackupView>> = api
                .read(&ListInstanceBackups { instance_id }, "")
                .await
                .ok();
            let accepted: JobAccepted = api
                .write_retryable(
                    &DeleteInstance { instance_id },
                    &(),
                    &retried_by_id(args.mutation.key(), &args.instance_id, instance_id),
                )
                .await?;
            #[cfg(unix)]
            ghostd::forget_instance(instance_id);
            if let Some(note) = backups.as_deref().and_then(kept_backups_note) {
                notice(&note);
            }
            mutation_result(api, accepted, &args.mutation, show_progress).await
        }
    }
}

/// The query string of the account's instance list `query`: each
/// parameter in the order of its fields, `state` once for each state and
/// `tag` for each tag.
fn instance_list_query(query: &InstanceListQuery) -> String {
    let mut url = reqwest::Url::parse("https://api.gigahost.cloud/").expect("static URL");
    {
        let mut pairs = url.query_pairs_mut();
        if let Some(ids) = &query.ids {
            pairs.append_pair("ids", ids);
        }
        if let Some(limit) = query.limit {
            pairs.append_pair("limit", &limit.to_string());
        }
        if let Some(before) = query.before {
            pairs.append_pair("before", &before.to_string());
        }
        for state in &query.state {
            pairs.append_pair("state", state.as_str());
        }
        if let Some(busy) = query.busy {
            pairs.append_pair("busy", &busy.to_string());
        }
        for (name, value) in [("location", &query.location), ("provider", &query.provider)] {
            if let Some(value) = value {
                pairs.append_pair(name, value);
            }
        }
        if let Some(mode) = query.mode {
            pairs.append_pair("mode", mode.as_str());
        }
        for (name, value) in [("image", &query.image), ("name", &query.name)] {
            if let Some(value) = value {
                pairs.append_pair(name, value);
            }
        }
        for tag in &query.tag {
            pairs.append_pair("tag", tag);
        }
        if let Some(sort) = query.sort {
            pairs.append_pair("sort", sort.as_str());
        }
        if let Some(order) = query.order {
            pairs.append_pair("order", order.as_str());
        }
    }
    url.query().unwrap_or_default().to_owned()
}

/// The query string of the account's backup list `query`: each parameter
/// in the order of its fields, `state` once for each state and `tag` for
/// each tag.
fn backup_list_query(query: &AccountBackupListQuery) -> String {
    let mut url = reqwest::Url::parse("https://api.gigahost.cloud/").expect("static URL");
    {
        let mut pairs = url.query_pairs_mut();
        if let Some(limit) = query.limit {
            pairs.append_pair("limit", &limit.to_string());
        }
        if let Some(include_deleted) = query.include_deleted {
            pairs.append_pair("include_deleted", &include_deleted.to_string());
        }
        if let Some(before) = query.before {
            pairs.append_pair("before", &before.to_string());
        }
        if let Some(instance_id) = query.instance_id {
            pairs.append_pair("instance_id", &instance_id.to_string());
        }
        for state in &query.state {
            pairs.append_pair("state", state.as_str());
        }
        if let Some(destination) = query.destination {
            pairs.append_pair("destination", destination.as_str());
        }
        for tag in &query.tag {
            pairs.append_pair("tag", tag);
        }
        if let Some(sort) = query.sort {
            pairs.append_pair("sort", sort.as_str());
        }
        if let Some(order) = query.order {
            pairs.append_pair("order", order.as_str());
        }
    }
    url.query().unwrap_or_default().to_owned()
}

async fn execute_backup(cli: &Cli, api: &ApiClient, command: &BackupCommand) -> Result<Value> {
    match command {
        BackupCommand::List {
            instance_id,
            all,
            states,
            hosted,
            local,
            tags,
            sort,
            asc,
            desc,
        } => {
            let instance_id =
                resolve_optional_instance(api, instance_id.as_ref(), InstanceUse::Read).await?;
            let query = AccountBackupListQuery {
                include_deleted: all.then_some(true),
                instance_id,
                state: states.clone(),
                destination: if *hosted {
                    Some(BackupDestinationFilter::Hosted)
                } else if *local {
                    Some(BackupDestinationFilter::Local)
                } else {
                    None
                },
                tag: tags.clone(),
                sort: *sort,
                order: if *asc {
                    Some(SortOrder::Asc)
                } else if *desc {
                    Some(SortOrder::Desc)
                } else {
                    None
                },
                ..AccountBackupListQuery::default()
            };
            let backups: Vec<BackupView> = match instance_id {
                // An instance's own list, unless a filter or a sort asks
                // for the account's list of it.
                Some(instance_id)
                    if query.state.is_empty()
                        && query.destination.is_none()
                        && query.tag.is_empty()
                        && query.sort.is_none()
                        && query.order.is_none() =>
                {
                    api.read(
                        &ListInstanceBackups { instance_id },
                        if *all { "include_deleted=true" } else { "" },
                    )
                    .await?
                }
                _ => api.read(&ListBackups, &backup_list_query(&query)).await?,
            };
            to_value(backups)
        }
        BackupCommand::Get { backup_id } => {
            let backup: BackupView = api
                .read(
                    &GetBackup {
                        backup_id: *backup_id,
                    },
                    "",
                )
                .await?;
            to_value(backup)
        }
        BackupCommand::Create(args) => {
            let instance_id = resolve_instance(api, &args.instance_id, InstanceUse::Change).await?;
            let mut key = retried_by_id(args.mutation.key(), &args.instance_id, instance_id);
            let seed = load_account_seed(cli)?;
            let destination = match args.destination {
                BackupDestinationArg::Hosted => "gigahost_s3",
                BackupDestinationArg::Local => "local",
            };
            let BackupCreationTerms {
                pricing_revision,
                maximum_charge_microusd,
                quote,
            } = if let (Some(revision), Some(maximum)) =
                (args.pricing_revision, args.maximum_charge_microusd)
            {
                BackupCreationTerms {
                    pricing_revision: revision,
                    maximum_charge_microusd: maximum,
                    quote: quote_block(
                        &[QuoteRow::Money(
                            "Creation",
                            pretty::dollars(maximum),
                            format!(
                                "at most, at pricing revision {revision} as the first attempt signed"
                            ),
                        )],
                        Terminal::stderr().colors,
                    )
                    .join("\n"),
                }
            } else {
                backup_creation_terms(api, instance_id, args.destination).await?
            };
            // The signed prices are part of the request body, so an exact
            // retry must sign the same ones even if prices changed since.
            if args.mutation.browser_intent.is_none() {
                let _ = write!(
                    key.retry,
                    " --pricing-revision {pricing_revision} --maximum-charge-microusd {maximum_charge_microusd}"
                );
            }
            let billing_authorization = backup_billing_authorization(
                &seed,
                &BackupBillingAuthorizationInput {
                    operation: "create_backup",
                    instance_id,
                    backup_id: None,
                    destination,
                    pricing_revision,
                    maximum_charge_microusd,
                    idempotency_key: &key.key,
                },
            )?;
            let request = CreateBackupRequest {
                destination: args.destination.into(),
                recipient_public_key: Some(
                    URL_SAFE_NO_PAD.encode(keys::recovery_key_pair(&seed)?.public_key),
                ),
                billing_authorization: Some(billing_authorization),
                accepted_charge: None,
            };
            if !cli.globals.compact {
                notice(&quote);
            }
            let accepted = accepted_job(
                api.write_retryable_answered(&CreateBackup { instance_id }, &request, &key)
                    .await?,
                !cli.globals.compact,
            );
            mutation_result(api, accepted, &args.mutation, !cli.globals.compact).await
        }
        BackupCommand::Cancel(args) => {
            let backup = named_backup(api, args.backup_id, None).await?;
            // The cancellation is done when the request returns, so there
            // is no job to wait for: the one named is the cancelled creation.
            let accepted: JobAccepted = api
                .write_retryable(
                    &CancelBackup {
                        instance_id: backup.instance_id,
                        backup_id: backup.backup_id,
                    },
                    &(),
                    &args.mutation.key(),
                )
                .await?;
            to_value(accepted)
        }
        BackupCommand::Restore(args) => restore_backup(cli, api, args).await,
        BackupCommand::Schedule { command } => match command {
            ScheduleCommand::Show { instance_id } => {
                let id = resolve_instance(api, instance_id, InstanceUse::Read).await?;
                let schedule: BackupScheduleView =
                    api.read(&GetBackupSchedule { instance_id: id }, "").await?;
                to_value(schedule)
            }
            ScheduleCommand::Set(args) => {
                let mut request = schedule_request(args)?;
                let id = resolve_instance(api, &args.instance_id, InstanceUse::Change).await?;
                let current: BackupScheduleView =
                    api.read(&GetBackupSchedule { instance_id: id }, "").await?;
                carry_rule_ids(&mut request, &current);
                let deletions = schedule_deletions(&request, &current);
                if !deletions.is_empty() && !args.yes {
                    bail!("{}", schedule_deletion_refusal(&deletions));
                }
                let schedule: BackupScheduleView = api
                    .write_retryable(
                        &SetBackupSchedule { instance_id: id },
                        &request,
                        &retried_by_id(args.idempotency.key(), &args.instance_id, id),
                    )
                    .await?;
                to_value(schedule)
            }
            ScheduleCommand::Clear {
                instance_id,
                idempotency,
            } => {
                let id = resolve_instance(api, instance_id, InstanceUse::Change).await?;
                let schedule: BackupScheduleView = api
                    .write_retryable(
                        &SetBackupSchedule { instance_id: id },
                        &SetBackupScheduleRequest::default(),
                        &retried_by_id(idempotency.key(), instance_id, id),
                    )
                    .await?;
                to_value(schedule)
            }
        },
        BackupCommand::Delete(args) => {
            if !args.yes {
                bail!("backup deletion is irreversible; repeat with --yes");
            }
            let backup = named_backup(api, args.first_id, args.legacy_backup_id).await?;
            let accepted: JobAccepted = api
                .write_retryable(
                    &DeleteBackup {
                        instance_id: backup.instance_id,
                        backup_id: backup.backup_id,
                    },
                    &(),
                    &args.mutation.key(),
                )
                .await?;
            mutation_result(api, accepted, &args.mutation, !cli.globals.compact).await
        }
    }
}

/// The backup a backup command names: by its ID alone, or in the older
/// form `INSTANCE_ID BACKUP_ID`, where the instance must be the backup's.
/// The API addresses a backup below the instance it was taken of.
async fn named_backup(
    api: &ApiClient,
    first_id: Uuid,
    legacy_backup_id: Option<Uuid>,
) -> Result<BackupView> {
    let (named_instance, backup_id) = match legacy_backup_id {
        Some(backup_id) => (Some(first_id), backup_id),
        None => (None, first_id),
    };
    let backup: BackupView = api.read(&GetBackup { backup_id }, "").await?;
    if let Some(named) = named_instance.filter(|named| *named != backup.instance_id) {
        refuse!(
            "backup_instance_mismatch",
            "backup {backup_id} belongs to instance {}, not {named}",
            backup.instance_id
        );
    }
    Ok(backup)
}

async fn restore_backup(cli: &Cli, api: &ApiClient, args: &RestoreBackupArgs) -> Result<Value> {
    if !args.yes {
        bail!("restore replaces the current root filesystem; repeat with --yes");
    }
    let backup = named_backup(api, args.first_id, args.legacy_backup_id).await?;
    ensure_backup_available(&backup, "restored")?;
    let instance_id = backup.instance_id;
    let key = args.mutation.key();
    let (billing_authorization, hosted_recovery) =
        backup_restore_credentials(cli, &backup, &key.key)?;
    if !cli.globals.compact
        && let Some(quote) = restore_quote(&backup, Terminal::stderr().colors)
    {
        notice(&quote);
    }
    let accepted = accepted_job(
        api.write_retryable_answered(
            &RestoreBackup {
                instance_id,
                backup_id: backup.backup_id,
            },
            &RestoreBackupRequest {
                billing_authorization: Some(billing_authorization),
                accepted_charge: None,
            },
            &key,
        )
        .await?,
        !cli.globals.compact,
    );
    #[cfg(unix)]
    ghostd::forget_instance(instance_id);

    if let Some(recovery) = hosted_recovery.as_ref() {
        if !cli.globals.compact {
            notice(&restore_offer_notice(accepted.job_id));
        }
        authorize_hosted_restore(
            api,
            HostedRestoreAuthorization {
                destination_instance_id: instance_id,
                backup: &backup,
                accepted: &accepted,
                recovery,
                idempotency_key: &key.key,
                poll_seconds: args.mutation.poll_seconds,
                timeout_seconds: args.authorization_timeout_seconds,
            },
        )
        .await
        .with_context(|| JobContext {
            job_id: accepted.job_id,
            message: format!("resume this restore with {}", key.retry),
        })?;
    }
    mutation_result(api, accepted, &args.mutation, !cli.globals.compact).await
}

/// What a backup of an instance may cost, as its creation signs it: the
/// pricing revision, the most the backup can be charged, and a line that
/// says what it costs.
struct BackupCreationTerms {
    pricing_revision: u64,
    maximum_charge_microusd: u64,
    quote: String,
}

/// The terms of a backup of `instance_id` to `destination` at the prices
/// in effect now. A backup is charged for its own size when it is made, and
/// for no more than the size of its volume.
async fn backup_creation_terms(
    api: &ApiClient,
    instance_id: Uuid,
    destination: BackupDestinationArg,
) -> Result<BackupCreationTerms> {
    let instance: InstanceView = api.read(&GetInstance { instance_id }, "").await?;
    let pricing: BackupPricingView = api.read(&GetBackupPricing, "").await?;
    let prices = pricing
        .prices(destination.into())
        .context("the backend gave no prices for the backup's destination")?;
    let (_, maximum) = backup_byte_charge(
        instance.root_disk_bytes,
        prices.creation_charge_microusd_per_gib,
    )
    .with_context(|| {
        format!(
            "{} backup creation charge overflow",
            match destination {
                BackupDestinationArg::Hosted => "hosted",
                BackupDestinationArg::Local => "local",
            }
        )
    })?;
    Ok(BackupCreationTerms {
        pricing_revision: pricing.pricing_revision,
        maximum_charge_microusd: maximum,
        quote: quote_block(
            &[
                QuoteRow::Money(
                    "Creation",
                    format!(
                        "{}/GiB",
                        pretty::exact_dollars(prices.creation_charge_microusd_per_gib)
                    ),
                    format!(
                        "of the finished backup, at most {} for the {} disk, charged when it is published, nothing if it fails or is cancelled",
                        pretty::dollars(maximum),
                        pretty::binary_size(instance.root_disk_bytes),
                    ),
                ),
                QuoteRow::Money(
                    "Storage",
                    format!(
                        "{}/GiB-month",
                        pretty::exact_dollars(prices.storage_charge_microusd_per_gib_month)
                    ),
                    "while it is kept".to_owned(),
                ),
                QuoteRow::Money(
                    "Restore",
                    format!(
                        "{}/GiB",
                        pretty::exact_dollars(prices.restore_charge_microusd_per_gib)
                    ),
                    "when you restore it".to_owned(),
                ),
            ],
            Terminal::stderr().colors,
        )
        .join("\n"),
    })
}

/// What restoring `backup` costs: its artifact's size at the restore price
/// it recorded when it was made, or `None` while its size is not known.
fn restore_charge(backup: &BackupView) -> Option<u64> {
    backup_byte_charge(backup.size_bytes?, backup.restore_charge_microusd_per_gib)
        .map(|(_, charge)| charge)
}

/// The row that says what restoring `backup` costs, posted when the
/// restore is accepted and kept whatever becomes of it.
fn restore_row(backup: &BackupView) -> Option<QuoteRow> {
    restore_charge(backup).map(|charge| {
        QuoteRow::Money(
            "Now",
            pretty::dollars(charge),
            "backup restore, not refunded".to_owned(),
        )
    })
}

/// The line that says what restoring `backup` costs, as a block of one row.
fn restore_quote(backup: &BackupView, colors: bool) -> Option<String> {
    restore_row(backup).and_then(|row| quote_block(&[row], colors).pop())
}

/// The job a paid mutation was answered with. When the answer is the job
/// of an earlier request with the same idempotency key, which the backend
/// gives again as it was, it says so if `show_progress`: the charges it
/// printed before were not charged again.
fn accepted_job(answered: Answered<JobAccepted>, show_progress: bool) -> JobAccepted {
    if show_progress && let Some(created) = replayed_job(&answered) {
        notice(&format!(
            "Nothing new was charged: job {} already answered this request (same idempotency key) at {}.",
            answered.value.job_id,
            created.format("%Y-%m-%d %H:%M:%S UTC")
        ));
    }
    answered.value
}

/// When the server made the job `answered` names, if that was before the
/// request could have reached it: the job answers an earlier request. A
/// job ID is a version 7 UUID, which carries the server's clock when it
/// made the job; a job this request made was made after it arrived, at
/// most `elapsed` before the response's `Date`, which is to the second.
/// Two more seconds allow for the clocks of the machines behind the API.
fn replayed_job(answered: &Answered<JobAccepted>) -> Option<DateTime<Utc>> {
    let (seconds, nanoseconds) = answered.value.job_id.get_timestamp()?.to_unix();
    let created = DateTime::from_timestamp(i64::try_from(seconds).ok()?, nanoseconds)?;
    let earliest = answered.server_date?
        - chrono::Duration::from_std(answered.elapsed).ok()?
        - chrono::Duration::seconds(2);
    (created < earliest).then_some(created)
}

/// What a reinstall of `instance` says first when the instance is stopped,
/// or a stop of it has not finished: the backend starts it with the new
/// system, as `--help` says. One already being started needs no note.
fn reinstall_start_note(instance: &InstanceView) -> Option<String> {
    let (now, start) = match (instance.state, instance.desired_power_state) {
        (InstanceState::Stopped, PowerState::Stopped) => ("stopped", "starts it"),
        (InstanceState::Running, PowerState::Stopped) => ("stopping", "starts it again"),
        _ => return None,
    };
    Some(format!(
        "Instance {} is {now}. The reinstall {start}.",
        instance.instance_id
    ))
}

/// What `instance delete` says about the instance's backups: they outlive it
/// and are billed for storage until they are deleted. None when it has none.
fn kept_backups_note(backups: &[BackupView]) -> Option<String> {
    use gigahost_client_api::website::BackupState;
    let kept = backups
        .iter()
        .filter(|backup| {
            !matches!(
                backup.status,
                BackupState::Deleting
                    | BackupState::Deleted
                    | BackupState::Failed
                    | BackupState::Lost
            )
        })
        .collect::<Vec<_>>();
    let first = kept.first()?;
    let lines = kept
        .iter()
        .map(|backup| {
            let place = match (backup.destination, backup.host_id) {
                (BackupDestinationKind::Local, Some(host_id)) => format!("local on host {host_id}"),
                (BackupDestinationKind::Local, None) => "local".to_owned(),
                (BackupDestinationKind::GigahostS3, _) => "hosted".to_owned(),
                (BackupDestinationKind::Unknown, _) => "unknown destination".to_owned(),
            };
            let size = backup
                .size_bytes
                .map_or_else(|| "size not known yet".to_owned(), pretty::binary_size);
            format!(
                "  {}  {place}, {size}, {}/GiB-month",
                backup.backup_id,
                pretty::exact_dollars(backup.storage_charge_microusd_per_gib_month)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let (count, verb) = match kept.len() {
        1 => ("1 backup".to_owned(), "is"),
        count => (format!("{count} backups"), "are"),
    };
    Some(format!(
        "{count} of this instance {verb} kept after it is deleted and billed for storage until deleted:\n{lines}\nTo delete one: ghost backup delete {} --yes",
        first.backup_id
    ))
}

/// Refuse a backup that cannot be `action` (a past participle) before
/// anything is signed or sent, as the backend would, with its code
/// `backup_not_available`: one still being created has no size or data key
/// to sign a restore for yet, and a lost one has no data any more. An
/// available backup in a backup pool its host is missing is refused with
/// `backup_pool_unavailable`.
fn ensure_backup_available(backup: &BackupView, action: &str) -> Result<()> {
    use gigahost_client_api::website::BackupState;
    let being_created = "; retry once its creation has finished";
    let (status, hint) = match backup.status {
        BackupState::Available => {
            if let Some(unavailable) = &backup.unavailable {
                refuse!(
                    "backup_pool_unavailable",
                    "backup_pool_unavailable: backup {} cannot be {action} now: {}; try again when the host has the pool back",
                    backup.backup_id,
                    escape_control(&unavailable.reason)
                );
            }
            return Ok(());
        }
        BackupState::Queued => ("queued", being_created),
        BackupState::Staging => ("staging", being_created),
        BackupState::Uploading => ("uploading", being_created),
        BackupState::Restoring => ("restoring", "; retry once that restore has finished"),
        BackupState::Failed => ("failed", ""),
        BackupState::Deleting => ("deleting", ""),
        BackupState::Deleted => ("deleted", ""),
        BackupState::Lost => ("lost", "; delete it with `ghost backup delete`"),
        BackupState::Unknown => ("in a state this release of ghost does not know", ""),
    };
    refuse!(
        "backup_not_available",
        "backup_not_available: backup {} is {status}; only an available backup can be {action}{hint}",
        backup.backup_id
    )
}

fn backup_restore_credentials(
    cli: &Cli,
    backup: &BackupView,
    restore_idempotency_key: &str,
) -> Result<(BillingAuthorization, Option<keys::RecoveryKeyPair>)> {
    let hosted_recovery = if backup.destination == BackupDestinationKind::GigahostS3 {
        let seed = load_recovery_seed(cli)?;
        let recovery = keys::recovery_key_pair(&seed)?;
        let expected_fingerprint = backup
            .recipient_key_fingerprint
            .as_deref()
            .context("hosted backup is missing its recipient-key fingerprint")?;
        if URL_SAFE_NO_PAD.encode(recovery.fingerprint) != expected_fingerprint {
            let backup_key = format!(
                "the key hosted backup {} was encrypted for (recipient key fingerprint {})",
                backup.backup_id,
                escape_control(expected_fingerprint)
            );
            if cli.globals.recovery_seed_file.is_some() {
                refuse!(
                    RECOVERY_KEY_MISMATCH,
                    "the --recovery-seed-file account key does not match {backup_key}; `ghost --seed-file FILE key inspect` shows an account key's recovery_key_fingerprint"
                );
            }
            refuse!(
                RECOVERY_KEY_MISMATCH,
                "this account key does not match {backup_key}; a backup made before an account key migration needs the account key it was made with: pass that account key as --recovery-seed-file"
            );
        }
        backup
            .wrapped_data_key
            .as_deref()
            .context("hosted backup is missing its wrapped data key")?;
        Some(recovery)
    } else {
        None
    };
    let processed_bytes = backup
        .size_bytes
        .context("backup is missing its immutable artifact size")?;
    let destination = match backup.destination {
        BackupDestinationKind::GigahostS3 => "gigahost_s3",
        BackupDestinationKind::Local => "local",
        BackupDestinationKind::Unknown => refuse!(
            "invalid_request",
            "backup {} is kept in a place this release of ghost does not know; update ghost to restore it",
            backup.backup_id
        ),
    };
    let pricing_revision = backup.restore_pricing_revision;
    let price_microusd_per_gib = backup.restore_charge_microusd_per_gib;
    let (_, maximum_charge_microusd) = backup_byte_charge(processed_bytes, price_microusd_per_gib)
        .context("backup restore charge overflow")?;
    let seed = load_account_seed(cli)?;
    let billing_authorization = backup_billing_authorization(
        &seed,
        &BackupBillingAuthorizationInput {
            operation: "restore_backup",
            instance_id: backup.instance_id,
            backup_id: Some(backup.backup_id),
            destination,
            pricing_revision,
            maximum_charge_microusd,
            idempotency_key: restore_idempotency_key,
        },
    )?;
    Ok((billing_authorization, hosted_recovery))
}

/// The account's signed consent to `input`: one backup operation charging
/// at most its maximum at its pricing revision.
fn backup_billing_authorization(
    seed: &[u8; 32],
    input: &BackupBillingAuthorizationInput<'_>,
) -> Result<BillingAuthorization> {
    let signature =
        keys::sign_billing_authorization(seed, &canonical_backup_billing_authorization(input))?;
    Ok(BillingAuthorization {
        pricing_revision: input.pricing_revision,
        maximum_charge_microusd: input.maximum_charge_microusd,
        signature: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

struct HostedRestoreAuthorization<'a> {
    destination_instance_id: Uuid,
    backup: &'a BackupView,
    accepted: &'a JobAccepted,
    recovery: &'a keys::RecoveryKeyPair,
    idempotency_key: &'a str,
    poll_seconds: u64,
    timeout_seconds: u64,
}

async fn authorize_hosted_restore(
    api: &ApiClient,
    context: HostedRestoreAuthorization<'_>,
) -> Result<()> {
    let HostedRestoreAuthorization {
        destination_instance_id,
        backup,
        accepted,
        recovery,
        idempotency_key,
        poll_seconds,
        timeout_seconds,
    } = context;
    let wrapped_data_key = backup
        .wrapped_data_key
        .as_deref()
        .context("hosted backup is missing its wrapped data key")?;
    let Some(offer) = wait_for_restore_offer(
        api,
        accepted.job_id,
        Duration::from_secs(poll_seconds),
        Duration::from_secs(timeout_seconds),
    )
    .await?
    else {
        // An earlier run of this command already authorized the restore.
        return Ok(());
    };
    if offer.offer_expires_at <= Utc::now() {
        refuse!(
            "restore_offer_expired",
            "destination hypervisor restore-key offer has already expired"
        );
    }
    let destination_wrapped_data_key = keys::rewrap_backup_data_key(
        recovery,
        &keys::BackupRewrapTarget {
            source_instance_id: backup.instance_id,
            destination_instance_id,
            backup_id: backup.backup_id,
            restore_job_id: accepted.job_id,
            destination_public_key: &offer.destination_public_key,
            destination_key_fingerprint: &offer.destination_key_fingerprint,
        },
        wrapped_data_key,
    )?;
    let request = AuthorizeBackupRestoreRequest {
        destination_key_fingerprint: offer.destination_key_fingerprint,
        destination_wrapped_data_key,
    };
    let _: JobAccepted = api
        .write(
            &AuthorizeBackupRestore {
                instance_id: destination_instance_id,
                backup_id: backup.backup_id,
                job_id: accepted.job_id,
            },
            &request,
            Some(&*restore_authorization_key(idempotency_key)),
        )
        .await?;
    Ok(())
}

async fn execute_job(api: &ApiClient, command: &JobCommand, show_progress: bool) -> Result<Value> {
    match command {
        JobCommand::List {
            instance,
            state,
            kind,
            page,
        } => {
            let instance =
                resolve_optional_instance(api, instance.as_ref(), InstanceUse::Read).await?;
            let filters = [
                ("instance_id", instance.map(|id| id.to_string())),
                ("state", state.map(wire_name)),
                ("kind", kind.map(wire_name)),
            ]
            .into_iter()
            .filter_map(|(name, value)| Some((name, value?)))
            .collect::<Vec<_>>();
            let jobs: JobPage = api.read(&ListJobs, &page.query_after(&filters)).await?;
            to_value(jobs)
        }
        JobCommand::Get { job_id } => {
            let job: JobView = api
                .read(&GetJob { job_id: *job_id }, "")
                .await
                .map_err(|error| job_read_error(error, *job_id))?;
            to_value(job)
        }
        JobCommand::Watch {
            job_id,
            poll_seconds,
        } => finished_job(
            wait_for_job(
                api,
                *job_id,
                Duration::from_secs(*poll_seconds),
                show_progress,
            )
            .await?,
        ),
    }
}

async fn execute_support(api: &ApiClient, command: &SupportCommand) -> Result<Value> {
    match command {
        SupportCommand::List { state, all } => {
            let mut parameters = Vec::new();
            if let Some(state) = state {
                parameters.push(format!("state={}", wire_name(state)));
            }
            if *all {
                parameters.push("all=true".to_owned());
            }
            let tickets: Vec<SupportTicketSummaryView> =
                api.read(&ListTickets, &parameters.join("&")).await?;
            to_value(tickets)
        }
        SupportCommand::Get { ticket_id } => {
            let ticket: SupportTicketView = api
                .read(
                    &GetTicket {
                        ticket_id: *ticket_id,
                    },
                    "",
                )
                .await?;
            to_value(ticket)
        }
        SupportCommand::Create(args) => {
            let message = load_required_text(
                args.message.as_deref(),
                args.message_file.as_deref(),
                "message",
            )?;
            let instance =
                resolve_optional_instance(api, args.instance.as_ref(), InstanceUse::Change).await?;
            let resource = if let Some(instance_id) = instance {
                Some(SupportTicketResourceInput::Instance { instance_id })
            } else if let Some(backup_id) = args.backup {
                Some(SupportTicketResourceInput::Backup { backup_id })
            } else if let Some(ledger_transaction_id) = args.ledger_transaction {
                Some(SupportTicketResourceInput::LedgerTransaction {
                    ledger_transaction_id,
                })
            } else if let Some(host_id) = args.host {
                Some(SupportTicketResourceInput::Host { host_id })
            } else {
                args.provider_incident.map(|provider_incident_id| {
                    SupportTicketResourceInput::ProviderIncident {
                        provider_incident_id,
                    }
                })
            };
            let key = match (args.instance.as_ref(), instance) {
                (Some(reference), Some(instance_id)) => {
                    retried_by_id(args.mutation.key(), reference, instance_id)
                }
                _ => args.mutation.key(),
            };
            let ticket: SupportTicketView = api
                .write_retryable(
                    &CreateTicket,
                    &CreateSupportTicketRequest {
                        category: args.category,
                        priority: args.priority,
                        subject: args.subject.clone(),
                        message,
                        resource,
                    },
                    &key,
                )
                .await?;
            to_value(ticket)
        }
        SupportCommand::Reply(args) => {
            let message = load_required_text(
                args.message.as_deref(),
                args.message_file.as_deref(),
                "message",
            )?;
            let ticket: SupportTicketView = api
                .write_retryable(
                    &AddTicketMessage {
                        ticket_id: args.ticket_id,
                    },
                    &AddSupportTicketMessageRequest { message },
                    &args.mutation.key(),
                )
                .await?;
            to_value(ticket)
        }
        SupportCommand::State(args) => {
            let ticket: SupportTicketView = api
                .write_retryable(
                    &SetTicketState {
                        ticket_id: args.ticket_id,
                    },
                    &SetSupportTicketStateRequest {
                        state: args.state,
                        waiting_on: args.waiting_on,
                    },
                    &args.mutation.key(),
                )
                .await?;
            to_value(ticket)
        }
    }
}

async fn mutation_result(
    api: &ApiClient,
    accepted: JobAccepted,
    args: &MutationArgs,
    show_progress: bool,
) -> Result<Value> {
    if args.wait {
        if show_progress {
            let job_id = accepted.job_id;
            notice(&format!(
                "Waiting for job {job_id}. Ctrl-C stops waiting, not the job.\nTo follow it again: ghost job watch {job_id}"
            ));
        }
        finished_job(
            wait_for_job(
                api,
                accepted.job_id,
                Duration::from_secs(args.poll_seconds),
                show_progress,
            )
            .await?,
        )
    } else {
        to_value(accepted)
    }
}

/// A waited job that ended failed or cancelled. The binary prints its final
/// snapshot like a result and then exits non-zero, so scripts using `--wait`
/// or `job watch` see the failure.
#[derive(Debug)]
pub struct JobUnsuccessful {
    snapshot: Value,
    message: String,
}

impl JobUnsuccessful {
    /// The job's final durable snapshot.
    #[must_use]
    pub const fn snapshot(&self) -> &Value {
        &self.snapshot
    }
}

impl std::fmt::Display for JobUnsuccessful {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for JobUnsuccessful {}

/// A finished job's snapshot, or [`JobUnsuccessful`] unless it succeeded:
/// one that ended in a state of a newer backend did not succeed as far as
/// this `ghost` can tell.
fn finished_job(job: JobView) -> Result<Value> {
    if job.state == JobState::Succeeded {
        return to_value(job);
    }
    let ended = if job.state == JobState::Unknown {
        format!("in a state this ghost does not know ({OLDER_THAN_THE_BACKEND})")
    } else {
        wire_name(job.state)
    };
    let message = format!(
        "job {} ended {ended}: {}",
        job.job_id,
        job.error_message.as_deref().unwrap_or("no error reported")
    );
    Err(JobUnsuccessful {
        snapshot: to_value(job)?,
        message,
    }
    .into())
}

/// How long a job poll keeps retrying transient failures in a row before it
/// gives up.
const TRANSIENT_POLL_WINDOW: Duration = Duration::from_mins(5);
/// The longest pause between retries of a failing job poll.
const MAXIMUM_POLL_RETRY_DELAY: Duration = Duration::from_secs(30);

/// Read a job, retrying transport failures, timeouts, and overloaded or
/// failing servers with backoff for up to [`TRANSIENT_POLL_WINDOW`]. The job
/// keeps running on the server either way, so each retry notice and the
/// final error name it.
async fn read_job(api: &ApiClient, job_id: Uuid, interval: Duration) -> Result<JobView> {
    read_job_as(api, job_id, interval).await
}

/// [`read_job`] into `T`.
async fn read_job_as<T: DeserializeOwned>(
    api: &ApiClient,
    job_id: Uuid,
    interval: Duration,
) -> Result<T> {
    let started = tokio::time::Instant::now();
    let mut delay = interval;
    loop {
        match api.read_as(&GetJob { job_id }, "").await {
            Ok(job) => return Ok(job),
            Err(error)
                if api::is_transient(&error) && started.elapsed() < TRANSIENT_POLL_WINDOW =>
            {
                notice(&format!(
                    "job {job_id}: {}. Retrying in {} s.",
                    escape_control(format!("{error:#}").trim_end_matches('.')),
                    delay.as_secs()
                ));
                tokio::time::sleep(delay).await;
                delay = next_poll_retry_delay(delay, interval);
            }
            // Waiting longer cannot make a job that is not there appear.
            Err(error) if api::rejection(&error).is_some_and(|answer| answer.status == 404) => {
                return Err(job_read_error(error, job_id));
            }
            Err(error) => {
                return Err(error.context(JobContext {
                    job_id,
                    message: format!(
                        "stopped following job {job_id}; check it later with `ghost job watch {job_id}`"
                    ),
                }));
            }
        }
    }
}

/// `error` from reading job `job_id`, saying what the backend's 404 for
/// it means: this account has no such job.
fn job_read_error(error: anyhow::Error, job_id: Uuid) -> anyhow::Error {
    if api::rejection(&error).is_some_and(|answer| answer.status == 404) {
        error.context(format!(
            "there is no job {job_id} in this account; `ghost job list` lists its jobs"
        ))
    } else {
        error
    }
}

/// Double the pause after each failed poll, up to
/// [`MAXIMUM_POLL_RETRY_DELAY`] but never below the poll interval, without
/// overflowing for a huge `--poll-seconds`.
fn next_poll_retry_delay(delay: Duration, interval: Duration) -> Duration {
    delay
        .saturating_mul(2)
        .min(MAXIMUM_POLL_RETRY_DELAY.max(interval))
}

/// Why a `ghost` does not know a state or a kind the backend names.
const OLDER_THAN_THE_BACKEND: &str =
    "this ghost is older than the backend; update it to follow such a job";

/// A job as read, with the name of its state as the backend sent it, which
/// keeps the name of a state a newer backend added (`JobState::Unknown`).
struct ReadJob {
    job: JobView,
    state: String,
}

impl<'de> Deserialize<'de> for ReadJob {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        use serde::de::Error as _;

        let value = Value::deserialize(deserializer)?;
        let state = value
            .get("state")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let job = JobView::deserialize(value).map_err(D::Error::custom)?;
        Ok(Self { job, state })
    }
}

/// Follow a job until it ends ([`terminal`]). One in a state this `ghost`
/// does not know, which a newer backend added, ends once it has completed;
/// until it does, the waiting stops after [`TRANSIENT_POLL_WINDOW`], with a
/// notice naming the state, as nothing here can tell whether it still runs.
async fn wait_for_job(
    api: &ApiClient,
    job_id: Uuid,
    interval: Duration,
    show_progress: bool,
) -> Result<JobView> {
    wait_for_job_within(api, job_id, interval, show_progress, TRANSIENT_POLL_WINDOW).await
}

/// [`wait_for_job`], waiting at most `unknown_window` on a job in a state
/// this `ghost` does not know.
async fn wait_for_job_within(
    api: &ApiClient,
    job_id: Uuid,
    interval: Duration,
    show_progress: bool,
    unknown_window: Duration,
) -> Result<JobView> {
    let mut printed = PrintedEvents::new();
    let mut unknown_since = None;
    loop {
        let ReadJob { job, state } = read_job_as(api, job_id, interval).await?;
        if show_progress {
            for line in new_event_lines(&job, &mut printed, Terminal::stderr().colors) {
                notice(&line);
            }
        }
        if terminal(&job) {
            return Ok(job);
        }
        if job.state == JobState::Unknown {
            let state = escape_control(&state);
            let since = *unknown_since.get_or_insert_with(tokio::time::Instant::now);
            if since.elapsed() >= unknown_window {
                let message = format!(
                    "Stopped following job {job_id}.\nIt is in a state this ghost does not know ({state}) and has not completed.\nThis ghost is older than the backend: update it to follow such a job.\nTo check the job: ghost job get {job_id}"
                );
                notice(&message);
                return Err(anyhow::Error::msg(JobContext { job_id, message }));
            }
        } else {
            unknown_since = None;
        }
        tokio::time::sleep(interval).await;
    }
}

/// What each event of a followed job said when it was last printed: its
/// whole percent and its message.
type PrintedEvents = HashMap<u64, (Option<u16>, Option<String>)>;

/// The lines for events not yet printed as they appear in `job` now.
/// An event is printed again when its whole percent or message changes.
/// An event names its step; older responses require lookup in the job's
/// steps.
fn new_event_lines(job: &JobView, printed: &mut PrintedEvents, colors: bool) -> Vec<String> {
    let steps = job
        .steps
        .iter()
        .map(|step| (step.step_id, step.step_key.as_str()))
        .collect::<HashMap<_, _>>();
    let mut lines = Vec::new();
    for event in &job.events {
        let shown = (
            event.progress_permyriad.map(|value| value / 100),
            event.message.clone(),
        );
        if printed.get(&event.event_id) != Some(&shown) {
            let step = event
                .step_key
                .as_deref()
                .or_else(|| event.step_id.and_then(|id| steps.get(&id).copied()));
            lines.push(format_job_event(event, step, colors));
            printed.insert(event.event_id, shown);
        }
    }
    lines
}

/// One line for a job event: its state, attempt and progress in brackets,
/// in the state's color on a stream with `colors`, then the step it belongs
/// to and its message. A queued step's attempt 0 and a waiting step's 0%
/// say nothing, so they are left out.
fn format_job_event(event: &JobEventView, step: Option<&str>, colors: bool) -> String {
    let state_name = event.state.as_deref().unwrap_or("update");
    let state = job_state_words(state_name);
    let mut parts = vec![state];
    if let Some(attempt) = event.attempt.filter(|attempt| *attempt > 0) {
        parts.push(format!("attempt {attempt}"));
    }
    if let Some(value) = event
        .progress_permyriad
        .filter(|value| *value > 0 || state_name == "running")
    {
        parts.push(percent_text(value));
    }
    let step = step
        .map(|step| format!("{}: ", job_step_words(step)))
        .unwrap_or_default();
    let message = escape_control(event.message.as_deref().unwrap_or("job state changed"));
    let tag = pretty::paint_state(state_name, &format!("[{}]", parts.join(", ")), colors);
    format!("{tag} {step}{message}")
}

/// An instance state as people say it; one this release does not know is
/// shown as the backend sent it.
fn instance_state_words(state: InstanceState) -> String {
    match state {
        InstanceState::PendingPayment => "waiting for payment".to_owned(),
        InstanceState::Provisioning => "being set up".to_owned(),
        other => escape_control(&wire_name(other)).into_owned(),
    }
}

/// A job or step state as people say it; one this release does not know is
/// shown as the backend sent it.
fn job_state_words(state: &str) -> String {
    match state {
        "pending" => "queued".to_owned(),
        "leased" => "starting".to_owned(),
        "retry_wait" => "waiting to retry".to_owned(),
        "running" | "succeeded" | "failed" | "cancelled" | "update" => state.to_owned(),
        other => escape_control(other).into_owned(),
    }
}

/// What a job step does, in words: a step this release does not know is its
/// key with the underscores as spaces.
fn job_step_words(key: &str) -> String {
    let known = match key {
        "create_instance" => "creating the instance",
        "create_container_instance" => "creating the container",
        "redeploy_container_instance" => "updating the container",
        "delete_instance" => "deleting the instance",
        "delete_instance_record" => "removing the instance record",
        "reinstall_instance" => "reinstalling the instance",
        "reset_instance_access" => "restarting the instance to reset SSH access",
        "rescue_instance" => "booting the rescue system",
        "end_instance_rescue" => "booting the instance's own system",
        "upgrade_instance" => "upgrading the instance",
        "set_power_state" => "changing the power state",
        "wait_for_ssh" => "waiting for SSH",
        "create_backup" => "creating the backup",
        "upload_parts" => "uploading the backup",
        "publish_backup" => "publishing the backup",
        "restore_backup" => "restoring the backup",
        "download_backup" => "downloading the backup",
        "await_restore_authorization" => "waiting for the restore to be authorized",
        "prepare_restore_key" => "preparing the restore key",
        "discard_restore_key" => "discarding the restore key",
        "start_restored_instance" => "starting the restored instance",
        "delete_hosted_backup" => "deleting the hosted backup",
        "delete_local_backup" => "deleting the local backup",
        "verify_backup" => "verifying the backup",
        "verify_backup_pool" => "verifying the backup pool",
        "provision_gateway" => "setting up the gateway",
        "prepare_gateway_tunnel" => "preparing the gateway tunnel",
        "rebind_gateway_tunnel" => "rebinding the gateway tunnel",
        "rotate_gateway_tunnel" => "rotating the gateway tunnel",
        "await_gateway_handshake" => "waiting for the gateway handshake",
        "await_gateway_key_rotation" => "waiting for the gateway key rotation",
        "await_gateway_ready" => "waiting for the gateway",
        "await_gateway_termination" => "waiting for the gateway to end",
        "terminate_gateway" => "ending the gateway",
        "move_gateway_lease" => "moving the gateway",
        "configure_router_gateway" => "configuring the router gateway",
        "unconfigure_router_gateway" => "removing the router gateway",
        "attach_router_address" => "attaching the address",
        "detach_router_address" => "detaching the address",
        "start_address_check" => "starting the address check",
        "probe_address_check" => "probing the address",
        "stop_address_check" => "stopping the address check",
        other => return escape_control(&other.replace('_', " ")).into_owned(),
    };
    known.to_owned()
}

/// Print what renting `offering_id` costs before it is rented. A malformed
/// ID is refused here, and so is a rental of a listed offering that the
/// backend would refuse for its gateway tier or `backup`. One the catalog
/// does not list now is only warned about: the backend decides whether it
/// can still be rented, and a retried creation may itself have taken the
/// offering's last capacity.
async fn quote_offering(
    api: &ApiClient,
    offering_id: &str,
    gateway_tier: Option<GatewayTier>,
    backup: Option<&BackupView>,
    kind: Option<InstanceKind>,
    heading: Option<&str>,
) -> Result<()> {
    check_offering_id(offering_id)?;
    let colors = Terminal::stderr().colors;
    // As the account reads the catalog: a private host's offering is listed to the accounts its
    // provider allows alone.
    let read = api
        .read_as_account(
            &GetOffering {
                offering_id: offering_id.to_owned(),
            },
            "",
        )
        .await;
    match read {
        Ok(offering) => {
            if let Some(kind) = kind {
                check_kind(&offering, kind)?;
            }
            check_rental(&offering, gateway_tier, backup)?;
            if let Some(tier) = gateway_tier.filter(|tier| {
                !offering
                    .network_prices
                    .iter()
                    .any(|price| price.gateway_tier == Some(*tier))
            }) {
                notice(&unlisted_gateway_warning(offering_id, tier));
            }
            if let Some(heading) = heading {
                notice(heading);
            }
            for line in offering_quote(
                &offering,
                gateway_tier,
                backup.and_then(restore_charge),
                colors,
            ) {
                notice(&line);
            }
            notice("");
            Ok(())
        }
        Err(error) if api::rejection_code(&error) == Some("invalid_offering_token") => Err(error),
        Err(error) => {
            notice(&format!(
                "offering {} is not listed right now ({}); the backend decides whether it can still be rented",
                escape_control(offering_id),
                escape_control(&format!("{error:#}"))
            ));
            if let Some(quote) = backup.and_then(|backup| restore_quote(backup, colors)) {
                notice(&quote);
                notice("");
            }
            Ok(())
        }
    }
}

/// What a quote warns when the offering `offering_id` lists no price for
/// the gateway `tier` that was asked for, the tier as people say it.
fn unlisted_gateway_warning(offering_id: &str, tier: GatewayTier) -> String {
    format!(
        "offering {} lists no {} gateway right now, so its gateway charges are not known here; the backend decides whether it can still be rented",
        escape_control(offering_id),
        gateway_tier_words(tier)
    )
}

/// The prices to choose from after a refusal's "give --gateway-tier": a
/// colon and the table, or nothing when no prices are listed.
fn tier_choices(prices: &[gigahost_client_api::website::NetworkPriceView], cloud: bool) -> String {
    if prices.is_empty() {
        String::new()
    } else {
        format!(":\n{}", network_prices_text(prices, cloud))
    }
}

/// Refuse a rental of `offering` that the backend would refuse, as an
/// invalid request: a home offering without a gateway tier, a cloud
/// offering with one but the shared IP, or without it where the offering
/// lists the shared IP alone (its hosts have no address of the VM's own
/// left), or a root disk smaller than the disk of the `backup` it would be
/// created from.
fn check_rental(
    offering: &OfferingView,
    gateway_tier: Option<GatewayTier>,
    backup: Option<&BackupView>,
) -> Result<()> {
    let id = escape_control(&offering.offering_id);
    match (offering.host_mode, gateway_tier) {
        (HostMode::HomeGateway, None) => refuse!(
            "invalid_request",
            "offering {id} is on a home host, which a hosted gateway connects.\nTo choose its tier, give --gateway-tier{}",
            tier_choices(&offering.network_prices, false)
        ),
        (HostMode::CloudRouted, Some(tier)) if tier != GatewayTier::SharedIp => refuse!(
            "invalid_request",
            "offering {id} is on a cloud host, which needs no gateway.\nTo rent it, leave out --gateway-tier {}.\nTo share the host's address instead: --gateway-tier shared_ip",
            wire_name(tier)
        ),
        (HostMode::CloudRouted, None)
            if offering
                .network_prices
                .iter()
                .all(|price| price.gateway_tier.is_some())
                && offering
                    .network_prices
                    .iter()
                    .any(|price| price.gateway_tier == Some(GatewayTier::SharedIp)) =>
        {
            refuse!(
                "invalid_request",
                "offering {id} has no address of the VM's own left on its host, which shares its own address instead.\nTo rent it, give --gateway-tier shared_ip{}",
                tier_choices(&offering.network_prices, true)
            )
        }
        _ => {}
    }
    if let Some(backup) = backup
        && let Some(disk_bytes) = backup.disk_bytes
        && offering.root_disk_bytes < disk_bytes
    {
        refuse!(
            "invalid_request",
            "offering {id} has a {} root disk, smaller than the {} disk of backup {}; find an offering that can take it with `ghost catalog offerings --for-backup {}`",
            pretty::binary_size(offering.root_disk_bytes),
            pretty::binary_size(disk_bytes),
            backup.backup_id,
            backup.backup_id
        );
    }
    Ok(())
}

/// Refuse what cannot be an offering ID before it goes into a URL path,
/// which only base64url characters leave as they are, as the backend
/// refuses an invalid one.
fn check_offering_id(offering_id: &str) -> Result<()> {
    if offering_id.is_empty()
        || !offering_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        refuse!(
            "invalid_offering_token",
            "offering {} is not an offering ID; copy one from `ghost catalog offerings`",
            escape_control(offering_id)
        );
    }
    Ok(())
}

/// One row of a quote block.
#[derive(Clone, Debug, Eq, PartialEq)]
enum QuoteRow {
    /// A label and what it names.
    Fact(&'static str, String),
    /// A label (empty on a row that continues the one above), an amount
    /// and what it is for.
    Money(&'static str, String, String),
    /// An empty line between two groups of rows.
    Gap,
}

/// `rows` as lines of a block: the labels in one column, the values in the
/// next, the amounts right-aligned among themselves. Bold labels and
/// amounts on a stream with `colors`. Every text in a row has been through
/// [`escape_control`] by the caller.
fn quote_block(rows: &[QuoteRow], colors: bool) -> Vec<String> {
    let label_width = rows
        .iter()
        .filter_map(|row| match row {
            QuoteRow::Fact(label, _) | QuoteRow::Money(label, _, _) => Some(label.chars().count()),
            QuoteRow::Gap => None,
        })
        .max()
        .unwrap_or(0);
    let amount_width = rows
        .iter()
        .filter_map(|row| match row {
            QuoteRow::Money(_, amount, _) => Some(amount.chars().count()),
            _ => None,
        })
        .max()
        .unwrap_or(0);
    let label = |text: &str| {
        let padding = " ".repeat(label_width - text.chars().count());
        format!("{}{padding}", pretty::paint_bold(text, colors))
    };
    rows.iter()
        .map(|row| match row {
            QuoteRow::Fact(name, value) => format!("  {}   {value}", label(name)),
            QuoteRow::Money(name, amount, text) => {
                let padding = " ".repeat(amount_width - amount.chars().count());
                format!(
                    "  {}   {padding}{}  {text}",
                    label(name),
                    pretty::paint_bold(amount, colors)
                )
            }
            QuoteRow::Gap => String::new(),
        })
        .collect()
}

/// A job kind as the instance list says what an instance is busy with; one
/// this release does not know is shown as the backend sent it.
fn job_kind_words(kind: JobKind) -> String {
    match kind {
        JobKind::CreateInstance => "creating",
        JobKind::SetPowerState => "changing power state",
        JobKind::DeleteInstance => "deleting",
        JobKind::CreateBackup => "backing up",
        JobKind::RestoreBackup => "restoring",
        JobKind::DeleteBackup => "deleting a backup",
        JobKind::ReinstallInstance => "reinstalling",
        JobKind::ResetInstanceAccess => "resetting SSH access",
        JobKind::RescueInstance => "booting into rescue",
        JobKind::EndInstanceRescue => "ending the rescue",
        JobKind::UpgradeInstance => "upgrading",
        JobKind::RotateGatewayKeys => "rotating gateway keys",
        JobKind::MoveGatewayLease => "moving the gateway",
        JobKind::TuneBandwidth => "tuning bandwidth",
        JobKind::RedeployContainerInstance => "updating",
        JobKind::Unknown => return wire_name(kind),
    }
    .to_owned()
}

/// A progress of `permyriad` (hundredths of a percent) as `37.5 %`, without
/// trailing zeros.
fn percent_text(permyriad: impl Into<u32>) -> String {
    let percent = format!("{:.2}", f64::from(permyriad.into()) / 100.0);
    format!("{} %", percent.trim_end_matches('0').trim_end_matches('.'))
}

/// A host mode as people say it.
fn host_words(mode: HostMode) -> String {
    match mode {
        HostMode::HomeGateway => "home".to_owned(),
        HostMode::CloudRouted => "cloud".to_owned(),
        HostMode::Unknown => wire_name(mode),
    }
}

/// A gateway tier as people say it.
fn gateway_tier_words(tier: GatewayTier) -> String {
    match tier {
        GatewayTier::SharedBandwidth => "shared bandwidth".to_owned(),
        GatewayTier::HighBandwidth => "high bandwidth".to_owned(),
        GatewayTier::SharedIp => "shared IP".to_owned(),
        GatewayTier::Unknown => wire_name(tier),
    }
}

/// What an offering is and what renting it costs, as the lines of a block
/// of labelled rows, with the `restore` charge of a creation from a backup.
fn offering_quote(
    offering: &OfferingView,
    gateway_tier: Option<GatewayTier>,
    restore: Option<u64>,
    colors: bool,
) -> Vec<String> {
    let network = offering
        .network_prices
        .iter()
        .find(|price| price.gateway_tier == gateway_tier);
    // A cloud offering's shared IP is its address, not a gateway: its
    // price takes the place of the address the hold and the listed price
    // count.
    let cloud = offering.host_mode == HostMode::CloudRouted;
    let gateway = network
        .zip(gateway_tier)
        .filter(|_| !cloud)
        .map(|(price, tier)| {
            (
                price.gateway_base_charge_microusd_per_month,
                gateway_tier_words(tier),
            )
        });
    let address = match (cloud, gateway_tier, network) {
        (true, Some(GatewayTier::SharedIp), Some(price)) => {
            price.gateway_base_charge_microusd_per_month
        }
        _ => offering.address_microusd_per_month,
    };
    let hold = offering
        .balance_reservation_microusd
        .saturating_sub(offering.address_microusd_per_month)
        .saturating_add(address)
        .saturating_add(gateway.as_ref().map_or(0, |(base, _)| *base));
    let shared_ip_included = cloud && gateway_tier == Some(GatewayTier::SharedIp);

    let location = if offering.location_name.is_empty() {
        escape_control(&offering.location).into_owned()
    } else {
        format!(
            "{} ({})",
            escape_control(&offering.location_name),
            escape_control(&offering.location)
        )
    };
    let mut rows = vec![
        QuoteRow::Fact(
            "Offering",
            escape_control(&offering.offering_id).into_owned(),
        ),
        QuoteRow::Fact(
            "Size",
            size_text(
                offering.vcpu_count,
                offering.memory_bytes,
                offering.root_disk_bytes,
            ),
        ),
        QuoteRow::Fact("Location", location),
        QuoteRow::Fact(
            "Host",
            format!(
                "{}, provider {}",
                host_words(offering.host_mode),
                escape_control(&offering.provider_name)
            ),
        ),
    ];
    let mut network_parts = Vec::new();
    if let Some((_, tier)) = &gateway {
        network_parts.push(format!("{tier} gateway"));
    } else if shared_ip_included {
        network_parts.push("shared IP, included".to_owned());
    }
    if let Some(bandwidth) = network.and_then(|network| network.bandwidth) {
        network_parts.push(bandwidth_text(bandwidth));
    }
    if !network_parts.is_empty() {
        rows.push(QuoteRow::Fact("Network", network_parts.join(", ")));
    }

    rows.push(QuoteRow::Gap);
    rows.push(QuoteRow::Money(
        "Now",
        pretty::dollars(offering.instance_creation_charge_microusd),
        "creation fee, refunded if the creation fails unless you caused it".to_owned(),
    ));
    if let Some(restore) = restore {
        rows.push(QuoteRow::Money(
            "",
            pretty::dollars(restore),
            "backup restore, not refunded".to_owned(),
        ));
    }
    rows.push(QuoteRow::Money(
        "Monthly",
        pretty::dollars(offering.base_price_microusd_per_month),
        format!(
            "base, up to {} at full CPU",
            pretty::dollars(offering.full_utilization_price_microusd_per_month)
        ),
    ));
    if let Some((base, tier)) = &gateway {
        rows.push(QuoteRow::Money(
            "",
            pretty::dollars(*base),
            format!("{tier} gateway"),
        ));
    }
    // A cloud offering's address, which its balance hold includes a month
    // of: its own, or its shared IP, which the host's fixed price includes.
    if !shared_ip_included && address > 0 {
        rows.push(QuoteRow::Money(
            "",
            pretty::dollars(address),
            "address".to_owned(),
        ));
    }
    if let Some(network) = network {
        rows.push(QuoteRow::Money(
            "Traffic",
            pretty::dollars(network.combined_microusd_per_tib),
            "per TiB".to_owned(),
        ));
    }
    rows.push(QuoteRow::Money(
        "Held",
        pretty::dollars(hold),
        "of your balance while the instance exists".to_owned(),
    ));
    quote_block(&rows, colors)
}

/// An instance reference as the user typed it, for the command a refusal
/// tells them to run.
fn instance_reference_text(reference: &InstanceReference) -> String {
    match reference {
        InstanceReference::Id(id) => id.to_string(),
        InstanceReference::Name(name) => name.clone(),
    }
}

/// A price that changes: `$2.35 → $4.70`, or the new price alone where the
/// old one is not known.
fn price_change(before: Option<u64>, after: u64) -> String {
    match before {
        Some(before) => format!("{} → {}", pretty::dollars(before), pretty::dollars(after)),
        None => pretty::dollars(after),
    }
}

/// The notice for a read that failed: the quote is missing, the command
/// goes on, and the backend decides.
fn prices_unread_notice(error: &anyhow::Error) -> String {
    format!(
        "the prices could not be read ({}); the backend decides",
        escape_control(&format!("{error:#}"))
    )
}

/// The block that tells what an upgrade to `offering_id` changes, or the
/// notice that says why there is none.
fn upgrade_quote(
    instance: &InstanceView,
    upgrades: &[InstanceUpgradeView],
    offering_id: &str,
    colors: bool,
) -> Result<Vec<String>, String> {
    let Some(upgrade) = upgrades
        .iter()
        .find(|upgrade| upgrade.offering_id == offering_id)
    else {
        return Err(format!(
            "offering {} is not among this instance's upgrades right now (ghost instance upgrades {} lists them), or this repeats an upgrade already made; the backend decides",
            escape_control(offering_id),
            instance.instance_id
        ));
    };
    if !upgrade.available {
        return Err(format!(
            "the host has no room for offering {} right now; the backend decides",
            escape_control(offering_id)
        ));
    }
    let new_size = size_text(
        upgrade.vcpu_count,
        upgrade.memory_bytes,
        upgrade.root_disk_bytes,
    );
    let size = if instance.vcpu_count == 0 {
        new_size
    } else {
        format!(
            "{}  →  {new_size}",
            size_text(
                instance.vcpu_count,
                instance.memory_bytes,
                instance.root_disk_bytes
            )
        )
    };
    let current = instance.pricing.as_ref().map(|pricing| &pricing.current);
    let mut rows = vec![
        QuoteRow::Fact("Size", size),
        QuoteRow::Money(
            "Monthly",
            price_change(
                current.map(|prices| prices.base_price_microusd_per_month),
                upgrade.base_price_microusd_per_month,
            ),
            "base".to_owned(),
        ),
        QuoteRow::Money(
            "",
            price_change(
                current.map(|prices| prices.full_utilization_price_microusd_per_month),
                upgrade.full_utilization_price_microusd_per_month,
            ),
            "at full CPU".to_owned(),
        ),
    ];
    if upgrade.balance_reservation_increase_microusd > 0 {
        rows.push(QuoteRow::Money(
            "Held",
            format!(
                "+{}",
                pretty::dollars(upgrade.balance_reservation_increase_microusd)
            ),
            "more of your balance, taken now".to_owned(),
        ));
    }
    let mut lines = vec![format!(
        "Upgrading {} ({}):",
        escape_control(instance.display_name()),
        instance.instance_id
    )];
    lines.extend(quote_block(&rows, colors));
    lines.push("  The instance shuts down and starts again with the new size.".to_owned());
    Ok(lines)
}

/// Print what an upgrade changes before it is asked for. A read that fails
/// only costs the quote.
async fn quote_upgrade(api: &ApiClient, instance_id: Uuid, offering_id: &str) {
    let colors = Terminal::stderr().colors;
    let read = async {
        let instance: InstanceView = api.read(&GetInstance { instance_id }, "").await?;
        let upgrades: Vec<InstanceUpgradeView> =
            api.read(&ListInstanceUpgrades { instance_id }, "").await?;
        Ok::<_, anyhow::Error>((instance, upgrades))
    };
    match read.await {
        Ok((instance, upgrades)) => {
            match upgrade_quote(&instance, &upgrades, offering_id, colors) {
                Ok(lines) => {
                    for line in lines {
                        notice(&line);
                    }
                    notice("");
                }
                Err(text) => notice(&text),
            }
        }
        Err(error) => notice(&prices_unread_notice(&error)),
    }
}

/// What a change of an instance's gateway costs, as the quote read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChangeCharge {
    /// Nothing: the gateway is being retired and the owner was asked to
    /// move the instance (`gateway_change_free`).
    Free,
    /// The offering's instance creation charge, in micro-dollars.
    Amount(u64),
    /// Not read: an older backend, or a read that failed.
    Unknown,
}

impl ChangeCharge {
    /// The charge of a change of `instance`'s gateway under `offering`.
    fn of(instance: &InstanceView, offering: &OfferingView) -> Self {
        if instance.gateway_change_free {
            Self::Free
        } else if offering.instance_creation_charge_microusd > 0 {
            Self::Amount(offering.instance_creation_charge_microusd)
        } else {
            Self::Unknown
        }
    }
}

/// What a change of the gateway costs and does, as the error of the
/// command without `--yes` words it: the charge when it is known (the
/// offering's), else the charge by name.
fn gateway_change_warning(charge: ChangeCharge) -> String {
    let charge = match charge {
        ChangeCharge::Free => "nothing: the gateway is being retired".to_owned(),
        ChangeCharge::Amount(charge) => {
            format!("{} (the instance creation charge)", pretty::dollars(charge))
        }
        ChangeCharge::Unknown => "the instance creation charge".to_owned(),
    };
    format!(
        "the change costs {charge}; the VM gets a new public address and is unreachable for the seconds the change takes."
    )
}

/// The block that tells what a change of `instance`'s gateway to `tier`
/// (its own when none) at `location` (its own when none) costs and
/// changes, or the notice that says why there is none.
fn gateway_change_quote(
    instance: &InstanceView,
    offering: &OfferingView,
    tier: Option<GatewayTier>,
    location: Option<&str>,
    colors: bool,
) -> Result<Vec<String>, String> {
    // The offering's locations and their prices are what a shared tier
    // pays there (`GatewayLocationView`); the backend decides any other.
    let current_tier = match instance.gateway_tier {
        Some(
            tier @ (GatewayTier::SharedBandwidth
            | GatewayTier::SharedIp
            | GatewayTier::HighBandwidth),
        ) => tier,
        Some(GatewayTier::Unknown) | None => {
            return Err(
                "the price of a change is not shown for this instance; the backend decides"
                    .to_owned(),
            );
        }
    };
    let target_tier = tier.unwrap_or(current_tier);
    if target_tier == GatewayTier::HighBandwidth {
        return high_bandwidth_quote(instance, offering, current_tier, location, colors);
    }
    // Off a gateway of its own without a location, the VM stays at its
    // location where a shared gateway there is listed, else goes to the
    // preselected one, as the backend places it.
    let location = location.or_else(|| {
        let own = instance.gateway_location.as_deref();
        if current_tier == GatewayTier::HighBandwidth
            && !offering
                .gateway_locations
                .iter()
                .any(|candidate| Some(candidate.location.as_str()) == own)
        {
            offering
                .gateway_locations
                .iter()
                .find(|candidate| candidate.preselected)
                .map(|candidate| candidate.location.as_str())
                .or(own)
        } else {
            own
        }
    });
    let Some(location) = location else {
        return Err(
            "the instance's gateway has no location of record; name one with --location; the backend decides"
                .to_owned(),
        );
    };
    if target_tier == current_tier && instance.gateway_location.as_deref() == Some(location) {
        return Err(format!(
            "the instance is reached through a {} gateway at {} already (or this repeats a change already made); the backend decides",
            gateway_tier_words(current_tier),
            escape_control(location)
        ));
    }
    let Some(target) = offering
        .gateway_locations
        .iter()
        .find(|candidate| candidate.location == location)
    else {
        return Err(format!(
            "{} is not among this offering's gateway locations (ghost catalog offering {} lists them); the backend decides",
            escape_control(location),
            escape_control(&offering.offering_id)
        ));
    };
    let place = if target.location_name.is_empty() {
        escape_control(&target.location).into_owned()
    } else {
        format!(
            "{} ({})",
            escape_control(&target.location_name),
            escape_control(&target.location)
        )
    };
    // A shared IP pays the slice prices of the location where it lists
    // them, else the gateway's.
    let (target_base, target_network) = if target_tier == GatewayTier::SharedIp
        && (target.shared_ip_base_charge_microusd_per_month != 0
            || target.shared_ip_network_microusd_per_tib != 0)
    {
        (
            target.shared_ip_base_charge_microusd_per_month,
            target.shared_ip_network_microusd_per_tib,
        )
    } else {
        (
            target.gateway_base_charge_microusd_per_month,
            target.gateway_network_microusd_per_tib,
        )
    };
    let current = instance.pricing.as_ref().map(|pricing| &pricing.current);
    let mut distance = format!("{} km from the host", target.distance_km);
    if target.bottleneck {
        distance.push_str(", crosses a bottleneck");
    }
    if target_tier == GatewayTier::SharedIp && target.shared_ip_full {
        distance.push_str(", no free slice now");
    }
    let mut rows = vec![QuoteRow::Fact("Distance", distance)];
    let prices_known = target_base != 0
        || target_network != 0
        || !match current {
            Some(prices) => {
                prices.gateway_base_microusd_per_month != 0
                    || prices.gateway_network_microusd_per_tib != 0
            }
            None => instance.network_microusd_per_tib != 0,
        };
    if prices_known {
        rows.push(QuoteRow::Money(
            "Gateway",
            price_change(
                current.map(|prices| prices.gateway_base_microusd_per_month),
                target_base,
            ),
            "per month".to_owned(),
        ));
        let (after, text) = match current {
            Some(prices) => (
                prices
                    .provider_network_microusd_per_tib
                    .saturating_add(target_network),
                "per TiB",
            ),
            None => (target_network, "per TiB, gateway part"),
        };
        rows.push(QuoteRow::Money(
            "Traffic",
            price_change(
                current
                    .is_some()
                    .then_some(instance.network_microusd_per_tib),
                after,
            ),
            text.to_owned(),
        ));
    } else {
        rows.push(QuoteRow::Fact(
            "Gateway",
            "prices not known (older backend)".to_owned(),
        ));
    }
    rows.push(charge_row(instance, offering));
    let mut lines = vec![format!(
        "Changing the gateway of {} ({}) to {} in {place}:",
        escape_control(instance.display_name()),
        instance.instance_id,
        gateway_tier_words(target_tier)
    )];
    lines.extend(quote_block(&rows, colors));
    lines.push("  From now on: the new prices apply at once.".to_owned());
    lines.push(
        "  The VM gets a new public address and is unreachable for the seconds the change takes."
            .to_owned(),
    );
    Ok(lines)
}

/// The quote's row of what a change of `instance`'s gateway is charged
/// under `offering`.
fn charge_row(instance: &InstanceView, offering: &OfferingView) -> QuoteRow {
    match ChangeCharge::of(instance, offering) {
        ChangeCharge::Free => QuoteRow::Fact(
            "Charge",
            "none: the gateway is being retired and you were asked to move the instance".to_owned(),
        ),
        ChangeCharge::Amount(charge) => QuoteRow::Money(
            "Charge",
            pretty::dollars(charge),
            "per change, the instance creation charge".to_owned(),
        ),
        ChangeCharge::Unknown => QuoteRow::Fact(
            "Charge",
            "the instance creation charge (amount not known: older backend)".to_owned(),
        ),
    }
}

/// [`gateway_change_quote`] of a change to high bandwidth, from
/// `current_tier`: a gateway of the VM's own at `location`, or without one
/// nearest to the host, at the high bandwidth prices the offering lists
/// (of the nearest; another location's are the backend's to decide), made
/// in a few minutes while the VM stays on its gateway.
fn high_bandwidth_quote(
    instance: &InstanceView,
    offering: &OfferingView,
    current_tier: GatewayTier,
    location: Option<&str>,
    colors: bool,
) -> Result<Vec<String>, String> {
    if current_tier == GatewayTier::HighBandwidth {
        match location {
            None => {
                return Err(
                    "the instance has a gateway of its own already; name another location with --location; the backend decides"
                        .to_owned(),
                );
            }
            Some(location) if instance.gateway_location.as_deref() == Some(location) => {
                return Err(format!(
                    "the instance is reached through a high bandwidth gateway at {} already (or this repeats a change already made); the backend decides",
                    escape_control(location)
                ));
            }
            Some(_) => {}
        }
    }
    let place = location.map_or_else(
        || "nearest to the host".to_owned(),
        |location| format!("at {}", escape_control(location)),
    );
    let current = instance.pricing.as_ref().map(|pricing| &pricing.current);
    let mut rows = vec![QuoteRow::Fact(
        "Takes",
        "a few minutes: Vultr creates the gateway; the VM stays on its gateway until then"
            .to_owned(),
    )];
    match offering
        .network_prices
        .iter()
        .find(|price| price.gateway_tier == Some(GatewayTier::HighBandwidth))
    {
        Some(price) => {
            let listed = if location.is_some() {
                " (nearest location's)"
            } else {
                ""
            };
            rows.push(QuoteRow::Money(
                "Gateway",
                price_change(
                    current.map(|prices| prices.gateway_base_microusd_per_month),
                    price.gateway_base_charge_microusd_per_month,
                ),
                format!("per month{listed}"),
            ));
            rows.push(QuoteRow::Money(
                "Traffic",
                price_change(
                    current
                        .is_some()
                        .then_some(instance.network_microusd_per_tib),
                    price.combined_microusd_per_tib,
                ),
                format!("per TiB{listed}"),
            ));
        }
        None if offering
            .full_gateway_tiers
            .contains(&GatewayTier::HighBandwidth) =>
        {
            rows.push(QuoteRow::Fact(
                "Gateway",
                "none of its own can be set up now (the offering lists high bandwidth full)"
                    .to_owned(),
            ));
        }
        None => rows.push(QuoteRow::Fact(
            "Gateway",
            "prices not listed by the offering".to_owned(),
        )),
    }
    rows.push(charge_row(instance, offering));
    let mut lines = vec![format!(
        "Changing the gateway of {} ({}) to high bandwidth, a gateway of its own {place}:",
        escape_control(instance.display_name()),
        instance.instance_id,
    )];
    lines.extend(quote_block(&rows, colors));
    lines.push("  From now on: the new prices apply at once.".to_owned());
    lines.push(
        "  The VM gets a new public address and is unreachable for the seconds the change takes."
            .to_owned(),
    );
    Ok(lines)
}

/// Read what a gateway change costs and changes, and print it (`print`)
/// before it is asked for; returns the charge, if the reads gave it. A
/// read that fails only costs the quote. `move_only`: the quote of
/// `gateway-location`, which moves a shared tier alone.
async fn quote_gateway_change(
    api: &ApiClient,
    instance_id: Uuid,
    tier: Option<GatewayTier>,
    location: Option<&str>,
    print: bool,
    move_only: bool,
) -> ChangeCharge {
    let colors = Terminal::stderr().colors;
    let read = async {
        let instance: InstanceView = api.read(&GetInstance { instance_id }, "").await?;
        let offering: OfferingView = api
            .read_as_account(
                &GetOffering {
                    offering_id: instance.offering_id.clone(),
                },
                "",
            )
            .await?;
        Ok::<_, anyhow::Error>((instance, offering))
    };
    match read.await {
        Ok((instance, offering)) => {
            // `gateway-location` moves a shared tier alone, as the backend
            // answers it.
            if print && move_only && instance.gateway_tier == Some(GatewayTier::HighBandwidth) {
                notice(
                    "a high bandwidth instance does not move with gateway-location; ghost instance gateway --location changes it to a gateway of its own there",
                );
            } else if print {
                match gateway_change_quote(&instance, &offering, tier, location, colors) {
                    Ok(lines) => {
                        for line in lines {
                            notice(&line);
                        }
                        notice("");
                    }
                    Err(text) => notice(&text),
                }
            }
            ChangeCharge::of(&instance, &offering)
        }
        Err(error) => {
            if print {
                notice(&prices_unread_notice(&error));
            }
            ChangeCharge::Unknown
        }
    }
}

/// What a command that must rewrap a hosted backup's key prints while it
/// waits for the destination hypervisor.
fn restore_offer_notice(job_id: Uuid) -> String {
    format!("Job {job_id} accepted. Waiting for the host to be ready to receive the backup.")
}

/// Wait at most `timeout` for the destination's restore-key offer.
/// An offer read after the deadline is refused, and waiting ends at the
/// deadline rather than a poll interval later. `None` means an earlier run
/// already authorized the restore.
async fn wait_for_restore_offer(
    api: &ApiClient,
    job_id: Uuid,
    interval: Duration,
    timeout: Duration,
) -> Result<Option<RestoreKeyOffer>> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let job = read_job(api, job_id, interval).await?;
        let Some(awaiting) = job
            .steps
            .iter()
            .find(|step| step.step_key == "await_restore_authorization")
        else {
            return Ok(None);
        };
        if terminal(&job) {
            bail!(
                "restore job {job_id} ended {} before the restore was authorized: {}",
                job_state_words(&wire_name(job.state)),
                job.error_message.as_deref().unwrap_or("no error reported")
            );
        }
        if awaiting.state != JobStepState::Pending {
            bail!(
                "restore job {job_id} no longer accepts an authorization: {}",
                awaiting
                    .error_message
                    .as_deref()
                    .unwrap_or("the authorization step ended")
            );
        }
        // The deadline before the offer: one that came with a read ending
        // after it came too late.
        let now = tokio::time::Instant::now();
        if now >= deadline {
            bail!("timed out waiting for the destination hypervisor restore-key offer");
        }
        if let Some(value) = job.result.get("prepare_restore_key") {
            return serde_json::from_value(value.clone())
                .map(Some)
                .context("decode destination hypervisor restore-key offer");
        }
        tokio::time::sleep(interval.min(deadline - now)).await;
    }
}

/// Whether `job` has ended: it succeeded, failed or was cancelled, or it is
/// in a state of a newer backend this `ghost` does not know and has
/// completed.
const fn terminal(job: &JobView) -> bool {
    match job.state {
        JobState::Succeeded | JobState::Failed | JobState::Cancelled => true,
        JobState::Unknown => job.completed_at.is_some(),
        JobState::Pending | JobState::Running => false,
    }
}

/// The client for `cli`'s backend. It loads the account key only when a
/// request that needs the account is sent: the public catalog needs none.
fn api_client(cli: &Cli) -> Result<ApiClient> {
    cli.globals.api_client()
}

/// The account identity of the seed at `seed_file`, or at the default
/// path when it is `None`. Public commands work before `ghost key
/// generate`, so a missing seed at the default location means no account.
/// A seed chosen with `--seed-file` or `GHOST_SEED_FILE` must exist, or a
/// typo would silently drop the account instead of failing.
fn account_identity(seed_file: Option<&Path>) -> Result<Option<keys::AuthenticationIdentity>> {
    if seed_file.is_none() {
        let path = default_seed_path()?;
        if !path
            .try_exists()
            .with_context(|| format!("inspect {}", path.display()))?
        {
            return Ok(None);
        }
    }
    keys::authentication_identity(&*load_seed_file(seed_file)?).map(Some)
}

fn load_account_seed(cli: &Cli) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    load_seed_file(cli.globals.seed_file.as_deref())
}

/// The account key at `seed_file`, or at the default path.
fn load_seed_file(seed_file: Option<&Path>) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    let path = seed_file.map_or_else(default_seed_path, |path| Ok(path.to_owned()))?;
    keys::load_seed(&path).with_context(|| {
        format!(
            "load account key {}; generate one with `ghost key generate`",
            path.display()
        )
    })
}

fn load_recovery_seed(cli: &Cli) -> Result<zeroize::Zeroizing<[u8; 32]>> {
    let path = if let Some(path) = &cli.globals.recovery_seed_file {
        path.clone()
    } else {
        cli.globals
            .seed_file
            .clone()
            .map_or_else(default_seed_path, Ok)?
    };
    keys::load_seed(&path).with_context(|| {
        format!(
            "load hosted-backup account key {}; use --recovery-seed-file for a pre-migration backup",
            path.display()
        )
    })
}

fn default_seed_path() -> Result<PathBuf> {
    let path = seed_path_below(
        std::env::var_os("XDG_CONFIG_HOME"),
        std::env::var_os("HOME"),
    );
    #[cfg(windows)]
    let path = path
        .or_else(|_| seed_path_below(std::env::var_os("APPDATA"), std::env::var_os("USERPROFILE")));
    path
}

/// The default seed path for these `XDG_CONFIG_HOME` and `HOME` values. Like
/// the XDG base directory specification requires, an empty or relative
/// value is ignored rather than resolved against the working directory.
fn seed_path_below(
    config_home: Option<std::ffi::OsString>,
    home: Option<std::ffi::OsString>,
) -> Result<PathBuf> {
    let absolute = |value: Option<std::ffi::OsString>| {
        value.map(PathBuf::from).filter(|path| path.is_absolute())
    };
    if let Some(config_home) = absolute(config_home) {
        return Ok(config_home.join("ghost").join("account.seed"));
    }
    let home = absolute(home).context(
        "neither --seed-file, GHOST_SEED_FILE, an absolute XDG_CONFIG_HOME, nor an absolute HOME is set",
    )?;
    Ok(home.join(".config").join("ghost").join("account.seed"))
}

/// The largest `--ssh-key-file` read: far more than 20 keys with comments.
const MAXIMUM_SSH_KEY_FILE_BYTES: u64 = 1 << 20;
/// The largest user data an instance request may carry.
const MAXIMUM_USER_DATA_BYTES: u64 = 1 << 20;
/// The largest message or startup program file read.
const MAXIMUM_TEXT_FILE_BYTES: u64 = 1 << 20;

/// The SSH public keys given with `--ssh-key` and `--ssh-key-file`. Each is
/// checked here, before any request, as the backend checks it: a private
/// key never leaves this machine, and neither does any line that is not an
/// OpenSSH public key. Errors name the argument or the file and line, never
/// what the line holds; a key the backend would refuse is refused with its
/// code for an invalid request.
/// Which of the account's saved SSH keys an instance gets beside `keys`:
/// every one when the command line names no key (`None`), none when it
/// does (`--ssh-key`, `--ssh-key-file`): the keys given are the keys
/// installed.
fn named_keys_only(keys: &[String]) -> Option<Vec<Uuid>> {
    if keys.is_empty() {
        None
    } else {
        Some(Vec::new())
    }
}

fn load_ssh_keys(literals: &[String], files: &[PathBuf]) -> Result<Vec<String>> {
    let mut keys = Vec::new();
    for (index, literal) in literals.iter().enumerate() {
        let key = literal.trim();
        if key.is_empty() {
            continue;
        }
        let position = index + 1;
        if holds_private_key(key) {
            refuse!(
                "invalid_request",
                "--ssh-key {position} is a private key, which must never leave this machine; pass the public key line from its .pub file"
            );
        }
        if !valid_ssh_public_key(key) {
            let hint = refused_key_type_hint(key).unwrap_or_else(|| {
                if Path::new(key).exists() {
                    "; to read a key file, use --ssh-key-file".to_owned()
                } else {
                    String::new()
                }
            });
            refuse!(
                "invalid_request",
                "--ssh-key {position} is not an OpenSSH public key line such as `ssh-ed25519 AAAAC3Nza... user@host`{hint}"
            );
        }
        keys.push(key.to_owned());
    }
    for path in files {
        let contents = zeroize::Zeroizing::new(read_argument_file(
            "--ssh-key-file",
            path,
            MAXIMUM_SSH_KEY_FILE_BYTES,
        )?);
        keys.extend(public_keys_in_file(path, &contents)?);
    }
    if keys.len() > MAX_SSH_PUBLIC_KEYS {
        refuse!(
            "invalid_request",
            "at most {MAX_SSH_PUBLIC_KEYS} SSH public keys may be supplied"
        );
    }
    Ok(keys)
}

/// The keys of an `authorized_keys`-style file: one OpenSSH public key per
/// line, with blank lines and `#` comments skipped.
fn public_keys_in_file(path: &Path, contents: &str) -> Result<Vec<String>> {
    if holds_private_key(contents) {
        let public = {
            let mut name = path.as_os_str().to_owned();
            name.push(".pub");
            PathBuf::from(name)
        };
        let instead = if public.is_file() {
            format!("use {} instead", public.display())
        } else {
            "pass the public key file, usually the same name with .pub".to_owned()
        };
        refuse!(
            "invalid_request",
            "--ssh-key-file {} holds a private key, which must never leave this machine; {instead}",
            path.display()
        );
    }
    let mut keys = Vec::new();
    for (index, line) in contents.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !valid_ssh_public_key(line) {
            let hint = if line.starts_with("---- BEGIN SSH2 PUBLIC KEY") {
                "; convert this RFC 4716 key with `ssh-keygen -i -f FILE`".to_owned()
            } else if let Some(hint) = refused_key_type_hint(line) {
                hint
            } else if line
                .split_ascii_whitespace()
                .skip(1)
                .any(|field| SSH_PUBLIC_KEY_TYPES.contains(&field))
            {
                "; options before the key type are not supported".to_owned()
            } else {
                String::new()
            };
            refuse!(
                "invalid_request",
                "--ssh-key-file {} line {} is not an OpenSSH public key such as `ssh-ed25519 AAAAC3Nza... user@host`{hint}",
                path.display(),
                index + 1
            );
        }
        keys.push(line.to_owned());
    }
    if keys.is_empty() {
        bail!("--ssh-key-file {} holds no SSH public key", path.display());
    }
    Ok(keys)
}

/// The hint for a key of a type OpenSSH knows that a guest is not given:
/// DSA, which current OpenSSH refuses, or a certificate.
fn refused_key_type_hint(line: &str) -> Option<String> {
    let key_type = line.split_ascii_whitespace().next()?;
    (key_type == "ssh-dss" || key_type.ends_with("-cert-v01@openssh.com")).then(|| {
        format!(
            "; {key_type} keys are not accepted, only {}",
            SSH_PUBLIC_KEY_TYPES.join(", ")
        )
    })
}

/// Whether `text` holds private key material: PEM or OpenSSH armor such as
/// `-----BEGIN OPENSSH PRIVATE KEY-----`, or a `PuTTY` key file.
fn holds_private_key(text: &str) -> bool {
    text.lines().any(|line| {
        let line = line.trim();
        line.starts_with("-----BEGIN ") && line.contains("PRIVATE KEY")
    }) || text.contains("PuTTY-User-Key-File-")
}

/// An image install needs a way in: an SSH key, or user data from the
/// `--cloud-init-file`, as the backend requires for creation and reinstall.
/// Without a key, a `#cloud-config` that sets no key or password of its own
/// is worth a warning: the VM would boot, and be billed, with no login.
/// An image needs a way in: a key or user data given here, or the keys the
/// account saved (`ghost account ssh-keys`), which the backend installs
/// when the command line names none. Without any, the refusal comes
/// before anything is sent; with saved keys alone, a note says they go in.
async fn require_login_material(
    api: &ApiClient,
    ssh_public_keys: &[String],
    user_data: Option<(&Path, &str)>,
) -> Result<()> {
    let saved = if ssh_public_keys.is_empty() {
        api.read::<gigahost_client_api::api::ListAccountSshKeys>(
            &gigahost_client_api::api::ListAccountSshKeys,
            "",
        )
        .await?
        .len()
    } else {
        0
    };
    if let Some(note) = login_material(ssh_public_keys, user_data, saved)? {
        notice(&note);
    }
    Ok(())
}

/// The rule of [`require_login_material`] with the account's `saved` key
/// count read: the refusal when nothing gives a login, else the note to
/// print, if any.
fn login_material(
    ssh_public_keys: &[String],
    user_data: Option<(&Path, &str)>,
    saved: usize,
) -> Result<Option<String>> {
    let Some((path, user_data)) = user_data else {
        if !ssh_public_keys.is_empty() {
            return Ok(None);
        }
        if saved == 0 {
            refuse!(
                "invalid_request",
                "at least one --ssh-key, --ssh-key-file, or --cloud-init-file is required, or a key saved with `ghost account ssh-keys add`"
            );
        }
        return Ok(Some(saved_keys_note(saved)));
    };
    if ssh_public_keys.is_empty() && saved == 0 && !cloud_config_grants_login(user_data) {
        return Ok(Some(format!(
            "warning: the VM may have no way to log in:\n  --cloud-init-file {} sets no SSH key or password\n  no --ssh-key was given\n  the account has no saved key",
            path.display()
        )));
    }
    Ok(None)
}

/// A stock image is reached over SSH with the keys given, or the account's
/// saved ones: refused without either, as the backend refuses it, else a
/// note of the saved keys it installs.
async fn require_stock_image_keys(api: &ApiClient, ssh_public_keys: &[String]) -> Result<()> {
    if !ssh_public_keys.is_empty() {
        return Ok(());
    }
    let saved = api
        .read::<gigahost_client_api::api::ListAccountSshKeys>(
            &gigahost_client_api::api::ListAccountSshKeys,
            "",
        )
        .await?
        .len();
    notice(&stock_image_keys(saved)?);
    Ok(())
}

/// The rule of [`require_stock_image_keys`] when no key is given and the
/// account has `saved` keys: the refusal, or the note to print.
fn stock_image_keys(saved: usize) -> Result<String> {
    if saved == 0 {
        refuse!(
            "invalid_request",
            "a stock image is reached over SSH with the instance's keys: give at least one --ssh-key or --ssh-key-file, or save a key with `ghost account ssh-keys add`"
        );
    }
    Ok(saved_keys_note(saved))
}

/// What a creation without a key of its own says: the account's `saved`
/// keys are installed.
fn saved_keys_note(saved: usize) -> String {
    format!(
        "Installing the {saved} SSH key{} saved in the account.\nTo see them: ghost account ssh-keys list\nTo install other keys: --ssh-key or --ssh-key-file",
        if saved == 1 { "" } else { "s" }
    )
}

/// The options of `instance create` that are given, by their names.
fn given_options(options: &[(&'static str, bool)]) -> Vec<&'static str> {
    options
        .iter()
        .filter(|(_, given)| *given)
        .map(|(name, _)| *name)
        .collect()
}

/// `names` as a sentence lists them: `a`, `a and b`, `a, b and c`.
fn listed(names: &[&str]) -> String {
    match names {
        [] => String::new(),
        [one] => (*one).to_owned(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// Refuse what a container instance does not take, as the backend refuses
/// it: a renter's image (`--container`) runs as it is, with no SSH keys,
/// user data or startup command; a stock image (`--stock-image`) takes SSH
/// keys, but no user data or startup command, as its own init system
/// writes the keys.
fn check_container_login(args: &CreateInstanceArgs) -> Result<()> {
    let keys = [
        ("--ssh-key", !args.ssh_keys.is_empty()),
        ("--ssh-key-file", !args.ssh_key_files.is_empty()),
    ];
    let user_data = [
        ("--cloud-init-file", args.cloud_init_file.is_some()),
        ("--startup-command", args.startup_command.is_some()),
        (
            "--startup-command-file",
            args.startup_command_file.is_some(),
        ),
    ];
    if args.spec.container.is_some() {
        let named = given_options(&[&keys[..], &user_data[..]].concat());
        if !named.is_empty() {
            refuse!(
                "invalid_request",
                "--container runs the image as it is, which gets no SSH keys, cloud-init or startup command: leave out {}; a stock image (--stock-image, from `ghost catalog container-images`) is reached over SSH with the keys given",
                listed(&named)
            );
        }
    }
    if args.spec.stock_image.is_some() {
        let named = given_options(&user_data);
        if !named.is_empty() {
            refuse!(
                "invalid_request",
                "--stock-image runs the distribution's own init system, which installs the SSH keys and runs no cloud-init or startup command: leave out {}",
                listed(&named)
            );
        }
    }
    Ok(())
}

/// A container's entrypoint or command.
type Arguments = Vec<String>;

impl ContainerArgs {
    /// The options that replace a renter's image's process, by their names.
    fn process_options(&self) -> [(&'static str, bool); 5] {
        [
            ("--entrypoint", self.entrypoint.is_some()),
            ("--command", self.command.is_some()),
            ("--user", self.user.is_some()),
            ("--workdir", self.workdir.is_some()),
            ("--stop-timeout", self.stop_timeout.is_some()),
        ]
    }

    /// The options a stock image takes too, by their names.
    fn shared_options(&self) -> [(&'static str, bool); 4] {
        [
            ("--env", !self.env.is_empty()),
            ("--env-file", !self.env_files.is_empty()),
            ("--restart", self.restart.is_some()),
            ("--volume", !self.volumes.is_empty()),
        ]
    }

    /// Refuse a stock image's overrides of its init, before anything is
    /// sent.
    fn refuse_stock_process(&self) -> Result<()> {
        if self.stock_image.is_some() {
            let named = given_options(&self.process_options());
            if !named.is_empty() {
                refuse!(
                    "invalid_request",
                    "--stock-image runs the distribution's own init system, which takes no {}; of the container options it takes --env, --env-file, --restart and --volume",
                    listed(&named)
                );
            }
        }
        Ok(())
    }

    /// The entrypoint and the command given.
    fn arguments(&self) -> Result<(Option<Arguments>, Option<Arguments>)> {
        Ok((
            self.entrypoint
                .as_deref()
                .map(|text| argument_list(text, "--entrypoint", true))
                .transpose()?,
            self.command
                .as_deref()
                .map(|text| argument_list(text, "--command", false))
                .transpose()?,
        ))
    }

    /// Whether an environment is given, by --env or --env-file.
    fn names_env(&self) -> bool {
        !self.env.is_empty() || !self.env_files.is_empty()
    }
}

/// The container instance `instance create` asks for, `None` for a VM; or
/// the refusal, before anything is sent, of what does not fit: a
/// container's options without a container, a stock image's overrides of
/// its init, or what the API refuses of the container. No error names a
/// variable's value.
fn container_request(args: &CreateInstanceArgs) -> Result<Option<CreateContainerRequest>> {
    let spec = &args.spec;
    if spec.container.is_none() && spec.stock_image.is_none() {
        let named =
            given_options(&[&spec.process_options()[..], &spec.shared_options()[..]].concat());
        if !named.is_empty() {
            refuse!(
                "invalid_request",
                "{} {} a container instance's: give {} with --container or --stock-image",
                listed(&named),
                if named.len() == 1 { "is" } else { "are" },
                if named.len() == 1 { "it" } else { "them" },
            );
        }
        return Ok(None);
    }
    spec.refuse_stock_process()?;
    let (entrypoint, command) = spec.arguments()?;
    let request = CreateContainerRequest {
        image: spec.container.clone(),
        stock_image: spec.stock_image.clone(),
        entrypoint,
        command,
        env: container_env(&spec.env_files, &spec.env)?,
        user: spec.user.clone(),
        workdir: spec.workdir.clone(),
        stop_timeout_seconds: spec.stop_timeout,
        restart_policy: spec.restart.map(RestartPolicy::from),
        volumes: spec.volumes.clone(),
    };
    if let Err(message) = request.validate() {
        return Err(Refusal {
            code: "invalid_request",
            message,
        }
        .into());
    }
    Ok(Some(request))
}

/// What `instance redeploy` asks for; or the refusal, before anything is
/// sent, of what does not fit: a stock image's overrides of its init, SSH
/// keys for a renter's image, paths the API refuses. No error names a
/// variable's value.
fn redeploy_request(args: &RedeployArgs) -> Result<RedeployInstanceRequest> {
    let spec = &args.spec;
    spec.refuse_stock_process()?;
    if spec.container.is_some() && (!args.ssh_keys.is_empty() || !args.ssh_key_files.is_empty()) {
        refuse!(
            "invalid_request",
            "--container runs the image as it is, which gets no SSH keys: leave out --ssh-key and --ssh-key-file"
        );
    }
    let ssh_public_keys = load_ssh_keys(&args.ssh_keys, &args.ssh_key_files)?;
    let (entrypoint, command) = spec.arguments()?;
    let env = if spec.names_env() {
        Some(container_env(&spec.env_files, &spec.env)?)
    } else {
        None
    };
    let volumes = if args.no_volumes {
        Some(Vec::new())
    } else if spec.volumes.is_empty() {
        None
    } else {
        Some(spec.volumes.clone())
    };
    if let Some(volumes) = &volumes
        && let Err(message) = gigahost_client_api::website::validate_container_volumes(volumes)
    {
        return Err(Refusal {
            code: "invalid_request",
            message,
        }
        .into());
    }
    let request = RedeployInstanceRequest {
        image: spec.container.clone(),
        stock_image: spec.stock_image.clone(),
        env,
        entrypoint,
        command,
        user: spec.user.clone(),
        workdir: spec.workdir.clone(),
        stop_timeout_seconds: spec.stop_timeout,
        restart_policy: spec.restart.map(RestartPolicy::from),
        volumes,
        ssh_key_ids: named_keys_only(&ssh_public_keys),
        ssh_public_keys,
        reset: args.reset,
        clear: args.clear.clone(),
    };
    if let Err(message) = request.validate() {
        return Err(Refusal {
            code: "invalid_request",
            message,
        }
        .into());
    }
    Ok(request)
}

/// Root replacement requires explicit confirmation, without reading secrets.
fn update_confirmation() -> &'static str {
    "an update preserves settings and secrets, the instance's volumes and kept paths, and the VOLUME paths of the current and new image. Everything else on the root disk is replaced. The instance stops temporarily and returns to its previous power state. A failure before commit attempts rollback. If rollback fails or commit has begun, the instance may remain stopped. A committed new image remains installed; repeat with --yes"
}

/// What `instance redeploy` without `--yes` says happens: what is kept of
/// the root disk (the paths of the instance's own as they will be, read
/// from `instance` when the request keeps them), that the rest is
/// replaced, and the stop and the rollback.
fn redeploy_confirmation(
    request: &RedeployInstanceRequest,
    instance: Option<&InstanceView>,
) -> String {
    let own: Option<Vec<String>> = match (&request.volumes, request.reset) {
        (Some(volumes), _) => Some(volumes.clone()),
        (None, true) => Some(Vec::new()),
        (None, false) => instance
            .and_then(|instance| instance.container.as_ref())
            .map(|container| container.volumes.clone()),
    };
    let kept = match own {
        Some(paths) if paths.is_empty() => {
            "the VOLUME paths of the current and the new image; no path of the instance's own"
                .to_owned()
        }
        Some(paths) => {
            let escaped: Vec<String> = paths
                .iter()
                .map(|path| escape_control(path).into_owned())
                .collect();
            format!(
                "{} and the VOLUME paths of the current and the new image",
                listed(&escaped.iter().map(String::as_str).collect::<Vec<_>>())
            )
        }
        None => "the instance's volumes and the VOLUME paths of the current and the new image"
            .to_owned(),
    };
    format!(
        "a redeploy replaces everything on the instance's root disk but the paths it keeps: {kept}. The instance is stopped meanwhile, and rolled back to how it was if the redeploy fails; repeat with --yes"
    )
}

/// What a waited redeploy says it ran onto: the image, and the digest its
/// host pinned. None for an instance that is not a container's.
fn redeployed_note(instance: &InstanceView) -> Option<String> {
    let container = instance.container.as_ref()?;
    if container.image_unknown {
        return Some(format!(
            "Instance {} runs an unknown image: its host has not said which it kept.",
            instance.instance_id
        ));
    }
    let image = container.stock_image.as_deref().unwrap_or(&container.image);
    Some(match &container.image_digest {
        Some(digest) => format!(
            "Instance {} runs {} ({}).",
            instance.instance_id,
            escape_control(image),
            escape_control(digest)
        ),
        None => format!(
            "Instance {} runs {}.",
            instance.instance_id,
            escape_control(image)
        ),
    })
}

/// A container's entrypoint or command as `option` gives it: a JSON array
/// of strings or, where `word` allows it, a single word.
fn argument_list(text: &str, option: &str, word: bool) -> Result<Vec<String>> {
    if text.trim_start().starts_with('[') {
        if let Ok(arguments) = serde_json::from_str::<Vec<String>>(text) {
            return Ok(arguments);
        }
    } else if word && !text.is_empty() && !text.chars().any(char::is_whitespace) {
        return Ok(vec![text.to_owned()]);
    }
    if word {
        refuse!(
            "invalid_request",
            "{option} takes a JSON array of strings, such as [\"/app/server\", \"--port\", \"80\"], or a single word, such as /app/server"
        );
    }
    refuse!(
        "invalid_request",
        "{option} takes a JSON array of strings, such as [\"nginx\", \"-g\", \"daemon off;\"]"
    );
}

/// The container's environment: each `--env-file`'s `NAME=VALUE` lines in
/// order, then each `--env`, one of a name given again replacing the
/// earlier. A line or option that is not `NAME=VALUE`, or a name the API
/// refuses, is refused by its place only: a value is a secret, and so can
/// be what stands before the first `=` of a text that is not `NAME=VALUE`,
/// such as a pasted URL, so neither is ever shown.
fn container_env(files: &[PathBuf], literals: &[String]) -> Result<Vec<ContainerEnvVar>> {
    let mut env: Vec<ContainerEnvVar> = Vec::new();
    for file in files {
        let text = fs::read_to_string(file)
            .with_context(|| format!("cannot read --env-file {}", file.display()))?;
        for (index, line) in text.lines().enumerate() {
            let line = line.trim_start();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let place = || format!("line {} of --env-file {}", index + 1, file.display());
            let Some((name, value)) = line.split_once('=') else {
                refuse!("invalid_request", "{} is not NAME=VALUE", place());
            };
            check_env_name(name, &place)?;
            set_env(&mut env, name, value);
        }
    }
    for (index, literal) in literals.iter().enumerate() {
        let place = || format!("--env {}", index + 1);
        let Some((name, value)) = literal.split_once('=') else {
            refuse!("invalid_request", "{} is not NAME=VALUE", place());
        };
        check_env_name(name, &place)?;
        set_env(&mut env, name, value);
    }
    Ok(env)
}

/// Refuse a variable's name the API refuses by its `place`, never the
/// name: what stands before the first `=` of a mistyped line can be a
/// secret.
fn check_env_name(name: &str, place: &dyn Fn() -> String) -> Result<()> {
    let bytes = name.as_bytes();
    let valid = !bytes.is_empty()
        && bytes.len() <= gigahost_client_api::website::MAXIMUM_CONTAINER_ENV_NAME_BYTES
        && (bytes[0].is_ascii_alphabetic() || bytes[0] == b'_')
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_');
    if !valid {
        refuse!(
            "invalid_request",
            "{} does not start with a variable's name before its first =: a name is letters, digits and _, not starting with a digit, of at most {} bytes",
            place(),
            gigahost_client_api::website::MAXIMUM_CONTAINER_ENV_NAME_BYTES
        );
    }
    Ok(())
}

/// Give the variable `name` its `value`, replacing one of its name.
fn set_env(env: &mut Vec<ContainerEnvVar>, name: &str, value: &str) {
    match env.iter_mut().find(|variable| variable.name == name) {
        Some(variable) => value.clone_into(&mut variable.value),
        None => env.push(ContainerEnvVar {
            name: name.to_owned(),
            value: value.to_owned(),
        }),
    }
}

/// A container image reference for `--container`, in the platform's
/// grammar ([`gigahost_client_api::container_image::ImageReference`]); sent as
/// given, which the backend puts in its canonical form.
fn parse_container_image(value: &str) -> Result<String, String> {
    value
        .parse::<gigahost_client_api::container_image::ImageReference>()
        .map(|_| value.to_owned())
        .map_err(|error| error.to_string())
}

/// A stock image's slug for `--stock-image`.
fn parse_stock_image(value: &str) -> Result<String, String> {
    if gigahost_client_api::website::is_stock_image_slug(value) {
        Ok(value.to_owned())
    } else {
        Err(format!(
            "must be a stock image's slug, such as debian-13, from `ghost catalog container-images`: lowercase letters, digits, . and -, of at most {} bytes",
            gigahost_client_api::website::MAXIMUM_STOCK_IMAGE_SLUG_BYTES
        ))
    }
}

/// Refuse a rental of `offering` as `kind` it is not rented as, as the
/// backend refuses it. An offering of an older backend, which names no
/// kinds, is a VM's.
fn check_kind(offering: &OfferingView, kind: InstanceKind) -> Result<()> {
    let choice = match kind {
        InstanceKind::Vm => KindChoice::Vm,
        InstanceKind::Container => KindChoice::Container,
        InstanceKind::Unknown => return Ok(()),
    };
    if choice.admits(&offering.kinds) {
        return Ok(());
    }
    let id = escape_control(&offering.offering_id);
    if kind == InstanceKind::Container {
        refuse!(
            "offering_unavailable",
            "offering {id} is not rented as a container instance: `ghost catalog offerings --kind container` lists the offerings that are"
        );
    }
    refuse!(
        "offering_unavailable",
        "offering {id} is rented as a container instance only: give --container or --stock-image instead of --image, or find a VM's offering with `ghost catalog offerings --kind vm`"
    );
}

/// Whether user data may give a login: anything but a `#cloud-config`
/// cannot be told, and a `#cloud-config` does when it sets SSH keys, a
/// password, or imports keys, at the top or for one of its users.
fn cloud_config_grants_login(user_data: &str) -> bool {
    const LOGIN_KEYS: [&str; 7] = [
        "ssh_authorized_keys",
        "ssh_import_id",
        "password",
        "chpasswd",
        "passwd",
        "hashed_passwd",
        "plain_text_passwd",
    ];
    if user_data_type(user_data) != Some(UserDataType::CloudConfig) {
        return true;
    }
    let Ok(serde_yaml_ng::Value::Mapping(document)) =
        serde_yaml_ng::from_str::<serde_yaml_ng::Value>(user_data)
    else {
        return true;
    };
    let grants =
        |mapping: &serde_yaml_ng::Mapping| LOGIN_KEYS.iter().any(|key| mapping.contains_key(*key));
    grants(&document)
        || document
            .get("users")
            .and_then(serde_yaml_ng::Value::as_sequence)
            .is_some_and(|users| {
                users
                    .iter()
                    .filter_map(serde_yaml_ng::Value::as_mapping)
                    .any(grants)
            })
}

/// The kinds of user data cloud-init tells apart by how they start.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UserDataType {
    CloudConfig,
    CloudConfigArchive,
    /// `#cloud-config-jsonp`: a JSON Patch of the merged cloud-config.
    CloudConfigJsonPatch,
    Script,
    Mime,
    /// `#include`, `#cloud-boothook`, a part handler, or a Jinja template:
    /// cloud-init runs them, and their content is not checked here.
    Other,
}

/// The starts cloud-init types user data by, longest first, so that
/// `#cloud-config-archive` is not taken for `#cloud-config`.
const USER_DATA_STARTS: [(&str, UserDataType); 8] = [
    ("#cloud-config-archive", UserDataType::CloudConfigArchive),
    ("#cloud-config-jsonp", UserDataType::CloudConfigJsonPatch),
    ("## template: jinja", UserDataType::Other),
    ("#cloud-boothook", UserDataType::Other),
    ("#cloud-config", UserDataType::CloudConfig),
    ("#part-handler", UserDataType::Other),
    ("#include", UserDataType::Other),
    ("#!", UserDataType::Script),
];

/// The type cloud-init gives `user_data`, or `None` when it would ignore it.
fn user_data_type(user_data: &str) -> Option<UserDataType> {
    let head = &user_data.as_bytes()[..user_data.len().min(4096)];
    // cloud-init recognizes MIME through its MIME-Version header;
    // Content-Type alone is not enough.
    if head
        .to_ascii_lowercase()
        .windows(b"mime-version:".len())
        .any(|window| window == b"mime-version:")
    {
        return Some(UserDataType::Mime);
    }
    // cloud-init's `type_from_starts_with` ignores case and leading
    // whitespace.
    let text = user_data.trim_start();
    USER_DATA_STARTS.iter().find_map(|&(start, kind)| {
        text.get(..start.len())
            .is_some_and(|head| head.eq_ignore_ascii_case(start))
            .then_some(kind)
    })
}

/// Read the `--cloud-init-file` and check that cloud-init would run it, so
/// a mistake is reported here instead of costing a VM that boots without
/// it: a `#cloud-config` must be a YAML mapping, a `#cloud-config-archive` a
/// YAML list, a `#cloud-config-jsonp` a JSON Patch, and anything else must
/// start with a type cloud-init knows.
fn load_user_data(path: &Path) -> Result<String> {
    let user_data = read_argument_file("--cloud-init-file", path, MAXIMUM_USER_DATA_BYTES)?;
    if let Err(problem) = check_user_data(&user_data) {
        bail!("--cloud-init-file {} {problem}", path.display());
    }
    Ok(user_data)
}

/// What is wrong with `user_data`, said of the file.
fn check_user_data(user_data: &str) -> Result<(), String> {
    use serde_yaml_ng::Value as Yaml;

    if user_data.trim().is_empty() {
        return Err("is empty".to_owned());
    }
    let parse = |kind: &str| {
        serde_yaml_ng::from_str::<Yaml>(user_data)
            .map_err(|error| format!("is not valid {kind} YAML: {error}"))
    };
    match user_data_type(user_data) {
        Some(UserDataType::CloudConfig) => match parse("#cloud-config")? {
            Yaml::Mapping(_) | Yaml::Null => Ok(()),
            _ => Err(
                "is not a #cloud-config mapping of modules, such as `packages: [nginx]`".to_owned(),
            ),
        },
        Some(UserDataType::CloudConfigArchive) => match parse("#cloud-config-archive")? {
            Yaml::Sequence(_) => Ok(()),
            _ => Err("is not a #cloud-config-archive list".to_owned()),
        },
        Some(UserDataType::CloudConfigJsonPatch) => check_json_patch(user_data),
        Some(UserDataType::Script | UserDataType::Mime | UserDataType::Other) => Ok(()),
        None => {
            let hint = if user_data
                .trim_start()
                .get(.."content-type:".len())
                .is_some_and(|start| start.eq_ignore_ascii_case("content-type:"))
            {
                "; a MIME document also needs a MIME-Version: 1.0 header"
            } else if matches!(
                serde_yaml_ng::from_str::<Yaml>(user_data),
                Ok(Yaml::Mapping(_))
            ) {
                "; if it is cloud-config, make #cloud-config its first line"
            } else {
                ""
            };
            Err(format!(
                "is not cloud-init user data: its first line must be #cloud-config (YAML), #! (a script), or a MIME multipart header, or cloud-init ignores it{hint}"
            ))
        }
    }
}

/// What is wrong with a `#cloud-config-jsonp` document. cloud-init strips
/// that start, exactly as written, and applies the rest as a JSON Patch: an
/// array of operations, each with a known `op` and a `path`.
fn check_json_patch(user_data: &str) -> Result<(), String> {
    const OPERATIONS: [&str; 6] = ["add", "remove", "replace", "move", "copy", "test"];
    let text = user_data.trim_start();
    let patch = text.strip_prefix("#cloud-config-jsonp").unwrap_or(text);
    let patch = serde_json::from_str::<Value>(patch)
        .map_err(|error| format!("is not valid #cloud-config-jsonp JSON: {error}"))?;
    let valid = patch.as_array().is_some_and(|operations| {
        operations.iter().all(|operation| {
            operation
                .get("op")
                .and_then(Value::as_str)
                .is_some_and(|op| OPERATIONS.contains(&op))
                && operation.get("path").is_some_and(Value::is_string)
        })
    });
    if valid {
        Ok(())
    } else {
        Err("is not a #cloud-config-jsonp JSON Patch, an array of operations such as `{\"op\": \"add\", \"path\": \"/packages/-\", \"value\": \"nginx\"}`".to_owned())
    }
}

/// The ID of the image `reference` names: an image ID as it is, or the ID of
/// the catalog image with that slug.
async fn resolve_image(api: &ApiClient, reference: &str) -> Result<Uuid> {
    if let Ok(image_id) = Uuid::parse_str(reference) {
        return Ok(image_id);
    }
    let images: Vec<ImageView> = api
        .read(&ListImages, "")
        .await
        .context("list the catalog images to find --image")?;
    if let Some(image) = images
        .iter()
        .find(|image| image.slug.eq_ignore_ascii_case(reference))
    {
        return Ok(image.image_id);
    }
    let mut slugs = images
        .iter()
        .map(|image| image.slug.as_str())
        .collect::<Vec<_>>();
    slugs.sort_unstable();
    bail!(
        "--image {reference} is not a catalog image; the catalog has {}",
        slugs.join(", ")
    )
}

/// Accept an image ID or something that can be a catalog slug, such as
/// `debian-13` or `opensuse-leap-16.0`.
fn parse_image_reference(value: &str) -> Result<String, String> {
    if Uuid::parse_str(value).is_ok()
        || ((1..=64).contains(&value.len())
            && value.as_bytes()[0].is_ascii_alphanumeric()
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_')))
    {
        Ok(value.to_owned())
    } else {
        Err("must be an image slug such as debian-13, or an image ID".to_owned())
    }
}

/// Read the UTF-8 text file given as `argument`, such as `--cloud-init-file`,
/// refusing one larger than `maximum` bytes. The error names the argument
/// and the file on one line.
fn read_argument_file(argument: &str, path: &Path, maximum: u64) -> Result<String> {
    use zeroize::Zeroize as _;

    let fail = |problem: &dyn std::fmt::Display| {
        anyhow::anyhow!("cannot read {argument} {}: {problem}", path.display())
    };
    let file = fs::File::open(path).map_err(|error| fail(&error))?;
    // A private key given by mistake is read too, before it is refused.
    // Room for any key file up front keeps a growing buffer from leaving
    // copies of it behind, and what is not returned is zeroized.
    let mut bytes = zeroize::Zeroizing::new(Vec::with_capacity(64 << 10));
    file.take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| fail(&error))?;
    if u64::try_from(bytes.len()).map_or(true, |length| length > maximum) {
        return Err(fail(&format_args!("it is larger than {maximum} bytes")));
    }
    String::from_utf8(std::mem::take(&mut *bytes)).map_err(|error| {
        error.into_bytes().zeroize();
        fail(&"it is not UTF-8 text")
    })
}

/// A host pricing file: what to earn, with the compute earnings in exactly
/// one of their two forms (the backend refuses neither and both too).
fn host_pricing_input(text: &str) -> Result<gigahost_client_api::website::HostPricingInput> {
    let input: gigahost_client_api::website::HostPricingInput =
        serde_json::from_str(text).context("parse host pricing JSON")?;
    input
        .compute()
        .map_err(|reason| anyhow::anyhow!("host pricing JSON: {reason}"))?;
    Ok(input)
}

fn read_text_file(path: &Path) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
}

fn load_required_text(literal: Option<&str>, file: Option<&Path>, label: &str) -> Result<String> {
    load_optional_text(literal, file, &format!("--{label}-file"))?
        .with_context(|| format!("--{label} or --{label}-file is required"))
}

/// Text given inline or read from a file, whichever of the two exclusive
/// arguments is present; `file_argument` names the file's.
fn load_optional_text(
    literal: Option<&str>,
    file: Option<&Path>,
    file_argument: &str,
) -> Result<Option<String>> {
    match (literal, file) {
        (Some(value), None) => Ok(Some(value.to_owned())),
        (None, Some(path)) => {
            read_argument_file(file_argument, path, MAXIMUM_TEXT_FILE_BYTES).map(Some)
        }
        (None, None) => Ok(None),
        (Some(_), Some(_)) => unreachable!("clap enforces mutually exclusive text inputs"),
    }
}

/// A port forward as `PUBLIC=GUEST`.
fn parse_port_forward(value: &str) -> Result<PortForwardChange, String> {
    let port = |text: &str| text.trim().parse::<u16>().ok().filter(|port| *port > 0);
    value
        .split_once('=')
        .and_then(|(public, guest)| {
            Some(PortForwardChange {
                public_port: port(public)?,
                guest_port: port(guest)?,
            })
        })
        .ok_or_else(|| {
            "must be PUBLIC=GUEST, such as 1020=22: the instance's public port and the port of the instance it goes to, each 1 to 65535".to_owned()
        })
}

/// What `ghost instance ports` shows of a shared IP instance: its address,
/// the SSH command where a port goes to 22, each public port with the
/// instance's port it goes to, and the ports its outgoing connections
/// leave from.
fn port_forwards_output(instance: &InstanceView) -> Value {
    let address = instance.public_ipv4.as_deref();
    let ssh = instance
        .port_forwards
        .iter()
        .find(|forward| forward.guest_port == 22)
        .zip(address)
        .map(|(forward, address)| {
            format!(
                "ssh -p {} root@{}",
                forward.public_port,
                escape_control(address)
            )
        });
    json!({
        "public_ipv4": address,
        "ssh": ssh,
        "port_forwards": instance.port_forwards,
        "outgoing_ports": instance.outgoing_ports.map(|range| format!(
            "{}-{}",
            range.first_port,
            range.last_port()
        )),
    })
}

/// Accept the hostnames the backend accepts, so a mistake is refused
/// before anything is sent or charged.
/// A tag as `valid_tag` takes it, refused in the API's words.
fn parse_tag(value: &str) -> Result<String, String> {
    if valid_tag(value) {
        Ok(value.to_owned())
    } else {
        Err(format!("must be a tag: {TAG_RULE}"))
    }
}

/// An amount in dollars, such as `5`, `2.50` or `$1`, to micro-USD: at most
/// nine digits of dollars and six decimals, read from the text alone
/// without floating point. The backend checks the bounds.
fn parse_usd(value: &str) -> Result<u64, String> {
    let invalid = || format!("{value} is not an amount in dollars; write one such as 5 or 2.50");
    let text = value.trim();
    let text = text.strip_prefix('$').unwrap_or(text);
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    if whole.is_empty()
        || whole.len() > 9
        || fraction.len() > 6
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || (text.contains('.') && fraction.is_empty())
    {
        return Err(invalid());
    }
    let whole: u64 = whole.parse().map_err(|_| invalid())?;
    let fraction: u64 = format!("{fraction:0<6}").parse().map_err(|_| invalid())?;
    Ok(whole * 1_000_000 + fraction)
}

fn parse_hostname(value: &str) -> Result<String, String> {
    if valid_hostname(value) {
        Ok(value.to_owned())
    } else {
        Err("must be a lowercase RFC 1123 hostname of at most 253 bytes: dot-separated labels of letters, digits and hyphens, each at most 63 long and starting and ending with a letter or digit".to_owned())
    }
}

/// An instance as a command names it: by its ID, or by its name, which
/// [`resolve_instance`] looks up among the account's current instances.
#[derive(Clone, Debug, PartialEq, Eq)]
enum InstanceReference {
    Id(Uuid),
    /// A name by the rules of a hostname, lower-cased.
    Name(String),
}

/// Accept an instance ID, or something that can be an instance's name. A
/// value that reads as a UUID is an ID, so an instance whose name looks
/// like one is named by its ID. `Uuid::parse_str` also reads the 32-digit
/// hex form, so a name of 32 hex digits is taken as an ID too and needs the
/// ID's own spelling to be told apart.
fn parse_instance_reference(value: &str) -> Result<InstanceReference, String> {
    if let Ok(id) = Uuid::parse_str(value) {
        return Ok(InstanceReference::Id(id));
    }
    let name = value.to_ascii_lowercase();
    if valid_hostname(&name) {
        Ok(InstanceReference::Name(name))
    } else {
        Err("must be an instance ID or an instance's name, from `ghost instance list`".to_owned())
    }
}

/// The most instances a page of `ListInstances` lists: a shorter page is
/// the last.
const LISTED_INSTANCES: usize = 500;

/// The account's current instances, newest first: every page of
/// `ListInstances`, each read after the last instance of the one before,
/// so that a name is looked up among all of them and not only the newest.
///
/// # Errors
///
/// The list's read failures, and a page that lists an instance again, as a
/// backend that did not page would.
async fn current_instances(api: &ApiClient) -> Result<Vec<InstanceView>> {
    let mut instances: Vec<InstanceView> = api.read(&ListInstances, "").await?;
    let mut listed: HashSet<Uuid> = instances
        .iter()
        .map(|instance| instance.instance_id)
        .collect();
    let mut page_length = instances.len();
    while page_length >= LISTED_INSTANCES {
        let Some(before) = instances.last().map(|instance| instance.instance_id) else {
            break;
        };
        let page: Vec<InstanceView> = api
            .read(&ListInstances, &format!("before={before}"))
            .await?;
        page_length = page.len();
        for instance in page {
            if !listed.insert(instance.instance_id) {
                bail!(
                    "the instance list named instance {} twice; name the instance by its ID",
                    instance.instance_id
                );
            }
            instances.push(instance);
        }
    }
    Ok(instances)
}

/// What a command does with the instance it names: a change says which
/// instance a name stands for before it acts on it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum InstanceUse {
    Read,
    Change,
}

/// The ID of the instance `reference` names: an ID as it is, without a
/// request; a name by the account's current instances, whose name (or,
/// from an older backend, hostname) it must be of exactly one. For a
/// [`InstanceUse::Change`] a name is followed by a notice of the ID it
/// stands for.
///
/// # Errors
///
/// `instance_not_found` for a name no current instance has,
/// `instance_name_ambiguous` for one several have, and the list's read
/// failures.
async fn resolve_instance(
    api: &ApiClient,
    reference: &InstanceReference,
    used: InstanceUse,
) -> Result<Uuid> {
    let name = match reference {
        InstanceReference::Id(id) => return Ok(*id),
        InstanceReference::Name(name) => name,
    };
    let mut matches: Vec<InstanceView> = current_instances(api)
        .await?
        .into_iter()
        .filter(|instance| {
            instance.state != InstanceState::Deleted
                && instance.display_name().eq_ignore_ascii_case(name)
        })
        .collect();
    matches.sort_by_key(|instance| std::cmp::Reverse(instance.created_at));
    match matches.as_slice() {
        [instance] => {
            if used == InstanceUse::Change {
                notice(&named_instance_notice(name, instance.instance_id));
            }
            Ok(instance.instance_id)
        }
        [] => refuse!(
            "instance_not_found",
            "no instance is named {name}; `ghost instance list` lists the names"
        ),
        several => refuse!(
            "instance_name_ambiguous",
            "{} instances are named {name}:\n{}\nTo choose one, name it by its ID.",
            several.len(),
            several
                .iter()
                .map(|instance| format!(
                    "  {}  {}",
                    instance.instance_id,
                    instance_state_words(instance.state)
                ))
                .collect::<Vec<_>>()
                .join("\n")
        ),
    }
}

/// The line a change of an instance named by its name writes first, so
/// that `ghost instance delete web-1 --yes` says which VM it deletes.
fn named_instance_notice(name: &str, instance_id: Uuid) -> String {
    format!("instance {name} is {instance_id}")
}

/// `key` for a change of the instance `reference` names, which resolved to
/// `instance_id`. Named by its name, the retry names it by its ID: a key
/// is scoped to the instance it was sent for, and the name, looked up
/// again, may by then stand for another instance, or for none once the
/// first is deleted, where the ID gets the first answer again.
fn retried_by_id(
    mut key: MutationKey,
    reference: &InstanceReference,
    instance_id: Uuid,
) -> MutationKey {
    if let InstanceReference::Name(name) = reference {
        key.retry = format!(
            "the ID {instance_id} in place of the name {name}, and {}",
            key.retry
        );
    }
    key
}

/// [`resolve_instance`] for an optional instance argument.
async fn resolve_optional_instance(
    api: &ApiClient,
    reference: Option<&InstanceReference>,
    used: InstanceUse,
) -> Result<Option<Uuid>> {
    match reference {
        Some(reference) => resolve_instance(api, reference, used).await.map(Some),
        None => Ok(None),
    }
}

/// Accept the keys the backend accepts (16 to 128 ASCII characters), minus
/// spaces and control characters, so a retry hint can be pasted as is.
fn parse_idempotency_key(value: &str) -> Result<String, String> {
    if (16..=128).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_graphic()) {
        Ok(value.to_owned())
    } else {
        Err("must contain 16 to 128 printable ASCII characters without spaces".to_owned())
    }
}

fn fresh_idempotency_key() -> String {
    Uuid::now_v7().to_string()
}

fn restore_authorization_key(restore_idempotency_key: &str) -> String {
    format!(
        "restore-authorize-{}",
        URL_SAFE_NO_PAD.encode(Sha256::digest(restore_idempotency_key.as_bytes()))
    )
}

fn to_value(value: impl Serialize) -> Result<Value> {
    serde_json::to_value(value).context("serialize command output")
}

fn parse_country_code(value: &str) -> Result<String, String> {
    let normalized = value.to_ascii_uppercase();
    if normalized.len() == 2 && normalized.bytes().all(|byte| byte.is_ascii_uppercase()) {
        Ok(normalized)
    } else {
        Err("country must be a two-letter ISO country code".to_owned())
    }
}

/// A provider as a command names it: by its ID, or by its alias, its
/// owner's account alias.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ProviderReference {
    Id(Uuid),
    Alias(String),
}

impl std::fmt::Display for ProviderReference {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Id(id) => id.fmt(formatter),
            Self::Alias(alias) => formatter.write_str(alias),
        }
    }
}

/// A provider ID, or an alias as accounts have them: `gh-` and eight of
/// a-z and 2-7, in any case.
fn parse_provider(value: &str) -> Result<ProviderReference, String> {
    if let Ok(id) = Uuid::parse_str(value) {
        return Ok(ProviderReference::Id(id));
    }
    let alias = value.to_ascii_lowercase();
    let valid = alias.strip_prefix("gh-").is_some_and(|rest| {
        rest.len() == 8
            && rest
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
    });
    if valid {
        Ok(ProviderReference::Alias(alias))
    } else {
        Err(format!(
            "{value} is neither a provider ID nor a provider alias such as gh-abcdefgh"
        ))
    }
}

/// A size in bytes from a number of binary units, such as `4GiB`,
/// `512MiB` or `1.5TiB`, in any case; `M`, `G` and `T` stand for MiB, GiB
/// and TiB, and a bare number is GiB.
fn parse_size(value: &str) -> Result<u64, String> {
    const UNITS: [(&str, u32); 5] = [("b", 0), ("k", 10), ("m", 20), ("g", 30), ("t", 40)];
    let invalid = || {
        format!("{value} is not a size; write one such as 4GiB or 4G, 512MiB or 512M, 1TiB or 1T")
    };
    let text = value.trim().to_ascii_lowercase();
    let split = text
        .find(|character: char| !(character.is_ascii_digit() || character == '.'))
        .unwrap_or(text.len());
    let (number, unit) = text.split_at(split);
    let unit = unit.trim_start();
    let unit = unit
        .strip_suffix("ib")
        .or_else(|| unit.strip_suffix('i'))
        .filter(|prefix| !prefix.is_empty() && *prefix != "b")
        .unwrap_or(unit);
    let shift = if unit.is_empty() {
        30
    } else {
        UNITS
            .iter()
            .find(|(name, _)| *name == unit)
            .map(|(_, shift)| *shift)
            .ok_or_else(invalid)?
    };
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    if whole.is_empty() && fraction.is_empty() {
        return Err(invalid());
    }
    let parse = |digits: &str| -> Result<u128, String> {
        if digits.is_empty() {
            Ok(0)
        } else {
            digits.parse::<u128>().map_err(|_| invalid())
        }
    };
    // Exactly, for a fraction of a unit: 1.5GiB is 3 GiB halves.
    let scale = 10_u128
        .checked_pow(u32::try_from(fraction.len()).map_err(|_| invalid())?)
        .ok_or_else(invalid)?;
    let bytes = (parse(whole)? * scale + parse(fraction)?)
        .checked_mul(1_u128 << shift)
        .ok_or_else(invalid)?
        / scale;
    u64::try_from(bytes).map_err(|_| invalid())
}

fn parse_mac_address(value: &str) -> Result<String, String> {
    let octets = value
        .split(':')
        .map(|octet| {
            if octet.len() != 2 {
                return Err(());
            }
            u8::from_str_radix(octet, 16).map_err(|_| ())
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|()| "MAC must contain six colon-separated hexadecimal octets".to_owned())?;
    if octets.len() != 6 || octets.iter().all(|octet| *octet == 0) || octets[0] & 1 != 0 {
        return Err("MAC must be a non-zero unicast address".to_owned());
    }
    Ok(octets
        .iter()
        .map(|octet| format!("{octet:02x}"))
        .collect::<Vec<_>>()
        .join(":"))
}

fn parse_continent_code(value: &str) -> Result<String, String> {
    let normalized = value.to_ascii_uppercase();
    if matches!(
        normalized.as_str(),
        "AF" | "AN" | "AS" | "EU" | "NA" | "OC" | "SA" | "XX"
    ) {
        Ok(normalized)
    } else {
        Err("continent must be AF, AN, AS, EU, NA, OC, SA, or XX".to_owned())
    }
}

impl LocationFilters {
    /// The filters as the location list's query string.
    fn query(&self) -> String {
        let mut url = reqwest::Url::parse("https://api.gigahost.cloud/").expect("static URL");
        let mut query = url.query_pairs_mut();
        for (name, value) in [("country", &self.country), ("continent", &self.continent)] {
            if let Some(value) = value {
                query.append_pair(name, value);
            }
        }
        drop(query);
        url.query().unwrap_or_default().to_owned()
    }
}

impl OfferingFilters {
    /// The address the list prices: dedicated unless `--ip shared`.
    fn ip(&self) -> IpChoice {
        self.ip.unwrap_or_default()
    }

    /// The smallest root disk an offering may have: what --min-disk asks
    /// for, and what an instance from the --for-backup `backup` needs.
    fn minimum_root_disk_bytes(&self, backup: Option<&BackupView>) -> Option<u64> {
        self.min_disk
            .into_iter()
            .chain(backup.and_then(|backup| backup.disk_bytes))
            .max()
    }

    /// Where the next page starts, when `offerings` fill this one: after
    /// its last offering, by listed price and ID, the catalog's order.
    fn next_page(&self, offerings: &[OfferingView]) -> Option<String> {
        let limit = self.limit.map_or(500, usize::from);
        let last = offerings.last().filter(|_| offerings.len() >= limit)?;
        Some(format!(
            "{}.{}",
            last.price_for(self.ip())
                .unwrap_or_else(|| last.listed_price_microusd_per_month()),
            last.offering_id
        ))
    }

    /// The filters as the catalog's query string. `backup` is the one
    /// --for-backup names: an instance created from it needs a root as large
    /// as its disk and, for a local backup, runs on the backup's host. The
    /// backend still checks the backup's architecture, which offerings do not
    /// show.
    fn query(&self, backup: Option<&BackupView>) -> Result<String> {
        let backup_host = backup.and_then(|backup| backup.host_id);
        let host = match (self.placement.host, backup_host) {
            (Some(host), Some(backup_host)) if host != backup_host => bail!(
                "backup {} is stored on host {backup_host}, where an instance created from it runs; leave out --host or pass that host",
                backup.map(|backup| backup.backup_id).unwrap_or_default()
            ),
            (host, backup_host) => host.or(backup_host),
        };
        // An instance from a backup is of the backup's kind: only the
        // offerings that take that kind.
        let backup_kind = match backup.map(|backup| backup.kind) {
            Some(InstanceKind::Vm) => Some(KindChoice::Vm),
            Some(InstanceKind::Container) => Some(KindChoice::Container),
            Some(InstanceKind::Unknown) | None => None,
        };
        let kind = match (self.kind, backup_kind) {
            (Some(requested), Some(kind))
                if !matches!(requested, KindChoice::Any) && requested != kind =>
            {
                bail!(
                    "backup {} is {}, and an instance created from it is {} too; leave out --kind or pass --kind {}",
                    backup.map(|backup| backup.backup_id).unwrap_or_default(),
                    if kind == KindChoice::Container {
                        "a container instance's backup"
                    } else {
                        "a VM's backup"
                    },
                    if kind == KindChoice::Container {
                        "a container instance"
                    } else {
                        "a VM"
                    },
                    wire_name(kind)
                );
            }
            (_, Some(kind)) => kind,
            (requested, None) => requested.unwrap_or(KindChoice::Any),
        };
        let mut url = reqwest::Url::parse("https://api.gigahost.cloud/").expect("static URL");
        let mut query = url.query_pairs_mut();
        for (name, value) in [
            ("mode", self.mode.map(wire_name)),
            ("ip", self.ip.map(wire_name)),
            // Every kind unless one is asked for, or the backup's: the API
            // lists only a VM's offerings where a request names none, as
            // releases of before ask.
            ("kind", Some(wire_name(kind))),
            ("location", self.location.clone()),
            ("country", self.country.clone()),
            ("continent", self.continent.clone()),
            ("provider", self.provider.as_ref().map(ToString::to_string)),
            ("minimum_vcpus", self.min_vcpu.map(|n| n.to_string())),
            ("host_id", host.map(|host| host.to_string())),
            (
                "minimum_memory_bytes",
                self.min_ram.map(|bytes| bytes.to_string()),
            ),
            (
                "minimum_root_disk_bytes",
                self.minimum_root_disk_bytes(backup)
                    .map(|bytes| bytes.to_string()),
            ),
            ("minimum_available", self.available.map(|n| n.to_string())),
            ("limit", self.limit.map(|limit| limit.to_string())),
            ("after", self.after.clone()),
        ] {
            if let Some(value) = value {
                query.append_pair(name, &value);
            }
        }
        drop(query);
        Ok(url.query().unwrap_or_default().to_owned())
    }
}

impl From<BackupDestinationArg> for BackupDestinationKind {
    fn from(value: BackupDestinationArg) -> Self {
        match value {
            BackupDestinationArg::Local => Self::Local,
            BackupDestinationArg::Hosted => Self::GigahostS3,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ghost backup schedule set` reads the spec's example and a rule's
    /// own time and day, and refuses what the API would.
    #[test]
    fn a_backup_schedule_is_set_from_its_rules_and_flags() {
        let request = |arguments: &[&str]| -> Result<SetBackupScheduleRequest> {
            let mut all = vec!["ghost", "backup", "schedule", "set", "web-1"];
            all.extend_from_slice(arguments);
            let cli =
                Cli::try_parse_from(all).map_err(|error| anyhow::anyhow!(error.to_string()))?;
            let Command::Backup {
                command:
                    BackupCommand::Schedule {
                        command: ScheduleCommand::Set(args),
                    },
            } = cli.command
            else {
                panic!("a schedule set");
            };
            schedule_request(&args)
        };
        let set = request(&[
            "--rule",
            "daily:local:3",
            "--rule",
            "weekly:hosted:2",
            "--at",
            "03:00",
            "--weekday",
            "sun",
        ])
        .unwrap();
        assert_eq!(
            serde_json::to_value(&set).unwrap(),
            json!({"rules": [
                {"destination": "local", "frequency": "daily", "minute_of_day": 180, "keep": 3},
                {"destination": "gigahost_s3", "frequency": "weekly", "minute_of_day": 180, "weekday": 0, "keep": 2},
            ]})
        );
        let own = request(&[
            "--rule",
            "daily:local:3@01:30",
            "--rule",
            "monthly:hosted:6@04:00/15",
        ])
        .unwrap();
        assert_eq!(own.rules[0].minute_of_day, 90);
        assert_eq!(
            (own.rules[1].minute_of_day, own.rules[1].day_of_month),
            (240, Some(15))
        );
        for refused in [
            vec!["--rule", "daily:local:3"],
            vec!["--rule", "weekly:local:3", "--at", "03:00"],
            vec!["--rule", "monthly:local:3/29", "--at", "03:00"],
            vec!["--rule", "daily:local:3/sun", "--at", "03:00"],
            vec!["--rule", "hourly:local:3", "--at", "03:00"],
            vec!["--rule", "daily:local:0", "--at", "03:00"],
            vec!["--rule", "daily:local:3", "--at", "3:5"],
        ] {
            assert!(request(&refused).is_err(), "{refused:?}");
        }
        assert_eq!(parse_weekday("Saturday"), Ok(6));
        assert_eq!(parse_clock("23:59"), Ok(1439));
        assert!(parse_clock("24:00").is_err());
    }

    /// A live rule as `GET .../backup-schedule` answers it.
    fn live_rule(
        id: Uuid,
        destination: &str,
        frequency: &str,
        minute_of_day: u16,
        keep: u32,
        completed: u32,
    ) -> Value {
        json!({
            "rule_id": id, "destination": destination, "frequency": frequency,
            "minute_of_day": minute_of_day, "keep": keep,
            "weekday": (frequency == "weekly").then_some(0),
            "day_of_month": (frequency == "monthly").then_some(1),
            "created_at": "2026-10-01T00:00:00Z", "next_run_at": "2026-10-04T02:17:00Z",
            "backup_count": completed, "completed_count": completed
        })
    }

    fn schedule_of(rules: &[Value]) -> BackupScheduleView {
        serde_json::from_value(json!({
            "instance_id": Uuid::nil(), "rules": rules, "maximum_backups": 100
        }))
        .unwrap()
    }

    /// The rules of `ghost backup schedule set web-1` with `arguments`,
    /// before their IDs are carried over.
    fn schedule_set(arguments: &[&str]) -> (ScheduleSetArgs, SetBackupScheduleRequest) {
        let mut all = vec!["ghost", "backup", "schedule", "set", "web-1"];
        all.extend_from_slice(arguments);
        let cli = Cli::try_parse_from(all).unwrap();
        let Command::Backup {
            command:
                BackupCommand::Schedule {
                    command: ScheduleCommand::Set(args),
                },
        } = cli.command
        else {
            panic!("a schedule set");
        };
        let request = schedule_request(&args).unwrap();
        (args, request)
    }

    fn carried(schedule: &BackupScheduleView, arguments: &[&str]) -> Vec<Option<Uuid>> {
        let (_, mut request) = schedule_set(arguments);
        carry_rule_ids(&mut request, schedule);
        request.rules.iter().map(|rule| rule.id).collect()
    }

    /// `ghost backup schedule set` changes a live rule in place: one equal
    /// in every field, else the one left of the rule's slot, else the one
    /// left of its destination and frequency; any other rule is new.
    #[test]
    fn a_schedule_set_carries_the_ids_of_the_live_rules_it_changes() {
        let (daily, weekly, first, second) = (
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
            Uuid::now_v7(),
        );
        let schedule = schedule_of(&[
            live_rule(daily, "local", "daily", 180, 3, 3),
            live_rule(weekly, "gigahost_s3", "weekly", 180, 3, 3),
            live_rule(first, "local", "monthly", 180, 3, 3),
            live_rule(second, "local", "monthly", 180, 3, 3),
        ]);
        // The one daily local rule changes, once; the weekly one is hosted,
        // and two monthly local rules of another time leave the choice
        // open: new.
        let ids = carried(
            &schedule,
            &[
                "--rule",
                "daily:local:2@01:00",
                "--rule",
                "daily:local:2@01:00",
                "--rule",
                "weekly:local:2@01:00/mon",
                "--rule",
                "monthly:local:2@01:00/2",
            ],
        );
        assert_eq!(ids, [Some(daily), None, None, None]);
        // The schedule given again unchanged changes nothing: the two equal
        // monthly local rules keep their IDs, each going to one rule.
        let again = [
            "--rule",
            "daily:local:3@03:00",
            "--rule",
            "weekly:hosted:3@03:00/sun",
            "--rule",
            "monthly:local:3@03:00/1",
            "--rule",
            "monthly:local:3@03:00/1",
        ];
        assert_eq!(
            carried(&schedule, &again),
            [Some(daily), Some(weekly), Some(first), Some(second)]
        );
        let (_, mut request) = schedule_set(&again);
        carry_rule_ids(&mut request, &schedule);
        assert_eq!(
            serde_json::to_value(&request.rules[0]).unwrap()["id"],
            json!(daily)
        );
        let (_, unmatched) = schedule_set(&["--rule", "daily:local:3@03:00"]);
        assert!(
            serde_json::to_value(&unmatched.rules[0])
                .unwrap()
                .get("id")
                .is_none()
        );
        // Twice daily local: each rule keeps its ID however the rules are
        // ordered, a keep changed by its slot, a time changed by the one
        // rule of its kind left; two times changed are new rules.
        let (morning, evening) = (Uuid::now_v7(), Uuid::now_v7());
        let twice = schedule_of(&[
            live_rule(morning, "local", "daily", 60, 3, 3),
            live_rule(evening, "local", "daily", 780, 3, 3),
        ]);
        for (arguments, expected) in [
            (
                ["daily:local:3@01:00", "daily:local:3@13:00"],
                [Some(morning), Some(evening)],
            ),
            (
                ["daily:local:3@13:00", "daily:local:3@01:00"],
                [Some(evening), Some(morning)],
            ),
            (
                ["daily:local:5@01:00", "daily:local:2@13:00"],
                [Some(morning), Some(evening)],
            ),
            (
                ["daily:local:3@02:00", "daily:local:3@13:00"],
                [Some(morning), Some(evening)],
            ),
            (["daily:local:3@02:00", "daily:local:3@14:00"], [None, None]),
        ] {
            let ids = carried(&twice, &["--rule", arguments[0], "--rule", arguments[1]]);
            assert_eq!(ids, expected, "{arguments:?}");
        }
    }

    /// A lower keep that deletes backups is named, and sent only with
    /// --yes; the backups its retention deletes anyway, a completed one
    /// over the old keep, are not counted.
    #[test]
    fn a_schedule_set_that_deletes_backups_needs_yes() {
        let (daily, weekly) = (Uuid::now_v7(), Uuid::now_v7());
        let schedule = schedule_of(&[
            live_rule(daily, "local", "daily", 180, 30, 30),
            live_rule(weekly, "gigahost_s3", "weekly", 180, 3, 4),
        ]);
        let deletions = |arguments: &[&str]| {
            let (args, mut request) = schedule_set(arguments);
            carry_rule_ids(&mut request, &schedule);
            let deletions: Vec<(usize, Uuid, u32)> = schedule_deletions(&request, &schedule)
                .into_iter()
                .map(|deletion| (deletion.number, deletion.live.rule_id, deletion.deleted))
                .collect();
            (args.yes, deletions)
        };
        let (yes, found) = deletions(&[
            "--rule",
            "daily:local:3@03:00",
            "--rule",
            "weekly:hosted:2@03:00/sun",
        ]);
        assert!(!yes);
        assert_eq!(found, [(1, daily, 27), (2, weekly, 1)]);
        let (_, mut request) = schedule_set(&["--rule", "daily:local:3@03:00"]);
        carry_rule_ids(&mut request, &schedule);
        assert_eq!(
            schedule_deletion_refusal(&schedule_deletions(&request, &schedule)),
            "rule 1 lowers the keep of the daily local rule from 30 to 3, which deletes its 27 oldest backups; backup deletion is irreversible; repeat with --yes"
        );
        // The same keeps, a higher keep and a removed rule delete nothing.
        assert_eq!(
            deletions(&[
                "--rule",
                "daily:local:30@03:00",
                "--rule",
                "weekly:hosted:3@03:00/sun"
            ])
            .1,
            []
        );
        assert_eq!(deletions(&["--rule", "daily:local:40@03:00"]).1, []);
        let (yes, found) = deletions(&["--rule", "daily:local:29@03:00", "--yes"]);
        assert!(yes);
        assert_eq!(found, [(1, daily, 1)]);
    }

    /// The schedule's table names each rule's times and what removed
    /// rules left.
    #[test]
    fn a_backup_schedule_reads_as_a_table() {
        let schedule: BackupScheduleView = serde_json::from_value(json!({
            "instance_id": Uuid::nil(),
            "rules": [{
                "rule_id": Uuid::nil(), "destination": "gigahost_s3", "frequency": "weekly",
                "minute_of_day": 120, "weekday": 0, "keep": 2,
                "created_at": "2026-10-01T00:00:00Z", "next_run_at": "2026-10-04T02:17:00Z",
                "last_run_at": "2026-09-27T02:17:00Z", "last_result": "skipped_balance",
                "last_message": "a backup needs a balance of $1.00", "backup_count": 1
            }],
            "removed": [{"rule_id": Uuid::nil(), "destination": "local", "frequency": "daily",
                         "keep": 3, "removed_at": "2026-10-01T00:00:00Z", "backups_kept": 2}],
            "maximum_backups": 100
        }))
        .unwrap();
        let table = Summary::backup_schedule(schedule);
        assert_eq!(table.rows[0]["when_utc"], "weekly sun 02:00");
        assert_eq!(table.rows[0]["destination"], "hosted");
        assert_eq!(
            table.rows[0]["last_result"],
            "skipped_balance: a backup needs a balance of $1.00"
        );
        assert!(
            table
                .note
                .as_deref()
                .is_some_and(|note| note.contains("a removed daily local rule left 2 backup(s)")),
            "{:?}",
            table.note
        );
    }

    #[test]
    fn account_balance_names_spending_credit_separately_from_earnings() {
        let output = json!({
            "available_microusd": 400_000_000,
            "reserved_microusd": 100_000_000,
            "total_microusd": 500_000_000,
            "provider_earnings_microusd": 30_000_000,
            "available_payout_microusd": 20_000_000,
            "funding_status": null,
            "provider_credits": [],
            "trial": {"credit_left_microusd": 5_000_000, "expires_at": "2026-11-17T09:00:00Z", "limited": true, "ended_at": null},
        });
        let cli = Cli::try_parse_from(["ghost", "account", "balance"]).unwrap();
        let text = render_result(&cli, &output, Terminal::plain());
        assert!(text.contains("credit_left  $5.00"), "{text}");
        assert!(
            text.contains("expires_at   2026-11-17 09:00:00 UTC"),
            "{text}"
        );
        for label in [
            "available_spending_credit",
            "reserved_spending_credit",
            "total_spending_credit",
            "provider_earnings",
            "available_payout",
        ] {
            assert!(text.contains(label), "{text}");
        }
        for amount in ["$400.00", "$100.00", "$500.00", "$30.00", "$20.00"] {
            assert!(text.contains(amount), "{text}");
        }
        let json = Cli::try_parse_from(["ghost", "--json", "account", "balance"]).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&render_result(&json, &output, Terminal::plain()))
                .unwrap(),
            output
        );
    }

    /// `provider pricing` reads in dollars: the whole-host total the
    /// compute earnings make, and beside the values the compute earnings
    /// as kept and the host's vCPUs. Its `values` are a pricing file.
    #[test]
    fn host_pricing_reads_in_dollars() {
        let output = json!({
            "host_id": Uuid::nil(),
            "revision": 2,
            "values": {
                "base_host_earnings_microusd_per_month": 36_720_000,
                "network_earnings_microusd_per_tib": 8_704_000,
                "sla_target_basis_points": 9900
            },
            "published_at": "2026-10-09T10:00:00Z",
            "existing_instances_effective_at": "2027-01-07T10:00:00Z",
            "compute_earnings": {"microusd_per_month": 2_295_000, "vcpus": 1},
            "saleable_vcpus": 16
        });
        let view: gigahost_client_api::website::HostPricingView =
            serde_json::from_value(output.clone()).unwrap();
        assert_eq!(view.saleable_vcpus, Some(16));
        assert_eq!(
            host_pricing_input(&output["values"].to_string())
                .unwrap()
                .compute(),
            Ok(gigahost_client_api::website::ComputeEarningsForm::WholeHost(36_720_000))
        );
        let host = Uuid::nil().to_string();
        let cli = Cli::try_parse_from(["ghost", "provider", "pricing", &host]).unwrap();
        let text = render_result(&cli, &output, Terminal::plain());
        for shown in ["$2.30 per month", "$36.72 per month", "$8.70 per TiB"] {
            assert!(text.contains(shown), "{shown}: {text}");
        }
    }

    /// A pricing file gives the compute earnings per vCPU or for the whole
    /// host, as every `pricing.json` before did, exactly one of the two.
    #[test]
    fn a_pricing_file_gives_its_compute_earnings_one_way() {
        use gigahost_client_api::website::{ComputeEarningsForm, ComputeEarningsInput};
        let file = |compute: &str| {
            format!(
                r#"{{{compute} "network_earnings_microusd_per_tib": 0, "sla_target_basis_points": 9900}}"#
            )
        };
        let total = host_pricing_input(&file(
            r#""base_host_earnings_microusd_per_month": 32000000,"#,
        ))
        .unwrap();
        assert_eq!(
            total.compute(),
            Ok(ComputeEarningsForm::WholeHost(32_000_000))
        );
        let per_vcpu = host_pricing_input(&file(
            r#""compute_earnings": {"microusd_per_month": 2000000, "vcpus": 1},"#,
        ))
        .unwrap();
        assert_eq!(
            per_vcpu.compute_earnings,
            Some(ComputeEarningsInput {
                microusd_per_month: 2_000_000,
                vcpus: 1
            })
        );
        assert_eq!(per_vcpu.base_host_earnings_microusd_per_month, None);
        let neither = host_pricing_input(&file("")).unwrap_err().to_string();
        assert!(neither.contains("give the compute earnings"), "{neither}");
        let both = host_pricing_input(&file(
            r#""compute_earnings": {"microusd_per_month": 2000000, "vcpus": 1}, "base_host_earnings_microusd_per_month": 32000000,"#,
        ))
        .unwrap_err()
        .to_string();
        assert!(both.contains("not both"), "{both}");
    }

    #[test]
    fn text_comes_inline_or_from_its_file() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("startup.sh");
        fs::write(&path, "echo from-file\n").unwrap();
        let flag = "--startup-command-file";
        assert_eq!(
            load_optional_text(Some("echo inline"), None, flag).unwrap(),
            Some("echo inline".to_owned())
        );
        assert_eq!(
            load_optional_text(None, Some(&path), flag).unwrap(),
            Some("echo from-file\n".to_owned())
        );
        assert_eq!(load_optional_text(None, None, flag).unwrap(), None);
        let missing = directory.path().join("missing");
        let os_error = fs::read_to_string(&missing).unwrap_err();
        assert_eq!(os_error.kind(), std::io::ErrorKind::NotFound);
        let error = load_optional_text(None, Some(&missing), flag).unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "cannot read --startup-command-file {}: {os_error}",
                missing.display()
            )
        );
        assert_eq!(
            load_required_text(None, None, "message")
                .unwrap_err()
                .to_string(),
            "--message or --message-file is required"
        );
    }

    /// The authorization carries the limits it signed, and the account's
    /// billing key verifies it over the canonical message.
    #[test]
    fn a_backup_billing_authorization_signs_what_it_carries() {
        let seed = [9_u8; 32];
        let input = BackupBillingAuthorizationInput {
            operation: "restore_backup",
            instance_id: Uuid::now_v7(),
            backup_id: Some(Uuid::now_v7()),
            destination: "local",
            pricing_revision: 7,
            maximum_charge_microusd: 1_234,
            idempotency_key: "restore-key-0001",
        };
        let authorization = backup_billing_authorization(&seed, &input).unwrap();
        assert_eq!(authorization.pricing_revision, 7);
        assert_eq!(authorization.maximum_charge_microusd, 1_234);
        let public_key: [u8; 32] = URL_SAFE_NO_PAD
            .decode(keys::key_summary(&seed).unwrap().billing_verifying_key)
            .unwrap()
            .try_into()
            .unwrap();
        let signature: [u8; 64] = URL_SAFE_NO_PAD
            .decode(&authorization.signature)
            .unwrap()
            .try_into()
            .unwrap();
        ed25519_dalek::VerifyingKey::from_bytes(&public_key)
            .unwrap()
            .verify_strict(
                &canonical_backup_billing_authorization(&input),
                &ed25519_dalek::Signature::from_bytes(&signature),
            )
            .expect("the billing key signed the canonical message");
    }

    #[test]
    fn offering_filters_become_the_catalog_query() {
        // Parsed from the command line, so the query is checked as typed and
        // options added to the filters later need no change here.
        let query = |arguments: &[&str]| {
            let cli =
                Cli::try_parse_from(["ghost", "catalog", "offerings"].iter().chain(arguments))
                    .unwrap();
            let Command::Catalog {
                command: Some(CatalogCommand::Offerings(filters)),
                ..
            } = cli.command
            else {
                panic!("not a catalog offerings command");
            };
            filters.query(None).unwrap()
        };
        assert_eq!(
            query(&[
                "--mode",
                "home-gateway",
                "--location",
                "pl-warsaw",
                "--country",
                "pl",
                "--continent",
                "eu",
                "--provider",
                "GH-Examples",
                "--min-vcpu",
                "4",
                "--min-ram",
                "8GiB",
                "--min-disk",
                "100",
                "--available",
                "3",
                "--host",
                "0199a1b2-0000-7000-8000-000000000001",
                "--limit",
                "50",
                "--after",
                "3100000.of2_F95QS_EuMsVz4IG5EulOew",
            ]),
            "mode=home_gateway&kind=any&location=pl-warsaw&country=PL&continent=EU&provider=gh-examples&minimum_vcpus=4&host_id=0199a1b2-0000-7000-8000-000000000001&minimum_memory_bytes=8589934592&minimum_root_disk_bytes=107374182400&minimum_available=3&limit=50&after=3100000.of2_F95QS_EuMsVz4IG5EulOew"
        );
        assert_eq!(
            query(&["--minimum-vcpus", "2"]),
            "kind=any&minimum_vcpus=2",
            "the old name still works"
        );
        // Every kind unless one is asked for.
        assert_eq!(query(&[]), "kind=any");
        assert_eq!(query(&["--kind", "vm"]), "kind=vm");
        assert_eq!(query(&["--kind", "container"]), "kind=container");
        assert!(
            Cli::try_parse_from(["ghost", "catalog", "offerings", "--kind", "unknown"]).is_err()
        );
        assert_eq!(query(&["--ip", "shared"]), "ip=shared&kind=any");
        assert_eq!(query(&["--ip", "dedicated"]), "ip=dedicated&kind=any");
        assert!(
            Cli::try_parse_from(["ghost", "catalog", "--ip", "own"]).is_err(),
            "only dedicated and shared are choices"
        );
        assert_eq!(parse_country_code("us").unwrap(), "US");
        assert_eq!(parse_continent_code("eu").unwrap(), "EU");
        assert!(parse_country_code("USA").is_err());
        assert!(parse_continent_code("USA").is_err());
    }

    #[test]
    fn restore_destination_fingerprint_is_checked_before_rewrap() {
        let seed = [11_u8; 32];
        let recovery = keys::recovery_key_pair(&seed).unwrap();
        let error = keys::rewrap_backup_data_key(
            &recovery,
            &keys::BackupRewrapTarget {
                source_instance_id: Uuid::nil(),
                destination_instance_id: Uuid::nil(),
                backup_id: Uuid::nil(),
                restore_job_id: Uuid::nil(),
                destination_public_key: &URL_SAFE_NO_PAD.encode([1_u8; 32]),
                destination_key_fingerprint: &URL_SAFE_NO_PAD.encode(Sha256::digest([2_u8; 32])),
            },
            "invalid",
        )
        .unwrap_err();
        assert!(error.to_string().contains("base64url") || error.to_string().contains("80 bytes"));
    }

    #[test]
    fn restore_authorization_idempotency_key_is_stable_and_bounded() {
        let key = restore_authorization_key(&"x".repeat(128));
        assert_eq!(key, restore_authorization_key(&"x".repeat(128)));
        assert!((16..=128).contains(&key.len()));
    }

    #[test]
    fn job_progress_event_is_human_readable() {
        let event = JobEventView {
            event_id: 7,
            step_id: Some(Uuid::nil()),
            step_key: Some("wait_for_ssh".to_owned()),
            attempt: Some(2),
            state: Some("retry_wait".to_owned()),
            progress_permyriad: Some(2500),
            message: Some("SSH is not ready".to_owned()),
            created_at: Utc::now(),
        };
        assert_eq!(
            format_job_event(&event, Some("wait_for_ssh"), false),
            "[waiting to retry, attempt 2, 25 %] waiting for SSH: SSH is not ready"
        );
        assert_eq!(
            format_job_event(&event, Some("wait_for_ssh"), true),
            "\u{1b}[33m[waiting to retry, attempt 2, 25 %]\u{1b}[0m waiting for SSH: SSH is not ready"
        );
        // A queued step's attempt 0 and a waiting step's 0% are left out; a
        // running step shows even 0%.
        let queued = JobEventView {
            attempt: Some(0),
            state: Some("pending".to_owned()),
            progress_permyriad: Some(0),
            message: Some("backup step upload_parts queued".to_owned()),
            ..event.clone()
        };
        assert_eq!(
            format_job_event(&queued, Some("upload_parts"), false),
            "[queued] uploading the backup: backup step upload_parts queued"
        );
        let running = JobEventView {
            attempt: Some(1),
            state: Some("running".to_owned()),
            ..queued
        };
        assert_eq!(
            format_job_event(&running, None, false),
            "[running, attempt 1, 0 %] backup step upload_parts queued"
        );
    }

    /// A followed job prints each event with its step's name, then prints
    /// it again when the same event has updated progress.
    #[test]
    fn a_followed_job_names_steps_and_repeats_growing_progress() {
        let step_id = Uuid::now_v7();
        let mut job: JobView = serde_json::from_str(&job_json(
            JobState::Running,
            &[("upload_parts", JobStepState::Running)],
            json!({}),
        ))
        .unwrap();
        job.steps[0].step_id = step_id;
        let event = |progress| JobEventView {
            event_id: 788,
            step_id: Some(step_id),
            step_key: None,
            attempt: Some(1),
            state: Some("running".to_owned()),
            progress_permyriad: Some(progress),
            message: Some("host operation is journaled and active".to_owned()),
            created_at: Utc::now(),
        };
        let mut printed = PrintedEvents::new();
        job.events = vec![event(125)];
        assert_eq!(
            new_event_lines(&job, &mut printed, false),
            [
                "[running, attempt 1, 1.25 %] uploading the backup: host operation is journaled and active"
            ]
        );
        // Unchanged, or changed within the same whole percent: nothing new.
        job.events = vec![event(150)];
        assert!(new_event_lines(&job, &mut printed, false).is_empty());
        job.events = vec![event(4_420)];
        assert_eq!(
            new_event_lines(&job, &mut printed, false),
            [
                "[running, attempt 1, 44.2 %] uploading the backup: host operation is journaled and active"
            ]
        );
        // The step an event names wins over the steps list, which an older
        // backend's events are looked up in.
        job.events = vec![JobEventView {
            event_id: 789,
            step_id: Some(Uuid::now_v7()),
            step_key: Some("verify_backup".to_owned()),
            state: Some("succeeded".to_owned()),
            ..event(10_000)
        }];
        assert_eq!(
            new_event_lines(&job, &mut printed, false),
            [
                "[succeeded, attempt 1, 100 %] verifying the backup: host operation is journaled and active"
            ]
        );
    }

    #[test]
    fn results_are_for_reading_unless_json_is_asked_for() {
        let format = |arguments: &[&str]| {
            Cli::try_parse_from(
                ["ghost"]
                    .iter()
                    .chain(arguments)
                    .chain(&["catalog", "images"]),
            )
            .unwrap()
            .output_format()
        };
        assert_eq!(format(&[]), OutputFormat::Readable);
        assert_eq!(format(&["--json"]), OutputFormat::Json);
        assert_eq!(format(&["--compact"]), OutputFormat::CompactJson);
        assert_eq!(format(&["--json", "--compact"]), OutputFormat::CompactJson);
        let after = Cli::try_parse_from(["ghost", "catalog", "images", "--json"]).unwrap();
        assert_eq!(after.output_format(), OutputFormat::Json);

        let value = json!({"state": "running", "image_id": "debian-13"});
        assert_eq!(
            render_output(&value, OutputFormat::Readable, Terminal::plain()),
            "  image_id    debian-13\n  state       running"
        );
        assert_eq!(
            render_output(&value, OutputFormat::Json, Terminal::plain()),
            "{\n  \"image_id\": \"debian-13\",\n  \"state\": \"running\"\n}"
        );
        assert_eq!(
            render_output(&value, OutputFormat::CompactJson, Terminal::plain()),
            r#"{"image_id":"debian-13","state":"running"}"#
        );
        let colors = Terminal {
            colors: true,
            width: 80,
        };
        assert_eq!(
            render_error(&anyhow::anyhow!("no such instance"), colors),
            "\u{1b}[1;31mError:\u{1b}[0m no such instance"
        );
    }

    #[test]
    fn server_supplied_text_cannot_inject_terminal_sequences() {
        let event = JobEventView {
            event_id: 1,
            step_id: None,
            step_key: None,
            attempt: None,
            state: Some("run\u{1b}[2J".to_owned()),
            progress_permyriad: None,
            message: Some("done\u{1b}]52;c;cm0gLXJmIH4=\u{7}\n\u{9b}31m".to_owned()),
            created_at: Utc::now(),
        };
        let line = format_job_event(&event, None, false);
        assert!(!line.chars().any(char::is_control), "{line:?}");
        assert_eq!(
            line,
            r"[run\u{1b}[2J] done\u{1b}]52;c;cm0gLXJmIH4=\u{7}\n\u{9b}31m"
        );
        assert!(matches!(escape_control("plain text"), Cow::Borrowed(_)));

        let error = anyhow::anyhow!("API returned 409: conflict: \u{1b}]0;owned\u{7}")
            .context("send \u{9d}mutation");
        let rendered = render_error(&error, Terminal::plain());
        assert!(
            !rendered.contains(['\u{1b}', '\u{7}', '\u{9d}']),
            "{rendered:?}"
        );
        assert!(rendered.starts_with(r"Error: send \u{9d}mutation"));

        let value = json!({"message": "a\u{1b}[31mb\u{7f}c\u{9b}d\u{85}e"});
        for format in [OutputFormat::CompactJson, OutputFormat::Json] {
            let text = render_output(&value, format, Terminal::plain());
            assert!(
                !text.chars().any(|c| c.is_control() && c != '\n'),
                "{text:?}"
            );
            assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), value);
        }
    }

    /// A refusal `ghost` words over several lines (the choices one per line,
    /// the hint on its own) prints with its real line breaks; only the other
    /// control characters are escaped, and a cause's later lines stay under
    /// the cause.
    #[test]
    fn a_multi_line_error_prints_its_lines_and_still_escapes_the_rest() {
        let home = listed_offering(HostMode::HomeGateway);
        let error = check_rental(&home, None, None).unwrap_err();
        assert_eq!(
            render_error(&error, Terminal::plain()),
            concat!(
                "Error: offering of2_J7hnuv_uO8PmXACeyas4QY is on a home host, which a hosted gateway connects.\n",
                "To choose its tier, give --gateway-tier:\n",
                "  shared bandwidth (--gateway-tier shared_bandwidth)  $10.24/TiB + $5.00/month\n",
                "  high bandwidth (--gateway-tier high_bandwidth)      $5.24/TiB + $15.00/month"
            )
        );

        let error = anyhow::Error::msg(JobContext {
            job_id: Uuid::nil(),
            message: "Stopped following job.\nTo check the job: ghost job get X".to_owned(),
        });
        assert_eq!(
            render_error(&error, Terminal::plain()),
            "Error: Stopped following job.\nTo check the job: ghost job get X"
        );

        // Only the line feed stays: a carriage return, which could write
        // over the line before it, and the escapes are shown, not obeyed.
        let error = anyhow::anyhow!("one\r\ntwo\u{1b}[2J\nthree");
        assert_eq!(
            render_error(&error, Terminal::plain()),
            "Error: one\\r\ntwo\\u{1b}[2J\nthree"
        );

        let coloured = Terminal {
            colors: true,
            width: 80,
        };
        assert_eq!(
            render_error(&anyhow::anyhow!("a\nb"), coloured),
            "\u{1b}[1;31mError:\u{1b}[0m a\nb"
        );

        let one = anyhow::anyhow!("first\nsecond\u{7}").context("outer");
        assert_eq!(
            render_error(&one, Terminal::plain()),
            "Error: outer\n\nCaused by:\n    first\n    second\\u{7}"
        );
        let two = anyhow::anyhow!("first\nsecond")
            .context("middle")
            .context("outer");
        assert_eq!(
            render_error(&two, Terminal::plain()),
            "Error: outer\n\nCaused by:\n    0: middle\n    1: first\n       second"
        );
    }

    #[test]
    fn default_seed_path_uses_only_absolute_config_directories() {
        let root = tempfile::tempdir().unwrap();
        let config = root.path().join("xdg");
        let home = root.path().join("home");
        let path = |config_home: Option<&Path>, home: Option<&Path>| {
            seed_path_below(config_home.map(Into::into), home.map(Into::into))
        };
        assert_eq!(
            path(Some(&config), Some(&home)).unwrap(),
            config.join("ghost/account.seed")
        );
        for ignored in ["", "relative/config"] {
            assert_eq!(
                path(Some(Path::new(ignored)), Some(&home)).unwrap(),
                home.join(".config/ghost/account.seed")
            );
        }
        assert!(path(Some(Path::new("")), Some(Path::new(""))).is_err());
        assert!(path(None, Some(Path::new("home"))).is_err());
        assert!(path(None, None).is_err());
    }

    /// The public catalog needs no account key, not even one named with
    /// --seed-file that does not exist; a command that needs the account
    /// fails for such a seed, by its name, before it sends anything.
    #[tokio::test]
    async fn only_commands_that_need_the_account_need_its_seed() {
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.seed");
        let (url, received) = canned_server(vec![(200, "[]".to_owned())]).await;
        let run = |command: &[&str]| {
            let mut arguments = vec![
                "ghost".as_ref(),
                "--api-url".as_ref(),
                url.as_ref(),
                "--seed-file".as_ref(),
                missing.as_os_str(),
            ];
            arguments.extend(command.iter().map(std::ffi::OsStr::new));
            Cli::try_parse_from(arguments).unwrap()
        };
        assert_eq!(
            execute(&run(&["catalog", "images"])).await.unwrap(),
            json!([])
        );
        let error = execute(&run(&["account", "show"])).await.unwrap_err();
        assert!(error.to_string().contains("missing.seed"), "{error:#}");
        assert_eq!(request_lines(&received), ["GET /v1/catalog/images"]);
    }

    /// `key import --from` puts the key in the `--seed-file` path and reads
    /// the account; a key with none yet is a note, not a failure, and the
    /// readable form says it in the account's row.
    #[tokio::test]
    async fn an_imported_key_without_an_account_is_imported() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("ghost").join("account.seed");
        let download = directory.path().join("account (1).seed");
        fs::write(
            &download,
            format!(
                "gigahost-account-seed-v1:{}\r\n",
                URL_SAFE_NO_PAD.encode([7_u8; 32])
            ),
        )
        .unwrap();
        let refusal = json!({"code": "account_not_activated", "message": "no account is registered for this key yet"});
        let (url, received) = canned_server(vec![(401, refusal.to_string())]).await;
        let cli = account_command(
            &url,
            &seed,
            &["key", "import", "--from", download.to_str().unwrap()],
        );
        let output = execute(&cli).await.unwrap();
        assert_eq!(output["result"], "imported");
        assert_eq!(output["account"], Value::Null);
        assert_eq!(output["account_note"], IMPORT_NO_ACCOUNT);
        assert_eq!(output["seed_file"], json!(seed));
        assert!(output.get("replaced_file").is_none());
        assert!(
            output["note"]
                .as_str()
                .unwrap()
                .contains("account (1).seed"),
            "{output}"
        );
        assert_eq!(
            output["keys"],
            serde_json::to_value(keys::key_summary(&[7; 32]).unwrap()).unwrap()
        );
        assert_eq!(*keys::load_seed(&seed).unwrap(), [7; 32]);
        assert_eq!(request_lines(&received), ["GET /v1/account"]);
        let readable = readable_sections(&cli.command, &output, Terminal::plain()).unwrap();
        assert!(
            readable.contains("this key has no account yet"),
            "{readable}"
        );
        assert!(readable.contains("imported"), "{readable}");
        assert!(readable.contains("authentication_key_id"), "{readable}");
        // The file it came from is left where it is.
        assert!(download.exists());
    }

    /// The account a key has is shown; a backend out of reach is a note.
    #[tokio::test]
    async fn an_import_shows_the_account_or_why_it_could_not() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        let download = directory.path().join("download.seed");
        keys::generate_seed(&download).unwrap();
        let account = json!({"account_alias": "gh-test", "deposit_memo": "memo", "key_epoch": 1, "status": "active"});
        let (url, _) = canned_server(vec![(200, account.to_string())]).await;
        let cli = account_command(
            &url,
            &seed,
            &["key", "import", "--from", download.to_str().unwrap()],
        );
        let output = execute(&cli).await.unwrap();
        assert_eq!(output["account"]["account_alias"], "gh-test");
        assert!(output.get("account_note").is_none());
        let readable = readable_sections(&cli.command, &output, Terminal::plain()).unwrap();
        assert!(readable.contains("gh-test (active)"), "{readable}");

        let failure = json!({"code": "internal_error", "message": "boom"});
        let (url, _) = canned_server(vec![(400, failure.to_string())]).await;
        let cli = account_command(
            &url,
            &seed,
            &["key", "import", "--from", download.to_str().unwrap()],
        );
        let output = execute(&cli).await.unwrap();
        assert_eq!(output["result"], "already_imported");
        assert_eq!(output["account"], Value::Null);
        assert!(
            output["account_note"]
                .as_str()
                .unwrap()
                .starts_with("the account could not be checked: "),
            "{output}"
        );
    }

    /// A malformed key is refused with the seed file's words before
    /// anything is written or sent; a different key is refused with
    /// `account_key_exists`, and `--replace` keeps the old one.
    #[tokio::test]
    async fn an_import_writes_only_a_valid_key_and_replaces_only_when_asked() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("ghost").join("account.seed");
        let given = directory.path().join("given.seed");
        fs::write(&given, "gigahost-account-seed-v1:not-a-key!\n").unwrap();
        let import = |extra: &[&str]| {
            let mut arguments = vec!["key", "import", "--from", given.to_str().unwrap()];
            arguments.extend(extra);
            account_command("http://127.0.0.1:9/", &seed, &arguments)
        };
        let error = execute(&import(&[])).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "account key is not valid unpadded base64url"
        );
        assert!(!seed.parent().unwrap().exists(), "nothing is written");
        fs::write(&given, "").unwrap();
        let error = execute(&import(&[])).await.unwrap_err();
        assert_eq!(error.to_string(), "no account key was given");

        keys::generate_seed(&seed).unwrap();
        let original = fs::read(&seed).unwrap();
        keys::generate_seed(&given.with_extension("other")).unwrap();
        fs::rename(given.with_extension("other"), &given).unwrap();
        let error = execute(&import(&[])).await.unwrap_err();
        assert_eq!(error_output(&error)["error"]["code"], "account_key_exists");
        let text = fs::read_to_string(&given).unwrap();
        let secret = text
            .trim()
            .strip_prefix("gigahost-account-seed-v1:")
            .unwrap();
        assert!(!error_output(&error).to_string().contains(secret));
        assert_eq!(fs::read(&seed).unwrap(), original);
        let (url, _) = canned_server(vec![(
            401,
            json!({"code": "account_not_activated", "message": "none"}).to_string(),
        )])
        .await;
        let cli = account_command(
            &url,
            &seed,
            &[
                "key",
                "import",
                "--from",
                given.to_str().unwrap(),
                "--replace",
            ],
        );
        let output = execute(&cli).await.unwrap();
        assert_eq!(output["result"], "replaced");
        let kept = PathBuf::from(output["replaced_file"].as_str().unwrap());
        assert_eq!(fs::read(&kept).unwrap(), original);
        assert_eq!(fs::read(&seed).unwrap(), fs::read(&given).unwrap());
        let readable = readable_sections(&cli.command, &output, Terminal::plain()).unwrap();
        assert!(
            readable.contains("the previous key is kept at"),
            "{readable}"
        );
    }

    #[test]
    fn the_key_help_lists_import() {
        let help = command()
            .find_subcommand_mut("key")
            .map(|key| key.render_help().to_string())
            .unwrap();
        assert!(help.contains("import"), "{help}");
        let help = command()
            .find_subcommand_mut("key")
            .and_then(|key| key.find_subcommand_mut("import"))
            .map(|import| import.render_long_help().to_string())
            .unwrap();
        assert!(help.contains("--from <FILE>"), "{help}");
        assert!(help.contains("--replace"), "{help}");
    }

    /// Requests a canned server received: the request line and the body.
    type Received = std::sync::Arc<std::sync::Mutex<Vec<(String, Vec<u8>)>>>;

    /// Serve one canned `(status, body)` response per connection, in order,
    /// and record each request.
    async fn canned_server(responses: Vec<(u16, String)>) -> (String, Received) {
        canned_server_with_headers(
            responses
                .into_iter()
                .map(|(status, body)| (status, String::new(), body))
                .collect(),
        )
        .await
    }

    /// [`canned_server`] with `(status, headers, body)` responses, whose
    /// headers are lines that each end in CRLF.
    async fn canned_server_with_headers(
        responses: Vec<(u16, String, String)>,
    ) -> (String, Received) {
        let (url, received, _) = canned_server_recording_heads(responses).await;
        (url, received)
    }

    /// The raw request heads (request line and headers) a canned server
    /// received, one per request, in the order of [`Received`].
    type Heads = std::sync::Arc<std::sync::Mutex<Vec<String>>>;

    /// [`canned_server_with_headers`] that also records each request head.
    async fn canned_server_recording_heads(
        responses: Vec<(u16, String, String)>,
    ) -> (String, Received, Heads) {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let received = Received::default();
        let log = received.clone();
        let heads = Heads::default();
        let head_log = heads.clone();
        tokio::spawn(async move {
            for (status, headers, body) in responses {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut chunk = [0_u8; 1024];
                let header_end = loop {
                    if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                        break end + 4;
                    }
                    let read = stream.read(&mut chunk).await.unwrap();
                    assert_ne!(read, 0, "request ended inside its headers");
                    request.extend_from_slice(&chunk[..read]);
                };
                let head = String::from_utf8_lossy(&request[..header_end]).into_owned();
                let content_length = head
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                while request.len() < header_end + content_length {
                    let read = stream.read(&mut chunk).await.unwrap();
                    assert_ne!(read, 0, "request ended inside its body");
                    request.extend_from_slice(&chunk[..read]);
                }
                head_log.lock().unwrap().push(head.clone());
                log.lock().unwrap().push((
                    head.lines().next().unwrap_or_default().to_owned(),
                    request[header_end..].to_vec(),
                ));
                let response = format!(
                    "HTTP/1.1 {status} Canned\r\ndate: {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n{headers}\r\n{body}",
                    Utc::now().format("%a, %d %b %Y %H:%M:%S GMT"),
                    body.len()
                );
                stream.write_all(response.as_bytes()).await.unwrap();
                let _ = stream.shutdown().await;
            }
        });
        (url, received, heads)
    }

    async fn canned_api(responses: Vec<(u16, String)>) -> ApiClient {
        let (url, _) = canned_server(responses).await;
        let identity = keys::authentication_identity(&[3_u8; 32]).unwrap();
        ApiClient::new(&url, Some(identity)).unwrap()
    }

    fn job_json(state: JobState, steps: &[(&str, JobStepState)], result: Value) -> String {
        let now = Utc::now();
        serde_json::to_string(&JobView {
            job_id: Uuid::nil(),
            kind: gigahost_client_api::website::JobKind::RestoreBackup,
            state,
            resource_id: Uuid::nil(),
            progress_permyriad: 0,
            current_step_key: None,
            current_step_progress_permyriad: None,
            result,
            error_code: None,
            error_message: (state == JobState::Failed).then(|| "disk full".to_owned()),
            created_at: now,
            updated_at: now,
            completed_at: None,
            steps: steps
                .iter()
                .map(|(key, state)| gigahost_client_api::website::JobStepView {
                    step_id: Uuid::now_v7(),
                    step_key: (*key).to_owned(),
                    state: *state,
                    attempt: 0,
                    maximum_attempts: 1,
                    progress_permyriad: 0,
                    error_code: None,
                    error_message: (*state == JobStepState::Failed)
                        .then(|| "client-side restore key authorization expired".to_owned()),
                    started_at: None,
                    completed_at: None,
                })
                .collect(),
            events: Vec::new(),
            waiting: None,
        })
        .unwrap()
    }

    /// A shared IP: `--gateway-tier shared_ip` (or `shared-ip`), `ghost
    /// instance ports ID` and `ghost instance ports ID set PUBLIC=GUEST…`,
    /// and what they show of the instance.
    #[test]
    fn a_shared_ip_has_its_tier_and_its_ports() {
        for tier in ["shared_ip", "shared-ip"] {
            let cli = Cli::try_parse_from([
                "ghost",
                "instance",
                "create",
                "--offering",
                "o",
                "--image",
                "debian-13",
                "--gateway-tier",
                tier,
            ])
            .unwrap();
            let Command::Instance {
                command: InstanceCommand::Create(args),
            } = cli.command
            else {
                panic!("not instance create");
            };
            assert_eq!(args.gateway_tier, Some(GatewayTier::SharedIp));
        }
        let id = Uuid::now_v7();
        let ports = |arguments: &[&str]| {
            let mut line = vec![
                "ghost".to_owned(),
                "instance".to_owned(),
                "ports".to_owned(),
                id.to_string(),
            ];
            line.extend(arguments.iter().map(|argument| (*argument).to_owned()));
            Cli::try_parse_from(line).map(|cli| match cli.command {
                Command::Instance {
                    command: InstanceCommand::Ports(args),
                } => args
                    .action
                    .map(|PortsAction::Set { forwards, .. }| forwards),
                _ => panic!("not instance ports"),
            })
        };
        assert_eq!(ports(&[]).unwrap(), None);
        assert_eq!(
            ports(&["set", "1020=22", "1021=80"]).unwrap(),
            Some(vec![
                PortForwardChange {
                    public_port: 1020,
                    guest_port: 22
                },
                PortForwardChange {
                    public_port: 1021,
                    guest_port: 80
                },
            ])
        );
        for wrong in ["1020", "1020=0", "=22", "1020=65536", "a=b"] {
            assert!(ports(&["set", wrong]).is_err(), "{wrong}");
        }
        assert!(ports(&["set"]).is_err(), "at least one port");

        let instance: InstanceView = serde_json::from_value(json!({
            "instance_id": id, "offering_id": "o", "restored_from_backup_id": null,
            "hostname": "web-1", "root_disk_bytes": 1, "state": "running",
            "desired_power_state": "running", "holds_capacity": true,
            "public_ipv4": "203.0.113.7", "gateway_tier": "shared_ip",
            "port_forwards": [{"public_port": 1020, "guest_port": 22}, {"public_port": 1021, "guest_port": 80}],
            "outgoing_ports": {"first_port": 11100, "ports": 100},
            "network_microusd_per_tib": 0, "created_at": Utc::now(), "billing_started_at": null,
            "balance_reservation_microusd": 0, "provider_termination": null
        }))
        .unwrap();
        assert_eq!(
            created_instance_note(&instance, false),
            [
                format!("Instance {id} (web-1) is running."),
                "  Address   203.0.113.7".to_owned(),
                "  SSH       ssh -p 1020 root@203.0.113.7".to_owned(),
                format!("  Ports     ghost instance ports {id}"),
            ]
        );
        assert_eq!(
            port_forwards_output(&instance),
            json!({
                "public_ipv4": "203.0.113.7",
                "ssh": "ssh -p 1020 root@203.0.113.7",
                "port_forwards": [{"public_port": 1020, "guest_port": 22}, {"public_port": 1021, "guest_port": 80}],
                "outgoing_ports": "11100-11199",
            })
        );
    }

    #[test]
    fn poll_retry_delay_backs_off_without_overflowing() {
        let second = Duration::from_secs(1);
        assert_eq!(next_poll_retry_delay(second, second), 2 * second);
        assert_eq!(
            next_poll_retry_delay(20 * second, second),
            MAXIMUM_POLL_RETRY_DELAY
        );
        assert_eq!(
            next_poll_retry_delay(Duration::MAX, Duration::MAX),
            Duration::MAX
        );
    }

    /// A job in a state a newer backend added ends once it has completed,
    /// and not as a success; one that has not completed is followed for its
    /// window only, after which the waiting stops naming the state, and
    /// the job for scripts.
    #[tokio::test]
    async fn a_job_in_a_state_this_ghost_does_not_know_ends_once_completed() {
        let interval = Duration::from_millis(10);
        let window = Duration::from_mins(1);
        let unknown = |completed: bool| {
            let mut job: Value =
                serde_json::from_str(&job_json(JobState::Running, &[], json!({}))).unwrap();
            job["state"] = json!("escalated");
            if completed {
                job["completed_at"] = json!(Utc::now());
            }
            job.to_string()
        };
        let api = canned_api(vec![
            (200, unknown(false)),
            (200, job_json(JobState::Running, &[], json!({}))),
            (200, unknown(true)),
        ])
        .await;
        let job = wait_for_job_within(&api, Uuid::nil(), interval, false, window)
            .await
            .unwrap();
        assert_eq!(job.state, JobState::Unknown);
        assert!(job.completed_at.is_some());
        let error = finished_job(job).unwrap_err();
        assert!(error.is::<JobUnsuccessful>());
        assert!(
            error.to_string().starts_with(&format!(
                "job {} ended in a state this ghost does not know (this ghost is older than the backend",
                Uuid::nil()
            )),
            "{error}"
        );

        let api = canned_api(vec![(200, unknown(false))]).await;
        let error = wait_for_job_within(&api, Uuid::nil(), interval, false, Duration::ZERO)
            .await
            .unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("state this ghost does not know (escalated)"),
            "{message}"
        );
        assert!(message.contains("older than the backend"), "{message}");
        assert_eq!(error_output(&error)["error"]["job_id"], json!(Uuid::nil()));
        // The stop is worded over four lines, and the terminal gets them as
        // lines.
        let rendered = render_error(&error, Terminal::plain());
        assert_eq!(
            rendered,
            format!(
                "Error: Stopped following job {id}.\nIt is in a state this ghost does not know (escalated) and has not completed.\nThis ghost is older than the backend: update it to follow such a job.\nTo check the job: ghost job get {id}",
                id = Uuid::nil()
            )
        );
    }

    #[tokio::test]
    async fn job_waits_retry_transient_errors_and_fail_on_unsuccessful_jobs() {
        let interval = Duration::from_millis(10);
        let api = canned_api(vec![
            (503, "upstream unavailable".to_owned()),
            (
                429,
                r#"{"code":"rate_limited","message":"slow down"}"#.to_owned(),
            ),
            (200, job_json(JobState::Running, &[], json!({}))),
            (200, job_json(JobState::Failed, &[], json!({}))),
            (200, job_json(JobState::Cancelled, &[], json!({}))),
            (200, job_json(JobState::Succeeded, &[], json!({}))),
        ])
        .await;
        let failed = wait_for_job(&api, Uuid::nil(), interval, false)
            .await
            .unwrap();
        let error = finished_job(failed).unwrap_err();
        let unsuccessful = error.downcast_ref::<JobUnsuccessful>().unwrap();
        assert_eq!(unsuccessful.snapshot()["state"], "failed");
        assert_eq!(
            error.to_string(),
            format!("job {} ended failed: disk full", Uuid::nil())
        );
        let cancelled = wait_for_job(&api, Uuid::nil(), interval, false)
            .await
            .unwrap();
        assert!(finished_job(cancelled).unwrap_err().is::<JobUnsuccessful>());
        let succeeded = wait_for_job(&api, Uuid::nil(), interval, false)
            .await
            .unwrap();
        assert_eq!(finished_job(succeeded).unwrap()["state"], "succeeded");

        // A rejection is final, and the error says what to do: a job that
        // does not exist cannot be watched later, while one refused for a
        // used-up quota, which no retry within the poll window lifts, can.
        // A retry would find the job succeeded.
        let api = canned_api(vec![
            (
                404,
                r#"{"code":"not_found","message":"job not found"}"#.to_owned(),
            ),
            (
                429,
                r#"{"code":"limit_reached","message":"daily job limit reached"}"#.to_owned(),
            ),
            (200, job_json(JobState::Succeeded, &[], json!({}))),
        ])
        .await;
        let unknown = wait_for_job(&api, Uuid::nil(), interval, false)
            .await
            .unwrap_err();
        assert!(!api::is_transient(&unknown));
        assert_eq!(
            unknown.to_string(),
            format!(
                "there is no job {} in this account; `ghost job list` lists its jobs",
                Uuid::nil()
            )
        );
        let limited = wait_for_job(&api, Uuid::nil(), interval, false)
            .await
            .unwrap_err();
        assert!(!api::is_transient(&limited));
        assert!(
            limited
                .to_string()
                .contains(&format!("ghost job watch {}", Uuid::nil())),
            "{limited:#}"
        );
        // The job that goes on is named for scripts; one that is not
        // there is not.
        assert_eq!(
            error_output(&limited)["error"]["job_id"],
            json!(Uuid::nil())
        );
        assert_eq!(error_output(&unknown)["error"]["job_id"], Value::Null);

        // A refused connection is transient.
        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", closed.local_addr().unwrap());
        drop(closed);
        let api = ApiClient::new(&url, None)
            .unwrap()
            .with_read_retry_delays(&[]);
        let error = api.read(&ListImages, "").await.unwrap_err();
        assert!(api::is_transient(&error), "{error:#}");
    }

    /// `job get` and `job watch` of a job the account does not have say
    /// so, and keep the backend's code for scripts.
    #[tokio::test]
    async fn an_unknown_job_is_named_as_one() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let not_found = json!({"code": "not_found", "message": "job not found"}).to_string();
        let (url, received) = canned_server(vec![(404, not_found.clone()), (404, not_found)]).await;
        let job_id = Uuid::now_v7();
        let id = job_id.to_string();
        for command in ["get", "watch"] {
            let error = execute(&account_command(&url, &seed, &["job", command, &id]))
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                format!(
                    "there is no job {job_id} in this account; `ghost job list` lists its jobs"
                )
            );
            let output = error_output(&error);
            assert_eq!(output["error"]["code"], "not_found");
            assert_eq!(output["error"]["status"], 404);
        }
        assert_eq!(request_lines(&received).len(), 2);
    }

    /// A server that closes each of the first `dropped` connections after
    /// reading its request, and answers each later one with 200 and
    /// `body`. It counts the connections it accepted.
    async fn dropping_server(
        dropped: usize,
        body: String,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let accepted = std::sync::Arc::new(AtomicUsize::new(0));
        let count = accepted.clone();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = [0_u8; 4096];
                let _ = stream.read(&mut request).await;
                if count.fetch_add(1, Ordering::SeqCst) < dropped {
                    continue;
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });
        (url, accepted)
    }

    /// A read that got no answer is sent again, as a lossy link needs; a
    /// mutation is not, since only its idempotency key makes it safe.
    #[tokio::test]
    async fn a_read_without_an_answer_is_sent_again() {
        use std::sync::atomic::Ordering;

        let pauses = [Duration::ZERO; 2];
        let (url, accepted) = dropping_server(2, "[]".to_owned()).await;
        let api = ApiClient::new(&url, None)
            .unwrap()
            .with_read_retry_delays(&pauses);
        let images: Vec<ImageView> = api.read(&ListImages, "").await.unwrap();
        assert!(images.is_empty());
        assert_eq!(accepted.load(Ordering::SeqCst), 3);

        // Two retries at most: the third attempt without an answer fails.
        let (url, accepted) = dropping_server(3, "[]".to_owned()).await;
        let api = ApiClient::new(&url, None)
            .unwrap()
            .with_read_retry_delays(&pauses);
        let error = api.read(&ListImages, "").await.unwrap_err();
        assert!(api::got_no_response(&error), "{error:#}");
        assert_eq!(accepted.load(Ordering::SeqCst), 3);

        let (url, accepted) = dropping_server(1, "{}".to_owned()).await;
        let api = ApiClient::new(&url, None)
            .unwrap()
            .with_read_retry_delays(&pauses);
        let error = api
            .write(
                &gigahost_client_api::api::RedeemLoginGrant,
                &gigahost_client_api::website::RedeemLoginGrantRequest {
                    token: "token".to_owned(),
                },
                None,
            )
            .await
            .unwrap_err();
        assert!(api::got_no_response(&error), "{error:#}");
        assert_eq!(accepted.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn resumed_hosted_restore_skips_an_accepted_authorization() {
        let interval = Duration::from_millis(10);
        let offer = json!({"prepare_restore_key": {
            "destination_public_key": URL_SAFE_NO_PAD.encode([1_u8; 32]),
            "destination_key_fingerprint": URL_SAFE_NO_PAD.encode([2_u8; 32]),
            "offer_expires_at": Utc::now() + chrono::Duration::minutes(10),
        }});
        let awaiting = |state| [("await_restore_authorization", state)];
        let api = canned_api(vec![
            // An earlier request already authorized the restore.
            (
                200,
                job_json(
                    JobState::Running,
                    &[
                        ("prepare_restore_key", JobStepState::Succeeded),
                        ("download_backup", JobStepState::Running),
                    ],
                    offer.clone(),
                ),
            ),
            (
                200,
                job_json(
                    JobState::Succeeded,
                    &[("download_backup", JobStepState::Succeeded)],
                    offer.clone(),
                ),
            ),
            (
                200,
                job_json(
                    JobState::Running,
                    &awaiting(JobStepState::Failed),
                    offer.clone(),
                ),
            ),
            (
                200,
                job_json(
                    JobState::Failed,
                    &awaiting(JobStepState::Pending),
                    offer.clone(),
                ),
            ),
            (
                200,
                job_json(
                    JobState::Running,
                    &awaiting(JobStepState::Pending),
                    json!({}),
                ),
            ),
            (
                200,
                job_json(JobState::Running, &awaiting(JobStepState::Pending), offer),
            ),
        ])
        .await;
        let timeout = Duration::from_secs(30);
        for _ in 0..2 {
            assert!(
                wait_for_restore_offer(&api, Uuid::nil(), interval, timeout)
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        let expired = wait_for_restore_offer(&api, Uuid::nil(), interval, timeout)
            .await
            .unwrap_err();
        assert!(expired.to_string().contains("expired"), "{expired:#}");
        let failed = wait_for_restore_offer(&api, Uuid::nil(), interval, timeout)
            .await
            .unwrap_err();
        assert!(failed.to_string().contains("ended failed"), "{failed:#}");
        let offered = wait_for_restore_offer(&api, Uuid::nil(), interval, timeout)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            offered.destination_key_fingerprint,
            URL_SAFE_NO_PAD.encode([2_u8; 32])
        );
    }

    /// A hosted restore that stops waiting for the destination's key offer
    /// after the backend accepted its job names the job in the `--json`
    /// error, which a script can follow or resume, as the text says to.
    #[tokio::test]
    async fn a_failure_after_the_job_was_accepted_names_the_job() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let recovery = keys::recovery_key_pair(&keys::load_seed(&seed).unwrap()).unwrap();
        let (backup_id, source, job_id) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let mut backup = backup_json(backup_id, source, "gigahost_s3", "available");
        backup["recipient_key_fingerprint"] = json!(URL_SAFE_NO_PAD.encode(recovery.fingerprint));
        backup["wrapped_data_key"] = json!(keys::wrap_backup_data_key(
            &recovery,
            source,
            backup_id,
            &[23_u8; 32]
        ));
        let accepted = json!({"job_id": job_id, "resource_id": Uuid::now_v7(),
            "status_url": format!("/v1/jobs/{job_id}")});
        let waiting = job_json(
            JobState::Running,
            &[("await_restore_authorization", JobStepState::Pending)],
            json!({}),
        );
        let id = backup_id.to_string();
        let create = [
            "instance",
            "create",
            "--offering",
            "offering",
            "--backup",
            &id,
        ];
        let restore = ["backup", "restore", &id, "--yes"];
        for (command, resume) in [
            (&create[..], "resume this backup-based creation with"),
            (&restore[..], "resume this restore with"),
        ] {
            let (url, _) = canned_server(vec![
                (200, backup.to_string()),
                (202, accepted.to_string()),
                (200, waiting.clone()),
                (200, waiting.clone()),
            ])
            .await;
            let mut arguments = vec!["--compact"];
            arguments.extend_from_slice(command);
            arguments.extend_from_slice(&["--authorization-timeout-seconds", "1"]);
            arguments.extend_from_slice(&["--poll-seconds", "1"]);
            let error = execute(&account_command(&url, &seed, &arguments))
                .await
                .unwrap_err();
            let text = format!("{error:#}");
            assert!(text.starts_with(resume), "{text}");
            assert!(
                text.ends_with(
                    "timed out waiting for the destination hypervisor restore-key offer"
                ),
                "{text}"
            );
            assert_eq!(error_output(&error)["error"]["job_id"], json!(job_id));
        }
    }

    /// `--authorization-timeout-seconds` is a hard limit: an offer read
    /// after it is not taken, not even one that a read begun before it
    /// brought, and the waiting ends at it, not a poll interval later.
    #[tokio::test]
    async fn an_offer_read_after_the_authorization_timeout_is_not_taken() {
        let offer = json!({"prepare_restore_key": {
            "destination_public_key": URL_SAFE_NO_PAD.encode([1_u8; 32]),
            "destination_key_fingerprint": URL_SAFE_NO_PAD.encode([2_u8; 32]),
            "offer_expires_at": Utc::now() + chrono::Duration::minutes(10),
        }});
        let awaiting = [("await_restore_authorization", JobStepState::Pending)];
        let waiting = job_json(JobState::Running, &awaiting, json!({}));
        let offered = job_json(JobState::Running, &awaiting, offer);
        let timed_out = "timed out waiting for the destination hypervisor restore-key offer";
        let api = canned_api(vec![(200, offered.clone())]).await;
        let late = wait_for_restore_offer(&api, Uuid::nil(), Duration::ZERO, Duration::ZERO)
            .await
            .unwrap_err();
        assert_eq!(late.to_string(), timed_out);
        // The offer comes with the first read after the timeout, which a
        // poll interval of a minute does not put off.
        let api = canned_api(vec![(200, waiting), (200, offered.clone())]).await;
        let started = tokio::time::Instant::now();
        let late = wait_for_restore_offer(
            &api,
            Uuid::nil(),
            Duration::from_mins(1),
            Duration::from_millis(20),
        )
        .await
        .unwrap_err();
        assert_eq!(late.to_string(), timed_out);
        assert!(started.elapsed() < Duration::from_secs(30));
        // Within the timeout the offer is taken.
        let api = canned_api(vec![(200, offered)]).await;
        let taken =
            wait_for_restore_offer(&api, Uuid::nil(), Duration::ZERO, Duration::from_secs(30))
                .await
                .unwrap();
        assert!(taken.is_some());
    }

    #[test]
    fn command_line_definition_is_consistent() {
        Cli::command().debug_assert();
        command().debug_assert();
    }

    /// Every command and argument says what it is for. A command without
    /// its own doc comment would otherwise show the doc comment of an
    /// `Args` struct it flattens, or nothing.
    #[test]
    fn every_argument_and_command_has_help() {
        fn missing(command: &clap::Command, path: &str, found: &mut Vec<String>) {
            for argument in command.get_arguments() {
                let id = argument.get_id().as_str();
                if argument.get_help().is_none() && id != "help" && id != "version" {
                    found.push(format!("{path} {id}"));
                }
            }
            for subcommand in command.get_subcommands() {
                let path = format!("{path} {}", subcommand.get_name());
                if subcommand.get_about().is_none() {
                    found.push(path.clone());
                }
                missing(subcommand, &path, found);
            }
        }
        let mut found = Vec::new();
        missing(&command(), "ghost", &mut found);
        assert!(found.is_empty(), "no help text: {found:#?}");
    }

    /// Help names each option's environment variable without its value, set or not.
    #[test]
    fn the_main_help_shows_what_renters_use() {
        let help = command().render_help().to_string();
        assert!(help.contains("[env: GHOST_SEED_FILE]"), "{help}");
        assert!(help.contains("[env: GHOST_API_URL]"), "{help}");
        assert!(!help.contains("GHOST_SEED_FILE="), "{help}");
    }

    /// Library parsing describes only customer commands; dispatch is in the binary.
    #[test]
    fn unknown_commands_keep_the_ordinary_parser() {
        assert!(
            Cli::try_parse_from(["ghost", "example", "--help"])
                .is_err_and(|error| error.kind() == clap::error::ErrorKind::InvalidSubcommand)
        );
        assert!(command().find_subcommand("example").is_none());
    }

    /// `ghost instance list --sort price` sorts by the price an instance
    /// pays now, which its help says, with the limit the API holds it to.
    #[test]
    fn the_instance_list_s_price_sort_is_the_price_paid_now() {
        let mut cli = command();
        cli.build();
        let help = cli
            .find_subcommand_mut("instance")
            .and_then(|instance| instance.find_subcommand_mut("list"))
            .map(|list| list.render_long_help().to_string())
            .unwrap();
        let help = help.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(
            help.contains("the price a month the instance pays now"),
            "{help}"
        );
        assert!(
            help.contains(&format!(
                "for an account of at most {},{:03} current instances",
                gigahost_client_api::website::MAXIMUM_PRICE_SORTED_INSTANCES / 1000,
                gigahost_client_api::website::MAXIMUM_PRICE_SORTED_INSTANCES % 1000
            )),
            "{help}"
        );
        assert!(!help.contains("rented at"), "{help}");
    }

    /// A renter or provider never reads of a platform fee: the long help of
    /// every customer command names no fee besides the creation fee.
    #[test]
    fn renter_and_provider_help_names_no_platform_fee() {
        fn walk(command: &mut clap::Command, path: &str, found: &mut Vec<String>) {
            let help = command.render_long_help().to_string().to_lowercase();
            if help.replace("creation fee", "").contains("fee") {
                found.push(format!("{path}:\n{help}"));
            }
            for subcommand in command.get_subcommands_mut() {
                let path = format!("{path} {}", subcommand.get_name());
                walk(subcommand, &path, found);
            }
        }
        let mut found = Vec::new();
        let mut cli = command();
        cli.build();
        walk(&mut cli, "ghost", &mut found);
        assert!(found.is_empty(), "a fee in the help: {found:#?}");
    }

    /// A usage error shows what the command takes, not the options that
    /// were typed, and one of --image, --backup, --container and
    /// --stock-image as the choice it is: no source is guessed.
    #[test]
    fn usage_errors_show_what_the_command_takes() {
        let usage_error = |arguments: &[&str]| {
            let mut command = command();
            let error = command
                .try_get_matches_from_mut(arguments)
                .expect_err("a usage error");
            error.format(&mut command).render().to_string()
        };
        let create = usage_error(&[
            "ghost",
            "--api-url",
            "http://192.0.2.1",
            "--json",
            "instance",
            "create",
            "--offering",
            "o",
            "--wait",
        ]);
        assert!(
            create.contains(
                "Usage: ghost instance create [OPTIONS] --offering <OFFERING> <--image <IMAGE>|--backup <BACKUP_ID>|--container <IMAGE>|--stock-image <SLUG>>"
            ),
            "{create}"
        );
        assert!(!create.contains("--api-url"), "{create}");
        let both = usage_error(&[
            "ghost",
            "instance",
            "create",
            "--offering",
            "o",
            "--image",
            "debian-13",
            "--backup",
            "01a0e357-b7d1-7f53-9a72-5ffacde8735b",
        ]);
        assert!(both.contains("cannot be used with"), "{both}");
        for command in ["cancel", "delete", "restore"] {
            let usage = usage_error(&["ghost", "--api-url", "http://192.0.2.1", "backup", command]);
            assert!(
                usage.contains(&format!(
                    "Usage: ghost backup {command} [OPTIONS] <BACKUP_ID>\n"
                )),
                "{usage}"
            );
        }
    }

    /// Both spellings of a multi-word value are accepted, and help shows
    /// the one the API and catalog use.
    #[test]
    fn multi_word_values_take_the_catalog_spelling_and_the_old_one() {
        for tier in [
            "shared_bandwidth",
            "shared-bandwidth",
            "high_bandwidth",
            "high-bandwidth",
            "shared_ip",
            "shared-ip",
        ] {
            let cli = Cli::try_parse_from([
                "ghost",
                "instance",
                "create",
                "--offering",
                "o",
                "--image",
                "debian-13",
                "--gateway-tier",
                tier,
            ]);
            assert!(cli.is_ok(), "{tier}");
        }
        for mode in ["home_gateway", "cloud-routed"] {
            assert!(Cli::try_parse_from(["ghost", "catalog", "offerings", "--mode", mode]).is_ok());
        }
        let help = command()
            .find_subcommand_mut("instance")
            .and_then(|instance| instance.find_subcommand_mut("create"))
            .map(|create| create.render_help().to_string())
            .unwrap();
        assert!(
            help.contains("[possible values: shared_bandwidth, high_bandwidth, shared_ip]"),
            "{help}"
        );
    }

    #[test]
    fn the_version_is_the_release_recorded_next_to_the_installed_binary() {
        let prefix = tempfile::tempdir().unwrap();
        let executable = prefix.path().join("bin/ghost");
        let record = prefix.path().join("lib/gigahost/cli-release");
        assert_eq!(installed_release(&executable), None);
        fs::create_dir_all(record.parent().unwrap()).unwrap();
        fs::write(&record, "20260927T074123Z-3d98cd281141\n").unwrap();
        assert_eq!(
            installed_release(&executable).as_deref(),
            Some("20260927T074123Z-3d98cd281141")
        );
        for invalid in [
            "",
            "0.1.0",
            "20260927T074123Z-3D98CD281141",
            "20260927T074123Z-3d98cd28114",
        ] {
            fs::write(&record, invalid).unwrap();
            assert_eq!(installed_release(&executable), None, "{invalid:?}");
        }
    }

    /// Every request names this ghost and its release; a backend that no
    /// longer serves it answers 426 `client_release_unsupported`, whose
    /// message says what to install.
    #[tokio::test]
    async fn every_request_names_the_release_and_a_refusal_says_what_to_install() {
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        // A backend refuses a release, never a build that names none: this
        // stand-in answers as for an older release.
        let refusal = gigahost_client_api::support_window::ClientReleaseUnsupported::new(
            "ghost",
            Some("20260101T000000Z-0123456789ab"),
            "20260201T000000Z-0123456789ab",
            Some("20260301T120000Z-fedcba987654"),
            "curl -fsSL https://api.example/install/ghost.sh | sh",
        );
        let body = serde_json::to_string(&refusal).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).await.unwrap();
                assert_ne!(read, 0, "request ended inside its headers");
                request.extend_from_slice(&chunk[..read]);
            }
            let response = format!(
                "HTTP/1.1 426 Upgrade Required\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            let _ = stream.shutdown().await;
            String::from_utf8_lossy(&request).to_lowercase()
        });
        let identity = keys::authentication_identity(&[3_u8; 32]).unwrap();
        let api = ApiClient::new(&url, Some(identity)).unwrap();
        let error = api
            .read(&gigahost_client_api::api::GetAccountBalance, "")
            .await
            .unwrap_err();
        let head = server.await.unwrap();
        // A test build is installed from no release.
        assert_eq!(release(), "dev");
        assert!(head.contains("\r\nuser-agent: ghost/dev\r\n"), "{head}");
        assert!(
            head.contains("\r\nx-gigahost-client: ghost/dev\r\n"),
            "{head}"
        );
        assert!(
            error.to_string().contains("client_release_unsupported: this ghost is release 20260101T000000Z-0123456789ab, older than release 20260201T000000Z-0123456789ab")
                && error.to_string().contains("install release 20260301T120000Z-fedcba987654: curl -fsSL https://api.example/install/ghost.sh | sh"),
            "{error:#}"
        );
        assert!(!api::is_transient(&error));
    }

    /// `set-password` sends only the public key derived from the password
    /// it drew, for the account's alias; `--print` writes the password
    /// alone, one line of 16 characters, in any output format.
    #[test]
    fn set_password_sends_only_the_derived_key_and_print_writes_the_password_alone() {
        let parse =
            |arguments: &[&str]| Cli::try_parse_from(["ghost", "account"].iter().chain(arguments));
        assert!(parse(&["set-password"]).is_ok());
        assert!(parse(&["set-password", "--expires-in", "90", "--print"]).is_ok());
        for invalid in ["0", "3651", "-1", "soon"] {
            assert!(
                parse(&["set-password", "--expires-in", invalid]).is_err(),
                "{invalid}"
            );
        }
        assert!(parse(&["set-password", "hunter2"]).is_err(), "never chosen");
        assert!(parse(&["remove-password"]).is_ok());

        let (password, request) =
            website_password_request("gh-abcdefgh", Some(90), &mut rand_core::OsRng);
        assert!(website_password::is_well_formed(&password), "{password}");
        assert_eq!(request.expires_in_days, Some(90));
        assert_eq!(
            request.public_key,
            URL_SAFE_NO_PAD.encode(
                website_password::signing_key("gh-abcdefgh", &password)
                    .verifying_key()
                    .as_bytes()
            )
        );
        let sent = serde_json::to_string(&request).unwrap();
        assert!(!sent.contains(&password), "{sent}");
        let (other, _) = website_password_request("gh-abcdefgh", None, &mut rand_core::OsRng);
        assert_ne!(other, password);

        let output = json!({
            "account_alias": "gh-abcdefgh",
            "password": password,
            "created_at": "2026-10-12T10:00:00Z",
            "expires_at": null,
            "note": "The password is shown only this once.",
        });
        for format in [&[][..], &["--json"][..]] {
            let arguments: Vec<&str> = ["ghost"]
                .iter()
                .chain(format)
                .chain(&["account", "set-password", "--print"])
                .copied()
                .collect();
            let cli = Cli::try_parse_from(arguments).unwrap();
            let printed = render_result(&cli, &output, Terminal::plain());
            assert_eq!(printed, password);
            assert_eq!(printed.lines().count(), 1);
            assert_eq!(printed.chars().count(), 16);
        }
        let cli = Cli::try_parse_from(["ghost", "account", "set-password"]).unwrap();
        let shown = render_result(&cli, &output, Terminal::plain());
        for part in [password.as_str(), "created_at"] {
            assert!(shown.contains(part), "{shown}");
        }
        // The note is not a row of the table: it follows on standard error.
        assert!(!shown.contains("shown only this once"), "{shown}");
        assert_eq!(
            result_hint_notes(&cli.command),
            [
                "note: the password is shown only this once.",
                "Keep it in a password manager."
            ]
        );
    }

    /// `account show` reads the password's times, and `account sessions`
    /// each session's origin.
    #[test]
    fn the_account_shows_its_password_and_its_sessions_their_origin() {
        let account = json!({
            "account_alias": "gh-abcdefgh",
            "deposit_memo": "memo000000000001",
            "key_epoch": 1,
            "status": "active",
            "website_password": {
                "created_at": "2026-10-12T10:00:00Z",
                "expires_at": "2027-01-10T10:00:00Z"
            },
        });
        let view: AccountView = serde_json::from_value(account.clone()).unwrap();
        assert!(view.website_password.is_some());
        let older: AccountView = serde_json::from_value(json!({
            "account_alias": "gh-abcdefgh",
            "deposit_memo": "memo000000000001",
            "key_epoch": 1,
            "status": "active",
        }))
        .unwrap();
        assert!(older.website_password.is_none(), "an older backend");
        let cli = Cli::try_parse_from(["ghost", "account", "show"]).unwrap();
        let shown = render_result(&cli, &account, Terminal::plain());
        for part in ["website_password", "created_at", "expires_at", "2027-01-10"] {
            assert!(shown.contains(part), "{shown}");
        }
        let sessions = json!([{
            "session_id": Uuid::nil(),
            "created_at": "2026-10-12T10:00:00Z",
            "expires_at": "2026-10-19T10:00:00Z",
            "last_used_at": null,
            "idle_expires_at": "2026-10-13T10:00:00Z",
            "auth_key_id": "devfixturekey001",
            "current": true,
            "origin": "password",
        }]);
        let cli = Cli::try_parse_from(["ghost", "account", "sessions"]).unwrap();
        let shown = render_result(&cli, &sessions, Terminal::plain());
        assert!(shown.contains("password"), "{shown}");
        let mut older = sessions[0].clone();
        older.as_object_mut().unwrap().remove("origin");
        let older: ActiveSessionView = serde_json::from_value(older).unwrap();
        assert_eq!(older.origin, "link", "a backend older than the password");
    }

    #[test]
    fn a_payout_goes_to_the_address_set_by_its_own_command() {
        let parse =
            |arguments: &[&str]| Cli::try_parse_from(["ghost", "provider"].iter().chain(arguments));
        assert!(parse(&["set-payout-address", "mmx1address"]).is_ok());
        assert!(parse(&["payout", "--amount-microusd", "1000000"]).is_ok());
        assert!(parse(&["payout", "--net-microusd", "1000000"]).is_err());
        assert!(parse(&["payout", "--destination", "mmx1address"]).is_err());
    }

    #[test]
    fn the_protected_balance_is_set_in_dollars() {
        assert_eq!(parse_usd("5"), Ok(5_000_000));
        assert_eq!(parse_usd("2.50"), Ok(2_500_000));
        assert_eq!(parse_usd("$1"), Ok(1_000_000));
        assert_eq!(parse_usd("0.000001"), Ok(1));
        assert_eq!(parse_usd("10000"), Ok(10_000_000_000));
        for invalid in [
            "",
            "five",
            "-1",
            "1.",
            ".5",
            "1.0000001",
            "1,50",
            "1e3",
            "1234567890",
        ] {
            assert!(parse_usd(invalid).is_err(), "{invalid}");
        }
        let parse = |arguments: &[&str]| {
            Cli::try_parse_from(["ghost", "account", "protection"].iter().chain(arguments))
        };
        let Ok(Cli {
            command:
                Command::Account {
                    command:
                        AccountCommand::Protection {
                            command: ProtectionCommand::Set { usd },
                        },
                },
            ..
        }) = parse(&["set", "2.50"])
        else {
            panic!("not a protection set");
        };
        assert_eq!(usd, 2_500_000);
        assert!(matches!(
            parse(&["default"]),
            Ok(Cli {
                command: Command::Account {
                    command: AccountCommand::Protection {
                        command: ProtectionCommand::Default
                    }
                },
                ..
            })
        ));
        assert!(parse(&["set", "lots"]).is_err());
        assert!(parse(&["set"]).is_err());
    }

    #[test]
    fn every_idempotency_key_argument_is_validated() {
        assert!(parse_idempotency_key("0123456789abcdef").is_ok());
        for invalid in [
            "too-short",
            &"k".repeat(129),
            "0123456789 abcdef",
            "0123456789abcdé",
            "0123456789abcdef\u{1b}",
        ] {
            assert!(parse_idempotency_key(invalid).is_err(), "{invalid:?}");
        }
        let host = Uuid::nil().to_string();
        let set_pricing = |key: &str| {
            Cli::try_parse_from([
                "ghost",
                "provider",
                "set-pricing",
                &host,
                "--expected-revision",
                "1",
                "--file",
                "pricing.json",
                "--reason",
                "test",
                "--idempotency-key",
                key,
            ])
        };
        assert!(set_pricing("too-short").is_err());
        assert!(set_pricing("0123456789abcdef").is_ok());
        // Signing earlier prices only makes sense for a retry with its key.
        assert!(
            Cli::try_parse_from([
                "ghost",
                "backup",
                "create",
                &host,
                "--destination",
                "hosted",
                "--pricing-revision",
                "1",
                "--maximum-charge-microusd",
                "2",
            ])
            .is_err()
        );
    }

    #[test]
    fn image_installs_accept_keys_or_cloud_init() {
        let key = [TEST_PUBLIC_KEY.to_owned()];
        let file = Path::new("user-data.yaml");
        assert!(login_material(&key, None, 0).is_ok());
        assert!(login_material(&[], Some((file, "#cloud-config\nusers: []\n")), 0).is_ok());
        assert!(login_material(&[], None, 0).is_err());
        // The account's saved keys count, with a note that they go in, and
        // the warning about a cloud-config without a login is spared.
        assert!(
            login_material(&[], None, 2)
                .expect("saved keys")
                .is_some_and(|note| note.starts_with("Installing the 2 SSH keys saved"))
        );
        assert_eq!(
            login_material(&[], Some((file, "#cloud-config\nusers: []\n")), 1).expect("user data"),
            None
        );
        // A #cloud-config without a key or password is allowed, with a warning.
        assert!(!cloud_config_grants_login(
            "#cloud-config\npackages: [nginx]\n"
        ));
        assert!(cloud_config_grants_login(
            "#cloud-config\nusers:\n  - name: ops\n    ssh_authorized_keys: [ssh-ed25519 AAAA]\n"
        ));
        assert!(cloud_config_grants_login(
            "#cloud-config\nchpasswd: {expire: false}\n"
        ));
        assert!(cloud_config_grants_login("#!/bin/sh\necho hello\n"));
        assert!(!cloud_config_grants_login(" #Cloud-Config\npackages: []\n"));
        assert!(cloud_config_grants_login(
            "#cloud-config-jsonp\n[{\"op\": \"remove\", \"path\": \"/users\"}]\n"
        ));
    }

    /// An `ssh-keygen -t ed25519` public key.
    const TEST_PUBLIC_KEY: &str = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILmpbTJskXPcOuo9FieOY3V1tsruIFFVSnAeegTZQFKy test@example";

    #[test]
    fn only_openssh_public_keys_are_taken_from_key_files() {
        let directory = tempfile::tempdir().unwrap();
        let file = |name: &str, contents: &str| {
            let path = directory.path().join(name);
            fs::write(&path, contents).unwrap();
            path
        };
        let good = file(
            "authorized_keys",
            &format!("# laptop\n\n{TEST_PUBLIC_KEY}\n  {TEST_PUBLIC_KEY}  \n"),
        );
        assert_eq!(
            load_ssh_keys(&[], &[good]).unwrap(),
            [TEST_PUBLIC_KEY, TEST_PUBLIC_KEY]
        );
        assert_eq!(
            load_ssh_keys(&[format!(" {TEST_PUBLIC_KEY} "), String::new()], &[]).unwrap(),
            [TEST_PUBLIC_KEY]
        );

        // A private key is refused, and its .pub file suggested when it exists.
        let secret = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW";
        let private = file(
            "id_ed25519",
            &format!(
                "-----BEGIN OPENSSH PRIVATE KEY-----\n{secret}\n-----END OPENSSH PRIVATE KEY-----\n"
            ),
        );
        let error = load_ssh_keys(&[], std::slice::from_ref(&private)).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("holds a private key"), "{message}");
        assert!(message.contains("same name with .pub"), "{message}");
        assert!(!message.contains(secret), "{message}");
        file("id_ed25519.pub", TEST_PUBLIC_KEY);
        let message = format!("{:#}", load_ssh_keys(&[], &[private]).unwrap_err());
        assert!(message.contains("id_ed25519.pub instead"), "{message}");
        for armor in [
            "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY-----\n",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIIE\n",
            "PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: none\n",
        ] {
            let path = file("key", armor);
            let message = format!("{:#}", load_ssh_keys(&[], &[path]).unwrap_err());
            assert!(message.contains("holds a private key"), "{message}");
        }
        let error = load_ssh_keys(&["-----BEGIN OPENSSH PRIVATE KEY-----".to_owned()], &[]);
        assert!(format!("{:#}", error.unwrap_err()).contains("--ssh-key 1 is a private key"));

        // Any other line is refused by its number, without its content.
        let other = file(
            "mixed",
            &format!("{TEST_PUBLIC_KEY}\nsecret-looking-line\n"),
        );
        let message = format!("{:#}", load_ssh_keys(&[], &[other]).unwrap_err());
        assert!(
            message.contains("line 2 is not an OpenSSH public key"),
            "{message}"
        );
        assert!(!message.contains("secret-looking-line"), "{message}");
        let options = file(
            "options",
            &format!("from=\"192.0.2.1\" {TEST_PUBLIC_KEY}\n"),
        );
        let message = format!("{:#}", load_ssh_keys(&[], &[options]).unwrap_err());
        assert!(message.contains("options before the key type"), "{message}");
        // Types OpenSSH knows but a guest is not given are named as such.
        let certificate = file(
            "id_ed25519-cert.pub",
            "ssh-ed25519-cert-v01@openssh.com AAAAIHNzaC1lZDI1NTE5LWNlcnQ= test\n",
        );
        let message = format!("{:#}", load_ssh_keys(&[], &[certificate]).unwrap_err());
        assert!(
            message.contains(
                "ssh-ed25519-cert-v01@openssh.com keys are not accepted, only ssh-ed25519, ssh-rsa,"
            ),
            "{message}"
        );
        let message = format!(
            "{:#}",
            load_ssh_keys(&["ssh-dss AAAAB3NzaC1kc3M= test".to_owned()], &[]).unwrap_err()
        );
        assert!(
            message.contains("ssh-dss keys are not accepted"),
            "{message}"
        );
        let empty = file("empty.pub", "\n# nothing\n");
        let message = format!("{:#}", load_ssh_keys(&[], &[empty]).unwrap_err());
        assert!(message.contains("holds no SSH public key"), "{message}");
        let path = file("literal.pub", TEST_PUBLIC_KEY);
        let message = format!(
            "{:#}",
            load_ssh_keys(&[path.display().to_string()], &[]).unwrap_err()
        );
        assert!(message.contains("use --ssh-key-file"), "{message}");
        let message = format!(
            "{:#}",
            load_ssh_keys(&[], &[directory.path().join("absent.pub")]).unwrap_err()
        );
        assert!(
            message.starts_with("cannot read --ssh-key-file "),
            "{message}"
        );
        let too_many = vec![TEST_PUBLIC_KEY.to_owned(); MAX_SSH_PUBLIC_KEYS + 1];
        assert!(load_ssh_keys(&too_many, &[]).is_err());
    }

    /// A private key given by mistake, in a file or as a literal, is refused
    /// before any request. The server here records the first request it is
    /// sent, and each case checks that none was, so one answer is enough.
    #[tokio::test]
    async fn a_private_key_never_reaches_the_server() {
        let directory = tempfile::tempdir().unwrap();
        let armor = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjE=\n-----END OPENSSH PRIVATE KEY-----\n";
        let private = directory.path().join("id_ed25519");
        fs::write(&private, armor).unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let (url, received) = canned_server(vec![(500, "{}".to_owned())]).await;
        let given = [
            (
                "--ssh-key-file",
                private.to_str().unwrap(),
                "holds a private key",
            ),
            ("--ssh-key", armor, "is a private key"),
            (
                "--ssh-key",
                armor.lines().nth(1).unwrap(),
                "is not an OpenSSH public key",
            ),
        ];
        // `--ssh-key "$(cat id_ed25519)"` passes armor, which starts with
        // dashes, as its own argument; `=` joins it to the option.
        for command in ["create", "reinstall"] {
            for ((argument, value, refusal), joined) in given
                .into_iter()
                .flat_map(|case| [(case, false), (case, true)])
            {
                let mut arguments = vec![
                    "ghost",
                    "--api-url",
                    &url,
                    "--seed-file",
                    seed.to_str().unwrap(),
                    "instance",
                    command,
                ];
                if command == "reinstall" {
                    arguments.extend(["01a0e357-b7d1-7f53-9a72-5ffacde8735b", "--yes"]);
                } else {
                    arguments.extend(["--offering", "o"]);
                }
                arguments.extend(["--image", "debian-13", "--ssh-key", TEST_PUBLIC_KEY]);
                let option = format!("{argument}={value}");
                if joined {
                    arguments.push(&option);
                } else {
                    arguments.extend([argument, value]);
                }
                let error = execute(&Cli::try_parse_from(arguments).unwrap())
                    .await
                    .unwrap_err();
                assert!(
                    received.lock().unwrap().is_empty(),
                    "{command} {argument} sent a request"
                );
                let message = format!("{error:#}");
                assert!(message.contains(refusal), "{message}");
                assert!(!message.contains("BEGIN OPENSSH"), "{message}");
                assert!(!message.contains("b3BlbnNz"), "{message}");
            }
        }
    }

    #[test]
    fn user_data_is_checked_before_it_is_sent() {
        for accepted in [
            "#cloud-config\npackages: [nginx]\n",
            "#cloud-config\n",
            "#cloud-config-archive\n- type: text/cloud-config\n  content: 'packages: []'\n",
            "#!/bin/sh\necho hello\n",
            "Content-Type: multipart/mixed; boundary=\"b\"\nMIME-Version: 1.0\n\n--b--\n",
            "#include\nhttps://example.com/user-data\n",
            "## template: jinja\n#cloud-config\nhostname: {{ v1.local_hostname }}\n",
            "#cloud-config-jsonp\n[{\"op\": \"add\", \"path\": \"/packages/-\", \"value\": \"nginx\"}]\n",
            // cloud-init ignores case and leading whitespace.
            "\n  #Cloud-Config\npackages: [nginx]\n",
        ] {
            assert_eq!(check_user_data(accepted), Ok(()), "{accepted:?}");
        }
        for (rejected, problem) in [
            (" \n", "is empty"),
            (
                "This: is: not [valid yaml\n  - {",
                "is not cloud-init user data",
            ),
            ("packages: [nginx]\n", "make #cloud-config its first line"),
            (
                "#cloud-config\npackages: [nginx\n",
                "is not valid #cloud-config YAML",
            ),
            ("#cloud-config\n- nginx\n", "is not a #cloud-config mapping"),
            (
                "#cloud-config-archive\nkey: value\n",
                "is not a #cloud-config-archive list",
            ),
            (
                "#cloud-config-jsonp\npackages: [nginx]\n",
                "is not valid #cloud-config-jsonp JSON",
            ),
            (
                "#cloud-config-jsonp\n{\"op\": \"add\", \"path\": \"/packages/-\"}\n",
                "is not a #cloud-config-jsonp JSON Patch",
            ),
            (
                "Content-Type: multipart/mixed; boundary=\"b\"\n\n--b--\n",
                "also needs a MIME-Version: 1.0 header",
            ),
        ] {
            let error = check_user_data(rejected).unwrap_err();
            assert!(error.contains(problem), "{rejected:?}: {error}");
        }
        let directory = tempfile::tempdir().unwrap();
        let missing = directory.path().join("missing.yaml");
        let os_error = fs::read_to_string(&missing).unwrap_err();
        assert_eq!(os_error.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(
            load_user_data(&missing).unwrap_err().to_string(),
            format!(
                "cannot read --cloud-init-file {}: {os_error}",
                missing.display()
            )
        );
        let invalid = directory.path().join("bad-cloud-init.yaml");
        fs::write(&invalid, "#cloud-config\nruncmd: [\n").unwrap();
        let message = load_user_data(&invalid).unwrap_err().to_string();
        assert!(
            message.starts_with(&format!(
                "--cloud-init-file {} is not valid #cloud-config YAML: ",
                invalid.display()
            )),
            "{message}"
        );
    }

    /// A rejection is final, so it carries no retry hint, and so is a 429
    /// for a used-up quota; a server error, a timeout, or rate limiting
    /// does, and a key spent on another request says so.
    #[tokio::test]
    async fn only_failures_a_retry_may_cure_carry_a_retry_hint() {
        let key = IdempotencyArgs {
            idempotency_key: Some("0123456789abcdef".to_owned()),
        }
        .key();
        let error = |status: u16, code: &str| {
            (
                status,
                json!({"code": code, "message": "rejected"}).to_string(),
            )
        };
        let api = canned_api(vec![
            error(400, "invalid_request"),
            error(403, "forbidden"),
            error(404, "not_found"),
            error(409, "conflict"),
            error(429, "limit_reached"),
            error(429, "active_auth_key_limit"),
            error(429, "pending_host_enrollment_token_limit"),
            error(409, api::IDEMPOTENCY_KEY_REUSED),
            error(429, api::RATE_LIMITED),
            (429, "slow down".to_owned()),
            error(408, "request_timeout"),
            error(503, "gateway_unavailable"),
        ])
        .await;
        let mut messages = Vec::new();
        for _ in 0..12 {
            let error = api
                .write_retryable(&CreateLoginGrant, &(), &key)
                .await
                .unwrap_err();
            messages.push(format!("{error:#}"));
        }
        for message in &messages[..7] {
            assert!(message.starts_with("API returned 4"), "{message}");
            assert!(!message.contains("--idempotency-key"), "{message}");
        }
        assert!(
            messages[7].starts_with("this idempotency key was used before for a different request"),
            "{}",
            messages[7]
        );
        for message in &messages[8..] {
            assert!(
                message.starts_with(
                    "this exact mutation may be retried with --idempotency-key 0123456789abcdef: API returned"
                ),
                "{message}"
            );
        }
    }

    /// A conflict with a job still running on the resource names that job,
    /// so it can be followed before the command is repeated.
    #[tokio::test]
    async fn a_conflict_names_the_job_to_wait_for() {
        let key = IdempotencyArgs {
            idempotency_key: Some("0123456789abcdef".to_owned()),
        }
        .key();
        let job_id = Uuid::now_v7();
        let busy = format!(
            "instance i1 is busy: its creation is still running (job {job_id}); retry after that job finishes"
        );
        let api = canned_api(vec![(
            409,
            json!({"code": "operation_in_progress", "message": busy,
                "request_id": "r1", "job_id": job_id})
            .to_string(),
        )])
        .await;
        let error = api
            .write_retryable(&CreateLoginGrant, &(), &key)
            .await
            .unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            format!(
                "API returned 409 Conflict: operation_in_progress: {busy}; follow the job with `ghost job watch {job_id}` (request r1)"
            )
        );
    }

    /// With `--json`, a failure is an object a script reads the backend's
    /// code, the job to wait for and the request from, and a failure the
    /// backend did not answer or that happened here says so.
    #[tokio::test]
    async fn a_failure_is_a_json_object_for_scripts() {
        let key = IdempotencyArgs {
            idempotency_key: Some("0123456789abcdef".to_owned()),
        }
        .key();
        let job_id = Uuid::now_v7();
        let api = canned_api(vec![
            (
                409,
                json!({"code": "operation_in_progress", "message": "busy",
                    "request_id": "r1", "job_id": job_id})
                .to_string(),
            ),
            (502, "<html>bad gateway</html>".to_owned()),
        ])
        .await;
        let conflict = api
            .write_retryable(&CreateLoginGrant, &(), &key)
            .await
            .unwrap_err();
        assert_eq!(
            error_output(&conflict),
            json!({"error": {
                "code": "operation_in_progress",
                "message": format!("{conflict:#}"),
                "status": 409,
                "job_id": job_id,
                "request_id": "r1",
                "transient": false,
            }})
        );
        let gateway = api
            .write_retryable(&CreateLoginGrant, &(), &key)
            .await
            .unwrap_err();
        let output = error_output(&gateway);
        assert_eq!(output["error"]["code"], Value::Null);
        assert_eq!(output["error"]["status"], 502);
        assert_eq!(output["error"]["transient"], true);
        assert!(
            output["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with("this exact mutation may be retried with --idempotency-key"),
            "{output}"
        );

        let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", closed.local_addr().unwrap());
        drop(closed);
        let unanswered = ApiClient::new(&url, None)
            .unwrap()
            .write(
                &gigahost_client_api::api::RedeemLoginGrant,
                &gigahost_client_api::website::RedeemLoginGrantRequest {
                    token: "token".to_owned(),
                },
                None,
            )
            .await
            .unwrap_err();
        let output = error_output(&unanswered);
        assert_eq!(output["error"]["code"], NO_RESPONSE);
        assert_eq!(output["error"]["status"], Value::Null);
        assert_eq!(output["error"]["transient"], true);

        let local = anyhow::anyhow!("reinstall destroys the current root filesystem");
        assert_eq!(
            error_output(&local),
            json!({"error": {
                "code": null, "message": "reinstall destroys the current root filesystem",
                "status": null, "job_id": null, "request_id": null, "transient": false,
            }})
        );

        // What is refused here, as the backend would refuse it, has the
        // backend's code, and no status: nothing was sent.
        let backup_id = Uuid::now_v7();
        let uploading = backup_json(backup_id, Uuid::now_v7(), "gigahost_s3", "uploading");
        let refused =
            ensure_backup_available(&serde_json::from_value(uploading).unwrap(), "restored")
                .unwrap_err()
                .context("resume this restore with --idempotency-key 0123456789abcdef");
        assert_eq!(
            error_output(&refused),
            json!({"error": {
                "code": "backup_not_available", "message": format!("{refused:#}"),
                "status": null, "job_id": null, "request_id": null, "transient": false,
            }})
        );
    }

    /// A failure names the request the backend answered: by the ID its
    /// error body gives, or else the one its `x-request-id` header gives,
    /// which comes with an error of any body too.
    #[tokio::test]
    async fn a_failure_names_the_request_from_its_body_or_header() {
        let header = |id: &str| format!("x-request-id: {id}\r\n");
        let not_found = json!({"code": "not_found", "message": "resource not found"});
        let (url, _) = canned_server_with_headers(vec![
            (
                409,
                header("header-1"),
                json!({"code": "conflict", "message": "resource already exists",
                    "request_id": "body-1"})
                .to_string(),
            ),
            (404, header("header-2"), not_found.to_string()),
            (
                502,
                header("header-3"),
                "<html>bad gateway</html>".to_owned(),
            ),
            (404, String::new(), not_found.to_string()),
        ])
        .await;
        let api = ApiClient::new(&url, None)
            .unwrap()
            .with_read_retry_delays(&[]);
        let mut named = Vec::new();
        for _ in 0..4 {
            let error = api.read(&ListImages, "").await.unwrap_err();
            let output = error_output(&error);
            named.push((
                output["error"]["request_id"].clone(),
                output["error"]["message"].as_str().unwrap().to_owned(),
            ));
        }
        assert_eq!(
            named,
            [
                (
                    json!("body-1"),
                    "API returned 409 Conflict: conflict: resource already exists (request body-1)"
                        .to_owned()
                ),
                (
                    json!("header-2"),
                    "API returned 404 Not Found: not_found: resource not found (request header-2)"
                        .to_owned()
                ),
                (
                    json!("header-3"),
                    "API returned 502 Bad Gateway: <html>bad gateway</html> (request header-3)"
                        .to_owned()
                ),
                (
                    Value::Null,
                    "API returned 404 Not Found: not_found: resource not found".to_owned()
                ),
            ]
        );
    }

    /// Each refusal made before anything is sent, for what the backend
    /// refuses too, carries the code the backend refuses it with.
    #[tokio::test]
    async fn local_refusals_carry_the_backends_codes() {
        let code = |error: anyhow::Error| error_output(&error)["error"]["code"].clone();
        let mut backup: BackupView = serde_json::from_value(backup_json(
            Uuid::now_v7(),
            Uuid::now_v7(),
            "local",
            "queued",
        ))
        .unwrap();
        assert_eq!(
            code(ensure_backup_available(&backup, "restored").unwrap_err()),
            "backup_not_available"
        );
        backup.status = gigahost_client_api::website::BackupState::Available;
        backup.disk_bytes = Some(96 << 30);
        let (home, cloud) = (
            listed_offering(HostMode::HomeGateway),
            listed_offering(HostMode::CloudRouted),
        );
        let private_key = "-----BEGIN OPENSSH PRIVATE KEY-----".to_owned();
        let too_many = vec![TEST_PUBLIC_KEY.to_owned(); MAX_SSH_PUBLIC_KEYS + 1];
        let retire = |command: &[&str]| {
            let mut arguments = vec!["ghost", "--api-url", "http://192.0.2.1/", "provider"];
            arguments.extend_from_slice(command);
            arguments.extend_from_slice(&["--notice-days", "3", "--yes"]);
            Cli::try_parse_from(arguments).unwrap()
        };
        let id = Uuid::nil().to_string();
        for refused in [
            check_rental(&home, None, None).unwrap_err(),
            check_rental(&cloud, Some(GatewayTier::SharedBandwidth), None).unwrap_err(),
            check_rental(&cloud, None, Some(&backup)).unwrap_err(),
            load_ssh_keys(&["not a key".to_owned()], &[]).unwrap_err(),
            load_ssh_keys(&[private_key], &[]).unwrap_err(),
            load_ssh_keys(&too_many, &[]).unwrap_err(),
            login_material(&[], None, 0).unwrap_err(),
            execute(&retire(&["host", "retire", &id]))
                .await
                .unwrap_err(),
            execute(&retire(&["retire-instance", &id]))
                .await
                .unwrap_err(),
        ] {
            assert_eq!(code(refused), "invalid_request");
        }
        assert_eq!(
            code(check_offering_id("../account").unwrap_err()),
            "invalid_offering_token"
        );
        // A website request that expired before it was approved.
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let intent_id = Uuid::now_v7();
        let expired = gigahost_client_api::website::BrowserOperationView {
            intent_id,
            operation: gigahost_client_api::website::BrowserOperation::RestoreBackup {
                instance_id: Uuid::nil(),
                backup_id: Uuid::nil(),
            },
            expires_at: Utc::now() - chrono::Duration::minutes(1),
            started_job_id: None,
            completed_job_id: None,
            refusal: None,
        };
        let (url, _) = canned_server(vec![(200, serde_json::to_string(&expired).unwrap())]).await;
        let id = intent_id.to_string();
        let approve = account_command(&url, &seed, &["account", "approve", &id, "--yes"]);
        assert_eq!(
            code(execute(&approve).await.unwrap_err()),
            "invalid_request"
        );
        // A file that cannot be read is no refusal of the backend's.
        let missing = [PathBuf::from("/nonexistent/id_ed25519.pub")];
        assert_eq!(code(load_ssh_keys(&[], &missing).unwrap_err()), Value::Null);
    }

    /// A paid mutation answered with a job made before the request was
    /// sent repeats an earlier request with the same idempotency key; one
    /// the request made, even slowly, does not.
    #[tokio::test]
    async fn an_answer_with_an_earlier_job_is_a_replay() {
        let now = Utc::now();
        let job = |at: DateTime<Utc>| {
            Uuid::new_v7(uuid::Timestamp::from_unix(
                uuid::NoContext,
                u64::try_from(at.timestamp()).unwrap(),
                at.timestamp_subsec_nanos(),
            ))
        };
        let answered = |job_id, server_date, elapsed| Answered {
            value: JobAccepted {
                job_id,
                resource_id: Uuid::nil(),
                status_url: String::new(),
            },
            server_date,
            elapsed,
        };
        let earlier = now - chrono::Duration::minutes(3);
        let replayed = replayed_job(&answered(job(earlier), Some(now), Duration::from_secs(1)));
        assert_eq!(
            replayed.map(|created| created.timestamp_millis()),
            Some(earlier.timestamp_millis())
        );
        let date = DateTime::from_timestamp(now.timestamp(), 0).unwrap();
        let slow = now - chrono::Duration::seconds(5);
        for (job_id, server_date) in [
            (job(slow), Some(date)),
            (job(earlier), None),
            (Uuid::nil(), Some(now)),
        ] {
            let elapsed = Duration::from_secs(6);
            assert_eq!(replayed_job(&answered(job_id, server_date, elapsed)), None);
        }

        // The server's date comes with the answer.
        let key = IdempotencyArgs {
            idempotency_key: Some("0123456789abcdef".to_owned()),
        }
        .key();
        let grant = json!({"login_url": "https://example.test/login", "expires_at": now});
        let api = canned_api(vec![(200, grant.to_string())]).await;
        let answered = api
            .write_retryable_answered(&CreateLoginGrant, &(), &key)
            .await
            .unwrap();
        let date = answered.server_date.unwrap();
        assert!((date - now).num_seconds().abs() < 5, "{date}");
    }

    #[tokio::test]
    async fn retry_hints_name_only_what_the_command_accepts() {
        let key = IdempotencyArgs {
            idempotency_key: Some("0123456789abcdef".to_owned()),
        };
        let api = canned_api(vec![(500, "boom".to_owned()), (500, "boom".to_owned())]).await;
        // A key the command derived itself cannot be passed back.
        let internal = api
            .write(&CreateLoginGrant, &(), Some("0123456789abcdef"))
            .await
            .err()
            .unwrap();
        assert!(!format!("{internal:#}").contains("--idempotency-key"));
        let retryable = api
            .write_retryable(&CreateLoginGrant, &(), &key.key())
            .await
            .err()
            .unwrap();
        assert_eq!(
            retryable.to_string(),
            "this exact mutation may be retried with --idempotency-key 0123456789abcdef"
        );

        let id = Uuid::now_v7();
        let approval = MutationArgs {
            idempotency: key,
            wait: false,
            poll_seconds: 2,
            browser_intent: Some(id),
        };
        assert_eq!(approval.key().key, format!("browser-intent-{id}"));
        assert_eq!(
            approval.key().retry,
            format!("`ghost account approve {id} --yes`")
        );
    }

    #[tokio::test]
    async fn backup_create_retry_hint_reproduces_the_signed_request() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let seed = seed.to_str().unwrap().to_owned();
        let instance_id = Uuid::now_v7();
        let instance = InstanceView {
            kind: gigahost_client_api::website::InstanceKind::Vm,
            container: None,
            instance_id,
            offering_id: "offering".to_owned(),
            restored_from_backup_id: None,
            hostname: "vm".to_owned(),
            tags: Vec::new(),
            redundant_tags: Vec::new(),
            name: "vm".to_owned(),
            root_disk_bytes: 10 << 30,
            state: gigahost_client_api::website::InstanceState::Running,
            desired_power_state: PowerState::Running,
            holds_capacity: true,
            public_ipv4: None,
            gateway_tier: None,
            gateway_location: None,
            gateway_change_free: false,
            port_forwards: Vec::new(),
            outgoing_ports: None,
            network_microusd_per_tib: 0,
            outgoing_mail_allowed: false,
            created_at: Utc::now(),
            billing_started_at: None,
            billing_ended_at: None,
            deleted_at: None,
            balance_reservation_microusd: 0,
            provider_termination: None,
            pricing: None,
            image: None,
            provider_id: None,
            provider_name: String::new(),
            host_mode: None,
            location: String::new(),
            location_name: String::new(),
            country_code: String::new(),
            cpu_tier: None,
            vcpu_count: 1,
            memory_bytes: 1 << 30,
            firmware: None,
            active_job: None,
            last_restore: None,
            backup_limits: None,
            guest_initialization: None,
            bandwidth: None,
            sla: None,
            hold: None,
            access_reset: None,
            rescue: None,
        };
        let pricing = BackupPricingView {
            pricing_revision: 7,
            hosted: gigahost_client_api::website::BackupPrices {
                creation_charge_microusd_per_gib: 20_000,
                restore_charge_microusd_per_gib: 20_000,
                storage_charge_microusd_per_gib_month: 30_000,
            },
            local: gigahost_client_api::website::BackupPrices {
                creation_charge_microusd_per_gib: 2_000,
                restore_charge_microusd_per_gib: 2_000,
                storage_charge_microusd_per_gib_month: 10_000,
            },
            billing_unit_bytes: gigahost_client_api::website::BACKUP_BILLING_UNIT_BYTES,
            balance_margin_microusd: 1_000_000,
        };
        let (first_url, first_requests) = canned_server(vec![
            (200, serde_json::to_string(&instance).unwrap()),
            (200, serde_json::to_string(&pricing).unwrap()),
            (503, "try again later".to_owned()),
        ])
        .await;
        let instance = instance_id.to_string();
        let command = |url: &str, retry: &[&str]| {
            let mut arguments = vec![
                "ghost",
                "--api-url",
                url,
                "--seed-file",
                &seed,
                "backup",
                "create",
                &instance,
                "--destination",
                "hosted",
            ];
            arguments.extend_from_slice(retry);
            Cli::try_parse_from(arguments).unwrap()
        };
        let error = execute(&command(
            &first_url,
            &["--idempotency-key", "backup-retry-key-0001"],
        ))
        .await
        .unwrap_err();
        let hint = error.to_string();
        let retry = hint
            .strip_prefix("this exact mutation may be retried with ")
            .unwrap();
        // The most a backup costs is one as large as its volume: 10 GiB at
        // the hosted price.
        assert_eq!(
            retry,
            "--idempotency-key backup-retry-key-0001 --pricing-revision 7 --maximum-charge-microusd 200000"
        );

        // Prices changed since, but the retry signs the first attempt's.
        let job_id = Uuid::now_v7();
        let accepted = JobAccepted {
            job_id,
            resource_id: instance_id,
            status_url: format!("/v1/jobs/{job_id}"),
        };
        let (second_url, second_requests) =
            canned_server(vec![(202, serde_json::to_string(&accepted).unwrap())]).await;
        let retry = retry.split_whitespace().collect::<Vec<_>>();
        let result = execute(&command(&second_url, &retry)).await.unwrap();
        assert_eq!(result["job_id"], job_id.to_string());
        let first = first_requests.lock().unwrap();
        let second = second_requests.lock().unwrap();
        assert_eq!(second.len(), 1, "a retry reads no current prices");
        assert!(first[2].0.starts_with("POST "), "{}", first[2].0);
        assert_eq!(first[2].1, second[0].1, "the retried body is identical");
    }

    /// `ghost account approve` shows a website request without `--yes`,
    /// reports a completed one as it is, and refuses an expired one. A
    /// request whose job was already admitted, even after it expired, is
    /// completed with that job instead of admitting another.
    #[tokio::test]
    async fn approving_a_website_request_resumes_the_job_it_started() {
        use gigahost_client_api::website::{BackupState, BrowserOperation, BrowserOperationView};

        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let seed = seed.to_str().unwrap().to_owned();
        let id = Uuid::now_v7();
        let job_id = Uuid::now_v7();
        let backup_id = Uuid::now_v7();
        let intent = |expires_in_minutes, started_job_id, completed_job_id| {
            serde_json::to_string(&BrowserOperationView {
                intent_id: id,
                operation: BrowserOperation::RestoreBackup {
                    instance_id: Uuid::now_v7(),
                    backup_id,
                },
                expires_at: Utc::now() + chrono::Duration::minutes(expires_in_minutes),
                started_job_id,
                completed_job_id,
                refusal: None,
            })
            .unwrap()
        };
        let backup = |destination| {
            serde_json::to_string(&BackupView {
                backup_id,
                instance_id: Uuid::now_v7(),
                destination,
                status: BackupState::Restoring,
                purpose: gigahost_client_api::website::BackupPurpose::Regular,
                funding_lifecycle_id: None,
                size_bytes: Some(1 << 30),
                restore_pricing_revision: 1,
                restore_charge_microusd_per_gib: 10_000,
                storage_charge_microusd_per_gib_month: 20_000,
                storage_cost_microusd_per_month: Some(20_000),
                recipient_key_fingerprint: None,
                wrapped_data_key: None,
                created_at: Utc::now(),
                completed_at: Some(Utc::now()),
                host_id: None,
                location: None,
                disk_bytes: None,
                firmware: None,
                image_id: None,
                image_slug: None,
                image_name: None,
                hostname: None,
                instance_hostname: None,
                instance_name: None,
                instance_state: None,
                unavailable: None,
                lost_at: None,
                kind: InstanceKind::Vm,
                container: None,
                schedule: None,
            })
            .unwrap()
        };
        let approve = async |responses: Vec<(u16, String)>, yes: bool, flags: &[&str]| {
            let (url, received) = canned_server(responses).await;
            let intent_id = id.to_string();
            let mut arguments = vec!["ghost"];
            arguments.extend_from_slice(flags);
            arguments.extend([
                "--api-url",
                &url,
                "--seed-file",
                &seed,
                "account",
                "approve",
                &intent_id,
            ]);
            if yes {
                arguments.push("--yes");
            }
            let result = execute(&Cli::try_parse_from(arguments).unwrap()).await;
            let received = received.lock().unwrap().clone();
            (result, received)
        };

        // Without --yes the request is only shown, with what the restore
        // would cost and the instance it would replace, read by its name.
        let instance = serde_json::to_string(&json!({
            "instance_id": Uuid::nil(), "offering_id": "o", "hostname": "vm", "name": "web",
            "root_disk_bytes": 12_u64 << 30, "state": "running", "desired_power_state": "running",
            "holds_capacity": true, "network_microusd_per_tib": 0, "created_at": Utc::now(),
            "balance_reservation_microusd": 0,
        }))
        .unwrap();
        let (shown, received) = approve(
            vec![
                (200, intent(10, None, None)),
                (200, backup(BackupDestinationKind::Local)),
                (200, instance.clone()),
            ],
            false,
            &[],
        )
        .await;
        let shown = shown.unwrap();
        assert_eq!(shown["request"]["intent_id"], id.to_string());
        assert_eq!(
            shown["approve_command"],
            format!("ghost account approve {id} --yes")
        );
        assert_eq!(received.len(), 3, "the intent, the backup, the instance");
        // The quote is above the notice on the screen for reading.
        assert!(
            shown["notice"].as_str().unwrap().ends_with("shown above."),
            "{shown}"
        );
        // JSON is read by a program, which has no "above": the notice says
        // what is charged and keeps the advice to inspect the request.
        let (json_shown, _) = approve(
            vec![
                (200, intent(10, None, None)),
                (200, backup(BackupDestinationKind::Local)),
                (200, instance),
            ],
            false,
            &["--json"],
        )
        .await;
        let notice = json_shown.unwrap()["notice"].as_str().unwrap().to_owned();
        assert!(!notice.contains("above"), "{notice}");
        assert!(notice.contains("backup restore"), "{notice}");
        assert!(
            notice.contains("Inspect the requested resources"),
            "{notice}"
        );
        // --compact prints no quote, so its notice points at none and the
        // request is the only thing read.
        let (compact, received) =
            approve(vec![(200, intent(10, None, None))], false, &["--compact"]).await;
        let notice = compact.unwrap()["notice"].as_str().unwrap().to_owned();
        assert!(!notice.contains("above"), "{notice}");
        assert!(
            notice.contains("Inspect the requested resources"),
            "{notice}"
        );
        assert_eq!(received.len(), 1);

        // A completed request is reported as it is, and an expired one that
        // never started is refused, both without another request.
        let (completed, received) = approve(
            vec![(200, intent(10, Some(job_id), Some(job_id)))],
            true,
            &[],
        )
        .await;
        assert_eq!(completed.unwrap()["completed_job_id"], job_id.to_string());
        assert_eq!(received.len(), 1);
        let (expired, received) = approve(vec![(200, intent(-1, None, None))], true, &[]).await;
        let expired = expired.unwrap_err();
        assert!(expired.to_string().contains("expired"), "{expired:#}");
        assert_eq!(received.len(), 1);

        // A started restore of a local backup needs no key authorization:
        // the request is completed with the job it started.
        let (resumed, received) = approve(
            vec![
                (200, intent(-1, Some(job_id), None)),
                (
                    200,
                    job_json(
                        JobState::Running,
                        &[("restore_backup", JobStepState::Running)],
                        json!({}),
                    ),
                ),
                (200, backup(BackupDestinationKind::Local)),
                (200, intent(-1, Some(job_id), Some(job_id))),
            ],
            true,
            &[],
        )
        .await;
        assert_eq!(resumed.unwrap()["job_id"], job_id.to_string());
        let lines = received
            .iter()
            .map(|(line, _)| {
                line.split_whitespace()
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            lines,
            [
                format!("GET /v1/account/operation-intents/{id}"),
                format!("GET /v1/jobs/{job_id}"),
                format!("GET /v1/backups/{backup_id}"),
                format!("POST /api/mut/v1/account/operation-intents/{id}/complete"),
            ]
        );
        let completion: Value = serde_json::from_slice(&received[3].1).unwrap();
        assert_eq!(completion, json!({"job_id": job_id}));

        // A hosted restore that already finished needs no backup read either.
        let (finished, received) = approve(
            vec![
                (200, intent(10, Some(job_id), None)),
                (200, job_json(JobState::Succeeded, &[], json!({}))),
                (200, intent(10, Some(job_id), Some(job_id))),
            ],
            true,
            &[],
        )
        .await;
        assert_eq!(finished.unwrap()["job_id"], job_id.to_string());
        assert_eq!(received.len(), 3);
        assert!(received[2].0.starts_with("POST "), "{}", received[2].0);
    }

    /// Approving a website request to create an instance from a hosted
    /// backup, whose job already exists but still waits for the backup key,
    /// rewraps the key for the instance that job created and then completes
    /// the request.
    #[tokio::test]
    async fn approving_a_started_hosted_restore_authorizes_it_for_the_new_instance() {
        use gigahost_client_api::website::{
            BackupPurpose, BackupState, BrowserOperation, BrowserOperationView,
        };
        use hpke::{Kem as _, Serializable as _, kem::X25519HkdfSha256};

        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let recovery = keys::recovery_key_pair(&keys::load_seed(&seed).unwrap()).unwrap();
        let seed = seed.to_str().unwrap().to_owned();
        let (id, job_id, backup_id) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let (source_instance_id, new_instance_id) = (Uuid::now_v7(), Uuid::now_v7());
        let intent = |completed_job_id| {
            serde_json::to_string(&BrowserOperationView {
                intent_id: id,
                operation: BrowserOperation::CreateFromBackup {
                    offering_id: "test-offering".to_owned(),
                    backup_id,
                    gateway_tier: None,
                    hostname: None,
                    tags: None,
                    name: None,
                },
                expires_at: Utc::now() + chrono::Duration::minutes(10),
                started_job_id: Some(job_id),
                completed_job_id,
                refusal: None,
            })
            .unwrap()
        };
        // The creation job made the new instance and waits for the key.
        let job = |result| {
            let mut job: Value = serde_json::from_str(&job_json(
                JobState::Running,
                &[("await_restore_authorization", JobStepState::Pending)],
                result,
            ))
            .unwrap();
            job["job_id"] = json!(job_id);
            job["resource_id"] = json!(new_instance_id);
            job.to_string()
        };
        let (_, destination_public) = X25519HkdfSha256::derive_keypair(&[9_u8; 32]);
        let destination_public = destination_public.to_bytes();
        let destination_fingerprint = URL_SAFE_NO_PAD.encode(Sha256::digest(destination_public));
        let offer = json!({"prepare_restore_key": {
            "destination_public_key": URL_SAFE_NO_PAD.encode(destination_public),
            "destination_key_fingerprint": destination_fingerprint,
            "offer_expires_at": Utc::now() + chrono::Duration::minutes(10),
        }});
        let backup = serde_json::to_string(&BackupView {
            backup_id,
            instance_id: source_instance_id,
            destination: BackupDestinationKind::GigahostS3,
            status: BackupState::Available,
            purpose: BackupPurpose::Regular,
            funding_lifecycle_id: None,
            size_bytes: Some(1 << 30),
            restore_pricing_revision: 1,
            restore_charge_microusd_per_gib: 10_000,
            storage_charge_microusd_per_gib_month: 20_000,
            storage_cost_microusd_per_month: Some(20_000),
            recipient_key_fingerprint: Some(URL_SAFE_NO_PAD.encode(recovery.fingerprint)),
            wrapped_data_key: Some(keys::wrap_backup_data_key(
                &recovery,
                source_instance_id,
                backup_id,
                &[23_u8; 32],
            )),
            created_at: Utc::now(),
            completed_at: Some(Utc::now()),
            host_id: None,
            location: None,
            disk_bytes: None,
            firmware: None,
            image_id: None,
            image_slug: None,
            image_name: None,
            hostname: None,
            instance_hostname: None,
            instance_name: None,
            instance_state: None,
            unavailable: None,
            lost_at: None,
            kind: InstanceKind::Vm,
            container: None,
            schedule: None,
        })
        .unwrap();
        let accepted = json!({
            "job_id": job_id,
            "resource_id": new_instance_id,
            "status_url": format!("/v1/jobs/{job_id}"),
        });
        let (url, received) = canned_server(vec![
            (200, intent(None)),
            (200, job(json!({}))),
            (200, backup),
            (200, job(offer)),
            (200, accepted.to_string()),
            (200, intent(Some(job_id))),
        ])
        .await;
        let intent_id = id.to_string();
        let approved = execute(
            &Cli::try_parse_from([
                "ghost",
                "--api-url",
                &url,
                "--seed-file",
                &seed,
                "account",
                "approve",
                &intent_id,
                "--yes",
            ])
            .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(approved, accepted);

        let received = received.lock().unwrap().clone();
        let lines = received
            .iter()
            .map(|(line, _)| {
                line.split_whitespace()
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            lines,
            [
                format!("GET /v1/account/operation-intents/{id}"),
                format!("GET /v1/jobs/{job_id}"),
                format!("GET /v1/backups/{backup_id}"),
                format!("GET /v1/jobs/{job_id}"),
                format!(
                    "POST /api/mut/v1/instances/{new_instance_id}/backups/{backup_id}/restore/{job_id}/authorize"
                ),
                format!("POST /api/mut/v1/account/operation-intents/{id}/complete"),
            ]
        );
        let authorization: Value = serde_json::from_slice(&received[4].1).unwrap();
        assert_eq!(
            authorization["destination_key_fingerprint"],
            destination_fingerprint
        );
        let rewrapped = URL_SAFE_NO_PAD
            .decode(
                authorization["destination_wrapped_data_key"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
        assert_eq!(rewrapped.len(), 80);
        let completion: Value = serde_json::from_slice(&received[5].1).unwrap();
        assert_eq!(completion, json!({"job_id": job_id}));
    }

    #[tokio::test]
    async fn gateway_traffic_prints_the_instances_gateway_statistics() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let instance = Uuid::now_v7();
        let direction = |arrived: u64, delivered: u64, dropped: u64| {
            json!({
                "arrived_bytes": arrived * 1_000, "arrived_packets": arrived,
                "delivered_bytes": delivered * 1_000, "delivered_packets": delivered,
                "dropped_bytes": dropped * 1_000, "dropped_packets": dropped,
            })
        };
        let view = json!({
            "instance_id": instance,
            "observed_until": "2026-09-25T10:14:00Z",
            "last_hour": {
                "window_started_at": "2026-09-25T09:15:00Z",
                "window_ended_at": "2026-09-25T10:15:00Z",
                "inbound": direction(900, 100, 800),
                "outbound": direction(50, 50, 0),
                "inbound_tunnel_discarded_packets": 4,
            },
            "last_day": {
                "window_started_at": "2026-09-24T10:15:00Z",
                "window_ended_at": "2026-09-25T10:15:00Z",
                "inbound": direction(9_000, 1_000, 8_000),
                "outbound": direction(500, 490, 10),
                "inbound_tunnel_discarded_packets": 40,
            },
        });
        let (url, requests) = canned_server(vec![(200, view.to_string())]).await;
        let cli = Cli::try_parse_from([
            "ghost".as_ref(),
            "--api-url".as_ref(),
            url.as_ref(),
            "--seed-file".as_ref(),
            seed.as_os_str(),
            "instance".as_ref(),
            "gateway-traffic".as_ref(),
            instance.to_string().as_ref(),
        ])
        .unwrap();
        let output = execute(&cli).await.unwrap();
        assert_eq!(
            requests.lock().unwrap()[0].0,
            format!("GET /v1/instances/{instance}/gateway-traffic HTTP/1.1")
        );
        assert_eq!(output, view);
        let text = render_output(&output, OutputFormat::Json, Terminal::plain());
        assert!(
            text.contains("\"inbound_tunnel_discarded_packets\": 40"),
            "{text}"
        );
        assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), view);
    }

    /// A test account's command line against a canned server.
    fn account_command(url: &str, seed: &Path, arguments: &[&str]) -> Cli {
        let mut line = vec![
            "ghost",
            "--api-url",
            url,
            "--seed-file",
            seed.to_str().unwrap(),
        ];
        line.extend_from_slice(arguments);
        Cli::try_parse_from(line).unwrap()
    }

    #[tokio::test]
    async fn an_image_slug_is_resolved_through_the_catalog() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let debian = Uuid::now_v7();
        let images = json!([
            {"image_id": Uuid::now_v7(), "slug": "ubuntu-24.04", "display_name": "Ubuntu 24.04",
             "architecture": "x86_64", "minimum_disk_bytes": 1},
            {"image_id": debian, "slug": "debian-13", "display_name": "Debian 13",
             "architecture": "x86_64", "minimum_disk_bytes": 1},
        ]);
        let job_id = Uuid::now_v7();
        let accepted = json!({"job_id": job_id, "resource_id": Uuid::now_v7(),
            "status_url": format!("/v1/jobs/{job_id}")});
        let (url, received) = canned_server(vec![
            (200, images.to_string()),
            (
                404,
                json!({"code": "not_found", "message": "listed offering not found"}).to_string(),
            ),
            (202, accepted.to_string()),
            (200, images.to_string()),
        ])
        .await;
        let create = |image: &str| {
            account_command(
                &url,
                &seed,
                &[
                    "instance",
                    "create",
                    "--offering",
                    "o",
                    "--image",
                    image,
                    "--ssh-key",
                    TEST_PUBLIC_KEY,
                ],
            )
        };
        assert_eq!(
            execute(&create("debian-13")).await.unwrap()["job_id"],
            job_id.to_string()
        );
        let unknown = execute(&create("debian-99")).await.unwrap_err().to_string();
        assert_eq!(
            unknown,
            "--image debian-99 is not a catalog image; the catalog has debian-13, ubuntu-24.04"
        );
        let received = received.lock().unwrap().clone();
        assert!(
            received[0].0.starts_with("GET /v1/catalog/images "),
            "{}",
            received[0].0
        );
        let body: Value = serde_json::from_slice(&received[2].1).unwrap();
        assert_eq!(body["source"], json!({"kind": "image", "image_id": debian}));
        assert!(
            Cli::try_parse_from([
                "ghost",
                "instance",
                "create",
                "--offering",
                "o",
                "--image",
                "bad slug!"
            ])
            .is_err()
        );
    }

    /// Offerings as the catalog lists them, one of each host mode.
    fn listed_offering(host_mode: HostMode) -> OfferingView {
        serde_json::from_value(json!({
            "offering_id": "of2_J7hnuv_uO8PmXACeyas4QY",
            "provider_id": Uuid::nil(), "provider_name": "Example Hosting",
            "provider_alias": "gh-examples",
            "host_mode": host_mode, "location": "pl-warsaw", "location_name": "Warsaw",
            "country_code": "PL", "continent_code": "EU", "measured_latency_ms": null,
            "cpu_model": "Test CPU", "cpu_tier": "shared_1x", "vcpu_count": 1,
            "memory_bytes": 5_905_580_032_u64, "root_disk_bytes": 51_539_607_552_u64,
            "root_storage_backend": "lvm_thin", "software_raid_levels": [], "storage_devices": [],
            "base_price_microusd_per_month": 3_240_000,
            "full_utilization_price_microusd_per_month": 4_860_000,
            "network_prices": if host_mode == HostMode::HomeGateway {
                json!([
                    {"gateway_tier": "shared_bandwidth", "gateway_base_charge_microusd_per_month": 5_000_000,
                     "combined_microusd_per_tib": 10_240_000},
                    {"gateway_tier": "high_bandwidth", "gateway_base_charge_microusd_per_month": 15_000_000,
                     "combined_microusd_per_tib": 5_240_000},
                ])
            } else {
                json!([{"gateway_tier": null, "gateway_base_charge_microusd_per_month": 0,
                        "combined_microusd_per_tib": 240_000}])
            },
            "sla_target_basis_points": 9_900, "sla_credit_multiplier": 1, "available_hosts": 1,
            "available_instances": 12,
            "instance_creation_charge_microusd": 125_000,
            "balance_reservation_microusd": 7_000_000,
        }))
        .unwrap()
    }

    /// A home offering on a host that tells its memory's technology, whose
    /// shared gateway may be at either of two locations: its catalog
    /// prices the preselected one, Singapore.
    fn home_offering_with_locations() -> OfferingView {
        let mut offering = listed_offering(HostMode::HomeGateway);
        offering.cpu_model = "Intel(R) Xeon(R) CPU E5-2683 v4 @ 2.10GHz".to_owned();
        offering.hardware_profiles = serde_json::from_value(json!([{
            "memory_devices": [
                {"technology": "DDR4", "size_bytes": 34_359_738_368_u64, "configured_speed_mts": 2400},
                {"technology": "DDR4", "size_bytes": 34_359_738_368_u64, "configured_speed_mts": 2400},
            ],
            "pcie_devices": [],
        }]))
        .unwrap();
        offering.memory_profiles = offering
            .hardware_profiles
            .iter()
            .map(gigahost_client_api::website::MemoryProfile::of)
            .collect();
        offering.gateway_locations = serde_json::from_value(json!([
            {"location": "sg-singapore", "location_name": "Singapore", "country_code": "SG",
             "distance_km": 1427, "bottleneck": false, "preselected": true,
             "gateway_base_charge_microusd_per_month": 5_000_000,
             "gateway_network_microusd_per_tib": 10_000_000},
            {"location": "pl-warsaw", "location_name": "Warsaw, Poland", "country_code": "PL",
             "distance_km": 8090, "bottleneck": true, "preselected": false,
             "gateway_base_charge_microusd_per_month": 2_500_000,
             "gateway_network_microusd_per_tib": 3_000_000},
        ]))
        .unwrap();
        offering
    }

    /// The RAM column names the memory's technology from the summary the
    /// list has, and from the hardware profiles where an older backend
    /// sends no summary.
    #[test]
    fn an_offering_names_its_memory_technology_with_or_without_the_summary() {
        let listed = {
            let mut offering = home_offering_with_locations();
            offering.hardware_profiles.clear();
            offering
        };
        assert_eq!(memory_technology(&listed).as_deref(), Some("DDR4"));
        let older = {
            let mut offering = home_offering_with_locations();
            offering.memory_profiles.clear();
            offering
        };
        assert_eq!(memory_technology(&older).as_deref(), Some("DDR4"));
        let mut untold = older;
        untold.hardware_profiles.clear();
        assert_eq!(memory_technology(&untold), None);
    }

    /// `catalog offering` lists every gateway option of a home offering,
    /// a shared gateway at each location with the provider's traffic rate
    /// added to the location's, and the best network test readings with
    /// where they were taken, a `+` marking one at its server's limit.
    #[test]
    fn an_offering_shows_every_gateway_option_and_where_its_readings_were_taken() {
        let mut offering = serde_json::to_value(home_offering_with_locations()).unwrap();
        offering["network"] = json!({
            "best_download_bits_per_second": 1_000_000_000_u64, "best_download_at_limit": true,
            "best_download_location_name": "Frankfurt, Germany",
            "best_upload_bits_per_second": 89_600_000, "best_upload_at_limit": false,
            "best_upload_location_name": "Singapore",
            "lowest_latency_ms": 19, "lowest_latency_location_name": "Singapore",
            "measured_at": "2026-10-01T16:50:40Z",
        });
        let cli = Cli::try_parse_from(["ghost", "catalog", "offering", "o"]).unwrap();
        let text = render_result(&cli, &offering, Terminal::plain());
        let network = &text[text.find("  ==> network\n").expect("network")..];
        assert_eq!(
            network,
            "  ==> network
      upload       89.6 Mbit/s (Singapore)
      download     1 Gbit/s+ (Frankfurt, Germany)
      latency      19 ms (Singapore)
      measured_at  2026-10-01 16:50:40 UTC

  ==> network_prices
      GATEWAY_TIER      GATEWAY_LOCATION  LOCATION_NAME        DISTANCE  BOTTLENECK  BASE_PER_MONTH  TRAFFIC_PER_TIB
      shared bandwidth  sg-singapore      Singapore (default)  1427 km   no          $5.00           $10.24
      shared bandwidth  pl-warsaw         Warsaw, Poland       8090 km   yes         $2.50           $3.24
      high bandwidth    nearest region    -                    -         -           $15.00          $5.24"
        );
        assert!(!text.contains("gateway_locations"), "{text}");

        let cloud = serde_json::to_value(listed_offering(HostMode::CloudRouted)).unwrap();
        let text = render_result(&cli, &cloud, Terminal::plain());
        assert!(
            text.ends_with("  ==> network_prices\n      TRAFFIC_PER_TIB\n      $0.24"),
            "{text}"
        );
        assert!(text.contains("\n  network     "), "unmeasured: {text}");
    }

    /// `catalog network-test` shows each test server's upload before its
    /// download, a `+` for a reading at the server's limit, and not the
    /// server's name, which its location tells.
    #[test]
    fn network_tests_show_upload_first_and_limits_with_a_plus() {
        let host = Uuid::nil();
        let tests = json!({
            "host_id": host,
            "summary": {
                "best_download_bits_per_second": 940_700_000, "best_download_at_limit": true,
                "best_upload_bits_per_second": 941_600_000, "best_upload_at_limit": false,
                "lowest_latency_ms": 10, "measured_at": "2026-10-01T07:02:46Z",
            },
            "results": [{
                "server": "test-eu1", "server_name": "Frankfurt test server",
                "location": "de-frankfurt", "location_name": "Frankfurt, Germany",
                "observed_at": "2026-10-01T07:02:46Z", "latency_ms": 10,
                "download_bits_per_second": 940_700_000, "download_at_limit": true,
                "upload_bits_per_second": 941_600_000, "upload_at_limit": false,
            }],
        });
        let cli =
            Cli::try_parse_from(["ghost", "catalog", "network-test", &host.to_string()]).unwrap();
        assert_eq!(
            render_result(&cli, &tests, Terminal::plain()),
            format!(
                "  host_id     {host}

  ==> summary
      upload       941.6 Mbit/s
      download     940.7 Mbit/s+
      latency      10 ms
      measured_at  2026-10-01 07:02:46 UTC

  ==> results
      UPLOAD        DOWNLOAD       LATENCY  LOCATION      LOCATION_NAME       SERVER    OBSERVED_AT
      941.6 Mbit/s  940.7 Mbit/s+  10 ms    de-frankfurt  Frankfurt, Germany  test-eu1  2026-10-01 07:02:46 UTC"
            )
        );
        assert!(
            Cli::try_parse_from(["ghost", "catalog", "host-network-tests", &host.to_string()])
                .is_ok(),
            "the old name still works"
        );
    }

    /// `catalog provider` shows a provider's name, rating, reliability and
    /// what it lists, from its reliability, its reviews' summary and the
    /// catalog's offerings.
    #[tokio::test]
    async fn a_provider_is_shown_with_its_rating_reliability_and_offerings() {
        let provider = Uuid::nil();
        let reliability = json!({
            "provider_id": provider, "window_started_at": "2025-10-03T00:00:00Z",
            "window_ended_at": "2026-10-03T00:00:00Z", "observed_milliseconds": 4_334_400_000_u64,
            "online_milliseconds": 4_330_000_000_u64, "uptime_basis_points": 9_990,
            "distinct_rented_instances": 232, "abandoned_instances": 0,
            "abandonment_basis_points": 0,
        });
        let reviews = json!({"items": [], "next_cursor": null, "summary":
            {"rating_millistars": 3_111, "review_count": 8, "spend_bucket": "under_10_usd"}});
        let mut other = listed_offering(HostMode::CloudRouted);
        other.provider_id = Uuid::now_v7();
        other.location = "us-chicago".to_owned();
        let mut home = home_offering_with_locations();
        home.host_ids = vec![Uuid::nil()];
        let mut cloud = listed_offering(HostMode::CloudRouted);
        cloud.host_ids = vec![Uuid::nil(), Uuid::max()];
        let offerings = json!([home, cloud, other]);
        let (url, received) = canned_server(vec![
            (200, reliability.to_string()),
            (200, reviews.to_string()),
            (200, offerings.to_string()),
        ])
        .await;
        let cli = Cli::try_parse_from([
            "ghost",
            "--api-url",
            &url,
            "catalog",
            "provider",
            &provider.to_string(),
        ])
        .unwrap();
        let output = execute(&cli).await.unwrap();
        assert_eq!(
            render_result(&cli, &output, Terminal::plain()),
            format!(
                "  provider_id       {provider}
  name              Example Hosting
  alias             gh-examples
  host_modes        cloud_routed, home_gateway
  listed_hosts      2
  listed_offerings  2
  locations         pl-warsaw (Warsaw)
  rating            3.111 stars
  review_count      8

  ==> reliability
      abandoned_instances        0
      abandonment                0.00%
      distinct_rented_instances  232
      observed                   50d 4h
      online                     50d 2h
      uptime                     99.90%
      window_ended_at            2026-10-03 00:00:00 UTC
      window_started_at          2025-10-03 00:00:00 UTC"
            )
        );
        let mut requests = request_lines(&received);
        requests.sort();
        assert_eq!(
            requests,
            [
                format!("GET /v1/catalog/offerings?provider={provider}&ip=any&kind=any"),
                format!("GET /v1/catalog/providers/{provider}/reliability"),
                format!("GET /v1/catalog/providers/{provider}/reviews?limit=1"),
            ]
        );

        // A provider that is not active, which the catalog refuses to
        // filter by, lists nothing.
        let (url, _) = canned_server(vec![
            (200, reliability.to_string()),
            (200, reviews.to_string()),
            (
                400,
                json!({"code": "invalid_query", "message": "unknown provider"}).to_string(),
            ),
        ])
        .await;
        let cli = Cli::try_parse_from([
            "ghost",
            "--api-url",
            &url,
            "catalog",
            "provider",
            &provider.to_string(),
        ])
        .unwrap();
        let inactive = execute(&cli).await.unwrap();
        assert_eq!(inactive["listed_offerings"], 0, "{inactive}");

        // An alias is looked up among the offerings the catalog finds by
        // it; one that lists none cannot be shown.
        let mine = json!([home, cloud]);
        let (url, received) = canned_server(vec![
            (200, mine.to_string()),
            (200, reliability.to_string()),
            (200, reviews.to_string()),
            (200, "[]".to_owned()),
        ])
        .await;
        let by_alias = |alias: &str| {
            Cli::try_parse_from(["ghost", "--api-url", &url, "catalog", "provider", alias]).unwrap()
        };
        let cli = by_alias("GH-Examples");
        let shown = execute(&cli).await.unwrap();
        assert_eq!(shown, output);
        let error = execute(&by_alias("gh-otherxyz")).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "provider gh-otherxyz lists no offerings now; name it by its provider ID"
        );
        assert_eq!(
            request_lines(&received),
            [
                "GET /v1/catalog/offerings?provider=gh-examples&ip=any&kind=any".to_owned(),
                format!("GET /v1/catalog/providers/{provider}/reliability"),
                format!("GET /v1/catalog/providers/{provider}/reviews?limit=1"),
                "GET /v1/catalog/offerings?provider=gh-otherxyz&ip=any&kind=any".to_owned(),
            ]
        );
        assert!(Cli::try_parse_from(["ghost", "catalog", "provider", "gh-short"]).is_err());
    }

    /// `provider hosts` lists each host as the website's hosts table does:
    /// whether it takes rentals, when it was last seen, what it is and holds,
    /// and what it earns; retired hosts only with --retired, last.
    #[test]
    fn provider_hosts_are_a_table_like_the_websites() {
        let now: DateTime<Utc> = "2026-10-10T12:00:00Z".parse().unwrap();
        let host = |label: &str, mode: &str, status: &str| {
            json!({
                "host_id": Uuid::nil(), "label": label, "mode": mode, "status": status,
                "location": "pl-warsaw", "rentals_paused": false, "active_instance_count": 3,
                "can_retire": false, "retired_at": null, "retirement_notice": null,
                "public_path_verified_at": "2026-10-01T00:00:00Z", "public_path_error": null,
                "public_path_checking": false, "last_heartbeat_at": "2026-10-10T11:59:55Z",
                "cpu_model": "AMD Ryzen 9 7950X 16-Core Processor",
                "memory_bytes": 66_000_000_000_u64, "storage_bytes": 3_000_000_000_000_u64,
                "installed_memory_bytes": 68_719_476_736_u64,
                "installed_storage_bytes": 3_840_000_000_000_u64,
                "pricing": {"host_id": Uuid::nil(), "revision": 4,
                    "published_at": "2026-10-03T16:00:00Z",
                    "existing_instances_effective_at": "2027-01-01T00:00:00Z",
                    "values": {"fixed_instance_earnings_microusd_per_month": 0,
                        "base_host_earnings_microusd_per_month": 50_400_000,
                        "network_earnings_microusd_per_tib": if mode == "cloud_routed" { 5_000_000 } else { 0 },
                        "sla_target_basis_points": 9_999}},
            })
        };
        let mut paused = host("home-1", "home_gateway", "active");
        paused["rentals_paused"] = json!(true);
        paused["last_heartbeat_at"] = json!("2026-10-10T10:58:00Z");
        let mut new = host("new-1", "cloud_routed", "active");
        new["public_path_verified_at"] = json!(null);
        new["last_heartbeat_at"] = json!(null);
        new["pricing"] = json!(null);
        new["cpu_model"] = json!(null);
        new["installed_memory_bytes"] = json!(0);
        new["installed_storage_bytes"] = json!(0);
        new["memory_bytes"] = json!(0);
        new["storage_bytes"] = json!(0);
        let mut retired = host("old-1", "cloud_routed", "retired");
        retired["retired_at"] = json!("2026-09-01T00:00:00Z");
        let hosts: Vec<ProviderHostView> = serde_json::from_value(json!([
            host("cloud-1", "cloud_routed", "active"),
            paused,
            new,
            retired
        ]))
        .unwrap();
        let summary = Summary::provider_hosts(hosts.clone(), false, now);
        let text = pretty::render_rows(&summary.columns, &summary.rows, None, Terminal::plain());
        assert_eq!(
            words(&text),
            [
                vec![
                    "HOST_ID",
                    "LABEL",
                    "STATE",
                    "SEEN",
                    "TYPE",
                    "LOCATION",
                    "VMS",
                    "CPU",
                    "RAM",
                    "DISK",
                    "SLA",
                    "TRAFFIC_PER_TIB",
                    "HOST_PER_MONTH"
                ],
                vec![
                    "00000000-0000-0000-0000-000000000000",
                    "cloud-1",
                    "accepting",
                    "5s",
                    "ago",
                    "cloud",
                    "pl-warsaw",
                    "3",
                    "AMD",
                    "Ryzen",
                    "9",
                    "7950X",
                    "64",
                    "GiB",
                    "3.5",
                    "TiB",
                    "99.99%",
                    "$5.00",
                    "$50.40"
                ],
                vec![
                    "00000000-0000-0000-0000-000000000000",
                    "home-1",
                    "paused",
                    "1h",
                    "2m",
                    "ago",
                    "home",
                    "pl-warsaw",
                    "3",
                    "AMD",
                    "Ryzen",
                    "9",
                    "7950X",
                    "64",
                    "GiB",
                    "3.5",
                    "TiB",
                    "99.99%",
                    "-",
                    "$50.40"
                ],
                vec![
                    "00000000-0000-0000-0000-000000000000",
                    "new-1",
                    "unverified",
                    "-",
                    "cloud",
                    "pl-warsaw",
                    "3",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-",
                    "-"
                ],
            ]
        );
        assert_eq!(
            summary.note.as_deref(),
            Some("1 retired host not listed; --retired lists it")
        );
        let all = Summary::provider_hosts(hosts, true, now);
        assert_eq!(all.rows.len(), 4);
        assert_eq!(all.rows[3]["state"], "retired");
        assert_eq!(all.rows[3]["host_per_month"], Value::Null);
        assert!(all.note.is_none());
        assert!(Cli::try_parse_from(["ghost", "provider", "hosts", "--retired"]).is_ok());
    }

    /// `ghost provider host <HOST_ID>` shows the host; `get` still does,
    /// and the subcommands keep their host IDs.
    #[test]
    fn a_host_is_shown_without_get() {
        let parse = |arguments: &[&str]| {
            Cli::try_parse_from(["ghost", "provider", "host"].iter().chain(arguments))
        };
        let host = Uuid::nil().to_string();
        let Command::Provider {
            command:
                ProviderCommand::Host {
                    command: None,
                    host_id: Some(id),
                },
        } = parse(&[&host]).unwrap().command
        else {
            panic!("not the host alone");
        };
        assert_eq!(id, Uuid::nil());
        assert!(matches!(
            parse(&["get", &host]).unwrap().command,
            Command::Provider {
                command: ProviderCommand::Host {
                    command: Some(ProviderHostCommand::Get { .. }),
                    host_id: None,
                },
            }
        ));
        assert!(matches!(
            parse(&["pause", &host]).unwrap().command,
            Command::Provider {
                command: ProviderCommand::Host {
                    command: Some(ProviderHostCommand::Pause { .. }),
                    host_id: None,
                },
            }
        ));
        assert!(parse(&[]).is_err(), "a host or a subcommand");
        assert!(parse(&["not-a-host"]).is_err());
    }

    fn agent_update_view(value: &Value) -> HostAgentUpdateView {
        let mut view = json!({
            "host_id": Uuid::nil(), "installed_release": "20261001T000000Z-aaaaaaaaaaaa",
            "remote_updates": true, "locally_disabled": false, "channel_release": null,
            "install_command": null, "named_release_unavailable": false, "policy": "manual",
            "paused": false, "paused_until": null, "window": null, "target": null,
            "pending_approval": null, "last_failure": null, "history": [],
        });
        for (key, value) in value.as_object().unwrap() {
            view[key] = value.clone();
        }
        serde_json::from_value(view).unwrap()
    }

    fn attempt(state: &str) -> Value {
        json!({
            "update_id": Uuid::from_u128(7), "release": "20261010T000000Z-bbbbbbbbbbbb",
            "state": state, "rollout_id": null, "failure_code": null, "detail": null,
            "created_at": "2026-10-10T00:00:00Z", "finished_at": null,
        })
    }

    /// Every command of `ghost provider agent-update` parses, a window only
    /// whole and never with --clear-window.
    #[test]
    fn agent_update_commands_parse() {
        let host = Uuid::nil().to_string();
        let parse = |arguments: &[&str]| {
            Cli::try_parse_from(
                ["ghost", "provider", "agent-update"]
                    .iter()
                    .chain(arguments),
            )
        };
        let Command::Provider {
            command:
                ProviderCommand::AgentUpdate {
                    command:
                        ProviderAgentUpdateCommand::Set {
                            policy: Some(AgentUpdatePolicyChoice::Automatic),
                            days,
                            start,
                            hours,
                            clear_window: false,
                            ..
                        },
                },
        } = parse(&[
            "set",
            &host,
            "--policy",
            "automatic",
            "--days",
            "mon,sun",
            "--start",
            "02:30",
            "--hours",
            "4",
        ])
        .unwrap()
        .command
        else {
            panic!("not the set command");
        };
        assert_eq!(
            named_window(&days, start, hours),
            Some(AgentUpdateWindow {
                days: 0b100_0001,
                start_minute: 150,
                minutes: 240,
            })
        );
        for arguments in [
            vec!["show", &host],
            vec!["set", &host, "--clear-window"],
            vec!["pause", &host],
            vec!["pause", &host, "--until", "2026-11-30T12:00:00Z"],
            vec!["resume", &host],
            vec!["approve", &host, "20261010T000000Z-bbbbbbbbbbbb"],
            vec!["retry", &host],
            vec!["cancel", &host, "--idempotency-key", "0123456789abcdef"],
        ] {
            assert!(parse(&arguments).is_ok(), "{arguments:?}");
        }
        for arguments in [
            vec!["set", &host, "--days", "mon"],
            vec!["set", &host, "--start", "02:00", "--hours", "4"],
            vec![
                "set", &host, "--days", "mon", "--start", "24:00", "--hours", "4",
            ],
            vec![
                "set", &host, "--days", "mon", "--start", "02:00", "--hours", "25",
            ],
            vec![
                "set", &host, "--days", "mon", "--start", "02:00", "--hours", "0",
            ],
            vec!["set", &host, "--policy", "unknown"],
            vec![
                "set",
                &host,
                "--clear-window",
                "--days",
                "mon",
                "--start",
                "02:00",
                "--hours",
                "4",
            ],
            vec!["approve", &host],
            vec!["pause", &host, "--until", "tomorrow"],
        ] {
            assert!(parse(&arguments).is_err(), "{arguments:?}");
        }
    }

    /// The API replaces a policy whole: a change keeps the rest, and a host
    /// of a policy this ghost does not know is left alone.
    #[test]
    fn an_agent_update_change_keeps_what_it_leaves_out() {
        let window = AgentUpdateWindow {
            days: 1,
            start_minute: 60,
            minutes: 120,
        };
        let until: DateTime<Utc> = "2026-11-30T12:00:00Z".parse().unwrap();
        let view = agent_update_view(&json!({
            "policy": "automatic", "paused": true, "paused_until": until,
            "window": window,
        }));
        let same = AgentUpdateChange {
            policy: None,
            window: WindowChange::Keep,
        };
        let kept = agent_update_policy_request(&view, &same, None).unwrap();
        assert_eq!(kept.policy, AgentUpdatePolicy::Automatic);
        assert!(kept.paused);
        assert_eq!(kept.paused_until, Some(until));
        assert_eq!(kept.window, Some(window));
        assert!(
            !serde_json::to_value(&kept)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("policy_revision"),
            "a backend of before refuses a field it does not know"
        );
        let resumed = agent_update_policy_request(&view, &same, Some((false, None))).unwrap();
        assert!(!resumed.paused);
        assert_eq!(resumed.paused_until, None);
        assert_eq!(resumed.window, Some(window));
        let cleared = agent_update_policy_request(
            &view,
            &AgentUpdateChange {
                policy: Some(AgentUpdatePolicy::Manual),
                window: WindowChange::Clear,
            },
            None,
        )
        .unwrap();
        assert_eq!(cleared.policy, AgentUpdatePolicy::Manual);
        assert_eq!(cleared.window, None);
        assert_eq!(cleared.paused_until, Some(until));
        let newer = agent_update_view(&json!({"policy": "from_the_future"}));
        assert!(agent_update_policy_request(&newer, &same, None).is_err());
    }

    /// Cancelling names the attempt on its way; a retry under its key finds
    /// the one it cancelled, and a first try none. One being applied is
    /// past cancelling, which says so.
    #[test]
    fn cancelling_names_the_attempt_on_its_way() {
        let refused = |view: &HostAgentUpdateView, retrying| {
            cancellable_attempt(view, retrying).unwrap_err().to_string()
        };
        let open = agent_update_view(&json!({"target": attempt("staged")}));
        assert_eq!(
            cancellable_attempt(&open, false).unwrap(),
            Uuid::from_u128(7)
        );
        let cancelled = agent_update_view(&json!({"history": [attempt("cancelled")]}));
        assert_eq!(
            refused(&cancelled, false),
            "this host has no update on its way"
        );
        assert_eq!(
            cancellable_attempt(&cancelled, true).unwrap(),
            Uuid::from_u128(7)
        );
        let failed = agent_update_view(&json!({"history": [attempt("failed")]}));
        assert_eq!(refused(&failed, true), "this host has no update on its way");
        let applying = agent_update_view(&json!({"target": attempt("applying")}));
        for retrying in [false, true] {
            assert_eq!(
                refused(&applying, retrying),
                "the update is being applied, so it cannot be cancelled"
            );
        }
    }

    /// Trying again names the host's newest attempt, the only one the backend
    /// takes; a retry under its key finds the failure it tried again.
    #[test]
    fn trying_again_names_the_newest_attempt_that_failed() {
        let refused = |view: &HostAgentUpdateView, retrying| {
            retryable_attempt(view, retrying).unwrap_err().to_string()
        };
        let failed = attempt("failed");
        let mut later = attempt("cancelled");
        later["update_id"] = json!(Uuid::from_u128(8));
        assert_eq!(
            refused(&agent_update_view(&json!({})), false),
            "no update of this host failed"
        );
        let newest = agent_update_view(&json!({
            "last_failure": failed.clone(), "history": [failed.clone()],
        }));
        assert_eq!(
            retryable_attempt(&newest, false).unwrap(),
            Uuid::from_u128(7)
        );
        let followed = agent_update_view(&json!({
            "last_failure": failed.clone(), "history": [later, failed],
        }));
        assert_eq!(
            refused(&followed, false),
            "the newest update of this host did not fail"
        );
        assert_eq!(
            retryable_attempt(&followed, true).unwrap(),
            Uuid::from_u128(7)
        );
    }

    /// The backend's plain conflict is no duplicate here: each command says
    /// the host cannot take it now, and keeps what `--json` reports.
    #[tokio::test]
    async fn an_agent_update_conflict_says_the_host_cannot_take_it() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let conflict = json!({"code": "conflict", "message": "resource already exists",
            "request_id": "agent-1"})
        .to_string();
        let open = agent_update_view(&json!({"target": attempt("staged")}));
        let (url, _) = canned_server(vec![
            (409, conflict.clone()),
            (200, serde_json::to_string(&open).unwrap()),
            (409, conflict),
        ])
        .await;
        let host = Uuid::nil().to_string();
        let release = "20261010T000000Z-bbbbbbbbbbbb";
        for arguments in [
            vec!["provider", "agent-update", "approve", &host, release],
            vec!["provider", "agent-update", "cancel", &host],
        ] {
            let error = execute(&account_command(&url, &seed, &arguments))
                .await
                .unwrap_err();
            let output = error_output(&error);
            assert_eq!(
                output["error"]["message"],
                "API returned 409 Conflict: this host cannot take that update now (request agent-1)",
                "{arguments:?}"
            );
            assert_eq!(output["error"]["code"], "conflict");
            assert_eq!(output["error"]["status"], 409);
            assert_eq!(output["error"]["request_id"], "agent-1");
        }
    }

    /// `show` says every state plainly, and a state of a newer backend
    /// still decodes.
    #[test]
    fn an_agent_update_reads_plainly() {
        let mut failed = attempt("rolled_back");
        failed["failure_code"] = json!("crash_loop");
        failed["detail"] = json!("two restarts");
        let view = agent_update_view(&json!({
            "remote_updates": true, "locally_disabled": true,
            "named_release_unavailable": true,
            "target": attempt("from_the_future"),
            "pending_approval": "20261010T000000Z-bbbbbbbbbbbb",
            "window": {"days": 9, "start_minute": 150, "minutes": 90},
            "paused": true, "paused_until": "2026-11-30T12:00:00Z",
            "last_failure": failed.clone(), "history": [failed],
        }));
        let record = agent_update_record(&view);
        assert_eq!(record["window"], "mon, thu 02:30 UTC for 1 h 30 min");
        assert_eq!(record["paused"], "until 2026-11-30 12:00 UTC");
        assert_eq!(record["remote_updates"], "disabled on the host");
        assert_eq!(record["target"], "20261010T000000Z-bbbbbbbbbbbb (unknown)");
        assert_eq!(
            record["last_failure"],
            "20261010T000000Z-bbbbbbbbbbbb (rolled_back): crash_loop: two restarts"
        );
        assert_eq!(record["history"][0]["state"], "rolled_back");
        let hand = agent_update_record(&agent_update_view(&json!({
            "remote_updates": false, "install_command": "curl | sudo sh",
        })));
        assert_eq!(hand["update"], "by hand");
        assert_eq!(hand["install_command"], "curl | sudo sh");
    }

    /// `ghost catalog` alone lists offerings, with their filters; a filter
    /// cannot go with another subcommand.
    #[test]
    fn the_catalog_alone_lists_offerings() {
        let parse = |arguments: &[&str]| Cli::try_parse_from(["ghost"].iter().chain(arguments));
        let Command::Catalog {
            command: None,
            offerings,
        } = parse(&["catalog", "--min-vcpu", "4"]).unwrap().command
        else {
            panic!("not the catalog alone");
        };
        assert_eq!(offerings.query(None).unwrap(), "kind=any&minimum_vcpus=4");
        assert!(parse(&["catalog", "--min-vcpu", "4", "images"]).is_err());
        let offerings = json!([listed_offering(HostMode::CloudRouted)]);
        assert_eq!(
            render_result(&parse(&["catalog"]).unwrap(), &offerings, Terminal::plain()),
            render_result(
                &parse(&["catalog", "offerings"]).unwrap(),
                &offerings,
                Terminal::plain()
            )
        );
        // The count of instances that can be rented now has a column before
        // the hosts', and `--available` filters on it; a backend of before
        // sends none, which reads as a dash and not as sold out.
        let readable = render_result(&parse(&["catalog"]).unwrap(), &offerings, Terminal::plain());
        let (head, row) = readable.trim_start().split_once('\n').unwrap();
        assert!(
            head.find("AVAILABLE").unwrap() < head.find("HOSTS").unwrap(),
            "{head}"
        );
        assert!(row.trim_end().ends_with("12         1"), "{row}");
        let mut older = listed_offering(HostMode::CloudRouted);
        older.available_instances = 0;
        let output = json!([older]);
        let readable = render_result(&parse(&["catalog"]).unwrap(), &output, Terminal::plain());
        assert!(readable.contains('—'), "{readable}");
        let json_output = render_result(
            &parse(&["--json", "catalog"]).unwrap(),
            &json!([listed_offering(HostMode::CloudRouted)]),
            Terminal::plain(),
        );
        assert!(
            json_output.contains("\"available_instances\": 12"),
            "{json_output}"
        );
        // `--ip shared` prices the shared IP, and a page's cursor is that
        // price; an offering without it has no price in the list.
        let mut shared = listed_offering(HostMode::CloudRouted);
        shared.network_prices.push(
            serde_json::from_value(json!({
                "gateway_tier": "shared_ip",
                "gateway_base_charge_microusd_per_month": 600_000,
                "combined_microusd_per_tib": 240_000,
            }))
            .unwrap(),
        );
        let output = json!([shared.clone()]);
        let dedicated = render_result(&parse(&["catalog"]).unwrap(), &output, Terminal::plain());
        let sharing = render_result(
            &parse(&["catalog", "--ip", "shared"]).unwrap(),
            &output,
            Terminal::plain(),
        );
        assert!(dedicated.contains("$3.24"), "{dedicated}");
        assert!(
            sharing.contains("$3.84") && !sharing.contains("$3.24"),
            "{sharing}"
        );
        let Command::Catalog { offerings, .. } =
            parse(&["catalog", "--ip", "shared", "--limit", "1"])
                .unwrap()
                .command
        else {
            panic!("not the catalog alone");
        };
        assert_eq!(
            offerings.next_page(&[shared]).as_deref(),
            Some("3840000.of2_J7hnuv_uO8PmXACeyas4QY")
        );
    }

    #[test]
    fn sizes_are_read_in_binary_units() {
        assert_eq!(parse_size("4"), Ok(4 << 30));
        assert_eq!(parse_size("4GiB"), Ok(4 << 30));
        assert_eq!(parse_size("4g"), Ok(4 << 30));
        assert_eq!(parse_size("4 Gi"), Ok(4 << 30));
        assert_eq!(parse_size("512MiB"), Ok(512 << 20));
        assert_eq!(parse_size("512M"), Ok(512 << 20));
        assert_eq!(parse_size("1.5TiB"), Ok(3 << 39));
        assert_eq!(parse_size("1.5T"), Ok(3 << 39));
        assert_eq!(parse_size("8G"), Ok(8 << 30));
        assert_eq!(parse_size("2048b"), Ok(2048));
        for invalid in ["", "GiB", "4GB", "4 gigs", "-4", "4.5.1G", "99999999999TiB"] {
            assert!(parse_size(invalid).is_err(), "{invalid}");
        }
    }

    /// A disk names its software RAID level, or without software RAID its
    /// hardware RAID array's, and nothing for a bare disk.
    #[test]
    fn a_disk_names_its_raid_level() {
        let raid = |software: &[&str], hardware: &[&str]| {
            let mut offering = listed_offering(HostMode::CloudRouted);
            offering.software_raid_levels =
                software.iter().map(|&level| level.to_owned()).collect();
            offering.hardware_raid_levels =
                hardware.iter().map(|&level| level.to_owned()).collect();
            raid_text(&offering)
        };
        assert_eq!(raid(&[], &[]), None);
        assert_eq!(raid(&["raid1"], &[]).as_deref(), Some("raid 1"));
        assert_eq!(raid(&["raid5"], &["raid1"]).as_deref(), Some("raid 5"));
        assert_eq!(raid(&[], &["raid0"]).as_deref(), Some("raid 0"));
        assert_eq!(raid(&[], &["raid"]).as_deref(), Some("raid"));
        assert_eq!(raid(&["raid10"], &[]).as_deref(), Some("raid 10"));
    }

    #[test]
    fn cpu_models_are_shortened_for_a_list() {
        for (model, short) in [
            (
                "Intel(R) Xeon(R) CPU E5-2683 v4 @ 2.10GHz",
                "Intel Xeon E5-2683 v4",
            ),
            ("AMD Ryzen 9 5950X 16-Core Processor", "AMD Ryzen 9 5950X"),
            (
                "13th Gen Intel(R) Core(TM) i7-13700",
                "13th Gen Intel Core i7-13700",
            ),
            ("AMD EPYC-Rome Processor", "AMD EPYC-Rome"),
            ("Processor", "Processor"),
        ] {
            assert_eq!(short_cpu_model(model), short);
        }
    }

    /// The words of each line of `text`, so a test does not depend on how
    /// wide a table's columns come out.
    fn words(text: &str) -> Vec<Vec<&str>> {
        text.lines()
            .map(|line| line.split_whitespace().collect())
            .collect()
    }

    /// For reading, a list shows one row per item with the columns that
    /// tell the items apart; `--json` is the API's list as it is.
    #[test]
    fn lists_are_summarized_for_reading_only() {
        let cli =
            |arguments: &[&str]| Cli::try_parse_from(["ghost"].iter().chain(arguments)).unwrap();
        let read = |arguments: &[&str], output: &Value| {
            render_result(&cli(arguments), output, Terminal::plain())
        };
        let (instance, backup, job) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let created = "2026-09-30T13:40:58.334Z";

        let instances = json!([{"instance_id": instance, "offering_id": "o", "hostname": "web-1",
            "root_disk_bytes": 48_u64 << 30, "state": "running", "desired_power_state": "running",
            "holds_capacity": true, "public_ipv4": "203.0.113.7",
            "network_microusd_per_tib": 5_000_000, "created_at": created,
            "balance_reservation_microusd": 9_000_000, "location": "pl-warsaw", "vcpu_count": 2,
            "memory_bytes": 4_u64 << 30, "image": {"image_id": Uuid::nil(), "slug": "debian-13",
            "display_name": "Debian 13", "architecture": "x86_64", "minimum_disk_bytes": 1}}]);
        let id = instance.to_string();
        assert_eq!(
            words(&read(&["instance", "list"], &instances)),
            [
                vec![
                    "INSTANCE_ID",
                    "NAME",
                    "STATE",
                    "PUBLIC_IPV4",
                    "LOCATION",
                    "IMAGE",
                    "SIZE"
                ],
                vec![
                    &*id,
                    "web-1",
                    "running",
                    "203.0.113.7",
                    "pl-warsaw",
                    "debian-13",
                    "2",
                    "vCPU,",
                    "4",
                    "GiB",
                    "RAM,",
                    "48",
                    "GiB",
                    "disk"
                ],
            ]
        );

        let mut busy = instances.clone();
        busy[0]["active_job"] = json!({"job_id": job, "kind": "create_backup",
            "state": "running", "current_step_key": "upload_parts", "progress_permyriad": 4_512,
            "backup_id": backup, "created_at": created});
        assert_eq!(
            words(&read(&["instance", "list"], &busy))[1][..6],
            [&*id, "web-1", "running", "backing", "up", "45.12"]
        );
        // A named instance is listed by its name, not its hostname.
        let mut named = instances.clone();
        named[0]["name"] = json!("shop");
        assert_eq!(
            words(&read(&["instance", "list"], &named))[1][..3],
            [&*id, "shop", "running"]
        );

        // The instance was called web-0 when the backup was taken, and has
        // been renamed web-1 since.
        let mut hosted = backup_json(backup, instance, "gigahost_s3", "available");
        hosted["wrapped_data_key"] = json!("d3JhcHBlZCBkYXRhIGtleQ");
        hosted["hostname"] = json!("web-0");
        hosted["instance_hostname"] = json!("web-1");
        hosted["image_slug"] = json!("debian-13");
        hosted["created_at"] = json!(created);
        let backups = json!([hosted]);
        let id = backup.to_string();
        assert_eq!(
            words(&read(&["backup", "list", "--all"], &backups)),
            [
                vec![
                    "BACKUP_ID",
                    "NAME",
                    "STATUS",
                    "DESTINATION",
                    "IMAGE",
                    "SIZE",
                    "PER_MONTH",
                    "CREATED_AT"
                ],
                vec![
                    &*id,
                    "web-0",
                    "available",
                    "hosted",
                    "debian-13",
                    "716.8",
                    "MiB",
                    "$0.014",
                    "2026-09-30",
                    "13:40:58",
                    "UTC"
                ],
            ]
        );
        // A backup that did not record the hostname shows the instance's.
        let mut unrecorded = hosted.clone();
        unrecorded["hostname"] = Value::Null;
        assert_eq!(
            words(&read(&["backup", "list"], &json!([unrecorded])))[1][..2],
            [&*id, "web-1"]
        );
        // A backend that sends the instance's name shows it.
        let mut named = hosted.clone();
        named["instance_name"] = json!("shop");
        assert_eq!(
            words(&read(&["backup", "list"], &json!([named])))[1][..2],
            [&*id, "shop"]
        );
        let mut recovery = hosted.clone();
        recovery["purpose"] = json!("final_recovery");
        let marked = read(&["backup", "list"], &json!([hosted.clone(), recovery]));
        assert_eq!(
            words(&marked)[0],
            [
                "BACKUP_ID",
                "NAME",
                "STATUS",
                "PURPOSE",
                "DESTINATION",
                "IMAGE",
                "SIZE",
                "PER_MONTH",
                "CREATED_AT"
            ]
        );
        assert_eq!(words(&marked)[2][3], "final_recovery", "{marked}");
        // A backup in a backup pool its host is missing is unavailable, and
        // says why; a lost one is lost.
        let mut unavailable = hosted.clone();
        unavailable["destination"] = json!("local");
        unavailable["unavailable"] = json!({"since": created,
            "reason": "backup pool backups of the host is missing: not in the host's inventory"});
        let mut lost = hosted.clone();
        lost["status"] = json!("lost");
        lost["lost_at"] = json!(created);
        let missing = read(&["backup", "list"], &json!([unavailable, lost]));
        assert_eq!(
            words(&missing)[0],
            [
                "BACKUP_ID",
                "NAME",
                "STATUS",
                "DESTINATION",
                "IMAGE",
                "SIZE",
                "PER_MONTH",
                "CREATED_AT",
                "UNAVAILABLE"
            ]
        );
        assert_eq!(words(&missing)[1][2], "unavailable", "{missing}");
        assert!(
            missing.contains(
                "backup pool backups of the host is missing: not in the host's inventory"
            ),
            "{missing}"
        );
        assert_eq!(words(&missing)[2][2], "lost", "{missing}");
        // A container instance's backup is marked by its kind and shows the
        // image it ran: a stock image's slug, or the renter's image.
        let mut renters = hosted.clone();
        renters["image_slug"] = Value::Null;
        renters["kind"] = json!("container");
        renters["container"] = json!({"image": "docker.io/library/nginx:1.27",
            "image_digest": null, "stock_image": null, "restart_policy": "always"});
        let mut stock = renters.clone();
        stock["container"]["stock_image"] = json!("debian-13");
        let kinds = read(
            &["backup", "list"],
            &json!([hosted.clone(), renters, stock]),
        );
        assert_eq!(
            words(&kinds)[0],
            [
                "BACKUP_ID",
                "NAME",
                "STATUS",
                "KIND",
                "DESTINATION",
                "IMAGE",
                "SIZE",
                "PER_MONTH",
                "CREATED_AT"
            ]
        );
        assert_eq!(
            words(&kinds)[1][3..6],
            ["vm", "hosted", "debian-13"],
            "{kinds}"
        );
        assert_eq!(
            words(&kinds)[2][3..6],
            ["container", "hosted", "docker.io/library/nginx:1.27"],
            "{kinds}"
        );
        assert_eq!(
            words(&kinds)[3][3..6],
            ["container", "hosted", "debian-13"],
            "{kinds}"
        );
        let json = read(&["--json", "backup", "list"], &backups);
        assert_eq!(
            json,
            render_output(&backups, OutputFormat::Json, Terminal::plain())
        );
        assert!(json.contains("\"wrapped_data_key\""), "{json}");
        assert!(json.contains("\"gigahost_s3\""), "{json}");

        let history = json!({"items": [
            {"transaction_id": Uuid::now_v7(), "entry_id": 7, "kind": "reservation_hold",
             "account_kind": "user_reserve", "amount_microusd": 8_000_000,
             "posted_at": created, "instance_id": instance, "vm_charge_microusd": null},
            {"transaction_id": Uuid::now_v7(), "entry_id": 6, "kind": "faucet",
             "account_kind": "user_balance", "amount_microusd": 500_000_000,
             "posted_at": created, "instance_id": null},
        ], "next_cursor": "c1"});
        let id = instance.to_string();
        assert_eq!(
            words(&read(&["account", "history"], &history)),
            [
                vec!["POSTED_AT", "KIND", "ACCOUNT", "AMOUNT", "INSTANCE_ID"],
                vec![
                    "2026-09-30",
                    "13:40:58",
                    "UTC",
                    "reservation_hold",
                    "reserved",
                    "$8.00",
                    &*id
                ],
                vec![
                    "2026-09-30",
                    "13:40:58",
                    "UTC",
                    "faucet",
                    "available",
                    "$500.00",
                    "-"
                ],
                vec![],
                vec!["next_cursor", "c1"],
            ]
        );

        let summary = |state: &str, error_code: Option<&str>| {
            json!({"job_id": job, "kind": "create_backup", "state": state, "resource_id": backup,
                "instance_id": instance, "backup_id": backup, "progress_permyriad": 6_500,
                "current_step_key": null, "current_step_progress_permyriad": null,
                "error_code": error_code, "error_message": null, "created_at": created,
                "updated_at": created, "completed_at": null})
        };
        let id = job.to_string();
        let jobs = json!({"items": [summary("running", None)], "next_cursor": null});
        assert_eq!(
            words(&read(&["job", "list"], &jobs)),
            [
                vec!["JOB_ID", "KIND", "STATE", "PROGRESS", "CREATED_AT"],
                vec![
                    &*id,
                    "create_backup",
                    "running",
                    "65.00%",
                    "2026-09-30",
                    "13:40:58",
                    "UTC"
                ],
            ]
        );
        let failed = json!({"items": [summary("failed", Some("disk_full"))], "next_cursor": null});
        assert_eq!(
            words(&read(&["job", "list"], &failed))[0],
            [
                "JOB_ID",
                "KIND",
                "STATE",
                "PROGRESS",
                "ERROR_CODE",
                "CREATED_AT"
            ]
        );

        // An offering's CPU names its model and its memory the hosts'
        // technology. A home offering's price holds its default gateway's
        // base, Singapore's $5.00, and its traffic is that gateway's too,
        // the provider's $0.24 and Singapore's $10.00 a TiB, with no
        // "from"; `catalog offering` shows each option. The disk names its
        // RAID level. The table fits 175 columns, and a narrower terminal
        // gets a block per row. The list carries no hardware profiles: the
        // memory's technology comes from its summary.
        let mut home = home_offering_with_locations();
        home.hardware_profiles.clear();
        home.software_raid_levels = vec!["raid1".to_owned()];
        let offerings = json!([home, listed_offering(HostMode::CloudRouted)]);
        let offering = read(&["catalog", "offerings"], &offerings);
        let lines = words(&offering);
        assert_eq!(
            lines[0],
            [
                "OFFERING_ID",
                "PROVIDER",
                "LOCATION",
                "HOST_MODE",
                "KINDS",
                "CPU",
                "RAM",
                "DISK",
                "PRICE_PER_MONTH",
                "NETWORK",
                "AVAILABLE",
                "HOSTS"
            ]
        );
        assert_eq!(lines[1][1], "gh-examples");
        assert_eq!(lines[1][4], "vm", "an offering of before is a VM's");
        assert_eq!(
            lines[1][5..],
            [
                "1",
                "vCPU",
                "Intel",
                "Xeon",
                "E5-2683",
                "v4",
                "5.5",
                "GiB",
                "DDR4",
                "48",
                "GiB",
                "raid",
                "1",
                "$8.24",
                "$10.24/TiB",
                "12",
                "1"
            ]
        );
        assert_eq!(
            lines[2][5..],
            [
                "1",
                "vCPU",
                "Test",
                "5.5",
                "GiB",
                "48",
                "GiB",
                "$3.24",
                "$0.24/TiB",
                "12",
                "1"
            ]
        );
        let at = |width| {
            let terminal = Terminal {
                colors: false,
                width,
            };
            render_result(&cli(&["catalog", "offerings"]), &offerings, terminal)
        };
        let table = at(185);
        assert!(table.starts_with("  OFFERING_ID"), "{table}");
        assert!(
            table.lines().all(|line| line.chars().count() <= 185),
            "{table}"
        );
        assert!(at(150).starts_with("    - offering_id"), "{}", at(150));

        let locations = json!([{"location": "pl-warsaw", "display_name": "Warsaw, Poland",
            "country_code": "PL", "continent_code": "EU", "latitude": 52.23, "longitude": 21.01}]);
        assert_eq!(
            read(&["catalog", "locations"], &locations),
            "  LOCATION   DISPLAY_NAME    COUNTRY_CODE  CONTINENT_CODE\n  pl-warsaw  Warsaw, Poland  PL            EU"
        );

        // A result in a shape the summary does not know is shown as it is.
        let unexpected = json!({"unexpected": true});
        assert_eq!(
            read(&["instance", "list"], &unexpected),
            "  unexpected  yes"
        );
    }

    /// `catalog offering` reads one listed offering, and refuses what cannot
    /// be an offering ID before it reaches the URL path.
    #[tokio::test]
    async fn one_offering_is_read_in_full() {
        let offering = serde_json::to_value(listed_offering(HostMode::CloudRouted)).unwrap();
        let (url, received) = canned_server(vec![(200, offering.to_string())]).await;
        let read = |id: &str| {
            Cli::try_parse_from(["ghost", "--api-url", &url, "catalog", "offering", id]).unwrap()
        };
        let id = "of2_J7hnuv_uO8PmXACeyas4QY";
        assert_eq!(execute(&read(id)).await.unwrap(), offering);
        let error = execute(&read("../account")).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "offering ../account is not an offering ID; copy one from `ghost catalog offerings`"
        );
        assert_eq!(
            request_lines(&received),
            [format!("GET /v1/catalog/offerings/{id}")]
        );
    }

    /// A size says its vCPUs alone, a mid-step of the ladder too: never the
    /// cores they share, nor the tier.
    #[test]
    fn a_size_says_its_vcpus_alone() {
        use gigahost_client_api::hypervisor::CpuTier;
        let mut offering = listed_offering(HostMode::CloudRouted);
        offering.cpu_tier = CpuTier::Shared2x;
        offering.vcpu_count = 4;
        let quote = offering_quote(&offering, None, None, false);
        assert_eq!(
            quote[1], "  Size       4 vCPU, 5.5 GiB RAM, 48 GiB disk",
            "{quote:?}"
        );
        assert_eq!(
            size_text(4, 8 << 30, 64 << 30),
            "4 vCPU, 8 GiB RAM, 64 GiB disk"
        );
    }

    /// `instance upgrades` from 2 vCPUs lists the mid-step and the 4-vCPU
    /// size after it by their vCPUs alone, told apart by their RAM and
    /// disk; `--json` keeps the tier and the vCPUs as the backend sent
    /// them.
    #[test]
    fn the_upgrades_of_an_instance_say_the_vcpus_of_each_size() {
        use gigahost_client_api::hypervisor::CpuTier;
        let upgrade = |cpu_tier, memory_bytes: u64| InstanceUpgradeView {
            offering_id: format!("of2_{cpu_tier:?}"),
            cpu_tier,
            vcpu_count: 4,
            memory_bytes,
            root_disk_bytes: memory_bytes * 16,
            base_price_microusd_per_month: 3_000_000,
            full_utilization_price_microusd_per_month: 6_000_000,
            balance_reservation_increase_microusd: 1_000_000,
            available: true,
        };
        let output = to_value(vec![
            upgrade(CpuTier::Shared2x, 8 << 30),
            upgrade(CpuTier::Shared1x, 16 << 30),
        ])
        .unwrap();
        let instance = Uuid::nil().to_string();
        let cli = Cli::try_parse_from(["ghost", "instance", "upgrades", &instance]).unwrap();
        let text = render_result(&cli, &output, Terminal::plain());
        let rows: Vec<&str> = text.lines().skip(1).collect();
        assert!(
            rows.len() == 2
                && rows[0].contains("  4 vCPU  ")
                && rows[0].contains("  8 GiB  ")
                && rows[1].contains("  4 vCPU  ")
                && rows[1].contains("  16 GiB  "),
            "{text}"
        );
        assert!(
            !text.contains("shared") && !text.contains("vcpu_count") && !text.contains("core"),
            "{text}"
        );
        let json =
            Cli::try_parse_from(["ghost", "--json", "instance", "upgrades", &instance]).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&render_result(&json, &output, Terminal::plain()))
                .unwrap(),
            output
        );
    }

    /// Each choice's bandwidth limit, where the backend sends it: in the
    /// offerings list beside the traffic price, in each network option of
    /// `catalog offering`, and in the quote of a rental.
    #[test]
    fn the_bandwidth_limits_are_shown_beside_the_traffic_prices() {
        let limited = |mut offering: OfferingView| {
            for price in &mut offering.network_prices {
                price.bandwidth = Some(gigahost_client_api::website::BandwidthView {
                    limit_mbit: match price.gateway_tier {
                        Some(GatewayTier::HighBandwidth) => None,
                        Some(GatewayTier::SharedIp) => Some(20),
                        Some(_) => Some(100),
                        None => Some(50),
                    },
                });
            }
            offering
        };
        let cli =
            |arguments: &[&str]| Cli::try_parse_from(["ghost"].iter().chain(arguments)).unwrap();
        let home = limited(home_offering_with_locations());
        let cloud = limited(listed_offering(HostMode::CloudRouted));
        let listed = render_result(
            &cli(&["catalog", "offerings"]),
            &json!([home, cloud]),
            Terminal::plain(),
        );
        let lines = words(&listed);
        assert_eq!(
            lines[0][9..],
            ["NETWORK", "BANDWIDTH", "AVAILABLE", "HOSTS"],
            "{listed}"
        );
        assert!(
            lines[1].windows(2).any(|pair| pair == ["100", "Mbit/s"]),
            "{listed}"
        );
        assert!(
            lines[2].windows(2).any(|pair| pair == ["50", "Mbit/s"]),
            "{listed}"
        );
        let shown = render_result(
            &cli(&["catalog", "offering", "o"]),
            &serde_json::to_value(&home).unwrap(),
            Terminal::plain(),
        );
        let prices = &shown[shown.find("==> network_prices").expect("prices")..];
        let rows = words(prices);
        assert_eq!(rows[1].last(), Some(&"BANDWIDTH"), "{prices}");
        assert!(rows[2].ends_with(&["100", "Mbit/s"]), "{prices}");
        assert!(rows[4].ends_with(&["no", "limit"]), "{prices}");
        let quote = offering_quote(&cloud, None, None, false).join("\n");
        assert!(quote.contains("  Network    50 Mbit/s\n"), "{quote}");
        assert!(quote.contains("  Traffic    $0.24  per TiB\n"), "{quote}");
    }

    #[test]
    fn an_offering_quote_names_its_terms_and_every_charge() {
        let quote = |offering: &OfferingView, tier, restore| {
            let lines = offering_quote(offering, tier, restore, false);
            assert!(
                lines.iter().all(|line| line.chars().count() <= 100),
                "{lines:#?}"
            );
            lines.join("\n")
        };
        assert_eq!(
            quote(&listed_offering(HostMode::CloudRouted), None, None),
            concat!(
                "  Offering   of2_J7hnuv_uO8PmXACeyas4QY\n",
                "  Size       1 vCPU, 5.5 GiB RAM, 48 GiB disk\n",
                "  Location   Warsaw (pl-warsaw)\n",
                "  Host       cloud, provider Example Hosting\n",
                "\n",
                "  Now        $0.13  creation fee, refunded if the creation fails unless you caused it\n",
                "  Monthly    $3.24  base, up to $4.86 at full CPU\n",
                "  Traffic    $0.24  per TiB\n",
                "  Held       $7.00  of your balance while the instance exists"
            )
        );
        assert_eq!(
            quote(
                &listed_offering(HostMode::HomeGateway),
                Some(GatewayTier::HighBandwidth),
                None
            ),
            concat!(
                "  Offering   of2_J7hnuv_uO8PmXACeyas4QY\n",
                "  Size       1 vCPU, 5.5 GiB RAM, 48 GiB disk\n",
                "  Location   Warsaw (pl-warsaw)\n",
                "  Host       home, provider Example Hosting\n",
                "  Network    high bandwidth gateway\n",
                "\n",
                "  Now         $0.13  creation fee, refunded if the creation fails unless you caused it\n",
                "  Monthly     $3.24  base, up to $4.86 at full CPU\n",
                "             $15.00  high bandwidth gateway\n",
                "  Traffic     $5.24  per TiB\n",
                "  Held       $22.00  of your balance while the instance exists"
            )
        );
        // A cloud offering's address, an older backend's absent.
        let mut addressed = listed_offering(HostMode::CloudRouted);
        addressed.address_microusd_per_month = 3_000_000;
        addressed.balance_reservation_microusd = 10_000_000;
        assert_eq!(
            quote(&addressed, None, None),
            concat!(
                "  Offering   of2_J7hnuv_uO8PmXACeyas4QY\n",
                "  Size       1 vCPU, 5.5 GiB RAM, 48 GiB disk\n",
                "  Location   Warsaw (pl-warsaw)\n",
                "  Host       cloud, provider Example Hosting\n",
                "\n",
                "  Now         $0.13  creation fee, refunded if the creation fails unless you caused it\n",
                "  Monthly     $3.24  base, up to $4.86 at full CPU\n",
                "              $3.00  address\n",
                "  Traffic     $0.24  per TiB\n",
                "  Held       $10.00  of your balance while the instance exists"
            )
        );
        assert_eq!(addressed.listed_price_microusd_per_month(), 6_240_000);
        // Its shared IP takes the place of that address in the hold and the
        // price, and is no gateway.
        addressed
            .network_prices
            .push(gigahost_client_api::website::NetworkPriceView {
                gateway_tier: Some(GatewayTier::SharedIp),
                gateway_base_charge_microusd_per_month: 0,
                combined_microusd_per_tib: 240_000,
                bandwidth: None,
            });
        assert_eq!(
            quote(&addressed, Some(GatewayTier::SharedIp), None),
            concat!(
                "  Offering   of2_J7hnuv_uO8PmXACeyas4QY\n",
                "  Size       1 vCPU, 5.5 GiB RAM, 48 GiB disk\n",
                "  Location   Warsaw (pl-warsaw)\n",
                "  Host       cloud, provider Example Hosting\n",
                "  Network    shared IP, included\n",
                "\n",
                "  Now        $0.13  creation fee, refunded if the creation fails unless you caused it\n",
                "  Monthly    $3.24  base, up to $4.86 at full CPU\n",
                "  Traffic    $0.24  per TiB\n",
                "  Held       $7.00  of your balance while the instance exists"
            )
        );
        assert!(check_rental(&addressed, Some(GatewayTier::SharedIp), None).is_ok());
        assert!(check_rental(&addressed, None, None).is_ok());
        // Where its hosts have no address of the VM's own left, it lists the
        // shared IP alone, which a rental must ask for.
        let mut shared_only = addressed.clone();
        shared_only.network_prices.remove(0);
        let refused = check_rental(&shared_only, None, None)
            .unwrap_err()
            .to_string();
        assert!(
            refused.contains(
                "To rent it, give --gateway-tier shared_ip:\n  shared IP (--gateway-tier shared_ip)  $0.24/TiB, included"
            ),
            "{refused}"
        );
        assert!(check_rental(&shared_only, Some(GatewayTier::SharedIp), None).is_ok());
        let rows = network_option_rows(&network_options(&addressed), true);
        let pretty::Section::Rows(_, rows) = rows else {
            panic!("the options are rows");
        };
        assert_eq!(rows[0]["gateway_location"], "own address");
        assert_eq!(rows[0]["base_per_month"], "$3.00");
        assert_eq!(rows[1]["gateway_location"], "host's address");
        assert_eq!(rows[1]["base_per_month"], "included");
    }

    /// The screen `ghost account approve` shows for a request to create an
    /// instance from a backup: the quote on standard error, line by line, and
    /// the two lines on standard output.
    #[test]
    fn the_approve_screen_of_a_creation_from_a_backup_reads_as_rows() {
        let mut offering = listed_offering(HostMode::HomeGateway);
        offering.offering_id = "of2_uMxIiJThRL48XCZwPS5k5Q".to_owned();
        offering.vcpu_count = 2;
        offering.memory_bytes = 4 << 30;
        offering.root_disk_bytes = 20 << 30;
        offering.location = "th-bangkok".to_owned();
        offering.location_name = "Bangkok, Thailand".to_owned();
        offering.provider_name = "gh-4a2l3v67".to_owned();
        offering.instance_creation_charge_microusd = 50_000;
        offering.base_price_microusd_per_month = 2_350_000;
        offering.full_utilization_price_microusd_per_month = 7_060_000;
        offering.balance_reservation_microusd = 1_000_000;
        offering.address_microusd_per_month = 0;
        offering.network_prices = vec![gigahost_client_api::website::NetworkPriceView {
            gateway_tier: Some(GatewayTier::SharedIp),
            gateway_base_charge_microusd_per_month: 500_000,
            combined_microusd_per_tib: 10_000_000,
            bandwidth: Some(gigahost_client_api::website::BandwidthView {
                limit_mbit: Some(20),
            }),
        }];
        let quote = offering_quote(&offering, Some(GatewayTier::SharedIp), Some(6_200), false);
        assert_eq!(
            quote.join("\n"),
            concat!(
                "  Offering   of2_uMxIiJThRL48XCZwPS5k5Q\n",
                "  Size       2 vCPU, 4 GiB RAM, 20 GiB disk\n",
                "  Location   Bangkok, Thailand (th-bangkok)\n",
                "  Host       home, provider gh-4a2l3v67\n",
                "  Network    shared IP gateway, 20 Mbit/s\n",
                "\n",
                "  Now          $0.05  creation fee, refunded if the creation fails unless you caused it\n",
                "             $0.0062  backup restore, not refunded\n",
                "  Monthly      $2.35  base, up to $7.06 at full CPU\n",
                "               $0.50  shared IP gateway\n",
                "  Traffic     $10.00  per TiB\n",
                "  Held         $1.50  of your balance while the instance exists",
            )
        );
        // Colors only where the stream shows them, and no wire names.
        assert!(!quote.join("").contains('\x1b'));
        assert!(
            offering_quote(&offering, Some(GatewayTier::SharedIp), None, true)[0]
                .contains("\x1b[1m")
        );
        let id = Uuid::nil();
        let output = json!({"request": {}, "approve_command": format!("ghost account approve {id} --yes"),
            "notice": approval_notice(&gigahost_client_api::website::BrowserOperation::CreateFromBackup {
                offering_id: "o".to_owned(), backup_id: id, gateway_tier: None, hostname: None, name: None, tags: None }, true)});
        let cli = Cli::try_parse_from(["ghost", "account", "approve", &id.to_string()]).unwrap();
        assert_eq!(
            render_result(&cli, &output, Terminal::plain()),
            format!(
                "Approving lets the host create this instance and charges what is shown above.\nTo approve:  ghost account approve {id} --yes"
            )
        );
    }

    /// The screen for a request to restore a backup onto an instance, line
    /// by line: the instance by its name and ID where it could be read,
    /// by its ID alone where it could not, and with no restore row while
    /// the backup's size is not known. A name from the server is escaped.
    #[test]
    fn the_approve_screen_of_a_restore_reads_as_rows() {
        let (intent_id, backup_id, instance_id) =
            (Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3));
        let mut backup: BackupView =
            serde_json::from_value(backup_json(backup_id, instance_id, "local", "available"))
                .unwrap();
        let screen = |backup: &BackupView, name: Option<&str>, colors: bool| {
            restore_screen(intent_id, backup_id, backup, instance_id, name, colors).join("\n")
        };

        assert_eq!(
            screen(&backup, Some("web"), false),
            concat!(
                "Website request 00000000-0000-0000-0000-000000000001: restore backup 00000000-0000-0000-0000-000000000002 onto web, replacing its disk\n",
                "\n",
                "  Backup     00000000-0000-0000-0000-000000000002\n",
                "  Instance   web (00000000-0000-0000-0000-000000000003)\n",
                "\n",
                "  Now        $0.007  backup restore, not refunded\n",
            )
        );
        // An instance that could not be read is shown by its ID.
        assert_eq!(
            screen(&backup, None, false),
            concat!(
                "Website request 00000000-0000-0000-0000-000000000001: restore backup 00000000-0000-0000-0000-000000000002 onto 00000000-0000-0000-0000-000000000003, replacing its disk\n",
                "\n",
                "  Backup     00000000-0000-0000-0000-000000000002\n",
                "  Instance   00000000-0000-0000-0000-000000000003\n",
                "\n",
                "  Now        $0.007  backup restore, not refunded\n",
            )
        );
        // A name is the server's text: no control character reaches the
        // terminal, and colours only where the stream shows them.
        let escaped = screen(&backup, Some("we\x1bb"), false);
        assert!(escaped.contains("onto we\\u{1b}b, replacing"), "{escaped}");
        assert!(
            escaped.contains("  Instance   we\\u{1b}b (0000"),
            "{escaped}"
        );
        assert!(!escaped.contains('\x1b'), "{escaped}");
        assert!(screen(&backup, Some("web"), true).contains("\x1b[1m"));
        // No size, no charge to show.
        backup.size_bytes = None;
        assert_eq!(
            screen(&backup, Some("web"), false),
            concat!(
                "Website request 00000000-0000-0000-0000-000000000001: restore backup 00000000-0000-0000-0000-000000000002 onto web, replacing its disk\n",
                "\n",
                "  Backup     00000000-0000-0000-0000-000000000002\n",
                "  Instance   web (00000000-0000-0000-0000-000000000003)\n",
            )
        );
    }

    /// The notice of an approval says it in words either way, never with a
    /// pointer at a quote that is not on the reader's screen, and a request
    /// of a kind this release does not know is the update advice.
    #[test]
    fn the_approval_notice_points_at_the_quote_only_where_it_is_shown() {
        use gigahost_client_api::website::BrowserOperation;
        let create = BrowserOperation::CreateFromBackup {
            offering_id: "o".to_owned(),
            backup_id: Uuid::nil(),
            gateway_tier: None,
            hostname: None,
            tags: None,
            name: None,
        };
        let restore = BrowserOperation::RestoreBackup {
            instance_id: Uuid::nil(),
            backup_id: Uuid::nil(),
        };
        for operation in [&create, &restore] {
            assert!(
                approval_notice(operation, true).ends_with("charges what is shown above."),
                "{}",
                approval_notice(operation, true)
            );
            let unshown = approval_notice(operation, false);
            assert!(!unshown.contains("above"), "{unshown}");
            assert!(unshown.contains("backup restore"), "{unshown}");
            assert!(
                unshown.ends_with("Inspect the requested resources before approving."),
                "{unshown}"
            );
        }
        assert!(approval_notice(&create, true).contains("create this instance"));
        assert!(approval_notice(&create, false).contains("creation fee"));
        assert!(approval_notice(&restore, true).contains("replace the instance's disk"));
        assert!(approval_notice(&restore, false).contains("replace the instance's disk"));
        for quote_above in [true, false] {
            assert_eq!(
                approval_notice(&BrowserOperation::Unknown, quote_above),
                UNKNOWN_OPERATION
            );
        }
    }

    /// The warning for a gateway tier an offering lists no price for names
    /// the tier as people say it, as the rest of the quote does.
    #[test]
    fn the_unlisted_gateway_warning_names_the_tier_in_words() {
        for (tier, words) in [
            (GatewayTier::SharedIp, "shared IP"),
            (GatewayTier::HighBandwidth, "high bandwidth"),
            (GatewayTier::SharedBandwidth, "shared bandwidth"),
        ] {
            let warning = unlisted_gateway_warning("of2_abc", tier);
            assert_eq!(
                warning,
                format!(
                    "offering of2_abc lists no {words} gateway right now, so its gateway charges are not known here; the backend decides whether it can still be rented"
                )
            );
            assert!(!warning.contains(&wire_name(tier)), "{warning}");
        }
        // An ID from the server is escaped.
        assert!(unlisted_gateway_warning("o\x1bx", GatewayTier::SharedIp).contains("o\\u{1b}x"));
    }

    /// A creation from a backup pays for the restore when it is accepted,
    /// and keeps paying it; a backup costs at most its volume's size at the
    /// creation price, and is kept and restored at the prices it records.
    #[tokio::test]
    async fn backup_charges_are_quoted_before_they_are_signed() {
        let quote = offering_quote(
            &listed_offering(HostMode::CloudRouted),
            None,
            Some(12_881),
            false,
        )
        .join("\n");
        assert!(
            quote.contains(
                "\n  Now          $0.13  creation fee, refunded if the creation fails unless you caused it\n             $0.0129  backup restore, not refunded\n"
            ),
            "{quote}"
        );
        let mut backup: BackupView = serde_json::from_value(backup_json(
            Uuid::now_v7(),
            Uuid::now_v7(),
            "local",
            "available",
        ))
        .unwrap();
        // 716.8 MiB is billed as 717 MiB, and the charge rounded up.
        assert_eq!(restore_charge(&backup), Some(7_002));
        assert_eq!(
            restore_quote(&backup, false).unwrap(),
            "  Now   $0.007  backup restore, not refunded"
        );
        backup.size_bytes = None;
        assert_eq!(restore_quote(&backup, false), None);

        let instance = json!({"instance_id": Uuid::nil(), "offering_id": "o", "hostname": "vm",
            "root_disk_bytes": 12_u64 << 30, "state": "running", "desired_power_state": "running",
            "holds_capacity": true, "network_microusd_per_tib": 0, "created_at": Utc::now(),
            "balance_reservation_microusd": 0});
        let prices = |creation: u64, storage: u64| {
            json!({"creation_charge_microusd_per_gib": creation,
                "restore_charge_microusd_per_gib": creation,
                "storage_charge_microusd_per_gib_month": storage})
        };
        let pricing = json!({"pricing_revision": 7, "hosted": prices(10_000, 30_000),
            "local": prices(2_000, 10_000), "billing_unit_bytes": 1_048_576,
            "balance_margin_microusd": 1_000_000});
        let api = canned_api(vec![
            (200, instance.to_string()),
            (200, pricing.to_string()),
        ])
        .await;
        let terms = backup_creation_terms(&api, Uuid::nil(), BackupDestinationArg::Hosted)
            .await
            .unwrap();
        assert_eq!(terms.pricing_revision, 7);
        assert_eq!(terms.maximum_charge_microusd, 120_000);
        assert_eq!(
            terms.quote,
            [
                "  Creation         $0.01/GiB  of the finished backup, at most $0.12 for the 12 GiB disk, charged when it is published, nothing if it fails or is cancelled",
                "  Storage    $0.03/GiB-month  while it is kept",
                "  Restore          $0.01/GiB  when you restore it",
            ]
            .join("\n")
        );
    }

    /// Creation reads the offering first: a malformed ID stops it, and one the catalog does not
    /// list right now only warns. A read with the account key that gets a server error is read
    /// again without it.
    #[tokio::test]
    async fn instance_create_quotes_the_offering_before_it_rents() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let image = Uuid::now_v7().to_string();
        let job_id = Uuid::now_v7();
        let accepted = json!({"job_id": job_id, "resource_id": Uuid::now_v7(),
            "status_url": format!("/v1/jobs/{job_id}")})
        .to_string();
        let offering = serde_json::to_string(&listed_offering(HostMode::CloudRouted)).unwrap();
        let malformed = json!({"code": "invalid_offering_token",
            "message": "offering_id is not a valid offering ID"})
        .to_string();
        let (url, received) = canned_server(vec![
            (200, offering),
            (202, accepted.clone()),
            (400, malformed),
            (503, "overloaded".to_owned()),
            (503, "overloaded".to_owned()),
            (202, accepted),
        ])
        .await;
        let create = |offering: &str| {
            account_command(
                &url,
                &seed,
                &[
                    "instance",
                    "create",
                    "--offering",
                    offering,
                    "--image",
                    &image,
                    "--ssh-key",
                    TEST_PUBLIC_KEY,
                ],
            )
        };
        let listed = "of2_J7hnuv_uO8PmXACeyas4QY";
        assert_eq!(
            execute(&create(listed)).await.unwrap()["job_id"],
            job_id.to_string()
        );
        let error = execute(&create("garbage")).await.unwrap_err();
        assert_eq!(api::rejection_code(&error), Some("invalid_offering_token"));
        // Nothing that is not base64url reaches the URL path.
        let error = execute(&create("../../account")).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "offering ../../account is not an offering ID; copy one from `ghost catalog offerings`"
        );
        assert_eq!(
            execute(&create(listed)).await.unwrap()["job_id"],
            job_id.to_string()
        );
        let lines = received
            .lock()
            .unwrap()
            .iter()
            .map(|(line, _)| {
                line.split_whitespace()
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            lines,
            [
                format!("GET /v1/catalog/offerings/{listed}"),
                "POST /api/mut/v1/instances".to_owned(),
                "GET /v1/catalog/offerings/garbage".to_owned(),
                format!("GET /v1/catalog/offerings/{listed}"),
                format!("GET /v1/catalog/offerings/{listed}"),
                "POST /api/mut/v1/instances".to_owned(),
            ]
        );
    }

    /// A hostname the backend would refuse is refused as the command line
    /// is read, for a creation and a reinstall alike.
    #[test]
    fn a_hostname_is_checked_as_the_backend_checks_it() {
        let instance = Uuid::nil().to_string();
        for (hostname, valid) in [
            ("web-1.example", true),
            ("a", true),
            ("Tomas_Bad", false),
            ("Web-1", false),
            ("-web", false),
            ("web..example", false),
        ] {
            for command in [
                &[
                    "instance",
                    "create",
                    "--offering",
                    "o",
                    "--image",
                    "debian-13",
                ][..],
                &["instance", "reinstall", &instance, "--image", "debian-13"],
            ] {
                let parsed = Cli::try_parse_from(
                    ["ghost"]
                        .iter()
                        .chain(command)
                        .chain(&["--hostname", hostname]),
                );
                assert_eq!(parsed.is_ok(), valid, "{hostname} {command:?}");
            }
        }
    }

    /// An instance's name follows the rules of a hostname, at the creation
    /// and in a rename alike; `instance rename` sends it and answers the
    /// instance, no job.
    #[tokio::test]
    async fn an_instance_is_named_by_the_rules_of_a_hostname() {
        let instance = Uuid::now_v7().to_string();
        for (name, valid) in [
            ("shop", true),
            ("web-1.example", true),
            ("Shop", false),
            ("my shop", false),
            ("-web", false),
            ("", false),
        ] {
            let create = Cli::try_parse_from([
                "ghost",
                "instance",
                "create",
                "--offering",
                "o",
                "--image",
                "debian-13",
                "--name",
                name,
            ]);
            assert_eq!(create.is_ok(), valid, "create {name:?}");
            let rename = Cli::try_parse_from(["ghost", "instance", "rename", &instance, name]);
            assert_eq!(rename.is_ok(), valid, "rename {name:?}");
        }

        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let renamed = json!({"instance_id": instance, "offering_id": "o", "hostname": "web-1",
            "name": "shop", "root_disk_bytes": 12_u64 << 30, "state": "running",
            "desired_power_state": "running", "holds_capacity": true, "public_ipv4": null,
            "network_microusd_per_tib": 0, "created_at": Utc::now(),
            "balance_reservation_microusd": 0});
        let (url, received) = canned_server(vec![(200, renamed.to_string())]).await;
        let result = execute(&account_command(
            &url,
            &seed,
            &["instance", "rename", &instance, "shop"],
        ))
        .await
        .unwrap();
        assert_eq!(result["name"], "shop");
        assert_eq!(result["hostname"], "web-1");
        assert_eq!(
            request_lines(&received),
            [format!("POST /api/mut/v1/instances/{instance}/rename")]
        );
        let body: Value = serde_json::from_slice(&received.lock().unwrap()[0].1).unwrap();
        assert_eq!(body, json!({"name": "shop"}));
    }

    /// `ghost instance tag` adds and removes tags by the rule the API
    /// takes, `ghost instance tags` lists the account's, and a creation
    /// sends its tags, none without --tag, an empty list with --no-tags.
    #[tokio::test]
    async fn instance_tags_are_added_removed_and_listed() {
        let instance = Uuid::now_v7().to_string();
        for (arguments, valid) in [
            (
                &[
                    "ghost", "instance", "tag", &instance, "add", "env:prod", "web",
                ][..],
                true,
            ),
            (
                &["ghost", "instance", "tag", &instance, "remove", "web"],
                true,
            ),
            (&["ghost", "instance", "tag", &instance, "add"], false),
            (
                &["ghost", "instance", "tag", &instance, "add", "Prod"],
                false,
            ),
            (
                &["ghost", "instance", "tag", &instance, "rename", "web"],
                false,
            ),
            (
                &[
                    "ghost",
                    "instance",
                    "create",
                    "--offering",
                    "o",
                    "--image",
                    "debian-13",
                    "--tag",
                    "a b",
                ],
                false,
            ),
            (
                &[
                    "ghost",
                    "instance",
                    "create",
                    "--offering",
                    "o",
                    "--backup",
                    &instance,
                    "--tag",
                    "a",
                    "--no-tags",
                ],
                false,
            ),
        ] {
            assert_eq!(
                Cli::try_parse_from(arguments).is_ok(),
                valid,
                "{arguments:?}"
            );
        }
        assert!(parse_tag("env:prod").is_ok());
        assert_eq!(
            parse_tag("Prod").unwrap_err(),
            format!("must be a tag: {TAG_RULE}")
        );

        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let tagged = json!({"instance_id": instance, "offering_id": "o", "hostname": "web-1",
            "name": "web-1", "tags": ["env:prod", "web"], "root_disk_bytes": 12_u64 << 30,
            "state": "running", "desired_power_state": "running", "holds_capacity": true,
            "public_ipv4": null, "network_microusd_per_tib": 0, "created_at": Utc::now(),
            "balance_reservation_microusd": 0});
        let tags = json!([{"tag": "env:prod", "instance_count": 2, "redundant": true}]);
        let flagged = json!({"tag": "env:prod", "instance_count": 2, "redundant": true});
        let (url, received) = canned_server(vec![
            (200, tagged.to_string()),
            (200, tagged.to_string()),
            (200, tags.to_string()),
            (200, flagged.to_string()),
            (200, flagged.to_string()),
        ])
        .await;
        let result = execute(&account_command(
            &url,
            &seed,
            &["instance", "tag", &instance, "add", "env:prod", "web"],
        ))
        .await
        .unwrap();
        assert_eq!(result["tags"], json!(["env:prod", "web"]));
        execute(&account_command(
            &url,
            &seed,
            &["instance", "tag", &instance, "remove", "old"],
        ))
        .await
        .unwrap();
        let listed = execute(&account_command(&url, &seed, &["instance", "tags"]))
            .await
            .unwrap();
        assert_eq!(listed, tags);
        // A tag marked redundant and cleared: its colon encoded in the path.
        for state in ["on", "off"] {
            let result = execute(&account_command(
                &url,
                &seed,
                &["instance", "tag", "redundant", "env:prod", state],
            ))
            .await
            .unwrap();
            assert_eq!(result, flagged);
        }
        assert_eq!(
            request_lines(&received),
            [
                format!("POST /api/mut/v1/instances/{instance}/tags"),
                format!("POST /api/mut/v1/instances/{instance}/tags"),
                "GET /v1/instances/tags".to_owned(),
                "POST /api/mut/v1/instances/tags/env%3Aprod/redundant".to_owned(),
                "POST /api/mut/v1/instances/tags/env%3Aprod/redundant".to_owned(),
            ]
        );
        let flags: Vec<Value> = received.lock().unwrap()[3..]
            .iter()
            .map(|request| serde_json::from_slice(&request.1).unwrap())
            .collect();
        assert_eq!(
            flags,
            [json!({"redundant": true}), json!({"redundant": false})]
        );
        // A tag that is none is refused before anything is sent, and an
        // instance's tags still need the action and a tag.
        for words in [
            &["instance", "tag", "redundant", "Prod", "on"][..],
            &["instance", "tag", "redundant", "web", "maybe"],
            &["instance", "tag", "web-1", "add"],
            &["instance", "tag", "web-1"],
        ] {
            assert!(
                Cli::try_parse_from(std::iter::once("ghost").chain(words.iter().copied())).is_err(),
                "{words:?}"
            );
        }
        let bodies: Vec<Value> = received.lock().unwrap()[..2]
            .iter()
            .map(|request| serde_json::from_slice(&request.1).unwrap())
            .collect();
        assert_eq!(
            bodies,
            [
                json!({"add": ["env:prod", "web"]}),
                json!({"remove": ["old"]})
            ]
        );
        // The readable list names each tag with its count, and the
        // instances' table shows their tags.
        let table = Summary::tags(serde_json::from_value(tags).unwrap());
        assert_eq!(table.columns, ["tag", "instance_count", "redundant"]);
        assert_eq!(table.rows[0]["redundant"], "yes");
        let instances = Summary::instances(vec![serde_json::from_value(tagged).unwrap()]);
        assert_eq!(instances.columns[..3], ["instance_id", "name", "tags"]);
        assert_eq!(instances.rows[0]["tags"], "env:prod, web");
    }

    /// A gateway tier a listed offering cannot take, or a backup larger
    /// than its root disk, is refused before its charges are printed and
    /// before anything is rented; a tier it does not list now is only
    /// warned about.
    #[tokio::test]
    async fn rental_mistakes_are_refused_before_the_charges() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let image = Uuid::now_v7().to_string();
        let offering_id = "of2_J7hnuv_uO8PmXACeyas4QY";
        let cloud = serde_json::to_string(&listed_offering(HostMode::CloudRouted)).unwrap();
        let home = serde_json::to_string(&listed_offering(HostMode::HomeGateway)).unwrap();
        let mut shared_only = listed_offering(HostMode::HomeGateway);
        shared_only.network_prices.truncate(1);
        let (backup_id, source) = (Uuid::now_v7(), Uuid::now_v7());
        let mut backup = backup_json(backup_id, source, "local", "available");
        backup["disk_bytes"] = json!(96_u64 << 30);
        let job_id = Uuid::now_v7();
        let accepted = json!({"job_id": job_id, "resource_id": Uuid::now_v7(),
            "status_url": format!("/v1/jobs/{job_id}")});
        let (url, received) = canned_server(vec![
            (200, cloud),
            (200, home),
            (200, backup.to_string()),
            (
                200,
                serde_json::to_string(&listed_offering(HostMode::CloudRouted)).unwrap(),
            ),
            (200, serde_json::to_string(&shared_only).unwrap()),
            (202, accepted.to_string()),
        ])
        .await;
        let create = async |extra: &[&str]| {
            let mut arguments = vec!["instance", "create", "--offering", offering_id];
            arguments.extend_from_slice(extra);
            execute(&account_command(&url, &seed, &arguments)).await
        };
        let key = ["--image", &image, "--ssh-key", TEST_PUBLIC_KEY];
        let tiered = [&key[..], &["--gateway-tier", "high_bandwidth"]].concat();
        let error = create(&tiered).await.unwrap_err().to_string();
        assert_eq!(
            error,
            format!(
                "offering {offering_id} is on a cloud host, which needs no gateway.\nTo rent it, leave out --gateway-tier high_bandwidth.\nTo share the host's address instead: --gateway-tier shared_ip"
            )
        );
        let error = create(&key).await.unwrap_err().to_string();
        assert!(
            error.starts_with(&format!(
                "offering {offering_id} is on a home host, which a hosted gateway connects.\nTo choose its tier, give --gateway-tier:\n  shared bandwidth (--gateway-tier shared_bandwidth)  $10.24/TiB + $5.00/month\n  high bandwidth (--gateway-tier high_bandwidth)"
            )),
            "{error}"
        );
        let backup_text = backup_id.to_string();
        let error = create(&["--backup", &backup_text]).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "offering {offering_id} has a 48 GiB root disk, smaller than the 96 GiB disk of backup {backup_id}; find an offering that can take it with `ghost catalog offerings --for-backup {backup_id}`"
            )
        );
        let created = create(&tiered).await.unwrap();
        assert_eq!(created["job_id"], job_id.to_string());
        let offering = format!("GET /v1/catalog/offerings/{offering_id}");
        assert_eq!(
            request_lines(&received),
            [
                offering.clone(),
                offering.clone(),
                format!("GET /v1/backups/{backup_id}"),
                offering.clone(),
                offering,
                "POST /api/mut/v1/instances".to_owned(),
            ]
        );
    }

    /// A reinstall says first that it starts a stopped instance, and goes
    /// ahead when the instance cannot be read; without --yes it says both
    /// what it destroys and that it starts the instance.
    #[tokio::test]
    async fn a_reinstall_says_it_starts_a_stopped_instance() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let (instance_id, job_id) = (Uuid::now_v7(), Uuid::now_v7());
        let instance = |state: &str, desired: &str| {
            json!({"instance_id": instance_id, "offering_id": "o", "hostname": "vm",
                "root_disk_bytes": 12_u64 << 30, "state": state, "desired_power_state": desired,
                "holds_capacity": true, "network_microusd_per_tib": 0, "created_at": Utc::now(),
                "balance_reservation_microusd": 0})
        };
        let view = |state, desired| -> InstanceView {
            serde_json::from_value(instance(state, desired)).unwrap()
        };
        assert_eq!(
            reinstall_start_note(&view("stopped", "stopped")).unwrap(),
            format!("Instance {instance_id} is stopped. The reinstall starts it.")
        );
        // A stop asked for that has not finished is no stopped instance.
        assert_eq!(
            reinstall_start_note(&view("running", "stopped")).unwrap(),
            format!("Instance {instance_id} is stopping. The reinstall starts it again.")
        );
        assert!(reinstall_start_note(&view("stopped", "running")).is_none());
        assert!(reinstall_start_note(&view("running", "running")).is_none());

        let accepted = json!({"job_id": job_id, "resource_id": instance_id,
            "status_url": format!("/v1/jobs/{job_id}")});
        let (url, received) = canned_server(vec![
            (200, instance("stopped", "stopped").to_string()),
            (202, accepted.to_string()),
            (
                404,
                json!({"code": "not_found", "message": "instance not found"}).to_string(),
            ),
            (202, accepted.to_string()),
        ])
        .await;
        let (id, image) = (instance_id.to_string(), Uuid::now_v7().to_string());
        let reinstall = |confirm: &[&str]| {
            let mut arguments = vec!["instance", "reinstall", &id, "--image", &image];
            arguments.extend_from_slice(&["--ssh-key", TEST_PUBLIC_KEY]);
            arguments.extend_from_slice(confirm);
            account_command(&url, &seed, &arguments)
        };
        for _ in 0..2 {
            let result = execute(&reinstall(&["--yes"])).await.unwrap();
            assert_eq!(result["job_id"], job_id.to_string());
        }
        let refused = execute(&reinstall(&[])).await.unwrap_err();
        assert_eq!(
            refused.to_string(),
            "reinstall destroys the current root filesystem and starts the instance if it is stopped; repeat with --yes"
        );
        let read = format!("GET /v1/instances/{id}");
        let post = format!("POST /api/mut/v1/instances/{id}/reinstall");
        assert_eq!(request_lines(&received), [&*read, &post, &read, &post]);
    }

    /// `instance rescue` sends the keys given with --ssh-key and none of
    /// the saved ones, or every saved key when none is given; `--exit`
    /// sends the end of the rescue with no body, and takes no keys. While
    /// the instance is in rescue, `instance get` names the rescue system's
    /// host key, the command that logs in checking it, and how to end it,
    /// and the list shows its state as rescue.
    #[tokio::test]
    async fn a_rescue_sends_its_keys_its_exit_ends_it_and_get_tells_how_to_log_in() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let (instance_id, job_id) = (Uuid::now_v7(), Uuid::now_v7());
        let accepted = json!({"job_id": job_id, "resource_id": instance_id,
            "status_url": format!("/v1/jobs/{job_id}")});
        let (url, received) = canned_server(vec![
            (202, accepted.to_string()),
            (202, accepted.to_string()),
            (202, accepted.to_string()),
        ])
        .await;
        let id = instance_id.to_string();
        let given = execute(&account_command(
            &url,
            &seed,
            &["instance", "rescue", &id, "--ssh-key", TEST_PUBLIC_KEY],
        ))
        .await
        .unwrap();
        assert_eq!(given["job_id"], job_id.to_string());
        execute(&account_command(&url, &seed, &["instance", "rescue", &id]))
            .await
            .unwrap();
        execute(&account_command(
            &url,
            &seed,
            &["instance", "rescue", &id, "--exit"],
        ))
        .await
        .unwrap();
        let rescue = format!("POST /api/mut/v1/instances/{id}/rescue");
        let exit = format!("POST /api/mut/v1/instances/{id}/rescue/exit");
        assert_eq!(request_lines(&received), [&*rescue, &rescue, &exit]);
        let bodies: Vec<Vec<u8>> = received
            .lock()
            .unwrap()
            .iter()
            .map(|(_, body)| body.clone())
            .collect();
        let json_of = |body: &[u8]| serde_json::from_slice::<Value>(body).unwrap();
        assert_eq!(
            json_of(&bodies[0]),
            json!({"ssh_key_ids": [], "ssh_public_keys": [TEST_PUBLIC_KEY]})
        );
        assert_eq!(json_of(&bodies[1]), json!({}));
        assert!(
            bodies[2].is_empty() || json_of(&bodies[2]).is_null(),
            "{:?}",
            String::from_utf8_lossy(&bodies[2])
        );
        assert!(
            Cli::try_parse_from([
                "ghost",
                "instance",
                "rescue",
                &id,
                "--exit",
                "--ssh-key",
                TEST_PUBLIC_KEY
            ])
            .is_err(),
            "an exit takes no keys"
        );

        let rescued: InstanceView = serde_json::from_value(json!({"instance_id": instance_id,
            "offering_id": "o", "hostname": "vm", "root_disk_bytes": 12_u64 << 30,
            "state": "running", "desired_power_state": "running", "holds_capacity": true,
            "network_microusd_per_tib": 0, "created_at": Utc::now(),
            "balance_reservation_microusd": 0, "public_ipv4": "203.0.113.7",
            "rescue": {"started_at": "2026-10-26T08:00:00Z",
                "host_key_public": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g",
                "host_key_fingerprint": "SHA256:abc\u{1b}[2J", "rescue_release": "13.7-r1"}}))
        .unwrap();
        assert_eq!(
            rescue_notes_with(&rescued, Ok("ssh -o HostKeyAlias=a root@203.0.113.7".to_owned())),
            [
                "The instance is in rescue: it runs the rescue system 13.7-r1 with its disk as /dev/vda; `mount-guest` mounts it at /mnt.".to_owned(),
                "Rescue system's host key: SHA256:abc\\u{1b}[2J".to_owned(),
                "Log in: ssh -o HostKeyAlias=a root@203.0.113.7".to_owned(),
                format!("End the rescue: ghost instance rescue {id} --exit"),
            ]
        );
        let mut own = rescued.clone();
        own.rescue = None;
        assert!(rescue_notes_with(&own, Ok(String::new())).is_empty());
        let summary = Summary::instances(vec![rescued, own]);
        assert_eq!(summary.rows[0]["state"], "rescue");
        assert_eq!(summary.rows[1]["state"], "running");
    }

    /// `instance reset-access` sends the keys given with --ssh-key, and
    /// none of the saved ones, or every saved key when none is given, and
    /// whether to stop the firewall; `instance get` tells what the guest
    /// reported of the latest reset, or that it reported nothing.
    #[tokio::test]
    async fn a_reset_of_access_sends_its_keys_and_get_tells_its_report() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let (instance_id, job_id) = (Uuid::now_v7(), Uuid::now_v7());
        let accepted = json!({"job_id": job_id, "resource_id": instance_id,
            "status_url": format!("/v1/jobs/{job_id}")});
        let (url, received) = canned_server(vec![
            (202, accepted.to_string()),
            (202, accepted.to_string()),
        ])
        .await;
        let id = instance_id.to_string();
        let given = execute(&account_command(
            &url,
            &seed,
            &[
                "instance",
                "reset-access",
                &id,
                "--ssh-key",
                TEST_PUBLIC_KEY,
                "--firewall",
            ],
        ))
        .await
        .unwrap();
        assert_eq!(given["job_id"], job_id.to_string());
        execute(&account_command(
            &url,
            &seed,
            &["instance", "reset-access", &id],
        ))
        .await
        .unwrap();
        let post = format!("POST /api/mut/v1/instances/{id}/reset-access");
        assert_eq!(request_lines(&received), [&*post, &post]);
        let bodies: Vec<Value> = received
            .lock()
            .unwrap()
            .iter()
            .map(|(_, body)| serde_json::from_slice(body).unwrap())
            .collect();
        assert_eq!(
            bodies,
            [
                json!({"ssh_key_ids": [], "ssh_public_keys": [TEST_PUBLIC_KEY], "firewall": true}),
                json!({"firewall": false}),
            ]
        );

        let view = |reset: Value| -> InstanceView {
            serde_json::from_value(json!({"instance_id": instance_id, "offering_id": "o",
                "hostname": "vm", "root_disk_bytes": 12_u64 << 30, "state": "running",
                "desired_power_state": "running", "holds_capacity": true,
                "network_microusd_per_tib": 0, "created_at": Utc::now(),
                "balance_reservation_microusd": 0, "access_reset": reset}))
            .unwrap()
        };
        let reset = |state: &str, steps: Value| {
            json!({"job_id": job_id, "requested_at": "2026-10-26T08:00:00Z", "firewall": false,
                "state": state, "steps": steps})
        };
        assert!(access_reset_notes(&view(Value::Null)).is_empty());
        assert_eq!(
            access_reset_notes(&view(reset("pending", Value::Null))),
            ["The SSH access reset of 2026-10-26 08:00 UTC has no report from the guest yet."]
        );
        assert_eq!(
            access_reset_notes(&view(reset("not_reached", Value::Null))),
            [
                "warning: the guest reported nothing of the SSH access reset of 2026-10-26 08:00 UTC.",
                "It has no cloud-init, has it turned off, or did not reach its userspace; a rescue boot is the other way in.",
            ]
        );
        assert_eq!(
            access_reset_notes(&view(reset(
                "reported",
                json!({"keys": "ok: 1 added", "sshd": "failed: no ssh or sshd service\u{1b}[2J",
                    "sshd_test": "ok"})
            ))),
            [
                "warning: the SSH access reset of 2026-10-26 08:00 UTC failed in part:",
                "  keys: ok: 1 added",
                "  sshd: failed: no ssh or sshd service\\u{1b}[2J",
                "  sshd -t: ok",
            ]
        );
        assert_eq!(
            access_reset_notes(&view(reset("reported", json!({"unreadable": true})))),
            [
                "warning: the guest's report of the SSH access reset of 2026-10-26 08:00 UTC could not be read."
            ]
        );
    }

    /// `instance create --wait` waits for cloud-init in the new guest to
    /// report, warns of what it found wrong, and ends with where the new
    /// instance can be reached; other commands, a creation not waited for
    /// or one that failed, and `--compact` end with their result.
    #[tokio::test]
    async fn a_waited_creation_ends_with_cloud_init_and_the_instance_address() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let seed = seed.to_str().unwrap();
        let (instance_id, job_id) = (Uuid::now_v7(), Uuid::now_v7());
        let instance = json!({"instance_id": instance_id, "offering_id": "o",
            "hostname": "web-1", "root_disk_bytes": 12_u64 << 30, "state": "running",
            "desired_power_state": "running", "holds_capacity": true,
            "public_ipv4": "203.0.113.7", "network_microusd_per_tib": 0,
            "created_at": Utc::now(), "balance_reservation_microusd": 0});
        let mut reported = instance.clone();
        reported["guest_initialization"] = json!({"status": "error",
            "messages": ["error: ('scripts_user', RuntimeError('Runparts: 1 failures'))\u{1b}[2J"],
            "reported_at": Utc::now()});
        let (url, received) = canned_server(vec![
            (200, instance.to_string()),
            (200, reported.to_string()),
        ])
        .await;
        let job = |state: &str| {
            json!({"job_id": job_id, "kind": "create_instance", "state": state,
                "resource_id": instance_id})
        };
        let create = |format: &[&str], wait: &[&str]| {
            let mut arguments = vec!["ghost", "--api-url", &url, "--seed-file", seed];
            arguments.extend_from_slice(format);
            arguments.extend_from_slice(&["instance", "create", "--offering", "o"]);
            arguments.extend_from_slice(&["--image", "debian-13"]);
            arguments.extend_from_slice(wait);
            Cli::try_parse_from(arguments).unwrap()
        };
        assert_eq!(
            closing_notes(
                &create(&["--json"], &["--wait", "--poll-seconds", "1"]),
                &job("succeeded")
            )
            .await,
            [
                format!("Instance {instance_id} (web-1) is running."),
                "  Address   203.0.113.7".to_owned(),
                "warning: cloud-init in the guest reported errors.".to_owned(),
                "  - error: ('scripts_user', RuntimeError('Runparts: 1 failures'))\\u{1b}[2J"
                    .to_owned(),
                "To see more:".to_owned(),
                "  In the guest: cloud-init status --long".to_owned(),
                format!("  On your machine: ghost instance console-log {instance_id}"),
            ]
        );
        for (cli, job) in [
            (create(&[], &["--wait"]), job("failed")),
            (create(&[], &[]), job("succeeded")),
            (create(&["--compact"], &["--wait"]), job("succeeded")),
        ] {
            assert!(closing_notes(&cli, &job).await.is_empty());
        }
        assert_eq!(
            request_lines(&received),
            [
                format!("GET /v1/instances/{instance_id}"),
                format!("GET /v1/instances/{instance_id}")
            ]
        );
        let mut view: InstanceView = serde_json::from_value(instance).unwrap();
        view.public_ipv4 = None;
        assert_eq!(
            created_instance_note(&view, false),
            [
                format!("Instance {instance_id} (web-1) is running."),
                "It has no public IPv4 address yet.".to_owned()
            ]
        );
        assert_eq!(
            guest_initialization_notes(&view),
            [
                "cloud-init in the guest has not reported yet.".to_owned(),
                format!("To see its result once it has: ghost instance get {instance_id}")
            ]
        );
        view.guest_initialization = serde_json::from_value(json!({"status": "done",
            "messages": [], "reported_at": Utc::now()}))
        .unwrap();
        assert_eq!(
            guest_initialization_notes(&view),
            ["cloud-init in the guest is done."]
        );
    }

    /// The wait for cloud-init ends when its time is up, and a failed read
    /// does not end it before.
    #[tokio::test]
    async fn the_wait_for_cloud_init_ends_in_time() {
        let instance_id = Uuid::now_v7();
        let instance = json!({"instance_id": instance_id, "offering_id": "o",
            "hostname": "web-1", "root_disk_bytes": 12_u64 << 30, "state": "running",
            "desired_power_state": "running", "holds_capacity": true,
            "public_ipv4": null, "network_microusd_per_tib": 0,
            "created_at": Utc::now(), "balance_reservation_microusd": 0});
        let (url, received) = canned_server(vec![
            (
                503,
                json!({"code": "unavailable", "message": "down"}).to_string(),
            ),
            (200, instance.to_string()),
        ])
        .await;
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let cli = account_command(&url, &seed, &["instance", "get", &instance_id.to_string()]);
        let api = api_client(&cli).unwrap().with_read_retry_delays(&[]);
        let started = tokio::time::Instant::now();
        let waited = await_guest_initialization(
            &api,
            serde_json::from_value(instance).unwrap(),
            Duration::from_millis(200),
            Duration::from_millis(1500),
        )
        .await;
        assert!(waited.guest_initialization.is_none());
        assert!(started.elapsed() >= Duration::from_millis(1500));
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(request_lines(&received).len() >= 2);
    }

    /// `instance get` shows cloud-init's result for the guest's latest boot
    /// in a section of its own.
    #[test]
    fn an_instance_shows_its_guests_cloud_init_result() {
        let instance_id = Uuid::now_v7();
        let output = json!({"instance_id": instance_id, "offering_id": "o",
            "hostname": "web-1", "root_disk_bytes": 12_u64 << 30, "state": "running",
            "desired_power_state": "running", "holds_capacity": true,
            "public_ipv4": "203.0.113.7", "network_microusd_per_tib": 0,
            "created_at": "2026-09-30T09:00:00Z", "balance_reservation_microusd": 0,
            "guest_initialization": {"status": "degraded",
                "messages": ["warning: Failed to set the hostname"],
                "reported_at": "2026-09-30T09:01:02Z"}});
        let cli =
            Cli::try_parse_from(["ghost", "instance", "get", &instance_id.to_string()]).unwrap();
        let text = render_result(&cli, &output, Terminal::plain());
        let section = text
            .split_once("==> guest_initialization")
            .map(|(_, section)| words(section))
            .unwrap_or_default();
        for line in [
            &["status", "degraded"][..],
            &[
                "messages", "warning:", "Failed", "to", "set", "the", "hostname",
            ],
            &["reported_at", "2026-09-30", "09:01:02", "UTC"],
        ] {
            assert!(section.contains(&line.to_vec()), "{text}");
        }
    }

    /// `instance console-log` asks for the bytes it is given and shows the
    /// output as the guest's lines, without what would restyle a terminal,
    /// and then when it was sent; `--json` has it as the guest wrote it.
    #[tokio::test]
    async fn the_console_log_shows_the_guests_lines() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let instance_id = Uuid::now_v7();
        let console = json!({"instance_id": instance_id, "hostname": "web-1",
            "output": "[\u{1b}[0;32m  OK  \u{1b}[0m] Started\r\n\u{1b}]0;title\u{7}login: \n",
            "truncated": true, "updated_at": "2026-09-30T10:00:00Z", "previous_boot": null});
        let (url, received) = canned_server(vec![(200, console.to_string())]).await;
        let id = instance_id.to_string();
        let cli = account_command(
            &url,
            &seed,
            &["instance", "console-log", &id, "--bytes", "4096"],
        );
        let output = execute(&cli).await.unwrap();
        assert_eq!(output, console);
        assert_eq!(
            request_lines(&received),
            [format!("GET /v1/instances/{id}/console-log?bytes=4096")]
        );
        assert_eq!(
            render_result(&cli, &output, Terminal::plain()),
            "[  OK  ] Started\nlogin: "
        );
        assert_eq!(
            closing_notes(&cli, &output).await,
            [format!(
                "the end of instance {id}'s console output as its host sent it at 2026-09-30 10:00:00 UTC; older output precedes it"
            )]
        );
        let json = account_command(&url, &seed, &["--json", "instance", "console-log", &id]);
        assert!(closing_notes(&json, &output).await.is_empty());
        assert!(
            render_result(&json, &output, Terminal::plain()).contains("\\u001b[0;32m"),
            "--json keeps the output as the guest wrote it"
        );
        let nothing: InstanceConsoleLogView = serde_json::from_value(json!({
            "instance_id": instance_id, "output": "", "truncated": false, "updated_at": null}))
        .unwrap();
        assert!(console_log_note(&nothing).contains("has sent none of its console output yet"));

        // After a reset, the end of the boot before comes first.
        let mut restarted = console.clone();
        restarted["truncated"] = json!(false);
        restarted["previous_boot"] = json!({
            "output": "[   42.1] Kernel panic - not syncing: sysrq triggered crash\r\n\u{1b}[0m",
            "truncated": true});
        assert_eq!(
            render_result(&cli, &restarted, Terminal::plain()),
            "[   42.1] Kernel panic - not syncing: sysrq triggered crash\n--- the platform started the instance again here ---\n[  OK  ] Started\nlogin: "
        );
        assert_eq!(
            closing_notes(&cli, &restarted).await,
            [format!(
                "the end of instance {id}'s console output as its host sent it at 2026-09-30 10:00:00 UTC: above the line, the end of what it wrote before the platform last started it again (older output left out); below, what it wrote since"
            )]
        );
        for bytes in ["0", "65537"] {
            assert!(
                Cli::try_parse_from(["ghost", "instance", "console-log", &id, "--bytes", bytes])
                    .is_err()
            );
        }
        assert_eq!(
            gigahost_client_api::website::MAXIMUM_CONSOLE_LOG_BYTES,
            65_536,
            "--bytes offers what the API returns"
        );
    }

    /// A hosted backup encrypted for another seed's recovery key is refused
    /// before anything is sent, with the key it needs and where to give the
    /// older seed after a migration, and with a code of its own.
    #[test]
    fn a_hosted_backup_of_another_seed_names_the_seed_it_needs() {
        let directory = tempfile::tempdir().unwrap();
        let (current, older) = (
            directory.path().join("account.seed"),
            directory.path().join("older.seed"),
        );
        keys::generate_seed(&current).unwrap();
        keys::generate_seed(&older).unwrap();
        let backup_id = Uuid::now_v7();
        let mut backup = backup_json(backup_id, Uuid::now_v7(), "gigahost_s3", "available");
        backup["recipient_key_fingerprint"] = json!("b3RoZXIgc2VlZA");
        backup["wrapped_data_key"] = json!("d3JhcHBlZA");
        let backup: BackupView = serde_json::from_value(backup).unwrap();
        let id = backup_id.to_string();
        let restore = |recovery: &[&str]| {
            let mut arguments = vec!["ghost", "--seed-file", current.to_str().unwrap()];
            arguments.extend_from_slice(recovery);
            arguments.extend_from_slice(&["backup", "restore", &id, "--yes"]);
            Cli::try_parse_from(arguments).unwrap()
        };
        let key = format!(
            "the key hosted backup {backup_id} was encrypted for (recipient key fingerprint b3RoZXIgc2VlZA)"
        );
        let error = backup_restore_credentials(&restore(&[]), &backup, "restore-key-0001")
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            format!(
                "this account key does not match {key}; a backup made before an account key migration needs the account key it was made with: pass that account key as --recovery-seed-file"
            )
        );
        assert_eq!(error_output(&error)["error"]["code"], RECOVERY_KEY_MISMATCH);
        let recovery = ["--recovery-seed-file", older.to_str().unwrap()];
        let error = backup_restore_credentials(&restore(&recovery), &backup, "restore-key-0001")
            .err()
            .unwrap();
        assert_eq!(
            error.to_string(),
            format!(
                "the --recovery-seed-file account key does not match {key}; `ghost --seed-file FILE key inspect` shows an account key's recovery_key_fingerprint"
            )
        );
        // `--json` names the refusal, which the backend never sees.
        assert_eq!(
            error_output(&error)["error"],
            json!({"code": "recovery_key_mismatch", "message": error.to_string(),
                   "status": null, "job_id": null, "request_id": null, "transient": false})
        );
    }

    #[tokio::test]
    async fn a_waiting_backup_is_cancelled_by_its_id() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let (backup_id, instance_id, job_id) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let backup = json!({"backup_id": backup_id, "instance_id": instance_id,
            "destination": "local", "status": "queued", "purpose": "regular",
            "funding_lifecycle_id": null, "size_bytes": null, "restore_pricing_revision": 1,
            "restore_charge_microusd_per_gib": 10_000, "storage_charge_microusd_per_gib_month": 20_000,
            "recipient_key_fingerprint": null, "wrapped_data_key": null,
            "created_at": Utc::now(), "completed_at": null})
        .to_string();
        let accepted = json!({"job_id": job_id, "resource_id": backup_id,
            "status_url": format!("/v1/jobs/{job_id}")});
        let started = json!({"code": "backup_started", "job_id": job_id,
            "message": format!("backup {backup_id} is queued and its creation is running")});
        let (url, received) = canned_server(vec![
            (200, backup.clone()),
            (200, accepted.to_string()),
            (200, backup),
            (409, started.to_string()),
        ])
        .await;
        let backup = backup_id.to_string();
        let cancel = account_command(&url, &seed, &["backup", "cancel", &backup]);
        let result = execute(&cancel).await.unwrap();
        assert_eq!(result["job_id"], job_id.to_string());
        // One its host has begun is refused, and the refusal is not retried.
        let error = execute(&cancel).await.unwrap_err();
        assert_eq!(api::rejection_code(&error), Some("backup_started"));
        let lines = received
            .lock()
            .unwrap()
            .iter()
            .map(|(line, _)| {
                line.split_whitespace()
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect::<Vec<_>>();
        let cancelled =
            format!("POST /api/mut/v1/instances/{instance_id}/backups/{backup_id}/cancel");
        let looked_up = format!("GET /v1/backups/{backup_id}");
        assert_eq!(
            lines,
            [looked_up.clone(), cancelled.clone(), looked_up, cancelled]
        );
    }

    #[tokio::test]
    async fn a_backup_is_deleted_by_its_id_alone() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let (backup_id, instance_id, job_id) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let backup = json!({"backup_id": backup_id, "instance_id": instance_id,
            "destination": "local", "status": "available", "purpose": "regular",
            "funding_lifecycle_id": null, "size_bytes": 1 << 30, "restore_pricing_revision": 1,
            "restore_charge_microusd_per_gib": 10_000, "storage_charge_microusd_per_gib_month": 20_000,
            "recipient_key_fingerprint": null, "wrapped_data_key": null,
            "created_at": Utc::now(), "completed_at": Utc::now()})
        .to_string();
        let accepted = json!({"job_id": job_id, "resource_id": backup_id,
            "status_url": format!("/v1/jobs/{job_id}")});
        let (url, received) = canned_server(vec![
            (200, backup.clone()),
            (202, accepted.to_string()),
            (200, backup),
        ])
        .await;
        let backup = backup_id.to_string();
        let result = execute(&account_command(
            &url,
            &seed,
            &["backup", "delete", &backup, "--yes"],
        ))
        .await
        .unwrap();
        assert_eq!(result["job_id"], job_id.to_string());
        // The older form still works, and a wrong instance is named.
        let other = Uuid::now_v7().to_string();
        let error = execute(&account_command(
            &url,
            &seed,
            &["backup", "delete", &other, &backup, "--yes"],
        ))
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("backup {backup_id} belongs to instance {instance_id}, not {other}")
        );
        let unconfirmed = execute(&account_command(
            &url,
            &seed,
            &["backup", "delete", &backup],
        ))
        .await
        .unwrap_err();
        assert_eq!(
            unconfirmed.to_string(),
            "backup deletion is irreversible; repeat with --yes"
        );
        let lines = received
            .lock()
            .unwrap()
            .iter()
            .map(|(line, _)| {
                line.split_whitespace()
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            lines,
            [
                format!("GET /v1/backups/{backup_id}"),
                format!("DELETE /api/mut/v1/instances/{instance_id}/backups/{backup_id}"),
                format!("GET /v1/backups/{backup_id}"),
            ]
        );
    }

    #[tokio::test]
    async fn job_list_sends_its_filters_as_the_query() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let (url, received) = canned_server(vec![
            (200, json!({"items": [], "next_cursor": null}).to_string()),
            (200, json!({"items": [], "next_cursor": null}).to_string()),
        ])
        .await;
        let instance = Uuid::now_v7().to_string();
        let page = execute(&account_command(
            &url,
            &seed,
            &[
                "job",
                "list",
                "--instance",
                &instance,
                "--state",
                "failed",
                "--kind",
                "create_backup",
                "--limit",
                "2",
                "--cursor",
                "next page",
            ],
        ))
        .await
        .unwrap();
        assert_eq!(page, json!({"items": [], "next_cursor": null}));
        execute(&account_command(&url, &seed, &["job", "list"]))
            .await
            .unwrap();
        let lines = received
            .lock()
            .unwrap()
            .iter()
            .map(|(line, _)| {
                line.split_whitespace()
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            lines,
            [
                format!(
                    "GET /v1/jobs?instance_id={instance}&state=failed&kind=create_backup&limit=2&cursor=next+page"
                ),
                "GET /v1/jobs?limit=50".to_owned(),
            ]
        );
    }

    #[tokio::test]
    async fn account_history_sends_its_filters_as_the_query() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let (url, received) = canned_server(vec![
            (200, json!({"items": [], "next_cursor": null}).to_string()),
            (200, json!({"items": [], "next_cursor": null}).to_string()),
        ])
        .await;
        let instance = Uuid::now_v7().to_string();
        let history = |arguments: &[&str]| {
            let mut command = vec!["account", "history"];
            command.extend_from_slice(arguments);
            account_command(&url, &seed, &command)
        };
        execute(&history(&[
            "--instance",
            &instance,
            "--kind",
            "backup_restore",
            "--limit",
            "5",
        ]))
        .await
        .unwrap();
        execute(&history(&[])).await.unwrap();
        let lines = received
            .lock()
            .unwrap()
            .iter()
            .map(|(line, _)| {
                line.split_whitespace()
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            lines,
            [
                format!(
                    "GET /v1/account/history?instance_id={instance}&kind=backup_restore&limit=5"
                ),
                "GET /v1/account/history?limit=50".to_owned(),
            ]
        );
    }

    /// `ghost catalog provider` reads the provider's offerings signed when there is an account key,
    /// like the website's provider page, so an allowed account's count includes the private ones.
    #[tokio::test]
    async fn the_catalog_provider_reads_its_offerings_signed() {
        let mut private = listed_offering(HostMode::CloudRouted);
        private.private = true;
        let offerings = serde_json::to_string(&[private]).unwrap();
        // The reliability and the reviews read at once, in either order:
        // one body serves both (the reviews are free-form).
        let reliability = json!({
            "provider_id": Uuid::nil(),
            "window_started_at": "2026-09-21T00:00:00Z",
            "window_ended_at": "2026-10-21T00:00:00Z",
            "observed_milliseconds": 0, "online_milliseconds": 0,
            "uptime_basis_points": null, "distinct_rented_instances": 0,
            "abandoned_instances": 0, "abandonment_basis_points": null,
        })
        .to_string();
        let (url, _, heads) = canned_server_recording_heads(vec![
            (200, String::new(), offerings),
            (200, String::new(), reliability.clone()),
            (200, String::new(), reliability),
        ])
        .await;
        let identity = keys::authentication_identity(&[3_u8; 32]).unwrap();
        let api = ApiClient::new(&url, Some(identity)).unwrap();
        let record = execute_catalog(
            &api,
            &CatalogCommand::Provider {
                provider: ProviderReference::Alias("gh-examples".to_owned()),
            },
        )
        .await
        .unwrap();
        assert_eq!(record["listed_offerings"], 1);
        let heads = heads.lock().unwrap();
        let signed = |head: &String| {
            head.to_ascii_lowercase()
                .contains(gigahost_client_api::account_auth::AUTH_KEY_ID_HEADER)
        };
        assert!(heads[0].contains("provider=gh-examples"));
        assert!(signed(&heads[0]), "the offerings read is signed");
    }

    /// With an account key the catalog's offerings are read signed (including private
    /// hosts' offerings its providers allow it), anonymous again when the backend does not take the
    /// key, and anonymous without one; a private offering has the list's private column, which is
    /// not there otherwise.
    #[tokio::test]
    async fn the_catalog_is_read_signed_when_there_is_an_account_key() {
        let unauthorized = json!({"code": "unauthorized", "message": "authentication required"});
        let mut private = listed_offering(HostMode::CloudRouted);
        private.private = true;
        let listed = serde_json::to_string(&[private.clone()]).unwrap();
        let (url, _, heads) = canned_server_recording_heads(vec![
            (200, String::new(), listed.clone()),
            (401, String::new(), unauthorized.to_string()),
            (200, String::new(), "[]".to_owned()),
            (200, String::new(), "[]".to_owned()),
        ])
        .await;
        let identity = keys::authentication_identity(&[3_u8; 32]).unwrap();
        let signed = ApiClient::new(&url, Some(identity)).unwrap();
        let read: Vec<OfferingView> = signed.read_as_account(&ListOfferings, "").await.unwrap();
        assert!(read[0].private);
        let read: Vec<OfferingView> = signed.read_as_account(&ListOfferings, "").await.unwrap();
        assert!(read.is_empty());
        let anonymous = ApiClient::new(&url, None).unwrap();
        let read: Vec<OfferingView> = anonymous.read_as_account(&ListOfferings, "").await.unwrap();
        assert!(read.is_empty());
        let signatures: Vec<bool> = heads
            .lock()
            .unwrap()
            .iter()
            .map(|head| {
                head.to_ascii_lowercase()
                    .contains(gigahost_client_api::account_auth::AUTH_KEY_ID_HEADER)
            })
            .collect();
        assert_eq!(signatures, [true, true, false, false]);

        let parse = |arguments: &[&str]| Cli::try_parse_from(["ghost"].iter().chain(arguments));
        let readable = render_result(
            &parse(&["catalog"]).unwrap(),
            &json!([private]),
            Terminal::plain(),
        );
        let (head, row) = readable.trim_start().split_once('\n').unwrap();
        assert!(head.contains("PRIVATE"), "{head}");
        assert!(row.contains("private"), "{row}");
        let readable = render_result(
            &parse(&["catalog"]).unwrap(),
            &json!([listed_offering(HostMode::CloudRouted)]),
            Terminal::plain(),
        );
        assert!(!readable.contains("PRIVATE"), "{readable}");
    }

    /// A signed read of the catalog that gets a server error is sent once and read again
    /// anonymously (the public answer, as the backend gives it through an outage);
    /// a refusal the anonymous read would get too is not.
    #[tokio::test]
    async fn the_catalog_is_read_anonymously_when_the_signed_read_is_not_answered() {
        let unavailable = json!({"code": "database_unavailable", "message": "try again"});
        let unknown = json!({"code": "not_found", "message": "listed offering not found"});
        let listed = serde_json::to_string(&[listed_offering(HostMode::CloudRouted)]).unwrap();
        let (url, _, heads) = canned_server_recording_heads(vec![
            (503, String::new(), unavailable.to_string()),
            (200, String::new(), listed),
            (404, String::new(), unknown.to_string()),
        ])
        .await;
        let identity = keys::authentication_identity(&[3_u8; 32]).unwrap();
        let signed = ApiClient::new(&url, Some(identity))
            .unwrap()
            .with_read_retry_delays(&[Duration::from_millis(1)]);
        let read: Vec<OfferingView> = signed.read_as_account(&ListOfferings, "").await.unwrap();
        assert_eq!(read.len(), 1);
        let refused = signed
            .read_as_account(
                &GetOffering {
                    offering_id: "of2_AAAAAAAAAAAAAAAAAAAAAA".to_owned(),
                },
                "",
            )
            .await
            .unwrap_err();
        assert_eq!(api::rejection_code(&refused), Some("not_found"));
        let signatures: Vec<bool> = heads
            .lock()
            .unwrap()
            .iter()
            .map(|head| {
                head.to_ascii_lowercase()
                    .contains(gigahost_client_api::account_auth::AUTH_KEY_ID_HEADER)
            })
            .collect();
        assert_eq!(signatures, [true, false, true]);
    }

    /// The catalog's filters go to the server, which refuses an unknown
    /// location rather than listing nothing for it.
    #[tokio::test]
    async fn offerings_in_an_unknown_location_are_an_error() {
        let unknown = json!({"code": "invalid_request",
            "message": "request body is invalid: unknown location code \"warsaw\""});
        let (url, received) =
            canned_server(vec![(400, unknown.to_string()), (200, "[]".to_owned())]).await;
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let offerings = |location: &str| {
            account_command(
                &url,
                &seed,
                &[
                    "catalog",
                    "offerings",
                    "--location",
                    location,
                    "--mode",
                    "home_gateway",
                ],
            )
        };
        let error = execute(&offerings("warsaw")).await.unwrap_err();
        assert!(
            error.to_string().contains("unknown location code"),
            "{error}"
        );
        assert_eq!(execute(&offerings("pl-warsaw")).await.unwrap(), json!([]));
        let lines = received
            .lock()
            .unwrap()
            .iter()
            .map(|(line, _)| {
                line.split_whitespace()
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect::<Vec<_>>();
        assert_eq!(
            lines,
            [
                "GET /v1/catalog/offerings?mode=home_gateway&kind=any&location=warsaw",
                "GET /v1/catalog/offerings?mode=home_gateway&kind=any&location=pl-warsaw",
            ]
        );
    }

    /// An instance as `ListInstances` lists it, created `age` minutes ago.
    fn listed_instance(instance_id: Uuid, name: &str, state: &str, age: i64) -> Value {
        json!({"instance_id": instance_id, "offering_id": "o", "hostname": "vm",
            "name": name, "root_disk_bytes": 12_u64 << 30, "state": state,
            "desired_power_state": "running", "holds_capacity": true,
            "network_microusd_per_tib": 0,
            "created_at": Utc::now() - chrono::Duration::minutes(age),
            "balance_reservation_microusd": 0})
    }

    #[test]
    fn an_instance_is_named_by_its_id_or_its_name() {
        let id = Uuid::now_v7();
        assert_eq!(
            parse_instance_reference(&id.to_string()),
            Ok(InstanceReference::Id(id))
        );
        assert_eq!(
            parse_instance_reference("Web-1.Example"),
            Ok(InstanceReference::Name("web-1.example".to_owned()))
        );
        for invalid in ["", "web_1", "-web", "web 1", "web..1"] {
            assert!(parse_instance_reference(invalid).is_err(), "{invalid}");
        }
        let help = Cli::try_parse_from(["ghost", "instance", "get", "web_1"])
            .err()
            .unwrap()
            .to_string();
        assert!(help.contains("instance ID or an instance's name"), "{help}");
    }

    #[tokio::test]
    async fn a_name_resolves_to_the_one_current_instance_of_that_name() {
        let (web, db, old_web) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let mut by_hostname = listed_instance(db, "", "stopped", 2);
        by_hostname["hostname"] = json!("db");
        let list = json!([
            listed_instance(web, "web-1", "running", 1),
            by_hostname,
            listed_instance(old_web, "web-1", "deleted", 3),
        ])
        .to_string();
        let api = canned_api(vec![(200, list.clone()), (200, list)]).await;
        let name = |name: &str| InstanceReference::Name(name.to_owned());
        assert_eq!(
            resolve_instance(&api, &name("WEB-1"), InstanceUse::Read)
                .await
                .unwrap(),
            web
        );
        assert_eq!(
            resolve_instance(&api, &name("db"), InstanceUse::Change)
                .await
                .unwrap(),
            db
        );
        // Known gap: `resolve_instance` writes the notice to standard error
        // itself, so only the notice's text is checked here, not that a
        // change prints it.
        assert_eq!(
            named_instance_notice("db", db),
            format!("instance db is {db}")
        );
    }

    #[tokio::test]
    async fn a_name_no_or_several_instances_have_is_refused() {
        let (newer, older) = (Uuid::now_v7(), Uuid::now_v7());
        let list = json!([
            listed_instance(newer, "web-1", "running", 1),
            listed_instance(older, "web-1", "stopped", 2),
        ])
        .to_string();
        let api = canned_api(vec![(200, list.clone()), (200, list)]).await;
        let name = |name: &str| InstanceReference::Name(name.to_owned());

        let error = resolve_instance(&api, &name("api"), InstanceUse::Read)
            .await
            .unwrap_err();
        assert_eq!(error_output(&error)["error"]["code"], "instance_not_found");
        assert_eq!(
            error.to_string(),
            "no instance is named api; `ghost instance list` lists the names"
        );

        let error = resolve_instance(&api, &name("web-1"), InstanceUse::Change)
            .await
            .unwrap_err();
        assert_eq!(
            error_output(&error)["error"]["code"],
            "instance_name_ambiguous"
        );
        assert_eq!(
            error.to_string(),
            format!(
                "2 instances are named web-1:\n  {newer}  running\n  {older}  stopped\nTo choose one, name it by its ID."
            )
        );
        // What the terminal gets keeps the lines.
        assert_eq!(
            render_error(&error, Terminal::plain()),
            format!(
                "Error: 2 instances are named web-1:\n  {newer}  running\n  {older}  stopped\nTo choose one, name it by its ID."
            )
        );
    }

    #[tokio::test]
    async fn a_name_is_looked_up_on_every_page_of_the_list() {
        let (newer, older, db) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let mut first: Vec<Value> = (0..LISTED_INSTANCES)
            .map(|age| listed_instance(Uuid::now_v7(), "other", "running", age.try_into().unwrap()))
            .collect();
        first[7] = listed_instance(newer, "web-1", "running", 7);
        let (newest, last) = (
            first[0]["instance_id"].as_str().unwrap().to_owned(),
            first[LISTED_INSTANCES - 1]["instance_id"]
                .as_str()
                .unwrap()
                .to_owned(),
        );
        let first = Value::from(first).to_string();
        let second = json!([
            listed_instance(older, "web-1", "stopped", 1_000),
            listed_instance(db, "db", "running", 1_001),
        ])
        .to_string();
        let (url, received) = canned_server(vec![
            (200, first.clone()),
            (200, second.clone()),
            (200, first.clone()),
            (200, second),
            // A backend that does not page answers the first page again.
            (200, first.clone()),
            (200, first),
        ])
        .await;
        let identity = keys::authentication_identity(&[3_u8; 32]).unwrap();
        let api = ApiClient::new(&url, Some(identity)).unwrap();
        let name = |name: &str| InstanceReference::Name(name.to_owned());

        // The newest 500 have one web-1; the page after them has another.
        let error = resolve_instance(&api, &name("web-1"), InstanceUse::Change)
            .await
            .unwrap_err();
        assert_eq!(
            error_output(&error)["error"]["code"],
            "instance_name_ambiguous"
        );
        assert_eq!(
            error.to_string(),
            format!(
                "2 instances are named web-1:\n  {newer}  running\n  {older}  stopped\nTo choose one, name it by its ID."
            )
        );
        assert_eq!(
            resolve_instance(&api, &name("db"), InstanceUse::Read)
                .await
                .unwrap(),
            db
        );
        let error = resolve_instance(&api, &name("db"), InstanceUse::Read)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("the instance list named instance {newest} twice; name the instance by its ID")
        );
        let next = format!("GET /v1/instances?before={last}");
        assert_eq!(
            request_lines(&received),
            [
                "GET /v1/instances",
                &next,
                "GET /v1/instances",
                &next,
                "GET /v1/instances",
                &next
            ]
        );
    }

    #[tokio::test]
    async fn a_change_by_name_is_retried_by_the_id_it_resolved_to() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let (instance, job_id) = (Uuid::now_v7(), Uuid::now_v7());
        let list = json!([listed_instance(instance, "web-1", "running", 1)]).to_string();
        let unanswered = (503, "try again later".to_owned());
        let accepted = json!({"job_id": job_id, "resource_id": instance,
            "status_url": format!("/v1/jobs/{job_id}")})
        .to_string();
        let (url, received) = canned_server(vec![
            (200, list.clone()),
            (200, "[]".to_owned()),
            unanswered.clone(),
            (200, "[]".to_owned()),
            unanswered.clone(),
            (200, list),
            unanswered,
            (202, accepted),
        ])
        .await;
        let instance_text = instance.to_string();
        let hint = |arguments: &[&str]| {
            let command = account_command(&url, &seed, arguments);
            async move { execute(&command).await.unwrap_err().to_string() }
        };

        // A name looked up again may stand for another instance by then.
        assert_eq!(
            hint(&[
                "instance",
                "delete",
                "web-1",
                "--yes",
                "--idempotency-key",
                "instance-ref-retry-1"
            ])
            .await,
            format!(
                "this exact mutation may be retried with the ID {instance} in place of the name web-1, and --idempotency-key instance-ref-retry-1"
            )
        );
        // An ID is repeated as it is.
        assert_eq!(
            hint(&[
                "instance",
                "delete",
                &instance_text,
                "--yes",
                "--idempotency-key",
                "instance-ref-retry-1"
            ])
            .await,
            "this exact mutation may be retried with --idempotency-key instance-ref-retry-1"
        );
        let backup_hint = hint(&[
            "backup",
            "create",
            "web-1",
            "--destination",
            "local",
            "--pricing-revision",
            "7",
            "--maximum-charge-microusd",
            "1000",
            "--idempotency-key",
            "instance-ref-retry-2",
        ])
        .await;
        let retry = backup_hint
            .strip_prefix(&format!(
                "this exact mutation may be retried with the ID {instance} in place of the name web-1, and "
            ))
            .unwrap();
        assert_eq!(
            retry,
            "--idempotency-key instance-ref-retry-2 --pricing-revision 7 --maximum-charge-microusd 1000"
        );
        // The retry by the ID sends the first request again.
        let mut arguments = vec!["backup", "create", &instance_text, "--destination", "local"];
        arguments.extend(retry.split_whitespace());
        let result = execute(&account_command(&url, &seed, &arguments))
            .await
            .unwrap();
        assert_eq!(result["job_id"], job_id.to_string());
        let received = received.lock().unwrap();
        let backups = format!("POST /api/mut/v1/instances/{instance}/backups");
        assert!(received[6].0.starts_with(&backups), "{}", received[6].0);
        assert!(received[7].0.starts_with(&backups), "{}", received[7].0);
        assert_eq!(
            received[6].1, received[7].1,
            "the retried body is identical"
        );
    }

    #[tokio::test]
    async fn an_instance_id_is_used_without_a_request() {
        let (url, received) = canned_server(Vec::new()).await;
        let api = ApiClient::new(&url, None).unwrap();
        let id = Uuid::now_v7();
        assert_eq!(
            resolve_instance(&api, &InstanceReference::Id(id), InstanceUse::Change)
                .await
                .unwrap(),
            id
        );
        assert!(request_lines(&received).is_empty());
    }

    #[tokio::test]
    async fn commands_send_the_id_a_name_resolves_to() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let (instance, job_id) = (Uuid::now_v7(), Uuid::now_v7());
        let list = json!([listed_instance(instance, "web-1", "running", 1)]).to_string();
        let accepted = json!({"job_id": job_id, "resource_id": instance,
            "status_url": format!("/v1/jobs/{job_id}")})
        .to_string();
        let (url, received) = canned_server(vec![
            (200, list.clone()),
            (200, "[]".to_owned()),
            (202, accepted.clone()),
            (200, list.clone()),
            (200, "[]".to_owned()),
            (200, list.clone()),
            (202, accepted),
            (200, list.clone()),
            (
                200,
                listed_instance(instance, "web-1", "running", 1).to_string(),
            ),
        ])
        .await;
        for arguments in [
            &["instance", "delete", "web-1", "--yes"][..],
            &["backup", "list", "web-1"],
            &[
                "--compact",
                "backup",
                "create",
                "web-1",
                "--destination",
                "local",
                "--pricing-revision",
                "7",
                "--maximum-charge-microusd",
                "1000",
                "--idempotency-key",
                "instance-ref-test-key",
            ],
            &["instance", "get", "Web-1"],
        ] {
            execute(&account_command(&url, &seed, arguments))
                .await
                .unwrap();
        }
        let lines = request_lines(&received);
        assert_eq!(
            lines,
            [
                "GET /v1/instances".to_owned(),
                format!("GET /v1/instances/{instance}/backups"),
                format!("DELETE /api/mut/v1/instances/{instance}"),
                "GET /v1/instances".to_owned(),
                format!("GET /v1/instances/{instance}/backups"),
                "GET /v1/instances".to_owned(),
                format!("POST /api/mut/v1/instances/{instance}/backups"),
                "GET /v1/instances".to_owned(),
                format!("GET /v1/instances/{instance}"),
            ]
        );
    }

    #[test]
    fn a_provider_names_a_rental_by_its_id_only() {
        let host = Uuid::now_v7().to_string();
        assert!(
            Cli::try_parse_from(["ghost", "provider", "retire-instance", "web-1", "--yes"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "ghost",
                "provider",
                "host",
                "instance-usage",
                &host,
                "web-1"
            ])
            .is_err()
        );
    }

    /// A backup as the API lists it.
    fn backup_json(backup_id: Uuid, instance_id: Uuid, destination: &str, status: &str) -> Value {
        json!({"backup_id": backup_id, "instance_id": instance_id,
            "destination": destination, "status": status, "purpose": "regular",
            "funding_lifecycle_id": null, "size_bytes": 751_619_277, "restore_pricing_revision": 1,
            "restore_charge_microusd_per_gib": 10_000, "storage_charge_microusd_per_gib_month": 20_000,
            "recipient_key_fingerprint": null, "wrapped_data_key": null,
            "created_at": Utc::now(), "completed_at": Utc::now()})
    }

    /// The method and path of each request the canned server received.
    fn request_lines(received: &Received) -> Vec<String> {
        received
            .lock()
            .unwrap()
            .iter()
            .map(|(line, _)| {
                line.split_whitespace()
                    .take(2)
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .collect()
    }

    #[test]
    fn instance_delete_notes_the_backups_it_keeps_billing() {
        let instance = Uuid::now_v7();
        let host = Uuid::now_v7();
        let (local, hosted) = (Uuid::now_v7(), Uuid::now_v7());
        let mut local_view = backup_json(local, instance, "local", "available");
        local_view["host_id"] = json!(host);
        let mut hosted_view = backup_json(hosted, instance, "gigahost_s3", "uploading");
        hosted_view["size_bytes"] = Value::Null;
        hosted_view["storage_charge_microusd_per_gib_month"] = json!(30_000);
        let backups: Vec<BackupView> = serde_json::from_value(json!([
            local_view,
            hosted_view,
            backup_json(Uuid::now_v7(), instance, "local", "deleted"),
            backup_json(Uuid::now_v7(), instance, "local", "deleting"),
            backup_json(Uuid::now_v7(), instance, "local", "failed"),
        ]))
        .unwrap();
        assert_eq!(
            kept_backups_note(&backups).unwrap(),
            format!(
                "2 backups of this instance are kept after it is deleted and billed for storage until deleted:\n  {local}  local on host {host}, 716.8 MiB, $0.02/GiB-month\n  {hosted}  hosted, size not known yet, $0.03/GiB-month\nTo delete one: ghost backup delete {local} --yes"
            )
        );
        assert!(kept_backups_note(&backups[2..]).is_none());
    }

    #[tokio::test]
    async fn instance_delete_goes_ahead_when_its_backups_cannot_be_read() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let (instance, job_id) = (Uuid::now_v7(), Uuid::now_v7());
        let accepted = json!({"job_id": job_id, "resource_id": instance,
            "status_url": format!("/v1/jobs/{job_id}")})
        .to_string();
        let backups = json!([backup_json(Uuid::now_v7(), instance, "local", "available")]);
        // The second deletion's backup list cannot be read.
        let (url, received) = canned_server(vec![
            (200, backups.to_string()),
            (202, accepted.clone()),
            (
                404,
                json!({"code": "not_found", "message": "instance not found"}).to_string(),
            ),
            (202, accepted),
        ])
        .await;
        let instance_text = instance.to_string();
        for _ in 0..2 {
            let result = execute(&account_command(
                &url,
                &seed,
                &["instance", "delete", &instance_text, "--yes"],
            ))
            .await
            .unwrap();
            assert_eq!(result["job_id"], job_id.to_string());
        }
        let list = format!("GET /v1/instances/{instance}/backups");
        let delete = format!("DELETE /api/mut/v1/instances/{instance}");
        assert_eq!(request_lines(&received), [&*list, &delete, &list, &delete]);
    }

    #[tokio::test]
    async fn backup_list_all_asks_for_deleted_backups_too() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let instance = Uuid::now_v7();
        let (url, received) = canned_server(vec![
            (200, "[]".to_owned()),
            (200, "[]".to_owned()),
            (200, "[]".to_owned()),
        ])
        .await;
        let instance_text = instance.to_string();
        for arguments in [
            &["backup", "list"][..],
            &["backup", "list", "--all"],
            &["backup", "list", &instance_text, "--all"],
        ] {
            execute(&account_command(&url, &seed, arguments))
                .await
                .unwrap();
        }
        assert_eq!(
            request_lines(&received),
            [
                "GET /v1/backups".to_owned(),
                "GET /v1/backups?include_deleted=true".to_owned(),
                format!("GET /v1/instances/{instance}/backups?include_deleted=true"),
            ]
        );
    }

    #[tokio::test]
    async fn instance_list_filters_and_sorts_through_its_query() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let (url, received) = canned_server(vec![(200, "[]".to_owned()); 5]).await;
        for arguments in [
            &["instance", "list"][..],
            &[
                "instance", "list", "--state", "stopped", "--state", "failed", "--busy",
            ],
            &[
                "instance",
                "list",
                "--location",
                "eu-fra",
                "--provider",
                "gh-abcdefgh",
                "--home",
                "--image",
                "ubuntu-24.04",
                "--name",
                "web",
                "--sort",
                "price",
                "--asc",
            ],
            &["instance", "list", "--cloud", "--sort", "name", "--desc"],
            &[
                "instance", "list", "--tag", "env:prod", "--tag", "web", "--sort", "age",
            ],
        ] {
            execute(&account_command(&url, &seed, arguments))
                .await
                .unwrap();
        }
        assert_eq!(
            request_lines(&received),
            [
                "GET /v1/instances".to_owned(),
                "GET /v1/instances?state=stopped&state=failed&busy=true".to_owned(),
                "GET /v1/instances?location=eu-fra&provider=gh-abcdefgh&mode=home_gateway\
                 &image=ubuntu-24.04&name=web&sort=price&order=asc"
                    .to_owned(),
                "GET /v1/instances?mode=cloud_routed&sort=name&order=desc".to_owned(),
                "GET /v1/instances?tag=env%3Aprod&tag=web&sort=age".to_owned(),
            ]
        );
        for conflicting in [
            &["ghost", "instance", "list", "--asc", "--desc"][..],
            &["ghost", "instance", "list", "--home", "--cloud"],
            &["ghost", "instance", "list", "--sort", "cost"],
            &["ghost", "instance", "list", "--sort", "hostname"],
            &["ghost", "instance", "list", "--hostname", "web"],
            &["ghost", "instance", "list", "--state", "paused"],
            &["ghost", "instance", "list", "--tag", "Prod"],
        ] {
            assert!(Cli::try_parse_from(conflicting).is_err(), "{conflicting:?}");
        }
    }

    #[tokio::test]
    async fn backup_list_filters_and_sorts_through_the_account_list() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let instance = Uuid::now_v7();
        let (url, received) = canned_server(vec![(200, "[]".to_owned()); 5]).await;
        let instance_text = instance.to_string();
        for arguments in [
            &[
                "backup",
                "list",
                "--state",
                "failed",
                "--state",
                "in_progress",
            ][..],
            &["backup", "list", "--hosted", "--sort", "cost", "--asc"],
            &[
                "backup", "list", "--all", "--local", "--sort", "size", "--desc",
            ],
            &[
                "backup",
                "list",
                &instance_text,
                "--sort",
                "age",
                "--state",
                "deleted",
            ],
            &["backup", "list", &instance_text, "--tag", "web"],
        ] {
            execute(&account_command(&url, &seed, arguments))
                .await
                .unwrap();
        }
        assert_eq!(
            request_lines(&received),
            [
                "GET /v1/backups?state=failed&state=in_progress".to_owned(),
                "GET /v1/backups?destination=hosted&sort=cost&order=asc".to_owned(),
                "GET /v1/backups?include_deleted=true&destination=local&sort=size&order=desc"
                    .to_owned(),
                format!("GET /v1/backups?instance_id={instance}&state=deleted&sort=age"),
                format!("GET /v1/backups?instance_id={instance}&tag=web"),
            ]
        );
        for conflicting in [
            &["ghost", "backup", "list", "--asc", "--desc"][..],
            &["ghost", "backup", "list", "--hosted", "--local"],
            &["ghost", "backup", "list", "--sort", "price"],
            &["ghost", "backup", "list", "--state", "staging"],
        ] {
            assert!(Cli::try_parse_from(conflicting).is_err(), "{conflicting:?}");
        }
    }

    #[test]
    fn the_backup_table_shows_what_storage_costs_a_month() {
        let made_in = |status: &str, size: Option<u64>, cost: Option<u64>| {
            let mut backup = backup_json(Uuid::now_v7(), Uuid::now_v7(), "local", status);
            backup["size_bytes"] = json!(size);
            backup["storage_charge_microusd_per_gib_month"] = json!(20_000);
            match cost {
                Some(cost) => backup["storage_cost_microusd_per_month"] = json!(cost),
                None => {
                    backup
                        .as_object_mut()
                        .unwrap()
                        .remove("storage_cost_microusd_per_month");
                }
            }
            serde_json::from_value::<BackupView>(backup).unwrap()
        };
        let made = |size: Option<u64>, cost: Option<u64>| made_in("available", size, cost);
        let summary = Summary::backups(vec![
            made(Some(1 << 30), Some(20_000)),
            // From an older backend: worked out from the size and rate.
            made(Some(3 << 29), None),
            made(None, None),
            // Deleted or lost, it costs nothing more, as the website
            // shows it, whatever it cost while it was kept.
            made_in("deleted", Some(1 << 30), Some(20_000)),
            made_in("lost", Some(1 << 30), None),
        ]);
        assert!(summary.columns.contains(&"per_month_microusd"));
        let costs: Vec<&Value> = summary
            .rows
            .iter()
            .map(|row| &row["per_month_microusd"])
            .collect();
        assert_eq!(
            costs,
            [
                &json!(20_000),
                &json!(30_000),
                &Value::Null,
                &Value::Null,
                &Value::Null
            ]
        );
    }

    #[tokio::test]
    async fn one_backup_is_read_by_its_id() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let (backup_id, instance_id) = (Uuid::now_v7(), Uuid::now_v7());
        let backup = backup_json(backup_id, instance_id, "gigahost_s3", "uploading");
        let (url, received) = canned_server(vec![(200, backup.to_string())]).await;
        let id = backup_id.to_string();
        let cli = account_command(&url, &seed, &["backup", "get", &id]);
        let output = execute(&cli).await.unwrap();
        let view: BackupView = serde_json::from_value(backup).unwrap();
        assert_eq!(output, to_value(view).unwrap());
        assert_eq!(request_lines(&received), [format!("GET /v1/backups/{id}")]);
        let text = render_result(&cli, &output, Terminal::plain());
        let lines = words(&text);
        for line in [["destination", "hosted"], ["status", "uploading"]] {
            assert!(lines.contains(&line.to_vec()), "{text}");
        }
        assert!(!text.contains("wrapped"), "{text}");
    }

    #[tokio::test]
    async fn create_with_backup_allows_cloud_init_file() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let user_data = directory.path().join("user.yaml");
        std::fs::write(&user_data, "#cloud-config\nruncmd: [touch /restored]\n").unwrap();
        let (backup, source, job_id) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let accepted = json!({"job_id": job_id, "resource_id": Uuid::now_v7(),
            "status_url": format!("/v1/jobs/{job_id}")});
        let (url, received) = canned_server(vec![
            (
                200,
                backup_json(backup, source, "local", "available").to_string(),
            ),
            (
                404,
                json!({"code": "not_found", "message": "listed offering not found"}).to_string(),
            ),
            (202, accepted.to_string()),
        ])
        .await;
        let backup_text = backup.to_string();
        let create = |extra: &[&str]| {
            let mut arguments = vec![
                "instance",
                "create",
                "--offering",
                "offering",
                "--backup",
                &backup_text,
                "--cloud-init-file",
                user_data.to_str().unwrap(),
            ];
            arguments.extend_from_slice(extra);
            account_command(&url, &seed, &arguments)
        };
        let result = execute(&create(&[])).await.unwrap();
        assert_eq!(result["job_id"], job_id.to_string());
        let (line, body) = received.lock().unwrap()[2].clone();
        assert!(line.starts_with("POST /api/mut/v1/instances "), "{line}");
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            body["cloud_init"],
            "#cloud-config\nruncmd: [touch /restored]\n"
        );
        assert_eq!(body["source"]["backup_id"], json!(backup));

        // Keys are refused before anything is sent.
        let error = execute(&create(&[
            "--ssh-key",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILmpbTJskXPcOuo9FieOY3V1tsruIFFVSnAeegTZQFKy test",
        ]))
        .await
        .unwrap_err();
        assert!(
            error.to_string().starts_with(
                "--ssh-key, --ssh-key-file, and startup commands cannot be used with --backup"
            ),
            "{error}"
        );
        assert_eq!(error_output(&error)["error"]["code"], "invalid_request");
        assert_eq!(received.lock().unwrap().len(), 3);
    }

    /// A backup still being created, such as a hosted one whose upload
    /// runs, is refused before anything is signed or sent, in the words of
    /// the backend's `backup_not_available`.
    #[tokio::test]
    async fn a_backup_being_created_is_neither_restored_nor_restored_from() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let (backup_id, instance_id) = (Uuid::now_v7(), Uuid::now_v7());
        let mut backup = backup_json(backup_id, instance_id, "gigahost_s3", "uploading");
        backup["size_bytes"] = Value::Null;
        let (url, received) =
            canned_server(vec![(200, backup.to_string()), (200, backup.to_string())]).await;
        let backup = backup_id.to_string();
        let error = execute(&account_command(
            &url,
            &seed,
            &["backup", "restore", &backup, "--yes"],
        ))
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "backup_not_available: backup {backup_id} is uploading; only an available backup can be restored; retry once its creation has finished"
            )
        );
        let error = execute(&account_command(
            &url,
            &seed,
            &[
                "instance",
                "create",
                "--offering",
                "test-offering",
                "--backup",
                &backup,
            ],
        ))
        .await
        .unwrap_err();
        assert!(
            error.to_string().starts_with(&format!(
                "backup_not_available: backup {backup_id} is uploading; only an available backup can be used to create an instance"
            )),
            "{error}"
        );
        assert_eq!(
            request_lines(&received),
            [
                format!("GET /v1/backups/{backup_id}"),
                format!("GET /v1/backups/{backup_id}"),
            ]
        );
    }

    /// A lost backup, and one in a backup pool its host is missing, are
    /// refused before anything is signed or sent, in the words of the
    /// backend's `backup_not_available` and `backup_pool_unavailable`.
    #[tokio::test]
    async fn a_lost_or_unavailable_backup_is_not_restored() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let (backup_id, instance_id) = (Uuid::now_v7(), Uuid::now_v7());
        let lost = backup_json(backup_id, instance_id, "local", "lost");
        let mut unavailable = backup_json(backup_id, instance_id, "local", "available");
        unavailable["unavailable"] = json!({"since": Utc::now(),
            "reason": "backup pool backups of the host is missing: not in the host's inventory"});
        let (url, received) = canned_server(vec![
            (200, lost.to_string()),
            (200, unavailable.to_string()),
        ])
        .await;
        let backup = backup_id.to_string();
        let restore = || account_command(&url, &seed, &["backup", "restore", &backup, "--yes"]);
        let error = execute(&restore()).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "backup_not_available: backup {backup_id} is lost; only an available backup can be restored; delete it with `ghost backup delete`"
            )
        );
        let error = execute(&restore()).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "backup_pool_unavailable: backup {backup_id} cannot be restored now: backup pool backups of the host is missing: not in the host's inventory; try again when the host has the pool back"
            )
        );
        assert_eq!(
            error_output(&error)["error"]["code"],
            "backup_pool_unavailable"
        );
        assert_eq!(
            request_lines(&received),
            [
                format!("GET /v1/backups/{backup_id}"),
                format!("GET /v1/backups/{backup_id}"),
            ]
        );
    }

    #[tokio::test]
    async fn a_backup_is_restored_by_its_id_alone() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let (backup_id, instance_id, job_id) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let backup = backup_json(backup_id, instance_id, "local", "available").to_string();
        let accepted = json!({"job_id": job_id, "resource_id": backup_id,
            "status_url": format!("/v1/jobs/{job_id}")});
        let (url, received) = canned_server(vec![
            (200, backup.clone()),
            (202, accepted.to_string()),
            (200, backup),
        ])
        .await;
        let backup = backup_id.to_string();
        let result = execute(&account_command(
            &url,
            &seed,
            &["backup", "restore", &backup, "--yes"],
        ))
        .await
        .unwrap();
        assert_eq!(result["job_id"], job_id.to_string());
        // The older form still works, and a wrong instance is named.
        let other = Uuid::now_v7().to_string();
        let error = execute(&account_command(
            &url,
            &seed,
            &["backup", "restore", &other, &backup, "--yes"],
        ))
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!("backup {backup_id} belongs to instance {instance_id}, not {other}")
        );
        assert_eq!(
            error_output(&error)["error"]["code"],
            "backup_instance_mismatch"
        );
        let unconfirmed = execute(&account_command(
            &url,
            &seed,
            &["backup", "restore", &backup],
        ))
        .await
        .unwrap_err();
        assert_eq!(
            unconfirmed.to_string(),
            "restore replaces the current root filesystem; repeat with --yes"
        );
        assert_eq!(
            request_lines(&received),
            [
                format!("GET /v1/backups/{backup_id}"),
                format!("POST /api/mut/v1/instances/{instance_id}/backups/{backup_id}/restore"),
                format!("GET /v1/backups/{backup_id}"),
            ]
        );
    }

    /// An offering of a `root_disk_bytes` root on `host_ids`.
    fn placement_offering(host_ids: &[Uuid], root_disk_bytes: u64) -> Value {
        json!({"offering_id": format!("offering-{root_disk_bytes}"), "provider_id": Uuid::nil(),
            "provider_name": "provider", "host_mode": "cloud_routed", "location": "pl-warsaw",
            "location_name": "Warsaw", "country_code": "PL", "continent_code": "EU",
            "measured_latency_ms": null, "host_ids": host_ids, "cpu_model": "cpu",
            "cpu_tier": "shared_1x", "vcpu_count": 1, "memory_bytes": 1 << 30,
            "root_disk_bytes": root_disk_bytes, "root_storage_backend": "preallocated_file",
            "software_raid_levels": [], "storage_devices": [], "base_price_microusd_per_month": 1,
            "full_utilization_price_microusd_per_month": 1, "network_prices": [],
            "sla_target_basis_points": 9_900,
            "sla_credit_multiplier": 1, "available_hosts": host_ids.len()})
    }

    #[tokio::test]
    async fn offering_filter_for_backup_asks_the_server_for_its_host_and_disk() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let (home, other) = (Uuid::now_v7(), Uuid::now_v7());
        let disk = 32_u64 << 30;
        let offerings = json!([placement_offering(&[home], 48 << 30)]).to_string();
        let (backup_id, instance_id) = (Uuid::now_v7(), Uuid::now_v7());
        let mut local = backup_json(backup_id, instance_id, "local", "available");
        local["host_id"] = json!(home);
        local["disk_bytes"] = json!(disk);
        let mut hosted = backup_json(backup_id, instance_id, "gigahost_s3", "available");
        hosted["disk_bytes"] = json!(disk);
        let (url, received) = canned_server(vec![
            (200, local.to_string()),
            (200, offerings.clone()),
            (200, hosted.to_string()),
            (200, offerings.clone()),
            (200, local.to_string()),
            (200, local.to_string()),
            (200, offerings),
        ])
        .await;
        let listed = async |arguments: &[&str]| {
            let mut line = vec!["catalog", "offerings"];
            line.extend_from_slice(arguments);
            execute(&account_command(&url, &seed, &line)).await
        };
        let backup = backup_id.to_string();
        // The server filters before it caps the list, so ghost asks it for
        // a local backup's host and every backup's disk size.
        let listed_offerings = listed(&["--for-backup", &backup]).await.unwrap();
        assert_eq!(listed_offerings.as_array().unwrap().len(), 1);
        listed(&["--for-backup", &backup, "--host", &other.to_string()])
            .await
            .unwrap();
        // An instance from a local backup runs on the backup's host.
        let error = listed(&["--for-backup", &backup, "--host", &other.to_string()])
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "backup {backup_id} is stored on host {home}, where an instance created from it runs; leave out --host or pass that host"
            )
        );
        listed(&["--for-backup", &backup, "--host", &home.to_string()])
            .await
            .unwrap();
        let filtered = |host: Uuid| {
            format!(
                "GET /v1/catalog/offerings?kind=vm&host_id={host}&minimum_root_disk_bytes={disk}"
            )
        };
        assert_eq!(
            request_lines(&received),
            [
                format!("GET /v1/backups/{backup_id}"),
                filtered(home),
                format!("GET /v1/backups/{backup_id}"),
                filtered(other),
                format!("GET /v1/backups/{backup_id}"),
                format!("GET /v1/backups/{backup_id}"),
                filtered(home),
            ]
        );
    }

    /// An instance from a backup is of the backup's kind, so
    /// `--for-backup` lists only the offerings of that kind; a backup of an
    /// older backend, which names no kind, is a VM's.
    #[tokio::test]
    async fn offering_filter_for_backup_asks_for_the_backups_kind() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let disk = 8_u64 << 30;
        let offerings = json!([placement_offering(&[Uuid::now_v7()], 48 << 30)]).to_string();
        let (backup_id, instance_id) = (Uuid::now_v7(), Uuid::now_v7());
        let mut container = backup_json(backup_id, instance_id, "gigahost_s3", "available");
        container["disk_bytes"] = json!(disk);
        container["kind"] = json!("container");
        container["container"] = json!({"image": "docker.io/library/nginx:1.27",
            "image_digest": null, "stock_image": null, "restart_policy": "always"});
        let mut older = backup_json(backup_id, instance_id, "gigahost_s3", "available");
        older["disk_bytes"] = json!(disk);
        let view: BackupView = serde_json::from_value(older.clone()).unwrap();
        assert_eq!(view.kind, InstanceKind::Vm);
        assert!(view.container.is_none());
        let (url, received) = canned_server(vec![
            (200, container.to_string()),
            (200, offerings.clone()),
            (200, container.to_string()),
            (200, offerings.clone()),
            (200, container.to_string()),
            (200, older.to_string()),
            (200, offerings),
        ])
        .await;
        let listed = async |arguments: &[&str]| {
            let mut line = vec!["catalog", "offerings"];
            line.extend_from_slice(arguments);
            execute(&account_command(&url, &seed, &line)).await
        };
        let backup = backup_id.to_string();
        listed(&["--for-backup", &backup]).await.unwrap();
        listed(&["--for-backup", &backup, "--kind", "any"])
            .await
            .unwrap();
        let error = listed(&["--for-backup", &backup, "--kind", "vm"])
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            format!(
                "backup {backup_id} is a container instance's backup, and an instance created from it is a container instance too; leave out --kind or pass --kind container"
            )
        );
        listed(&["--for-backup", &backup]).await.unwrap();
        let filtered = |kind: &str| {
            format!("GET /v1/catalog/offerings?kind={kind}&minimum_root_disk_bytes={disk}")
        };
        assert_eq!(
            request_lines(&received),
            [
                format!("GET /v1/backups/{backup_id}"),
                filtered("container"),
                format!("GET /v1/backups/{backup_id}"),
                filtered("container"),
                format!("GET /v1/backups/{backup_id}"),
                format!("GET /v1/backups/{backup_id}"),
                filtered("vm"),
            ]
        );
    }

    fn trial_claim(expires_in_seconds: i64) -> TrialClaimView {
        TrialClaimView {
            claim_id: "claim0123".to_owned(),
            claim_url: "https://example.test/trial/start?claim=claim0123".to_owned(),
            expires_at: Utc::now() + chrono::Duration::seconds(expires_in_seconds),
        }
    }

    fn claim_status(status: &str, alias: Option<&str>, reason: Option<&str>) -> String {
        json!({
            "status": status,
            "account_alias": alias,
            "reason": reason,
            "expires_at": Utc::now() + chrono::Duration::minutes(5),
        })
        .to_string()
    }

    #[test]
    fn the_github_commands_parse() {
        for (arguments, expected) in [
            (&["ghost", "account", "signup", "--github"][..], false),
            (
                &["ghost", "account", "signup", "--github", "--no-wait"][..],
                true,
            ),
        ] {
            let cli = Cli::try_parse_from(arguments).unwrap();
            assert!(matches!(
                cli.command,
                Command::Account { command: AccountCommand::Signup { github: true, no_wait } } if no_wait == expected
            ));
        }
        assert!(
            Cli::try_parse_from(["ghost", "account", "signup"]).is_err(),
            "a sign-up is with GitHub"
        );
        let cli = Cli::try_parse_from(["ghost", "account", "link-github", "--no-wait"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Account {
                command: AccountCommand::LinkGithub { no_wait: true }
            }
        ));
        for (arguments, expected) in [
            (&["ghost", "account", "unlink-github"][..], false),
            (&["ghost", "account", "unlink-github", "--yes"][..], true),
        ] {
            let cli = Cli::try_parse_from(arguments).unwrap();
            assert!(matches!(
                cli.command,
                Command::Account { command: AccountCommand::UnlinkGithub { yes } } if yes == expected
            ));
        }
        let cli = Cli::try_parse_from(["ghost", "account", "github-status", "abc"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Account { command: AccountCommand::GithubStatus { claim_id } } if claim_id == "abc"
        ));
        assert!(Cli::try_parse_from(["ghost", "account", "github-status"]).is_err());
        for gone in ["trial", "trial-status"] {
            assert!(
                Cli::try_parse_from(["ghost", "account", gone]).is_err(),
                "{gone} is gone"
            );
        }
    }

    /// `signup --github --no-wait` sends the three public keys, signed, and prints
    /// the claim; `github-status` reads it once.
    #[tokio::test]
    async fn a_github_signup_carries_only_the_public_keys() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let claim = trial_claim(600);
        let (url, received, heads) = canned_server_recording_heads(vec![
            (200, String::new(), serde_json::to_string(&claim).unwrap()),
            (200, String::new(), claim_status("pending", None, None)),
        ])
        .await;
        let output = execute(&account_command(
            &url,
            &seed,
            &["account", "signup", "--github", "--no-wait"],
        ))
        .await
        .unwrap();
        assert_eq!(output["claim_id"], "claim0123");
        assert_eq!(output["claim_url"], claim.claim_url);
        let status = execute(&account_command(
            &url,
            &seed,
            &["account", "github-status", "claim0123"],
        ))
        .await
        .unwrap();
        assert_eq!(status["status"], "pending");
        assert_eq!(
            request_lines(&received),
            [
                "POST /api/mut/v1/account/github/signup",
                "GET /v1/account/github/claims/claim0123"
            ]
        );
        let summary = keys::key_summary(&keys::load_seed(&seed).unwrap()).unwrap();
        let head = heads.lock().unwrap()[0].to_lowercase();
        let key_id_header = format!("{}:", gigahost_client_api::account_auth::AUTH_KEY_ID_HEADER);
        let key_id = head
            .lines()
            .find_map(|line| line.strip_prefix(&key_id_header))
            .map(str::trim);
        assert_eq!(
            key_id,
            Some(
                keys::authentication_identity(&keys::load_seed(&seed).unwrap())
                    .unwrap()
                    .key_id
                    .to_lowercase()
                    .as_str()
            ),
            "the claim is signed with the generated key: {head}"
        );
        assert!(
            head.contains(&format!(
                "{}:",
                gigahost_client_api::account_auth::REQUEST_SIGNATURE_HEADER
            )),
            "the claim carries a signature: {head}"
        );
        let body: Value = serde_json::from_slice(&received.lock().unwrap()[0].1).unwrap();
        assert_eq!(
            body,
            json!({
                "authentication_public_key": summary.authentication_public_key,
                "billing_public_key": summary.billing_verifying_key,
                "recovery_public_key": summary.recovery_public_key,
            })
        );
    }

    /// `github-status` refuses a claim ID that could name another route,
    /// before it sends anything.
    #[tokio::test]
    async fn a_github_status_refuses_an_id_that_is_no_claim_s() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let (url, received, _) = canned_server_recording_heads(vec![]).await;
        for id in ["../activation-terms", "a/b", "", &"x".repeat(65)] {
            let refused = execute(&account_command(
                &url,
                &seed,
                &["account", "github-status", "--", id],
            ))
            .await
            .unwrap_err();
            assert!(
                refused.to_string().contains("GitHub claim's ID"),
                "{refused}"
            );
        }
        assert!(received.lock().unwrap().is_empty());
    }

    /// A wait long enough that only an answer ends it.
    const LONG: Duration = Duration::from_mins(1);

    #[tokio::test]
    async fn a_github_claim_is_polled_until_created_or_refused() {
        let tick = Duration::from_millis(1);
        let (url, received) = canned_server(vec![
            (200, claim_status("pending", None, None)),
            (200, claim_status("pending", None, None)),
            (200, claim_status("created", Some("gh-trial001"), None)),
        ])
        .await;
        let api = ApiClient::new(&url, None).unwrap();
        let status =
            await_github_claim(&api, &trial_claim(600), GithubClaimUse::Signup, tick, LONG)
                .await
                .unwrap();
        assert_eq!(status.account_alias.as_deref(), Some("gh-trial001"));
        assert_eq!(request_lines(&received).len(), 3);

        let (url, _) = canned_server(vec![
            (200, claim_status("pending", None, None)),
            (
                200,
                claim_status("refused", None, Some("the GitHub account had a trial")),
            ),
        ])
        .await;
        let api = ApiClient::new(&url, None).unwrap();
        let error = await_github_claim(&api, &trial_claim(600), GithubClaimUse::Signup, tick, LONG)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "the sign-up was refused: the GitHub account had a trial"
        );
    }

    /// The backend finishes a sign-in made just before the expiry after
    /// it: this computer's clock passing the expiry (or running ahead of
    /// the backend's) does not end the wait, the backend's answer does.
    #[tokio::test]
    async fn a_github_claim_is_followed_past_its_expiry_until_the_backend_answers() {
        let tick = Duration::from_millis(1);
        let (url, received) = canned_server(vec![
            (200, claim_status("pending", None, None)),
            (200, claim_status("pending", None, None)),
            (200, claim_status("created", Some("gh-trial001"), None)),
        ])
        .await;
        let api = ApiClient::new(&url, None).unwrap();
        let expired = trial_claim(-30);
        let status = await_github_claim(&api, &expired, GithubClaimUse::Signup, tick, LONG)
            .await
            .unwrap();
        assert_eq!(status.account_alias.as_deref(), Some("gh-trial001"));
        assert_eq!(request_lines(&received).len(), 3);

        // The backend's own answer for a claim that ran out is a refusal.
        let (url, _) = canned_server(vec![
            (200, claim_status("pending", None, None)),
            (
                200,
                claim_status("refused", None, Some("the trial claim expired")),
            ),
        ])
        .await;
        let api = ApiClient::new(&url, None).unwrap();
        let error = await_github_claim(&api, &expired, GithubClaimUse::Signup, tick, LONG)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "the sign-up was refused: the trial claim expired"
        );
    }

    #[test]
    fn a_github_claim_is_followed_a_whole_lifetime_and_the_exchange_margin_at_least() {
        let now = Utc::now();
        let claim = |seconds: i64| TrialClaimView {
            claim_id: "claim0123".to_owned(),
            claim_url: String::new(),
            expires_at: now + chrono::Duration::seconds(seconds),
        };
        let lifetime = Duration::from_mins(10);
        let margin = Duration::from_mins(2);
        // A made claim has its lifetime, whatever this clock reads.
        assert_eq!(github_wait_limit(&claim(600), now), lifetime + margin);
        assert_eq!(github_wait_limit(&claim(300), now), lifetime + margin);
        assert_eq!(github_wait_limit(&claim(-30), now), lifetime + margin);
        // A clock behind the backend's leaves more.
        assert_eq!(
            github_wait_limit(&claim(900), now),
            Duration::from_mins(15) + margin
        );
    }

    /// With no answer that ends it, the wait ends at its bound with the
    /// expiry message.
    #[tokio::test]
    async fn a_github_claim_wait_ends_at_its_bound() {
        let pending = || (200, claim_status("pending", None, None));
        let (url, received) = canned_server(vec![pending(), pending()]).await;
        let api = ApiClient::new(&url, None).unwrap();
        let error = await_github_claim(
            &api,
            &trial_claim(600),
            GithubClaimUse::Signup,
            Duration::ZERO,
            Duration::ZERO,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "the link expired; run `ghost account signup --github` again"
        );
        assert_eq!(
            request_lines(&received).len(),
            1,
            "one reading at the bound"
        );

        let (url, _) = canned_server(vec![(
            503,
            json!({"code": "unavailable", "message": "restarting"}).to_string(),
        )])
        .await;
        let api = ApiClient::new(&url, None).unwrap();
        let error = await_github_claim(
            &api,
            &trial_claim(600),
            GithubClaimUse::Signup,
            Duration::ZERO,
            Duration::ZERO,
        )
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("ghost account show"),
            "{error:#}"
        );
        assert!(api::is_transient(&error), "{error:#}");
    }

    /// The browser sign-in goes on while the backend restarts or throttles:
    /// the command keeps asking and only a rejection ends it.
    #[tokio::test]
    async fn a_github_claim_reading_that_fails_for_a_moment_is_tried_again() {
        let tick = Duration::from_millis(1);
        let (url, received) = canned_server(vec![
            (
                503,
                json!({"code": "unavailable", "message": "restarting"}).to_string(),
            ),
            (
                429,
                json!({"code": "rate_limited", "message": "slow down"}).to_string(),
            ),
            (200, claim_status("pending", None, None)),
            (200, claim_status("created", Some("gh-trial001"), None)),
        ])
        .await;
        let api = ApiClient::new(&url, None).unwrap();
        let status =
            await_github_claim(&api, &trial_claim(600), GithubClaimUse::Signup, tick, LONG)
                .await
                .unwrap();
        assert_eq!(status.account_alias.as_deref(), Some("gh-trial001"));
        assert_eq!(request_lines(&received).len(), 4);

        // The claim being gone is no moment to wait out.
        let (url, received) = canned_server(vec![
            (
                503,
                json!({"code": "unavailable", "message": "restarting"}).to_string(),
            ),
            (
                404,
                json!({"code": "not_found", "message": "trial claim not found"}).to_string(),
            ),
            (200, claim_status("pending", None, None)),
        ])
        .await;
        let api = ApiClient::new(&url, None).unwrap();
        let error = await_github_claim(&api, &trial_claim(600), GithubClaimUse::Signup, tick, LONG)
            .await
            .unwrap_err();
        assert_eq!(
            api::rejection(&error).map(|answer| answer.status),
            Some(404)
        );
        assert_eq!(request_lines(&received).len(), 2);
    }

    /// The API chooses the claim link, so only its own website's is opened.
    #[test]
    fn only_the_apis_website_is_opened_in_the_browser() {
        let api = "https://api.gigahost.cloud/";
        let opened = |link: &str| browser_link(link, api).map(|url| url.to_string());
        assert_eq!(
            opened("https://gigahost.cloud/trial/start?claim=abc").as_deref(),
            Some("https://gigahost.cloud/trial/start?claim=abc")
        );
        assert!(opened("https://api.gigahost.cloud/trial/start?claim=abc").is_some());
        for refused in [
            "file:///C:/Users/x/payload.exe",
            "ms-msdt:/id PCWDiagnostic",
            "javascript:alert(1)",
            "-oProxyCommand=evil",
            "--help",
            "gigahost.cloud/trial/start",
            "https://user:pass@gigahost.cloud/trial/start",
            "https://user@gigahost.cloud/trial/start",
            "https://evil.example/trial/start",
            "https://notgigahost.cloud/trial/start",
            "https://gigahost.cloud.evil.example/trial/start",
            "https://cloud/trial/start",
            "https://127.0.0.1/trial/start",
        ] {
            assert_eq!(opened(refused), None, "{refused}");
        }
        // A test backend on an address has its website on that address.
        let local = |link: &str| browser_link(link, "http://127.0.0.1:8880/").is_some();
        assert!(local("http://127.0.0.1:8081/trial/start?claim=abc"));
        assert!(!local("http://0.0.0.1/trial/start"));
        assert!(!local("file:///etc/passwd"));
    }

    /// A link claim is signed by the account's key and carries no body;
    /// polled to `linked` it names the login and the credit; a refusal
    /// says why.
    #[tokio::test]
    async fn a_github_link_is_signed_by_the_account_key_and_polled_to_linked() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let claim = trial_claim(600);
        let linked = json!({
            "status": "linked", "account_alias": "gh-abcdefgh", "purpose": "link",
            "trial_credit": true, "github_login": "octocat",
            "expires_at": Utc::now() + chrono::Duration::minutes(5),
        });
        let (url, received, heads) = canned_server_recording_heads(vec![
            (200, String::new(), serde_json::to_string(&claim).unwrap()),
            (200, String::new(), linked.to_string()),
        ])
        .await;
        let output = execute(&account_command(
            &url,
            &seed,
            &["account", "link-github", "--no-wait"],
        ))
        .await
        .unwrap();
        assert_eq!(output["claim_id"], "claim0123");
        let api = ApiClient::new(&url, None).unwrap();
        let status = await_github_claim(
            &api,
            &claim,
            GithubClaimUse::Link,
            Duration::from_millis(1),
            LONG,
        )
        .await
        .unwrap();
        assert_eq!(status.github_login.as_deref(), Some("octocat"));
        assert!(status.trial_credit);
        assert_eq!(github_login_label(&status), "@octocat");
        assert_eq!(
            request_lines(&received),
            [
                "POST /api/mut/v1/account/github/link",
                "GET /v1/account/github/claims/claim0123"
            ]
        );
        let head = heads.lock().unwrap()[0].to_lowercase();
        assert!(
            head.contains(&format!(
                "{}:",
                gigahost_client_api::account_auth::REQUEST_SIGNATURE_HEADER
            )),
            "the link claim carries a signature: {head}"
        );
        assert!(
            received.lock().unwrap()[0].1.is_empty(),
            "the link claim carries no body"
        );

        let (url, _) = canned_server(vec![(
            200,
            claim_status(
                "refused",
                None,
                Some("the account has a GitHub account linked"),
            ),
        )])
        .await;
        let api = ApiClient::new(&url, None).unwrap();
        let error = await_github_claim(&api, &claim, GithubClaimUse::Link, Duration::ZERO, LONG)
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "the link was refused: the account has a GitHub account linked"
        );
    }

    /// Without `--no-wait`, `signup --github` and `link-github` follow the claim
    /// to its end and return the login and whether the credit came with it.
    #[tokio::test]
    async fn the_github_commands_wait_and_return_the_login_and_the_credit() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let claim = serde_json::to_string(&trial_claim(600)).unwrap();
        let finished = |status: &str, purpose: &str, credit: bool| {
            json!({
                "status": status, "account_alias": "gh-abcdefgh", "purpose": purpose,
                "trial_credit": credit, "github_login": "octocat",
                "expires_at": Utc::now() + chrono::Duration::minutes(5),
            })
            .to_string()
        };
        let (url, received, _) = canned_server_recording_heads(vec![
            (200, String::new(), claim.clone()),
            (200, String::new(), finished("created", "signup", true)),
            (500, String::new(), String::new()),
        ])
        .await;
        let signed_up = execute(&account_command(
            &url,
            &seed,
            &["account", "signup", "--github"],
        ))
        .await
        .unwrap();
        assert_eq!(signed_up["status"], "created");
        assert_eq!(signed_up["account_alias"], "gh-abcdefgh");
        assert_eq!(signed_up["github_login"], "octocat");
        assert_eq!(signed_up["trial_credit"], true);
        assert_eq!(
            request_lines(&received)[1],
            "GET /v1/account/github/claims/claim0123"
        );

        let (url, _, _) = canned_server_recording_heads(vec![
            (200, String::new(), claim),
            (200, String::new(), finished("linked", "link", false)),
        ])
        .await;
        let linked = execute(&account_command(&url, &seed, &["account", "link-github"]))
            .await
            .unwrap();
        assert_eq!(linked["status"], "linked");
        assert_eq!(linked["github_login"], "octocat");
        assert_eq!(linked["trial_credit"], false);
    }

    /// A sign-up that made the account without the trial credit returns
    /// why and the deposit memo, and says that a deposit adds funds.
    #[tokio::test]
    async fn a_github_sign_up_without_the_credit_names_the_deposit() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let memo = keys::key_summary(&load_seed_file(Some(&seed)).unwrap())
            .unwrap()
            .deposit_memo;
        let claim = serde_json::to_string(&trial_claim(600)).unwrap();
        let finished = json!({
            "status": "created", "account_alias": "gh-abcdefgh", "purpose": "signup",
            "trial_credit": false, "trial_credit_refusal": "trials are closed at the moment",
            "github_login": "octocat",
            "expires_at": Utc::now() + chrono::Duration::minutes(5),
        });
        let (url, _, _) = canned_server_recording_heads(vec![
            (200, String::new(), claim),
            (200, String::new(), finished.to_string()),
            (500, String::new(), String::new()),
        ])
        .await;
        let signed_up = execute(&account_command(
            &url,
            &seed,
            &["account", "signup", "--github"],
        ))
        .await
        .unwrap();
        assert_eq!(signed_up["status"], "created");
        assert_eq!(signed_up["trial_credit"], false);
        assert_eq!(
            signed_up["trial_credit_refusal"],
            "trials are closed at the moment"
        );
        assert_eq!(signed_up["deposit_memo"], memo.as_str());
        let status: TrialClaimStatusView = serde_json::from_value(finished).unwrap();
        assert_eq!(
            signup_without_credit(&status, &memo),
            format!(
                "No trial credit: trials are closed at the moment.\nThe account starts with a $0 balance.\nTo add funds: make an MMX deposit with the deposit memo {memo}.\nTo see the deposit address: ghost account activation-terms"
            )
        );
    }

    /// A sign-up, an activation and a host enrollment token each name
    /// the Terms of Service, as the website's activation step does.
    #[test]
    fn signing_up_and_enrolling_name_the_terms() {
        assert_eq!(
            signup_terms_line("signing up"),
            "By signing up you agree to the Terms of Service and the Acceptable Use Policy, and ask that the service starts at once: https://gigahost.cloud/terms"
        );
        assert!(
            signup_terms_line("activating the account")
                .starts_with("By activating the account you agree")
        );
        assert!(provider_terms_line().ends_with("https://gigahost.cloud/terms#providers"));
    }

    /// Unlinking needs `--yes` and sends nothing without it.
    #[tokio::test]
    async fn unlinking_github_needs_yes() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let (url, received, _) = canned_server_recording_heads(vec![(
            200,
            String::new(),
            json!({"unlinked": true, "ended_sessions": 2}).to_string(),
        )])
        .await;
        let refused = execute(&account_command(&url, &seed, &["account", "unlink-github"]))
            .await
            .unwrap_err();
        assert!(refused.to_string().contains("--yes"), "{refused}");
        assert!(received.lock().unwrap().is_empty());
        let done = execute(&account_command(
            &url,
            &seed,
            &["account", "unlink-github", "--yes"],
        ))
        .await
        .unwrap();
        assert_eq!(done["unlinked"], true);
        assert_eq!(done["ended_sessions"], 2);
        assert_eq!(
            request_lines(&received),
            ["POST /api/mut/v1/account/github/unlink"]
        );
    }

    /// `ghost account balance` reads the account's projection by type,
    /// its total and the days the balance lasts under a heading of their
    /// own; `ghost instance usage` the instance's under its usage; `--json`
    /// keeps the API's views.
    #[tokio::test]
    async fn the_balance_and_the_usage_show_their_monthly_projection() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        let balance = json!({
            "available_microusd": 5_000_000, "reserved_microusd": 0, "total_microusd": 5_000_000,
            "funding_status": null, "provider_credits": [],
            "projection": {
                "instances_base_microusd": 38_320_000, "traffic_microusd": 10_000_000,
                "local_backups_microusd": 130_000, "hosted_backups_microusd": 200_000,
                "total_microusd": 48_650_000, "days_balance_lasts": 3,
            },
        });
        let cli = account_command("http://127.0.0.1:9", &seed, &["account", "balance"]);
        let text = render_result(&cli, &balance, Terminal::plain());
        let section = &text[text.find("==> projected_monthly_charges").expect(&text)..];
        for line in [
            "instances       $38.32",
            "traffic         $10.00",
            "local_backups   $0.13",
            "hosted_backups  $0.20",
            "total           $48.65",
            "balance_lasts   3 days at this rate",
            "basis           the past 30 days of each service;",
        ] {
            assert!(section.contains(line), "{line}: {text}");
        }
        assert!(
            section.find("instances") < section.find("traffic")
                && section.find("hosted_backups") < section.find("total")
        );
        assert!(text.contains("available_spending_credit"), "{text}");
        let json_cli = account_command(
            "http://127.0.0.1:9",
            &seed,
            &["--json", "account", "balance"],
        );
        let printed: Value =
            serde_json::from_str(&render_result(&json_cli, &balance, Terminal::plain())).unwrap();
        assert_eq!(printed["projection"]["days_balance_lasts"], 3);
        // Enough balance: no days line.
        let mut enough = balance.clone();
        enough["projection"]["days_balance_lasts"] = Value::Null;
        let text = render_result(&cli, &enough, Terminal::plain());
        assert!(!text.contains("balance_lasts"), "{text}");
        // An older backend's answer without one reads as before.
        let mut older = balance.clone();
        older.as_object_mut().unwrap().remove("projection");
        let text = render_result(&cli, &older, Terminal::plain());
        assert!(!text.contains("projected_monthly_charges"), "{text}");

        let usage = json!({
            "items": [{"instance_id": "01900000-0000-7000-8000-000000000201",
                       "observed_at": "2026-10-20T12:00:00Z", "cpu_time_ns": 5}],
            "next_cursor": null,
            "projection": {
                "base_microusd": 7_000_000, "traffic_microusd": 7_000_000,
                "local_backups_microusd": 100_000, "hosted_backups_microusd": 0,
                "total_microusd": 14_100_000,
            },
        });
        let arguments = [
            "instance",
            "usage",
            "01900000-0000-7000-8000-000000000201",
            "--resolution",
            "current",
        ];
        let cli = account_command("http://127.0.0.1:9", &seed, &arguments);
        let text = render_result(&cli, &usage, Terminal::plain());
        let section = &text[text.find("==> projected_monthly_charges").expect(&text)..];
        for line in [
            "base            $7.00",
            "traffic         $7.00",
            "local_backups   $0.10",
            "hosted_backups  $0.00",
            "total           $14.10",
        ] {
            assert!(section.contains(line), "{line}: {text}");
        }
        assert!(
            text.find("==> items") < text.find("==> projected_monthly_charges"),
            "{text}"
        );
        let mut json_arguments = vec!["--json"];
        json_arguments.extend(arguments);
        let json_cli = account_command("http://127.0.0.1:9", &seed, &json_arguments);
        let printed: Value =
            serde_json::from_str(&render_result(&json_cli, &usage, Terminal::plain())).unwrap();
        assert_eq!(printed["projection"]["total_microusd"], 14_100_000);
    }

    /// `instance usage` reads the three paths of an instance's traffic by default (the usage, then
    /// the first page of the WAN and LAN mesh's), one with --path (the mesh's at the resolution
    /// asked, with the page's cursor), and refuses a mesh path's current values before it sends
    /// anything; `instance mesh` reads the links, another customer's instance unnamed.
    #[tokio::test]
    async fn instance_usage_reads_each_path_and_mesh_its_links() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let instance = "01900000-0000-7000-8000-000000000203";
        let usage = json!({"items": [{"usage_date": "2026-10-02", "network_egress_bytes": 5}], "next_cursor": null});
        let wan = json!({"items": [{"usage_date": "2026-10-02", "path": "wan_mesh", "sent_bytes": 7, "received_bytes": 9}], "next_cursor": "c2"});
        let lan = json!({"items": [], "next_cursor": null});
        let (url, received) = canned_server(vec![
            (200, usage.to_string()),
            (200, wan.to_string()),
            (200, lan.to_string()),
            (200, wan.to_string()),
        ])
        .await;
        let all = account_command(
            &url,
            &seed,
            &[
                "--json",
                "instance",
                "usage",
                instance,
                "--resolution",
                "daily",
            ],
        );
        let output = execute(&all).await.unwrap();
        assert_eq!(output["items"][0]["network_egress_bytes"], 5);
        assert_eq!(output["wan_mesh"]["items"][0]["sent_bytes"], 7);
        assert_eq!(output["lan_mesh"]["items"], json!([]));
        let one = account_command(
            &url,
            &seed,
            &[
                "--json",
                "instance",
                "usage",
                instance,
                "--resolution",
                "monthly",
                "--path",
                "wan-mesh",
                "--cursor",
                "c1",
            ],
        );
        let output = execute(&one).await.unwrap();
        assert_eq!(output["items"][0]["received_bytes"], 9);
        assert!(output.get("wan_mesh").is_none());
        let paths: Vec<String> = received
            .lock()
            .unwrap()
            .iter()
            .map(|(line, _)| {
                line.split_whitespace()
                    .nth(1)
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect();
        assert_eq!(
            paths,
            [
                format!("/v1/instances/{instance}/usage?resolution=daily&limit=50"),
                format!(
                    "/v1/instances/{instance}/mesh-usage?path=wan_mesh&resolution=daily&limit=50"
                ),
                format!(
                    "/v1/instances/{instance}/mesh-usage?path=lan_mesh&resolution=daily&limit=50"
                ),
                format!(
                    "/v1/instances/{instance}/mesh-usage?path=wan_mesh&resolution=monthly&limit=50&cursor=c1"
                ),
            ]
        );
        let current = account_command(
            &url,
            &seed,
            &[
                "instance",
                "usage",
                instance,
                "--resolution",
                "current",
                "--path",
                "lan-mesh",
            ],
        );
        let error = execute(&current).await.unwrap_err();
        assert!(error.to_string().contains("no current values"), "{error:#}");
        assert_eq!(received.lock().unwrap().len(), 4, "nothing sent");

        let links = json!({
            "instance_id": instance,
            "mesh_enabled": true,
            "links": [{
                "kind": "lan", "peer_instance_id": null, "peer_name": null, "other_customers": 2,
                "state": "gateways", "state_since": "2026-10-02T04:40:00Z",
                "linked_since": "2026-09-20T09:00:00Z",
                "month": {"sent_bytes": 5, "received_bytes": 7},
                "day": {"sent_bytes": 0, "received_bytes": 1},
                "quarter": {"sent_bytes": 0, "received_bytes": 0},
            }],
            "no_link_reason": null,
            "month_started_at": "2026-10-01T00:00:00Z",
            "day_started_at": "2026-10-02T00:00:00Z",
            "quarter_started_at": null,
            "prices": {"wan_mesh_microusd_per_tib": 5_000_000, "lan_mesh_microusd_per_tib": 1_000_000},
        });
        let (url, received) = canned_server(vec![(200, links.to_string())]).await;
        let mesh = account_command(&url, &seed, &["--json", "instance", "mesh", instance]);
        let output = execute(&mesh).await.unwrap();
        assert_eq!(output["links"][0]["other_customers"], 2);
        assert!(output["links"][0]["peer_name"].is_null());
        assert_eq!(
            request_lines(&received),
            [format!("GET /v1/instances/{instance}/mesh")]
        );
        let text = render_result(&mesh, &output, Terminal::plain());
        assert!(text.contains("other_customers"), "{text}");
    }

    #[tokio::test]
    async fn account_show_lists_the_trial_and_a_limit_refusal_hints_at_a_deposit() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let account = json!({
            "account_alias": "gh-trial001", "deposit_memo": "memo000000000001",
            "key_epoch": 1, "status": "active",
            "github": {"login": "octocat", "linked_at": "2026-10-12T10:00:00Z"},
        });
        let balance = json!({
            "available_microusd": 0, "reserved_microusd": 0, "total_microusd": 0,
            "funding_status": null, "provider_credits": [],
            "trial": {
                "credit_left_microusd": 4_500_000,
                "expires_at": "2026-11-01T10:00:00Z",
                "limited": true,
            },
        });
        let (url, _) =
            canned_server(vec![(200, account.to_string()), (200, balance.to_string())]).await;
        let cli = account_command(&url, &seed, &["account", "show"]);
        let shown = execute(&cli).await.unwrap();
        assert_eq!(shown["trial"]["credit_left_microusd"], 4_500_000);
        assert_eq!(shown["trial"]["limited"], true);
        // The result keeps the object the API answers; only the text for
        // reading shows the one line.
        assert_eq!(
            shown["github"],
            json!({"login": "octocat", "linked_at": "2026-10-12T10:00:00Z"})
        );
        assert!(shown["trial_note"].as_str().unwrap().contains("deposit"));
        let text = render_result(&cli, &shown, Terminal::plain());
        assert!(text.contains("$4.50"), "{text}");
        assert!(text.contains("@octocat (linked 2026-10-12)"), "{text}");
        let json_cli = account_command(&url, &seed, &["--json", "account", "show"]);
        let text = render_result(&json_cli, &shown, Terminal::plain());
        let printed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(printed["github"]["login"], "octocat");
        assert_eq!(printed["github"]["linked_at"], "2026-10-12T10:00:00Z");
        assert!(!text.contains("(linked"), "{text}");
        let unlinked = json!({
            "account_alias": "gh-trial001", "deposit_memo": "memo000000000001",
            "key_epoch": 1, "status": "active",
        });
        let (url, _) = canned_server(vec![(200, unlinked.to_string()), (500, String::new())]).await;
        let cli = account_command(&url, &seed, &["account", "show"]);
        let shown = execute(&cli).await.unwrap();
        assert!(shown["github"].is_null());
        let text = render_result(&cli, &shown, Terminal::plain());
        assert!(
            text.lines()
                .any(|line| line.trim_start().starts_with("github ")
                    && line.trim_end().ends_with(" -")),
            "{text}"
        );

        let refusal =
            json!({"code": "trial_limit", "message": "a trial rents only 1 vCPU instances"});
        let api = canned_api(vec![(403, refusal.to_string())]).await;
        let error = api.read(&GetAccount, "").await.unwrap_err();
        let text = format!("{error:#}");
        assert!(
            text.contains("a trial rents only 1 vCPU instances"),
            "{text}"
        );
        assert!(
            text.contains("a deposit lifts the trial's limits"),
            "{text}"
        );
    }

    /// A running container instance's view, of `image` and, for a stock
    /// image, its slug.
    fn container_instance(instance_id: Uuid, image: &str, stock_image: Option<&str>) -> Value {
        json!({"instance_id": instance_id, "offering_id": "o", "hostname": "app-1",
            "root_disk_bytes": 4_u64 << 30, "state": "running",
            "desired_power_state": "running", "holds_capacity": true,
            "public_ipv4": "203.0.113.9", "network_microusd_per_tib": 0,
            "created_at": "2026-10-19T09:00:00Z", "balance_reservation_microusd": 0,
            "vcpu_count": 1, "memory_bytes": 256_u64 << 20,
            "kind": "container", "image": null,
            "container": {"image": image,
                "image_digest": "registry-1.docker.io/library/nginx@sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "stock_image": stock_image, "restart_policy": "on_failure",
                "status": {"state": "backing_off", "restart_at": "2026-10-19T10:00:05Z",
                    "restarts": 3,
                    "last_exit": {"code": 1, "signal": null, "reason": "exited",
                        "at": "2026-10-19T10:00:00Z"},
                    "reported_at": "2026-10-19T10:00:01Z"}}})
    }

    /// The offerings list asks for every kind and names what each is
    /// rented as, its default first; one offering shows its kinds and
    /// default; `--json` is the API's list.
    #[tokio::test]
    async fn the_offerings_list_every_kind_and_name_their_kinds() {
        let mut both = listed_offering(HostMode::CloudRouted);
        both.kinds = vec![InstanceKind::Vm, InstanceKind::Container];
        both.default_kind = Some(InstanceKind::Container);
        let mut container_only = listed_offering(HostMode::CloudRouted);
        container_only.kinds = vec![InstanceKind::Container];
        container_only.default_kind = Some(InstanceKind::Container);
        container_only.cpu_tier = gigahost_client_api::hypervisor::CpuTier::Shared8x;
        let offerings = json!([both, container_only]);
        let (url, received) = canned_server(vec![(200, offerings.to_string())]).await;
        let cli =
            Cli::try_parse_from(["ghost", "--api-url", &url, "catalog", "offerings"]).unwrap();
        let output = execute(&cli).await.unwrap();
        assert_eq!(output, offerings, "--json is the API's list");
        assert_eq!(
            request_lines(&received),
            ["GET /v1/catalog/offerings?kind=any"]
        );
        let text = render_result(&cli, &output, Terminal::plain());
        let lines = words(&text);
        assert_eq!(lines[0][4], "KINDS", "{text}");
        assert_eq!(lines[1][4..7], ["container,", "vm", "1"], "{text}");
        // Shared 8x is "1 vCPU" too, never a share of a core.
        assert_eq!(lines[2][4..7], ["container", "1", "vCPU"], "{text}");
        let shown = render_result(
            &Cli::try_parse_from(["ghost", "catalog", "offering", "o"]).unwrap(),
            &serde_json::to_value(&both).unwrap(),
            Terminal::plain(),
        );
        let field = |name: &str| {
            shown
                .lines()
                .find(|line| line.trim_start().starts_with(&format!("{name} ")))
                .map(|line| {
                    line.split_whitespace()
                        .skip(1)
                        .collect::<Vec<_>>()
                        .join(" ")
                })
        };
        assert_eq!(field("kinds").as_deref(), Some("vm, container"), "{shown}");
        assert_eq!(
            field("default_kind").as_deref(),
            Some("container"),
            "{shown}"
        );
    }

    /// The stock images are listed with what an offering and its host need
    /// of them; `--json` is the API's list.
    #[tokio::test]
    async fn the_stock_images_are_listed() {
        let images = json!([
            {"slug": "debian-13", "display_name": "Debian 13 (trixie)",
             "reference": format!("ghcr.io/gigahost-apps/debian@sha256:{}", "1".repeat(64)),
             "init_system": "systemd", "minimum_memory_bytes": 256_u64 << 20, "x86_64_level": 1},
            {"slug": "almalinux-10", "display_name": "AlmaLinux 10",
             "reference": format!("ghcr.io/gigahost-apps/almalinux@sha256:{}", "2".repeat(64)),
             "init_system": "systemd", "minimum_memory_bytes": 512_u64 << 20, "x86_64_level": 3},
        ]);
        let (url, received) = canned_server(vec![(200, images.to_string())]).await;
        let cli = Cli::try_parse_from(["ghost", "--api-url", &url, "catalog", "container-images"])
            .unwrap();
        let output = execute(&cli).await.unwrap();
        assert_eq!(output, images);
        assert_eq!(
            request_lines(&received),
            ["GET /v1/catalog/container-images"]
        );
        let text = render_result(&cli, &output, Terminal::plain());
        let lines = words(&text);
        assert_eq!(
            lines[0],
            [
                "SLUG",
                "DISPLAY_NAME",
                "INIT_SYSTEM",
                "MINIMUM_MEMORY",
                "CPU_LEVEL"
            ],
            "{text}"
        );
        assert_eq!(lines[1][0], "debian-13");
        assert_eq!(lines[1][lines[1].len() - 3..], ["256", "MiB", "x86-64-v1"]);
        assert_eq!(lines[2][lines[2].len() - 3..], ["512", "MiB", "x86-64-v3"]);
    }

    /// `instance logs` prints the container's lines, the end from before
    /// its last start under a heading, or that alone with `--previous`;
    /// `--json` is the API's view; a VM's answer is the API's 404.
    #[tokio::test]
    async fn the_logs_show_the_containers_lines() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let id = Uuid::now_v7().to_string();
        let logs = json!({"tail": "\u{1b}[32mlistening\u{1b}[0m on :80\r\n", "truncated": true,
            "previous": {"tail": "panic: no config\n", "truncated": false},
            "reported_at": "2026-10-19T10:00:00Z"});
        let refusal = json!({"code": "not_container_instance",
            "message": "the instance is not a container instance"});
        let (url, received) = canned_server(vec![
            (200, logs.to_string()),
            (200, logs.to_string()),
            (404, refusal.to_string()),
        ])
        .await;
        let cli = account_command(&url, &seed, &["instance", "logs", &id]);
        let output = execute(&cli).await.unwrap();
        assert_eq!(output, logs);
        assert_eq!(
            render_result(&cli, &output, Terminal::plain()),
            "--- before the container's last start ---\npanic: no config\n--- since its last start ---\nlistening on :80"
        );
        assert_eq!(
            closing_notes(&cli, &output).await,
            [
                "the end of the container's output as its host sent it at 2026-10-19 10:00:00 UTC: under the first heading, what it wrote before its last start; under the second, what it wrote since (older output left out)"
            ]
        );
        let previous = account_command(&url, &seed, &["instance", "logs", &id, "--previous"]);
        let output = execute(&previous).await.unwrap();
        assert_eq!(
            render_result(&previous, &output, Terminal::plain()),
            "panic: no config"
        );
        assert_eq!(
            closing_notes(&previous, &output).await,
            [
                "the end of the container's output as its host sent it at 2026-10-19 10:00:00 UTC: what it wrote before its last start"
            ]
        );
        let json = account_command(&url, &seed, &["--json", "instance", "logs", &id]);
        assert!(closing_notes(&json, &output).await.is_empty());
        assert!(
            render_result(&json, &output, Terminal::plain()).contains("\\u001b[32m"),
            "--json keeps the output as the container wrote it"
        );
        let error = execute(&cli).await.unwrap_err();
        assert!(
            format!("{error:#}").contains("the instance is not a container instance"),
            "{error:#}"
        );
        assert_eq!(
            error_output(&error)["error"]["code"],
            "not_container_instance"
        );
        assert_eq!(
            request_lines(&received),
            vec![format!("GET /v1/instances/{id}/logs"); 3]
        );
        let empty: ContainerLogView = serde_json::from_value(
            json!({"tail": "", "truncated": false, "previous": null, "reported_at": null}),
        )
        .unwrap();
        assert_eq!(readable_container_log(&empty, false), "");
        assert_eq!(
            container_log_note(&empty, false),
            "the container's host has sent none of its output yet"
        );
    }

    /// `instance create --container` sends the image and every override,
    /// the environment from its files then its options, one of a name given
    /// again replacing the earlier; nothing of the keys, user data or
    /// startup command.
    #[tokio::test]
    async fn a_container_is_created_with_its_settings() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let env_file = directory.path().join("app.env");
        fs::write(
            &env_file,
            "# the app's settings\n\nDATABASE_URL=postgres://u:hunter2@db/app\r\n  MODE=a=b\nTOKEN=old\n",
        )
        .unwrap();
        let job_id = Uuid::now_v7();
        let accepted = json!({"job_id": job_id, "resource_id": Uuid::now_v7(),
            "status_url": format!("/v1/jobs/{job_id}")});
        let (url, received) = canned_server(vec![(202, accepted.to_string())]).await;
        let created = execute(&account_command(
            &url,
            &seed,
            &[
                "--compact",
                "instance",
                "create",
                "--offering",
                "o",
                "--container",
                "nginx:1.27",
                "--env-file",
                env_file.to_str().unwrap(),
                "--env",
                "TOKEN=s3cret",
                "--env",
                "EMPTY=",
                "--entrypoint",
                "/docker-entrypoint.sh",
                "--command",
                r#"["nginx", "-g", "daemon off;"]"#,
                "--user",
                "101:101",
                "--workdir",
                "/srv",
                "--stop-timeout",
                "30",
                "--restart",
                "on-failure",
            ],
        ))
        .await
        .unwrap();
        assert_eq!(created["job_id"], job_id.to_string());
        assert_eq!(request_lines(&received), ["POST /api/mut/v1/instances"]);
        let body: Value = serde_json::from_slice(&received.lock().unwrap()[0].1).unwrap();
        assert!(body.get("source").is_none(), "{body}");
        assert_eq!(body["ssh_public_keys"], json!([]));
        assert!(body["ssh_key_ids"].is_null() && body["cloud_init"].is_null());
        assert!(body["startup_command"].is_null());
        assert_eq!(
            body["container"],
            json!({"image": "nginx:1.27",
                "entrypoint": ["/docker-entrypoint.sh"],
                "command": ["nginx", "-g", "daemon off;"],
                "env": [
                    {"name": "DATABASE_URL", "value": "postgres://u:hunter2@db/app"},
                    {"name": "MODE", "value": "a=b"},
                    {"name": "TOKEN", "value": "s3cret"},
                    {"name": "EMPTY", "value": ""},
                ],
                "user": "101:101", "workdir": "/srv", "stop_timeout_seconds": 30,
                "restart_policy": "on_failure"})
        );
        // An entrypoint as a JSON array, `[]` with a command too.
        let args = |extra: &[&str]| {
            let mut arguments = vec!["ghost", "instance", "create", "--offering", "o"];
            arguments.extend_from_slice(extra);
            let Command::Instance {
                command: InstanceCommand::Create(args),
            } = Cli::try_parse_from(arguments).unwrap().command
            else {
                panic!("not instance create");
            };
            args
        };
        let request = container_request(&args(&[
            "--container",
            "ghcr.io/owner/app@sha256:1111111111111111111111111111111111111111111111111111111111111111",
            "--entrypoint",
            "[]",
            "--command",
            r#"["/app"]"#,
            "--volume",
            "/var/lib/app",
        ]))
        .unwrap()
        .unwrap();
        assert_eq!(request.entrypoint, Some(Vec::new()));
        assert_eq!(request.volumes, ["/var/lib/app"]);
        assert!(request.env.is_empty() && request.restart_policy.is_none());
        assert!(
            container_request(&args(&["--image", "debian-13"]))
                .unwrap()
                .is_none()
        );
    }

    /// What a container instance does not take is refused before anything
    /// is sent, in words that never show a variable's value.
    #[test]
    fn container_mistakes_are_refused_before_anything_is_sent() {
        let directory = tempfile::tempdir().unwrap();
        let env_file = directory.path().join("bad.env");
        fs::write(&env_file, "GOOD=1\nhunter2-secret\n").unwrap();
        let env_file = env_file.to_str().unwrap();
        let url_file = directory.path().join("url.env");
        fs::write(
            &url_file,
            "# a pasted URL\nhttps://u:hunter2@db/app?token=s3cret=1\n",
        )
        .unwrap();
        let url_file = url_file.to_str().unwrap();
        let parse = |extra: &[&str]| {
            let mut arguments = vec!["ghost", "instance", "create", "--offering", "o"];
            arguments.extend_from_slice(extra);
            Cli::try_parse_from(arguments)
        };
        let refused = |extra: &[&str]| -> String {
            let Command::Instance {
                command: InstanceCommand::Create(args),
            } = parse(extra).unwrap().command
            else {
                panic!("not instance create");
            };
            let error = container_request(&args)
                .and_then(|_| check_container_login(&args))
                .unwrap_err();
            assert_eq!(error_output(&error)["error"]["code"], "invalid_request");
            let message = error.to_string();
            assert!(
                !message.contains("hunter2") && !message.contains("s3cret"),
                "a value is never shown: {message}"
            );
            message
        };
        let container = ["--container", "nginx:1.27"];
        assert_eq!(
            refused(
                &[
                    &container[..],
                    &["--ssh-key", TEST_PUBLIC_KEY, "--startup-command", "true"]
                ]
                .concat()
            ),
            "--container runs the image as it is, which gets no SSH keys, cloud-init or startup command: leave out --ssh-key and --startup-command; a stock image (--stock-image, from `ghost catalog container-images`) is reached over SSH with the keys given"
        );
        assert_eq!(
            refused(&[
                "--stock-image",
                "debian-13",
                "--entrypoint",
                "/bin/sh",
                "--stop-timeout",
                "5"
            ]),
            "--stock-image runs the distribution's own init system, which takes no --entrypoint and --stop-timeout; of the container options it takes --env, --env-file, --restart and --volume"
        );
        assert!(
            refused(&["--stock-image", "debian-13", "--cloud-init-file", env_file])
                .ends_with("leave out --cloud-init-file"),
        );
        assert_eq!(
            refused(&[
                "--image",
                "debian-13",
                "--env",
                "TOKEN=s3cret",
                "--restart",
                "never"
            ]),
            "--env and --restart are a container instance's: give them with --container or --stock-image"
        );
        assert_eq!(
            refused(
                &[
                    &container[..],
                    &["--env", "TOKEN=s3cret", "--env", "s3cret"]
                ]
                .concat()
            ),
            "--env 2 is not NAME=VALUE"
        );
        assert_eq!(
            refused(&[&container[..], &["--env", "1TOKEN=s3cret"]].concat()),
            "--env 1 does not start with a variable's name before its first =: a name is letters, digits and _, not starting with a digit, of at most 256 bytes"
        );
        // What stands before the first `=` of a text that is not
        // `NAME=VALUE` can be the secret itself.
        assert_eq!(
            refused(&[&container[..], &["--env", "https://u:s3cret@x/?a=1"]].concat()),
            "--env 1 does not start with a variable's name before its first =: a name is letters, digits and _, not starting with a digit, of at most 256 bytes"
        );
        assert_eq!(
            refused(&[&container[..], &["--env-file", env_file]].concat()),
            format!("line 2 of --env-file {env_file} is not NAME=VALUE")
        );
        assert_eq!(
            refused(&[&container[..], &["--env-file", url_file]].concat()),
            format!(
                "line 2 of --env-file {url_file} does not start with a variable's name before its first =: a name is letters, digits and _, not starting with a digit, of at most 256 bytes"
            )
        );
        assert!(
            refused(&[&container[..], &["--command", "nginx -g"]].concat())
                .starts_with("--command takes a JSON array of strings"),
        );
        assert!(
            refused(&[&container[..], &["--entrypoint", "/bin/sh -c"]].concat())
                .contains("or a single word"),
        );
        // The API's own checks, in its words.
        assert!(
            refused(&[&container[..], &["--entrypoint", "[]"]].concat())
                .contains("the container would run nothing"),
        );
        assert!(refused(&[&container[..], &["--workdir", "srv"]].concat()).contains("workdir"),);
        // Exactly one source.
        for both in [
            &["--container", "nginx", "--stock-image", "debian-13"][..],
            &["--image", "debian-13", "--container", "nginx"],
            &[
                "--stock-image",
                "debian-13",
                "--backup",
                "01a0e357-b7d1-7f53-9a72-5ffacde8735b",
            ],
        ] {
            assert_eq!(
                parse(both).err().map(|error| error.kind()),
                Some(clap::error::ErrorKind::ArgumentConflict),
                "{both:?}"
            );
        }
        for bad in [
            &["--container", "Nginx:"][..],
            &["--stock-image", "Debian 13"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        assert!(parse(&[&container[..], &["--stop-timeout", "301"]].concat()).is_err());
        // A stock image needs a key: one given, or a saved one.
        assert_eq!(
            stock_image_keys(0).unwrap_err().to_string(),
            "a stock image is reached over SSH with the instance's keys: give at least one --ssh-key or --ssh-key-file, or save a key with `ghost account ssh-keys add`"
        );
        assert!(
            stock_image_keys(2)
                .unwrap()
                .starts_with("Installing the 2 SSH keys saved")
        );
        // An offering is rented as the kinds it lists; one of before as a VM.
        let mut offering = listed_offering(HostMode::CloudRouted);
        assert!(check_kind(&offering, InstanceKind::Vm).is_ok());
        let error = check_kind(&offering, InstanceKind::Container).unwrap_err();
        assert_eq!(
            error_output(&error)["error"]["code"],
            "offering_unavailable"
        );
        assert!(error.to_string().contains("--kind container"), "{error}");
        offering.kinds = vec![InstanceKind::Container];
        assert!(check_kind(&offering, InstanceKind::Container).is_ok());
        assert!(
            check_kind(&offering, InstanceKind::Vm)
                .unwrap_err()
                .to_string()
                .contains("rented as a container instance only")
        );
    }

    /// `instance create --stock-image` sends the slug with the keys, as a
    /// VM's creation does; without a key given, the account's saved keys,
    /// which it reads first, and none refused before anything is rented.
    #[tokio::test]
    async fn a_stock_image_is_created_with_its_keys() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let job_id = Uuid::now_v7();
        let accepted = json!({"job_id": job_id, "resource_id": Uuid::now_v7(),
            "status_url": format!("/v1/jobs/{job_id}")});
        let saved = json!([{"ssh_key_id": Uuid::now_v7(), "label": "laptop",
            "public_key": TEST_PUBLIC_KEY, "key_type": "ssh-ed25519", "fingerprint": "SHA256:x",
            "created_at": Utc::now()}]);
        let (url, received) = canned_server(vec![
            (202, accepted.to_string()),
            (200, saved.to_string()),
            (202, accepted.to_string()),
            (200, "[]".to_owned()),
        ])
        .await;
        let create = async |extra: &[&str]| {
            let mut arguments = vec!["--compact", "instance", "create", "--offering", "o"];
            arguments.extend_from_slice(&["--stock-image", "debian-13", "--env", "TZ=UTC"]);
            arguments.extend_from_slice(extra);
            execute(&account_command(&url, &seed, &arguments)).await
        };
        create(&["--ssh-key", TEST_PUBLIC_KEY, "--restart", "always"])
            .await
            .unwrap();
        create(&[]).await.unwrap();
        let error = create(&[]).await.unwrap_err();
        assert!(
            error
                .to_string()
                .starts_with("a stock image is reached over SSH"),
            "{error}"
        );
        assert_eq!(
            request_lines(&received),
            [
                "POST /api/mut/v1/instances",
                "GET /v1/account/ssh-keys",
                "POST /api/mut/v1/instances",
                "GET /v1/account/ssh-keys",
            ]
        );
        let bodies: Vec<Value> = received
            .lock()
            .unwrap()
            .iter()
            .filter(|(line, _)| line.starts_with("POST"))
            .map(|(_, body)| serde_json::from_slice(body).unwrap())
            .collect();
        assert_eq!(bodies[0]["ssh_public_keys"], json!([TEST_PUBLIC_KEY]));
        assert_eq!(bodies[0]["ssh_key_ids"], json!([]), "the keys given only");
        assert_eq!(
            bodies[0]["container"],
            json!({"stock_image": "debian-13", "env": [{"name": "TZ", "value": "UTC"}],
                "restart_policy": "always"})
        );
        assert!(bodies[0].get("source").is_none());
        assert_eq!(bodies[1]["ssh_public_keys"], json!([]));
        assert!(bodies[1].get("ssh_key_ids").is_none(), "every saved key");
    }

    #[tokio::test]
    async fn a_simple_update_sends_only_the_tag_after_confirmation_and_can_wait() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let instance = Uuid::now_v7();
        let job = Uuid::now_v7();
        let accepted =
            json!({"job_id":job, "resource_id":instance, "status_url":format!("/v1/jobs/{job}")});
        let done = job_json(JobState::Succeeded, &[], json!({}));
        let (url, received) = canned_server(vec![
            (202, accepted.to_string()),
            (202, accepted.to_string()),
            (200, done),
        ])
        .await;
        let id = instance.to_string();
        let update = async |extra: &[&str]| {
            let mut args = vec!["--compact", "instance", "update", id.as_str()];
            args.extend_from_slice(extra);
            execute(&account_command(&url, &seed, &args)).await
        };
        let error = update(&[]).await.unwrap_err().to_string();
        assert!(
            error.contains("Everything else on the root disk is replaced")
                && error.contains("before commit attempts rollback")
        );
        assert!(error.contains("stops temporarily") && error.ends_with("--yes"));
        assert!(
            request_lines(&received).is_empty(),
            "no mutation or settings read without --yes"
        );
        assert!(update(&["--tag", "other/repo", "--yes"]).await.is_err());
        update(&["--yes"]).await.unwrap();
        let result = update(&["--tag", "stable", "--yes", "--wait"])
            .await
            .unwrap();
        assert_eq!(result["state"], "succeeded");
        assert_eq!(
            request_lines(&received),
            [
                format!("POST /api/mut/v1/instances/{instance}/update"),
                format!("POST /api/mut/v1/instances/{instance}/update"),
                format!("GET /v1/jobs/{job}"),
            ]
        );
        let bodies: Vec<Value> = received
            .lock()
            .unwrap()
            .iter()
            .filter(|(line, _)| line.starts_with("POST"))
            .map(|(_, body)| serde_json::from_slice(body).unwrap())
            .collect();
        assert_eq!(bodies, [json!({}), json!({"tag":"stable"})]);
        for option in ["--reset", "--env", "--volume", "--container"] {
            assert!(
                Cli::try_parse_from(["ghost", "instance", "update", &id, option, "x"]).is_err()
            );
        }
    }

    /// `instance redeploy` says what it replaces and keeps before it asks,
    /// without a variable's value; sends only what is given (absent keeps
    /// the instance's), `--no-volumes` as no paths and `--reset`; and a
    /// stock image takes the account's saved keys when none are given.
    #[tokio::test]
    async fn a_redeploy_sends_what_is_given_after_saying_what_it_replaces() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let instance_id = Uuid::now_v7();
        let mut instance =
            container_instance(instance_id, "registry-1.docker.io/library/nginx:1.27", None);
        instance["container"]["volumes"] = json!(["/data", "/srv/uploads"]);
        let job_id = Uuid::now_v7();
        let accepted = json!({"job_id": job_id, "resource_id": instance_id,
            "status_url": format!("/v1/jobs/{job_id}")});
        let saved = json!([{"ssh_key_id": Uuid::now_v7(), "label": "laptop",
            "public_key": TEST_PUBLIC_KEY, "key_type": "ssh-ed25519", "fingerprint": "SHA256:x",
            "created_at": Utc::now()}]);
        let (url, received) = canned_server(vec![
            (200, instance.to_string()),
            (200, instance.to_string()),
            (202, accepted.to_string()),
            (200, instance.to_string()),
            (202, accepted.to_string()),
            (200, instance.to_string()),
            (200, saved.to_string()),
            (202, accepted.to_string()),
        ])
        .await;
        let id = instance_id.to_string();
        let redeploy = async |extra: &[&str]| {
            let mut arguments = vec!["--compact", "instance", "redeploy", id.as_str()];
            arguments.extend_from_slice(extra);
            execute(&account_command(&url, &seed, &arguments)).await
        };
        let error = redeploy(&["--container", "nginx:1.28", "--env", "TOKEN=s3cret"])
            .await
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("/data and /srv/uploads and the VOLUME paths"),
            "{error}"
        );
        assert!(
            error.contains("rolled back") && error.ends_with("--yes"),
            "{error}"
        );
        assert!(!error.contains("s3cret"), "{error}");
        redeploy(&[
            "--container",
            "nginx:1.28",
            "--env",
            "TOKEN=s3cret",
            "--volume",
            "/data",
            "--yes",
        ])
        .await
        .unwrap();
        redeploy(&[
            "--container",
            "nginx:1.28",
            "--no-volumes",
            "--reset",
            "--yes",
        ])
        .await
        .unwrap();
        redeploy(&["--stock-image", "debian-13", "--yes"])
            .await
            .unwrap();
        // Refused before anything is sent.
        for refused in [
            &[
                "--container",
                "nginx:1.28",
                "--user",
                "101",
                "--clear",
                "user",
                "--yes",
            ][..],
            &["--stock-image", "debian-13", "--command", "[]", "--yes"][..],
            &[
                "--container",
                "nginx:1.28",
                "--ssh-key",
                TEST_PUBLIC_KEY,
                "--yes",
            ][..],
            &["--container", "nginx:1.28", "--volume", "data", "--yes"][..],
        ] {
            assert!(redeploy(refused).await.is_err(), "{refused:?}");
        }
        assert!(
            Cli::try_parse_from([
                "ghost",
                "instance",
                "redeploy",
                &id,
                "--container",
                "nginx:1.28",
                "--no-volumes",
                "--volume",
                "/data"
            ])
            .is_err(),
            "--no-volumes and --volume conflict"
        );
        assert!(
            Cli::try_parse_from(["ghost", "instance", "redeploy", &id, "--env", "A=b"]).is_err(),
            "an image is required"
        );
        let Cli {
            command:
                Command::Instance {
                    command: InstanceCommand::Redeploy(args),
                },
            ..
        } = Cli::try_parse_from([
            "ghost",
            "instance",
            "redeploy",
            &id,
            "--container",
            "nginx:1.28",
            "--clear",
            "entrypoint",
            "--clear",
            "workdir",
        ])
        .unwrap()
        else {
            panic!("a redeploy");
        };
        let cleared = redeploy_request(&args).unwrap();
        assert_eq!(
            serde_json::to_value(&cleared).unwrap(),
            json!({"image": "nginx:1.28", "clear": ["entrypoint", "workdir"]})
        );
        assert!(
            Cli::try_parse_from([
                "ghost",
                "instance",
                "redeploy",
                &id,
                "--container",
                "nginx:1.28",
                "--clear",
                "stop_timeout"
            ])
            .is_err(),
            "only the four settings clear"
        );
        let path = format!("/api/mut/v1/instances/{instance_id}/redeploy");
        assert_eq!(
            request_lines(&received),
            [
                format!("GET /v1/instances/{instance_id}"),
                format!("GET /v1/instances/{instance_id}"),
                format!("POST {path}"),
                format!("GET /v1/instances/{instance_id}"),
                format!("POST {path}"),
                format!("GET /v1/instances/{instance_id}"),
                "GET /v1/account/ssh-keys".to_owned(),
                format!("POST {path}"),
            ]
        );
        let bodies: Vec<Value> = received
            .lock()
            .unwrap()
            .iter()
            .filter(|(line, _)| line.starts_with("POST"))
            .map(|(_, body)| serde_json::from_slice(body).unwrap())
            .collect();
        assert_eq!(
            bodies,
            [
                json!({"image": "nginx:1.28", "env": [{"name": "TOKEN", "value": "s3cret"}],
                    "volumes": ["/data"]}),
                json!({"image": "nginx:1.28", "volumes": [], "reset": true}),
                json!({"stock_image": "debian-13"}),
            ]
        );
    }

    /// A waited container creation does not wait for a cloud-init report
    /// that never comes: it says where the instance is and how to read its
    /// logs, and, for a stock image, how to log in.
    #[tokio::test]
    async fn a_waited_container_creation_ends_with_its_logs() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let seed = seed.to_str().unwrap();
        let (instance_id, job_id) = (Uuid::now_v7(), Uuid::now_v7());
        let own = container_instance(instance_id, "registry-1.docker.io/library/nginx:1.27", None);
        let mut stock = container_instance(
            instance_id,
            &format!("ghcr.io/gigahost-apps/debian@sha256:{}", "1".repeat(64)),
            Some("debian-13"),
        );
        stock["gateway_tier"] = json!("shared_ip");
        stock["port_forwards"] = json!([{"public_port": 40022, "guest_port": 22}]);
        let (url, received) =
            canned_server(vec![(200, own.to_string()), (200, stock.to_string())]).await;
        let job = json!({"job_id": job_id, "kind": "create_instance", "state": "succeeded",
            "resource_id": instance_id});
        let create = |source: &[&str]| {
            let mut arguments = vec!["ghost", "--api-url", &url, "--seed-file", seed];
            arguments.extend_from_slice(&["instance", "create", "--offering", "o"]);
            arguments.extend_from_slice(source);
            arguments.extend_from_slice(&["--wait", "--poll-seconds", "1"]);
            Cli::try_parse_from(arguments).unwrap()
        };
        assert_eq!(
            closing_notes(&create(&["--container", "nginx:1.27"]), &job).await,
            [
                format!("Container instance {instance_id} (app-1) is running."),
                "  Address   203.0.113.9".to_owned(),
                format!("To read what its container writes: ghost instance logs {instance_id}"),
            ]
        );
        assert_eq!(
            closing_notes(&create(&["--stock-image", "debian-13"]), &job).await,
            [
                format!("Instance {instance_id} (app-1) is running."),
                "  Address   203.0.113.9".to_owned(),
                "  SSH       ssh -p 40022 root@203.0.113.9".to_owned(),
                format!("  Ports     ghost instance ports {instance_id}"),
                format!("To read what its container writes: ghost instance logs {instance_id}"),
            ]
        );
        assert_eq!(
            request_lines(&received),
            vec![format!("GET /v1/instances/{instance_id}"); 2],
            "no wait for cloud-init"
        );
    }

    /// A container instance is marked in the list, with its image; `get`
    /// shows its image, digest, restart policy and status; `--json` is the
    /// API's view.
    #[test]
    fn a_container_instance_shows_its_image_and_status() {
        let (own, stock, vm) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
        let mut virtual_machine = container_instance(vm, "", None);
        virtual_machine["kind"] = json!("vm");
        virtual_machine["container"] = Value::Null;
        virtual_machine["image"] = json!({"image_id": Uuid::now_v7(), "slug": "debian-13",
            "display_name": "Debian 13", "architecture": "x86_64", "minimum_disk_bytes": 1});
        let instances = json!([
            container_instance(own, "registry-1.docker.io/library/nginx:1.27", None),
            container_instance(
                stock,
                "ghcr.io/gigahost-apps/debian@sha256:11",
                Some("debian-13")
            ),
            virtual_machine,
        ]);
        let list = Cli::try_parse_from(["ghost", "instance", "list"]).unwrap();
        let text = render_result(&list, &instances, Terminal::plain());
        let lines = words(&text);
        assert_eq!(
            lines[0],
            [
                "INSTANCE_ID",
                "NAME",
                "STATE",
                "KIND",
                "PUBLIC_IPV4",
                "LOCATION",
                "IMAGE",
                "SIZE"
            ],
            "{text}"
        );
        assert_eq!(lines[1][3], "container");
        assert_eq!(lines[1][6], "registry-1.docker.io/library/nginx:1.27");
        assert_eq!(lines[2][6], "debian-13", "a stock image by its slug");
        assert_eq!((lines[3][3], lines[3][6]), ("vm", "debian-13"));
        assert_eq!(
            lines[1][7..],
            ["1", "vCPU,", "256", "MiB", "RAM,", "4", "GiB", "disk"]
        );
        let get = Cli::try_parse_from(["ghost", "instance", "get", &own.to_string()]).unwrap();
        let instance = container_instance(own, "registry-1.docker.io/library/nginx:1.27", None);
        let shown = render_result(&get, &instance, Terminal::plain());
        let container = &shown[shown.find("==> container").expect("a container section")..];
        for expected in [
            "image ",
            "registry-1.docker.io/library/nginx:1.27",
            "image_digest ",
            "restart_policy ",
            "on_failure",
            "backing_off",
            "restarts ",
            "last_exit",
            "exited",
        ] {
            assert!(container.contains(expected), "{expected}: {container}");
        }
        let json =
            Cli::try_parse_from(["ghost", "--json", "instance", "get", &own.to_string()]).unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&render_result(&json, &instance, Terminal::plain()))
                .unwrap(),
            instance
        );
    }

    /// The readable-output wording: steps and states in words, unknown ones
    /// as sent, the instance list's job in words.
    #[test]
    fn job_steps_states_and_kinds_are_said_in_words() {
        assert_eq!(job_step_words("download_backup"), "downloading the backup");
        assert_eq!(
            job_step_words("await_restore_authorization"),
            "waiting for the restore to be authorized"
        );
        assert_eq!(job_step_words("brand_new_step"), "brand new step");
        assert_eq!(job_state_words("pending"), "queued");
        assert_eq!(job_state_words("retry_wait"), "waiting to retry");
        assert_eq!(job_state_words("escalated"), "escalated");
        assert_eq!(job_kind_words(JobKind::CreateBackup), "backing up");
        assert_eq!(percent_text(3_750_u16), "37.5 %");
        assert_eq!(percent_text(0_u16), "0 %");
        let event = JobEventView {
            event_id: 1,
            step_id: None,
            step_key: Some("download_backup".to_owned()),
            attempt: Some(2),
            state: Some("running".to_owned()),
            progress_permyriad: Some(3_750),
            message: Some("downloading artifact".to_owned()),
            created_at: Utc::now(),
        };
        assert_eq!(
            format_job_event(&event, Some("download_backup"), false),
            "[running, attempt 2, 37.5 %] downloading the backup: downloading artifact"
        );
    }

    /// The prices of an offering's tiers, one per line with the tier in
    /// words and the flag value to type.
    #[test]
    fn the_tier_prices_of_a_refusal_are_one_per_line() {
        let offering = listed_offering(HostMode::HomeGateway);
        let text = network_prices_text(&offering.network_prices, false);
        assert!(
            text.lines().all(|line| line.starts_with("  ")) && !text.contains(';'),
            "{text}"
        );
        assert!(
            text.contains(
                "shared bandwidth (--gateway-tier shared_bandwidth)  $10.24/TiB + $5.00/month"
            ),
            "{text}"
        );
    }

    /// Hints of `key generate`, `account set-password` and `account
    /// migrate-seed` are not rows of the table; they follow on standard
    /// error, and `--json` keeps every key.
    #[tokio::test]
    async fn hints_follow_the_table_as_notes_and_json_keeps_them() {
        let output = json!({"seed_file": "/home/a/account.seed",
            "warning": "Back up this file. Losing it makes encrypted hosted backups unrecoverable.",
            "keys": {"authentication_public_key": "k"}});
        let cli = Cli::try_parse_from(["ghost", "key", "generate"]).unwrap();
        let text = render_result(&cli, &output, Terminal::plain());
        assert!(
            text.contains("seed_file") && !text.contains("Back up"),
            "{text}"
        );
        assert_eq!(
            closing_notes(&cli, &output).await,
            [
                "warning: back up the account key file.",
                "Losing it makes encrypted hosted backups unrecoverable."
            ]
        );
        let json = Cli::try_parse_from(["ghost", "--json", "key", "generate"]).unwrap();
        assert!(render_result(&json, &output, Terminal::plain()).contains("Back up this file"));
        assert!(closing_notes(&json, &output).await.is_empty());
    }

    /// A sign-up without the credit says why and how to deposit in its
    /// notice, so the result for reading does not repeat them; with the
    /// credit the trial's limits are a short list.
    #[test]
    fn a_sign_up_result_does_not_repeat_what_its_notice_said() {
        let output = json!({"status": "created", "account_alias": "gh-a",
            "github_login": "octocat", "trial_credit": false,
            "trial_credit_refusal": "trials are closed", "deposit_memo": "memo1",
            "trial": null});
        let cli = Cli::try_parse_from(["ghost", "account", "signup", "--github"]).unwrap();
        let text = render_result(&cli, &output, Terminal::plain());
        assert!(
            !text.contains("trials are closed") && !text.contains("memo1"),
            "{text}"
        );
        let json =
            Cli::try_parse_from(["ghost", "--json", "account", "signup", "--github"]).unwrap();
        let text = render_result(&json, &output, Terminal::plain());
        assert!(
            text.contains("trials are closed") && text.contains("memo1"),
            "{text}"
        );
        let limits = trial_limit_lines();
        assert!(limits.starts_with("A trial account:\n  rents instances of 1 vCPU only\n"));
        assert!(
            limits.ends_with(
                "A deposit lifts these limits.\nThe trial credit still ends on its date."
            )
        );
        assert!(!limits.contains(';'));
    }

    /// `provider host delete` reads as a sentence and its steps; the
    /// activation terms show the exchange rate on one line and MMX amounts
    /// as MMX; the upgrades are a table of sizes and prices.
    #[test]
    fn deleted_hosts_terms_and_upgrades_read_as_text() {
        let host_id = Uuid::now_v7();
        let output = json!({"host": {"host_id": host_id, "label": "mev-1", "mode": "home_gateway",
            "status": "retired", "location": "de", "rentals_paused": true,
            "active_instance_count": 0, "can_retire": false,
            "retired_at": "2026-10-19T10:00:00Z"},
            "next_step": "Stop the hypervisor service."});
        let cli = Cli::try_parse_from([
            "ghost",
            "provider",
            "host",
            "delete",
            &host_id.to_string(),
            "--yes",
        ])
        .unwrap();
        let text = render_result(&cli, &output, Terminal::plain());
        assert_eq!(
            text.lines().take(2).collect::<Vec<_>>(),
            [
                format!("Host mev-1 ({host_id}) deleted."),
                "Before enrolling it again:".to_owned()
            ],
            "{text}"
        );
        assert!(text.contains("  3. Enroll it with a new token."), "{text}");

        let terms = json!({"deposit_address": "mmx1x", "minimum_deposit_mmx_atomic": 2_500_000,
            "minimum_confirmations": 6,
            "mmx_exchange_rate": {"usd_per_mmx": "0.100000000000000000",
                "expires_at": "2026-10-19T10:00:00Z"}});
        let cli = Cli::try_parse_from(["ghost", "account", "activation-terms"]).unwrap();
        let text = render_result(&cli, &terms, Terminal::plain());
        assert!(
            text.contains("$0.10 per MMX, until 2026-10-19 10:00:00 UTC"),
            "{text}"
        );
        assert!(text.contains("2.5 MMX"), "{text}");

        let upgrades = json!([{"offering_id": "of2_x", "cpu_tier": "shared_2x", "vcpu_count": 4,
            "memory_bytes": 8_u64 << 30, "root_disk_bytes": 64_u64 << 30,
            "base_price_microusd_per_month": 3_000_000,
            "full_utilization_price_microusd_per_month": 6_000_000,
            "balance_reservation_increase_microusd": 1_000_000, "available": true}]);
        let cli = Cli::try_parse_from(["ghost", "instance", "upgrades", &Uuid::nil().to_string()])
            .unwrap();
        let text = render_result(&cli, &upgrades, Terminal::plain());
        let rows = words(&text);
        assert_eq!(
            rows[1],
            [
                "of2_x", "4", "vCPU", "8", "GiB", "64", "GiB", "$3.00", "$6.00", "$1.00", "yes"
            ],
            "{text}"
        );
    }

    /// An instance with prices as the quotes read them.
    fn quoted_instance(with_pricing: bool) -> InstanceView {
        let mut view = json!({"instance_id": Uuid::nil(), "offering_id": "of2_J7hnuv_uO8PmXACeyas4QY",
            "hostname": "web-1", "name": "web-1", "root_disk_bytes": 20_u64 << 30,
            "vcpu_count": 2, "memory_bytes": 4_u64 << 30, "state": "running",
            "desired_power_state": "running", "holds_capacity": true, "public_ipv4": null,
            "gateway_tier": "shared_bandwidth", "gateway_location": "sg-singapore",
            "network_microusd_per_tib": 10_000_000, "created_at": Utc::now(),
            "balance_reservation_microusd": 0});
        if with_pricing {
            view["pricing"] = json!({"pending": [], "current": {
                "base_price_microusd_per_month": 2_350_000,
                "full_utilization_price_microusd_per_month": 7_060_000,
                "provider_network_microusd_per_tib": 7_000_000,
                "gateway_network_microusd_per_tib": 3_000_000,
                "gateway_base_microusd_per_month": 500_000}});
        }
        serde_json::from_value(view).unwrap()
    }

    fn quoted_upgrade(available: bool) -> InstanceUpgradeView {
        InstanceUpgradeView {
            offering_id: "of2_up".to_owned(),
            cpu_tier: gigahost_client_api::hypervisor::CpuTier::Shared2x,
            vcpu_count: 4,
            memory_bytes: 8 << 30,
            root_disk_bytes: 40 << 30,
            base_price_microusd_per_month: 4_700_000,
            full_utilization_price_microusd_per_month: 14_120_000,
            balance_reservation_increase_microusd: 1_200_000,
            available,
        }
    }

    /// The upgrade quote names the size and the prices before and after, and
    /// what is held more; without the instance's prices it shows the new
    /// ones alone; an offering that is not listed or has no room is a
    /// notice.
    #[test]
    fn the_upgrade_quote_shows_what_changes() {
        let quote = upgrade_quote(
            &quoted_instance(true),
            &[quoted_upgrade(true)],
            "of2_up",
            false,
        )
        .unwrap();
        assert_eq!(
            quote,
            [
                format!("Upgrading web-1 ({}):", Uuid::nil()),
                "  Size      2 vCPU, 4 GiB RAM, 20 GiB disk  →  4 vCPU, 8 GiB RAM, 40 GiB disk"
                    .to_owned(),
                "  Monthly    $2.35 → $4.70  base".to_owned(),
                "            $7.06 → $14.12  at full CPU".to_owned(),
                "  Held              +$1.20  more of your balance, taken now".to_owned(),
                "  The instance shuts down and starts again with the new size.".to_owned(),
            ],
            "{quote:#?}"
        );
        let bare = upgrade_quote(
            &quoted_instance(false),
            &[quoted_upgrade(true)],
            "of2_up",
            false,
        )
        .unwrap()
        .join("\n");
        assert!(bare.contains("$4.70") && !bare.contains("→  $") && !bare.contains("$2.35"));
        let unlisted = upgrade_quote(
            &quoted_instance(true),
            &[quoted_upgrade(true)],
            "other",
            false,
        )
        .unwrap_err();
        assert!(
            unlisted.contains("not among this instance's upgrades")
                && unlisted.contains("repeats an upgrade already made"),
            "{unlisted}"
        );
        let full = upgrade_quote(
            &quoted_instance(true),
            &[quoted_upgrade(false)],
            "of2_up",
            false,
        )
        .unwrap_err();
        assert!(full.contains("no room"), "{full}");
    }

    fn quoted_offering() -> OfferingView {
        let mut offering = home_offering_with_locations();
        offering.gateway_locations = serde_json::from_value(json!([
            {"location": "de-fra", "location_name": "Frankfurt, Germany", "country_code": "DE",
             "distance_km": 840, "bottleneck": true, "preselected": false,
             "gateway_base_charge_microusd_per_month": 700_000,
             "gateway_network_microusd_per_tib": 3_250_000,
             "shared_ip_base_charge_microusd_per_month": 300_000,
             "shared_ip_network_microusd_per_tib": 2_000_000},
            {"location": "old", "location_name": "", "country_code": "XX",
             "distance_km": 10, "bottleneck": false, "preselected": false},
        ]))
        .unwrap();
        offering.instance_creation_charge_microusd = 800_000;
        offering
    }

    /// The change quote shows the gateway and traffic prices before and
    /// after, the charge, the bottleneck only when there is one, no dollars
    /// where an older backend sent no prices, and a notice for a location
    /// that is not listed.
    #[test]
    fn the_gateway_change_quote_shows_what_changes() {
        let change = |instance, offering, tier, location| {
            gateway_change_quote(&instance, &offering, tier, location, false)
        };
        let quote = change(
            quoted_instance(true),
            quoted_offering(),
            None,
            Some("de-fra"),
        )
        .unwrap();
        assert_eq!(
            quote,
            [
                format!(
                    "Changing the gateway of web-1 ({}) to shared bandwidth in Frankfurt, Germany (de-fra):",
                    Uuid::nil()
                ),
                "  Distance   840 km from the host, crosses a bottleneck".to_owned(),
                "  Gateway      $0.50 → $0.70  per month".to_owned(),
                "  Traffic    $10.00 → $10.25  per TiB".to_owned(),
                "  Charge               $0.80  per change, the instance creation charge".to_owned(),
                "  From now on: the new prices apply at once.".to_owned(),
                "  The VM gets a new public address and is unreachable for the seconds the change takes."
                    .to_owned(),
            ],
            "{quote:#?}"
        );
        // A change of the tier alone stays at the location, at the shared
        // IP's slice prices there; with both, the location's.
        let ip = change(
            quoted_instance(true),
            quoted_offering(),
            Some(GatewayTier::SharedIp),
            Some("de-fra"),
        )
        .unwrap()
        .join("\n");
        assert!(
            ip.contains("to shared IP in Frankfurt")
                && ip.contains("$0.50 → $0.30")
                && ip.contains("$10.00 → $9.00")
                && ip.contains("$0.80"),
            "{ip}"
        );
        let bare = change(
            quoted_instance(false),
            quoted_offering(),
            None,
            Some("de-fra"),
        )
        .unwrap()
        .join("\n");
        assert!(
            bare.contains("per TiB, gateway part") && !bare.contains("→"),
            "{bare}"
        );
        let old = change(quoted_instance(true), quoted_offering(), None, Some("old"))
            .unwrap()
            .join("\n");
        assert!(
            old.contains("prices not known (older backend)")
                && !old.contains("$0.00")
                && !old.contains("bottleneck"),
            "{old}"
        );
        // A change off a gateway that is being retired, which its owner was
        // asked to move the instance off, costs nothing, whatever the
        // offering's charge: the quote says so and names no amount.
        let mut asked = quoted_instance(true);
        asked.gateway_change_free = true;
        let nothing = change(asked, quoted_offering(), None, Some("de-fra"))
            .unwrap()
            .join("\n");
        assert!(
            nothing.contains(
                "Charge     none: the gateway is being retired and you were asked to move the instance"
            ) && !nothing.contains("$0.80"),
            "{nothing}"
        );
        let mut free = quoted_offering();
        free.instance_creation_charge_microusd = 0;
        let unknown = change(quoted_instance(true), free, None, Some("de-fra"))
            .unwrap()
            .join("\n");
        assert!(
            unknown.contains("the instance creation charge (amount not known: older backend)"),
            "{unknown}"
        );
        let unlisted =
            change(quoted_instance(true), quoted_offering(), None, Some("xx")).unwrap_err();
        assert!(
            unlisted.contains("not among this offering's gateway locations"),
            "{unlisted}"
        );
    }

    /// An instance whose tier is not known gets a notice and no figures; a
    /// change to what the instance has already is a notice too, a high
    /// bandwidth one's included.
    #[test]
    fn the_gateway_change_quote_refuses_what_the_backend_refuses() {
        let notice = |tier: Option<GatewayTier>, to: Option<GatewayTier>, location: &str| {
            let mut instance = quoted_instance(true);
            instance.gateway_tier = tier;
            gateway_change_quote(&instance, &quoted_offering(), to, Some(location), false)
                .unwrap_err()
        };
        let high = notice(Some(GatewayTier::HighBandwidth), None, "sg-singapore");
        assert!(
            high.starts_with(
                "the instance is reached through a high bandwidth gateway at sg-singapore already"
            ),
            "{high}"
        );
        let mut instance = quoted_instance(true);
        instance.gateway_tier = Some(GatewayTier::HighBandwidth);
        let nowhere =
            gateway_change_quote(&instance, &quoted_offering(), None, None, false).unwrap_err();
        assert!(
            nowhere.contains("name another location with --location"),
            "{nowhere}"
        );
        for tier in [Some(GatewayTier::Unknown), None] {
            assert_eq!(
                notice(tier, None, "de-fra"),
                "the price of a change is not shown for this instance; the backend decides"
            );
        }
        let here = notice(Some(GatewayTier::SharedBandwidth), None, "sg-singapore");
        assert!(
            here.starts_with(
                "the instance is reached through a shared bandwidth gateway at sg-singapore already"
            ) && here.ends_with("the backend decides"),
            "{here}"
        );
        // Another tier at the same location is a change: with the
        // instance's own location among the offering's, the quote is the
        // other tier's prices there, and the same tier again is not one.
        let mut offering = quoted_offering();
        let mut own = offering.gateway_locations[0].clone();
        own.location = "sg-singapore".to_owned();
        own.location_name = "Singapore".to_owned();
        own.country_code = "SG".to_owned();
        offering.gateway_locations.push(own);
        let mut instance = quoted_instance(true);
        instance.gateway_tier = Some(GatewayTier::SharedBandwidth);
        let quote = gateway_change_quote(
            &instance,
            &offering,
            Some(GatewayTier::SharedIp),
            None,
            false,
        )
        .unwrap()
        .join("\n");
        assert!(
            quote.contains("to shared IP in Singapore (sg-singapore):")
                && quote.contains("$0.50 → $0.30")
                && quote.contains("$10.00 → $9.00")
                && quote.contains("$0.80"),
            "{quote}"
        );
        let same = gateway_change_quote(
            &instance,
            &offering,
            Some(GatewayTier::SharedBandwidth),
            None,
            false,
        )
        .unwrap_err();
        assert!(
            same.starts_with(
                "the instance is reached through a shared bandwidth gateway at sg-singapore already"
            ),
            "{same}"
        );
    }

    /// A change to high bandwidth quotes a gateway of the VM's own: that it
    /// takes a few minutes, the tier's prices the offering lists, the
    /// charge; full while the offering lists the tier full. A high
    /// bandwidth instance's change to a shared tier without a location goes
    /// where the backend places it: its location where one is listed, else
    /// the preselected one.
    #[test]
    fn the_gateway_change_quote_of_high_bandwidth() {
        let mut offering = quoted_offering();
        offering.network_prices = serde_json::from_value(json!([
            {"gateway_tier": "shared_bandwidth", "gateway_base_charge_microusd_per_month": 500_000,
             "combined_microusd_per_tib": 10_000_000},
            {"gateway_tier": "high_bandwidth", "gateway_base_charge_microusd_per_month": 6_000_000,
             "combined_microusd_per_tib": 8_000_000},
        ]))
        .unwrap();
        let quote = gateway_change_quote(
            &quoted_instance(true),
            &offering,
            Some(GatewayTier::HighBandwidth),
            None,
            false,
        )
        .unwrap();
        assert_eq!(
            quote,
            [
                format!(
                    "Changing the gateway of web-1 ({}) to high bandwidth, a gateway of its own nearest to the host:",
                    Uuid::nil()
                ),
                "  Takes     a few minutes: Vultr creates the gateway; the VM stays on its gateway until then"
                    .to_owned(),
                "  Gateway    $0.50 → $6.00  per month".to_owned(),
                "  Traffic   $10.00 → $8.00  per TiB".to_owned(),
                "  Charge             $0.80  per change, the instance creation charge".to_owned(),
                "  From now on: the new prices apply at once.".to_owned(),
                "  The VM gets a new public address and is unreachable for the seconds the change takes."
                    .to_owned(),
            ],
            "{quote:#?}"
        );
        // Another location of a high bandwidth instance: the nearest's
        // prices, said so.
        let mut high = quoted_instance(true);
        high.gateway_tier = Some(GatewayTier::HighBandwidth);
        let moved = gateway_change_quote(&high, &offering, None, Some("jp-tokyo"), false)
            .unwrap()
            .join("\n");
        assert!(
            moved.contains("a gateway of its own at jp-tokyo:")
                && moved.contains("per month (nearest location's)"),
            "{moved}"
        );
        let mut full = offering.clone();
        full.network_prices
            .retain(|price| price.gateway_tier != Some(GatewayTier::HighBandwidth));
        full.full_gateway_tiers = vec![GatewayTier::HighBandwidth];
        let none = gateway_change_quote(
            &quoted_instance(true),
            &full,
            Some(GatewayTier::HighBandwidth),
            None,
            false,
        )
        .unwrap()
        .join("\n");
        assert!(none.contains("none of its own can be set up now"), "{none}");
        // Off high bandwidth to shared IP, the instance's location is not
        // listed: the preselected one.
        let mut listed = offering.clone();
        listed.gateway_locations[0].preselected = true;
        let shared = gateway_change_quote(&high, &listed, Some(GatewayTier::SharedIp), None, false)
            .unwrap()
            .join("\n");
        assert!(
            shared.contains("to shared IP in Frankfurt, Germany (de-fra):"),
            "{shared}"
        );
    }

    fn instance_command(cli: &Cli) -> &InstanceCommand {
        match &cli.command {
            Command::Instance { command } => command,
            _ => unreachable!(),
        }
    }

    /// Both commands read before they write and, without `--yes`, write
    /// nothing and name the command to run; a failed read never stops them.
    #[tokio::test]
    async fn the_quotes_never_block_and_without_yes_write_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let id = Uuid::nil().to_string();
        let instance = serde_json::to_string(&quoted_instance(true)).unwrap();
        let upgrades = serde_json::to_string(&[quoted_upgrade(true)]).unwrap();
        let offering = serde_json::to_string(&quoted_offering()).unwrap();
        let job_id = Uuid::now_v7();
        let accepted = json!({"job_id": job_id, "resource_id": Uuid::nil(),
            "status_url": format!("/v1/jobs/{job_id}")})
        .to_string();
        let down = json!({"code": "unavailable", "message": "down"}).to_string();

        // Upgrade without --yes: two reads, no write, the command in the error.
        let (url, received) =
            canned_server(vec![(200, instance.clone()), (200, upgrades.clone())]).await;
        let error = execute(&account_command(
            &url,
            &seed,
            &["instance", "upgrade", &id, "--offering", "of2_up"],
        ))
        .await
        .unwrap_err();
        assert!(
            error.to_string().ends_with(&format!(
                "To upgrade: ghost instance upgrade {id} --offering of2_up --yes"
            )),
            "{error}"
        );
        assert_eq!(
            request_lines(&received),
            [
                format!("GET /v1/instances/{id}"),
                format!("GET /v1/instances/{id}/upgrades")
            ]
        );

        // Upgrade with a failed read: the write is still sent.
        // The first failed read ends the quote, so one read and the write.
        let (url, received) =
            canned_server(vec![(400, down.clone()), (200, accepted.clone())]).await;
        let cli = account_command(
            &url,
            &seed,
            &["instance", "upgrade", &id, "--offering", "of2_up", "--yes"],
        );
        let api = api_client(&cli).unwrap().with_read_retry_delays(&[]);
        let result = execute_instance(&cli, &api, instance_command(&cli), false)
            .await
            .unwrap();
        assert_eq!(result["job_id"], job_id.to_string());
        assert_eq!(request_lines(&received).len(), 2);
        assert!(request_lines(&received)[1].starts_with("POST /api/mut/v1/instances"));

        // Upgrade to an offering the instance's upgrades do not list: the
        // notice, and the write is still sent.
        let (url, received) = canned_server(vec![
            (200, instance.clone()),
            (200, upgrades.clone()),
            (200, accepted.clone()),
        ])
        .await;
        let result = execute(&account_command(
            &url,
            &seed,
            &["instance", "upgrade", &id, "--offering", "xx", "--yes"],
        ))
        .await
        .unwrap();
        assert_eq!(result["job_id"], job_id.to_string());
        assert_eq!(request_lines(&received).len(), 3);
        assert!(request_lines(&received)[2].starts_with("POST /api/mut/v1/instances"));

        // Move with a failed offering read: the write is still sent.
        let (url, received) = canned_server(vec![
            (200, instance.clone()),
            (400, down),
            (200, accepted.clone()),
        ])
        .await;
        let cli = account_command(
            &url,
            &seed,
            &["instance", "gateway-location", &id, "de-fra", "--yes"],
        );
        let api = api_client(&cli).unwrap().with_read_retry_delays(&[]);
        let result = execute_instance(&cli, &api, instance_command(&cli), false)
            .await
            .unwrap();
        assert_eq!(result["job_id"], job_id.to_string());
        assert_eq!(request_lines(&received).len(), 3);
        assert!(request_lines(&received)[2].starts_with("POST /api/mut/v1/instances"));

        // Move to a location the offering lists: reads, then the write.
        let (url, received) = canned_server(vec![
            (200, instance.clone()),
            (200, offering.clone()),
            (200, accepted.clone()),
        ])
        .await;
        let result = execute(&account_command(
            &url,
            &seed,
            &["instance", "gateway-location", &id, "de-fra", "--yes"],
        ))
        .await
        .unwrap();
        assert_eq!(result["job_id"], job_id.to_string());
        assert_eq!(
            request_lines(&received)[..2],
            [
                format!("GET /v1/instances/{id}"),
                "GET /v1/catalog/offerings/of2_J7hnuv_uO8PmXACeyas4QY".to_owned()
            ]
        );
        assert!(request_lines(&received)[2].starts_with("POST /api/mut/v1/instances"));

        // Move to an unlisted location: the notice, and the write is still sent.
        let (url, received) = canned_server(vec![
            (200, instance.clone()),
            (200, offering.clone()),
            (200, accepted.clone()),
        ])
        .await;
        execute(&account_command(
            &url,
            &seed,
            &["instance", "gateway-location", &id, "xx", "--yes"],
        ))
        .await
        .unwrap();
        assert_eq!(request_lines(&received).len(), 3);

        // Move without --yes: reads only, and the command in the error.
        let (url, received) =
            canned_server(vec![(200, instance.clone()), (200, offering.clone())]).await;
        let error = execute(&account_command(
            &url,
            &seed,
            &["instance", "gateway-location", &id, "de-fra"],
        ))
        .await
        .unwrap_err();
        assert!(
            error.to_string().ends_with(&format!(
                "To move: ghost instance gateway-location {id} de-fra --yes"
            )),
            "{error}"
        );
        // The change costs the charge, named before anything is charged.
        assert!(
            error.to_string().contains("the change costs $0.80"),
            "{error}"
        );
        assert_eq!(request_lines(&received).len(), 2);

        // A change off a gateway being retired, which its owner was asked
        // to move the instance off, is free, and both commands say so
        // instead of naming the charge.
        let mut asked = quoted_instance(true);
        asked.gateway_change_free = true;
        let asked = serde_json::to_string(&asked).unwrap();
        for args in [
            vec!["instance", "gateway-location", &id, "de-fra"],
            vec!["instance", "gateway", &id, "--location", "de-fra"],
        ] {
            let (url, received) =
                canned_server(vec![(200, asked.clone()), (200, offering.clone())]).await;
            let error = execute(&account_command(&url, &seed, &args))
                .await
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("the change costs nothing: the gateway is being retired;")
                    && !error.to_string().contains("$0.80"),
                "{error}"
            );
            assert_eq!(request_lines(&received).len(), 2);
        }

        // The change of the tier without --yes: reads only, the charge and
        // the command with its tier and location in the error.
        let (url, received) =
            canned_server(vec![(200, instance.clone()), (200, offering.clone())]).await;
        let error = execute(&account_command(
            &url,
            &seed,
            &[
                "instance",
                "gateway",
                &id,
                "--tier",
                "shared-ip",
                "--location",
                "de-fra",
            ],
        ))
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("the change costs $0.80")
                && error.to_string().ends_with(&format!(
                    "To change: ghost instance gateway {id} --tier shared-ip --location de-fra --yes"
                )),
            "{error}"
        );
        assert_eq!(request_lines(&received).len(), 2);

        // With --yes it posts the change of the gateway.
        let (url, received) = canned_server(vec![
            (200, instance.clone()),
            (200, offering.clone()),
            (200, accepted.clone()),
        ])
        .await;
        let result = execute(&account_command(
            &url,
            &seed,
            &["instance", "gateway", &id, "--tier", "shared-ip", "--yes"],
        ))
        .await
        .unwrap();
        assert_eq!(result["job_id"], job_id.to_string());
        assert_eq!(
            request_lines(&received)[2],
            format!("POST /api/mut/v1/instances/{id}/gateway")
        );

        // High bandwidth: the quote says it takes minutes and names the
        // charge; with --yes it posts the tier alone.
        let (url, received) =
            canned_server(vec![(200, instance.clone()), (200, offering.clone())]).await;
        let error = execute(&account_command(
            &url,
            &seed,
            &["instance", "gateway", &id, "--tier", "high-bandwidth"],
        ))
        .await
        .unwrap_err();
        assert!(
            error.to_string().contains("the change costs $0.80")
                && error.to_string().ends_with(&format!(
                    "To change: ghost instance gateway {id} --tier high-bandwidth --yes"
                )),
            "{error}"
        );
        assert_eq!(request_lines(&received).len(), 2);
        let (url, received) = canned_server(vec![
            (200, instance.clone()),
            (200, offering.clone()),
            (200, accepted.clone()),
        ])
        .await;
        let result = execute(&account_command(
            &url,
            &seed,
            &[
                "instance",
                "gateway",
                &id,
                "--tier",
                "high-bandwidth",
                "--yes",
            ],
        ))
        .await
        .unwrap();
        assert_eq!(result["job_id"], job_id.to_string());
        let posted = received.lock().unwrap()[2].clone();
        assert!(
            posted
                .0
                .starts_with(&format!("POST /api/mut/v1/instances/{id}/gateway "))
        );
        let body: serde_json::Value = serde_json::from_slice(&posted.1).unwrap();
        assert_eq!(body, json!({"tier": "high_bandwidth"}));

        // Neither a tier nor a location is refused before any request.
        let (url, received) = canned_server(vec![]).await;
        execute(&account_command(
            &url,
            &seed,
            &["instance", "gateway", id.as_str()],
        ))
        .await
        .unwrap_err();
        assert!(request_lines(&received).is_empty());
    }
}
