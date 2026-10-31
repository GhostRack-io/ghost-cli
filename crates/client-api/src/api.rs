//! Customer and browser API contracts.
use crate::website::{
    AccountActivationTerms, AccountAuthKeyView, AccountBalanceView, AccountSessionView,
    AccountSshKeyView, AccountView, ActivateAccountRequest, ActiveSessionView,
    AddAccountSshKeyRequest, AddCloudIpAddressesRequest, AddPrivateRenterRequest,
    AddSupportTicketMessageRequest, AgentUpdateAttemptRequest, ApproveAgentUpdateRequest,
    AuthorizeBackupRestoreRequest, BackupInstanceView, BackupPricingView, BackupScheduleView,
    BackupView, BrowserOperationInput, BrowserOperationView, CloudIpPoolView,
    CompleteOperationIntentRequest, CompleteTrialClaimRequest, CompletedTrialClaimView,
    ContainerLogView, CreateBackupRequest, CreateCloudIpPoolRequest,
    CreateHostEnrollmentTokenRequest, CreateInstanceRequest, CreateProviderPayoutRequest,
    CreateSupportTicketRequest, DeclareHostEmergencyRequest, GatewayTrafficView,
    GithubLoginRequest, GithubLoginStart, GithubUnlinked, HandOverCloudIpPoolRequest, HistoryPage,
    HostAgentUpdateView, HostEnrollmentToken, HostNetworkTestsView, HostPricingView,
    HostPrivacyView, ImageView, InstanceConsoleLogView, InstanceConsoleSessionsView,
    InstanceHardwareView, InstanceLocationView, InstanceProviderTerminationView,
    InstanceProviderView, InstanceSystemView, InstanceTagView, InstanceUpgradeView, InstanceView,
    JobAccepted, JobPage, JobView, LocationView, LoginGrant, MigrateAccountSeedRequest,
    NotificationsReadView, OfferingView, PasswordChallenge, PasswordChallengeRequest,
    PasswordLoginRequest, PrivateRenterView, ProtectedBalanceView, ProviderBalanceView,
    ProviderHostDetailView, ProviderHostView, ProviderIncidentView, ProviderOutageDetailView,
    ProviderOutagePage, ProviderPayoutAddressView, ProviderPayoutView, ProviderReliabilityView,
    ProviderRentalView, ProviderUptimeView, RedeemLoginGrantRequest, RedeemLoginGrantResponse,
    RedeployInstanceRequest, ReinstallInstanceRequest, ReleaseChannelsView, RenameInstanceRequest,
    RestoreBackupRequest, RotateGatewayKeysRequest, ScheduleHostRetirementRequest,
    ScheduleInstanceRetirementRequest, SessionRevocationView, SetAgentUpdatePolicyRequest,
    SetBackupScheduleRequest, SetHostPrivateRequest, SetHostRentalPauseRequest,
    SetNotificationReadRequest, SetPortForwardsRequest, SetPowerStateRequest,
    SetProtectedBalanceRequest, SetProviderIncidentStateRequest, SetProviderPayoutAddressRequest,
    SetSupportTicketStateRequest, SetTagRedundantRequest, SetWebsitePasswordRequest,
    SupportTicketSummaryView, SupportTicketView, TagInstanceRequest, TrialClaimStatusView,
    TrialClaimView, UpdateHostPricingRequest, UpdateInstanceRequest, UpgradeInstanceRequest,
    UserNotificationView, WebsitePasswordRemoved, WebsitePasswordView, WriteProviderReviewRequest,
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use uuid::Uuid;
/// An HTTP method of the website API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
}

impl Method {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Delete => "DELETE",
        }
    }
}

/// Authorization required to call an endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Access {
    /// Anyone, without credentials.
    Public,
    /// The account, by a request its key signs or with its website session.
    User,
    /// An account with the operator role, signed or with its website
    /// session; any other account gets 403.
    Operator,
    /// Only a request signed with the account key: key management and payout
    /// destinations require it. A website session receives 403
    /// `signed_request_required`.
    Wallet,
}

impl Access {
    /// Whether the backend serves anonymous callers.
    #[must_use]
    pub const fn is_public(self) -> bool {
        matches!(self, Self::Public)
    }
}

/// One endpoint as [`ALL`] lists it.
#[derive(Clone, Copy, Debug)]
pub struct Listing {
    pub method: Method,
    pub route: &'static str,
    /// [`Endpoint::ACCESS`].
    pub access: Access,
}

/// One API endpoint. A value of the implementing type is one call: it holds
/// the path parameters.
pub trait Endpoint {
    const METHOD: Method;
    /// The route with `{name}` for each path parameter.
    const ROUTE: &'static str;
    /// Who may call it.
    const ACCESS: Access;
    /// Whether the call carries a JSON body of type `Request`.
    const HAS_BODY: bool;
    type Request: Serialize;
    type Response: DeserializeOwned;

    /// The path of this call, without a query string.
    fn path(&self) -> String;
}

/// A path parameter as one path segment: every byte but RFC 3986's
/// unreserved ones percent-encoded, and a `.` or `..` value's dots too, so
/// no value (an offering ID from a URL) can add a segment, a dot segment
/// or a query, or make the request target unbuildable. A UUID, an
/// offering ID and a resource name stay as they are.
#[must_use]
pub fn path_segment(value: &str) -> String {
    use std::fmt::Write as _;
    let dots = matches!(value, "." | "..");
    let mut segment = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'~')
            || (byte == b'.' && !dots)
        {
            segment.push(char::from(byte));
        } else {
            let _ = write!(segment, "%{byte:02X}");
        }
    }
    segment
}

#[macro_export]
macro_rules! endpoints {
    ($(
        $(#[doc = $doc:literal])*
        $name:ident $({ $($param:ident: $param_type:ty),* $(,)? })?
            = $access:ident $method:ident $route:literal $(($request:ty))? => $response:ty;
    )*) => {
        $(
            $crate::endpoints!(@struct [$(#[doc = $doc])*] $name $({ $($param: $param_type),* })?);

            impl $crate::api::Endpoint for $name {
                const METHOD: $crate::api::Method = $crate::endpoints!(@method $method);
                const ROUTE: &'static str = $route;
                const ACCESS: $crate::api::Access = $crate::endpoints!(@access $access);
                const HAS_BODY: bool = $crate::endpoints!(@has_body $($request)?);
                type Request = $crate::endpoints!(@request $($request)?);
                type Response = $response;

                fn path(&self) -> String {
                    #[allow(unused_mut)]
                    let mut path = String::from($route);
                    $($(
                        path = path.replace(
                            concat!("{", stringify!($param), "}"),
                            &$crate::api::path_segment(&self.$param.to_string()),
                        );
                    )*)?
                    path
                }
            }
        )*

        /// Method, route, and access of every endpoint.
        pub const DECLARED: &[$crate::api::Listing] = &[$($crate::api::Listing {
            method: <$name as $crate::api::Endpoint>::METHOD,
            route: <$name as $crate::api::Endpoint>::ROUTE,
            access: <$name as $crate::api::Endpoint>::ACCESS,
        }),*];
    };
    (@struct [$($doc:tt)*] $name:ident) => {
        $($doc)*
        #[derive(Clone, Debug)]
        pub struct $name;
    };
    (@struct [$($doc:tt)*] $name:ident { $($param:ident: $param_type:ty),* }) => {
        $($doc)*
        #[derive(Clone, Debug)]
        pub struct $name {
            $(pub $param: $param_type),*
        }
    };
    (@method GET) => { $crate::api::Method::Get };
    (@method POST) => { $crate::api::Method::Post };
    (@method PUT) => { $crate::api::Method::Put };
    (@method DELETE) => { $crate::api::Method::Delete };
    (@access public) => { $crate::api::Access::Public };
    (@access user) => { $crate::api::Access::User };
    (@access operator) => { $crate::api::Access::Operator };
    (@access wallet) => { $crate::api::Access::Wallet };
    (@has_body) => { false };
    (@has_body $request:ty) => { true };
    (@request) => { () };
    (@request $request:ty) => { $request };
}

endpoints! {

    // Catalog
    /// The enabled locations; with `listed=true` only those the catalog
    /// lists an offering in now, as the cached catalog has them.
    ListLocations = public GET "/v1/catalog/locations" => Vec<LocationView>;
    /// The listed offerings, cheapest first by the listed price
    /// ([`OfferingView::price_for`] of the `ip` asked for, dedicated
    /// without it) and then by ID; `after=PRICE.ID` starts after that
    /// listed price and offering.
    ListOfferings = public GET "/v1/catalog/offerings" => Vec<OfferingView>;
    /// One offering while it is listed: it has capacity and its terms hold.
    GetOffering { offering_id: String } =
        public GET "/v1/catalog/offerings/{offering_id}" => OfferingView;
    ListImages = public GET "/v1/catalog/images" => Vec<ImageView>;
    /// The platform's stock container images, by slug.
    ListContainerImages =
        public GET "/v1/catalog/container-images" => Vec<crate::website::ContainerImageView>;
    GetBackupPricing = public GET "/v1/catalog/backup-pricing" => BackupPricingView;
    /// The platform's own prices the renting flow does not show: the host
    /// mesh's, in effect and to come.
    GetPlatformPricing =
        public GET "/v1/catalog/platform-pricing" => crate::website::PlatformPricingView;
    /// The signed release channels for the hypervisor agent and the CLI.
    GetReleaseChannels = public GET "/v1/releases" => ReleaseChannelsView;
    GetHostNetworkTests { host_id: Uuid } =
        public GET "/v1/catalog/hosts/{host_id}/network-tests" => HostNetworkTestsView;
    GetProviderReliability { provider_id: Uuid } =
        public GET "/v1/catalog/providers/{provider_id}/reliability" => ProviderReliabilityView;
    /// The reliability of each active provider `ids` names (comma-separated,
    /// at most 100), in one read for a page that lists many providers.
    ListProviderReliability =
        public GET "/v1/catalog/providers/reliability" => Vec<ProviderReliabilityView>;
    ListProviderReviews { provider_id: Uuid } =
        public GET "/v1/catalog/providers/{provider_id}/reviews" => Value;
    /// The public status page's data: every component's state and the
    /// operator's notices, reused for 15 seconds.
    GetStatus = public GET "/v1/status" => crate::website::PlatformStatusView;

    // Account
    GetAccount = user GET "/v1/account" => AccountView;
    /// The caller's account alias, operator role and provider profile, and
    /// the website session the request came with, if any.
    GetAccountSession = user GET "/v1/account/session" => AccountSessionView;
    GetActivationTerms = public GET "/v1/account/activation-terms" => AccountActivationTerms;
    /// Signed with the key it registers; no existing account is required.
    ActivateAccount =
        wallet POST "/api/mut/v1/account/activate" (ActivateAccountRequest) => AccountView;
    /// A trial claim for the account the three keys would make: signed
    /// with the key it registers, as an activation is, and refused while
    /// trials are off, for a key that has an account, and past the claims
    /// an address or the platform may make an hour. Its link, valid 10
    /// minutes, signs in with GitHub; a new claim of the key replaces it.
    CreateTrialClaim = wallet POST "/api/mut/v1/account/trial-claims"
        (ActivateAccountRequest) => TrialClaimView;
    /// What became of a trial claim, which the client polls after opening
    /// its link: pending, created (the account's alias) or refused (why).
    GetTrialClaim { claim_id: String } =
        public GET "/v1/account/trial-claims/{claim_id}" => TrialClaimStatusView;
    /// The GitHub sign-in's return, which the website sends: spends the
    /// claim `state` names, once, and creates the trial account when the
    /// GitHub account qualifies, with a website session for the browser
    /// that came back (a sign-up's claim only).
    CompleteTrialClaim = public POST "/api/mut/v1/account/trial-claims/complete"
        (CompleteTrialClaimRequest) => CompletedTrialClaimView;
    /// A GitHub sign-up: the trial claim's new name, the same request and
    /// answer. The account is made at the sign-in, linked to the GitHub
    /// account, with the trial credit; one that cannot have the credit is
    /// refused.
    CreateGithubSignup = wallet POST "/api/mut/v1/account/github/signup"
        (ActivateAccountRequest) => TrialClaimView;
    /// A claim that links the GitHub account the browser signs in with to
    /// the account whose owner key signs this, with the trial credit if
    /// that GitHub account qualifies. Refused while the account has a
    /// GitHub account linked.
    CreateGithubLink = wallet POST "/api/mut/v1/account/github/link" => TrialClaimView;
    /// What became of a GitHub sign-up's or link's claim (as
    /// `GetTrialClaim`).
    GetGithubClaim { claim_id: String } =
        public GET "/v1/account/github/claims/{claim_id}" => TrialClaimStatusView;
    /// Unlinks the account's GitHub account and ends the website sessions
    /// a GitHub login began; the link's record stays.
    UnlinkGithub = wallet POST "/api/mut/v1/account/github/unlink" => GithubUnlinked;
    /// A GitHub login's start: GitHub's sign-in URL with a signed state,
    /// valid 10 minutes, and its nonce, which the website keeps in a cookie.
    StartGithubLogin = public POST "/api/mut/v1/account/login/github/start" => GithubLoginStart;
    /// Logs in with GitHub: the state, GitHub's code and the browser's
    /// nonce. The session is a password's: never a fresh login. A GitHub
    /// account linked to no account is refused.
    GithubLogin = public POST "/api/mut/v1/account/login/github"
        (GithubLoginRequest) => RedeemLoginGrantResponse;
    ListAuthKeys = user GET "/v1/account/auth-keys" => Vec<AccountAuthKeyView>;
    /// The SSH public keys the account saved for new instances, oldest
    /// first; the website offers them when an instance is rented or
    /// reinstalled, and the CLI installs them unless keys are named.
    ListAccountSshKeys = user GET "/v1/account/ssh-keys" => Vec<AccountSshKeyView>;
    /// Save an SSH public key under a label; at most 20 per account.
    AddAccountSshKey =
        user POST "/api/mut/v1/account/ssh-keys" (AddAccountSshKeyRequest) => AccountSshKeyView;
    /// Forget a saved key; the instances it was copied into keep it.
    RemoveAccountSshKey { ssh_key_id: Uuid } =
        user POST "/api/mut/v1/account/ssh-keys/{ssh_key_id}/remove" => AccountSshKeyView;
    GetAccountBalance = user GET "/v1/account/balance" => AccountBalanceView;
    /// Sets the account's protected balance, which new rentals, upgrades, backups and restores
    /// leave for the instances already running; none follows the platform's default again. It takes
    /// effect at once, lower or higher.
    SetProtectedBalance = user PUT "/api/mut/v1/account/protected-balance"
        (SetProtectedBalanceRequest) => ProtectedBalanceView;
    /// A session that could mint sessions would let a stolen cookie outlive
    /// every expiry.
    CreateLoginGrant = wallet POST "/api/mut/v1/account/login" => LoginGrant;
    RedeemLoginGrant = public POST "/api/mut/v1/account/login/redeem"
        (RedeemLoginGrantRequest) => RedeemLoginGrantResponse;
    /// A password login's challenge: 32 bytes, single use, for 60 seconds.
    /// Any well-formed alias gets one, known or not; at most 20 challenges and
    /// logins a minute from one address.
    CreatePasswordChallenge = public POST "/api/mut/v1/account/login/challenge"
        (PasswordChallengeRequest) => PasswordChallenge;
    /// Logs in with the website password: the challenge signed by the key
    /// derived from it. An unknown alias and a wrong password are refused
    /// alike; the session is the one a login link gives.
    PasswordLogin = public POST "/api/mut/v1/account/login/password"
        (PasswordLoginRequest) => RedeemLoginGrantResponse;
    /// Sets or replaces the website password by the public key derived
    /// from it, ending the sessions the old one began. Only the account
    /// key does, so a stolen session cannot take the account over.
    SetWebsitePassword = wallet PUT "/api/mut/v1/account/website-password"
        (SetWebsitePasswordRequest) => WebsitePasswordView;
    /// Turns password login off, ending the sessions the password began.
    RemoveWebsitePassword =
        wallet POST "/api/mut/v1/account/website-password/remove" => WebsitePasswordRemoved;
    Logout = user POST "/api/mut/v1/account/logout" => SessionRevocationView;
    RevokeSessions = user POST "/api/mut/v1/account/sessions/revoke" => SessionRevocationView;
    /// The account's website sessions that still work, newest first.
    ListSessions = user GET "/v1/account/sessions" => Vec<ActiveSessionView>;
    /// End one website session of the account, such as one a lost device
    /// holds.
    RevokeSession { session_id: Uuid } =
        user POST "/api/mut/v1/account/sessions/{session_id}/revoke" => SessionRevocationView;
    MigrateAccountSeed =
        wallet POST "/api/mut/v1/account/migrate-seed" (MigrateAccountSeedRequest) => AccountView;
    /// A single-use token that enrolls one host, shown once. It records the
    /// key that signed the request, or for a website session the key whose
    /// login link began it.
    CreateHostEnrollmentToken = user POST "/api/mut/v1/account/host-enrollment-tokens"
        (CreateHostEnrollmentTokenRequest) => HostEnrollmentToken;
    ListNotifications = user GET "/v1/account/notifications" => Vec<UserNotificationView>;
    SetNotificationRead { notification_id: Uuid } =
        user POST "/api/mut/v1/account/notifications/{notification_id}"
        (SetNotificationReadRequest) => UserNotificationView;
    MarkNotificationsRead =
        user POST "/api/mut/v1/account/notifications/read" => NotificationsReadView;
    AccountHistory = user GET "/v1/account/history" => HistoryPage;
    /// The account history's totals per UTC hour, day or month (`period`),
    /// by kind and instance, newest first; `instance_id` and `kind` filter
    /// it as they filter the history.
    AccountHistoryTotals = user GET "/v1/account/history/totals" => HistoryPage;
    /// What the caller's providers earned per UTC hour, day or month
    /// (`period`), by kind, newest first, 50 periods a page.
    ProviderEarningsTotals = user GET "/v1/provider/earnings/totals" => HistoryPage;
    AccountDeposits = user GET "/v1/account/deposits" => HistoryPage;
    AccountSlaCredits = user GET "/v1/account/sla-credits" => HistoryPage;
    CreateOperationIntent = user POST "/api/mut/v1/account/operation-intents"
        (BrowserOperationInput) => BrowserOperationView;
    GetOperationIntent { id: Uuid } =
        user GET "/v1/account/operation-intents/{id}" => BrowserOperationView;
    CompleteOperationIntent { id: Uuid } =
        user POST "/api/mut/v1/account/operation-intents/{id}/complete"
        (CompleteOperationIntentRequest) => BrowserOperationView;
    GetOwnProviderReview { provider_id: Uuid } =
        user GET "/v1/account/provider-reviews/{provider_id}" => Option<Value>;
    WriteProviderReview { provider_id: Uuid } =
        user PUT "/api/mut/v1/providers/{provider_id}/review" (WriteProviderReviewRequest) => Value;

    // Instances, backups, and jobs
    /// The account's instances that are not deleted, newest first, or as
    /// the query's filters and sort ask; with `ids` (comma-separated, at
    /// most 100) the named ones, deleted ones too.
    ListInstances = user GET "/v1/instances" => Vec<InstanceView>;
    /// The providers of the account's instances that are not deleted, at
    /// most 500: what the instance list's provider filter offers.
    ListInstanceProviders = user GET "/v1/instances/providers" => Vec<InstanceProviderView>;
    /// The locations of the account's instances that are not deleted, at
    /// most 500: what the instance list's location filter offers.
    ListInstanceLocations = user GET "/v1/instances/locations" => Vec<InstanceLocationView>;
    /// The systems the account's instances that are not deleted run (a
    /// catalog image or a stock container image), at most 500: what the
    /// instance list's system filter offers.
    ListInstanceSystems = user GET "/v1/instances/systems" => Vec<InstanceSystemView>;
    /// The account's tags, each with how many of its instances that are
    /// not deleted carry it, by tag, at most 500 (the first by tag): what
    /// the lists' tag filters offer.
    ListInstanceTags = user GET "/v1/instances/tags" => Vec<InstanceTagView>;
    CreateInstance = user POST "/api/mut/v1/instances" (CreateInstanceRequest) => JobAccepted;
    GetInstance { instance_id: Uuid } = user GET "/v1/instances/{instance_id}" => InstanceView;
    DeleteInstance { instance_id: Uuid } =
        user DELETE "/api/mut/v1/instances/{instance_id}" => JobAccepted;
    SetInstancePower { instance_id: Uuid } =
        user POST "/api/mut/v1/instances/{instance_id}/power" (SetPowerStateRequest) => JobAccepted;
    ReinstallInstance { instance_id: Uuid } = user POST
        "/api/mut/v1/instances/{instance_id}/reinstall" (ReinstallInstanceRequest) => JobAccepted;
    /// Refresh the saved container image or replace only its tag, keeping all settings, secrets and
    /// allocations.
    UpdateInstance { instance_id: Uuid } = user POST
        "/api/mut/v1/instances/{instance_id}/update" (UpdateInstanceRequest) => JobAccepted;
    /// Move a container instance to another image on its own root disk, keeping its volumes.
    RedeployInstance { instance_id: Uuid } = user POST
        "/api/mut/v1/instances/{instance_id}/redeploy" (RedeployInstanceRequest) => JobAccepted;
    /// Reset a VM's SSH access through cloud-init at its next boot, which the reset starts.
    ResetInstanceAccess { instance_id: Uuid } = user POST
        "/api/mut/v1/instances/{instance_id}/reset-access"
        (crate::website::ResetInstanceAccessRequest) => JobAccepted;
    /// Boot a VM into the platform's rescue system with its own disk attached, reached over SSH at
    /// its own addresses.
    RescueInstance { instance_id: Uuid } = user POST
        "/api/mut/v1/instances/{instance_id}/rescue"
        (crate::website::RescueInstanceRequest) => JobAccepted;
    /// End a VM's rescue: it boots its own system again.
    EndInstanceRescue { instance_id: Uuid } = user POST
        "/api/mut/v1/instances/{instance_id}/rescue/exit" => JobAccepted;
    ListInstanceUpgrades { instance_id: Uuid } =
        user GET "/v1/instances/{instance_id}/upgrades" => Vec<InstanceUpgradeView>;
    UpgradeInstance { instance_id: Uuid } = user POST
        "/api/mut/v1/instances/{instance_id}/upgrade" (UpgradeInstanceRequest) => JobAccepted;
    /// Move a shared bandwidth instance to a shared gateway at another
    /// location, where it gets a new public address.
    MoveGatewayLocation { instance_id: Uuid } = user POST
        "/api/mut/v1/instances/{instance_id}/gateway-location"
        (crate::website::MoveGatewayLocationRequest) => JobAccepted;
    /// Change a home instance's gateway: its tier (shared IP or shared
    /// bandwidth), its location, or both; it gets a new public address.
    ChangeGateway { instance_id: Uuid } = user POST
        "/api/mut/v1/instances/{instance_id}/gateway"
        (crate::website::ChangeGatewayRequest) => JobAccepted;
    RotateGatewayKeys { instance_id: Uuid } = user POST
        "/api/mut/v1/instances/{instance_id}/gateway/rotate-keys" (RotateGatewayKeysRequest)
        => JobAccepted;
    /// Give the instance another name, which only the website and the CLI
    /// show; the guest and its hostname stay as they are. No job: the
    /// instance as it is now.
    RenameInstance { instance_id: Uuid } = user POST
        "/api/mut/v1/instances/{instance_id}/rename" (RenameInstanceRequest) => InstanceView;
    /// Add tags to the instance and remove others, which only its renter
    /// and the operators see. No job: the instance as it is now.
    TagInstance { instance_id: Uuid } = user POST
        "/api/mut/v1/instances/{instance_id}/tags" (TagInstanceRequest) => InstanceView;
    /// Mark one of the account's tags redundant, or clear the flag: its
    /// instances are then never placed on one host. The tag as the list
    /// of the account's tags shows it.
    SetTagRedundant { tag: String } = user POST
        "/api/mut/v1/instances/tags/{tag}/redundant" (SetTagRedundantRequest) => InstanceTagView;
    /// Change where ports of a shared IP instance's slice are forwarded;
    /// unnamed ports stay unchanged. No job; returns the instance as it is now.
    SetPortForwards { instance_id: Uuid } = user POST
        "/api/mut/v1/instances/{instance_id}/port-forwards" (SetPortForwardsRequest)
        => InstanceView;
    GetHttpProxy { instance_id: Uuid } = user GET
        "/v1/instances/{instance_id}/http-proxy" => crate::website::HttpProxyView;
    SetHttpProxy { instance_id: Uuid } = user PUT
        "/api/mut/v1/instances/{instance_id}/http-proxy" (crate::website::SetHttpProxyRequest)
        => crate::website::HttpProxyView;
    SaveHttpProxyEntry { instance_id: Uuid } = user POST
        "/api/mut/v1/instances/{instance_id}/http-proxy/entries" (crate::website::SaveHttpProxyEntryRequest)
        => crate::website::HttpProxyView;
    RemoveHttpProxyEntry { instance_id: Uuid, subdomain: String } = user DELETE
        "/api/mut/v1/instances/{instance_id}/http-proxy/entries/{subdomain}"
        => crate::website::HttpProxyView;
    GetInstanceUsage { instance_id: Uuid } =
        user GET "/v1/instances/{instance_id}/usage" => HistoryPage;
    /// A page of a home instance's host mesh traffic over one path (`path`, `wan_mesh` or
    /// `lan_mesh`) at a resolution: what it sent (billed) and received (free) each period.
    GetInstanceMeshUsage { instance_id: Uuid } =
        user GET "/v1/instances/{instance_id}/mesh-usage" => HistoryPage;
    /// The instance's links of the host mesh, with what each carried this
    /// month, today and in the last 15 minutes, or why it has none.
    GetInstanceMesh { instance_id: Uuid } =
        user GET "/v1/instances/{instance_id}/mesh" => crate::website::InstanceMeshView;
    /// The current reading of each instance `ids` names (comma-separated,
    /// at most 100), as `GetInstanceUsage?resolution=current` has it; one
    /// read for a page of instances.
    ListInstancesCurrentUsage = user GET "/v1/instances/current-usage" => HistoryPage;
    /// The hardware of the instance's host, as its offering shows it.
    GetInstanceHardware { instance_id: Uuid } =
        user GET "/v1/instances/{instance_id}/hardware" => InstanceHardwareView;
    /// Informational; billing never uses these figures.
    GetInstanceGatewayTraffic { instance_id: Uuid } =
        user GET "/v1/instances/{instance_id}/gateway-traffic" => GatewayTrafficView;
    /// The end of the guest's serial console output, as its host last sent
    /// it: at most the last `bytes` (1 to 65536, the default) bytes. The
    /// instance's renter and operators may read it.
    GetInstanceConsoleLog { instance_id: Uuid } =
        user GET "/v1/instances/{instance_id}/console-log" => InstanceConsoleLogView;
    /// The sessions of the instance's serial console its renter opened over
    /// SSH, the newest first: when, from where, with which key, and how
    /// each ended. Only the instance's renter may read them.
    ListInstanceConsoleSessions { instance_id: Uuid } =
        user GET "/v1/instances/{instance_id}/console-sessions" => InstanceConsoleSessionsView;
    /// The end of what a container instance's container wrote, as its host
    /// last sent it, and of what it wrote before its last start. Only the
    /// instance's renter may read it; a VM has none (404).
    GetInstanceLogs { instance_id: Uuid } =
        user GET "/v1/instances/{instance_id}/logs" => ContainerLogView;
    ListBackups = user GET "/v1/backups" => Vec<BackupView>;
    /// The account's instances that have backups, deleted instances too,
    /// the newest first and at most 500: those with a backup that is not
    /// deleted, or with any backup when `include_deleted` is true. What
    /// the backup list's instance filter offers.
    ListBackupInstances = user GET "/v1/backups/instances" => Vec<BackupInstanceView>;
    GetBackup { backup_id: Uuid } = user GET "/v1/backups/{backup_id}" => BackupView;
    ListInstanceBackups { instance_id: Uuid } =
        user GET "/v1/instances/{instance_id}/backups" => Vec<BackupView>;
    CreateBackup { instance_id: Uuid } =
        user POST "/api/mut/v1/instances/{instance_id}/backups" (CreateBackupRequest) => JobAccepted;
    RestoreBackup { instance_id: Uuid, backup_id: Uuid } = user POST
        "/api/mut/v1/instances/{instance_id}/backups/{backup_id}/restore" (RestoreBackupRequest)
        => JobAccepted;
    DeleteBackup { instance_id: Uuid, backup_id: Uuid } =
        user DELETE "/api/mut/v1/instances/{instance_id}/backups/{backup_id}" => JobAccepted;
    /// The instance's backup schedule: its live rules with their next run
    /// and last result, and the latest removed rules whose backups stay.
    GetBackupSchedule { instance_id: Uuid } =
        user GET "/v1/instances/{instance_id}/backup-schedule" => BackupScheduleView;
    /// Replace the instance's backup schedule; no rules clears it. No job:
    /// the schedule as it is now, with the rules it removed and how many
    /// of their backups stay.
    SetBackupSchedule { instance_id: Uuid } = user PUT
        "/api/mut/v1/instances/{instance_id}/backup-schedule" (SetBackupScheduleRequest)
        => BackupScheduleView;
    /// Withdraws a backup that waits for its turn; the job is its creation,
    /// which is cancelled.
    CancelBackup { instance_id: Uuid, backup_id: Uuid } = user POST
        "/api/mut/v1/instances/{instance_id}/backups/{backup_id}/cancel" => JobAccepted;
    /// Carries the backup's data key rewrapped with the seed's recovery key,
    /// which no website session can produce.
    AuthorizeBackupRestore { instance_id: Uuid, backup_id: Uuid, job_id: Uuid } = wallet POST
        "/api/mut/v1/instances/{instance_id}/backups/{backup_id}/restore/{job_id}/authorize"
        (AuthorizeBackupRestoreRequest) => JobAccepted;
    /// The account's jobs, newest first: filter with `instance_id`, `state`
    /// and `kind`, page with `cursor` and `limit`.
    ListJobs = user GET "/v1/jobs" => JobPage;
    GetJob { job_id: Uuid } = user GET "/v1/jobs/{job_id}" => JobView;

    // Provider
    GetProviderBalance = user GET "/v1/provider/balance" => Option<ProviderBalanceView>;
    ListPayouts = user GET "/v1/provider/payouts" => Vec<ProviderPayoutView>;
    CreatePayout = user POST "/api/mut/v1/provider/payouts" (CreateProviderPayoutRequest)
        => ProviderPayoutView;
    /// It decides where earnings leave the platform; a session can only
    /// request payouts to it.
    SetPayoutAddress = wallet PUT "/api/mut/v1/provider/payout-address"
        (SetProviderPayoutAddressRequest) => ProviderPayoutAddressView;
    ListProviderHosts = user GET "/v1/provider/hosts" => Vec<ProviderHostView>;
    GetProviderHost { host_id: Uuid } =
        user GET "/v1/provider/hosts/{host_id}" => ProviderHostDetailView;
    /// A host's mesh summary: its days of the last 30, its links by kind
    /// and state.
    GetProviderHostMesh { host_id: Uuid } =
        user GET "/v1/provider/hosts/{host_id}/mesh" => crate::website::HostMeshView;
    /// The provider's hosts' mesh over the last 30 days, per host.
    ListProviderMesh = user GET "/v1/provider/mesh" => crate::website::ProviderMeshView;
    GetProviderHostMetrics { host_id: Uuid } =
        user GET "/v1/provider/hosts/{host_id}/metrics" => HistoryPage;
    ListProviderHostInstances { host_id: Uuid } =
        user GET "/v1/provider/hosts/{host_id}/instances" => HistoryPage;
    GetProviderHostInstance { host_id: Uuid, instance_id: Uuid } =
        user GET "/v1/provider/hosts/{host_id}/instances/{instance_id}" => ProviderRentalView;
    GetProviderHostInstanceUsage { host_id: Uuid, instance_id: Uuid } =
        user GET "/v1/provider/hosts/{host_id}/instances/{instance_id}/usage" => HistoryPage;
    GetHostPricing { host_id: Uuid } =
        user GET "/v1/provider/hosts/{host_id}/pricing" => Option<HostPricingView>;
    UpdateHostPricing { host_id: Uuid } = user PUT "/api/mut/v1/provider/hosts/{host_id}/pricing"
        (UpdateHostPricingRequest) => HostPricingView;
    SetHostRentalAdmission { host_id: Uuid } = user POST
        "/api/mut/v1/provider/hosts/{host_id}/rental-admission" (SetHostRentalPauseRequest)
        => ProviderHostView;
    /// Whether the host is private and how many instances and local backups of accounts the
    /// provider does not allow are on it: what stays there once it is private, shown before the
    /// change.
    GetHostPrivacy { host_id: Uuid } =
        user GET "/v1/provider/hosts/{host_id}/private" => HostPrivacyView;
    /// Make the host private, so that only the provider and the accounts
    /// it allows place new instances on it and no public read shows it, or
    /// public again, which lists it at once. What is on it stays as it is.
    SetHostPrivate { host_id: Uuid } = user POST
        "/api/mut/v1/provider/hosts/{host_id}/private" (SetHostPrivateRequest)
        => HostPrivacyView;
    /// The host's agent: its release, its update policy and its update
    /// attempts.
    GetHostAgentUpdate { host_id: Uuid } =
        user GET "/v1/provider/hosts/{host_id}/agent-update" => HostAgentUpdateView;
    /// Set the host's update policy, pause and maintenance window, whole.
    SetHostAgentUpdatePolicy { host_id: Uuid } = user POST
        "/api/mut/v1/provider/hosts/{host_id}/agent-update/policy"
        (SetAgentUpdatePolicyRequest) => HostAgentUpdateView;
    /// Approve one exact release for the host: the one that waits for the
    /// approval, or the channel's current one.
    ApproveHostAgentUpdate { host_id: Uuid } = user POST
        "/api/mut/v1/provider/hosts/{host_id}/agent-update/approve"
        (ApproveAgentUpdateRequest) => HostAgentUpdateView;
    /// A new attempt at the release of an attempt that failed or was
    /// rolled back.
    RetryHostAgentUpdate { host_id: Uuid } = user POST
        "/api/mut/v1/provider/hosts/{host_id}/agent-update/retry"
        (AgentUpdateAttemptRequest) => HostAgentUpdateView;
    /// Cancel an attempt that is not being applied yet.
    CancelHostAgentUpdate { host_id: Uuid } = user POST
        "/api/mut/v1/provider/hosts/{host_id}/agent-update/cancel"
        (AgentUpdateAttemptRequest) => HostAgentUpdateView;
    /// The accounts the provider allows on its private hosts, by alias,
    /// each with what of it is on them; at most 100. Its own account is
    /// always allowed and not listed.
    ListPrivateRenters = user GET "/v1/provider/private-renters" => Vec<PrivateRenterView>;
    /// Allow an account on the provider's private hosts by its alias. An
    /// alias that names no account, and the provider's own, are refused.
    AddPrivateRenter = user POST "/api/mut/v1/provider/private-renters"
        (AddPrivateRenterRequest) => PrivateRenterView;
    /// Stop allowing an account: its new instances are refused, what it
    /// has on the private hosts stays as it is.
    RemovePrivateRenter { alias: String } = user POST
        "/api/mut/v1/provider/private-renters/{alias}/remove" => PrivateRenterView;
    RetireHost { host_id: Uuid } =
        user DELETE "/api/mut/v1/provider/hosts/{host_id}" => ProviderHostView;
    ScheduleHostRetirement { host_id: Uuid } = user POST
        "/api/mut/v1/provider/hosts/{host_id}/retirement-notice" (ScheduleHostRetirementRequest)
        => ProviderHostView;
    DeclareHostEmergency { host_id: Uuid } = user POST
        "/api/mut/v1/provider/hosts/{host_id}/emergency" (DeclareHostEmergencyRequest)
        => ProviderHostView;
    ScheduleInstanceRetirement { instance_id: Uuid } = user POST
        "/api/mut/v1/provider/instances/{instance_id}/retirement-notice"
        (ScheduleInstanceRetirementRequest) => InstanceProviderTerminationView;
    ListIpPools = user GET "/v1/provider/ip-pools" => Vec<CloudIpPoolView>;
    GetIpPool { pool_id: Uuid } =
        user GET "/v1/provider/ip-pools/{pool_id}" => CloudIpPoolView;
    CreateIpPool = user POST "/api/mut/v1/provider/ip-pools" (CreateCloudIpPoolRequest)
        => CloudIpPoolView;
    DeleteIpPool { pool_id: Uuid } =
        user DELETE "/api/mut/v1/provider/ip-pools/{pool_id}" => CloudIpPoolView;
    HandOverIpPool { pool_id: Uuid } = user POST
        "/api/mut/v1/provider/ip-pools/{pool_id}/hand-over" (HandOverCloudIpPoolRequest)
        => CloudIpPoolView;
    AddIpAddresses { pool_id: Uuid } = user POST
        "/api/mut/v1/provider/ip-pools/{pool_id}/addresses" (AddCloudIpAddressesRequest)
        => CloudIpPoolView;
    RemoveIpAddress { pool_id: Uuid, address_id: Uuid } = user DELETE
        "/api/mut/v1/provider/ip-pools/{pool_id}/addresses/{address_id}" => CloudIpPoolView;
    CheckIpAddress { pool_id: Uuid, address_id: Uuid } = user POST
        "/api/mut/v1/provider/ip-pools/{pool_id}/addresses/{address_id}/check"
        => CloudIpPoolView;
    CheckHostPublicPath { host_id: Uuid } = user POST
        "/api/mut/v1/provider/hosts/{host_id}/public-path-check" => ProviderHostView;
    ListIncidents = user GET "/v1/provider/incidents" => Vec<ProviderIncidentView>;
    GetIncident { incident_id: Uuid } =
        user GET "/v1/provider/incidents/{incident_id}" => ProviderIncidentView;
    SetIncidentState { incident_id: Uuid } = user POST
        "/api/mut/v1/provider/incidents/{incident_id}/state" (SetProviderIncidentStateRequest)
        => ProviderIncidentView;
    GetProviderUptime = user GET "/v1/provider/uptime" => ProviderUptimeView;
    ListProviderOutages = user GET "/v1/provider/outages" => ProviderOutagePage;
    GetProviderOutage { outage_id: Uuid } =
        user GET "/v1/provider/outages/{outage_id}" => ProviderOutageDetailView;

    // Support
    ListTickets = user GET "/v1/support/tickets" => Vec<SupportTicketSummaryView>;
    GetTicket { ticket_id: Uuid } = user GET "/v1/support/tickets/{ticket_id}" => SupportTicketView;
    CreateTicket = user POST "/api/mut/v1/support/tickets" (CreateSupportTicketRequest)
        => SupportTicketView;
    AddTicketMessage { ticket_id: Uuid } = user POST
        "/api/mut/v1/support/tickets/{ticket_id}/messages" (AddSupportTicketMessageRequest)
        => SupportTicketView;
    SetTicketState { ticket_id: Uuid } = user POST
        "/api/mut/v1/support/tickets/{ticket_id}/state" (SetSupportTicketStateRequest)
        => SupportTicketView;
}
pub const ALL: &[Listing] = DECLARED;
