//! Compatibility rules for dated client releases. A release ID starts with
//! `YYYYMMDDTHHMMSSZ-` and twelve hexadecimal digits. Releases remain supported
//! for at least [`SUPPORT_WINDOW_DAYS`] days. A request below the server's
//! supported minimum receives a 426 [`ClientReleaseUnsupported`] response naming
//! the release to install, also available in the `Upgrade` header.
//!
//! Clients advertise their release through [`CLIENT_HEADER`] and `User-Agent`.
//! Undated development versions cannot be compared with a dated minimum.
//! Release checks provide compatibility guidance rather than authentication.

use chrono::{DateTime, NaiveDateTime, TimeDelta, Utc};
use serde::{Deserialize, Serialize};

use crate::release::is_release_version;

/// How long the backend serves a release after it was built.
pub const SUPPORT_WINDOW_DAYS: i64 = 90;
/// How long before the end of its window a release is flagged.
pub const SUPPORT_NOTICE_DAYS: i64 = 14;

/// The `code` of a refusal of a client older than the minimum release of
/// its kind ([`ClientReleaseUnsupported`]).
pub const CLIENT_RELEASE_UNSUPPORTED: &str = "client_release_unsupported";

/// The header in which `ghost` names itself and its release on every
/// request: `ghost/RELEASE`. The backend refuses a `ghost` older than
/// `minimum_cli_release` by it.
pub const CLIENT_HEADER: &str = "x-gigahost-client";

/// The name `ghost` gives itself in [`CLIENT_HEADER`] and its `User-Agent`.
pub const GHOST_CLIENT: &str = "ghost";

/// The name the hypervisor agent gives itself in its `User-Agent`.
pub const HYPERVISOR_CLIENT: &str = "gigahost-hypervisor";

/// The name of the platform machines' software (gateways, routers, network
/// test servers) in the `Upgrade` header of a refusal of their release.
pub const PLATFORM_CLIENT: &str = "gigahost-platform";

/// The release a build names that was not installed from a release.
pub const DEVELOPMENT_RELEASE: &str = "dev";

/// What a client sends as its identity: `ghost/20261010T120000Z-0123456789ab`.
#[must_use]
pub fn client_identity(client: &str, release: &str) -> String {
    format!("{client}/{release}")
}

/// The release `value`, a `User-Agent` or [`CLIENT_HEADER`], names for
/// `client`: the text after `client/` up to the first space, when there is
/// any. `None` when the value names another client.
#[must_use]
pub fn release_of<'a>(value: &'a str, client: &str) -> Option<&'a str> {
    let release = value.strip_prefix(client)?.strip_prefix('/')?;
    let release = release.split_ascii_whitespace().next().unwrap_or_default();
    (!release.is_empty()
        && release.len() <= 64
        && release.bytes().all(|byte| byte.is_ascii_graphic()))
    .then_some(release)
}

/// When the release `version` was built, from its timestamp; `None` when
/// `version` is no release version.
#[must_use]
pub fn released_at(version: &str) -> Option<DateTime<Utc>> {
    if !is_release_version(version) {
        return None;
    }
    NaiveDateTime::parse_from_str(&version[..15], "%Y%m%dT%H%M%S")
        .ok()
        .map(|at| at.and_utc())
}

/// The end of the support window of the release `version`: its build
/// time plus [`SUPPORT_WINDOW_DAYS`].
#[must_use]
pub fn support_ends_at(version: &str) -> Option<DateTime<Utc>> {
    released_at(version).map(|at| at + TimeDelta::days(SUPPORT_WINDOW_DAYS))
}

/// Whether a client of `release` is below `minimum`, the oldest release
/// the backend serves of its kind, which an empty value sets none of. A
/// client that names no release version (`dev`, `0.1.0`, or nothing) is of
/// a release the backend cannot date, and never below a minimum. Releases
/// are compared by their build time: two builds of one second are the
/// same age.
#[must_use]
pub fn below_minimum(release: Option<&str>, minimum: &str) -> bool {
    !minimum.is_empty()
        && release
            .filter(|release| is_release_version(release))
            .is_some_and(|release| {
                release.as_bytes()[..16] < minimum.as_bytes()[..minimum.len().min(16)]
            })
}

/// Whether `value` may be a runtime setting's minimum release: empty for
/// none, or a release version. How old it must be is
/// [`minimum_within_window`]'s.
#[must_use]
pub fn valid_minimum(value: &str) -> bool {
    value.is_empty() || is_release_version(value)
}

/// Whether the minimum release `value`, set at `now`, would refuse a
/// release its window still covers: one built less than
/// [`SUPPORT_WINDOW_DAYS`] before `now`, or later. The platform promises
/// every release those days, so such a minimum is not set.
#[must_use]
pub fn minimum_within_window(value: &str, now: DateTime<Utc>) -> bool {
    released_at(value).is_some_and(|at| at + TimeDelta::days(SUPPORT_WINDOW_DAYS) > now)
}

/// The `Upgrade` header of a 426 that refuses `client`'s release (RFC 9110,
/// section 7.8): the client and the release to install, `client/RELEASE`,
/// or the client alone when there is none to name.
#[must_use]
pub fn upgrade_protocol(client: &str, install: Option<&str>) -> String {
    match install {
        Some(install) => client_identity(client, install),
        None => client.to_owned(),
    }
}

/// The release a machine or a host runs and where it stands in the
/// support window, as the fleet and the provider's host views show it.
/// The views hold it as an option, absent from a backend of before.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ReleaseSupportView {
    /// What the binary reports: a release version, `dev` for a build that
    /// was not installed from a release, or `0.1.0` from an agent of before
    /// releases were reported.
    pub release: String,
    /// When the release was built, from its version; absent when it names
    /// no release.
    #[serde(default)]
    pub released_at: Option<DateTime<Utc>>,
    /// Whole days since then.
    #[serde(default)]
    pub age_days: Option<u32>,
    /// The end of its support window, 90 days after it was built.
    #[serde(default)]
    pub support_ends_at: Option<DateTime<Utc>>,
    /// Its window ends within 14 days or has ended: update it.
    #[serde(default)]
    pub support_ending: bool,
    /// Older than the oldest release the platform serves of its kind: the
    /// backend refuses it until it is updated (an agent's host stays up,
    /// degraded, without new rentals or work). A build that names no
    /// release never is.
    #[serde(default)]
    pub below_minimum: bool,
}

/// Where `release` stands in the support window at `now`, and whether it
/// is below `minimum`.
#[must_use]
pub fn release_support(release: &str, minimum: &str, now: DateTime<Utc>) -> ReleaseSupportView {
    let released_at = released_at(release);
    let support_ends_at = released_at.map(|at| at + TimeDelta::days(SUPPORT_WINDOW_DAYS));
    ReleaseSupportView {
        release: release.to_owned(),
        released_at,
        age_days: released_at
            .map(|at| u32::try_from((now - at).num_days().max(0)).unwrap_or(u32::MAX)),
        support_ends_at,
        support_ending: support_ends_at
            .is_some_and(|ends| ends - TimeDelta::days(SUPPORT_NOTICE_DAYS) <= now),
        below_minimum: below_minimum(Some(release), minimum),
    }
}

/// The JSON body of a refusal of a client older than the minimum release
/// of its kind: a 426 `client_release_unsupported`. It reads as an
/// [`crate::website::ErrorResponse`] too, so a client that knows only that
/// shows the message.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ClientReleaseUnsupported {
    /// [`CLIENT_RELEASE_UNSUPPORTED`].
    pub code: String,
    /// What to do, for a person.
    pub message: String,
    /// The client's release as it named it; absent when it named none.
    #[serde(default)]
    pub release: Option<String>,
    /// The oldest release the backend serves of the client's kind.
    pub minimum: String,
    /// The release to install, the current one of its channel, when the
    /// backend knows it and it is at or above the minimum.
    #[serde(default)]
    pub install: Option<String>,
    /// The request's ID, which the response's `x-request-id` header names
    /// too; the backend fills it in as it answers.
    #[serde(default)]
    pub request_id: Option<String>,
}

impl ClientReleaseUnsupported {
    /// The refusal of `client`'s `release` below `minimum`, naming
    /// `install` and how to install it (`how`, such as `curl -fsSL
    /// https://api.example/install/ghost.sh | sh`).
    #[must_use]
    pub fn new(
        client: &str,
        release: Option<&str>,
        minimum: &str,
        install: Option<&str>,
        how: &str,
    ) -> Self {
        let install_text = match install {
            Some(install) => format!("install release {install}"),
            None => "install the current release".to_owned(),
        };
        Self::saying(
            client,
            release,
            minimum,
            install,
            &format!("{install_text}: {how}"),
        )
    }

    /// The refusal of `client`'s `release` below `minimum` while the
    /// current release of its channel is below the minimum too: there is
    /// nothing to install until the operator publishes a release.
    #[must_use]
    pub fn nothing_to_install(client: &str, release: Option<&str>, minimum: &str) -> Self {
        Self::saying(client, release, minimum, None, NOTHING_TO_INSTALL)
    }

    fn saying(
        client: &str,
        release: Option<&str>,
        minimum: &str,
        install: Option<&str>,
        what_to_do: &str,
    ) -> Self {
        let named = match release {
            Some(release) if is_release_version(release) => format!("release {release}"),
            Some(release) => format!("a build that names no release ({release})"),
            None => "a build that names no release".to_owned(),
        };
        Self {
            code: CLIENT_RELEASE_UNSUPPORTED.to_owned(),
            message: format!(
                "this {client} is {named}, older than release {minimum}, the oldest the platform serves; {what_to_do}"
            ),
            release: release.map(str::to_owned),
            minimum: minimum.to_owned(),
            install: install.map(str::to_owned),
            request_id: None,
        }
    }
}

/// What a refusal says while the current release of the client's channel
/// is below the minimum itself.
pub const NOTHING_TO_INSTALL: &str =
    "the channel's current release is below the minimum; the operator must publish one";

#[cfg(test)]
mod tests {
    use super::*;

    const RELEASE: &str = "20261010T120000Z-0123456789ab";

    #[test]
    fn a_release_dates_its_window() {
        let built = released_at(RELEASE).expect("a release");
        assert_eq!(built.to_rfc3339(), "2026-10-10T12:00:00+00:00");
        assert_eq!(
            support_ends_at(RELEASE).map(|at| at.to_rfc3339()),
            Some("2027-01-08T12:00:00+00:00".to_owned())
        );
        for other in ["dev", "0.1.0", "", "20261310T120000Z-0123456789ab"] {
            assert_eq!(released_at(other), None, "{other:?}");
        }
        let at = |days: i64| built + TimeDelta::days(days);
        let view = release_support(RELEASE, "", at(10));
        assert_eq!(view.age_days, Some(10));
        assert!(!view.support_ending && !view.below_minimum);
        assert!(!release_support(RELEASE, "", at(75) - TimeDelta::seconds(1)).support_ending);
        assert!(release_support(RELEASE, "", at(76)).support_ending);
        assert!(release_support(RELEASE, "", at(400)).support_ending);
        let unnamed = release_support("dev", "", at(1));
        assert_eq!(
            (
                unnamed.released_at,
                unnamed.age_days,
                unnamed.support_ends_at
            ),
            (None, None, None)
        );
        assert!(!unnamed.support_ending && !unnamed.below_minimum);
        // A build that names no release is never below a minimum.
        assert!(!release_support("dev", RELEASE, at(1)).below_minimum);
        assert!(release_support("20261001T000000Z-0123456789ab", RELEASE, at(1)).below_minimum);
    }

    #[test]
    fn a_minimum_is_compared_by_build_time() {
        assert!(!below_minimum(None, ""));
        assert!(!below_minimum(Some("dev"), ""));
        // What names no release is of a release that cannot be dated.
        assert!(!below_minimum(None, RELEASE));
        assert!(!below_minimum(Some("dev"), RELEASE));
        assert!(!below_minimum(Some("0.1.0"), RELEASE));
        assert!(!below_minimum(
            Some("20261010T120000Z-0123456789AB"),
            RELEASE
        ));
        assert!(below_minimum(
            Some("20261010T115959Z-ffffffffffff"),
            RELEASE
        ));
        assert!(!below_minimum(Some(RELEASE), RELEASE));
        // Another build of the same second is as old.
        assert!(!below_minimum(
            Some("20261010T120000Z-000000000000"),
            RELEASE
        ));
        assert!(!below_minimum(
            Some("20261011T000000Z-000000000000"),
            RELEASE
        ));
        assert!(valid_minimum("") && valid_minimum(RELEASE));
        assert!(!valid_minimum("dev") && !valid_minimum("2026"));
        // A minimum refuses only releases the window no longer covers.
        let built = released_at(RELEASE).expect("a release");
        let window = TimeDelta::days(SUPPORT_WINDOW_DAYS);
        assert!(!minimum_within_window(RELEASE, built + window));
        assert!(minimum_within_window(
            RELEASE,
            built + window - TimeDelta::seconds(1)
        ));
        assert!(minimum_within_window(RELEASE, built - TimeDelta::days(1)));
        assert!(!minimum_within_window("", built));
    }

    #[test]
    fn a_refusal_names_what_to_upgrade_to() {
        assert_eq!(
            upgrade_protocol(GHOST_CLIENT, Some(RELEASE)),
            format!("ghost/{RELEASE}")
        );
        assert_eq!(upgrade_protocol(PLATFORM_CLIENT, None), "gigahost-platform");
        let refusal = ClientReleaseUnsupported::nothing_to_install(
            HYPERVISOR_CLIENT,
            Some("20260901T000000Z-0123456789ab"),
            RELEASE,
        );
        assert_eq!(refusal.install, None);
        assert_eq!(
            refusal.message,
            "this gigahost-hypervisor is release 20260901T000000Z-0123456789ab, older than release 20261010T120000Z-0123456789ab, the oldest the platform serves; the channel's current release is below the minimum; the operator must publish one"
        );
    }

    #[test]
    fn a_client_names_its_release() {
        let identity = client_identity(GHOST_CLIENT, RELEASE);
        assert_eq!(identity, format!("ghost/{RELEASE}"));
        assert_eq!(release_of(&identity, GHOST_CLIENT), Some(RELEASE));
        assert_eq!(release_of("ghost/dev", GHOST_CLIENT), Some("dev"));
        assert_eq!(
            release_of(
                &format!("gigahost-hypervisor/{RELEASE} (linux)"),
                HYPERVISOR_CLIENT
            ),
            Some(RELEASE)
        );
        for other in ["ghost", "ghost/", "ghostly/x", "curl/8.5.0", "ghost/\u{1}x"] {
            assert_eq!(release_of(other, GHOST_CLIENT), None, "{other:?}");
        }
        assert_eq!(release_of(&"ghost/".repeat(20), GHOST_CLIENT), None);
    }

    #[test]
    fn a_refusal_reads_as_an_error() {
        let refusal = ClientReleaseUnsupported::new(
            GHOST_CLIENT,
            Some("20260901T000000Z-0123456789ab"),
            RELEASE,
            Some("20261020T000000Z-0123456789ab"),
            "curl -fsSL https://api.example/install/ghost.sh | sh",
        );
        assert_eq!(
            refusal.message,
            "this ghost is release 20260901T000000Z-0123456789ab, older than release 20261010T120000Z-0123456789ab, the oldest the platform serves; install release 20261020T000000Z-0123456789ab: curl -fsSL https://api.example/install/ghost.sh | sh"
        );
        let error: crate::website::ErrorResponse =
            serde_json::from_value(serde_json::to_value(&refusal).unwrap()).unwrap();
        assert_eq!(error.code, CLIENT_RELEASE_UNSUPPORTED);
        assert_eq!(error.message, refusal.message);
        let unnamed = ClientReleaseUnsupported::new(HYPERVISOR_CLIENT, None, RELEASE, None, "x");
        assert!(
            unnamed
                .message
                .starts_with("this gigahost-hypervisor is a build that names no release, older"),
            "{}",
            unnamed.message
        );
        assert!(unnamed.message.contains("install the current release: x"));
    }
}
