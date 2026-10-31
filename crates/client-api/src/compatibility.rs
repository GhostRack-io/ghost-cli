//! Forward-compatible enum readers shared by customer API clients and services.
//!
//! Responses accept unknown fields and decode newer enum variants as `Unknown`.
//! Request fields use [`known`] or [`known_option`] to reject those values with
//! serde's usual variant errors.

use std::fmt;

use serde::{
    Deserialize, Deserializer,
    de::{self, DeserializeOwned, Error as _, Visitor},
    forward_to_deserialize_any,
};

/// Every enum a client decodes, each ending in `#[serde(other)] Unknown`.
/// This registry names the enums used by the crate's views and messages.
pub const CLIENT_DECODED_ENUMS: &[&str] = &[
    "AccessResetState",
    "AccountFundingState",
    "AgentUpdatePolicy",
    "AgentUpdateState",
    "BackupDestinationKind",
    "BackupPurpose",
    "BackupScheduleFrequency",
    "BackupScheduleRunResult",
    "BackupState",
    "BrowserOperation",
    "CloudIpPoolScope",
    "CloudIpVerification",
    "ComponentState",
    "ContainerExitCause",
    "ContainerState",
    "GatewayTier",
    "HostRetirementState",
    "HttpProxyStatus",
    "HttpProxyProtocol",
    "InstanceKind",
    "InstanceState",
    "JobKind",
    "JobState",
    "JobStepState",
    "LanLinkKind",
    "LanLinkState",
    "LedgerKind",
    "MeshLinkState",
    "MeshNoLinkReason",
    "MeshPath",
    "ProviderIncidentSeverity",
    "ProviderIncidentState",
    "ProviderPayoutState",
    "ProviderStatus",
    "ProviderTerminationState",
    "StatusComponentKind",
    "StatusNoticeKind",
    "StatusNoticeState",
    "StatusReason",
    "StockImageInit",
    "SupportTicketCategory",
    "SupportTicketPriority",
    "SupportTicketResource",
    "SupportTicketState",
    "SupportWaitingOn",
    "TrialClaimStatus",
    "GithubClaimPurpose",
    "CpuTier",
    "GuestFirmware",
    "GuestInitializationStatus",
    "HostMode",
    "ImageCacheState",
    "PowerState",
    "StorageBackend",
    "RestartPolicy",
];
pub const ENUMS_WITHOUT_FALLBACK: &[(&str, &str)] = &[];
/// An enum of [`CLIENT_DECODED_ENUMS`]: its `Unknown` is a variant this
/// build lacks.
pub trait Fallback {
    /// The variants a refusal of an unknown one leaves out of the ones it
    /// names: values one client of the platform's own asks for alone,
    /// which the API's words of before do not name.
    const UNNAMED: &'static [&'static str] = &[];

    /// Whether the value is the fallback for a variant this build lacks.
    fn is_unknown(&self) -> bool;
}

macro_rules! fallback {
    ($($name:path),* $(,)?) => {
        $(impl Fallback for $name {
            fn is_unknown(&self) -> bool {
                matches!(self, Self::Unknown)
            }
        })*
    };
}

fallback!(
    crate::website::AgentUpdatePolicy,
    crate::website::AccountFundingState,
    crate::website::BackupDestinationKind,
    crate::website::BackupPurpose,
    crate::website::BackupScheduleFrequency,
    crate::website::BackupScheduleRunResult,
    crate::website::BackupState,
    crate::website::BrowserOperation,
    crate::website::CloudIpPoolScope,
    crate::website::CloudIpVerification,
    crate::website::ComponentState,
    crate::website::ContainerExitCause,
    crate::website::ContainerState,
    crate::website::GatewayTier,
    crate::website::HostRetirementState,
    crate::website::HttpProxyStatus,
    crate::website::HttpProxyProtocol,
    crate::website::InstanceKind,
    crate::website::InstanceState,
    crate::website::KindChoice,
    crate::website::JobKind,
    crate::website::JobState,
    crate::website::JobStepState,
    crate::website::LanLinkState,
    crate::website::LedgerKind,
    crate::website::MeshLinkState,
    crate::website::MeshNoLinkReason,
    crate::website::MeshPath,
    crate::website::ProviderIncidentSeverity,
    crate::website::ProviderIncidentState,
    crate::website::ProviderPayoutState,
    crate::website::ProviderStatus,
    crate::website::ProviderTerminationState,
    crate::website::StatusComponentKind,
    crate::website::StatusNoticeKind,
    crate::website::TrialClaimStatus,
    crate::website::GithubClaimPurpose,
    crate::website::StatusNoticeState,
    crate::website::StatusReason,
    crate::website::StockImageInit,
    crate::website::SupportTicketCategory,
    crate::website::SupportTicketPriority,
    crate::website::SupportTicketResource,
    crate::website::SupportTicketState,
    crate::website::SupportWaitingOn,
    crate::hypervisor::CpuTier,
    crate::hypervisor::GuestFirmware,
    crate::hypervisor::GuestInitializationStatus,
    crate::hypervisor::HostMode,
    crate::hypervisor::ImageCacheState,
    crate::hypervisor::PowerState,
    crate::hypervisor::StorageBackend,
    crate::hypervisor::RestartPolicy
);

/// Read a field of a received type as `T`, refusing a variant this build
/// lacks as serde refuses it without the fallback, with the same words
/// where the format names variants by name (JSON, a query string): for
/// `#[serde(deserialize_with = "known")]`.
///
/// # Errors
///
/// When the field does not read as `T` or reads as its fallback.
pub fn known<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned + Fallback,
{
    if deserializer.is_human_readable() {
        let given = serde_json::Value::deserialize(deserializer)?;
        let value: T = serde_json::from_value(given.clone()).map_err(D::Error::custom)?;
        if value.is_unknown() {
            return Err(D::Error::custom(unknown_variant::<T>(&given)));
        }
        Ok(value)
    } else {
        let value = T::deserialize(deserializer)?;
        if value.is_unknown() {
            return Err(D::Error::custom(unknown_variant::<T>(
                &serde_json::Value::Null,
            )));
        }
        Ok(value)
    }
}

/// [`known`] for an optional field: with `#[serde(default, deserialize_with
/// = "known_option")]`, as a field with `deserialize_with` is no longer
/// optional by itself.
///
/// # Errors
///
/// When the field does not read as `Option<T>` or reads as `T`'s fallback.
pub fn known_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned + Fallback,
{
    struct Present<T>(T);

    impl<'de, T: DeserializeOwned + Fallback> Deserialize<'de> for Present<T> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            known(deserializer).map(Present)
        }
    }

    Ok(Option::<Present<T>>::deserialize(deserializer)?.map(|present| present.0))
}

/// The website's Capacity list (`shared_reference`) is no choice the API's refusal names: its words
/// stay those of before.
impl Fallback for crate::website::IpChoice {
    const UNNAMED: &'static [&'static str] = &["shared_reference"];

    fn is_unknown(&self) -> bool {
        matches!(self, Self::Unknown)
    }
}

/// serde's words for a variant the enum does not have, from the variants
/// `T` names (its fallback and [`Fallback::UNNAMED`] left out); `given` is
/// the variant as read, null where the format names it by its index.
fn unknown_variant<T: DeserializeOwned + Fallback>(given: &serde_json::Value) -> String {
    let expected: Vec<String> = variant_names::<T>()
        .iter()
        .filter(|name| **name != "unknown" && !T::UNNAMED.contains(name))
        .map(|name| format!("`{name}`"))
        .collect();
    let expected = match expected.as_slice() {
        [] => "there are no variants".to_owned(),
        [one] => format!("expected {one}"),
        [first, second] => format!("expected {first} or {second}"),
        all => format!("expected one of {}", all.join(", ")),
    };
    match given {
        serde_json::Value::String(name) => format!("unknown variant `{name}`, {expected}"),
        serde_json::Value::Null => format!("unknown variant, {expected}"),
        other => format!("unknown variant {other}, {expected}"),
    }
}

/// The variants `T`'s `Deserialize` names, which it hands a deserializer of
/// an enum.
fn variant_names<T: DeserializeOwned>() -> &'static [&'static str] {
    #[derive(Debug)]
    struct Named(&'static [&'static str]);

    impl fmt::Display for Named {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("the variants are named")
        }
    }

    impl std::error::Error for Named {}

    impl de::Error for Named {
        fn custom<M: fmt::Display>(_: M) -> Self {
            Self(&[])
        }
    }

    struct Names;

    impl<'de> Deserializer<'de> for Names {
        type Error = Named;

        fn deserialize_any<V: Visitor<'de>>(self, _: V) -> Result<V::Value, Named> {
            Err(Named(&[]))
        }

        fn deserialize_enum<V: Visitor<'de>>(
            self,
            _: &'static str,
            variants: &'static [&'static str],
            _: V,
        ) -> Result<V::Value, Named> {
            Err(Named(variants))
        }

        forward_to_deserialize_any! {
            bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
            bytes byte_buf option unit unit_struct newtype_struct seq tuple
            tuple_struct map struct identifier ignored_any
        }
    }

    match T::deserialize(Names) {
        Ok(_) => &[],
        Err(Named(variants)) => variants,
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::{known, known_option};
    use crate::website::{GatewayTier, SupportTicketState};

    #[derive(Debug, Deserialize)]
    struct Received {
        #[serde(deserialize_with = "known")]
        state: SupportTicketState,
        #[serde(default, deserialize_with = "known_option")]
        tier: Option<GatewayTier>,
    }

    #[test]
    fn a_client_reads_a_variant_it_lacks_as_unknown() {
        let state: SupportTicketState = serde_json::from_str(r#""escalated""#).unwrap();
        assert_eq!(state, SupportTicketState::Unknown);
        let tier: Option<GatewayTier> = serde_json::from_str(r#""satellite""#).unwrap();
        assert_eq!(tier, Some(GatewayTier::Unknown));
    }

    #[test]
    fn a_received_type_refuses_a_variant_it_lacks() {
        let read = |json: &str| serde_json::from_str::<Received>(json);
        let received = read(r#"{"state": "open"}"#).unwrap();
        assert_eq!(received.state, SupportTicketState::Open);
        assert_eq!(received.tier, None);
        let received = read(r#"{"state": "open", "tier": null}"#).unwrap();
        assert_eq!(received.tier, None);
        let received = read(r#"{"state": "open", "tier": "shared_bandwidth"}"#).unwrap();
        assert_eq!(received.tier, Some(GatewayTier::SharedBandwidth));
        for (json, words) in [
            (
                r#"{"state": "escalated"}"#,
                "unknown variant `escalated`, expected one of `open`, `waiting`, `resolved`, `closed`",
            ),
            (
                r#"{"state": "unknown"}"#,
                "unknown variant `unknown`, expected one of `open`, `waiting`, `resolved`, `closed`",
            ),
            (
                r#"{"state": "open", "tier": "satellite"}"#,
                "unknown variant `satellite`, expected one of `shared_bandwidth`, `high_bandwidth`, `shared_ip`",
            ),
        ] {
            let error = read(json).unwrap_err().to_string();
            assert!(error.contains(words), "{json}: {error}");
        }
        // Where variants travel by their index, the fallback is refused
        // too (postcard keeps no words of an error).
        let bytes = postcard::to_stdvec(&SupportTicketState::Unknown).unwrap();
        let mut deserializer = postcard::Deserializer::from_bytes(&bytes);
        assert!(known::<_, SupportTicketState>(&mut deserializer).is_err());
        let bytes = postcard::to_stdvec(&SupportTicketState::Open).unwrap();
        let mut deserializer = postcard::Deserializer::from_bytes(&bytes);
        assert_eq!(
            known::<_, SupportTicketState>(&mut deserializer).unwrap(),
            SupportTicketState::Open
        );
    }
}
