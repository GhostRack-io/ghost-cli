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
    "AgentUpdateSequenceHostPhase",
    "AgentUpdateSequenceState",
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
    "HostOpeningCheck",
    "HostOpeningCheckState",
    "HostRetirementState",
    "HttpProxyStatus",
    "HttpProxyProtocol",
    "InstanceEgressLevel",
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
    "ProviderAgentState",
    "ProviderDisplayNameStatus",
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
    "VpnConnectionState",
    "CpuTier",
    "GuestFirmware",
    "GuestInitializationStatus",
    "HostMode",
    "ImageCacheState",
    "PowerState",
    "StorageBackend",
    "RestartPolicy",
    "PendingAccountActionKind",
    "PendingAccountActionState",
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
    crate::website::AgentUpdateSequenceHostPhase,
    crate::website::AgentUpdateSequenceState,
    crate::website::ProviderAgentState,
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
    crate::website::HostOpeningCheck,
    crate::website::HostOpeningCheckState,
    crate::website::HostRetirementState,
    crate::website::HttpProxyStatus,
    crate::website::HttpProxyProtocol,
    crate::website::InstanceEgressLevel,
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
    crate::website::VpnConnectionState,
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
    crate::hypervisor::RestartPolicy,
    crate::website::PendingAccountActionKind,
    crate::website::PendingAccountActionState
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

    /// The x86-64 levels of item 186 are additive: an image, an offering
    /// and an instance from an older backend decode without them, as none
    /// (level 1), and with them as given.
    #[test]
    fn the_cpu_levels_read_from_older_backends() {
        use crate::website::{ImageView, InstanceView, OfferingView};

        let mut image = serde_json::json!({
            "image_id": "01a00000-0000-7000-8000-000000000024", "slug": "ubuntu-24.04",
            "display_name": "Ubuntu 24.04 LTS", "architecture": "x86_64",
            "minimum_disk_bytes": 4_294_967_296_u64,
        });
        let older: ImageView = serde_json::from_value(image.clone()).unwrap();
        assert_eq!(older.x86_64_level, None);
        assert!(
            serde_json::to_value(&older)
                .unwrap()
                .get("x86_64_level")
                .is_none()
        );
        image["x86_64_level"] = 3.into();
        let newer: ImageView = serde_json::from_value(image).unwrap();
        assert_eq!(newer.x86_64_level, Some(3));

        let mut offering = serde_json::json!({
            "offering_id": "of2_J7hnuv_uO8PmXACeyas4QY",
            "provider_id": "00000000-0000-0000-0000-000000000000",
            "provider_name": "Example Hosting", "host_mode": "cloud_routed",
            "location": "pl-warsaw", "location_name": "Warsaw", "country_code": "PL",
            "continent_code": "EU", "measured_latency_ms": null, "cpu_model": "Test CPU",
            "cpu_tier": "shared_1x", "vcpu_count": 1, "memory_bytes": 5_905_580_032_u64,
            "root_disk_bytes": 51_539_607_552_u64, "root_storage_backend": "lvm_thin",
            "software_raid_levels": [], "storage_devices": [],
            "base_price_microusd_per_month": 3_240_000,
            "full_utilization_price_microusd_per_month": 4_860_000, "network_prices": [],
            "sla_target_basis_points": 9_900, "sla_credit_multiplier": 1, "available_hosts": 1,
        });
        let older: OfferingView = serde_json::from_value(offering.clone()).unwrap();
        assert_eq!(older.host_x86_64_level, None);
        offering["host_x86_64_level"] = 2.into();
        let newer: OfferingView = serde_json::from_value(offering).unwrap();
        assert_eq!(newer.host_x86_64_level, Some(2));

        let mut instance = serde_json::json!({
            "instance_id": "00000000-0000-0000-0000-000000000000", "offering_id": "o",
            "hostname": "vm", "name": "web", "root_disk_bytes": 12_u64 << 30,
            "state": "running", "desired_power_state": "running", "holds_capacity": true,
            "network_microusd_per_tib": 0, "created_at": "2026-11-11T00:00:00Z",
            "balance_reservation_microusd": 0,
        });
        let older: InstanceView = serde_json::from_value(instance.clone()).unwrap();
        assert_eq!(older.host_x86_64_level, None);
        instance["host_x86_64_level"] = 3.into();
        let newer: InstanceView = serde_json::from_value(instance).unwrap();
        assert_eq!(newer.host_x86_64_level, Some(3));
    }

    /// A host's opening checks are additive (item 193d): a view without
    /// them reads as None, and a check or state of a newer release as
    /// Unknown.
    #[test]
    fn a_host_s_opening_checks_read_from_older_and_newer_backends() {
        use crate::website::{HostOpeningCheck, HostOpeningCheckState, HostOpeningCheckView};
        let lines: Vec<HostOpeningCheckView> = serde_json::from_str(
            r#"[{"check": "prices_published", "state": "pending"},
                {"check": "gpu_tested", "state": "skipped", "detail": "x", "more": 1}]"#,
        )
        .unwrap();
        assert_eq!(lines[0].check, HostOpeningCheck::PricesPublished);
        assert_eq!(lines[0].state, HostOpeningCheckState::Pending);
        assert_eq!(lines[0].detail, None);
        assert_eq!(lines[1].check, HostOpeningCheck::Unknown);
        assert_eq!(lines[1].state, HostOpeningCheckState::Unknown);
        assert_eq!(lines[1].detail.as_deref(), Some("x"));
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
