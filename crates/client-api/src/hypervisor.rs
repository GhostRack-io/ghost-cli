use serde::{Deserialize, Serialize};

/// The part of a VM's memory, the amount its size names (its nominal
/// RAM), that is the VM's own fixed overhead (QEMU, its devices): QEMU
/// gives the guest the rest ([`guest_memory_bytes`]). No more is reserved
/// for it, as it is inside the size's amount.
pub const GUEST_MEMORY_ALLOWANCE_BYTES: u64 = 64 * 1024 * 1024;

/// The RAM QEMU gives a guest whose size has `nominal_bytes`:
/// [`GUEST_MEMORY_ALLOWANCE_BYTES`] less. `None` for a size of no more than
/// the allowance, which leaves the guest nothing and is never offered.
#[must_use]
pub const fn guest_memory_bytes(nominal_bytes: u64) -> Option<u64> {
    match nominal_bytes.checked_sub(GUEST_MEMORY_ALLOWANCE_BYTES) {
        Some(guest) if guest > 0 => Some(guest),
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
#[cfg_attr(feature = "clap", value(rename_all = "snake_case"))]
pub enum HostMode {
    #[cfg_attr(feature = "clap", value(alias = "home-gateway"))]
    HomeGateway,
    #[cfg_attr(feature = "clap", value(alias = "cloud-routed"))]
    CloudRouted,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    #[cfg_attr(feature = "clap", value(skip))]
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum CpuTier {
    #[serde(rename = "shared_1x")]
    #[cfg_attr(feature = "clap", value(name = "shared_1x"))]
    Shared1x,
    #[serde(rename = "shared_2x")]
    #[cfg_attr(feature = "clap", value(name = "shared_2x"))]
    Shared2x,
    #[serde(rename = "shared_4x")]
    #[cfg_attr(feature = "clap", value(name = "shared_4x"))]
    Shared4x,
    /// Eight vCPUs to a logical CPU, for container instances only.
    #[serde(rename = "shared_8x")]
    #[cfg_attr(feature = "clap", value(name = "shared_8x"))]
    Shared8x,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    #[cfg_attr(feature = "clap", value(skip))]
    Unknown,
}

impl CpuTier {
    /// Whether a VM may have the tier: every tier but [`Self::Shared8x`],
    /// which is for container instances only, and a tier of a newer
    /// release.
    #[must_use]
    pub const fn takes_vms(self) -> bool {
        matches!(self, Self::Shared1x | Self::Shared2x | Self::Shared4x)
    }

    /// How many vCPUs of the tier share a logical CPU; none for a tier of a
    /// newer release.
    pub const fn share_ratio(self) -> Option<u8> {
        match self {
            Self::Shared1x => Some(1),
            Self::Shared2x => Some(2),
            Self::Shared4x => Some(4),
            Self::Shared8x => Some(8),
            Self::Unknown => None,
        }
    }
}

/// A size's CPU label: its vCPU count, such as "1 vCPU" or "4 vCPU".
/// Sharing tiers and reserved cores are left out; sizes with the same vCPU
/// count differ in RAM, disk and price. Uses plain spaces.
#[must_use]
pub fn size_cpu_text(vcpu_count: u32) -> String {
    format!("{vcpu_count} vCPU")
}

/// The firmware a guest boots with, part of its image artifact: most catalog
/// images boot with `SeaBIOS`, Debian 13 with UEFI.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum GuestFirmware {
    /// `SeaBIOS`.
    #[default]
    Bios,
    /// OVMF with secure boot off and a per-domain NVRAM from the OVMF
    /// template.
    Uefi,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    #[cfg_attr(feature = "clap", value(skip))]
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageBackend {
    LvmThin,
    PreallocatedFile,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
pub struct HardwareDetails {
    pub memory_devices: Vec<MemoryDevice>,
    pub pcie_devices: Vec<PcieDevice>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct MemoryDevice {
    pub technology: String,
    pub size_bytes: u64,
    pub configured_speed_mts: Option<u32>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct PcieDevice {
    pub device_class: String,
    pub vendor_id: String,
    pub device_id: String,
    pub current_link_speed: String,
    pub current_link_width: u32,
    pub maximum_link_speed: String,
    pub maximum_link_width: u32,
}

/// The transport of a hardware RAID controller's logical disk.
pub const HARDWARE_RAID_TRANSPORT: &str = "raid";

#[derive(Clone, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub struct StorageDeviceInventory {
    /// Device model reported by Linux, or a conservative generic label.
    pub model: String,
    /// Normalized transport such as `nvme`, `sata`, `sas`, `virtio`, or `unknown`.
    pub transport: String,
    pub rotational: bool,
    pub capacity_bytes: u64,
}

impl StorageDeviceInventory {
    /// What a VM on this drive gets from it, whatever its model or exact
    /// size: hosts whose drives are of the same classes share an offering.
    /// The rotational flag counts only on a transport that names the
    /// hardware: a `virtio` disk reports rotation on some kernels and not
    /// on others, so a drive on any other transport is
    /// [`StorageClass::Other`] whatever the flag says.
    #[must_use]
    pub fn class(&self) -> StorageClass {
        match (self.transport.as_str(), self.rotational) {
            (HARDWARE_RAID_TRANSPORT, _) => StorageClass::Raid,
            ("nvme", false) => StorageClass::Nvme,
            ("sata" | "sas", false) => StorageClass::Ssd,
            ("nvme" | "sata" | "sas", true) => StorageClass::Hdd,
            _ => StorageClass::Other,
        }
    }

    /// Whether the drive's heads seek: its rotational flag, on any
    /// transport but a virtual disk's, whose flag says nothing of the disk
    /// below. A `virtio` disk reports rotation on some kernels and not on
    /// others, and a disk Linux names no transport for (`unknown`, such as a
    /// virtio-scsi or Xen disk) rotates unless it says otherwise. A hard
    /// disk on USB, as a home host's backup disk can be, rotates although
    /// [`Self::class`] does not call it one.
    #[must_use]
    pub fn rotates(&self) -> bool {
        self.rotational && !matches!(self.transport.as_str(), "virtio" | "unknown")
    }
}

/// The class of a drive ([`StorageDeviceInventory::class`]), ordered as a
/// storage profile lists its drive classes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageClass {
    /// A solid-state drive on the `nvme` transport.
    Nvme,
    /// A solid-state drive on SATA or SAS.
    Ssd,
    /// A rotational drive on the `nvme`, `sata` or `sas` transport.
    Hdd,
    /// A hardware RAID controller's logical disk.
    Raid,
    /// A drive whose transport says nothing of the hardware (`virtio`,
    /// `unknown`, any but `nvme`, `sata`, `sas` and `raid`), rotational or
    /// not: never grouped with a real drive.
    Other,
}

impl StorageClass {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nvme => "nvme",
            Self::Ssd => "ssd",
            Self::Hdd => "hdd",
            Self::Raid => "raid",
            Self::Other => "other",
        }
    }
}

impl std::fmt::Display for StorageClass {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The maximum guest serial console log tail: its last 64 KiB.
pub const MAXIMUM_CONSOLE_TAIL_BYTES: usize = 64 * 1024;

/// How cloud-init in a guest ended a boot, in the words of its own
/// `cloud-init status`: done, done with recoverable errors (degraded), or
/// with errors.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GuestInitializationStatus {
    Done,
    Degraded,
    Error,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

/// What happens when a container instance's process exits by itself.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RestartPolicy {
    /// Start it again, after a wait that grows after quick exits.
    #[default]
    Always,
    /// Start it again only when it failed.
    OnFailure,
    /// Leave it off.
    Never,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ImageCacheState {
    /// In the cache.
    Cached,
    /// Being downloaded, or paused while the downlink carries a download a
    /// job needs now or a network test.
    Downloading,
    /// To be downloaded after the images before it.
    Pending,
    /// Does not fit: in the cache's limit beside the cached images, or on
    /// its filesystem beside the room pre-downloads leave free.
    LeftOut,
    /// Its last download failed; it is tried again after a pause.
    Failed,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum PowerState {
    /// Start the guest.
    Running,
    /// Shut the guest down, forcing it off when it has not powered off
    /// two minutes after an ACPI shutdown request.
    Stopped,
    /// Shut the guest down as a stop does and start it again.
    Reboot,
    /// Force the guest off without asking it and start it again at once,
    /// as a reset button does: for a guest that hangs.
    Reset,
    /// A variant of a newer release, which this one does not know.
    #[serde(other)]
    #[cfg_attr(feature = "clap", value(skip))]
    Unknown,
}

/// The kinds of drive a host has, as a list writes them: "`NVMe`", "SSD" (SATA
/// or SAS) and "HDD", joined by `/` when there are several; `None` where no
/// drive is of a kind (a hardware RAID's logical disk, a virtual disk).
#[must_use]
pub fn drive_kinds(devices: &[StorageDeviceInventory]) -> Option<String> {
    let kinds: Vec<&str> = [
        (StorageClass::Nvme, "NVMe"),
        (StorageClass::Ssd, "SSD"),
        (StorageClass::Hdd, "HDD"),
    ]
    .into_iter()
    .filter(|(class, _)| devices.iter().any(|device| device.class() == *class))
    .map(|(_, label)| label)
    .collect();
    (!kinds.is_empty()).then(|| kinds.join("/"))
}

#[cfg(test)]
mod drive_kind_tests {
    use super::*;
    #[test]
    fn kinds_are_unique_and_sorted_with_unknown_devices_omitted() {
        let device = |transport: &str, rotational| StorageDeviceInventory {
            model: "disk".to_owned(),
            capacity_bytes: 1,
            transport: transport.to_owned(),
            rotational,
        };
        assert_eq!(drive_kinds(&[]), None);
        assert_eq!(drive_kinds(&[device("virtio", false)]), None);
        assert_eq!(
            drive_kinds(&[
                device("sata", true),
                device("nvme", false),
                device("sas", false),
                device("nvme", false)
            ])
            .as_deref(),
            Some("NVMe/SSD/HDD")
        );
    }
}
