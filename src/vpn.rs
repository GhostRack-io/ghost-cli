//! `ghost vpn`: the account's VPN connections (backlog item 161), one
//! device each on a gateway's `WireGuard` tunnel.
//!
//! The device's key pair is the customer's: ghost makes one with `--out`
//! and sends only its public key, or takes the public key of one made
//! elsewhere. A private key is never printed, logged or sent; it is
//! written only into a configuration file only its owner may read
//! (`0600`), or drawn as a QR code when `--qr` asks for it.

use std::{
    fmt::Write as _,
    future::Future,
    io::{Read as _, Write as _},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use chrono::Utc;
use clap::{Args, Subcommand, ValueEnum};
use ghostrack_client_api::{
    api::{
        CreateVpnConnection, DeleteVpnConnection, GetVpnCatalog, GetVpnConnection,
        ListVpnConnections, RotateVpnKey, SetVpnIncoming, SetVpnTrackedConnections,
    },
    website::{
        CreateVpnConnectionRequest, GatewayTier, RotateVpnKeyRequest, SetVpnIncomingRequest,
        SetVpnTrackedConnectionsRequest, VPN_TRACKED_CONNECTION_TIERS, VpnCatalogView,
        VpnConnectionState, VpnConnectionView, valid_hostname,
    },
};
use rand_core::{OsRng, RngCore as _};
use serde_json::{Map, Value, json};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    ApiClient, Cli, GatewayTierArg, IdempotencyArgs, InstanceReference, MutationArgs, OutputFormat,
    TRANSIENT_POLL_WINDOW, Terminal, api, escape_control, gateway_tier_words, keys, local_moment,
    next_poll_retry_delay, notice, pretty, retried_by_id, to_value, typed_refusal, wire_name,
};

/// `ghost vpn`'s commands.
#[derive(Subcommand)]
pub(crate) enum VpnCommand {
    /// List where VPN connections can be created: each location's tiers,
    /// whether it has room, and their prices; and the prices of more
    /// tracked connections.
    Catalog,
    /// List this account's VPN connections, newest first, and those that
    /// failed lately.
    List,
    /// Get one VPN connection: its addresses, its key's state, its last
    /// handshake and its prices, those to come too.
    Get {
        /// VPN connection ID or name, from `ghost vpn list`.
        #[arg(value_name = "CONNECTION", value_parser = parse_vpn_reference)]
        connection: InstanceReference,
    },
    /// Create a VPN connection for one device.
    ///
    /// With --out, ghost makes the device's key pair, sends only its public
    /// key, waits until the connection is ready and writes the device's
    /// configuration to FILE, which only you may read. With --public-key,
    /// it sends the public key of a pair you made, such as with `wg
    /// genkey`; `ghost vpn config` then writes the configuration from your
    /// private key.
    Create(CreateArgs),
    /// Write a VPN connection's configuration from the device's private
    /// key, to standard output or to a file.
    Config(ConfigArgs),
    /// Give a VPN connection a new device key: the old key stops working
    /// once its gateway takes the new one. With --out, ghost makes the new
    /// key pair, waits until the gateway has it and writes the new
    /// configuration.
    NewConfig(NewConfigArgs),
    /// Allow or block traffic from the internet to the device. It is
    /// blocked until you allow it.
    Incoming {
        /// VPN connection ID or name, from `ghost vpn list`.
        #[arg(value_name = "CONNECTION", value_parser = parse_vpn_reference)]
        connection: InstanceReference,
        /// Allow or block it.
        #[arg(value_enum)]
        setting: IncomingSetting,
        #[command(flatten)]
        idempotency: IdempotencyArgs,
    },
    /// Change how many connections the device may hold open at once:
    /// 4096 (included), 16384, 65536 or 262144. More is possible while the
    /// gateway has room; fewer always.
    TrackedConnections {
        /// VPN connection ID or name, from `ghost vpn list`.
        #[arg(value_name = "CONNECTION", value_parser = parse_vpn_reference)]
        connection: InstanceReference,
        /// 4096, 16384, 65536 or 262144.
        #[arg(value_name = "N", value_parser = parse_tracked_connections)]
        tracked_connections: u32,
        #[command(flatten)]
        idempotency: IdempotencyArgs,
    },
    /// Delete a VPN connection: its address and its device's key stop
    /// working at once.
    Delete {
        /// VPN connection ID or name, from `ghost vpn list`.
        #[arg(value_name = "CONNECTION", value_parser = parse_vpn_reference)]
        connection: InstanceReference,
        /// Confirm the irreversible deletion.
        #[arg(long)]
        yes: bool,
        #[command(flatten)]
        idempotency: IdempotencyArgs,
    },
}

/// `ghost vpn incoming`'s setting.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum IncomingSetting {
    Allow,
    Block,
}

/// Where the device's key comes from: ghost makes it and writes the
/// configuration, or the customer gives the public key of their own.
#[derive(Args)]
#[group(required = true, multiple = false)]
pub(crate) struct KeySource {
    /// Make the device's key pair and write its configuration to FILE
    /// (only you may read it). The private key is written nowhere else.
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
    /// The device's `WireGuard` public key (base64, as `wg pubkey` prints
    /// it), of a key pair you made. Never a private key.
    #[arg(long, value_name = "KEY", value_parser = parse_public_key)]
    public_key: Option<String>,
}

#[derive(Args)]
pub(crate) struct CreateArgs {
    /// The location's code, from `ghost vpn catalog`.
    #[arg(long, value_name = "CODE")]
    location: String,
    /// `shared-ip`, `shared-bandwidth`, or `dedicated-ip` (also
    /// `high-bandwidth`) for a gateway of its own; a trial account takes
    /// `shared-ip` only.
    #[arg(long, value_enum)]
    tier: GatewayTierArg,
    /// Its name: lowercase letters, digits and `-`, at most 63. Without it,
    /// `vpn-` and the end of its ID.
    #[arg(long, value_parser = parse_vpn_name)]
    name: Option<String>,
    /// How many connections the device may hold open at once: 4096
    /// (included, the default), 16384, 65536 or 262144.
    #[arg(long, value_name = "N", value_parser = parse_tracked_connections)]
    tracked_connections: Option<u32>,
    #[command(flatten)]
    key: KeySource,
    /// Replace the --out file when it exists.
    #[arg(long, conflicts_with = "public_key")]
    force: bool,
    /// Also show the configuration as a QR code, for the `WireGuard` app on
    /// a phone to scan.
    #[arg(long, conflicts_with = "public_key")]
    qr: bool,
    #[command(flatten)]
    mutation: MutationArgs,
}

#[derive(Args)]
pub(crate) struct ConfigArgs {
    /// VPN connection ID or name, from `ghost vpn list`.
    #[arg(value_name = "CONNECTION", value_parser = parse_vpn_reference)]
    connection: InstanceReference,
    /// The file that holds the device's private key, as `wg genkey`
    /// writes it.
    #[arg(long, value_name = "FILE")]
    private_key_file: PathBuf,
    /// Write the configuration to FILE (only you may read it) rather than
    /// to standard output.
    #[arg(long, value_name = "FILE")]
    out: Option<PathBuf>,
    /// Replace the --out file when it exists.
    #[arg(long, requires = "out")]
    force: bool,
    /// Show the configuration as a QR code, for the `WireGuard` app on a
    /// phone to scan.
    #[arg(long)]
    qr: bool,
}

#[derive(Args)]
pub(crate) struct NewConfigArgs {
    /// VPN connection ID or name, from `ghost vpn list`.
    #[arg(value_name = "CONNECTION", value_parser = parse_vpn_reference)]
    connection: InstanceReference,
    #[command(flatten)]
    key: KeySource,
    /// Replace the --out file when it exists.
    #[arg(long, conflicts_with = "public_key")]
    force: bool,
    /// Also show the configuration as a QR code, for the `WireGuard` app on
    /// a phone to scan.
    #[arg(long, conflicts_with = "public_key")]
    qr: bool,
    #[command(flatten)]
    mutation: MutationArgs,
}

/// Accept a VPN connection's ID, or something that can be its name.
fn parse_vpn_reference(value: &str) -> Result<InstanceReference, String> {
    if let Ok(id) = Uuid::parse_str(value) {
        return Ok(InstanceReference::Id(id));
    }
    let name = value.to_ascii_lowercase();
    if valid_vpn_name(&name) {
        Ok(InstanceReference::Name(name))
    } else {
        Err("must be a VPN connection's ID or name, from `ghost vpn list`".to_owned())
    }
}

/// A VPN connection's name: lowercase letters, digits and `-`, at most 63.
fn valid_vpn_name(name: &str) -> bool {
    name.len() <= 63 && !name.contains('.') && valid_hostname(name)
}

fn parse_vpn_name(value: &str) -> Result<String, String> {
    if valid_vpn_name(value) {
        Ok(value.to_owned())
    } else {
        Err("must be lowercase letters, digits and `-`, at most 63".to_owned())
    }
}

fn parse_tracked_connections(value: &str) -> Result<u32, String> {
    value
        .replace([',', '_'], "")
        .parse::<u32>()
        .ok()
        .filter(|count| VPN_TRACKED_CONNECTION_TIERS.contains(count))
        .ok_or_else(|| "must be 4096, 16384, 65536 or 262144".to_owned())
}

/// A `WireGuard` key as its tools write it: standard base64 of 32 bytes.
fn decoded_key(value: &str) -> Option<[u8; 32]> {
    let value = value.trim();
    if value.len() != 44 {
        return None;
    }
    STANDARD.decode(value).ok()?.try_into().ok()
}

fn parse_public_key(value: &str) -> Result<String, String> {
    decoded_key(value)
        .map(|key| STANDARD.encode(key))
        .ok_or_else(|| {
            "must be a WireGuard public key: 44 characters of base64, as `wg pubkey` prints it"
                .to_owned()
        })
}

/// The wire tier of `--tier`: Dedicated IP is a gateway of the
/// connection's own, the instances' high bandwidth tier
/// (`high_bandwidth`), which `high-bandwidth` names too.
const fn vpn_tier(tier: GatewayTierArg) -> GatewayTier {
    match tier {
        GatewayTierArg::SharedIp => GatewayTier::SharedIp,
        GatewayTierArg::SharedBandwidth => GatewayTier::SharedBandwidth,
        GatewayTierArg::HighBandwidth | GatewayTierArg::DedicatedIp => GatewayTier::HighBandwidth,
    }
}

/// A device's `WireGuard` key pair. The private key is clamped as `wg
/// genkey` clamps it and is wiped when dropped.
pub(crate) struct DeviceKey {
    private: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl DeviceKey {
    /// A new key pair from the operating system's random source.
    pub(crate) fn generate() -> Self {
        let mut private = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(private.as_mut());
        private[0] &= 0xf8;
        private[31] &= 0x7f;
        private[31] |= 0x40;
        Self::from_private(private)
    }

    /// The pair of a private key.
    pub(crate) fn from_private(private: Zeroizing<[u8; 32]>) -> Self {
        let public = x25519_dalek::x25519(*private, x25519_dalek::X25519_BASEPOINT_BYTES);
        Self { private, public }
    }

    /// The private key in a file such as `wg genkey` writes: its base64,
    /// with surrounding white space. The file's text is never part of an
    /// error.
    pub(crate) fn read(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("open private key file {}", path.display()))?;
        let mut text = Zeroizing::new(Vec::with_capacity(PRIVATE_KEY_FILE_BYTES));
        file.take(PRIVATE_KEY_FILE_BYTES as u64)
            .read_to_end(&mut text)
            .with_context(|| format!("read private key file {}", path.display()))?;
        let invalid = || {
            anyhow::anyhow!(
                "{} holds no WireGuard private key: 44 characters of base64, as `wg genkey` writes it",
                path.display()
            )
        };
        let encoded = std::str::from_utf8(text.trim_ascii()).map_err(|_| invalid())?;
        if encoded.len() != 44 {
            return Err(invalid());
        }
        let decoded = Zeroizing::new(STANDARD.decode(encoded).map_err(|_| invalid())?);
        let private: [u8; 32] = decoded.as_slice().try_into().map_err(|_| invalid())?;
        Ok(Self::from_private(Zeroizing::new(private)))
    }

    /// The public key, standard base64.
    pub(crate) fn public_base64(&self) -> String {
        STANDARD.encode(self.public)
    }

    fn private_base64(&self) -> Zeroizing<String> {
        Zeroizing::new(STANDARD.encode(*self.private))
    }
}

/// More than any private key file `wg genkey` writes (45 bytes).
const PRIVATE_KEY_FILE_BYTES: usize = 256;

/// The `WireGuard` configuration of `view`'s device with its private key
/// `key`: a full tunnel through public resolvers (the owner, 2026-11-13),
/// MTU 1420 and a keepalive every 25 seconds. The gateway's values are
/// checked first, so none of them can add a line to it.
///
/// # Errors
///
/// A connection that is not ready yet, and a value of the gateway's that
/// is not what its field holds.
pub(crate) fn config_text(key: &DeviceKey, view: &VpnConnectionView) -> Result<Zeroizing<String>> {
    let not_ready = || {
        anyhow::anyhow!(
            "VPN connection {} is not ready yet ({}): its configuration needs its gateway's address and key",
            view.id,
            wire_name(view.state)
        )
    };
    let address = view.tunnel_address.as_deref().ok_or_else(not_ready)?;
    let endpoint = view.endpoint.as_deref().ok_or_else(not_ready)?;
    let gateway_key = view.gateway_public_key.as_deref().ok_or_else(not_ready)?;
    let address = tunnel_address(address)
        .with_context(|| format!("the tunnel address {} is invalid", escape_control(address)))?;
    if endpoint.parse::<SocketAddr>().is_err() {
        bail!(
            "the gateway's endpoint {} is not an address and port",
            escape_control(endpoint)
        );
    }
    let gateway_key = decoded_key(gateway_key)
        .map(|key| STANDARD.encode(key))
        .context("the gateway's public key is not a WireGuard key")?;
    let private = key.private_base64();
    Ok(Zeroizing::new(format!(
        "[Interface]\nPrivateKey = {}\nAddress = {address}\nDNS = 1.1.1.1, 9.9.9.9\nMTU = 1420\n\n[Peer]\nPublicKey = {gateway_key}\nEndpoint = {endpoint}\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
        private.as_str()
    )))
}

/// The device's tunnel address with its prefix: `/32` when it has none
/// (`/128` for an IPv6 one).
fn tunnel_address(address: &str) -> Option<String> {
    let (ip, prefix) = match address.split_once('/') {
        Some((ip, prefix)) => (ip, Some(prefix)),
        None => (address, None),
    };
    let ip: IpAddr = ip.parse().ok()?;
    let most = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix {
        Some(prefix) => prefix.parse::<u8>().ok().filter(|prefix| *prefix <= most)?,
        None => most,
    };
    Some(format!("{ip}/{prefix}"))
}

/// `config` as a QR code of Unicode half blocks, light modules drawn, for
/// a terminal with a dark background as most have.
///
/// # Errors
///
/// A configuration too long for a QR code.
pub(crate) fn qr_text(config: &str) -> Result<Zeroizing<String>> {
    use qrcode::render::unicode::Dense1x2;

    let code = qrcode::QrCode::with_error_correction_level(config.as_bytes(), qrcode::EcLevel::L)
        .context("the configuration does not fit a QR code")?;
    Ok(Zeroizing::new(
        code.render::<Dense1x2>()
            .dark_color(Dense1x2::Light)
            .light_color(Dense1x2::Dark)
            .quiet_zone(true)
            .build(),
    ))
}

/// Write `text` and a newline to standard output now, before the result:
/// a QR code, which `--json` never carries.
fn print_now(text: &str) -> Result<()> {
    let mut stdout = std::io::stdout().lock();
    match writeln!(stdout, "{text}").and_then(|()| stdout.flush()) {
        Err(error) if error.kind() != std::io::ErrorKind::BrokenPipe => {
            Err(error).context("write the QR code")
        }
        _ => Ok(()),
    }
}

/// `--qr` draws on the terminal, which `--json` and `--compact` leave for
/// JSON alone.
fn refuse_qr_with_json(cli: &Cli, qr: bool) -> Result<()> {
    if qr && cli.output_format() != OutputFormat::Readable {
        bail!("--qr draws the QR code on the terminal; leave out --json and --compact");
    }
    Ok(())
}

/// Refuse an `--out` file that exists before anything is sent, unless
/// `force`.
fn refuse_existing(out: Option<&Path>, force: bool) -> Result<()> {
    if let Some(out) = out
        && !force
        && std::fs::symlink_metadata(out).is_ok()
    {
        bail!(
            "{} already exists: give another file, or --force to replace it",
            out.display()
        );
    }
    Ok(())
}

/// Write `config` to `out`, `0600`, and draw it as a QR code when `qr`.
fn deliver(config: &str, out: &Path, force: bool, qr: bool) -> Result<()> {
    keys::write_private_file(out, config.as_bytes(), force, CONFIG_FILE)?;
    if qr {
        print_now(&qr_text(config)?)?;
    }
    Ok(())
}

/// What a VPN configuration file is called in errors.
const CONFIG_FILE: &str = "VPN configuration file";

/// How long `new-config` waits for the gateway to take the new key: as
/// long as the backend gives a new connection to be ready.
const KEY_APPLY_LIMIT: Duration = Duration::from_mins(15);

/// A wait that stopped because the connection will never use the device
/// key it waited with: the connection failed or ended, or its gateway
/// refused the key. A key ghost made for it is then not kept.
#[derive(Debug)]
struct KeyUnused(String);

impl std::fmt::Display for KeyUnused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for KeyUnused {}

fn key_unused(error: &anyhow::Error) -> bool {
    error.downcast_ref::<KeyUnused>().is_some()
}

/// Whether a mutation that ended in `error` may have been applied: the
/// backend did not answer it, or answered success in a shape this ghost
/// cannot read.
fn maybe_applied(error: &anyhow::Error) -> bool {
    api::unanswered(error) || error.downcast_ref::<serde_json::Error>().is_some()
}

/// Ctrl-C, from the first time this is polled on; never where it cannot
/// be caught. A creation or a new key that it stops keeps the key ghost
/// made, as a failed wait does.
async fn interrupted() {
    if tokio::signal::ctrl_c().await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// The line to recover by when a key ghost made was sent but could not be
/// kept, for the connection `connection_id`, or one the backend may have
/// created.
fn recover_line(connection_id: Option<Uuid>) -> String {
    match connection_id {
        Some(id) => format!(
            "Its private key was not kept. To give it a new key and a configuration once it is ready: ghost vpn new-config {id} --out FILE"
        ),
        None => "Its private key was not kept. If `ghost vpn list` lists the connection, to give it a new key and a configuration once it is ready: ghost vpn new-config CONNECTION --out FILE".to_owned(),
    }
}

/// Keep the private key ghost made alone in `out`'s reserved `file`
/// (`0600`, as `wg genkey` writes one) when `error` stopped a creation
/// that the backend has made, or may have, and say how to write the
/// configuration from it; when even that fails, how to give the
/// connection a new key.
fn keep_key(
    file: keys::PrivateFile,
    key: &DeviceKey,
    connection_id: Option<Uuid>,
    out: &Path,
    error: anyhow::Error,
) -> anyhow::Error {
    let mut text = Zeroizing::new(String::with_capacity(45));
    text.push_str(&key.private_base64());
    text.push('\n');
    if let Err(kept) = file.place(text.as_bytes()) {
        return error
            .context(format!("{kept:#}"))
            .context(recover_line(connection_id));
    }
    let out = out.display();
    error.context(match connection_id {
        Some(id) => format!(
            "The device's private key is in {out}. To write its configuration from it once VPN connection {id} is ready: ghost vpn config {id} --private-key-file {out} --out {out} --force"
        ),
        None => format!(
            "The VPN connection may have been created; the device's private key is in {out}. If `ghost vpn list` lists the connection, to write its configuration from it once it is ready: ghost vpn config CONNECTION --private-key-file {out} --out {out} --force"
        ),
    })
}

/// Run a `ghost vpn` command.
pub(crate) async fn execute(
    cli: &Cli,
    api: &ApiClient,
    command: &VpnCommand,
    show_progress: bool,
) -> Result<Value> {
    match command {
        VpnCommand::Catalog => to_value(api.read(&GetVpnCatalog, "").await?),
        VpnCommand::List => to_value(api.read(&ListVpnConnections, "").await?),
        VpnCommand::Get { connection } => {
            let connection_id = resolve(api, connection, false).await?;
            to_value(api.read(&GetVpnConnection { connection_id }, "").await?)
        }
        VpnCommand::Create(args) => create(cli, api, args, show_progress, interrupted()).await,
        VpnCommand::Config(args) => {
            refuse_qr_with_json(cli, args.qr)?;
            let key = DeviceKey::read(&args.private_key_file)?;
            refuse_existing(args.out.as_deref(), args.force)?;
            let connection_id = resolve(api, &args.connection, false).await?;
            let view = api.read(&GetVpnConnection { connection_id }, "").await?;
            if view.device_public_key != key.public_base64() {
                bail!(
                    "{} is not the key of VPN connection {connection_id}: its public key is {}, the connection's {}",
                    args.private_key_file.display(),
                    key.public_base64(),
                    escape_control(&view.device_public_key)
                );
            }
            let config = config_text(&key, &view)?;
            match &args.out {
                Some(out) => {
                    deliver(&config, out, args.force, args.qr)?;
                    Ok(json!({"vpn_connection_id": connection_id, "config_file": out}))
                }
                None if args.qr => Ok(json!({"qr": qr_text(&config)?.as_str()})),
                None => Ok(json!({"config": config.as_str()})),
            }
        }
        VpnCommand::NewConfig(args) => {
            new_config(cli, api, args, show_progress, interrupted()).await
        }
        VpnCommand::Incoming {
            connection,
            setting,
            idempotency,
        } => {
            let connection_id = resolve(api, connection, true).await?;
            let view = api
                .write_retryable(
                    &SetVpnIncoming { connection_id },
                    &SetVpnIncomingRequest {
                        allowed: *setting == IncomingSetting::Allow,
                    },
                    &retried_by_id(idempotency.key(), connection, connection_id),
                )
                .await?;
            to_value(view)
        }
        VpnCommand::TrackedConnections {
            connection,
            tracked_connections,
            idempotency,
        } => {
            let connection_id = resolve(api, connection, true).await?;
            let view = api
                .write_retryable(
                    &SetVpnTrackedConnections { connection_id },
                    &SetVpnTrackedConnectionsRequest {
                        tracked_connections: *tracked_connections,
                    },
                    &retried_by_id(idempotency.key(), connection, connection_id),
                )
                .await?;
            to_value(view)
        }
        VpnCommand::Delete {
            connection,
            yes,
            idempotency,
        } => {
            if !*yes {
                bail!("VPN connection deletion is irreversible; repeat with --yes");
            }
            let connection_id = resolve(api, connection, true).await?;
            let view = api
                .write_retryable(
                    &DeleteVpnConnection { connection_id },
                    &(),
                    &retried_by_id(idempotency.key(), connection, connection_id),
                )
                .await?;
            to_value(view)
        }
    }
}

/// The creation `args` asks for, with the device's public key.
fn creation(args: &CreateArgs, device_public_key: String) -> CreateVpnConnectionRequest {
    CreateVpnConnectionRequest {
        name: args.name.clone(),
        tier: vpn_tier(args.tier),
        location: args.location.clone(),
        device_public_key,
        tracked_connections: args.tracked_connections,
    }
}

/// `ghost vpn create`. With --out, the file's place is reserved before
/// anything is sent; once the backend may have the key, any stop short of
/// the configuration (a failed wait, `interrupt`) keeps the private key
/// alone in that file, unless the connection ended and will never use it.
async fn create(
    cli: &Cli,
    api: &ApiClient,
    args: &CreateArgs,
    show_progress: bool,
    interrupt: impl Future<Output = ()>,
) -> Result<Value> {
    refuse_qr_with_json(cli, args.qr)?;
    let interval = Duration::from_secs(args.mutation.poll_seconds);
    let Some(out) = &args.key.out else {
        let Some(public_key) = &args.key.public_key else {
            bail!("give --out FILE or --public-key KEY");
        };
        let created = api
            .write_retryable(
                &CreateVpnConnection,
                &creation(args, public_key.clone()),
                &args.mutation.key(),
            )
            .await?;
        if !args.mutation.wait {
            return to_value(created);
        }
        return to_value(wait_until_ready(api, created, interval, show_progress).await?);
    };
    let file = keys::PrivateFile::reserve(out, args.force, CONFIG_FILE)?;
    let key = DeviceKey::generate();
    let request = creation(args, key.public_base64());
    let mutation_key = args.mutation.key();
    tokio::pin!(interrupt);
    let created = tokio::select! {
        created = api.write_retryable(&CreateVpnConnection, &request, &mutation_key) => match created {
            Ok(created) => created,
            Err(error) if maybe_applied(&error) => {
                return Err(keep_key(file, &key, None, out, error));
            }
            Err(error) => return Err(error),
        },
        () = &mut interrupt => {
            let error = anyhow::anyhow!("interrupted before the backend answered");
            return Err(keep_key(file, &key, None, out, error));
        }
    };
    let connection_id = created.id;
    let waited = tokio::select! {
        ready = wait_until_ready(api, created, interval, show_progress) => ready,
        () = &mut interrupt => Err(anyhow::anyhow!(
            "interrupted before VPN connection {connection_id} was ready"
        )),
    };
    let ready = match waited {
        Ok(ready) => ready,
        Err(error) if key_unused(&error) => return Err(error),
        Err(error) => return Err(keep_key(file, &key, Some(connection_id), out, error)),
    };
    let config = match config_text(&key, &ready) {
        Ok(config) => config,
        Err(error) => return Err(keep_key(file, &key, Some(connection_id), out, error)),
    };
    file.place(config.as_bytes())
        .map_err(|error| error.context(recover_line(Some(connection_id))))?;
    if args.qr {
        print_now(&qr_text(&config)?)?;
    }
    let mut output = to_value(ready)?;
    output["config_file"] = json!(out);
    Ok(output)
}

/// `ghost vpn new-config`. With --out, the file's place is reserved before
/// the key is sent. The rotation's answer has what the configuration needs,
/// so a wait that stops short of the gateway taking the key (a failed read,
/// [`KEY_APPLY_LIMIT`], `interrupt`) still writes the new configuration; a
/// refused key, or a connection that ended, writes nothing, and the file
/// that was there stays.
async fn new_config(
    cli: &Cli,
    api: &ApiClient,
    args: &NewConfigArgs,
    show_progress: bool,
    interrupt: impl Future<Output = ()>,
) -> Result<Value> {
    refuse_qr_with_json(cli, args.qr)?;
    refuse_existing(args.key.out.as_deref(), args.force)?;
    let interval = Duration::from_secs(args.mutation.poll_seconds);
    let connection_id = resolve(api, &args.connection, true).await?;
    let mutation_key = retried_by_id(args.mutation.key(), &args.connection, connection_id);
    let Some(out) = &args.key.out else {
        let Some(public_key) = &args.key.public_key else {
            bail!("give --out FILE or --public-key KEY");
        };
        let rotated = api
            .write_retryable(
                &RotateVpnKey { connection_id },
                &RotateVpnKeyRequest {
                    public_key: public_key.clone(),
                },
                &mutation_key,
            )
            .await?;
        if !args.mutation.wait {
            return to_value(rotated);
        }
        return to_value(
            wait_until_applied(api, rotated, interval, show_progress, KEY_APPLY_LIMIT).await?,
        );
    };
    let file = keys::PrivateFile::reserve(out, args.force, CONFIG_FILE)?;
    let key = DeviceKey::generate();
    let endpoint = RotateVpnKey { connection_id };
    let request = RotateVpnKeyRequest {
        public_key: key.public_base64(),
    };
    tokio::pin!(interrupt);
    let rotated = tokio::select! {
        rotated = api.write_retryable(&endpoint, &request, &mutation_key) => match rotated {
            Ok(rotated) => rotated,
            Err(error) if maybe_applied(&error) => {
                return Err(error.context(recover_line(Some(connection_id))));
            }
            Err(error) => return Err(error),
        },
        () = &mut interrupt => {
            return Err(anyhow::anyhow!("interrupted before the backend answered")
                .context(recover_line(Some(connection_id))));
        }
    };
    let early = config_text(&key, &rotated)
        .map_err(|error| error.context(recover_line(Some(connection_id))))?;
    let waited = tokio::select! {
        applied = wait_until_applied(api, rotated, interval, show_progress, KEY_APPLY_LIMIT) => applied,
        () = &mut interrupt => Err(anyhow::anyhow!(
            "interrupted before the gateway of VPN connection {connection_id} took the new key"
        )),
    };
    let applied = match waited {
        Ok(applied) => applied,
        Err(error) if key_unused(&error) => return Err(error),
        Err(error) => {
            if let Err(placed) = file.place(early.as_bytes()) {
                return Err(error
                    .context(format!("{placed:#}"))
                    .context(recover_line(Some(connection_id))));
            }
            return Err(error.context(format!(
                "The new configuration is in {}; it works once the gateway takes the new key. To see when: ghost vpn get {connection_id}",
                out.display()
            )));
        }
    };
    let config = config_text(&key, &applied)
        .and_then(|config| {
            file.place(config.as_bytes())?;
            Ok(config)
        })
        .map_err(|error| error.context(recover_line(Some(connection_id))))?;
    if args.qr {
        print_now(&qr_text(&config)?)?;
    }
    let mut output = to_value(applied)?;
    output["config_file"] = json!(out);
    Ok(output)
}

/// Read the connection `connection_id` for a wait, retrying transport
/// failures, timeouts, and overloaded or failing servers with backoff for
/// up to [`TRANSIENT_POLL_WINDOW`], as a job's wait does: a backend deploy
/// does not end the wait.
async fn read_connection(
    api: &ApiClient,
    connection_id: Uuid,
    interval: Duration,
) -> Result<VpnConnectionView> {
    let started = tokio::time::Instant::now();
    let mut delay = interval;
    loop {
        match api.read(&GetVpnConnection { connection_id }, "").await {
            Ok(view) => return Ok(view),
            Err(error)
                if api::is_transient(&error) && started.elapsed() < TRANSIENT_POLL_WINDOW =>
            {
                notice(&format!(
                    "VPN connection {connection_id}: {}. Retrying in {} s.",
                    escape_control(format!("{error:#}").trim_end_matches('.')),
                    delay.as_secs()
                ));
                tokio::time::sleep(delay).await;
                delay = next_poll_retry_delay(delay, interval);
            }
            Err(error) => return Err(error),
        }
    }
}

/// Follow a new connection until it is ready, every `interval`. One that
/// fails, or that ends, stops the wait with why ([`KeyUnused`]); one in a
/// state this ghost does not know stops it after
/// [`TRANSIENT_POLL_WINDOW`], as a job's does. The backend fails a
/// connection that is not ready within its provisioning limit, so the wait
/// ends.
async fn wait_until_ready(
    api: &ApiClient,
    mut view: VpnConnectionView,
    interval: Duration,
    show_progress: bool,
) -> Result<VpnConnectionView> {
    let connection_id = view.id;
    if show_progress && view.state == VpnConnectionState::Provisioning {
        notice(&format!(
            "Waiting for VPN connection {connection_id} to be ready"
        ));
    }
    let mut unknown_since = None;
    loop {
        match view.state {
            VpnConnectionState::Ready => return Ok(view),
            VpnConnectionState::Provisioning => unknown_since = None,
            VpnConnectionState::Failed => {
                return Err(KeyUnused(format!(
                    "VPN connection {connection_id} failed: {}. Its charges were given back; to try again, create a new one.",
                    escape_control(
                        view.last_error
                            .as_deref()
                            .unwrap_or("no reason given")
                            .trim_end_matches('.')
                    )
                ))
                .into());
            }
            VpnConnectionState::Suspended | VpnConnectionState::Deleted => {
                return Err(KeyUnused(format!(
                    "VPN connection {connection_id} is {}",
                    wire_name(view.state)
                ))
                .into());
            }
            VpnConnectionState::Unknown => {
                let since = *unknown_since.get_or_insert_with(tokio::time::Instant::now);
                if since.elapsed() >= TRANSIENT_POLL_WINDOW {
                    bail!(
                        "VPN connection {connection_id} is in a state this ghost does not know; update ghost, then: ghost vpn get {connection_id}"
                    );
                }
            }
        }
        tokio::time::sleep(interval).await;
        view = read_connection(api, connection_id, interval).await?;
    }
}

/// Follow a key rotation until the gateway applied the new key's revision,
/// every `interval`, for at most `limit`. A refusal of the key, or a
/// connection that is no longer ready, stops the wait with why
/// ([`KeyUnused`]).
async fn wait_until_applied(
    api: &ApiClient,
    mut view: VpnConnectionView,
    interval: Duration,
    show_progress: bool,
    limit: Duration,
) -> Result<VpnConnectionView> {
    let started = tokio::time::Instant::now();
    let connection_id = view.id;
    let Some(wanted) = view.key_revision else {
        bail!(
            "the backend did not say the new key's revision; to follow it: ghost vpn get {connection_id}"
        );
    };
    if show_progress {
        notice(&format!(
            "Waiting for the gateway of VPN connection {connection_id} to take the new key"
        ));
    }
    let mut unknown_since = None;
    loop {
        if let Some(reason) = &view.refused_reason {
            return Err(KeyUnused(format!(
                "the gateway refused the new key of VPN connection {connection_id}: {}",
                escape_control(reason)
            ))
            .into());
        }
        match view.state {
            VpnConnectionState::Ready => {
                unknown_since = None;
                if view
                    .applied_key_revision
                    .is_some_and(|applied| applied >= wanted)
                {
                    return Ok(view);
                }
            }
            VpnConnectionState::Unknown => {
                let since = *unknown_since.get_or_insert_with(tokio::time::Instant::now);
                if since.elapsed() >= TRANSIENT_POLL_WINDOW {
                    bail!(
                        "VPN connection {connection_id} is in a state this ghost does not know; update ghost, then: ghost vpn get {connection_id}"
                    );
                }
            }
            state => {
                return Err(KeyUnused(format!(
                    "VPN connection {connection_id} is {} and takes no new key",
                    wire_name(state)
                ))
                .into());
            }
        }
        if started.elapsed() >= limit {
            bail!(
                "the gateway of VPN connection {connection_id} has not taken the new key within {} minutes",
                limit.as_secs() / 60
            );
        }
        tokio::time::sleep(interval).await;
        view = read_connection(api, connection_id, interval).await?;
    }
}

/// The ID of the connection `reference` names: an ID as it is; a name by
/// the account's listed connections, not deleted or failed, of which
/// exactly one must have it. A `change` names the ID first.
async fn resolve(api: &ApiClient, reference: &InstanceReference, change: bool) -> Result<Uuid> {
    let name = match reference {
        InstanceReference::Id(id) => return Ok(*id),
        InstanceReference::Name(name) => name,
    };
    let listed: Vec<VpnConnectionView> = api.read(&ListVpnConnections, "").await?;
    let matches: Vec<&VpnConnectionView> = listed
        .iter()
        .filter(|view| {
            !matches!(
                view.state,
                VpnConnectionState::Deleted | VpnConnectionState::Failed
            ) && view.name.eq_ignore_ascii_case(name)
        })
        .collect();
    match matches.as_slice() {
        [view] => {
            if change {
                notice(&format!("VPN connection {name} is {}", view.id));
            }
            Ok(view.id)
        }
        [] => Err(typed_refusal(
            "vpn_connection_not_found",
            format!("no VPN connection is named {name}; `ghost vpn list` lists the names"),
        )),
        several => Err(typed_refusal(
            "vpn_connection_name_ambiguous",
            format!(
                "{} VPN connections are named {name}:\n{}\nTo choose one, name it by its ID.",
                several.len(),
                several
                    .iter()
                    .map(|view| format!("  {}  {}", view.id, wire_name(view.state)))
                    .collect::<Vec<_>>()
                    .join("\n")
            ),
        )),
    }
}

/// What `ghost vpn config` prints as it is, in any format but JSON: the
/// configuration, or its QR code.
pub(crate) fn raw_output(command: &VpnCommand, output: &Value) -> Option<String> {
    if !matches!(command, VpnCommand::Config(ConfigArgs { out: None, .. })) {
        return None;
    }
    output["qr"]
        .as_str()
        .or_else(|| output["config"].as_str().map(str::trim_end))
        .map(str::to_owned)
}

/// A `ghost vpn` result for reading; `None` for one not in the shape it
/// knows, which is then shown as it is.
pub(crate) fn readable(command: &VpnCommand, output: &Value, terminal: Terminal) -> Option<String> {
    match command {
        VpnCommand::Catalog => Some(catalog_text(
            &serde_json::from_value(output.clone()).ok()?,
            terminal,
        )),
        VpnCommand::List => {
            let views: Vec<VpnConnectionView> = serde_json::from_value(output.clone()).ok()?;
            Some(list_text(&views, terminal))
        }
        VpnCommand::Config(_) => None,
        _ => {
            let view: VpnConnectionView = serde_json::from_value(output.clone()).ok()?;
            let mut record = record(&view);
            if let Some(file) = output.get("config_file") {
                record.insert("config_file".to_owned(), file.clone());
            }
            Some(pretty::render(&Value::Object(record), terminal))
        }
    }
}

/// `count` with its thousands grouped: `16,384`.
fn grouped(count: u32) -> String {
    let digits = count.to_string();
    let mut text = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            text.push(',');
        }
        text.push(digit);
    }
    text
}

fn catalog_text(catalog: &VpnCatalogView, terminal: Terminal) -> String {
    if !catalog.enabled {
        return "  VPN connections are not offered yet.".to_owned();
    }
    let rows: Vec<Value> = catalog
        .locations
        .iter()
        .flat_map(|location| {
            location.tiers.iter().map(move |offer| {
                json!({
                    "location": location.location,
                    "name": location.display_name,
                    "tier": gateway_tier_words(offer.tier),
                    "room": if offer.room { "yes" } else { "at capacity" },
                    "a_month": offer.base_microusd_per_month.map(pretty::dollars),
                    "a_tib": offer.traffic_microusd_per_tib.map(pretty::dollars),
                    "incoming_ports": offer.incoming_ports,
                })
            })
        })
        .collect();
    let mut text = pretty::render_rows(
        &[
            "location",
            "name",
            "tier",
            "room",
            "a_month",
            "a_tib",
            "incoming_ports",
        ],
        &rows,
        None,
        terminal,
    );
    let mut prices = Vec::new();
    for price in &catalog.tracked_connection_prices {
        prices.push(if price.microusd_per_month == 0 {
            format!("{} included", grouped(price.tracked_connections))
        } else {
            format!(
                "{} {} a month",
                grouped(price.tracked_connections),
                pretty::dollars(price.microusd_per_month)
            )
        });
    }
    if !prices.is_empty() {
        let _ = write!(text, "\n\n  Tracked connections: {}", prices.join(", "));
    }
    text
}

fn list_text(views: &[VpnConnectionView], terminal: Terminal) -> String {
    let now = Utc::now();
    let rows: Vec<Value> = views
        .iter()
        .map(|view| {
            json!({
                "id": view.id,
                "name": view.name,
                "state": view.state,
                "tier": gateway_tier_words(view.tier),
                "location": view.location,
                "public_ipv4": view.public_ipv4,
                "incoming": if view.incoming_allowed { "allowed" } else { "blocked" },
                "last_handshake": view.last_handshake_at.map(|at| local_moment(at, now)),
            })
        })
        .collect();
    pretty::render_rows(
        &[
            "id",
            "name",
            "state",
            "tier",
            "location",
            "public_ipv4",
            "incoming",
            "last_handshake",
        ],
        &rows,
        None,
        terminal,
    )
}

/// A connection as `get` shows it for reading: its facts, its key's state
/// and its prices.
fn record(view: &VpnConnectionView) -> Map<String, Value> {
    let now = Utc::now();
    let mut record = Map::new();
    let mut put = |key: &str, value: Value| {
        if !value.is_null() {
            record.insert(key.to_owned(), value);
        }
    };
    put("id", json!(view.id));
    put("name", json!(view.name));
    put("state", json!(view.state));
    put("last_error", json!(view.last_error));
    put("tier", json!(gateway_tier_words(view.tier)));
    put(
        "location",
        json!(format!("{} ({})", view.location, view.location_name)),
    );
    put("public_ipv4", json!(view.public_ipv4));
    if !view.port_forwards.is_empty() {
        put(
            "port_forwards",
            json!(
                view.port_forwards
                    .iter()
                    .map(|forward| format!("{} → {}", forward.public_port, forward.device_port))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        );
    }
    put(
        "outgoing_ports",
        json!(view.outgoing_ports.map(|range| format!(
            "{}–{}",
            range.first_port,
            u32::from(range.first_port) + u32::from(range.ports).saturating_sub(1)
        ))),
    );
    put(
        "incoming",
        json!(if view.incoming_allowed {
            "allowed"
        } else {
            "blocked"
        }),
    );
    put(
        "tracked_connections",
        json!(grouped(view.tracked_connections)),
    );
    put("tunnel_address", json!(view.tunnel_address));
    put("endpoint", json!(view.endpoint));
    put("device_public_key", json!(view.device_public_key));
    put("key", json!(key_state(view)));
    put(
        "last_handshake",
        json!(view.last_handshake_at.map(|at| local_moment(at, now))),
    );
    put(
        "a_month",
        json!(view.base_microusd_per_month.map(pretty::dollars)),
    );
    put(
        "a_tib",
        json!(view.traffic_microusd_per_tib.map(pretty::dollars)),
    );
    put(
        "tracked_connections_a_month",
        json!(
            view.tracked_connections_microusd_per_month
                .filter(|price| *price > 0)
                .map(pretty::dollars)
        ),
    );
    if !view.pending_price_changes.is_empty() {
        put(
            "price_changes",
            json!(
                view.pending_price_changes
                    .iter()
                    .map(|change| format!(
                        "{} {} from {}",
                        price_component_words(&change.component),
                        pretty::dollars(change.microusd),
                        change.effective_at.format("%Y-%m-%d")
                    ))
                    .collect::<Vec<_>>()
            ),
        );
    }
    put("created_at", json!(local_moment(view.created_at, now)));
    record
}

/// Where the device's key is: taken by the gateway, waiting for it, or
/// refused.
fn key_state(view: &VpnConnectionView) -> Option<String> {
    if let Some(reason) = &view.refused_reason {
        return Some(format!("refused: {reason}"));
    }
    match (view.key_revision, view.applied_key_revision) {
        (Some(wanted), Some(applied)) if applied >= wanted => Some("applied".to_owned()),
        (Some(_), _) => Some("waiting for the gateway".to_owned()),
        (None, _) => None,
    }
}

/// A price change's component as people say it.
fn price_component_words(component: &str) -> String {
    match component {
        "gateway_base" => "a month".to_owned(),
        "gateway_traffic" => "a TiB".to_owned(),
        "tracked" => "tracked connections a month".to_owned(),
        other => escape_control(other).into_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{Received, canned_server, request_lines};
    use std::fs;

    /// RFC 7748 section 6.1: Alice's private key and its public key.
    #[test]
    fn the_public_key_is_rfc_7748_s() {
        let private: [u8; 32] =
            hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let key = DeviceKey::from_private(Zeroizing::new(private));
        assert_eq!(
            key.public,
            hex::<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
    }

    fn hex<const N: usize>(text: &str) -> [u8; N] {
        let bytes: Vec<u8> = (0..text.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
            .collect();
        bytes.try_into().unwrap()
    }

    /// A made key is clamped as `wg genkey`'s are.
    #[test]
    fn a_made_key_is_clamped() {
        let key = DeviceKey::generate();
        assert_eq!(key.private[0] & 7, 0);
        assert_eq!(key.private[31] & 0xc0, 0x40);
    }

    const GATEWAY_KEY: &str = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";

    fn view(id: Uuid, public_key: &str, state: &str) -> Value {
        json!({
            "id": id,
            "name": "home",
            "tier": "shared_ip",
            "location": "de-frankfurt",
            "location_name": "Frankfurt",
            "state": state,
            "created_at": "2026-11-13T10:00:00Z",
            "device_public_key": public_key,
            "tracked_connections": 4096,
            "incoming_allowed": false,
            "tunnel_address": "10.200.0.2",
            "public_ipv4": "203.0.113.7",
            "endpoint": "203.0.113.7:51820",
            "gateway_public_key": GATEWAY_KEY,
            "key_revision": 1,
            "applied_key_revision": 1,
        })
    }

    fn command(url: &str, seed: &Path, arguments: &[&str]) -> Cli {
        let mut line = vec![
            "ghost",
            "--api-url",
            url,
            "--seed-file",
            seed.to_str().unwrap(),
        ];
        line.extend_from_slice(arguments);
        <Cli as clap::Parser>::try_parse_from(line).unwrap()
    }

    fn bodies(received: &Received) -> Vec<Value> {
        received
            .lock()
            .unwrap()
            .iter()
            .map(|(_, body)| serde_json::from_slice(body).unwrap_or(Value::Null))
            .collect()
    }

    fn expected_config(private: &str) -> String {
        format!(
            "[Interface]\nPrivateKey = {private}\nAddress = 10.200.0.2/32\nDNS = 1.1.1.1, 9.9.9.9\nMTU = 1420\n\n[Peer]\nPublicKey = {GATEWAY_KEY}\nEndpoint = 203.0.113.7:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n"
        )
    }

    /// The private key in a written configuration.
    fn written_private_key(config: &str) -> String {
        config
            .lines()
            .find_map(|line| line.strip_prefix("PrivateKey = "))
            .unwrap()
            .to_owned()
    }

    /// `create --out` sends the public key of the private key it writes,
    /// and nothing of the private key; it waits until the connection is
    /// ready, writes the configuration `0600`, and never overwrites a file
    /// without --force.
    #[tokio::test]
    async fn create_with_out_writes_the_config_of_the_key_it_sent() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let out = directory.path().join("home.conf");
        let id = Uuid::now_v7();
        // The key is made by ghost: the canned answers carry a placeholder
        // that the test checks against the sent key below.
        let provisioning = view(id, GATEWAY_KEY, "provisioning");
        let ready = view(id, GATEWAY_KEY, "ready");
        let (url, received) = canned_server(vec![
            (200, provisioning.to_string()),
            (200, ready.to_string()),
        ])
        .await;
        let cli = command(
            &url,
            &seed,
            &[
                "vpn",
                "create",
                "--location",
                "de-frankfurt",
                "--tier",
                "shared-ip",
                "--out",
                out.to_str().unwrap(),
                "--poll-seconds",
                "1",
            ],
        );
        let output = crate::execute(&cli).await.unwrap();
        assert_eq!(output["config_file"], json!(out));
        assert_eq!(
            request_lines(&received),
            [
                "POST /api/mut/v1/vpn/connections",
                &format!("GET /v1/vpn/connections/{id}")
            ]
        );
        let config = fs::read_to_string(&out).unwrap();
        let private = written_private_key(&config);
        assert_eq!(config, expected_config(&private));
        let decoded: [u8; 32] = STANDARD.decode(&private).unwrap().try_into().unwrap();
        let key = DeviceKey::from_private(Zeroizing::new(decoded));
        let sent = &bodies(&received)[0];
        assert_eq!(
            sent,
            &json!({
                "tier": "shared_ip",
                "location": "de-frankfurt",
                "device_public_key": key.public_base64(),
            })
        );
        // Nothing of the private key was sent or is in the result.
        for (_, body) in received.lock().unwrap().iter() {
            assert!(!String::from_utf8_lossy(body).contains(&private));
        }
        assert!(!output.to_string().contains(&private));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&out).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // The file exists: a second creation sends nothing without --force.
        let (url, received) = canned_server(Vec::new()).await;
        let again = command(
            &url,
            &seed,
            &[
                "vpn",
                "create",
                "--location",
                "de-frankfurt",
                "--tier",
                "shared-ip",
                "--out",
                out.to_str().unwrap(),
            ],
        );
        let error = crate::execute(&again).await.unwrap_err();
        assert!(error.to_string().contains("--force"), "{error:#}");
        assert!(request_lines(&received).is_empty());
        assert_eq!(fs::read_to_string(&out).unwrap(), config);
    }

    /// The arguments of a parsed `ghost vpn create`.
    fn create_args(cli: &Cli) -> &CreateArgs {
        let crate::Command::Vpn {
            command: VpnCommand::Create(args),
        } = &cli.command
        else {
            panic!("not `ghost vpn create`");
        };
        args
    }

    /// The arguments of a parsed `ghost vpn new-config`.
    fn new_config_args(cli: &Cli) -> &NewConfigArgs {
        let crate::Command::Vpn {
            command: VpnCommand::NewConfig(args),
        } = &cli.command
        else {
            panic!("not `ghost vpn new-config`");
        };
        args
    }

    /// The temporary files left in `directory`.
    fn temporaries(directory: &Path) -> Vec<PathBuf> {
        fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "tmp"))
            .collect()
    }

    fn create_line<'a>(out: &'a str, poll_seconds: &'a str) -> Vec<&'a str> {
        vec![
            "vpn",
            "create",
            "--location",
            "de-frankfurt",
            "--tier",
            "shared-bandwidth",
            "--out",
            out,
            "--poll-seconds",
            poll_seconds,
        ]
    }

    /// An --out directory that does not exist is refused before anything
    /// is sent: no connection is made, and no setup fee charged, for a key
    /// that could not be written.
    #[tokio::test]
    async fn create_refuses_an_out_directory_that_takes_no_file_before_sending() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let out = directory.path().join("missing").join("home.conf");
        let (url, received) = canned_server(vec![(
            200,
            view(Uuid::now_v7(), GATEWAY_KEY, "provisioning").to_string(),
        )])
        .await;
        let cli = command(&url, &seed, &create_line(out.to_str().unwrap(), "1"));
        let error = crate::execute(&cli).await.unwrap_err();
        assert!(
            format!("{error:#}").contains("create temporary VPN configuration file"),
            "{error:#}"
        );
        assert!(request_lines(&received).is_empty());
    }

    /// A read that fails as a backend deploy makes it fail (503) is read
    /// again, and the wait goes on to the configuration.
    #[tokio::test]
    async fn a_failing_read_does_not_end_the_wait() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let out = directory.path().join("home.conf");
        let id = Uuid::now_v7();
        let (url, received) = canned_server(vec![
            (200, view(id, GATEWAY_KEY, "provisioning").to_string()),
            (
                503,
                json!({"code": "unavailable", "message": "restarting"}).to_string(),
            ),
            (200, view(id, GATEWAY_KEY, "ready").to_string()),
        ])
        .await;
        let cli = command(&url, &seed, &create_line(out.to_str().unwrap(), "1"));
        let output = crate::execute(&cli).await.unwrap();
        assert_eq!(output["config_file"], json!(out));
        assert_eq!(request_lines(&received).len(), 3);
        let config = fs::read_to_string(&out).unwrap();
        assert_eq!(config, expected_config(&written_private_key(&config)));
        assert!(temporaries(directory.path()).is_empty());
    }

    /// A wait stopped after the connection was created (here by Ctrl-C)
    /// keeps the key ghost sent alone in the --out file, `0600`, as `wg
    /// genkey` writes one, and `ghost vpn config` makes the configuration
    /// from it.
    #[tokio::test]
    async fn an_interrupted_wait_keeps_the_key_it_sent() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let out = directory.path().join("home.conf");
        let out_text = out.to_str().unwrap();
        let id = Uuid::now_v7();
        let (url, received) = canned_server(vec![(
            200,
            view(id, GATEWAY_KEY, "provisioning").to_string(),
        )])
        .await;
        let cli = command(&url, &seed, &create_line(out_text, "5"));
        let api = crate::api_client(&cli).unwrap();
        let interrupt = tokio::time::sleep(Duration::from_millis(200));
        let error = create(&cli, &api, create_args(&cli), false, interrupt)
            .await
            .unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("interrupted"), "{text}");
        assert!(
            text.contains(&format!(
                "ghost vpn config {id} --private-key-file {out_text} --out {out_text} --force"
            )),
            "{text}"
        );
        let key = DeviceKey::read(&out).unwrap();
        let private = key.private_base64();
        assert_eq!(
            fs::read_to_string(&out).unwrap(),
            format!("{}\n", private.as_str())
        );
        assert_eq!(
            bodies(&received)[0]["device_public_key"],
            key.public_base64()
        );
        assert!(!text.contains(private.as_str()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::metadata(&out).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(temporaries(directory.path()).is_empty());
        // The line it gives writes the configuration from the kept key.
        let (url, _) = canned_server(vec![(
            200,
            view(id, &key.public_base64(), "ready").to_string(),
        )])
        .await;
        let id_text = id.to_string();
        let config = command(
            &url,
            &seed,
            &[
                "vpn",
                "config",
                &id_text,
                "--private-key-file",
                out_text,
                "--out",
                out_text,
                "--force",
            ],
        );
        crate::execute(&config).await.unwrap();
        assert_eq!(
            fs::read_to_string(&out).unwrap(),
            expected_config(private.as_str())
        );
    }

    /// A creation the backend may have made without its answer reaching
    /// ghost (a 502 from the proxy in front) keeps the key it sent.
    #[tokio::test]
    async fn an_unanswered_creation_keeps_the_key_it_sent() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let out = directory.path().join("home.conf");
        let (url, received) = canned_server(vec![(502, "Bad Gateway".to_owned())]).await;
        let cli = command(&url, &seed, &create_line(out.to_str().unwrap(), "1"));
        let error = crate::execute(&cli).await.unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("may have been created"), "{text}");
        let key = DeviceKey::read(&out).unwrap();
        assert_eq!(
            bodies(&received)[0]["device_public_key"],
            key.public_base64()
        );
        assert!(temporaries(directory.path()).is_empty());
    }

    /// A connection that fails will never use its key: nothing is kept,
    /// and the error says the charges came back, not to give it a new key.
    #[tokio::test]
    async fn a_failed_connection_keeps_no_key() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let out = directory.path().join("home.conf");
        let id = Uuid::now_v7();
        let mut failed = view(id, GATEWAY_KEY, "failed");
        failed["last_error"] = json!("no gateway had room.");
        let (url, _) = canned_server(vec![
            (200, view(id, GATEWAY_KEY, "provisioning").to_string()),
            (200, failed.to_string()),
        ])
        .await;
        let cli = command(&url, &seed, &create_line(out.to_str().unwrap(), "1"));
        let error = crate::execute(&cli).await.unwrap_err();
        let text = format!("{error:#}");
        assert_eq!(
            text,
            format!(
                "VPN connection {id} failed: no gateway had room. Its charges were given back; to try again, create a new one."
            )
        );
        assert!(!out.exists());
        assert!(temporaries(directory.path()).is_empty());
    }

    /// `new-config --out` whose wait stops short (here by Ctrl-C) still
    /// writes the new configuration from the rotation's answer; a key the
    /// gateway refuses writes nothing, and the file that was there stays.
    #[tokio::test]
    async fn new_config_writes_the_config_when_the_wait_stops_and_none_when_refused() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let id = Uuid::now_v7();
        let id_text = id.to_string();
        let mut pending = view(id, GATEWAY_KEY, "ready");
        pending["key_revision"] = json!(2);
        let (url, received) = canned_server(vec![(200, pending.to_string())]).await;
        let out = directory.path().join("new.conf");
        let cli = command(
            &url,
            &seed,
            &[
                "vpn",
                "new-config",
                &id_text,
                "--out",
                out.to_str().unwrap(),
                "--poll-seconds",
                "5",
            ],
        );
        let api = crate::api_client(&cli).unwrap();
        let interrupt = tokio::time::sleep(Duration::from_millis(200));
        let error = new_config(&cli, &api, new_config_args(&cli), false, interrupt)
            .await
            .unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("The new configuration is in"), "{text}");
        assert!(text.contains(&format!("ghost vpn get {id}")), "{text}");
        let config = fs::read_to_string(&out).unwrap();
        let private = written_private_key(&config);
        assert_eq!(config, expected_config(&private));
        let decoded: [u8; 32] = STANDARD.decode(&private).unwrap().try_into().unwrap();
        let key = DeviceKey::from_private(Zeroizing::new(decoded));
        assert_eq!(
            bodies(&received)[0],
            json!({"public_key": key.public_base64()})
        );

        let kept = directory.path().join("home.conf");
        fs::write(&kept, "the config that works\n").unwrap();
        let mut refused = pending.clone();
        refused["refused_reason"] =
            json!("the gateway refused the device key: another peer has it");
        let (url, _) =
            canned_server(vec![(200, pending.to_string()), (200, refused.to_string())]).await;
        let cli = command(
            &url,
            &seed,
            &[
                "vpn",
                "new-config",
                &id_text,
                "--out",
                kept.to_str().unwrap(),
                "--force",
                "--poll-seconds",
                "1",
            ],
        );
        let error = crate::execute(&cli).await.unwrap_err();
        assert_eq!(
            format!("{error:#}"),
            format!(
                "the gateway refused the new key of VPN connection {id}: the gateway refused the device key: another peer has it"
            )
        );
        assert_eq!(
            fs::read_to_string(&kept).unwrap(),
            "the config that works\n"
        );
        assert!(temporaries(directory.path()).is_empty());
    }

    /// The wait for a new key ends at its limit as a wait that may still
    /// end well, so the new configuration is written.
    #[tokio::test]
    async fn a_new_key_wait_ends_at_its_limit() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let cli = command("http://127.0.0.1:9/", &seed, &["vpn", "list"]);
        let api = crate::api_client(&cli).unwrap();
        let mut pending = view(Uuid::now_v7(), GATEWAY_KEY, "ready");
        pending["key_revision"] = json!(2);
        let error = wait_until_applied(
            &api,
            serde_json::from_value(pending).unwrap(),
            Duration::from_secs(1),
            false,
            Duration::ZERO,
        )
        .await
        .unwrap_err();
        assert!(!key_unused(&error));
        assert!(
            error.to_string().contains("has not taken the new key"),
            "{error:#}"
        );
    }

    /// `--public-key` sends that key and writes no file; `dedicated-ip`
    /// is a gateway of the connection's own.
    #[tokio::test]
    async fn create_with_a_public_key_sends_that_key() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let id = Uuid::now_v7();
        let (url, received) = canned_server(vec![(
            200,
            view(id, GATEWAY_KEY, "provisioning").to_string(),
        )])
        .await;
        let cli = command(
            &url,
            &seed,
            &[
                "--json",
                "vpn",
                "create",
                "--location",
                "de-frankfurt",
                "--tier",
                "dedicated-ip",
                "--name",
                "laptop",
                "--tracked-connections",
                "16384",
                "--public-key",
                GATEWAY_KEY,
            ],
        );
        let output = crate::execute(&cli).await.unwrap();
        assert_eq!(output["id"], json!(id));
        assert_eq!(output["state"], "provisioning");
        assert_eq!(
            bodies(&received)[0],
            json!({
                "name": "laptop",
                "tier": "high_bandwidth",
                "location": "de-frankfurt",
                "device_public_key": GATEWAY_KEY,
                "tracked_connections": 16384,
            })
        );
        // The JSON is the connection as the API gave it.
        assert_eq!(
            crate::render_result(&cli, &output, Terminal::plain()),
            crate::render_output(&output, OutputFormat::Json, Terminal::plain())
        );
        // A private key's place takes no non-key, and --out and
        // --public-key are one or the other.
        for refused in [
            vec!["--public-key", "not-a-key"],
            vec!["--public-key", GATEWAY_KEY, "--out", "x.conf"],
            vec![],
            vec!["--public-key", GATEWAY_KEY, "--qr"],
            vec!["--public-key", GATEWAY_KEY, "--tracked-connections", "1000"],
        ] {
            let mut line = vec![
                "ghost",
                "vpn",
                "create",
                "--location",
                "x",
                "--tier",
                "shared-ip",
            ];
            line.extend_from_slice(&refused);
            assert!(
                <Cli as clap::Parser>::try_parse_from(line).is_err(),
                "{refused:?}"
            );
        }
    }

    /// `delete` without --yes sends nothing.
    #[tokio::test]
    async fn delete_without_yes_sends_nothing() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let (url, received) = canned_server(Vec::new()).await;
        let cli = command(&url, &seed, &["vpn", "delete", "home"]);
        let error = crate::execute(&cli).await.unwrap_err();
        assert!(error.to_string().contains("--yes"), "{error:#}");
        assert!(request_lines(&received).is_empty());
    }

    /// `config` builds the configuration from a private key file, to
    /// standard output or a file, and refuses a key that is not the
    /// connection's.
    #[tokio::test]
    async fn config_is_made_from_a_private_key_file() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let key = DeviceKey::generate();
        let private = key.private_base64();
        let key_file = directory.path().join("device.key");
        fs::write(&key_file, format!("{}\n", private.as_str())).unwrap();
        let id = Uuid::now_v7();
        let ready = view(id, &key.public_base64(), "ready");
        let (url, received) = canned_server(vec![
            (200, ready.to_string()),
            (200, ready.to_string()),
            (200, view(id, GATEWAY_KEY, "ready").to_string()),
        ])
        .await;
        let id_text = id.to_string();
        let printed = command(
            &url,
            &seed,
            &[
                "vpn",
                "config",
                &id_text,
                "--private-key-file",
                key_file.to_str().unwrap(),
            ],
        );
        let output = crate::execute(&printed).await.unwrap();
        let text = crate::render_result(&printed, &output, Terminal::plain());
        assert_eq!(format!("{text}\n"), expected_config(&private));
        let out = directory.path().join("device.conf");
        let written = command(
            &url,
            &seed,
            &[
                "vpn",
                "config",
                &id_text,
                "--private-key-file",
                key_file.to_str().unwrap(),
                "--out",
                out.to_str().unwrap(),
            ],
        );
        let output = crate::execute(&written).await.unwrap();
        assert_eq!(output, json!({"vpn_connection_id": id, "config_file": out}));
        assert_eq!(fs::read_to_string(&out).unwrap(), expected_config(&private));
        // Another connection's key is refused, and its text is in no error.
        let error = crate::execute(&printed).await.unwrap_err();
        assert!(error.to_string().contains("is not the key"), "{error:#}");
        assert!(!format!("{error:#}").contains(private.as_str()));
        assert_eq!(request_lines(&received).len(), 3);
    }

    /// `new-config --out` sends the new public key, waits until the
    /// gateway applied its revision, then writes the configuration.
    #[tokio::test]
    async fn new_config_waits_for_the_applied_revision() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let id = Uuid::now_v7();
        let mut pending = view(id, GATEWAY_KEY, "ready");
        pending["key_revision"] = json!(2);
        let mut applied = pending.clone();
        applied["applied_key_revision"] = json!(2);
        let (url, received) = canned_server(vec![
            (200, pending.to_string()),
            (200, pending.to_string()),
            (200, applied.to_string()),
        ])
        .await;
        let out = directory.path().join("new.conf");
        let id_text = id.to_string();
        let cli = command(
            &url,
            &seed,
            &[
                "vpn",
                "new-config",
                &id_text,
                "--out",
                out.to_str().unwrap(),
                "--poll-seconds",
                "1",
            ],
        );
        let output = crate::execute(&cli).await.unwrap();
        assert_eq!(output["applied_key_revision"], 2);
        assert_eq!(
            request_lines(&received),
            [
                format!("POST /api/mut/v1/vpn/connections/{id}/rotate-key"),
                format!("GET /v1/vpn/connections/{id}"),
                format!("GET /v1/vpn/connections/{id}"),
            ]
        );
        let config = fs::read_to_string(&out).unwrap();
        let private = written_private_key(&config);
        let decoded: [u8; 32] = STANDARD.decode(&private).unwrap().try_into().unwrap();
        let key = DeviceKey::from_private(Zeroizing::new(decoded));
        assert_eq!(
            bodies(&received)[0],
            json!({"public_key": key.public_base64()})
        );
        assert_eq!(config, expected_config(&private));
    }

    /// The readable and JSON forms of `list`, `get` and `catalog`.
    #[tokio::test]
    async fn list_get_and_catalog_read_and_print_as_json() {
        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let id = Uuid::now_v7();
        let catalog = json!({
            "enabled": true,
            "locations": [{"location": "de-frankfurt", "display_name": "Frankfurt", "country_code": "DE",
                           "tiers": [{"tier": "shared_ip", "room": true, "base_microusd_per_month": 1_000_000,
                                      "traffic_microusd_per_tib": 2_000_000, "incoming_ports": 20}]}],
            "tracked_connection_prices": [{"tracked_connections": 4096, "microusd_per_month": 0},
                                          {"tracked_connections": 16384, "microusd_per_month": 200_000}],
        });
        let (url, received) = canned_server(vec![
            (200, json!([view(id, GATEWAY_KEY, "ready")]).to_string()),
            (200, json!([view(id, GATEWAY_KEY, "ready")]).to_string()),
            (200, view(id, GATEWAY_KEY, "ready").to_string()),
            (200, catalog.to_string()),
            (200, catalog.to_string()),
        ])
        .await;
        let list = command(&url, &seed, &["vpn", "list"]);
        let output = crate::execute(&list).await.unwrap();
        let text = crate::render_result(&list, &output, Terminal::plain());
        assert!(text.contains("home") && text.contains("blocked"), "{text}");
        // A name is looked up in the list.
        let get = command(&url, &seed, &["--json", "vpn", "get", "home"]);
        let output = crate::execute(&get).await.unwrap();
        assert_eq!(output["id"], json!(id));
        let readable = readable(
            &VpnCommand::Get {
                connection: InstanceReference::Id(id),
            },
            &output,
            Terminal::plain(),
        )
        .unwrap();
        assert!(readable.contains("shared IP"), "{readable}");
        assert!(readable.contains("applied"), "{readable}");
        let catalog_cli = command(&url, &seed, &["vpn", "catalog"]);
        let output = crate::execute(&catalog_cli).await.unwrap();
        let text = crate::render_result(&catalog_cli, &output, Terminal::plain());
        assert!(
            text.contains("Frankfurt") && text.contains("$1.00"),
            "{text}"
        );
        assert!(
            text.contains("4,096 included, 16,384 $0.20 a month"),
            "{text}"
        );
        let json_cli = command(&url, &seed, &["--json", "vpn", "catalog"]);
        let output = crate::execute(&json_cli).await.unwrap();
        assert_eq!(output, catalog);
        assert_eq!(request_lines(&received).len(), 5);
        let closed: VpnCatalogView = serde_json::from_value(json!({"enabled": false})).unwrap();
        assert!(catalog_text(&closed, Terminal::plain()).contains("not offered yet"));
    }

    /// A gateway value that would add a line to the configuration is
    /// refused, and a tunnel address keeps a prefix it has.
    #[test]
    fn the_config_takes_only_well_formed_gateway_values() {
        let key = DeviceKey::generate();
        let id = Uuid::now_v7();
        let parsed = |value: Value| -> VpnConnectionView { serde_json::from_value(value).unwrap() };
        let mut bad = view(id, GATEWAY_KEY, "ready");
        bad["endpoint"] = json!("203.0.113.7:51820\nPostUp = touch /tmp/x");
        assert!(config_text(&key, &parsed(bad)).is_err());
        let mut bad = view(id, GATEWAY_KEY, "ready");
        bad["tunnel_address"] = json!("10.0.0.2\nDNS = 1.1.1.1");
        assert!(config_text(&key, &parsed(bad)).is_err());
        let mut bad = view(id, GATEWAY_KEY, "ready");
        bad["gateway_public_key"] = json!("short");
        assert!(config_text(&key, &parsed(bad)).is_err());
        let mut provisioning = view(id, GATEWAY_KEY, "provisioning");
        provisioning["endpoint"] = Value::Null;
        assert!(config_text(&key, &parsed(provisioning)).is_err());
        assert_eq!(
            tunnel_address("10.0.0.2/30").as_deref(),
            Some("10.0.0.2/30")
        );
        assert_eq!(tunnel_address("10.0.0.2").as_deref(), Some("10.0.0.2/32"));
        let config = config_text(&key, &parsed(view(id, GATEWAY_KEY, "ready"))).unwrap();
        // The one DNS line is the platform's own; no gateway value adds one.
        assert_eq!(config.matches("DNS").count(), 1);
        assert!(config.contains("\nDNS = 1.1.1.1, 9.9.9.9\n"));
    }

    /// A configuration renders as a QR code of half blocks, and --qr is
    /// refused with --json before anything is sent.
    #[tokio::test]
    async fn a_qr_code_renders() {
        let key = DeviceKey::generate();
        let id = Uuid::now_v7();
        let parsed: VpnConnectionView =
            serde_json::from_value(view(id, GATEWAY_KEY, "ready")).unwrap();
        let config = config_text(&key, &parsed).unwrap();
        let qr = qr_text(&config).unwrap();
        let lines: Vec<&str> = qr.lines().collect();
        assert!(lines.len() > 20, "{}", qr.as_str());
        assert!(qr.chars().any(|character| "▀▄█".contains(character)));
        assert!(!qr.contains(key.private_base64().as_str()));

        let directory = tempfile::tempdir().unwrap();
        let seed = directory.path().join("account.seed");
        keys::generate_seed(&seed).unwrap();
        let key_file = directory.path().join("device.key");
        fs::write(&key_file, key.private_base64().as_str()).unwrap();
        let (url, received) = canned_server(Vec::new()).await;
        let id_text = id.to_string();
        let cli = command(
            &url,
            &seed,
            &[
                "--json",
                "vpn",
                "config",
                &id_text,
                "--private-key-file",
                key_file.to_str().unwrap(),
                "--qr",
            ],
        );
        assert!(crate::execute(&cli).await.is_err());
        assert!(request_lines(&received).is_empty());
    }
}
