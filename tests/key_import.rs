//! `ghost key import` as the desktop app and scripts run it: the built
//! binary with the key on a standard input that is no terminal.

use std::{
    io::{Read as _, Write as _},
    net::TcpListener,
    path::Path,
    process::{Command, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use serde_json::Value;

/// The key every vector-free test here imports: 32 sevens.
const LINE: &str = "gigahost-account-seed-v1:BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";

/// A backend that answers every request, one connection at a time, as the
/// backend answers a key no account is registered for.
fn unregistered_backend() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let mut request = Vec::new();
            let mut chunk = [0_u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => request.extend_from_slice(&chunk[..read]),
                }
            }
            let body = r#"{"code":"account_not_activated","message":"no account is registered for this key yet"}"#;
            let _ = write!(
                stream,
                "HTTP/1.1 401 Unauthorized\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    url
}

/// A backend that reads every request and closes the connection without
/// an answer, as one that is cut off after the connect, and the number of
/// connections it took.
fn silent_backend() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let accepted = Arc::new(AtomicUsize::new(0));
    let count = accepted.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            count.fetch_add(1, Ordering::SeqCst);
            let mut request = [0_u8; 4096];
            let _ = stream.read(&mut request);
        }
    });
    (url, accepted)
}

fn import(seed: &Path, url: &str, input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ghost"))
        .args(["--json", "--api-url", url, "--seed-file"])
        .arg(seed)
        .args(["key", "import"])
        .env_remove("GHOST_SEED_FILE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

/// A pasted line, with a `\r\n` and spaces around it, piped in imports the
/// key, and the same key again is a no-op; neither prints the secret.
#[test]
fn a_piped_line_imports_the_key() {
    let directory = tempfile::tempdir().unwrap();
    let seed = directory.path().join("ghost").join("account.seed");
    let url = unregistered_backend();
    let secret = LINE.split_once(':').unwrap().1;
    for (input, result) in [
        (format!("  {LINE} \r\n"), "imported"),
        (format!("{LINE}\n"), "already_imported"),
    ] {
        let output = import(&seed, &url, input.as_bytes());
        let stdout = String::from_utf8(output.stdout).unwrap();
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(output.status.success(), "{stdout}{stderr}");
        let value: Value = serde_json::from_str(&stdout).unwrap();
        assert_eq!(value["result"], result, "{stdout}");
        assert_eq!(value["account"], Value::Null);
        assert!(
            value["account_note"]
                .as_str()
                .unwrap()
                .starts_with("this key has no account yet"),
            "{stdout}"
        );
        assert!(value.get("note").is_none(), "{stdout}");
        assert!(!stdout.contains(secret) && !stderr.contains(secret));
    }
    assert_eq!(std::fs::read_to_string(&seed).unwrap(), format!("{LINE}\n"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&seed).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

/// The account check after an import is asked once, not again after each
/// of the reads' pauses: the desktop gives the whole import 90 s, and
/// three of the 30 s timeouts would outlast it, after the key is in place.
/// A backend that never answers is a note, not a failure.
#[test]
fn the_account_check_is_asked_once() {
    let directory = tempfile::tempdir().unwrap();
    let seed = directory.path().join("account.seed");
    let (url, accepted) = silent_backend();
    let output = import(&seed, &url, format!("{LINE}\n").as_bytes());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(output.status.success(), "{stdout}{stderr}");
    let value: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value["result"], "imported", "{stdout}");
    assert_eq!(value["account"], Value::Null);
    assert!(
        value["account_note"]
            .as_str()
            .unwrap()
            .starts_with("the account could not be checked: "),
        "{stdout}"
    );
    assert!(!stderr.contains("trying again"), "{stderr}");
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
    assert_eq!(std::fs::read_to_string(&seed).unwrap(), format!("{LINE}\n"));
}

/// On a terminal, a paste of several lines is read up to its first line,
/// and the rest is dropped when the echo is turned back on: left in the
/// terminal's input, the shell would read it when ghost ends and run the
/// key line as a command. Here the first line is no key and is refused.
#[cfg(target_os = "linux")]
#[test]
fn the_rest_of_a_paste_is_dropped_from_the_terminal() {
    use rustix::{
        fs::{Mode, OFlags},
        pty::{OpenptFlags, grantpt, openpt, ptsname, unlockpt},
        termios::{LocalModes, tcgetattr},
    };

    let pty = openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC).unwrap();
    grantpt(&pty).unwrap();
    unlockpt(&pty).unwrap();
    let terminal = rustix::fs::open(
        ptsname(&pty, Vec::new()).unwrap().as_c_str(),
        OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .unwrap();
    let directory = tempfile::tempdir().unwrap();
    let seed = directory.path().join("account.seed");
    let mut child = Command::new(env!("CARGO_BIN_EXE_ghost"))
        .args(["--json", "--api-url", "http://127.0.0.1:9/", "--seed-file"])
        .arg(&seed)
        .args(["key", "import"])
        .env_remove("GHOST_SEED_FILE")
        .stdin(Stdio::from(terminal.try_clone().unwrap()))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // The paste comes after the prompt, once the echo is off.
    let mut stderr = child.stderr.take().unwrap();
    let mut prompt = Vec::new();
    let mut chunk = [0_u8; 256];
    while !prompt.ends_with(b"(input hidden): ") {
        let read = stderr.read(&mut chunk).unwrap();
        assert!(read > 0, "{}", String::from_utf8_lossy(&prompt));
        prompt.extend_from_slice(&chunk[..read]);
    }
    rustix::io::write(&pty, format!("not the key\n{LINE}\n").as_bytes()).unwrap();
    let output = child.wait_with_output().unwrap();
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(!output.status.success());
    let message = value["error"]["message"].as_str().unwrap();
    assert!(
        message.starts_with("account key has an unsupported format"),
        "{message}"
    );
    assert_eq!(rustix::io::ioctl_fionread(&terminal).unwrap(), 0);
    assert!(
        tcgetattr(&terminal)
            .unwrap()
            .local_modes
            .contains(LocalModes::ECHO)
    );
    assert!(!seed.exists());
}

/// A malformed key piped in is refused with the seed file's words, and
/// nothing is written.
#[test]
fn a_malformed_piped_key_writes_nothing() {
    let directory = tempfile::tempdir().unwrap();
    let seed = directory.path().join("ghost").join("account.seed");
    let output = import(
        &seed,
        "http://127.0.0.1:9/",
        b"gigahost-account-seed-v1:c2hvcnQ\n",
    );
    assert!(!output.status.success());
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    let message = value["error"]["message"].as_str().unwrap();
    assert!(
        message.starts_with("account key must encode exactly 32 bytes"),
        "{message}"
    );
    assert!(!seed.parent().unwrap().exists());
}
