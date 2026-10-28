//! `ghost x` and `ghost mcp` as installed clients run them: the built
//! binary against a real ghostd on the target `local`. Ignored without a
//! ghostd: run them with
//! `GHOSTD_BIN=/path/to/ghostd cargo test -p ghost -- --ignored ghostd`.
#![cfg(unix)]

use std::{
    io::{BufRead as _, BufReader, Write as _},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use serde_json::{Value, json};

/// A ghostd of its own: its state and socket in a temporary directory,
/// stopped at the end.
struct Daemon {
    directory: tempfile::TempDir,
    program: PathBuf,
}

impl Daemon {
    fn start() -> Self {
        let program = std::env::var_os("GHOSTD_BIN")
            .map(PathBuf::from)
            .expect("these tests need GHOSTD_BIN, the ghostd binary to test against");
        // A short path: the socket's must fit in sun_path.
        let directory = tempfile::Builder::new()
            .prefix("gx")
            .tempdir_in("/tmp")
            .unwrap();
        Self { directory, program }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }

    /// `ghost ARGS` with this ghostd as `local`.
    fn ghost(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ghost"));
        command
            .args(args)
            .env("GHOSTD_BIN", &self.program)
            .env("GHOSTD_STATE_DIR", self.path("s"))
            .env("GHOSTD_RUNTIME_DIR", self.path("r"))
            .env("GHOSTD_CONFIG", self.path("config.toml"))
            .env("XDG_CACHE_HOME", self.path("cache"))
            .env("XDG_RUNTIME_DIR", self.path("run"))
            .env("XDG_CONFIG_HOME", self.path("config"))
            .env("NO_COLOR", "1");
        command
    }

    fn run(&self, args: &[&str]) -> Output {
        self.ghost(args).stdin(Stdio::null()).output().unwrap()
    }
}

impl Daemon {
    /// Stops the daemon and removes its state, as a reinstalled machine's:
    /// the next connection starts one with a new host ID.
    fn wipe(&self) {
        let _ = Command::new(&self.program)
            .arg("stop")
            .env("GHOSTD_STATE_DIR", self.path("s"))
            .env("GHOSTD_RUNTIME_DIR", self.path("r"))
            .output();
        std::fs::remove_dir_all(self.path("s")).unwrap();
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = Command::new(&self.program)
            .arg("stop")
            .env("GHOSTD_STATE_DIR", self.path("s"))
            .env("GHOSTD_RUNTIME_DIR", self.path("r"))
            .output();
    }
}

/// A digest to compare large outputs by, without printing them.
fn digest(data: &[u8]) -> String {
    use sha2::Digest as _;
    format!("{:x}", sha2::Sha256::digest(data))
}

fn random_file(path: &Path, size: usize) -> Vec<u8> {
    let mut data = vec![0u8; size];
    let mut state = 0x2545_f491_4f6c_dd1d_u64;
    for chunk in data.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
    std::fs::write(path, &data).unwrap();
    data
}

#[test]
#[ignore = "needs GHOSTD_BIN"]
fn ghostd_x_passes_hostile_arguments_byte_for_byte() {
    let daemon = Daemon::start();
    let hostile = [
        "a b",
        "'single'",
        "\"double\"",
        "$(id)",
        "`id`",
        "; rm -rf /tmp/nothing",
        "back\\slash",
        "new\nline",
        "*",
        "-n",
        "",
        "ünïcödé",
    ];
    let mut args = vec!["x", "local", "--", "printf", "%s\\0"];
    args.extend(hostile);
    let output = daemon.run(&args);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let mut expected = Vec::new();
    for argument in hostile {
        expected.extend_from_slice(argument.as_bytes());
        expected.push(0);
    }
    assert_eq!(output.stdout, expected);
    assert!(output.stderr.is_empty(), "{output:?}");
}

#[test]
#[ignore = "needs GHOSTD_BIN"]
fn ghostd_x_exits_with_the_program_s_code() {
    let daemon = Daemon::start();
    let output = daemon.run(&[
        "x",
        "local",
        "--",
        "sh",
        "-c",
        "echo out; echo err >&2; exit 3",
    ]);
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(output.stdout, b"out\n");
    assert_eq!(output.stderr, b"err\n");
    let output = daemon.run(&["x", "local", "--", "sh", "-c", "kill -TERM $$"]);
    assert_eq!(output.status.code(), Some(143));
    let output = daemon.run(&["x", "local", "--timeout", "1", "--", "sleep", "10"]);
    assert_eq!(output.status.code(), Some(124));
    assert!(String::from_utf8_lossy(&output.stderr).contains("timed out"));
    let output = daemon.run(&["x", "local", "--", "no-such-program-here"]);
    assert_eq!(output.status.code(), Some(127));
    // ghost's own failure.
    let output = daemon.run(&["x", "ssh://-oProxyCommand=x", "--", "true"]);
    assert_ne!(output.status.code(), Some(0));
    let output = Command::new(env!("CARGO_BIN_EXE_ghost"))
        .args(["x", "local", "--", "true"])
        .env("GHOSTD_BIN", daemon.path("missing-ghostd"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(255));
    assert!(String::from_utf8_lossy(&output.stderr).contains("ghostd is not installed on local"));
}

#[test]
#[ignore = "needs GHOSTD_BIN"]
fn ghostd_x_prints_output_beyond_the_cap_in_full() {
    let daemon = Daemon::start();
    let file = daemon.path("blob");
    let data = random_file(&file, 3 * 1024 * 1024 + 17);
    let output = daemon.run(&["x", "local", "--", "cat", file.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout.len(), data.len());
    assert_eq!(
        digest(&output.stdout),
        digest(&data),
        "stdout differs from the file"
    );
    // The same on stderr.
    let output = daemon.run(&[
        "x",
        "local",
        "--",
        "sh",
        "-c",
        "cat \"$0\" >&2",
        file.to_str().unwrap(),
    ]);
    assert_eq!(
        digest(&output.stderr),
        digest(&data),
        "stderr differs from the file"
    );
}

#[test]
#[ignore = "needs GHOSTD_BIN"]
fn ghostd_x_gives_stdin_scripts_and_json() {
    let daemon = Daemon::start();
    let mut child = daemon
        .ghost(&["x", "local", "--stdin", "--", "tr", "a-z", "A-Z"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"hello\n").unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.stdout, b"HELLO\n");
    let input = daemon.path("input");
    std::fs::write(&input, "from a file").unwrap();
    let output = daemon.run(&[
        "x",
        "local",
        "--stdin-file",
        input.to_str().unwrap(),
        "--",
        "cat",
    ]);
    assert_eq!(output.stdout, b"from a file");
    let script = daemon.path("script.sh");
    std::fs::write(&script, "#!/bin/sh\necho \"$# args: $1|$2\"\n").unwrap();
    let output = daemon.run(&[
        "x",
        "local",
        "--script",
        script.to_str().unwrap(),
        "--",
        "a b",
        "$c",
    ]);
    assert_eq!(output.stdout, b"2 args: a b|$c\n");
    let output = daemon.run(&[
        "x",
        "local",
        "--env",
        "GREETING=hi there",
        "--cwd",
        "/",
        "--",
        "sh",
        "-c",
        "echo \"$GREETING\"; pwd",
    ]);
    assert_eq!(output.stdout, b"hi there\n/\n");
    let output = daemon.run(&["--json", "x", "local", "--", "printf", "\\377"]);
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["exit_code"], 0);
    assert_eq!(result["stdout_base64"], "/w==");
    assert!(result.get("stdout").is_none());
    let output = daemon.run(&["x", "local", "--detach", "--", "sleep", "30"]);
    let job_id = String::from_utf8(output.stdout).unwrap().trim().to_owned();
    assert!(job_id.starts_with('j'), "{job_id}");
    let output = daemon.run(&["--json", "ghostd", "job", "stop", "local", &job_id]);
    let stopped: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(stopped["finished"], true);
}

#[test]
#[ignore = "needs GHOSTD_BIN"]
fn ghostd_commands_copy_files_and_follow_jobs() {
    let daemon = Daemon::start();
    let local = daemon.path("up");
    let data = random_file(&local, 2 * 1024 * 1024 + 3);
    let remote = daemon.path("remote/copy");
    let output = daemon.run(&[
        "--json",
        "ghostd",
        "put",
        "local",
        local.to_str().unwrap(),
        remote.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(digest(&std::fs::read(&remote).unwrap()), digest(&data));
    let back = daemon.path("back");
    let output = daemon.run(&[
        "ghostd",
        "get",
        "local",
        remote.to_str().unwrap(),
        back.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert_eq!(digest(&std::fs::read(&back).unwrap()), digest(&data));
    let output = daemon.run(&[
        "x",
        "local",
        "--detach",
        "--",
        "sh",
        "-c",
        "for i in 1 2 3; do echo line $i; sleep 0.2; done; echo bye >&2",
    ]);
    let job_id = String::from_utf8(output.stdout).unwrap().trim().to_owned();
    let output = daemon.run(&["ghostd", "job", "logs", "local", &job_id, "--follow"]);
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(output.stdout, b"line 1\nline 2\nline 3\n");
    assert_eq!(output.stderr, b"bye\n");
    let output = daemon.run(&["--json", "ghostd", "job", "wait", "local", &job_id]);
    let waited: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(waited["exit_code"], 0);
    let output = daemon.run(&["--json", "ghostd", "status", "local"]);
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(status["protocol_version"], 2);
    assert_eq!(status["host_check"], true);
}

/// `ghost mcp` as a child process: stdout carries only JSON-RPC.
#[test]
#[ignore = "needs GHOSTD_BIN"]
fn ghostd_mcp_child_speaks_only_json_rpc_on_stdout() {
    let daemon = Daemon::start();
    let mut child = daemon
        .ghost(&["mcp"])
        .current_dir(daemon.directory.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
    let mut send = |message: Value| {
        let mut line = serde_json::to_vec(&message).unwrap();
        line.push(b'\n');
        stdin.write_all(&line).unwrap();
        stdin.flush().unwrap();
    };
    send(
        json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "test", "version": "1"}}}),
    );
    let answer: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    assert_eq!(answer["id"], 1);
    send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
    send(
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {
        "name": "ghostd_exec",
        "arguments": {"target": "local", "argv": ["echo", "over stdio"], "output_file": "out.txt"}}}),
    );
    let answer: Value = serde_json::from_str(&lines.next().unwrap().unwrap()).unwrap();
    assert_eq!(answer["id"], 2, "{answer}");
    assert_eq!(
        answer["result"]["structuredContent"]["stdout"],
        "over stdio\n"
    );
    // output_file is relative to the server's working directory.
    assert_eq!(
        std::fs::read_to_string(daemon.path("out.txt")).unwrap(),
        "over stdio\n"
    );
    drop(stdin);
    let status = child.wait().unwrap();
    assert!(status.success());
    // Nothing but JSON-RPC came on stdout.
    for line in lines {
        let line = line.unwrap();
        let message: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(message["jsonrpc"], "2.0");
    }
}

/// `ghost x local` learns local's host ID and names it with every request:
/// after the ghostd state was wiped (a new host ID), it refuses with both
/// IDs and runs nothing, until `ghost ghostd forget local`.
#[test]
#[ignore = "needs GHOSTD_BIN"]
fn ghostd_x_refuses_a_new_host_id_until_forgotten() {
    let daemon = Daemon::start();
    let output = daemon.run(&["x", "local", "--", "true"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let cache = std::fs::read_to_string(daemon.path("cache/ghost/ghostd-targets-v2.json")).unwrap();
    assert!(cache.contains("\"local\""), "{cache}");
    // An older ghost's file, which it would write back without host IDs.
    assert!(!daemon.path("cache/ghost/ghostd-targets.json").exists());
    let output = daemon.run(&["--json", "ghostd", "status", "local"]);
    let status: Value = serde_json::from_slice(&output.stdout).unwrap();
    let before = status["host_id"].as_str().unwrap().to_owned();
    assert!(cache.contains(&before));
    daemon.wipe();
    let marker = daemon.path("marker");
    let touch = ["x", "local", "--", "touch", marker.to_str().unwrap()];
    let output = daemon.run(&touch);
    assert_eq!(output.status.code(), Some(255), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(&before), "{stderr}");
    assert!(stderr.contains("ghost ghostd forget local"), "{stderr}");
    assert!(!marker.exists(), "the refused command ran");
    let output = daemon.run(&["--json", "ghostd", "forget", "local"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let forgot: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(forgot["forgotten"]["hosts"], 1);
    let output = daemon.run(&touch);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(marker.exists());
}

/// `ghost ghostd wait` exits 0 when the condition held and 1 at its
/// timeout; `state` and the session commands answer.
#[test]
#[ignore = "needs GHOSTD_BIN"]
fn ghostd_commands_wait_read_sessions_and_the_state() {
    let daemon = Daemon::start();
    let file = daemon.path("ready");
    let wait = [
        "ghostd",
        "wait",
        "local",
        "--file",
        file.to_str().unwrap(),
        "--timeout",
        "1",
    ];
    let output = daemon.run(&wait);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("not met"));
    std::fs::write(&file, "ok").unwrap();
    let output = daemon.run(&wait);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let output = daemon.run(&["--json", "ghostd", "state", "local"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let state: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(state["cpus"].as_u64().unwrap() > 0);
    let output = daemon.run(&["ghostd", "state", "local"]);
    assert!(String::from_utf8_lossy(&output.stdout).contains("memory"));
    let output = daemon.run(&["--json", "ghostd", "session", "start", "local", "--", "sh"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let started: Value = serde_json::from_slice(&output.stdout).unwrap();
    let id = started["session_id"].as_str().unwrap().to_owned();
    let output = daemon.run(&[
        "ghostd",
        "session",
        "send",
        "local",
        &id,
        "--text",
        "echo $((6*7))",
        "--key",
        "Enter",
    ]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let output = daemon.run(&[
        "ghostd", "session", "read", "local", &id, "--until", "(?m)^42$",
    ]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout)
            .lines()
            .any(|line| line == "42")
    );
    let output = daemon.run(&["--json", "ghostd", "session", "list", "local"]);
    let listed: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(listed.as_array().unwrap().len(), 1);
    let output = daemon.run(&["ghostd", "session", "close", "local", &id]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
}
