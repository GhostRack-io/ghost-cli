//! Process contract for command extensions.
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::OnceLock,
};

fn fixture() -> &'static Path {
    static FIXTURE: OnceLock<PathBuf> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let directory=tempfile::tempdir().unwrap().keep();
        let source=directory.join("helper.rs");
        fs::write(&source,r#"
use std::io::{Read,Write};
fn main() {
 let mode=std::env::var("TEST_HELPER_MODE").unwrap_or_default();
 if mode=="streams" { let mut input=Vec::new(); std::io::stdin().read_to_end(&mut input).unwrap(); std::io::stdout().write_all(&input).unwrap(); eprint!("helper stderr"); }
 else if mode=="cwd" { std::io::stdout().write_all(&std::fs::read("cwd-marker").unwrap()).unwrap(); }
 else if mode=="signal" { #[cfg(unix)] { std::process::Command::new("/bin/kill").args(["-TERM",&std::process::id().to_string()]).status().unwrap(); } }
 else { for argument in std::env::args_os().skip(1) { #[cfg(unix)] {use std::os::unix::ffi::OsStrExt; for byte in argument.as_bytes() {print!("{byte:02x}");}} #[cfg(windows)] {use std::os::windows::ffi::OsStrExt; for unit in argument.encode_wide() {print!("{unit:04x}");}} println!(); } }
 if let Ok(code)=std::env::var("TEST_HELPER_EXIT") {std::process::exit(code.parse().unwrap());}
}
"#).unwrap();
        let output=directory.join(helper_name());
        assert!(Command::new("rustc").arg("--edition=2024").arg(&source).arg("-o").arg(&output).status().unwrap().success());
        output
    })
}
fn helper_name() -> &'static str {
    if cfg!(windows) {
        "ghost-example.exe"
    } else {
        "ghost-example"
    }
}
struct Sandbox {
    directory: tempfile::TempDir,
    binary: PathBuf,
}
impl Sandbox {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory
            .path()
            .join(if cfg!(windows) { "ghost.exe" } else { "ghost" });
        fs::copy(env!("CARGO_BIN_EXE_ghost"), &binary).unwrap();
        Self { directory, binary }
    }
    fn helper(&self) {
        fs::copy(fixture(), self.directory.path().join(helper_name())).unwrap();
    }
    fn command(&self) -> Command {
        let mut command = Command::new(&self.binary);
        command
            .env("PATH", self.directory.path())
            .env_remove("GHOST_API_URL")
            .env_remove("GHOST_SEED_FILE")
            .env_remove("GHOST_RECOVERY_SEED_FILE")
            .env_remove("_GHOST_EXTENSION_DISPATCHED");
        command
    }
    fn run(&self, args: &[&str]) -> Output {
        self.command().args(args).output().unwrap()
    }
}
fn encoded(args: &[OsString]) -> Vec<u8> {
    use std::fmt::Write as _;
    let mut text = String::new();
    for arg in args {
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt as _;
            for byte in arg.as_os_str().as_bytes() {
                write!(text, "{byte:02x}").unwrap();
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStrExt as _;
            for unit in arg.encode_wide() {
                write!(text, "{unit:04x}").unwrap();
            }
        }
        text.push('\n');
    }
    text.into_bytes()
}
#[test]
fn missing_extension_keeps_the_ordinary_parser_error() {
    let sandbox = Sandbox::new();
    let output = sandbox.run(&["--json", "example", "--help"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unrecognized subcommand"));
}

#[test]
fn opaque_arguments_and_globals_keep_their_order() {
    let sandbox = Sandbox::new();
    sandbox.helper();
    for args in [
        vec![
            "--api-url",
            "example",
            "example",
            "opaque-action",
            "--json",
            "a b;$(true)",
        ],
        vec![
            "--seed-file=example",
            "--compact",
            "example",
            "--seed-file",
            "a b",
            "--",
            "example",
        ],
        vec!["example", "--version"],
        vec!["--api-url=http://127.0.0.1/", "example", "--help"],
    ] {
        let output = sandbox.run(&args);
        assert!(output.status.success(), "{output:?}");
        let index = args
            .iter()
            .position(|arg| *arg == "example" && args.first() != Some(&"--api-url"))
            .unwrap_or(2);
        let forwarded: Vec<OsString> = args
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != index)
            .map(|(_, arg)| OsString::from(arg))
            .collect();
        assert_eq!(output.stdout, encoded(&forwarded), "{args:?}");
    }
}
#[cfg(unix)]
#[test]
fn non_utf8_paths_are_opaque() {
    use std::os::unix::ffi::OsStringExt as _;
    let sandbox = Sandbox::new();
    sandbox.helper();
    let path = OsString::from_vec(vec![b'x', 0xff, b' ']);
    let output = sandbox
        .command()
        .arg("--seed-file")
        .arg(&path)
        .args(["example", "--", "strange"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        encoded(&["--seed-file".into(), path, "--".into(), "strange".into()])
    );
}
#[cfg(unix)]
#[test]
fn non_utf8_equals_paths_are_opaque() {
    use std::os::unix::ffi::OsStringExt as _;
    let sandbox = Sandbox::new();
    sandbox.helper();
    let mut bytes = b"--recovery-seed-file=".to_vec();
    bytes.extend([b'x', 0xff, b' ']);
    let option = OsString::from_vec(bytes);
    let output = sandbox
        .command()
        .arg(&option)
        .args(["example", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, encoded(&[option, "--help".into()]));
}
#[test]
fn ordinary_parser_still_handles_early_exits_and_root_errors() {
    let sandbox = Sandbox::new();
    sandbox.helper();
    for args in [&["--help"][..], &["--version"]] {
        assert!(sandbox.run(args).status.success());
    }
    for args in [
        &["exampel"][..],
        &["--unknown", "example"],
        &["--api-url"],
        &["--api-url", "--json", "example"],
        &["--json=false", "example"],
        &["--compact=true", "example"],
    ] {
        let output = sandbox.run(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}: {output:?}");
        assert!(output.stdout.is_empty());
    }
    assert_ne!(
        sandbox
            .run(&["--api-url", "example", "catalog", "offerings"])
            .status
            .code(),
        Some(2)
    );
    #[cfg(unix)]
    {
        let output = sandbox.run(&["x", "local", "--", "example"]);
        assert_ne!(
            output.stdout,
            encoded(&["x".into(), "local".into(), "--".into()])
        );
    }
}
#[test]
fn sibling_precedes_path_and_path_fallback_is_explicit() {
    let sandbox = Sandbox::new();
    let elsewhere = tempfile::tempdir().unwrap();
    fs::copy(fixture(), elsewhere.path().join(helper_name())).unwrap();
    let output = sandbox
        .command()
        .env("PATH", elsewhere.path())
        .args(["example", "path"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, encoded(&["path".into()]));
    sandbox.helper();
    let output = sandbox
        .command()
        .env("PATH", "")
        .args(["example", "sibling"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, encoded(&["sibling".into()]));
}
#[test]
fn streams_environment_and_exit_status_are_inherited() {
    use std::io::Write as _;
    let sandbox = Sandbox::new();
    sandbox.helper();
    let mut child = sandbox
        .command()
        .args(["example", "opaque"])
        .env("TEST_HELPER_MODE", "streams")
        .env("TEST_HELPER_EXIT", "73")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"input\x00bytes\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(73));
    assert_eq!(output.stdout, b"input\x00bytes\n");
    assert_eq!(output.stderr, b"helper stderr");
    #[cfg(windows)]
    {
        let output = sandbox
            .command()
            .arg("example")
            .env("TEST_HELPER_EXIT", "305419896")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(305419896));
    }
}
#[test]
fn recursion_is_rejected_for_self_and_copies_without_global_env_changes() {
    let sandbox = Sandbox::new();
    fs::copy(
        &sandbox.binary,
        sandbox.directory.path().join(helper_name()),
    )
    .unwrap();
    let output = sandbox.run(&["example", "example", "example"]);
    assert_eq!(output.status.code(), Some(126));
    assert!(
        output
            .stderr
            .windows(b"recursive".len())
            .any(|part| part == b"recursive")
    );
    let output = sandbox
        .command()
        .env("_GHOST_EXTENSION_DISPATCHED", "1")
        .arg("example")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(126));
    #[cfg(unix)]
    {
        fs::remove_file(sandbox.directory.path().join(helper_name())).unwrap();
        fs::hard_link(
            &sandbox.binary,
            sandbox.directory.path().join(helper_name()),
        )
        .unwrap();
        assert_eq!(sandbox.run(&["example"]).status.code(), Some(126));
    }
}
#[cfg(unix)]
#[test]
fn unix_signals_survive_exec() {
    use std::os::unix::process::ExitStatusExt as _;
    let sandbox = Sandbox::new();
    sandbox.helper();
    let output = sandbox
        .command()
        .arg("example")
        .env("TEST_HELPER_MODE", "signal")
        .output()
        .unwrap();
    assert_eq!(output.status.signal(), Some(15));
}
#[cfg(unix)]
#[test]
fn a_nonexecutable_sibling_fails_with_126() {
    let sandbox = Sandbox::new();
    fs::write(
        sandbox.directory.path().join(helper_name()),
        "not an executable",
    )
    .unwrap();
    assert_eq!(sandbox.run(&["example"]).status.code(), Some(126));
}

#[test]
fn helper_inherits_a_distinct_working_directory() {
    let sandbox = Sandbox::new();
    sandbox.helper();
    let working = tempfile::tempdir().unwrap();
    fs::write(
        working.path().join("cwd-marker"),
        b"relative file from child cwd",
    )
    .unwrap();
    let output = sandbox
        .command()
        .current_dir(working.path())
        .arg("example")
        .env("TEST_HELPER_MODE", "cwd")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"relative file from child cwd");
}

#[test]
fn root_separators_follow_the_ordinary_parser() {
    let sandbox = Sandbox::new();
    sandbox.helper();
    for args in [
        vec!["--", "example", "opaque-action", "--help"],
        vec!["--", "example", "--help"],
    ] {
        let ordinary = ghost::command()
            .try_get_matches_from(std::iter::once("ghost").chain(args.iter().copied()))
            .unwrap_err();
        let output = sandbox.run(&args);
        assert_eq!(output.status.code(), Some(ordinary.exit_code()));
        assert!(output.stdout.is_empty());
    }
}

#[cfg(windows)]
#[test]
fn empty_windows_path_does_not_implicitly_search_working_directory() {
    let sandbox = Sandbox::new();
    let working = tempfile::tempdir().unwrap();
    fs::copy(fixture(), working.path().join(helper_name())).unwrap();
    for path in ["", ";;"] {
        let output = sandbox
            .command()
            .current_dir(working.path())
            .env("PATH", path)
            .arg("example")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    let output = sandbox
        .command()
        .current_dir(working.path())
        .env("PATH", ".")
        .args(["example", "explicit"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, encoded(&["explicit".into()]));
}

#[test]
fn customer_commands_and_nested_aliases_cannot_be_shadowed() {
    let sandbox = Sandbox::new();
    for name in [
        "catalog",
        "provider-reliability",
        "host-network-tests",
        "help",
    ] {
        let executable = if cfg!(windows) {
            format!("ghost-{name}.exe")
        } else {
            format!("ghost-{name}")
        };
        fs::copy(fixture(), sandbox.directory.path().join(executable)).unwrap();
    }
    for args in [
        vec!["catalog", "--help"],
        vec!["catalog", "provider-reliability", "--help"],
        vec!["catalog", "host-network-tests", "--help"],
        vec!["help"],
    ] {
        let output = sandbox.run(&args);
        assert!(output.status.success(), "{args:?}: {output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("Usage:"));
    }
}

#[test]
fn invalid_extension_names_never_resolve_a_program() {
    let sandbox = Sandbox::new();
    sandbox.helper();
    for name in [
        "../example",
        "a/b",
        "a\\b",
        ".example",
        "-example",
        "example.exe",
        "éxample",
        "example;echo",
    ] {
        let output = sandbox.run(&[name, "opaque"]);
        assert_eq!(output.status.code(), Some(2), "{name}: {output:?}");
        assert!(output.stdout.is_empty());
    }
}
