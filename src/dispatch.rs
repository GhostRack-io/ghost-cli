//! Dispatch installed command extensions without changing customer parsing.
use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
    process::Command,
};

const GUARD: &str = "_GHOST_EXTENSION_DISPATCHED";

/// Dispatch an installed extension before initializing the async runtime.
/// Returns only for ordinary customer commands.
pub fn dispatch() {
    let args: Vec<OsString> = std::env::args_os().collect();
    let Some(index) = extension_index(&args) else {
        return;
    };
    let fail = |message: &str, code| -> ! {
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr().lock(), "Error: {message}");
        std::process::exit(code)
    };
    let executable =
        std::env::current_exe().unwrap_or_else(|_| fail("cannot locate ghost executable", 126));
    let Some(name) = args.get(index).and_then(|argument| argument.to_str()) else {
        return;
    };
    let Some(helper) = resolve(&executable, name) else {
        return;
    };
    if std::env::var_os(GUARD).is_some() {
        fail("refusing recursive command extension dispatch", 126);
    }
    if same_file(&helper, &executable) {
        fail("refusing recursive command extension dispatch", 126);
    }
    let mut command = Command::new(helper);
    command
        .args(
            args.iter()
                .enumerate()
                .skip(1)
                .filter_map(|(i, arg)| (i != index).then_some(arg)),
        )
        .env(GUARD, "1");
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        let error = command.exec();
        fail(
            &format!(
                "cannot start command extension: {}",
                error.to_string().escape_default()
            ),
            126,
        );
    }
    #[cfg(windows)]
    {
        match command.status() {
            Ok(status) => std::process::exit(status.code().unwrap_or(126)),
            Err(error) => fail(
                &format!(
                    "cannot start command extension: {}",
                    error.to_string().escape_default()
                ),
                126,
            ),
        }
    }
}

fn extension_index(args: &[OsString]) -> Option<usize> {
    let ordinary = crate::command();
    let mut index = 1;
    while index < args.len() {
        let token = &args[index];
        if token == OsStr::new("--") {
            return None;
        }
        let bytes = token.as_encoded_bytes();
        if bytes.first().is_some_and(u8::is_ascii_alphanumeric) {
            let name = token.to_str()?;
            if !bytes
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
                || ordinary.find_subcommand(name).is_some()
            {
                return None;
            }
            let parsed = ordinary
                .clone()
                .allow_external_subcommands(true)
                .external_subcommand_value_parser(clap::value_parser!(OsString))
                .try_get_matches_from(&args[..=index])
                .ok()?;
            return (parsed.subcommand_name() == Some(name)).then_some(index);
        }
        // Decode only the option name: an equals-form path value can contain
        // arbitrary OS bytes, just like a separate PathBuf argument.
        let bytes = token.as_encoded_bytes();
        let equals_at = bytes.iter().position(|byte| *byte == b'=');
        let name_end = equals_at.unwrap_or(bytes.len());
        let name = std::str::from_utf8(&bytes[..name_end])
            .ok()?
            .strip_prefix("--")?;
        let equals = equals_at.is_some();
        let option = ordinary
            .get_arguments()
            .find(|arg| arg.is_global_set() && arg.get_long() == Some(name))?;
        let takes_value = option
            .get_num_args()
            .is_some_and(|range| range.max_values() > 0);
        index += if takes_value && !equals { 2 } else { 1 };
    }
    None
}

fn resolve(executable: &Path, command: &str) -> Option<PathBuf> {
    let name = if cfg!(windows) {
        format!("ghost-{command}.exe")
    } else {
        format!("ghost-{command}")
    };
    if let Some(parent) = executable.parent() {
        let sibling = parent.join(&name);
        if sibling.is_file() {
            return Some(sibling);
        }
    }
    std::env::var_os("PATH")
        .and_then(|paths| {
            std::env::split_paths(&paths)
                .filter(|path| !cfg!(windows) || !path.as_os_str().is_empty())
                .map(|path| path.join(&name))
                .find(|path| is_executable(path))
        })
        .and_then(|path| std::fs::canonicalize(path).ok())
}
fn is_executable(path: &Path) -> bool {
    let Ok(metadata) = std::fs::metadata(path) else {
        return false;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
    }
    #[cfg(windows)]
    {
        metadata.is_file()
    }
}
fn same_file(left: &Path, right: &Path) -> bool {
    if let (Ok(left), Ok(right)) = (std::fs::canonicalize(left), std::fs::canonicalize(right))
        && left == right
    {
        return true;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if let (Ok(left), Ok(right)) = (std::fs::metadata(left), std::fs::metadata(right)) {
            return left.dev() == right.dev() && left.ino() == right.ino();
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_global_option_uses_the_same_prefix_grammar() {
        for argument in crate::command()
            .get_arguments()
            .filter(|arg| arg.is_global_set())
        {
            assert!(
                argument.get_short().is_none(),
                "add short-option scanning before adding a short global option"
            );
            let long = argument.get_long().expect("global options have long names");
            let flag = OsString::from(format!("--{long}"));
            if argument
                .get_num_args()
                .is_some_and(|range| range.max_values() > 0)
            {
                assert_eq!(
                    extension_index(&[
                        "ghost".into(),
                        flag.clone(),
                        "example".into(),
                        "example".into(),
                        "opaque".into()
                    ]),
                    Some(3)
                );
                assert_eq!(
                    extension_index(&[
                        "ghost".into(),
                        format!("--{long}=example").into(),
                        "example".into()
                    ]),
                    Some(2)
                );
                assert_eq!(extension_index(&["ghost".into(), flag]), None);
            } else {
                assert_eq!(
                    extension_index(&["ghost".into(), flag, "example".into()]),
                    Some(2)
                );
                assert_eq!(
                    extension_index(&[
                        "ghost".into(),
                        format!("--{long}=false").into(),
                        "example".into()
                    ]),
                    None
                );
            }
        }
    }
}
