//! `ghost nixos builder`: the steps a leased builder runs for a remote
//! build (item 323g4), hidden from help. They need no account key: `build`
//! builds the given source, `send` publishes with the one generation's
//! upload grant the platform wrote beside it. Each prints one JSON object.
use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use clap::Subcommand;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::process::Command;
use uuid::Uuid;

use super::{
    BuildArgs,
    archive::{self, Archive, Grant},
    build, client,
};

#[derive(Subcommand)]
pub(crate) enum BuilderCommand {
    /// Build a source archive's NixOS configuration and pack its generation.
    Build {
        /// The flake source as `tar.zst`, as `ghost nixos deploy` exports it.
        #[arg(long)]
        source: PathBuf,
        /// Name under nixosConfigurations.
        #[arg(long)]
        configuration: String,
        /// Directory for the generation archive and its figures.
        #[arg(long)]
        out: PathBuf,
    },
    /// Send a packed generation to its location with an upload grant.
    Send {
        /// The directory `build` wrote.
        #[arg(long)]
        archive: PathBuf,
        /// JSON file with the generation's upload grant.
        #[arg(long)]
        grant_file: PathBuf,
    },
}

pub(crate) async fn execute(command: &BuilderCommand) -> Result<Value> {
    match command {
        BuilderCommand::Build {
            source,
            configuration,
            out,
        } => build_source(source, configuration, out).await,
        BuilderCommand::Send {
            archive,
            grant_file,
        } => send(archive, grant_file).await,
    }
}

async fn build_source(source: &Path, configuration: &str, out: &Path) -> Result<Value> {
    let bytes = tokio::fs::read(source)
        .await
        .context("read the source archive")?;
    let digest = format!("{:x}", Sha256::digest(&bytes));
    let tree = tempfile::Builder::new()
        .prefix("ghost-nixos-source-")
        .tempdir()?;
    let status = Command::new("tar")
        .args(["--zstd", "--no-same-owner", "-xf"])
        .arg(source)
        .arg("-C")
        .arg(tree.path())
        .kill_on_drop(true)
        .status()
        .await
        .context("start tar")?;
    ensure!(
        status.success(),
        "the source archive did not unpack ({status})"
    );
    let input = BuildArgs {
        instance: Uuid::nil(),
        flake: tree.path().to_owned(),
        configuration: configuration.to_owned(),
    };
    let candidate = build::local(&input).await?;
    let archive = archive::prepare_with_source(&client()?, &candidate, &digest, source).await?;
    ensure!(
        archive.source_sha256 == digest,
        "the packed source differs from the given one"
    );
    let figures = archive.persist(out)?;
    Ok(serde_json::to_value(figures)?)
}

async fn send(directory: &Path, grant_file: &Path) -> Result<Value> {
    let grant: Grant = serde_json::from_slice(
        &tokio::fs::read(grant_file)
            .await
            .context("read the upload grant")?,
    )
    .context("invalid Nix upload grant")?;
    let archive = Archive::open(directory)?;
    let generation = archive.send_with(&client()?, &grant).await?;
    Ok(json!({"generation_id": generation, "root_path": archive.figures().root_path}))
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;

    #[derive(clap::Parser)]
    struct Probe {
        #[command(subcommand)]
        command: BuilderCommand,
    }

    #[test]
    fn the_steps_parse_as_the_runner_calls_them() {
        let parsed = Probe::try_parse_from([
            "builder",
            "build",
            "--source",
            "/home/ci/builds/b/source.tar.zst",
            "--configuration",
            "web",
            "--out",
            "/home/ci/builds/b/out",
        ])
        .unwrap();
        assert!(matches!(
            parsed.command,
            BuilderCommand::Build { ref configuration, .. } if configuration == "web"
        ));
        let parsed = Probe::try_parse_from([
            "builder",
            "send",
            "--archive",
            "/home/ci/builds/b/out",
            "--grant-file",
            "/home/ci/builds/b/grant.json",
        ])
        .unwrap();
        assert!(matches!(parsed.command, BuilderCommand::Send { .. }));
    }

    #[test]
    fn build_prints_the_figures_the_runner_reads() {
        let figures = archive::Figures {
            root_path: "/nix/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-system".into(),
            manifest_sha256: "ab".repeat(32),
            source_sha256: "cd".repeat(32),
        };
        assert_eq!(
            serde_json::to_value(&figures).unwrap(),
            json!({
                "root_path": "/nix/store/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz-system",
                "manifest_sha256": "ab".repeat(32),
                "source_sha256": "cd".repeat(32),
            })
        );
    }
}
