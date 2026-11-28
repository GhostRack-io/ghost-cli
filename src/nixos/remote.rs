//! Remote builds (item 323g4): `ghost nixos build` and `ghost nixos deploy
//! --remote` lock the flake here, upload its source to the Nix app in
//! chunks and follow the build on a leased builder; the generation lands in
//! the instance's location cache. Ctrl-C leaves the build running.
use std::{io::Write as _, time::Duration};

use anyhow::{Context as _, Result, ensure};
use clap::Args;
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use super::{BuildArgs, app_mutation, archive, build, derived_key};
use crate::{
    ApiClient, JobUnsuccessful,
    api::{is_transient, rejection},
};

/// The most source a remote build takes (its compressed `tar.zst`).
const MAXIMUM_SOURCE: u64 = 64 * 1024 * 1024;
/// How often a followed build is read.
const POLL: Duration = Duration::from_secs(2);
/// Tries of one source chunk after a transient failure.
const CHUNK_ATTEMPTS: u32 = 3;

#[derive(Args, Clone, Default)]
pub(crate) struct RemoteArgs {
    /// Builder tier (2k, 4k, 8k or 16k); later builds of this configuration
    /// start from it. Without it, the tier the last builds settled on.
    #[arg(long, value_parser = ["2k", "4k", "8k", "16k"])]
    tier: Option<String>,
    /// The build's time limit in minutes (default 120, at most 720).
    #[arg(long, value_parser = clap::value_parser!(u32).range(1..=720))]
    max_time: Option<u32>,
}

#[derive(Deserialize)]
struct Created {
    build_id: Uuid,
    /// `receiving` for a new build; a create repeated under its key answers
    /// where the build is now.
    #[serde(default)]
    state: Option<String>,
    chunk_bytes: usize,
}

impl Created {
    /// Whether the build still takes its source. One that went on has it,
    /// and one that ended has deleted it: its chunks are refused.
    fn takes_source(&self) -> bool {
        self.state
            .as_deref()
            .is_none_or(|state| state == "receiving")
    }
}

/// A build as the Nix app answers it.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(default)]
pub(super) struct Status {
    pub build_id: Uuid,
    pub generation_id: Uuid,
    pub state: String,
    pub ending: Option<String>,
    pub tier: String,
    pub next_tier: String,
    pub root_path: Option<String>,
    pub seconds: Option<u64>,
    pub amount_microusd: Option<u64>,
    pub failure: Option<String>,
    pub log_tail: String,
    pub log_bytes: u64,
}

impl Status {
    fn ended(&self) -> bool {
        matches!(self.state.as_str(), "done" | "failed" | "cancelled")
    }

    /// The tier as people read it: `≥ 4,000`.
    fn tier_name(&self) -> String {
        tier_name(&self.tier)
    }

    /// What the build prints at its end.
    pub fn receipt(&self) -> Value {
        json!({
            "build_id": self.build_id,
            "generation_id": self.generation_id,
            "root_path": self.root_path,
            "tier": self.tier,
            "next_tier": self.next_tier,
            "seconds": self.seconds,
            "amount": self.amount_microusd.map(dollars),
        })
    }
}

fn tier_name(key: &str) -> String {
    match key {
        "2k" => "≥ 2,000",
        "4k" => "≥ 4,000",
        "8k" => "≥ 8,000",
        "16k" => "≥ 16,000",
        other => other,
    }
    .to_owned()
}

/// Microdollars as dollars: `$0.0012`.
fn dollars(microusd: u64) -> String {
    format!(
        "${}.{:04}",
        microusd / 1_000_000,
        microusd % 1_000_000 / 100
    )
}

/// What a followed build's state change says, terse.
fn state_line(status: &Status) -> Option<String> {
    match status.state.as_str() {
        "queued" | "leasing" => Some(format!("Queued for a {} builder", status.tier_name())),
        "building" => Some("Building".into()),
        "publishing" => Some("Uploading".into()),
        "done" => Some(format!(
            "Done in {} s · {}",
            status.seconds.unwrap_or(0),
            dollars(status.amount_microusd.unwrap_or(0))
        )),
        "failed" | "cancelled" => status.failure.clone(),
        _ => None,
    }
}

/// The part of `tail` (the last bytes of a build's output, which wrote
/// `total` bytes) after the first `printed`, and whether output between was
/// lost to the tail's bound.
pub(super) fn new_output(tail: &str, total: u64, printed: u64) -> (&str, bool) {
    let new = total.saturating_sub(printed);
    let new = usize::try_from(new).unwrap_or(usize::MAX);
    if new == 0 {
        return ("", false);
    }
    if new > tail.len() {
        return (tail, true);
    }
    let mut start = tail.len() - new;
    while !tail.is_char_boundary(start) {
        start += 1;
    }
    (&tail[start..], false)
}

/// How a remote build went: ended (done, or failed with its status as the
/// error), or still running when the wait was over.
pub(super) enum Outcome {
    Done(Box<Status>),
    Running(Value),
}

/// Build `args`' configuration remotely under `key`, then follow it for
/// `wait` (`None`: to its end; zero: the receipt once it is queued).
pub(super) async fn build(
    api: &ApiClient,
    args: &BuildArgs,
    remote: &RemoteArgs,
    key: &str,
    wait: Option<Duration>,
) -> Result<(Outcome, Option<String>)> {
    let locked = build::lock(args).await?;
    let scratch = tempfile::Builder::new().prefix("ghost-nixos-").tempdir()?;
    let file = scratch.path().join("source.tar.zst");
    archive::export_source(&file, &locked.source).await?;
    let bytes = tokio::fs::read(&file).await?;
    ensure!(
        bytes.len() as u64 <= MAXIMUM_SOURCE,
        "the flake source archive exceeds 64 MiB, the most a remote build takes"
    );
    let mut body = json!({
        "instance_id": args.instance,
        "configuration": args.configuration,
        "source_sha256": format!("{:x}", Sha256::digest(&bytes)),
        "source_bytes": bytes.len(),
    });
    if let Some(tier) = &remote.tier {
        body["tier"] = json!(tier);
    }
    if let Some(minutes) = remote.max_time {
        body["max_seconds"] = json!(minutes * 60);
    }
    let created: Created = serde_json::from_value(
        app_mutation(api, "/builds", &body, &derived_key("build", key)).await?,
    )
    .context("invalid build receipt")?;
    let id = created.build_id;
    let queued = submit(api, &created, &bytes, key).await?;
    if wait == Some(Duration::ZERO) {
        return Ok((Outcome::Running(queued), locked.revision));
    }
    let outcome = follow(api, id, wait).await?;
    Ok((outcome, locked.revision))
}

/// Send `bytes` as the created build's source, then queue it: what `done`
/// answers. A build past `receiving` (its create repeated) is sent none;
/// its `done` answers where it is.
async fn submit(api: &ApiClient, created: &Created, bytes: &[u8], key: &str) -> Result<Value> {
    let id = created.build_id;
    if created.takes_source() {
        ensure!(created.chunk_bytes > 0, "invalid build chunk size");
        for (index, chunk) in bytes.chunks(created.chunk_bytes).enumerate() {
            put_chunk(api, id, index, chunk, key).await?;
        }
    }
    app_mutation(
        api,
        &format!("/builds/{id}/source/done"),
        &json!({}),
        &derived_key("build-done", key),
    )
    .await
}

async fn put_chunk(api: &ApiClient, id: Uuid, index: usize, chunk: &[u8], key: &str) -> Result<()> {
    let target = format!("/builds/{id}/source/{index}");
    let key = derived_key(&format!("build-chunk-{index}"), key);
    for attempt in 1..=CHUNK_ATTEMPTS {
        match api
            .app_bytes("nix", "PUT", &target, chunk.to_vec(), &key)
            .await
        {
            Ok(_) => return Ok(()),
            Err(error) if is_transient(&error) && attempt < CHUNK_ATTEMPTS => {
                tokio::time::sleep(Duration::from_secs(1 << (attempt - 1))).await;
            }
            Err(error) => {
                return Err(error.context(format!("upload source chunk {index} of build {id}")));
            }
        }
    }
    unreachable!("the last attempt returns")
}

/// Read build `id` until it ends or `wait` is over, printing its new output
/// and its state changes to standard error.
async fn follow(api: &ApiClient, id: Uuid, wait: Option<Duration>) -> Result<Outcome> {
    let deadline = wait.map(|wait| tokio::time::Instant::now() + wait);
    let mut printed = None;
    let mut shown: Option<String> = None;
    let mut last = Value::Null;
    loop {
        match api
            .app("nix", "GET", &format!("/builds/{id}"), None, None)
            .await
        {
            Ok(value) => {
                let status: Status =
                    serde_json::from_value(value.clone()).context("invalid build status")?;
                // Its output so far is shown once, then what follows.
                let (output, gap) =
                    new_output(&status.log_tail, status.log_bytes, printed.unwrap_or(0));
                let mut stderr = std::io::stderr().lock();
                if gap && printed.is_some() {
                    let _ = writeln!(stderr, "…");
                }
                let _ = stderr.write_all(output.as_bytes());
                printed = Some(status.log_bytes);
                let line = state_line(&status);
                if line.is_some() && line != shown {
                    if let Some(line) = &line {
                        let _ = writeln!(stderr, "{line}");
                    }
                    shown = line;
                }
                drop(stderr);
                last = value;
                if status.ended() {
                    return if status.state == "done" {
                        Ok(Outcome::Done(Box::new(status)))
                    } else {
                        let message = format!(
                            "build {id} ended {}{}",
                            status.state,
                            status
                                .failure
                                .as_deref()
                                .map(|failure| format!(": {failure}"))
                                .unwrap_or_default()
                        );
                        Err(JobUnsuccessful {
                            snapshot: last,
                            message,
                        }
                        .into())
                    };
                }
            }
            Err(error)
                if is_transient(&error)
                    || rejection(&error).is_some_and(|answer| answer.status == 404) => {}
            Err(error) => return Err(error),
        }
        let sleep = tokio::time::sleep(POLL);
        tokio::select! {
            () = sleep => {}
            _ = tokio::signal::ctrl_c() => {
                anyhow::bail!("build {id} goes on; `ghost nixos cancel {id}` ends it");
            }
        }
        if deadline.is_some_and(|deadline| tokio::time::Instant::now() >= deadline) {
            return Ok(Outcome::Running(json!({
                "build_id": id,
                "settled": false,
                "last_observed": last,
                "status_target": format!("/builds/{id}"),
            })));
        }
    }
}

/// `ghost nixos cancel`: end a build; the seconds it used are charged.
pub(super) async fn cancel(api: &ApiClient, build: Uuid) -> Result<Value> {
    app_mutation(
        api,
        &format!("/builds/{build}/cancel"),
        &json!({}),
        &crate::fresh_idempotency_key(),
    )
    .await
}

/// `ghost nixos providers`: the account's trusted providers, or a new list.
pub(super) async fn providers(api: &ApiClient, set: Option<&[Uuid]>, clear: bool) -> Result<Value> {
    let list = if clear { Some(&[][..]) } else { set };
    let Some(list) = list else {
        return api.app("nix", "GET", "/builds/settings", None, None).await;
    };
    let body = json!({ "trusted_providers": list });
    let key = crate::fresh_idempotency_key();
    for delay in [1, 2] {
        match api
            .app("nix", "PUT", "/builds/settings", Some(&body), Some(&key))
            .await
        {
            Err(error) if is_transient(&error) => {
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
            result => return result,
        }
    }
    api.app("nix", "PUT", "/builds/settings", Some(&body), Some(&key))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_output_is_what_follows_the_printed_bytes() {
        let tail = "line one\nline two\n";
        // Nothing printed yet: all of it.
        assert_eq!(new_output(tail, 18, 0), (tail, false));
        // Nine more bytes after the first nine.
        assert_eq!(new_output(tail, 18, 9), ("line two\n", false));
        assert_eq!(new_output(tail, 18, 18), ("", false));
        // More new bytes than the tail keeps: the tail, with a gap.
        assert_eq!(new_output(tail, 100, 10), (tail, true));
        // A cut inside a character moves to its end.
        assert_eq!(new_output("aé", 3, 1), ("é", false));
        assert_eq!(new_output("aé", 3, 2), ("", false));
    }

    #[tokio::test]
    async fn a_repeated_create_of_a_build_past_receiving_sends_no_source() {
        let id = Uuid::now_v7();
        let done = json!({"build_id": id, "state": "done", "tier": "2k", "next_tier": "2k",
                          "seconds": 84, "amount_microusd": 1_200, "log_tail": "", "log_bytes": 0});
        let (url, requests) =
            crate::tests::canned_server(vec![(200, done.to_string()), (200, done.to_string())])
                .await;
        let api = ApiClient::new(
            &url,
            Some(crate::keys::authentication_identity(&[3; 32]).unwrap()),
        )
        .unwrap();
        let created: Created = serde_json::from_value(
            json!({"build_id": id, "state": "done", "chunk_bytes": 1_048_576}),
        )
        .unwrap();
        assert!(!created.takes_source());
        submit(&api, &created, &[7; 10], "remote-fixture-key-01")
            .await
            .unwrap();
        // No chunk: the build ended and deleted its source.
        assert_eq!(
            crate::tests::request_lines(&requests),
            [format!("POST /api/mut/v1/apps/nix/builds/{id}/source/done")]
        );
        let Outcome::Done(status) = follow(&api, id, None).await.unwrap() else {
            panic!("the build ended");
        };
        assert_eq!(status.seconds, Some(84));
        assert_eq!(
            crate::tests::request_lines(&requests)[1],
            format!("GET /v1/apps/nix/builds/{id}")
        );
        // A new build, and an answer without its state, take the source.
        for answer in [
            json!({"build_id": id, "state": "receiving", "chunk_bytes": 1}),
            json!({"build_id": id, "chunk_bytes": 1}),
        ] {
            assert!(
                serde_json::from_value::<Created>(answer)
                    .unwrap()
                    .takes_source()
            );
        }
    }

    #[test]
    fn states_read_as_terse_facts() {
        let status = |state: &str| Status {
            state: state.into(),
            tier: "4k".into(),
            seconds: Some(84),
            amount_microusd: Some(1_200),
            failure: Some("The build failed (exit 1).".into()),
            ..Status::default()
        };
        assert_eq!(
            state_line(&status("queued")).as_deref(),
            Some("Queued for a ≥ 4,000 builder")
        );
        assert_eq!(state_line(&status("building")).as_deref(), Some("Building"));
        assert_eq!(
            state_line(&status("publishing")).as_deref(),
            Some("Uploading")
        );
        assert_eq!(
            state_line(&status("done")).as_deref(),
            Some("Done in 84 s · $0.0012")
        );
        assert_eq!(
            state_line(&status("failed")).as_deref(),
            Some("The build failed (exit 1).")
        );
        assert_eq!(state_line(&status("receiving")), None);
        assert_eq!(dollars(250_000), "$0.2500");
    }
}
