mod archive;
mod build;
mod builder;
mod remote;

use std::{path::PathBuf, time::Duration};

use anyhow::{Context as _, Result, ensure};
use clap::{Args, Subcommand};
use ghostrack_client_api::{
    api::CreateInstanceSnapshot,
    website::{CreateInstanceSnapshotRequest, JobAccepted, JobState},
};
use reqwest::{Client, Url, redirect};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    ApiClient, JobUnsuccessful, MutationKey,
    api::{is_transient, rejection},
    fresh_idempotency_key, parse_idempotency_key, wait_for_job,
};

#[derive(Subcommand)]
pub(crate) enum NixosCommand {
    /// Compare a locked local build with the instance's active system.
    Diff(BuildArgs),
    /// Upload a locked local build and deploy its generation.
    Deploy {
        #[command(flatten)]
        build: BuildArgs,
        /// Build on a GhostRack builder instead of this machine.
        #[arg(long)]
        remote: bool,
        #[command(flatten)]
        remote_args: remote::RemoteArgs,
        /// Take and wait for an instance disk snapshot before queueing the deploy.
        #[arg(long)]
        snapshot: bool,
        /// JSON file containing health check settings.
        #[arg(long)]
        health: Option<PathBuf>,
        #[command(flatten)]
        queue: QueueArgs,
    },
    /// Deploy an earlier retained generation.
    Rollback {
        /// ID of the instance to roll back.
        instance: Uuid,
        /// ID of the retained generation to apply.
        generation: Uuid,
        /// JSON file containing health check settings. Defaults to the
        /// generation's settings when it was last deployed.
        #[arg(long)]
        health: Option<PathBuf>,
        #[command(flatten)]
        queue: QueueArgs,
    },
    /// Read the recorded outcome of an exact deployment job.
    Status {
        /// ID of the instance the deployment belongs to.
        instance: Uuid,
        /// Job ID returned when the deployment was queued.
        job: Uuid,
    },
    /// Build on a GhostRack builder and keep the generation in the
    /// instance's cache.
    Build {
        #[command(flatten)]
        build: BuildArgs,
        #[command(flatten)]
        remote: remote::RemoteArgs,
        /// Signed request key. Generated when omitted.
        #[arg(long, value_parser = parse_idempotency_key)]
        idempotency_key: Option<String>,
        /// Maximum time to follow the build. Use 0 to print its receipt.
        #[arg(long, default_value_t = 10_800, value_parser = clap::value_parser!(u64).range(0..=50_400))]
        wait_seconds: u64,
    },
    /// End a remote build. The seconds it used are charged.
    Cancel {
        /// ID of the build.
        build: Uuid,
    },
    /// Show or set the providers remote builds may run on.
    Providers {
        /// Provider IDs, comma-separated.
        #[arg(long, value_delimiter = ',', conflicts_with = "clear")]
        set: Option<Vec<Uuid>>,
        /// Allow any provider.
        #[arg(long)]
        clear: bool,
    },
    /// A remote build's steps on its builder.
    #[command(hide = true, version)]
    Builder {
        #[command(subcommand)]
        command: builder::BuilderCommand,
    },
}

#[derive(Args)]
pub(crate) struct BuildArgs {
    /// ID of the GhostRack NixOS instance.
    instance: Uuid,
    /// Local directory with flake.nix and flake.lock.
    #[arg(long, default_value = ".")]
    flake: PathBuf,
    /// Name under nixosConfigurations.
    #[arg(long)]
    configuration: String,
}

#[derive(Args)]
pub(crate) struct QueueArgs {
    /// Signed request key. Generated when omitted.
    #[arg(long, value_parser = parse_idempotency_key)]
    idempotency_key: Option<String>,
    /// Maximum time to follow the job. Use 0 to print its queue receipt.
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u64).range(0..=3600))]
    wait_seconds: u64,
}

#[derive(Deserialize)]
struct Active {
    generation_id: Option<Uuid>,
    last_safe_generation_id: Option<Uuid>,
    root_path: Option<String>,
    unsettled_job_id: Option<Uuid>,
    reconciliation_gap: Option<i64>,
}

fn path(instance: Uuid, suffix: &str) -> String {
    format!("/deployments/instances/{instance}/{suffix}")
}

async fn active(api: &ApiClient, instance: Uuid) -> Result<Active> {
    let value = api
        .app("nix", "GET", &path(instance, "active"), None, None)
        .await?;
    Ok(serde_json::from_value(value)?)
}

pub(crate) async fn execute(api: &ApiClient, command: &NixosCommand) -> Result<Value> {
    match command {
        NixosCommand::Diff(args) => {
            let prior = active(api, args.instance).await?;
            let candidate = build::local(args).await?;
            let mut result =
                build::diff(api, args.instance, prior.root_path.as_deref(), &candidate).await?;
            result["reconciliation_gap"] = json!(prior.reconciliation_gap);
            Ok(result)
        }
        NixosCommand::Deploy {
            build,
            remote,
            remote_args,
            snapshot,
            health,
            queue,
        } => {
            let remote = remote.then_some(remote_args);
            deploy(api, build, remote, *snapshot, health.as_deref(), queue).await
        }
        NixosCommand::Rollback {
            instance,
            generation,
            health,
            queue,
        } => {
            let prior = active(api, *instance).await?;
            let mut body = json!({"generation_id": generation, "expected_active_generation_id": prior.last_safe_generation_id.or(prior.generation_id)});
            if let Some(path) = health {
                body["health"] = read_health(path).await?;
            }
            queue_job(api, *instance, "rollback", &body, queue, &queue_key(queue)).await
        }
        NixosCommand::Status { instance, job } => status(api, *instance, *job).await,
        NixosCommand::Build {
            build,
            remote,
            idempotency_key,
            wait_seconds,
        } => {
            let key = idempotency_key
                .clone()
                .unwrap_or_else(fresh_idempotency_key);
            let wait = Some(Duration::from_secs(*wait_seconds));
            match remote::build(api, build, remote, &key, wait).await?.0 {
                remote::Outcome::Done(status) => Ok(status.receipt()),
                remote::Outcome::Running(receipt) => Ok(receipt),
            }
        }
        NixosCommand::Cancel { build } => remote::cancel(api, *build).await,
        NixosCommand::Providers { set, clear } => {
            remote::providers(api, set.as_deref(), *clear).await
        }
        NixosCommand::Builder { command } => builder::execute(command).await,
    }
}

async fn deploy(
    api: &ApiClient,
    args: &BuildArgs,
    remote: Option<&remote::RemoteArgs>,
    snapshot: bool,
    health: Option<&std::path::Path>,
    queue: &QueueArgs,
) -> Result<Value> {
    let prior = active(api, args.instance).await?;
    if let Some(job) = prior.unsettled_job_id {
        anyhow::bail!("deployment {job} is still unsettled");
    }
    let health = match health {
        Some(path) => read_health(path).await?,
        None => json!({}),
    };
    let key = queue_key(queue);
    let (generation, revision) = match remote {
        // Built on a builder, its generation already in the cache.
        Some(remote) => match remote::build(api, args, remote, &key, None).await? {
            (remote::Outcome::Done(status), revision) => (status.generation_id, revision),
            (remote::Outcome::Running(_), _) => {
                anyhow::bail!("the remote build did not end")
            }
        },
        None => upload_local(api, args, &key).await?,
    };
    let snapshot_id = if snapshot {
        Some(create_snapshot(api, args.instance, &key).await?)
    } else {
        None
    };
    let body = json!({
        "generation_id": generation,
        "expected_active_generation_id": prior.last_safe_generation_id.or(prior.generation_id),
        "snapshot_id": snapshot_id,
        "flake_revision": revision,
        "health": health,
    });
    queue_job(api, args.instance, "deploy", &body, queue, &key).await
}

/// Build `args` here and upload its generation: its ID and the flake's
/// revision.
async fn upload_local(
    api: &ApiClient,
    args: &BuildArgs,
    key: &str,
) -> Result<(Uuid, Option<String>)> {
    let candidate = build::local(args).await?;
    let digest = Sha256::digest(format!(
        "ghostrack/nixos/generation/v1/{}/{key}",
        args.instance
    ));
    let generation = uuid::Builder::from_random_bytes(digest[..16].try_into()?).into_uuid();
    let client = client()?;
    let archive = archive::prepare(&client, &candidate, key).await?;
    let body = json!({
        "generation_id": generation,
        "root_path": candidate.root,
        "manifest_sha256": archive.manifest_sha256,
        "source_sha256": archive.source_sha256,
    });
    let register_key = derived_key("upload", key);
    app_mutation(
        api,
        &format!("/cache/instances/{}/uploads", args.instance),
        &body,
        &register_key,
    )
    .await?;
    archive.upload(api, &client, generation).await?;
    Ok((generation, candidate.revision))
}

async fn read_health(path: &std::path::Path) -> Result<Value> {
    let bytes = tokio::fs::read(path)
        .await
        .context("read health settings")?;
    ensure!(bytes.len() <= 8192, "health settings exceed 8 KiB");
    serde_json::from_slice::<Value>(&bytes).context("read JSON health settings")
}

async fn create_snapshot(api: &ApiClient, instance: Uuid, key: &str) -> Result<Uuid> {
    let key = derived_key("snapshot", key);
    let mutation = MutationKey {
        retry: format!("--idempotency-key {key}"),
        key,
    };
    let accepted: JobAccepted = api
        .write_retryable(
            &CreateInstanceSnapshot {
                instance_id: instance,
            },
            &CreateInstanceSnapshotRequest::default(),
            &mutation,
        )
        .await?;
    let job = tokio::time::timeout(
        Duration::from_mins(8),
        wait_for_job(api, accepted.job_id, Duration::from_secs(2), false),
    )
    .await
    .with_context(|| format!("snapshot job {} is still unresolved", accepted.job_id))??;
    ensure!(
        job.state == JobState::Succeeded,
        "snapshot job {} ended as {:?}",
        accepted.job_id,
        job.state
    );
    Ok(accepted.resource_id)
}

fn derived_key(domain: &str, key: &str) -> String {
    format!("nixos-{domain}-{:x}", Sha256::digest(key))
}

fn queue_key(args: &QueueArgs) -> String {
    args.idempotency_key
        .clone()
        .unwrap_or_else(fresh_idempotency_key)
}

async fn app_mutation(api: &ApiClient, target: &str, body: &Value, key: &str) -> Result<Value> {
    for delay in [1, 2] {
        match api.app("nix", "POST", target, Some(body), Some(key)).await {
            Err(error) if is_transient(&error) => {
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
            result => return result,
        }
    }
    api.app("nix", "POST", target, Some(body), Some(key)).await
}

async fn queue_job(
    api: &ApiClient,
    instance: Uuid,
    operation: &str,
    body: &Value,
    args: &QueueArgs,
    key: &str,
) -> Result<Value> {
    let target = path(instance, operation);
    let receipt = match app_mutation(api, &target, body, key).await {
        Ok(receipt) => receipt,
        Err(error) if is_transient(&error) => {
            return Ok(json!({
                "phase": "unknown", "settled": false, "job_id": null,
                "retry": {"app":"nix", "method":"POST", "target":target, "body":body, "idempotency_key":key},
            }));
        }
        Err(error) => return Err(error),
    };
    let job = serde_json::from_value::<Uuid>(receipt["job_id"].clone())
        .context("deployment receipt has no job ID")?;
    if args.wait_seconds == 0 {
        return Ok(receipt);
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(args.wait_seconds);
    let mut observed = receipt;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout_at(deadline, status(api, instance, job)).await {
            Ok(Ok(result)) => {
                if result["settled"].as_bool() == Some(true) {
                    return settled_job(result, job);
                }
                observed = result;
            }
            Ok(Err(error))
                if is_transient(&error)
                    || rejection(&error).is_some_and(|answer| answer.status == 404) => {}
            Ok(Err(error)) => return Err(error),
            Err(_) => break,
        }
        tokio::time::sleep_until(
            (tokio::time::Instant::now() + Duration::from_secs(2)).min(deadline),
        )
        .await;
    }
    Ok(
        json!({"job_id":job, "phase":"unknown", "settled":false, "last_observed":observed, "status_target":path(instance, &format!("jobs/{job}"))}),
    )
}

fn settled_job(outcome: Value, job: Uuid) -> Result<Value> {
    let phase = outcome["phase"].as_str().unwrap_or("unknown");
    if phase == "committed" {
        return Ok(outcome);
    }
    let detail = outcome["failure"]["detail"]
        .as_str()
        .filter(|detail| !detail.is_empty());
    let message = match (outcome["failure"]["stage"].as_str(), detail) {
        (Some(stage), Some(detail)) => {
            format!("deployment {job} ended {phase} ({stage}: {detail})")
        }
        (Some(stage), None) => format!("deployment {job} ended {phase} ({stage})"),
        (None, _) => format!("deployment {job} ended {phase}"),
    };
    Err(JobUnsuccessful {
        snapshot: outcome,
        message,
    }
    .into())
}

async fn status(api: &ApiClient, instance: Uuid, job: Uuid) -> Result<Value> {
    api.app(
        "nix",
        "GET",
        &path(instance, &format!("jobs/{job}")),
        None,
        None,
    )
    .await
}

fn client() -> Result<Client> {
    Ok(Client::builder()
        .redirect(redirect::Policy::none())
        .https_only(true)
        .connect_timeout(Duration::from_secs(8))
        .build()?)
}

fn https_url(raw: &str) -> Result<Url> {
    let url = Url::parse(raw).context("invalid HTTPS URL returned by Nix app")?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "invalid HTTPS URL returned by Nix app"
    );
    Ok(url)
}

#[derive(Deserialize)]
struct CacheCredential {
    url: String,
    public_key_url: String,
    login: String,
    #[serde(deserialize_with = "password")]
    password: Zeroizing<String>,
}

fn password<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_nixos_deployment_wait_retries_replica_lag_and_prints_a_settled_failure() {
        let instance = Uuid::now_v7();
        let job = Uuid::now_v7();
        let generation = Uuid::now_v7();
        let receipt =
            json!({"job_id":job,"generation_id":generation,"phase":"queued","settled":false});
        let failed = json!({"job_id":job,"generation_id":generation,"phase":"rolled_back","settled":true,
                            "failure":{"stage":"systemd","detail":"nginx.service"}});
        let (url, requests) = crate::tests::canned_server(vec![
            (202, receipt.to_string()),
            (404, String::new()),
            (503, String::new()),
            (200, failed.to_string()),
        ])
        .await;
        let api = ApiClient::new(
            &url,
            Some(crate::keys::authentication_identity(&[3; 32]).unwrap()),
        )
        .unwrap();
        let args = QueueArgs {
            idempotency_key: None,
            wait_seconds: 10,
        };
        let error = queue_job(
            &api,
            instance,
            "deploy",
            &json!({"generation_id":generation}),
            &args,
            "nixos-fixture-key",
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.downcast_ref::<JobUnsuccessful>().unwrap().snapshot(),
            &failed
        );
        assert!(
            error
                .to_string()
                .contains("ended rolled_back (systemd: nginx.service)"),
            "{error}"
        );
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 4);
        assert!(requests[0].0.starts_with("POST "));
        let exact =
            format!("GET /v1/apps/nix/deployments/instances/{instance}/jobs/{job} HTTP/1.1");
        assert!(requests[1..].iter().all(|(request, _)| request == &exact));
    }
}
