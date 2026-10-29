use std::{sync::OnceLock, time::Duration};

use anyhow::{Context as _, Result, bail};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use gigahost_client_api::{
    account_auth::{
        AUTH_KEY_ID_HEADER, REQUEST_NONCE_HEADER, REQUEST_SIGNATURE_HEADER,
        REQUEST_TIMESTAMP_HEADER, RequestSignatureInput, canonical_request,
    },
    api::{self, Endpoint},
    support_window::{CLIENT_HEADER, GHOST_CLIENT, client_identity},
    website::ErrorResponse,
};
use reqwest::{Method, StatusCode, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use uuid::Uuid;

use crate::keys::AuthenticationIdentity;

/// The pauses before a read that got no answer is sent again, one per
/// retry. On a lossy link a connection attempt times out now and then, and
/// a read changes nothing, so it is safe to repeat.
const READ_RETRY_DELAYS: [Duration; 2] = [Duration::from_secs(1), Duration::from_secs(2)];

/// Loads the account identity that signs requests, or finds there is none.
type IdentityLoader = Box<dyn Fn() -> Result<Option<AuthenticationIdentity>> + Send + Sync>;

pub struct ApiClient {
    client: reqwest::Client,
    base_url: Url,
    /// The identity signed requests use, once it is loaded.
    identity: OnceLock<AuthenticationIdentity>,
    /// Loads it when the first request that needs it is sent, so that a
    /// command calling only public endpoints needs no account key.
    load_identity: IdentityLoader,
    read_retry_delays: Vec<Duration>,
}

/// A response's value, with when the server answered, by its own clock,
/// and how long the request took from its sending to its answer.
pub struct Answered<T> {
    pub value: T,
    /// The response's `Date`, to the second.
    pub server_date: Option<DateTime<Utc>>,
    pub elapsed: Duration,
}

/// The `Idempotency-Key` of a mutation the user can repeat, and the
/// arguments that repeat it, such as `--idempotency-key KEY`.
pub struct MutationKey {
    pub key: String,
    pub retry: String,
}

impl ApiClient {
    /// A client that signs with `identity`, or sends only public requests.
    #[cfg(test)]
    pub(crate) fn new(base_url: &str, identity: Option<AuthenticationIdentity>) -> Result<Self> {
        let client = Self::with_identity_loader(base_url, Box::new(|| Ok(None)))?;
        if let Some(identity) = identity {
            let _ = client.identity.set(identity);
        }
        Ok(client)
    }

    /// A client whose signed requests use the identity `load_identity`
    /// returns, loaded when the first of them is sent. It returns `None`
    /// when there is no account, which such a request then fails for.
    #[cfg(any(unix, test))]
    pub(crate) fn with_identity_loader(
        base_url: &str,
        load_identity: IdentityLoader,
    ) -> Result<Self> {
        Self::with_identity_loader_for_release(base_url, load_identity, crate::release())
    }
    pub(crate) fn with_identity_loader_for_release(
        base_url: &str,
        load_identity: IdentityLoader,
        release: &str,
    ) -> Result<Self> {
        let mut base_url = Url::parse(base_url).context("parse --api-url")?;
        if !matches!(base_url.scheme(), "http" | "https") {
            bail!("--api-url must use http or https");
        }
        if base_url.scheme() == "http" && !base_url.host_str().is_some_and(is_literal_ip_host) {
            bail!("plain HTTP is allowed only for a literal-IP test backend");
        }
        if base_url.cannot_be_a_base()
            || base_url.host_str().is_none()
            || !base_url.username().is_empty()
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
        {
            bail!("--api-url must be a base URL without a query or fragment");
        }
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        // Every request names this ghost and its release, by which the
        // backend refuses a release it no longer serves.
        let identity = client_identity(GHOST_CLIENT, release);
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            CLIENT_HEADER,
            reqwest::header::HeaderValue::from_str(&identity).context("name this ghost")?,
        );
        let client = reqwest::Client::builder()
            .user_agent(identity)
            .default_headers(headers)
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(1)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .context("build HTTP client")?;
        Ok(Self {
            client,
            base_url,
            identity: OnceLock::new(),
            load_identity,
            read_retry_delays: READ_RETRY_DELAYS.to_vec(),
        })
    }

    /// The identity that signs requests, loaded the first time.
    fn identity(&self) -> Result<&AuthenticationIdentity> {
        if let Some(identity) = self.identity.get() {
            return Ok(identity);
        }
        let identity = (self.load_identity)()?.context(
            "this command requires the account key; generate one with `ghost key generate`",
        )?;
        Ok(self.identity.get_or_init(|| identity))
    }

    /// This client with `delays` between the attempts of a read: none for
    /// a read that is only a part of a command's answer.
    #[must_use]
    pub fn with_read_retry_delays(mut self, delays: &[Duration]) -> Self {
        self.read_retry_delays = delays.to_vec();
        self
    }

    /// Call a read endpoint; a non-empty `query` becomes the query string.
    /// A GET that got no answer is sent again after each of the
    /// [`READ_RETRY_DELAYS`], with a notice.
    /// # Errors
    /// Returns an error if credentials, transport, or the backend reject this request.
    pub async fn read<E: Endpoint>(&self, endpoint: &E, query: &str) -> Result<E::Response> {
        self.read_as::<E, E::Response>(endpoint, query).await
    }

    /// [`Self::read`] into `T` rather than the endpoint's own answer type:
    /// for a command that only prints an answer and reads it loosely, so
    /// that what a newer backend changes in it never stops the command.
    /// # Errors
    /// Returns an error if credentials, transport, or the backend reject this request.
    pub async fn read_as<E: Endpoint, T: DeserializeOwned>(
        &self,
        endpoint: &E,
        query: &str,
    ) -> Result<T> {
        self.read_signed::<E, T>(
            endpoint,
            query,
            !E::ACCESS.is_public(),
            &self.read_retry_delays,
        )
        .await
    }

    /// [`Self::read`] of a public endpoint that answers an account more than an anonymous caller
    /// (the catalog's offerings: a private host's that its provider allows the account): signed
    /// when the account key is there, anonymous without one, and anonymous again when the backend
    /// does not take the signature (a 401 for a key it does not know yet, or a 426 for a release it
    /// serves only anonymously), as the read was before. The signed read is sent once: one that
    /// gets no answer, or a server error, is read again anonymously, with a notice, as the backend
    /// answers the public read through an outage.
    ///
    /// # Errors
    /// Returns an error if credentials, transport, or the backend reject this request.
    pub async fn read_as_account<E: Endpoint>(
        &self,
        endpoint: &E,
        query: &str,
    ) -> Result<E::Response> {
        if E::ACCESS.is_public() && self.identity().is_ok() {
            match self
                .read_signed::<E, E::Response>(endpoint, query, true, &[])
                .await
            {
                Err(error)
                    if error.downcast_ref::<StatusError>().is_some_and(|error| {
                        matches!(
                            error.status,
                            StatusCode::UNAUTHORIZED | StatusCode::UPGRADE_REQUIRED
                        )
                    }) => {}
                Err(error) if unanswered(&error) => crate::notice(&format!(
                    "GET {}: the read with the account key failed ({}); it is read again without it, so no private host's offering is listed",
                    crate::escape_control(&endpoint.path()),
                    crate::escape_control(&format!("{error:#}")),
                )),
                read => return read,
            }
        }
        self.read_signed::<E, E::Response>(
            endpoint,
            query,
            !E::ACCESS.is_public(),
            &self.read_retry_delays,
        )
        .await
    }

    /// [`Self::read_as`], `signed` or not, a GET that got no answer sent
    /// again after each of `retry_delays`.
    async fn read_signed<E: Endpoint, T: DeserializeOwned>(
        &self,
        endpoint: &E,
        query: &str,
        signed: bool,
        retry_delays: &[Duration],
    ) -> Result<T> {
        let mut path = endpoint.path();
        if !query.is_empty() {
            path.push('?');
            path.push_str(query);
        }
        let mut delays = retry_delays.iter();
        loop {
            let result = self
                .send::<(), T>(method(E::METHOD), &path, signed, None, None)
                .await
                .map(|answered| answered.value);
            match (result, delays.next()) {
                (Err(error), Some(delay))
                    if E::METHOD == api::Method::Get && got_no_response(&error) =>
                {
                    crate::notice(&format!(
                        "GET {}: no answer ({}); trying again in {} s",
                        crate::escape_control(&path),
                        crate::escape_control(&format!("{error:#}")),
                        delay.as_secs_f32()
                    ));
                    tokio::time::sleep(*delay).await;
                }
                (result, _) => return result,
            }
        }
    }

    /// Call a mutating endpoint with a key the command derives itself, so a
    /// failure carries no retry hint.
    /// # Errors
    /// Returns an error if credentials, transport, or the backend reject this request.
    pub async fn write<E: Endpoint>(
        &self,
        endpoint: &E,
        body: &E::Request,
        idempotency_key: Option<&str>,
    ) -> Result<E::Response> {
        self.write_as::<E, E::Response>(endpoint, body, idempotency_key)
            .await
    }

    /// [`Self::write`] with its answer read into `T`, as [`Self::read_as`].
    /// # Errors
    /// Returns an error if credentials, transport, or the backend reject this request.
    pub async fn write_as<E: Endpoint, T: DeserializeOwned>(
        &self,
        endpoint: &E,
        body: &E::Request,
        idempotency_key: Option<&str>,
    ) -> Result<T> {
        self.send(
            method(E::METHOD),
            &endpoint.path(),
            !E::ACCESS.is_public(),
            E::HAS_BODY.then_some(body),
            idempotency_key,
        )
        .await
        .map(|answered| answered.value)
    }

    /// Call a mutating endpoint with a key the user can repeat. A failure
    /// that repeating may cure, or whose outcome is unknown, says how to
    /// retry exactly this mutation: [`is_transient`] tells them apart. A
    /// rejection such as 400, 403, 404, a conflict or a 429 for a used-up
    /// quota is returned as it is: the same request would be rejected
    /// again. Only a key already spent on a different request gets its own
    /// hint.
    /// # Errors
    /// Returns an error if credentials, transport, or the backend reject this request.
    pub async fn write_retryable<E: Endpoint>(
        &self,
        endpoint: &E,
        body: &E::Request,
        key: &MutationKey,
    ) -> Result<E::Response> {
        self.write_retryable_answered(endpoint, body, key)
            .await
            .map(|answered| answered.value)
    }

    /// [`Self::write_retryable`], with when the server answered, which
    /// tells an answer to an earlier request with the same key.
    /// # Errors
    /// Returns an error if credentials, transport, or the backend reject this request.
    pub async fn write_retryable_answered<E: Endpoint>(
        &self,
        endpoint: &E,
        body: &E::Request,
        key: &MutationKey,
    ) -> Result<Answered<E::Response>> {
        self.send(
            method(E::METHOD),
            &endpoint.path(),
            !E::ACCESS.is_public(),
            E::HAS_BODY.then_some(body),
            Some(&key.key),
        )
        .await
        .map_err(|error| {
            if is_transient(&error) {
                error.context(format!(
                    "this exact mutation may be retried with {}",
                    key.retry
                ))
            } else if rejection_code(&error) == Some(IDEMPOTENCY_KEY_REUSED) {
                error.context(
                    "this idempotency key was used before for a different request; repeat that request unchanged, or leave out --idempotency-key",
                )
            } else {
                error
            }
        })
    }

    async fn send<B: Serialize + ?Sized, T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
        authenticated: bool,
        body: Option<&B>,
        idempotency_key: Option<&str>,
    ) -> Result<Answered<T>> {
        let url = self
            .base_url
            .join(path.trim_start_matches('/'))
            .with_context(|| format!("construct API URL for {path}"))?;
        let encoded_body = body
            .map(serde_json::to_vec)
            .transpose()
            .context("encode API request body")?
            .unwrap_or_default();
        let target = url.query().map_or_else(
            || url.path().to_owned(),
            |query| format!("{}?{query}", url.path()),
        );
        let mut request = self.client.request(method.clone(), url);
        if authenticated {
            let identity = self.identity()?;
            let timestamp = Utc::now().timestamp_millis();
            let nonce = Uuid::now_v7();
            let canonical = canonical_request(&RequestSignatureInput {
                auth_key_id: &identity.key_id,
                timestamp_unix_ms: timestamp,
                nonce,
                method: method.as_str(),
                target: &target,
                body: &encoded_body,
                idempotency_key,
            });
            let signature = identity.sign(&canonical);
            request = request
                .header(AUTH_KEY_ID_HEADER, &identity.key_id)
                .header(REQUEST_TIMESTAMP_HEADER, timestamp)
                .header(REQUEST_NONCE_HEADER, nonce.to_string())
                .header(
                    REQUEST_SIGNATURE_HEADER,
                    URL_SAFE_NO_PAD.encode(signature.to_bytes()),
                );
        }
        if let Some(key) = idempotency_key {
            request = request.header("Idempotency-Key", key);
        }
        if body.is_some() {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(encoded_body);
        }
        let sent = std::time::Instant::now();
        let response = request.send().await.context("send API request")?;
        let status = response.status();
        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        let server_date = response
            .headers()
            .get(reqwest::header::DATE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| DateTime::parse_from_rfc2822(value).ok())
            .map(|date| date.with_timezone(&Utc));
        let bytes = response.bytes().await.context("read API response")?;
        let elapsed = sent.elapsed();
        if !status.is_success() {
            let parsed = serde_json::from_slice::<ErrorResponse>(&bytes).ok();
            let code = parsed.as_ref().map(|error| error.code.clone());
            // The backend's message already names the job it waits for, so
            // only the command to follow it is added.
            let job_id = serde_json::from_slice::<ConflictingJob>(&bytes)
                .ok()
                .and_then(|body| body.job_id);
            let hint = job_id
                .map(|job_id| format!("; follow the job with `ghost job watch {job_id}`"))
                .or_else(|| {
                    (code.as_deref() == Some("trial_limit"))
                        .then(|| "; a deposit lifts the trial's limits".to_owned())
                })
                .unwrap_or_default();
            // The body names the request when the backend sent it; the
            // header does too, also for an error without that body.
            let (detail, request_id) = match parsed {
                Some(error) => (
                    format!("{}: {}", error.code, error.message),
                    error.request_id.or(request_id),
                ),
                None => (
                    String::from_utf8_lossy(&bytes).trim().to_owned(),
                    request_id,
                ),
            };
            let request = request_id
                .as_ref()
                .map(|request_id| format!(" (request {request_id})"))
                .unwrap_or_default();
            let message = format!("API returned {status}: {detail}{hint}{request}");
            return Err(StatusError {
                status,
                code,
                job_id,
                request_id,
                message,
            }
            .into());
        }
        let value = serde_json::from_slice(&bytes).with_context(|| {
            format!(
                "decode successful API response as {}",
                std::any::type_name::<T>()
            )
        })?;
        Ok(Answered {
            value,
            server_date,
            elapsed,
        })
    }
}

/// A response with a non-success status, kept typed so a poller can tell a
/// failing or overloaded server from a rejection.
#[derive(Debug)]
struct StatusError {
    status: StatusCode,
    /// The stable `code` of the backend's error body, when it sent one.
    code: Option<String>,
    /// The job still running on the resource that a conflict names.
    job_id: Option<Uuid>,
    /// The request's ID, from the error body or the `x-request-id` header.
    request_id: Option<String>,
    message: String,
}

impl std::fmt::Display for StatusError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for StatusError {}

/// The job a conflict names in the error body: one still running on the
/// resource, which the request has to wait for.
#[derive(Deserialize)]
struct ConflictingJob {
    job_id: Option<Uuid>,
}

/// Whether repeating a failed request unchanged may succeed: the request got
/// no answer, or the server timed out, was overloaded, throttled the caller,
/// or failed internally. A 429 for a quota, such as `limit_reached` for the
/// daily job limit or `active_auth_key_limit`, is a rejection: the quota does
/// not lift in the moments a retry takes. A 429 without the backend's error
/// body came from something in between and is taken as throttling.
pub fn is_transient(error: &anyhow::Error) -> bool {
    if let Some(error) = error.downcast_ref::<StatusError>() {
        return error.status.is_server_error()
            || error.status == StatusCode::REQUEST_TIMEOUT
            || (error.status == StatusCode::TOO_MANY_REQUESTS
                && error
                    .code
                    .as_deref()
                    .is_none_or(|code| code == RATE_LIMITED));
    }
    got_no_response(error)
}

/// The error code the backend answers a request with when its
/// `Idempotency-Key` was already used for a request with another body.
pub const IDEMPOTENCY_KEY_REUSED: &str = "idempotency_key_reused";

/// The error code of the backend's 429 for a caller sending requests too
/// fast, the one 429 that a later retry may get past.
pub const RATE_LIMITED: &str = "rate_limited";

/// The backend's error code for a rejected request, such as `not_found`.
pub fn rejection_code(error: &anyhow::Error) -> Option<&str> {
    error
        .downcast_ref::<StatusError>()
        .and_then(|error| error.code.as_deref())
}

/// How the backend answered a request it did not carry out: the HTTP
/// status and, from its error body, the stable code, the job a conflict
/// names, and the request's ID.
pub struct Rejection<'e> {
    pub status: u16,
    pub code: Option<&'e str>,
    pub job_id: Option<Uuid>,
    pub request_id: Option<&'e str>,
}

/// The backend's answer that `error` carries, if the request got one.
pub fn rejection(error: &anyhow::Error) -> Option<Rejection<'_>> {
    error.downcast_ref::<StatusError>().map(|error| Rejection {
        status: error.status.as_u16(),
        code: error.code.as_deref(),
        job_id: error.job_id,
        request_id: error.request_id.as_deref(),
    })
}

/// Whether `error` is a request that got no answer: it could not be sent,
/// or no response came back in time.
pub fn got_no_response(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<reqwest::Error>()
        .is_some_and(|error| !error.is_builder())
}

/// Whether `error` says the backend did not answer the request: none came
/// ([`got_no_response`]: a transport error or a timeout), or a server
/// error or a 408 came instead, which the same read sent again may get
/// past.
fn unanswered(error: &anyhow::Error) -> bool {
    error.downcast_ref::<StatusError>().map_or_else(
        || got_no_response(error),
        |error| error.status.is_server_error() || error.status == StatusCode::REQUEST_TIMEOUT,
    )
}

pub(crate) fn is_literal_ip_host(host: &str) -> bool {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::IpAddr>()
        .is_ok()
}

fn method(method: api::Method) -> Method {
    match method {
        api::Method::Get => Method::GET,
        api::Method::Post => Method::POST,
        api::Method::Put => Method::PUT,
        api::Method::Delete => Method::DELETE,
    }
}
