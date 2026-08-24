use std::{
	borrow::Cow,
	collections::HashMap,
	error::Error,
	io,
	sync::{
		PoisonError, RwLock,
		atomic::{AtomicBool, Ordering},
	},
	time::Duration,
};

use aws_sdk_kms::config::SharedCredentialsProvider;
use aws_smithy_runtime_api::client::{
	connection::{CaptureSmithyConnection, ConnectionMetadata},
	connector_metadata::ConnectorMetadata,
	http::{
		HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings, SharedHttpConnector,
	},
	orchestrator::{HttpRequest, HttpResponse},
	result::ConnectorError,
	runtime_components::RuntimeComponents,
};
use aws_smithy_types::{body::SdkBody, timeout::TimeoutConfig};
use aws_types::SdkConfig;
use hyper_rustls::HttpsConnector;
use hyper_util::{
	client::legacy::{
		Client,
		connect::{CaptureConnection, capture_connection},
	},
	rt::{TokioExecutor, TokioTimer},
};
use tokio_vsock::VsockAddr;

use crate::utils::http::{ConnectTimeout, VSockClientBuilder, vsock_proxy_http1};

/// The CID of the vsock proxy.
pub const VSOCK_PROXY_CID: u32 = 3;

/// Applied when the caller's `SdkConfig` carries no timeout of its own. Connection timeout.
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
/// Timeout on reading the response headers.
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(30);
/// Bounds one attempt end to end.
const DEFAULT_ATTEMPT_TIMEOUT: Duration = Duration::from_mins(1);

/// Credentials to use for KMS requests.
pub struct Credentials {
	access_key_id: String,
	secret_access_key: String,
	session_token: Option<String>,
}

impl Credentials {
	/// Creates a new set of KMS credentials.
	pub fn new(
		access_key_id: impl Into<String>,
		secret_access_key: impl Into<String>,
		session_token: Option<String>,
	) -> Self {
		Self {
			session_token,
			access_key_id: access_key_id.into(),
			secret_access_key: secret_access_key.into(),
		}
	}
}

/// Creates a new KMS client. Re-uses a TLS connection pool, avoid re-creating it.
///
/// # Timeouts
///
/// If no timeouts are set in the `SdkConfig`, sensible defaults will be enforced here.
#[must_use]
pub fn client(
	config: &SdkConfig,
	credentials: Credentials,
	vsock_proxy_port: u32,
) -> aws_sdk_kms::Client {
	let builder = config
		.to_builder()
		.timeout_config(bounded_timeouts(config.timeout_config()))
		.credentials_provider(SharedCredentialsProvider::new(
			aws_sdk_kms::config::Credentials::new(
				credentials.access_key_id,
				credentials.secret_access_key,
				credentials.session_token,
				None,
				"SDK",
			),
		))
		.http_client(VSockHttpClient::new(VsockAddr::new(
			VSOCK_PROXY_CID,
			vsock_proxy_port,
		)))
		.build();

	aws_sdk_kms::Client::new(&builder)
}

/// Fills in any timeout the caller left unset
fn bounded_timeouts(configured: Option<&TimeoutConfig>) -> TimeoutConfig {
	configured
		.map(TimeoutConfig::to_builder)
		.unwrap_or_default()
		.take_unset_from(
			TimeoutConfig::builder()
				.connect_timeout(DEFAULT_CONNECT_TIMEOUT)
				.read_timeout(DEFAULT_READ_TIMEOUT)
				.operation_attempt_timeout(DEFAULT_ATTEMPT_TIMEOUT),
		)
		.build()
}

/// The connect and read timeouts in force for a request. Always bounded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct Timeouts {
	connect: Duration,
	read: Duration,
}

/// Idle connections one connector keeps per upstream authority. hyper-util's default is unbounded,
/// which an enclave cannot afford.
const MAX_IDLE_CONNECTIONS: usize = 8;

/// Distinct timeout configurations to cache a connector for. A caller that derives a per-request
/// timeout from a remaining deadline would otherwise grow this map without bound.
const MAX_CACHED_CONNECTORS: usize = 8;

/// Routes the AWS SDK's HTTP traffic through the host's vsock proxy.
///
/// The orchestrator asks for a connector on every request attempt, so connectors are cached to
/// keep the underlying connection pool alive across requests.
#[derive(Debug)]
struct VSockHttpClient {
	address: VsockAddr,
	connectors: RwLock<HashMap<Timeouts, SharedHttpConnector>>,
	cache_full_warned: AtomicBool,
}

impl VSockHttpClient {
	fn new(address: VsockAddr) -> Self {
		Self {
			address,
			connectors: RwLock::default(),
			cache_full_warned: AtomicBool::new(false),
		}
	}

	/// Once, not once per request: past the cap this fires at the full request rate.
	fn warn_cache_full(&self) {
		if !self.cache_full_warned.swap(true, Ordering::Relaxed) {
			tracing::warn!(
				cap = MAX_CACHED_CONNECTORS,
				"too many distinct timeout configurations; further ones get their own pool"
			);
		}
	}
}

impl HttpClient for VSockHttpClient {
	fn http_connector(
		&self,
		settings: &HttpConnectorSettings,
		_: &RuntimeComponents,
	) -> SharedHttpConnector {
		// An explicit setting always wins; the default only fills a gap.
		let timeouts = Timeouts {
			connect: settings
				.connect_timeout()
				.unwrap_or(DEFAULT_CONNECT_TIMEOUT),
			read: settings.read_timeout().unwrap_or(DEFAULT_READ_TIMEOUT),
		};

		let cacheable = {
			let connectors = self
				.connectors
				.read()
				.unwrap_or_else(PoisonError::into_inner);

			if let Some(connector) = connectors.get(&timeouts) {
				return connector.clone();
			}

			connectors.len() < MAX_CACHED_CONNECTORS
		};

		// Built before taking the write lock: this constructs a rustls `ClientConfig`, and holding
		// an exclusive lock across that would serialize every concurrent KMS call behind it.
		let connector = SharedHttpConnector::new(VSockConnector::new(self.address, timeouts));

		if !cacheable {
			self.warn_cache_full();

			return connector;
		}

		self.connectors
			.write()
			.unwrap_or_else(PoisonError::into_inner)
			.entry(timeouts)
			.or_insert(connector)
			.clone()
	}

	fn connector_metadata(&self) -> Option<ConnectorMetadata> {
		Some(ConnectorMetadata::new(
			"pontifex-vsock",
			Some(Cow::Borrowed(env!("CARGO_PKG_VERSION"))),
		))
	}
}

#[derive(Debug)]
struct VSockConnector {
	client: Client<ConnectTimeout<HttpsConnector<VSockClientBuilder>>, SdkBody>,
	read_timeout: Duration,
}

#[cfg(test)]
static CONNECTORS_BUILT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

impl VSockConnector {
	fn new(address: VsockAddr, timeouts: Timeouts) -> Self {
		#[cfg(test)]
		CONNECTORS_BUILT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

		let mut builder = Client::builder(TokioExecutor::new());

		builder
			.timer(TokioTimer::new())
			.pool_timer(TokioTimer::new())
			.pool_max_idle_per_host(MAX_IDLE_CONNECTIONS);

		Self {
			client: builder.build(vsock_proxy_http1(address, timeouts.connect)),
			read_timeout: timeouts.read,
		}
	}
}

impl HttpConnector for VSockConnector {
	fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
		let mut request = match request.try_into_http1x() {
			Ok(request) => request,
			Err(err) => return HttpConnectorFuture::ready(Err(ConnectorError::user(err.into()))),
		};

		let captured = capture_connection(&mut request);

		if let Some(sink) = request.extensions().get::<CaptureSmithyConnection>() {
			sink.set_connection_retriever(move || connection_metadata(&captured));
		}

		let target = request.uri().clone();
		let response = self.client.request(request);
		let read_timeout = self.read_timeout;

		HttpConnectorFuture::new(async move {
			let response = await_headers(response, &target, read_timeout)
				.await?
				.map(SdkBody::from_body_1_x);

			HttpResponse::try_from(response).map_err(|err| ConnectorError::other(err.into(), None))
		})
	}
}

/// Bounds the wait for response headers and maps a transport failure onto the SDK's error model.
async fn await_headers<B>(
	response: impl Future<Output = Result<hyper::Response<B>, hyper_util::client::legacy::Error>>,
	target: &hyper::Uri,
	read_timeout: Duration,
) -> Result<hyper::Response<B>, ConnectorError> {
	tokio::time::timeout(read_timeout, response)
		.await
		.map_err(|_| read_timed_out(target, read_timeout))?
		.map_err(|err| {
			let is_connect = err.is_connect();
			classify_error(err, is_connect)
		})
}

/// Addresses are left unset: a vsock peer has no socket address, and nothing on this path
/// populates hyper's `HttpInfo`.
fn connection_metadata(captured: &CaptureConnection) -> Option<ConnectionMetadata> {
	let proxied = captured.connection_metadata().as_ref()?.is_proxied();
	let captured = captured.clone();

	Some(
		ConnectionMetadata::builder()
			.proxied(proxied)
			.poison_fn(move || {
				if let Some(conn) = captured.connection_metadata().as_ref() {
					conn.poison();
				}
			})
			.build(),
	)
}

fn read_timed_out(target: &hyper::Uri, timeout: Duration) -> ConnectorError {
	ConnectorError::timeout(Box::new(io::Error::new(
		io::ErrorKind::TimedOut,
		format!("no response headers from {target} within {timeout:?} (connect included)"),
	)))
}

/// Classifies a transport failure so the SDK's retry policy can act on it.
///
/// `is_io` and `is_timeout` are the two classes the SDK retries; everything else is terminal.
fn classify_error<E: Error + Send + Sync + 'static>(err: E, is_connect: bool) -> ConnectorError {
	if let Some(hyper_err) = find_source::<hyper::Error>(&err) {
		if hyper_err.is_timeout() {
			return ConnectorError::timeout(err.into());
		}

		if hyper_err.is_user() {
			return ConnectorError::user(err.into());
		}

		if hyper_err.is_closed() || hyper_err.is_canceled() || hyper_err.is_incomplete_message() {
			return ConnectorError::io(err.into());
		}
	}

	if let Some(rustls::Error::InvalidCertificate(cert_err)) = find_source::<rustls::Error>(&err) {
		tracing::warn!(
			error = ?cert_err,
			"upstream certificate rejected; not retrying"
		);

		return ConnectorError::other(err.into(), None);
	}

	if let Some(io_err) = find_source::<io::Error>(&err) {
		if io_err.kind() == io::ErrorKind::TimedOut {
			return ConnectorError::timeout(err.into());
		}

		return ConnectorError::io(err.into());
	}

	if is_connect {
		return ConnectorError::io(err.into());
	}

	tracing::warn!(
		error = ?err,
		"unrecognised transport error from hyper; treating it as non-retryable"
	);

	ConnectorError::other(err.into(), None)
}

fn find_source<'a, E: Error + 'static>(err: &'a (dyn Error + 'static)) -> Option<&'a E> {
	let mut next = Some(err);

	while let Some(err) = next {
		if let Some(matched) = err.downcast_ref::<E>() {
			return Some(matched);
		}

		// `io::Error::source()` returns the source of the error it wraps, skipping the wrapped
		// error itself, so step into it explicitly or everything behind one is invisible.
		next = err
			.downcast_ref::<io::Error>()
			.and_then(io::Error::get_ref)
			.map(|inner| inner as &(dyn Error + 'static))
			.or_else(|| err.source());
	}

	None
}

#[cfg(test)]
mod tests {
	use super::*;

	#[derive(Debug)]
	struct Wrapper(io::Error);

	impl std::fmt::Display for Wrapper {
		fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
			f.write_str("wrapper")
		}
	}

	impl Error for Wrapper {
		fn source(&self) -> Option<&(dyn Error + 'static)> {
			Some(&self.0)
		}
	}

	/// An error with nothing the classifier recognises in its chain.
	#[derive(Debug)]
	struct Opaque;

	impl std::fmt::Display for Opaque {
		fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
			f.write_str("opaque")
		}
	}

	impl Error for Opaque {}

	/// Transient transport failures reach us wrapped, and are only retried if they are recognised.
	#[test]
	fn find_source_walks_the_error_chain() {
		let err = Wrapper(io::Error::from(io::ErrorKind::ConnectionReset));

		assert_eq!(
			find_source::<io::Error>(&err).map(io::Error::kind),
			Some(io::ErrorKind::ConnectionReset)
		);
		assert!(find_source::<std::fmt::Error>(&err).is_none());
	}

	#[test]
	fn an_unset_timeout_config_is_fully_bounded() {
		let bounded = bounded_timeouts(None);

		assert_eq!(bounded.connect_timeout(), Some(DEFAULT_CONNECT_TIMEOUT));
		assert_eq!(bounded.read_timeout(), Some(DEFAULT_READ_TIMEOUT));
		assert_eq!(
			bounded.operation_attempt_timeout(),
			Some(DEFAULT_ATTEMPT_TIMEOUT)
		);
	}

	/// A caller's own timeout has to win, or configuring one would be pointless.
	#[test]
	fn a_configured_timeout_is_not_overridden() {
		let configured = TimeoutConfig::builder()
			.read_timeout(Duration::from_secs(1))
			.build();

		let bounded = bounded_timeouts(Some(&configured));

		assert_eq!(bounded.read_timeout(), Some(Duration::from_secs(1)));
		assert_eq!(bounded.connect_timeout(), Some(DEFAULT_CONNECT_TIMEOUT));
	}

	/// `disabled()` is an explicit choice, distinct from leaving a timeout unset.
	#[test]
	fn explicitly_disabled_timeouts_stay_disabled() {
		let bounded = bounded_timeouts(Some(&TimeoutConfig::disabled()));

		assert_eq!(bounded.read_timeout(), None);
		assert_eq!(bounded.connect_timeout(), None);
	}

	#[tokio::test(start_paused = true)]
	async fn headers_that_never_arrive_time_out() {
		let never = std::future::pending::<
			Result<hyper::Response<()>, hyper_util::client::legacy::Error>,
		>();

		let err = await_headers(
			never,
			&hyper::Uri::from_static("https://kms.eu-west-1.amazonaws.com"),
			Duration::from_secs(5),
		)
		.await
		.expect_err("headers that never arrive must time out");

		assert!(err.is_timeout(), "got {err:?}");
	}

	#[test]
	fn a_read_timeout_names_its_target() {
		let err = read_timed_out(
			&hyper::Uri::from_static("https://kms.eu-west-1.amazonaws.com/"),
			Duration::from_secs(5),
		);

		assert!(format!("{err:?}").contains("kms.eu-west-1"), "got {err:?}");
	}

	#[test]
	fn find_source_sees_through_an_io_error() {
		let err = io::Error::other(rustls::Error::InvalidCertificate(
			rustls::CertificateError::UnknownIssuer,
		));

		assert!(find_source::<rustls::Error>(&err).is_some());
	}

	#[test]
	fn a_rejected_certificate_is_terminal() {
		let err = classify_error(
			io::Error::other(rustls::Error::InvalidCertificate(
				rustls::CertificateError::UnknownIssuer,
			)),
			true,
		);

		assert!(
			err.is_other(),
			"a bad certificate must not be retried, got {err:?}"
		);
	}

	#[test]
	fn a_wrapped_connection_reset_is_retryable() {
		let err = classify_error(
			Wrapper(io::Error::from(io::ErrorKind::ConnectionReset)),
			false,
		);

		assert!(
			err.is_io(),
			"a reset connection must be retried, got {err:?}"
		);
	}

	#[test]
	fn a_timed_out_connect_is_classified_as_a_timeout() {
		let err = classify_error(Wrapper(io::Error::from(io::ErrorKind::TimedOut)), true);

		assert!(err.is_timeout(), "got {err:?}");
	}

	#[test]
	fn a_connect_failure_with_no_io_source_is_still_retryable() {
		let err = classify_error(Opaque, true);

		assert!(err.is_io(), "got {err:?}");
	}

	#[test]
	fn an_unrecognized_failure_is_terminal() {
		let err = classify_error(Opaque, false);

		assert!(err.is_other(), "got {err:?}");
	}

	/// `CONNECTORS_BUILT` is process-wide, so every test that can build a connector has to go
	/// through this or the counting tests race each other.
	static COUNTER_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

	/// Runs `body` with exclusive access to `CONNECTORS_BUILT`, returning how many connectors it
	/// built.
	fn counting_connectors(body: impl FnOnce()) -> usize {
		use std::sync::atomic::Ordering;

		let _guard = COUNTER_LOCK.lock().unwrap_or_else(PoisonError::into_inner);
		let before = CONNECTORS_BUILT.load(Ordering::Relaxed);
		body();

		CONNECTORS_BUILT.load(Ordering::Relaxed) - before
	}

	/// Re-resolving a connector has to hand back the existing one; building a fresh one would give
	/// every request its own connection pool and reconnect each time.
	#[test]
	fn a_repeated_timeout_configuration_reuses_its_connector() {
		use aws_smithy_runtime_api::client::runtime_components::RuntimeComponentsBuilder;

		let client = VSockHttpClient::new(VsockAddr::new(VSOCK_PROXY_CID, 8000));
		let components = RuntimeComponentsBuilder::for_tests().build().unwrap();
		let settings = HttpConnectorSettings::builder()
			.connect_timeout(Duration::from_secs(3))
			.build();
		let other = HttpConnectorSettings::builder()
			.connect_timeout(Duration::from_secs(7))
			.build();

		let built = counting_connectors(|| {
			client.http_connector(&settings, &components);
			client.http_connector(&settings, &components);
			client.http_connector(&other, &components);
		});

		assert_eq!(
			built, 2,
			"two distinct timeout configurations, so exactly two connectors"
		);
	}

	#[test]
	fn the_connector_cache_is_bounded() {
		use aws_smithy_runtime_api::client::runtime_components::RuntimeComponentsBuilder;

		let client = VSockHttpClient::new(VsockAddr::new(VSOCK_PROXY_CID, 8000));
		let components = RuntimeComponentsBuilder::for_tests().build().unwrap();

		counting_connectors(|| {
			for millis in 0..(MAX_CACHED_CONNECTORS as u64 + 5) {
				let settings = HttpConnectorSettings::builder()
					.read_timeout(Duration::from_millis(millis + 1))
					.build();

				client.http_connector(&settings, &components);
			}
		});

		assert_eq!(
			client
				.connectors
				.read()
				.unwrap_or_else(PoisonError::into_inner)
				.len(),
			MAX_CACHED_CONNECTORS
		);
	}
}
