use std::{
	collections::HashMap,
	error::Error,
	io,
	sync::{PoisonError, RwLock},
	time::Duration,
};

use aws_sdk_kms::config::SharedCredentialsProvider;
use aws_smithy_runtime_api::client::{
	http::{
		HttpClient, HttpConnector, HttpConnectorFuture, HttpConnectorSettings, SharedHttpConnector,
	},
	orchestrator::{HttpRequest, HttpResponse},
	result::ConnectorError,
	runtime_components::RuntimeComponents,
};
use aws_smithy_types::body::SdkBody;
use aws_types::SdkConfig;
use hyper_rustls::HttpsConnector;
use hyper_util::{
	client::legacy::Client,
	rt::{TokioExecutor, TokioTimer},
};
use tokio_vsock::VsockAddr;

use crate::utils::http::{VSockClientBuilder, vsock_proxy_http1};

/// The CID of the vsock proxy.
pub const VSOCK_PROXY_CID: u32 = 3;

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

/// Creates a new KMS client.
#[must_use]
pub fn client(
	config: &SdkConfig,
	credentials: Credentials,
	vsock_proxy_port: u32,
) -> aws_sdk_kms::Client {
	let builder = config
		.to_builder()
		.credentials_provider(SharedCredentialsProvider::new(
			aws_sdk_kms::config::Credentials::new(
				credentials.access_key_id,
				credentials.secret_access_key,
				credentials.session_token,
				None,
				"SDK",
			),
		))
		.http_client(VSockHttpClient {
			address: VsockAddr::new(VSOCK_PROXY_CID, vsock_proxy_port),
			connectors: RwLock::default(),
		})
		.build();

	aws_sdk_kms::Client::new(&builder)
}

/// The connect and read timeouts the orchestrator resolved for a request.
type Timeouts = (Option<Duration>, Option<Duration>);

/// Routes the AWS SDK's HTTP traffic through the host's vsock proxy.
///
/// The orchestrator asks for a connector on every request attempt, so connectors are cached to
/// keep the underlying connection pool alive across requests. There is one entry per distinct
/// timeout configuration, which in practice means exactly one.
#[derive(Debug)]
struct VSockHttpClient {
	address: VsockAddr,
	connectors: RwLock<HashMap<Timeouts, SharedHttpConnector>>,
}

impl HttpClient for VSockHttpClient {
	fn http_connector(
		&self,
		settings: &HttpConnectorSettings,
		_: &RuntimeComponents,
	) -> SharedHttpConnector {
		let timeouts = (settings.connect_timeout(), settings.read_timeout());

		if let Some(connector) = self
			.connectors
			.read()
			.unwrap_or_else(PoisonError::into_inner)
			.get(&timeouts)
		{
			return connector.clone();
		}

		self.connectors
			.write()
			.unwrap_or_else(PoisonError::into_inner)
			.entry(timeouts)
			.or_insert_with(|| {
				SharedHttpConnector::new(VSockConnector::new(self.address, timeouts))
			})
			.clone()
	}
}

#[derive(Debug)]
struct VSockConnector {
	client: Client<HttpsConnector<VSockClientBuilder>, SdkBody>,
	read_timeout: Option<Duration>,
}

impl VSockConnector {
	fn new(address: VsockAddr, (connect_timeout, read_timeout): Timeouts) -> Self {
		let mut builder = Client::builder(TokioExecutor::new());

		// Unlike hyper 0.14, hyper-util does not install a timer of its own, and silently drops
		// pool idle timeouts without one.
		builder
			.timer(TokioTimer::new())
			.pool_timer(TokioTimer::new());

		Self {
			client: builder.build(vsock_proxy_http1(address, connect_timeout)),
			read_timeout,
		}
	}
}

impl HttpConnector for VSockConnector {
	fn call(&self, request: HttpRequest) -> HttpConnectorFuture {
		let request = match request.try_into_http1x() {
			Ok(request) => request,
			Err(err) => return HttpConnectorFuture::ready(Err(ConnectorError::user(err.into()))),
		};

		let response = self.client.request(request);
		let read_timeout = self.read_timeout;

		HttpConnectorFuture::new(async move {
			let response = match read_timeout {
				Some(timeout) => tokio::time::timeout(timeout, response)
					.await
					.map_err(|_| read_timed_out(timeout))?,
				None => response.await,
			}
			.map_err(classify_error)?
			.map(SdkBody::from_body_1_x);

			HttpResponse::try_from(response).map_err(|err| ConnectorError::other(err.into(), None))
		})
	}
}

fn read_timed_out(timeout: Duration) -> ConnectorError {
	ConnectorError::timeout(Box::new(io::Error::new(
		io::ErrorKind::TimedOut,
		format!("no response headers within {timeout:?}"),
	)))
}

/// Classifies a transport failure so the SDK's retry policy can act on it.
fn classify_error(err: hyper_util::client::legacy::Error) -> ConnectorError {
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

	if err.is_connect() || find_source::<io::Error>(&err).is_some() {
		return ConnectorError::io(err.into());
	}

	ConnectorError::other(err.into(), None)
}

fn find_source<'a, E: Error + 'static>(err: &'a (dyn Error + 'static)) -> Option<&'a E> {
	let mut next = Some(err);

	while let Some(err) = next {
		if let Some(matched) = err.downcast_ref::<E>() {
			return Some(matched);
		}

		next = err.source();
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
}
