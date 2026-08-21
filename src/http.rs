use std::time::Duration;

use hyper::body::Body;
use hyper_rustls::HttpsConnector;
use hyper_util::{
	client::legacy::Client,
	rt::{TokioExecutor, TokioTimer},
};
use tokio_vsock::VsockAddr;

use crate::utils::http::vsock_proxy_http2;

// Re-export VSockClientBuilder for public use
pub use crate::utils::http::VSockClientBuilder;

/// The CID of the vsock proxy.
pub const VSOCK_PROXY_CID: u32 = 3;

/// A HTTP client that tunnels all requests through the host's vsock proxy.
///
/// `B` is the request body, e.g. `http_body_util::Full<bytes::Bytes>`.
pub type HttpClient<B> = Client<HttpsConnector<VSockClientBuilder>, B>;

#[must_use]
/// Creates an HTTPS client that tunnels all requests through the host's vsock proxy.
///
/// Inside a Nitro Enclave, the parent instance (host) is reachable at CID 3. This
/// client establishes TLS to the upstream server over that vsock stream.
/// The host-side vsock proxy forwards raw bytes to the intended
/// TCP destination.
///
/// TLS is handled by rustls using the webpki root store. There is no client
/// authentication or certificate pinning by default. SNI and hostname
/// verification are derived from the request's URI, and TLS terminates at the
/// upstream service (e.g., `api.example.com` or AWS KMS), not on the proxy.
///
/// Example usage (generic HTTPS request):
/// ```rust,ignore
/// use bytes::Bytes;
/// use http_body_util::{BodyExt, Full};
/// use hyper::Request;
/// use pontifex::http::{self, HttpClient};
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     // The port where your host's vsock proxy listens
///     let client: HttpClient<Full<Bytes>> = http::client(8000);
///
///     let req = Request::builder()
///         .method("GET")
///         .uri("https://api.example.com/v1/ping")
///         .body(Full::default())?;
///
///     let res = client.request(req).await?;
///     let body = res.into_body().collect().await?.to_bytes();
///     println!("{}", String::from_utf8_lossy(&body));
///     Ok(())
/// }
/// ```
///
/// Notes:
/// - For non-AWS APIs, add your own auth headers/tokens to requests.
/// - For AWS services, prefer the typed AWS SDK clients and configure them to
///   use this HTTPS-over-vsock transport (see `kms::client`).
/// - The connector ignores the dial target from the URI and always connects to
///   the fixed vsock address (CID 3 + `vsock_proxy_port`), while preserving
///   Host/SNI for end-to-end TLS to the upstream.
pub fn client<B>(vsock_proxy_port: u32) -> HttpClient<B>
where
	B: Body + Send,
	B::Data: Send,
{
	client_http2_only(
		vsock_proxy_port,
		&Http2ClientConfig {
			keep_alive_interval: Some(Duration::from_secs(30)),
			keep_alive_timeout: Duration::from_secs(10),
			..Http2ClientConfig::default()
		},
	)
}

/// Configuration for an HTTPS client that tunnels all requests through the host's vsock proxy and only uses HTTP/2.
pub struct Http2ClientConfig {
	initial_stream_window_size: Option<u32>,
	initial_connection_window_size: Option<u32>,
	adaptive_window: bool,
	keep_alive_interval: Option<Duration>,
	keep_alive_timeout: Duration,
}

impl Default for Http2ClientConfig {
	fn default() -> Self {
		Self {
			initial_stream_window_size: None,
			initial_connection_window_size: None,
			adaptive_window: false,
			keep_alive_interval: None,
			// Hyper's default is 20 seconds
			keep_alive_timeout: Duration::from_secs(20),
		}
	}
}

/// Creates an HTTPS client that tunnels all requests through the host's vsock proxy and only uses HTTP/2.
#[must_use]
pub fn client_http2_only<B>(vsock_proxy_port: u32, config: &Http2ClientConfig) -> HttpClient<B>
where
	B: Body + Send,
	B::Data: Send,
{
	let mut builder = Client::builder(TokioExecutor::new());

	builder
		// Unlike hyper 0.14, hyper-util does not install a timer of its own, and silently drops
		// keep-alives and pool idle timeouts without one.
		.timer(TokioTimer::new())
		.pool_timer(TokioTimer::new())
		.http2_only(true)
		.http2_adaptive_window(config.adaptive_window)
		.http2_keep_alive_interval(config.keep_alive_interval)
		.http2_keep_alive_timeout(config.keep_alive_timeout)
		.http2_initial_stream_window_size(config.initial_stream_window_size)
		.http2_initial_connection_window_size(config.initial_connection_window_size);

	builder.build(vsock_proxy_http2(VsockAddr::new(
		VSOCK_PROXY_CID,
		vsock_proxy_port,
	)))
}
