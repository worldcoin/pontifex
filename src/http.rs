use hyper::Client;
use hyper_rustls::HttpsConnector;
use tokio_vsock::VsockAddr;

use crate::utils::http::vsock_proxy;

// Re-export VSockClientBuilder for public use
pub use crate::utils::http::VSockClientBuilder;

/// The CID of the vsock proxy.
pub const VSOCK_PROXY_CID: u32 = 3;

/// A HTTP client that tunnels all requests through the host's vsock proxy.
pub type HttpClient = Client<HttpsConnector<VSockClientBuilder>>;

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
/// use hyper::{Client, Request, Body, body::to_bytes};
/// use pontifex::http;
///
/// #[tokio::main]
/// async fn main() -> anyhow::Result<()> {
///     // The port where your host's vsock proxy listens
///     let client: Client<_> = http::client(8000);
///
///     let req = Request::builder()
///         .method("GET")
///         .uri("https://api.example.com/v1/ping")
///         .body(Body::empty())?;
///
///     let res = client.request(req).await?;
///     let body = to_bytes(res).await?;
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
pub fn client(vsock_proxy_port: u32) -> HttpClient {
	Client::builder().build(vsock_proxy(VsockAddr::new(
		VSOCK_PROXY_CID,
		vsock_proxy_port,
	)))
}
