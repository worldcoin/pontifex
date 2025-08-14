use hyper::Client;
use hyper_rustls::HttpsConnector;
use tokio_vsock::VsockAddr;

use crate::utils::http::{VSockClientBuilder, vsock_proxy};

/// The CID of the vsock proxy.
pub const VSOCK_PROXY_CID: u32 = 3;

#[must_use]
/// Creates a new HTTP client that tunnels requests through a vsock proxy
pub fn client(vsock_proxy_port: u32) -> Client<HttpsConnector<VSockClientBuilder>> {
	Client::builder().build(vsock_proxy(VsockAddr::new(
		VSOCK_PROXY_CID,
		vsock_proxy_port,
	)))
}
