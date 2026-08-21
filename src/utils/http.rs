use std::{
	io,
	net::Shutdown,
	pin::Pin,
	sync::Arc,
	task::{Context, Poll},
	time::Duration,
};

use hyper::{
	Uri,
	rt::{Read, ReadBufCursor, Write},
};
use hyper_rustls::{ConfigBuilderExt, HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
	client::legacy::connect::{Connected, Connection},
	rt::TokioIo,
};
use tokio_vsock::{VsockAddr, VsockStream};
use tower_service::Service;

/// An HTTPS-over-vsock connector for HTTP/1.1.
#[cfg(feature = "kms")]
pub fn vsock_proxy_http1(
	address: VsockAddr,
	connect_timeout: Option<Duration>,
) -> HttpsConnector<VSockClientBuilder> {
	tls_builder()
		.enable_http1()
		.wrap_connector(VSockClientBuilder {
			address,
			connect_timeout,
		})
}

/// An HTTPS-over-vsock connector that advertises only `h2` over ALPN.
#[cfg(feature = "http")]
pub fn vsock_proxy_http2(address: VsockAddr) -> HttpsConnector<VSockClientBuilder> {
	tls_builder()
		.enable_http2()
		.wrap_connector(VSockClientBuilder {
			address,
			connect_timeout: None,
		})
}

fn tls_builder() -> HttpsConnectorBuilder<hyper_rustls::builderstates::WantsProtocols1> {
	// Naming the provider avoids rustls' "could not determine the process-level `CryptoProvider`"
	// panic, which fires whenever something else in the tree also enables `aws_lc_rs`.
	let config = rustls::ClientConfig::builder_with_provider(Arc::new(
		rustls::crypto::ring::default_provider(),
	))
	.with_safe_default_protocol_versions()
	.expect("ring supports the default protocol versions")
	.with_webpki_roots()
	.with_no_client_auth();

	HttpsConnectorBuilder::new()
		.with_tls_config(config)
		.https_or_http()
}

/// A connector builder for creating vsock-based HTTP(S) connections.
///
/// This type implements hyper's `Service` trait to create connections through
/// a vsock address, typically used for communication with the host from within
/// a Nitro Enclave.
#[derive(Debug, Clone, Copy)]
pub struct VSockClientBuilder {
	address: VsockAddr,
	connect_timeout: Option<Duration>,
}

pub struct VSockClient {
	io: TokioIo<VsockStream>,
}

impl VSockClient {
	pub async fn connect(address: VsockAddr) -> io::Result<Self> {
		let stream = VsockStream::connect(address).await?;

		Ok(Self {
			io: TokioIo::new(stream),
		})
	}
}

impl Service<Uri> for VSockClientBuilder {
	type Response = VSockClient;
	type Error = io::Error;
	type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

	fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		Poll::Ready(Ok(()))
	}

	fn call(&mut self, _: Uri) -> Self::Future {
		let address = self.address;

		let Some(timeout) = self.connect_timeout else {
			return Box::pin(VSockClient::connect(address));
		};

		Box::pin(async move {
			tokio::time::timeout(timeout, VSockClient::connect(address))
				.await
				.map_err(|_| {
					io::Error::new(
						io::ErrorKind::TimedOut,
						format!("vsock connect to {address:?} timed out after {timeout:?}"),
					)
				})?
		})
	}
}

impl Read for VSockClient {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: ReadBufCursor<'_>,
	) -> Poll<io::Result<()>> {
		Pin::new(&mut self.io).poll_read(cx, buf)
	}
}

impl Write for VSockClient {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<Result<usize, io::Error>> {
		Pin::new(&mut self.io).poll_write(cx, buf)
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
		Pin::new(&mut self.io).poll_flush(cx)
	}

	fn poll_shutdown(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Result<(), io::Error>> {
		Pin::new(&mut self.io).poll_shutdown(cx)
	}
}

impl Drop for VSockClient {
	fn drop(&mut self) {
		_ = self.io.inner().shutdown(Shutdown::Both);
	}
}

impl Connection for VSockClient {
	fn connected(&self) -> Connected {
		Connected::new()
	}
}
