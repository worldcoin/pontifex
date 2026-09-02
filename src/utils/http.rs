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
) -> ConnectTimeout<HttpsConnector<VSockClientBuilder>> {
	ConnectTimeout {
		inner: tls_builder()
			.enable_http1()
			.wrap_connector(VSockClientBuilder { address }),
		timeout: connect_timeout,
	}
}

/// An HTTPS-over-vsock connector that advertises only `h2` over ALPN.
#[cfg(feature = "http")]
pub fn vsock_proxy_http2(
	address: VsockAddr,
	connect_timeout: Option<Duration>,
) -> ConnectTimeout<HttpsConnector<VSockClientBuilder>> {
	ConnectTimeout {
		inner: tls_builder()
			.enable_http2()
			.wrap_connector(VSockClientBuilder { address }),
		timeout: connect_timeout,
	}
}

/// Provides a TLS connection builder which explicitly rejects non-HTTPs connections. The
/// host side cannot be considered trusted, so this rejects HTTP-only connections.
fn tls_builder() -> HttpsConnectorBuilder<hyper_rustls::builderstates::WantsProtocols1> {
	let config = rustls::ClientConfig::builder_with_provider(Arc::new(
		rustls::crypto::ring::default_provider(),
	))
	.with_safe_default_protocol_versions()
	.expect("ring supports the default protocol versions")
	.with_webpki_roots()
	.with_no_client_auth();

	HttpsConnectorBuilder::new()
		.with_tls_config(config)
		.https_only()
}

/// A connector builder for creating vsock-based HTTP(S) connections.
///
/// This type implements hyper's `Service` trait to create connections through
/// a vsock address, typically used for communication with the host from within
/// a Nitro Enclave.
#[derive(Debug, Clone, Copy)]
pub struct VSockClientBuilder {
	address: VsockAddr,
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
		Box::pin(VSockClient::connect(self.address))
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

/// Limits the time establishing a connection.
#[derive(Debug, Clone)]
pub struct ConnectTimeout<C> {
	inner: C,
	timeout: Option<Duration>,
}

#[cfg(any(feature = "http", test))]
impl<C> ConnectTimeout<C> {
	/// The bound this connector applies, or `None` if connects are unbounded.
	#[must_use]
	pub const fn timeout(&self) -> Option<Duration> {
		self.timeout
	}
}

impl<C> Service<Uri> for ConnectTimeout<C>
where
	C: Service<Uri>,
	C::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
	C::Response: Send + 'static,
	C::Future: Send + 'static,
{
	type Response = C::Response;
	type Error = Box<dyn std::error::Error + Send + Sync>;
	type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

	fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
		self.inner.poll_ready(cx).map_err(Into::into)
	}

	fn call(&mut self, uri: Uri) -> Self::Future {
		let target = uri.clone();
		let connect = self.inner.call(uri);

		let Some(timeout) = self.timeout else {
			return Box::pin(async move { connect.await.map_err(Into::into) });
		};

		Box::pin(async move {
			tokio::time::timeout(timeout, connect)
				.await
				.map_err(|_| -> Self::Error {
					io::Error::new(
						io::ErrorKind::TimedOut,
						format!("vsock dial and TLS handshake to {target} exceeded {timeout:?}"),
					)
					.into()
				})?
				.map_err(Into::into)
		})
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	/// A connector whose future never resolves, standing in for a proxy that accepts the vsock
	/// connection and then stalls partway through the TLS handshake.
	#[derive(Clone)]
	struct Stalls;

	impl Service<Uri> for Stalls {
		type Response = ();
		type Error = io::Error;
		type Future = Pin<Box<dyn Future<Output = Result<(), io::Error>> + Send>>;

		fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
			Poll::Ready(Ok(()))
		}

		fn call(&mut self, _: Uri) -> Self::Future {
			Box::pin(std::future::pending())
		}
	}

	fn target() -> Uri {
		Uri::from_static("https://kms.eu-west-1.amazonaws.com")
	}

	/// The KMS path passes its own bound in; dropping it on the floor would silently unbound it.
	#[cfg(feature = "kms")]
	#[test]
	fn the_http1_connector_keeps_the_bound_it_was_given() {
		let connector = vsock_proxy_http1(VsockAddr::new(3, 8000), Some(Duration::from_secs(7)));

		assert_eq!(connector.timeout(), Some(Duration::from_secs(7)));
	}

	#[tokio::test(start_paused = true)]
	async fn a_stalled_connect_is_bounded() {
		let mut connector = ConnectTimeout {
			inner: Stalls,
			timeout: Some(Duration::from_secs(5)),
		};

		let err = connector
			.call(target())
			.await
			.expect_err("a connect that never resolves must fail");
		let err = err.downcast_ref::<io::Error>().expect("an io error");

		assert_eq!(err.kind(), io::ErrorKind::TimedOut);
		// The message has to name the target, or a dead proxy and a dead upstream look identical.
		assert!(
			err.to_string().contains("kms.eu-west-1.amazonaws.com"),
			"got {err}"
		);
	}

	/// hyper-rustls rejects a non-HTTPS URI before it reaches the inner connector, so this never
	/// touches vsock.
	#[cfg(feature = "kms")]
	#[tokio::test]
	async fn a_plaintext_uri_is_refused_rather_than_forwarded() {
		let result = vsock_proxy_http1(VsockAddr::new(3, 8000), Some(Duration::from_secs(1)))
			.call(Uri::from_static("http://kms.eu-west-1.amazonaws.com"))
			.await;

		let Err(err) = result else {
			panic!("an http:// URI must not be forwarded to the host proxy in the clear")
		};

		assert!(err.to_string().contains("scheme"), "got {err}");
	}

	#[tokio::test(start_paused = true)]
	async fn a_stalled_connect_without_a_timeout_is_left_alone() {
		let mut connector = ConnectTimeout {
			inner: Stalls,
			timeout: None,
		};

		assert!(
			tokio::time::timeout(Duration::from_secs(30), connector.call(target()))
				.await
				.is_err(),
			"no timeout was configured, so nothing should bound the connect"
		);
	}
}
