use aws_smithy_http_client::hyper_014::HyperClientBuilder;
use aws_smithy_runtime_api::client::http::SharedHttpClient;
use hyper::{
	Uri,
	client::connect::{Connected, Connection},
	service::Service,
};
use hyper_rustls::{ConfigBuilderExt, HttpsConnector};
use std::{
	io,
	net::Shutdown,
	pin::Pin,
	task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_vsock::{VsockAddr, VsockStream};

pub fn vsock_proxy(address: VsockAddr) -> SharedHttpClient {
	// copied from aws_smithy_http_client::hyper_legacy::default_connector except for the cert roots
	let cc = rustls::ClientConfig::builder()
		.with_cipher_suites(&[
			// TLS1.3 suites
			rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
			rustls::cipher_suite::TLS13_AES_128_GCM_SHA256,
			// TLS1.2 suites
			rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			rustls::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			rustls::cipher_suite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		])
		.with_safe_default_kx_groups()
		.with_safe_default_protocol_versions()
		.expect("Error with the TLS configuration")
		.with_webpki_roots()
		.with_no_client_auth();

	let https_connector = HttpsConnector::from((VSockClientBuilder { address }, cc));

	HyperClientBuilder::new().build(https_connector)
}

#[derive(Debug, Clone, Copy)]
struct VSockClientBuilder {
	address: VsockAddr,
}

struct VSockClient {
	stream: Option<VsockStream>,
}

impl VSockClient {
	pub async fn connect(address: VsockAddr) -> io::Result<Self> {
		let stream = VsockStream::connect(address).await?;

		Ok(Self {
			stream: Some(stream),
		})
	}

	fn with_pinned_stream<T>(&mut self, closure: impl FnOnce(Pin<&mut VsockStream>) -> T) -> T {
		let mut stream = self.stream.take().expect("stream is None");
		let pinned_stream = Pin::new(&mut stream);

		let result = closure(pinned_stream);

		self.stream = Some(stream);
		result
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

impl AsyncRead for VSockClient {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut tokio::io::ReadBuf<'_>,
	) -> Poll<io::Result<()>> {
		self.with_pinned_stream(|stream| stream.poll_read(cx, buf))
	}
}

impl AsyncWrite for VSockClient {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<Result<usize, io::Error>> {
		self.with_pinned_stream(|stream| stream.poll_write(cx, buf))
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
		self.with_pinned_stream(|stream| stream.poll_flush(cx))
	}

	fn poll_shutdown(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
	) -> Poll<Result<(), io::Error>> {
		self.with_pinned_stream(|stream| stream.poll_shutdown(cx))
	}
}

impl Drop for VSockClient {
	fn drop(&mut self) {
		self.stream
			.as_ref()
			.map(|stream| stream.shutdown(Shutdown::Both));
	}
}

impl Connection for VSockClient {
	fn connected(&self) -> Connected {
		Connected::new()
	}
}
