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

pub fn vsock_proxy(address: VsockAddr) -> HttpsConnector<VSockClientBuilder> {
	let cc = rustls::ClientConfig::builder()
		.with_webpki_roots()
		.with_no_client_auth();

	HttpsConnector::from((VSockClientBuilder { address }, cc))
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
