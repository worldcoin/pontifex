use std::fmt::Display;
#[cfg(feature = "client")]
use tokio_vsock::VsockAddr;
#[cfg(any(feature = "client", feature = "server"))]
use {
	std::{
		io,
		net::Shutdown,
		ops::{Deref, DerefMut},
	},
	tokio::io::AsyncReadExt,
	tokio_vsock::VsockStream,
};

#[cfg(any(feature = "http", feature = "kms"))]
pub mod http;

/// The piece of data that was being read/written when an error occurred.
#[derive(Debug)]
#[allow(
	dead_code,
	reason = "CodingKey gets re-exported in client.rs and server.rs, but clippy doesn't know that"
)]
pub enum CodingKey {
	/// The length of the data.
	Length,
	/// The data itself.
	Payload,
}

impl Display for CodingKey {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Length => write!(f, "length"),
			Self::Payload => write!(f, "payload"),
		}
	}
}

#[cfg(any(feature = "server", feature = "client"))]
pub struct Stream {
	stream: VsockStream,
}

#[cfg(any(feature = "server", feature = "client"))]
impl Stream {
	#[cfg(feature = "server")]
	pub const fn new(stream: VsockStream) -> Self {
		Self { stream }
	}

	#[cfg(feature = "client")]
	pub async fn connect(cid: u32, port: u32) -> io::Result<Self> {
		let stream = VsockStream::connect(VsockAddr::new(cid, port)).await?;

		Ok(Self { stream })
	}

	#[cfg(any(feature = "client", feature = "server"))]
	pub async fn read_exact(&mut self, size: u64) -> io::Result<Vec<u8>> {
		let mut buf = vec![0; usize::try_from(size).map_err(|_| io::ErrorKind::InvalidInput)?];
		self.stream.read_exact(&mut buf).await?;

		Ok(buf)
	}
}

#[cfg(any(feature = "server", feature = "client"))]
impl Deref for Stream {
	type Target = VsockStream;

	fn deref(&self) -> &Self::Target {
		&self.stream
	}
}

#[cfg(any(feature = "server", feature = "client"))]
impl DerefMut for Stream {
	fn deref_mut(&mut self) -> &mut Self::Target {
		&mut self.stream
	}
}

#[cfg(any(feature = "server", feature = "client"))]
impl Drop for Stream {
	fn drop(&mut self) {
		_ = self.stream.shutdown(Shutdown::Both);
	}
}
