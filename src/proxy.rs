//! Host-side vsock-to-TCP proxy with a fixed destination.
//!
//! The enclave's `http` and `kms` clients reach the network by dialing the parent (CID 3) on a
//! vsock port. This forwards each such connection, byte for byte, to one configured TCP
//! destination. TLS terminates inside the enclave, so the proxy only ever sees ciphertext and
//! cannot affect confidentiality; a bug here costs availability.
//!
//! ```rust,ignore
//! use pontifex::proxy::{self, Config};
//!
//! let mut config = Config::new(8000, "kms.eu-central-1.amazonaws.com", 443);
//! config.allowed_cid = Some(enclave_cid);
//! proxy::serve(config, |event| record_metric(event)).await?;
//! ```

use std::{
	convert::Infallible,
	pin::Pin,
	sync::{Arc, Mutex, PoisonError},
	task::{Context, Poll},
	time::Duration,
};

use tokio::{
	io::{AsyncRead, AsyncWrite, ReadBuf},
	net::TcpStream,
	time::Instant,
};
use tokio_vsock::{VsockAddr, VsockListener};

use crate::utils::connections::{self, Accept, Limits, ListenerEvent};

const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;

/// Where the proxy listens and forwards, and how much it admits.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Config {
	/// vsock port the enclave dials on the parent.
	pub port: u32,
	/// Hostname or IP every connection is forwarded to; resolved per connection.
	pub destination_host: String,
	/// TCP port every connection is forwarded to.
	pub destination_port: u16,
	/// Only this CID may connect. `None` admits any peer.
	pub allowed_cid: Option<u32>,
	/// Connections served at once; further ones are dropped and reported.
	pub max_connections: usize,
	/// Bounds resolving and connecting to the destination.
	pub connect_timeout: Duration,
	/// Closes a connection after this long without bytes in either direction. Keep it above
	/// the enclave client's pool idle timeout, so the client retires pooled connections first.
	pub idle_timeout: Duration,
}

impl Config {
	/// A proxy from `port` to `destination_host:destination_port`, admitting any peer.
	#[must_use]
	pub fn new(port: u32, destination_host: impl Into<String>, destination_port: u16) -> Self {
		Self {
			port,
			destination_host: destination_host.into(),
			destination_port,
			allowed_cid: None,
			max_connections: 64,
			connect_timeout: Duration::from_secs(4),
			// hyper's pooled connections idle out after 90 seconds.
			idle_timeout: Duration::from_secs(120),
		}
	}
}

/// Errors that stop the proxy.
#[derive(Debug, thiserror::Error)]
pub enum Error {
	/// The configuration cannot serve any connection.
	#[error("invalid proxy configuration: {0}")]
	InvalidConfig(&'static str),
	/// Failed to bind to the vsock address.
	#[error("failed to bind to vsock port {port}: {source}")]
	Bind {
		/// The configured vsock port.
		port: u32,
		/// The underlying failure.
		source: std::io::Error,
	},
}

/// What happened to one connection, for metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
	/// The peer was not [`Config::allowed_cid`]; the connection was dropped.
	RejectedPeer,
	/// All [`Config::max_connections`] slots were in use; the connection was dropped.
	RejectedCapacity,
	/// Accepting a connection failed; the proxy keeps serving.
	AcceptFailed,
	/// A forwarded connection ended.
	Closed {
		/// Why it ended.
		outcome: Outcome,
		/// From accept to close.
		duration: Duration,
	},
}

/// How a forwarded connection ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
	/// Both sides closed cleanly.
	Completed,
	/// Resolving or connecting to the destination failed.
	ConnectFailed,
	/// Resolving and connecting took longer than [`Config::connect_timeout`].
	ConnectTimedOut,
	/// No bytes moved for [`Config::idle_timeout`].
	IdleTimedOut,
	/// Reading or writing failed after connecting.
	Io,
}

impl From<ListenerEvent> for Event {
	fn from(event: ListenerEvent) -> Self {
		match event {
			ListenerEvent::RejectedPeer => Self::RejectedPeer,
			ListenerEvent::RejectedCapacity => Self::RejectedCapacity,
			ListenerEvent::AcceptFailed => Self::AcceptFailed,
		}
	}
}

/// Serves the proxy until the returned future is dropped, which also closes open connections.
///
/// `on_event` runs on the proxy's tasks for every [`Event`]; keep it cheap, e.g. a counter.
/// Failures are also logged at `warn`.
///
/// # Errors
///
/// Only fails at startup, on an invalid [`Config`] or when the port cannot be bound.
pub async fn serve(
	config: Config,
	on_event: impl Fn(Event) + Send + Sync + 'static,
) -> Result<Infallible, Error> {
	validate(&config)?;
	let listener =
		VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, config.port)).map_err(|source| {
			Error::Bind {
				port: config.port,
				source,
			}
		})?;

	Ok(serve_with(listener, config, on_event).await)
}

const fn validate(config: &Config) -> Result<(), Error> {
	if config.destination_host.is_empty() {
		return Err(Error::InvalidConfig("destination host is empty"));
	}
	if config.destination_port == 0 {
		return Err(Error::InvalidConfig("destination port is 0"));
	}
	if config.max_connections == 0 {
		return Err(Error::InvalidConfig("max_connections is 0"));
	}

	Ok(())
}

async fn serve_with<A>(
	listener: A,
	config: Config,
	on_event: impl Fn(Event) + Send + Sync + 'static,
) -> Infallible
where
	A: Accept,
	A::Stream: AsyncRead + AsyncWrite + Unpin,
{
	let limits = Limits {
		allowed_cid: config.allowed_cid,
		max_connections: config.max_connections,
	};
	let config = Arc::new(config);
	let on_event = Arc::new(on_event);
	let on_listener_event = Arc::clone(&on_event);

	connections::serve(
		listener,
		limits,
		move |event| on_listener_event(event.into()),
		move |stream| {
			let config = Arc::clone(&config);
			let on_event = Arc::clone(&on_event);
			async move {
				let started = Instant::now();
				let outcome = forward(stream, &config).await;
				if outcome != Outcome::Completed {
					tracing::warn!(
						?outcome,
						destination = %config.destination_host,
						"proxied connection failed"
					);
				}
				on_event(Event::Closed {
					outcome,
					duration: started.elapsed(),
				});
			}
		},
	)
	.await
}

async fn forward<S>(downstream: S, config: &Config) -> Outcome
where
	S: AsyncRead + AsyncWrite + Unpin,
{
	let connect = TcpStream::connect((config.destination_host.as_str(), config.destination_port));
	let upstream = match tokio::time::timeout(config.connect_timeout, connect).await {
		Ok(Ok(upstream)) => upstream,
		Ok(Err(_)) => return Outcome::ConnectFailed,
		Err(_) => return Outcome::ConnectTimedOut,
	};
	_ = upstream.set_nodelay(true);

	copy_until_idle(downstream, upstream, config.idle_timeout).await
}

/// Copies both ways until both sides close, an error, or `idle` passes without progress.
async fn copy_until_idle<A, B>(a: A, b: B, idle: Duration) -> Outcome
where
	A: AsyncRead + AsyncWrite + Unpin,
	B: AsyncRead + AsyncWrite + Unpin,
{
	let activity = Activity::new();
	let mut a = Tracked {
		inner: a,
		activity: &activity,
	};
	let mut b = Tracked {
		inner: b,
		activity: &activity,
	};
	let copy = tokio::io::copy_bidirectional(&mut a, &mut b);
	tokio::pin!(copy);

	loop {
		tokio::select! {
			result = &mut copy => return if result.is_ok() { Outcome::Completed } else { Outcome::Io },
			() = tokio::time::sleep_until(activity.last() + idle) => {
				if activity.last().elapsed() >= idle {
					return Outcome::IdleTimedOut;
				}
			},
		}
	}
}

/// When bytes last moved through a connection.
struct Activity(Mutex<Instant>);

impl Activity {
	fn new() -> Self {
		Self(Mutex::new(Instant::now()))
	}

	fn touch(&self) {
		*self.0.lock().unwrap_or_else(PoisonError::into_inner) = Instant::now();
	}

	fn last(&self) -> Instant {
		*self.0.lock().unwrap_or_else(PoisonError::into_inner)
	}
}

/// Records progress on [`Activity`] whenever bytes are read or written.
struct Tracked<'a, S> {
	inner: S,
	activity: &'a Activity,
}

impl<S: AsyncRead + Unpin> AsyncRead for Tracked<'_, S> {
	fn poll_read(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &mut ReadBuf<'_>,
	) -> Poll<std::io::Result<()>> {
		let before = buf.filled().len();
		let result = Pin::new(&mut self.inner).poll_read(cx, buf);
		if buf.filled().len() > before {
			self.activity.touch();
		}

		result
	}
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Tracked<'_, S> {
	fn poll_write(
		mut self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		buf: &[u8],
	) -> Poll<std::io::Result<usize>> {
		let result = Pin::new(&mut self.inner).poll_write(cx, buf);
		if matches!(result, Poll::Ready(Ok(written)) if written > 0) {
			self.activity.touch();
		}

		result
	}

	fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		Pin::new(&mut self.inner).poll_flush(cx)
	}

	fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		Pin::new(&mut self.inner).poll_shutdown(cx)
	}
}

#[cfg(test)]
mod tests {
	use std::{
		sync::{Arc, Mutex},
		time::Duration,
	};

	use tokio::{
		io::{AsyncReadExt, AsyncWriteExt},
		net::TcpListener,
	};

	use super::{Config, Error, Event, Outcome, copy_until_idle, serve_with, validate};
	use crate::utils::connections::test_support::{QueuedListener, connection};

	const ENCLAVE_CID: u32 = 16;

	fn recorder() -> (
		Arc<Mutex<Vec<Event>>>,
		impl Fn(Event) + Send + Sync + 'static,
	) {
		let events = Arc::new(Mutex::new(Vec::new()));
		let sink = Arc::clone(&events);

		(events, move |event| sink.lock().unwrap().push(event))
	}

	/// An upstream that answers each connection's first message with `pong:` and the message.
	async fn upstream() -> u16 {
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let port = listener.local_addr().unwrap().port();
		tokio::spawn(async move {
			loop {
				let (mut stream, _) = listener.accept().await.unwrap();
				tokio::spawn(async move {
					let mut message = [0; 4];
					stream.read_exact(&mut message).await.unwrap();
					stream.write_all(b"pong:").await.unwrap();
					stream.write_all(&message).await.unwrap();
				});
			}
		});

		port
	}

	fn config(destination_port: u16) -> Config {
		let mut config = Config::new(8000, "127.0.0.1", destination_port);
		config.allowed_cid = Some(ENCLAVE_CID);

		config
	}

	async fn wait_for_close(events: &Mutex<Vec<Event>>) -> Event {
		loop {
			let last = events.lock().unwrap().last().copied();
			if let Some(event) = last {
				return event;
			}
			tokio::task::yield_now().await;
		}
	}

	#[tokio::test]
	async fn bytes_reach_the_destination_and_back() {
		let (queue, listener) = QueuedListener::new();
		let (events, on_event) = recorder();
		let config = config(upstream().await);
		tokio::spawn(serve_with(listener, config, on_event));

		let (mut enclave, server) = connection();
		queue.send(Ok((server, ENCLAVE_CID))).unwrap();
		enclave.write_all(b"ping").await.unwrap();
		let mut reply = Vec::new();
		enclave.read_to_end(&mut reply).await.unwrap();
		drop(enclave);

		assert_eq!(reply, b"pong:ping");
		assert!(matches!(
			wait_for_close(&events).await,
			Event::Closed {
				outcome: Outcome::Completed,
				..
			}
		));
	}

	#[tokio::test]
	async fn an_unreachable_destination_is_reported() {
		let closed_port = {
			let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
			listener.local_addr().unwrap().port()
		};
		let (queue, listener) = QueuedListener::new();
		let (events, on_event) = recorder();
		tokio::spawn(serve_with(listener, config(closed_port), on_event));

		let (mut enclave, server) = connection();
		queue.send(Ok((server, ENCLAVE_CID))).unwrap();
		let mut reply = Vec::new();
		enclave.read_to_end(&mut reply).await.unwrap();

		assert_eq!(reply, Vec::<u8>::new());
		assert!(matches!(
			wait_for_close(&events).await,
			Event::Closed {
				outcome: Outcome::ConnectFailed,
				..
			}
		));
	}

	#[tokio::test]
	async fn listener_rejections_are_reported_as_events() {
		let (queue, listener) = QueuedListener::new();
		let (events, on_event) = recorder();
		tokio::spawn(serve_with(listener, config(upstream().await), on_event));

		let (mut stranger, server) = connection();
		queue.send(Ok((server, ENCLAVE_CID + 1))).unwrap();
		let mut reply = Vec::new();
		stranger.read_to_end(&mut reply).await.unwrap();

		assert_eq!(reply, Vec::<u8>::new());
		assert_eq!(wait_for_close(&events).await, Event::RejectedPeer);
	}

	#[tokio::test(start_paused = true)]
	async fn a_silent_connection_is_closed_after_the_idle_timeout() {
		let (_enclave, downstream) = connection();
		let (_destination, upstream) = connection();

		let outcome = copy_until_idle(downstream, upstream, Duration::from_secs(120)).await;

		assert_eq!(outcome, Outcome::IdleTimedOut);
	}

	#[tokio::test(start_paused = true)]
	async fn traffic_keeps_a_connection_open_past_the_idle_timeout() {
		let (mut enclave, downstream) = connection();
		let (mut destination, upstream) = connection();
		let idle = Duration::from_secs(120);
		let copy = tokio::spawn(copy_until_idle(downstream, upstream, idle));

		for _ in 0..3 {
			tokio::time::sleep(idle / 2).await;
			enclave.write_all(b"x").await.unwrap();
			destination.read_exact(&mut [0]).await.unwrap();
		}
		assert!(!copy.is_finished(), "activity resets the idle timer");

		drop((enclave, destination));
		assert_eq!(copy.await.unwrap(), Outcome::Completed);
	}

	#[test]
	fn configurations_that_cannot_serve_are_rejected() {
		let mut no_slots = Config::new(8000, "kms.eu-central-1.amazonaws.com", 443);
		no_slots.max_connections = 0;

		for config in [
			Config::new(8000, "", 443),
			Config::new(8000, "kms.eu-central-1.amazonaws.com", 0),
			no_slots,
		] {
			assert!(matches!(validate(&config), Err(Error::InvalidConfig(_))));
		}
		assert!(validate(&Config::new(8000, "kms.eu-central-1.amazonaws.com", 443)).is_ok());
	}
}
