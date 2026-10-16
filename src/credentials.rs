//! Host-side delivery of temporary AWS credentials to the enclave.
//!
//! The enclave has no credentials of its own. Its [`crate::kms`] client signs requests with the
//! host's temporary workload credentials, which it fetches from this server through
//! `kms::ParentCredentials` and refreshes before they expire. Credentials authorize requests;
//! they cannot redirect them, and the host already holds them, so serving them adds no access.
//!
//! ```rust,ignore
//! use pontifex::credentials::{self, Config};
//!
//! let aws_config = aws_config::load_defaults(BehaviorVersion::latest()).await;
//! let config = Config::new(8001, enclave_cid);
//! credentials::serve(config, aws_config.credentials_provider().unwrap(), |event| record_metric(event)).await?;
//! ```

use std::{convert::Infallible, io, time::Duration};

use aws_credential_types::provider::{ProvideCredentials, SharedCredentialsProvider};
use tokio::{
	io::{AsyncRead, AsyncWrite},
	time::Instant,
};
use tokio_vsock::{VsockAddr, VsockListener};

use crate::utils::{
	connections::{self, Accept, Limits, ListenerEvent},
	credentials_wire::{self, WireError},
};

const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;

/// Where the server listens and how much it admits.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Config {
	/// vsock port the enclave dials on the parent.
	pub port: u32,
	/// The only CID that may connect. Required: vsock is not namespaced, so other processes or
	/// pods on the node could otherwise read the host's credentials.
	pub allowed_cid: u32,
	/// Exchanges served at once; further connections wait in the kernel's accept queue.
	pub max_connections: usize,
	/// Bounds one exchange, including a provider refresh.
	pub timeout: Duration,
}

impl Config {
	/// A server on `port` that only answers `allowed_cid`.
	#[must_use]
	pub const fn new(port: u32, allowed_cid: u32) -> Self {
		Self {
			port,
			allowed_cid,
			max_connections: 8,
			timeout: Duration::from_secs(3),
		}
	}
}

/// Errors that stop the server.
#[derive(Debug, thiserror::Error)]
pub enum Error {
	/// The configuration cannot serve any connection.
	#[error("invalid credentials server configuration: {0}")]
	InvalidConfig(&'static str),
	/// Failed to bind to the vsock address.
	#[error("failed to bind to vsock port {port}: {source}")]
	Bind {
		/// The configured vsock port.
		port: u32,
		/// The underlying failure.
		source: io::Error,
	},
}

/// What happened to one connection, for metrics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
	/// The peer was not [`Config::allowed_cid`]; the connection was dropped.
	RejectedPeer,
	/// Accepting a connection failed; the server keeps serving.
	AcceptFailed,
	/// An exchange ended.
	Served {
		/// How it ended.
		outcome: Outcome,
		/// From accept to close.
		duration: Duration,
	},
}

/// How one exchange ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Outcome {
	/// Credentials were sent.
	Sent,
	/// The host's provider failed.
	ProviderFailed,
	/// The provider returned static or nearly expired credentials, which are never sent.
	NotTemporary,
	/// The exchange took longer than [`Config::timeout`].
	TimedOut,
	/// Writing to the enclave failed.
	Io,
}

impl From<ListenerEvent> for Event {
	fn from(event: ListenerEvent) -> Self {
		match event {
			ListenerEvent::RejectedPeer => Self::RejectedPeer,
			ListenerEvent::AcceptFailed => Self::AcceptFailed,
		}
	}
}

/// Serves `provider`'s credentials until the returned future is dropped.
///
/// `on_event` runs on the server's tasks for every [`Event`]; keep it cheap, e.g. a counter.
/// Failures are also logged at `warn`, without credential material.
///
/// # Errors
///
/// Only fails at startup, on an invalid [`Config`] or when the port cannot be bound.
pub async fn serve(
	config: Config,
	provider: SharedCredentialsProvider,
	on_event: impl Fn(Event) + Send + Sync + 'static,
) -> Result<Infallible, Error> {
	if config.max_connections == 0 {
		return Err(Error::InvalidConfig("max_connections is 0"));
	}
	let listener =
		VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, config.port)).map_err(|source| {
			Error::Bind {
				port: config.port,
				source,
			}
		})?;

	Ok(serve_with(listener, config, provider, on_event).await)
}

/// [`serve`] over any [`Accept`] source, so tests can run without vsock.
async fn serve_with<A>(
	listener: A,
	config: Config,
	provider: SharedCredentialsProvider,
	on_event: impl Fn(Event) + Send + Sync + 'static,
) -> Infallible
where
	A: Accept,
	A::Stream: AsyncRead + AsyncWrite + Unpin,
{
	let limits = Limits {
		allowed_cid: Some(config.allowed_cid),
		max_connections: config.max_connections,
	};
	let (timeout, provider, on_event) = (config.timeout, &provider, &on_event);

	connections::serve(
		listener,
		limits,
		|event| on_event(event.into()),
		|stream| async move {
			let started = Instant::now();
			let outcome = tokio::time::timeout(timeout, send(stream, provider))
				.await
				.unwrap_or(Outcome::TimedOut);
			if outcome != Outcome::Sent {
				tracing::warn!(?outcome, "failed to send credentials to the enclave");
			}
			on_event(Event::Served {
				outcome,
				duration: started.elapsed(),
			});
		},
	)
	.await
}

async fn send(
	mut stream: impl AsyncWrite + Unpin,
	provider: &SharedCredentialsProvider,
) -> Outcome {
	let credentials = match provider.provide_credentials().await {
		Ok(credentials) => credentials,
		Err(error) => {
			tracing::warn!(error = %aws_smithy_types::error::display::DisplayErrorContext(&error), "workload credential provider failed");
			return Outcome::ProviderFailed;
		},
	};

	match credentials_wire::write(&mut stream, &credentials).await {
		Ok(()) => Outcome::Sent,
		Err(error) if wire_error(&error).is_some() => Outcome::NotTemporary,
		Err(_) => Outcome::Io,
	}
}

fn wire_error(error: &io::Error) -> Option<WireError> {
	error.get_ref()?.downcast_ref::<WireError>().copied()
}

#[cfg(test)]
mod tests {
	use std::{
		sync::{Arc, Mutex},
		time::{Duration, SystemTime},
	};

	use aws_credential_types::{
		Credentials,
		provider::{
			ProvideCredentials, SharedCredentialsProvider, error::CredentialsError, future,
		},
	};

	use super::{Config, Event, Outcome, serve_with};
	use crate::utils::{
		connections::test_support::{QueuedListener, connection},
		credentials_wire,
	};

	const ENCLAVE_CID: u32 = 16;

	#[derive(Debug)]
	struct Failing;

	impl ProvideCredentials for Failing {
		fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
		where
			Self: 'a,
		{
			future::ProvideCredentials::ready(Err(CredentialsError::not_loaded_no_source()))
		}
	}

	#[derive(Debug)]
	struct Hanging;

	impl ProvideCredentials for Hanging {
		fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
		where
			Self: 'a,
		{
			future::ProvideCredentials::new(std::future::pending())
		}
	}

	fn temporary() -> SharedCredentialsProvider {
		SharedCredentialsProvider::new(Credentials::new(
			"synthetic-id",
			"synthetic-secret",
			Some("synthetic-token".into()),
			Some(SystemTime::now() + Duration::from_secs(3600)),
			"test",
		))
	}

	/// Runs one exchange against `provider` and returns what the enclave read and the event.
	async fn exchange(provider: SharedCredentialsProvider) -> (Option<Credentials>, Event) {
		let (queue, listener) = QueuedListener::new();
		let events = Arc::new(Mutex::new(Vec::new()));
		let sink = Arc::clone(&events);
		let config = Config::new(8001, ENCLAVE_CID);
		tokio::spawn(serve_with(listener, config, provider, move |event| {
			sink.lock().unwrap().push(event);
		}));

		let (mut enclave, server) = connection();
		queue.send(Ok((server, ENCLAVE_CID))).unwrap();
		let received = credentials_wire::read(&mut enclave, "parent").await.ok();
		loop {
			let last = events.lock().unwrap().last().copied();
			if let Some(event) = last {
				return (received, event);
			}
			tokio::task::yield_now().await;
		}
	}

	#[tokio::test]
	async fn temporary_credentials_reach_the_enclave() {
		let (received, event) = exchange(temporary()).await;

		assert_eq!(received.unwrap().access_key_id(), "synthetic-id");
		assert!(matches!(
			event,
			Event::Served {
				outcome: Outcome::Sent,
				..
			}
		));
	}

	#[tokio::test]
	async fn other_peers_get_nothing() {
		let (queue, listener) = QueuedListener::new();
		tokio::spawn(serve_with(
			listener,
			Config::new(8001, ENCLAVE_CID),
			temporary(),
			|_| {},
		));

		// CID 1 is a local process on the host, CID 2 the host itself.
		for cid in [1, 2, ENCLAVE_CID + 1] {
			let (mut peer, server) = connection();
			queue.send(Ok((server, cid))).unwrap();
			assert!(credentials_wire::read(&mut peer, "parent").await.is_err());
		}
	}

	#[tokio::test]
	async fn static_credentials_are_never_sent() {
		let (received, event) =
			exchange(SharedCredentialsProvider::new(Credentials::for_tests())).await;

		assert!(received.is_none());
		assert!(matches!(
			event,
			Event::Served {
				outcome: Outcome::NotTemporary,
				..
			}
		));
	}

	#[tokio::test]
	async fn a_failing_provider_is_reported() {
		let (received, event) = exchange(SharedCredentialsProvider::new(Failing)).await;

		assert!(received.is_none());
		assert!(matches!(
			event,
			Event::Served {
				outcome: Outcome::ProviderFailed,
				..
			}
		));
	}

	#[tokio::test(start_paused = true)]
	async fn a_hanging_provider_times_out() {
		let (received, event) = exchange(SharedCredentialsProvider::new(Hanging)).await;

		assert!(received.is_none());
		assert!(matches!(
			event,
			Event::Served {
				outcome: Outcome::TimedOut,
				..
			}
		));
	}
}
