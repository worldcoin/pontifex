//! A bounded accept loop for host-side vsock listeners.

use std::{convert::Infallible, future::Future, io, sync::Arc, time::Duration};

use tokio::{sync::Semaphore, task::JoinSet};
use tokio_vsock::{VsockListener, VsockStream};

/// Pause after a failed accept, so a persistent failure (e.g. `EMFILE`) cannot spin the loop.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// Why the accept loop did not hand a connection to its handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerEvent {
	/// The peer's CID was not the allowed one.
	RejectedPeer,
	/// All connection slots were in use.
	RejectedCapacity,
	/// Accepting a connection failed; the loop keeps serving.
	AcceptFailed,
}

/// Which connections the accept loop admits.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
	pub allowed_cid: Option<u32>,
	pub max_connections: usize,
}

/// A source of accepted connections and their peer CIDs; tests use an in-memory one.
pub trait Accept: Send {
	type Stream: Send + 'static;

	fn accept(&mut self) -> impl Future<Output = io::Result<(Self::Stream, u32)>> + Send;
}

impl Accept for VsockListener {
	type Stream = VsockStream;

	async fn accept(&mut self) -> io::Result<(VsockStream, u32)> {
		let (stream, address) = Self::accept(self).await?;

		Ok((stream, address.cid()))
	}
}

/// Hands admitted connections to `handle` until dropped.
///
/// A slot frees as soon as its handler finishes. A panicking handler is re-raised here.
pub async fn serve<A, H, Fut>(
	mut listener: A,
	limits: Limits,
	on_event: impl Fn(ListenerEvent),
	handle: H,
) -> Infallible
where
	A: Accept,
	H: Fn(A::Stream) -> Fut,
	Fut: Future<Output = ()> + Send + 'static,
{
	let slots = Arc::new(Semaphore::new(limits.max_connections));
	let mut workers = JoinSet::new();

	loop {
		tokio::select! {
			accepted = listener.accept() => match accepted {
				Ok((stream, cid)) => {
					if limits.allowed_cid.is_some_and(|allowed| allowed != cid) {
						tracing::warn!(cid, "rejected a vsock connection from an unexpected peer");
						on_event(ListenerEvent::RejectedPeer);
						continue;
					}
					let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
						tracing::warn!(cid, "rejected a vsock connection: all slots are in use");
						on_event(ListenerEvent::RejectedCapacity);
						continue;
					};
					let worker = handle(stream);
					workers.spawn(async move {
						worker.await;
						drop(slot);
					});
				},
				Err(error) => {
					tracing::warn!(%error, "failed to accept a vsock connection");
					on_event(ListenerEvent::AcceptFailed);
					tokio::time::sleep(ACCEPT_BACKOFF).await;
				},
			},
			Some(finished) = workers.join_next(), if !workers.is_empty() => {
				match finished {
					Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
					// Workers are only cancelled when this loop is dropped.
					Ok(()) | Err(_) => {},
				}
			},
		}
	}
}

#[cfg(test)]
pub mod test_support {
	use std::io;

	use tokio::{
		io::DuplexStream,
		sync::mpsc::{self, UnboundedSender},
	};

	use super::Accept;

	/// Yields queued `(stream, cid)` results, then waits forever.
	pub struct QueuedListener(mpsc::UnboundedReceiver<io::Result<(DuplexStream, u32)>>);

	impl QueuedListener {
		pub fn new() -> (UnboundedSender<io::Result<(DuplexStream, u32)>>, Self) {
			let (sender, receiver) = mpsc::unbounded_channel();

			(sender, Self(receiver))
		}
	}

	impl Accept for QueuedListener {
		type Stream = DuplexStream;

		async fn accept(&mut self) -> io::Result<(DuplexStream, u32)> {
			match self.0.recv().await {
				Some(accepted) => accepted,
				None => std::future::pending().await,
			}
		}
	}

	/// A connected pair: the peer's end, and the end the listener hands out.
	pub fn connection() -> (DuplexStream, DuplexStream) {
		tokio::io::duplex(4096)
	}
}

#[cfg(test)]
mod tests {
	use std::{
		io,
		sync::{Arc, Mutex},
		time::Duration,
	};

	use tokio::{
		io::{AsyncReadExt, AsyncWriteExt},
		sync::Notify,
	};

	use super::{Limits, ListenerEvent, serve, test_support::*};

	const LIMITS: Limits = Limits {
		allowed_cid: Some(16),
		max_connections: 1,
	};

	fn recorder() -> (Arc<Mutex<Vec<ListenerEvent>>>, impl Fn(ListenerEvent)) {
		let events = Arc::new(Mutex::new(Vec::new()));
		let sink = Arc::clone(&events);

		(events, move |event| sink.lock().unwrap().push(event))
	}

	/// Echoes one message, so a test can tell an admitted connection from a dropped one.
	async fn echo(mut stream: tokio::io::DuplexStream) {
		let mut byte = [0];
		if stream.read_exact(&mut byte).await.is_ok() {
			_ = stream.write_all(&byte).await;
		}
	}

	/// Waits for the handler to drop its end; on a current-thread runtime its slot is free by then.
	async fn closed(peer: &mut tokio::io::DuplexStream) {
		let mut rest = Vec::new();
		_ = peer.read_to_end(&mut rest).await;
	}

	async fn admitted(peer: &mut tokio::io::DuplexStream) -> bool {
		_ = peer.write_all(&[7]).await;
		let mut byte = [0];

		matches!(peer.read(&mut byte).await, Ok(1))
	}

	#[tokio::test]
	async fn only_the_allowed_peer_is_admitted() {
		let (queue, listener) = QueuedListener::new();
		let (events, on_event) = recorder();
		tokio::spawn(async move { serve(listener, LIMITS, on_event, echo).await });

		let (mut stranger, server) = connection();
		queue.send(Ok((server, 17))).unwrap();
		assert!(!admitted(&mut stranger).await);

		let (mut enclave, server) = connection();
		queue.send(Ok((server, 16))).unwrap();
		assert!(admitted(&mut enclave).await);
		assert_eq!(*events.lock().unwrap(), [ListenerEvent::RejectedPeer]);
	}

	#[tokio::test]
	async fn a_slot_frees_when_its_handler_finishes() {
		let (queue, listener) = QueuedListener::new();
		let (events, on_event) = recorder();
		let release = Arc::new(Notify::new());
		let handler_release = Arc::clone(&release);
		tokio::spawn(async move {
			serve(listener, LIMITS, on_event, move |stream| {
				let release = Arc::clone(&handler_release);
				async move {
					release.notified().await;
					echo(stream).await;
				}
			})
			.await
		});

		let (mut first, server) = connection();
		queue.send(Ok((server, 16))).unwrap();
		let (mut second, server) = connection();
		queue.send(Ok((server, 16))).unwrap();
		assert!(!admitted(&mut second).await, "the only slot is taken");

		release.notify_one();
		assert!(admitted(&mut first).await);
		closed(&mut first).await;

		let (mut third, server) = connection();
		queue.send(Ok((server, 16))).unwrap();
		release.notify_one();
		assert!(
			admitted(&mut third).await,
			"the finished handler freed its slot"
		);
		assert_eq!(*events.lock().unwrap(), [ListenerEvent::RejectedCapacity]);
	}

	#[tokio::test(start_paused = true)]
	async fn a_failed_accept_does_not_stop_the_listener() {
		let (queue, listener) = QueuedListener::new();
		let (events, on_event) = recorder();
		tokio::spawn(async move { serve(listener, LIMITS, on_event, echo).await });

		queue
			.send(Err(io::Error::from_raw_os_error(24 /* EMFILE */)))
			.unwrap();
		let (mut enclave, server) = connection();
		queue.send(Ok((server, 16))).unwrap();
		tokio::time::advance(Duration::from_secs(1)).await;

		assert!(admitted(&mut enclave).await);
		assert_eq!(*events.lock().unwrap(), [ListenerEvent::AcceptFailed]);
	}

	#[tokio::test]
	#[should_panic(expected = "handler bug")]
	async fn a_panicking_handler_is_not_swallowed() {
		let (queue, listener) = QueuedListener::new();
		let (_, server) = connection();
		queue.send(Ok((server, 16))).unwrap();

		serve(
			listener,
			LIMITS,
			|_| {},
			|_| async { panic!("handler bug") },
		)
		.await;
	}
}
