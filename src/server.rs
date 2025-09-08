use std::{collections::HashMap, future::Future, io, marker::PhantomData, pin::Pin, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_vsock::{VsockAddr, VsockListener};

pub use crate::utils::CodingKey;
use crate::{Request, utils::Stream};

const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Errors that can occur when running the server.
#[derive(Debug, thiserror::Error)]
pub enum Error {
	/// Failed to bind to vsock address.
	#[error("Failed to bind to vsock address: {0}")]
	Bind(io::Error),
	/// Failed to accept connection.
	#[error("Failed to accept connection: {0}")]
	Accept(io::Error),
	/// Failed to connect to NSM.
	#[cfg(feature = "nsm")]
	#[error("Failed to connect to NSM: {0}")]
	NsmConnect(io::Error),
	/// Failed to encode the request payload.
	#[error("encoding failed: {0}")]
	Encoding(rmp_serde::encode::Error),
	/// Failed to decode the request payload.
	#[error("decoding failed: {0}")]
	Decoding(rmp_serde::decode::Error),
	/// Failed to write a payload to the stream.
	#[error("failed to write {0}: {1}")]
	Writing(CodingKey, io::Error),
	/// Failed to read a payload from the stream.
	#[error("failed to read {0}: {1}")]
	Reading(CodingKey, io::Error),
	/// Unknown request type.
	#[error("Unknown request type: 0x{0:08x}")]
	UnknownRequest(u32),
}

/// Type-erased handler trait - provides a uniform interface for all handlers.
/// This allows us to store handlers with different request/response types in the same HashMap.
/// All type-specific logic is hidden behind this common interface.
trait Handler<S>: Send + Sync {
	fn handle<'a>(&'a self, stream: &'a mut Stream, state: S) -> BoxFuture<'a, Result<(), Error>>;
}

/// Adapter that wraps a typed handler (with specific Request/Response types)
/// and implements the type-erased Handler trait.
///
/// This is the bridge between:
/// - The typed world: `fn(State, HealthCheckRequest) -> HealthCheckResponse`
/// - The type-erased world: `Box<dyn Handler<State>>`
///
/// Each TypedHandler knows its specific R type, so it can deserialize the
/// incoming bytes to the correct request type and serialize the response.
struct TypedHandler<R, S, H, Fut>
where
	R: Request,
	H: Fn(S, R) -> Fut + Send + Sync,
	Fut: Future<Output = R::Response> + Send,
{
	handler: H,                    // The actual user-provided handler function
	_phantom: PhantomData<(R, S)>, // Remembers types R and S without storing values
}

// This impl is where the magic happens - it converts typed operations to type-erased ones
impl<R, S, H, Fut> Handler<S> for TypedHandler<R, S, H, Fut>
where
	R: Request + Sync,
	S: Clone + Send + Sync + 'static,
	H: Fn(S, R) -> Fut + Send + Sync,
	Fut: Future<Output = R::Response> + Send,
{
	fn handle<'a>(&'a self, stream: &'a mut Stream, state: S) -> BoxFuture<'a, Result<(), Error>> {
		Box::pin(async move {
			// HERE: We know the concrete type R, so we can deserialize correctly
			// Read request length
			let len = stream
				.read_u64()
				.await
				.map_err(|e| Error::Reading(CodingKey::Length, e))?;

			// Read request payload
			let payload = stream
				.read_exact(len)
				.await
				.map_err(|e| Error::Reading(CodingKey::Payload, e))?;

			// Deserialize to the SPECIFIC request type R (e.g., HealthCheckRequest)
			// This works because TypedHandler remembers what R is
			let request: R = rmp_serde::from_slice(&payload).map_err(Error::Decoding)?;

			// Call the user's handler with the concrete typed request
			// Returns the concrete response type (R::Response)
			let response = (self.handler)(state, request).await;

			// Serialize the typed response back to bytes
			let response_bytes = rmp_serde::to_vec(&response).map_err(Error::Encoding)?;

			// Send response
			stream
				.write_u64(response_bytes.len() as u64)
				.await
				.map_err(|e| Error::Writing(CodingKey::Length, e))?;

			stream
				.write_all(&response_bytes)
				.await
				.map_err(|e| Error::Writing(CodingKey::Payload, e))?;

			Ok(())
		})
	}
}

/// Router that dispatches requests to handlers based on type ID.
///
/// The HashMap stores type-erased handlers (Box<dyn Handler>) so we can store
/// handlers with different request/response types in the same collection.
/// Each handler is keyed by its request type's ID (hash of ROUTE_ID).
pub struct Router<S> {
	routes: HashMap<u32, Box<dyn Handler<S>>>, // Type-erased storage
	state: S,
}

impl<S: Clone + Send + Sync + 'static> Router<S> {
	/// Create a new router with the given state
	pub fn new(state: S) -> Self {
		Self {
			routes: HashMap::new(),
			state,
		}
	}

	/// Register a route - type safety guaranteed here
	pub fn route<R, H, Fut>(mut self, handler: H) -> Self
	where
		R: Request + Sync,
		H: Fn(S, R) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = R::Response> + Send + 'static,
	{
		let type_id = R::type_id();
		tracing::debug!(
			route_id = R::ROUTE_ID,
			type_id = format!("0x{:08x}", type_id),
			"Registering route"
		);

		// Wrap the typed handler in TypedHandler adapter, then box it as trait object.
		// This converts: fn(State, HealthCheckRequest) -> Response
		// Into: Box<dyn Handler<State>>
		let boxed = Box::new(TypedHandler {
			handler,
			_phantom: PhantomData::<(R, S)>,
		});

		// Store the type-erased handler, keyed by request type ID
		self.routes.insert(type_id, boxed);
		self
	}

	/// Start serving requests
	pub async fn serve(self, port: u32) -> Result<(), Error> {
		let listener =
			VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port)).map_err(Error::Bind)?;

		tracing::info!("Router listening on port {port}");

		// Initialize the secure module global if the feature is enabled.
		#[cfg(feature = "nsm")]
		{
			match crate::SecureModule::connect() {
				Ok(nsm) => {
					crate::nsm::SECURE_MODULE_GLOBAL
						.get_or_init(|| async { nsm })
						.await
				},
				Err(e) => {
					return Err(Error::NsmConnect(e));
				},
			};
		}

		let router = Arc::new(self);

		loop {
			let (stream, _) = listener.accept().await.map_err(Error::Accept)?;
			let mut stream = Stream::new(stream);
			let router = router.clone();

			tokio::spawn(async move {
				if let Err(e) = handle_connection(&mut stream, router).await {
					tracing::error!("Failed to handle request: {e}");
				}
			});
		}
	}
}

async fn handle_connection<S>(stream: &mut Stream, router: Arc<Router<S>>) -> Result<(), Error>
where
	S: Clone + Send + Sync + 'static,
{
	// Read type ID from the wire (first 4 bytes of the message)
	let type_id = stream
		.read_u32()
		.await
		.map_err(|e| Error::Reading(CodingKey::Length, e))?;

	// Look up the type-erased handler for this type ID
	let handler = router.routes.get(&type_id).ok_or_else(|| {
		tracing::warn!(
			type_id = format!("0x{:08x}", type_id),
			"Unknown request type"
		);
		Error::UnknownRequest(type_id)
	})?;

	// Call the handler's type-erased handle method.
	// The handler internally knows its concrete types and will:
	// 1. Deserialize the stream to the correct request type
	// 2. Call the user's handler function with typed parameters
	// 3. Serialize and send the typed response
	handler.handle(stream, router.state.clone()).await
}
