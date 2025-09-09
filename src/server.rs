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

/// A common interface that all request handlers must implement.
///
/// # Why This Exists
///
/// In Rust, we can't store different types in the same collection (like a `HashMap`).
/// For example, we can't have a `HashMap` that stores both:
/// - A handler for `HealthCheck -> HealthStatus`  
/// - A handler for `UserLogin -> AuthToken`
///
/// This trait solves that by providing a common "shape" that all handlers follow,
/// regardless of their specific request/response types. Think of it like an electrical
/// outlet standard - different appliances (handlers) work differently internally,
/// but they all plug into the same socket (implement this trait).
trait Handler<S>: Send + Sync {
	fn handle<'a>(
		&'a self,
		stream: &'a mut Stream,
		state: Arc<S>,
	) -> BoxFuture<'a, Result<(), Error>>;
}

/// A wrapper that allows strongly-typed handlers to work with the type-erased system.
///
/// # The Problem It Solves
///
/// Users write handlers with specific types:
/// ```rust
/// async fn handle_health(state: AppState, req: HealthCheck) -> HealthStatus { ... }
/// ```
///
/// But the router needs to store all handlers together, which requires them to have
/// the same type. This struct acts as an "adapter" that:
/// 1. Stores the user's typed handler function
/// 2. Knows the specific request type (R) it handles
/// 3. Implements the common `Handler` interface
///
/// # How It Works
///
/// When a request comes in, this adapter:
/// 1. Deserializes bytes -> specific request type (because it knows R)
/// 2. Calls the user's handler with the typed request
/// 3. Serializes the typed response back to bytes
///
/// The `PhantomData` field is a Rust pattern that tells the compiler "remember these
/// types exist" without actually storing any data. It's like a sticky note reminding
/// the compiler what types this handler works with.
struct TypedHandler<R, S, H, Fut>
where
	R: Request,
	H: Fn(Arc<S>, R) -> Fut + Send + Sync,
	Fut: Future<Output = R::Response> + Send,
{
	handler: H,                    // The actual user-provided handler function
	_phantom: PhantomData<(R, S)>, // Compiler hint: "this handler is for type R with state S"
}

// This implementation bridges the gap between typed and type-erased worlds.
// It's like a translator that speaks both "specific type" language and "generic handler" language.
impl<R, S, H, Fut> Handler<S> for TypedHandler<R, S, H, Fut>
where
	R: Request,
	S: Clone + Send + Sync + 'static,
	H: Fn(Arc<S>, R) -> Fut + Send + Sync,
	Fut: Future<Output = R::Response> + Send,
{
	fn handle<'a>(
		&'a self,
		stream: &'a mut Stream,
		state: Arc<S>,
	) -> BoxFuture<'a, Result<(), Error>> {
		Box::pin(async move {
			// At this point, we know the concrete type R (e.g., HealthCheck),
			// so we can correctly deserialize the incoming bytes
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

			// Convert bytes -> the specific request type this handler expects.
			// For example, if R = HealthCheck, this deserializes to HealthCheck.
			// This is safe because the router already verified the type ID matches.
			let request: R = rmp_serde::from_slice(&payload).map_err(Error::Decoding)?;

			// Call the user's actual handler function with properly typed parameters.
			// The handler doesn't know about bytes or type erasure - it just gets
			// its expected types and returns its expected response.
			let response = (self.handler)(state, request).await;

			// Convert the typed response back to bytes for transmission
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

/// The main routing system that directs incoming requests to the appropriate handlers.
///
/// # How It Works
///
/// The Router maintains a map of:
/// - **Key**: Type ID (a number derived from the request's `ROUTE_ID`)
/// - **Value**: A handler that can process that request type
///
/// When a request arrives:
/// 1. Read the type ID from the message
/// 2. Look up the corresponding handler in the map
/// 3. Let the handler deserialize and process the request
///
/// # Type Erasure Explained
///
/// The `Box<dyn Handler<S>>` type means "a box containing any type that implements `Handler`".
/// This is how we store handlers for different request types in the same `HashMap`.
/// It's like having a filing cabinet where each drawer (handler) processes different
/// paperwork (request types), but they all fit in the same cabinet (`HashMap`).
///
/// # Optional State
///
/// The router supports both stateless and stateful handlers:
/// - `Router::new()` creates a stateless router (`Router<()>`)
/// - `Router::with_state(state)` creates a stateful router (`Router<S>`)
pub struct Router<S = ()> {
	routes: HashMap<u32, Box<dyn Handler<S>>>, // Maps type IDs to their handlers
	state: Arc<S>, // Shared application state (wrapped in Arc for cheap cloning)
}

impl Router<()> {
	/// Create a new stateless router.
	///
	/// Use this when your handlers don't need shared state.
	/// Note: handlers still receive a unit state parameter that can be ignored.
	///
	/// # Example
	///
	/// ```rust
	/// let router = Router::new()
	///     .route::<HealthCheck>(|_state, req| async {
	///         HealthStatus { ok: true }
	///     });
	/// ```
	#[must_use]
	pub fn new() -> Self {
		Self {
			routes: HashMap::new(),
			state: Arc::new(()),
		}
	}
}

impl Default for Router<()> {
	fn default() -> Self {
		Self::new()
	}
}

impl<S> Router<S>
where
	S: Clone + Send + Sync + 'static,
{
	/// Create a new router with the given state.
	///
	/// Use this when your handlers need access to shared application state.
	///
	/// # Example
	///
	/// ```rust
	/// let router = Router::with_state(AppState::new())
	///     .route::<GetUser>(|state, req| async move {
	///         state.get_user(req.id).await
	///     });
	/// ```
	#[must_use]
	pub fn with_state(state: S) -> Self {
		Self {
			routes: HashMap::new(),
			state: Arc::new(state),
		}
	}

	/// Register a handler for a specific request type.
	///
	/// This method is type-safe: the compiler ensures that:
	/// - The handler accepts the correct request type
	/// - The handler returns the correct response type
	/// - The types match what the Request trait specifies
	///
	/// # Example
	///
	/// ```rust
	/// router.route::<HealthCheck>(|state, req| async move {
	///     // state is Arc<AppState> - cheap to clone!
	///     // Access fields with state.field_name
	///     HealthStatus { ok: true }
	/// })
	/// ```
	#[must_use]
	pub fn route<R, H, Fut>(mut self, handler: H) -> Self
	where
		R: Request,
		H: Fn(Arc<S>, R) -> Fut + Send + Sync + 'static,
		Fut: Future<Output = R::Response> + Send + 'static,
	{
		let type_id = R::type_id();
		tracing::debug!(
			route_id = R::ROUTE_ID,
			type_id = format!("0x{:08x}", type_id),
			"Registering route"
		);

		// Step 1: Wrap the user's typed handler in our adapter.
		// This preserves type information while providing a common interface.
		let typed_adapter = TypedHandler {
			handler,
			_phantom: PhantomData::<(R, S)>,
		};

		// Step 2: Box the adapter as a trait object.
		// This "erases" the specific type, allowing storage in the HashMap.
		// The adapter still knows the real types internally.
		let boxed: Box<dyn Handler<S>> = Box::new(typed_adapter);

		// Step 3: Store the handler, indexed by its type ID for fast lookup
		self.routes.insert(type_id, boxed);
		self
	}

	/// Start serving requests on the specified port.
	///
	/// # Errors
	///
	/// - `Error::Bind`: Failed to bind to the vsock address
	/// - `Error::Accept`: Failed to accept incoming connection
	/// - `Error::Nsm`: Failed to connect to NSM (if feature enabled)
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
	// Note: We clone the Arc (cheap!) not the state itself
	handler.handle(stream, Arc::clone(&router.state)).await
}
