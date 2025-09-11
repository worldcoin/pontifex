#![deny(
	clippy::all,
	clippy::pedantic,
	clippy::nursery,
	missing_docs,
	dead_code
)]
#![doc = include_str!("../README.md")]

use const_fnv1a_hash::fnv1a_hash_str_32;
use serde::{Serialize, de::DeserializeOwned};

/// Type-safe request-response pairing for client-server communication.
///
/// This trait links each request type to its corresponding response type at compile time,
/// preventing mismatched request/response errors that would otherwise only appear at runtime.
///
/// # How It Works
///
/// When you implement this trait for a request type, you specify:
/// 1. A unique string identifier (`ROUTE_ID`) that the router uses to dispatch requests
/// 2. The expected response type via the `Response` associated type
///
/// The client and server use this information to ensure type safety:
/// - The client knows what response to expect for each request
/// - The server knows how to deserialize requests and what response type to return
///
/// # Example
///
/// ```rust,ignore
/// #[derive(Serialize, Deserialize)]
/// struct HealthCheck;
///
/// #[derive(Serialize, Deserialize)]
/// struct HealthStatus { ok: bool }
///
/// impl Request for HealthCheck {
///     const ROUTE_ID: &'static str = "health_check_v1";
///     type Response = HealthStatus;
/// }
/// ```
pub trait Request: Serialize + DeserializeOwned + Send + Sync + 'static {
	/// Unique string identifier for this request type.
	///
	/// ⚠️ **CRITICAL**: Never change this value after deployment!
	/// Changing it breaks compatibility between client and server versions.
	///
	/// **Naming convention**: Use versioned names like `"operation_v1"`, `"operation_v2"`
	/// to support multiple versions of the same operation.
	const ROUTE_ID: &'static str;

	/// The response type that this request expects to receive.
	/// This creates a compile-time guarantee that requests and responses match.
	type Response: Serialize + DeserializeOwned + Send;

	/// Computes a numeric ID from `ROUTE_ID` for efficient routing.
	///
	/// This is used internally by the router to quickly dispatch requests.
	/// The hash function (FNV-1a) is deterministic, so the same `ROUTE_ID`
	/// always produces the same numeric ID.
	#[must_use]
	fn type_id() -> u32 {
		// FNV-1a is a fast, simple hash that's deterministic across runs
		fnv1a_hash_str_32(Self::ROUTE_ID)
	}
}

/// Client-side functionality.
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "client")]
pub use client::{ConnectionDetails, send};

/// Server-side functionality.
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "server")]
pub use server::Router;

/// Enables low-level interfacing with the Nitro Secure Module (NSM).
#[cfg(any(feature = "nsm", feature = "nsm-types"))]
pub mod nsm;
#[cfg(feature = "nsm")]
pub use nsm::SecureModule;
#[cfg(feature = "nsm-types")]
pub use nsm::{AttestationDoc, AttestationError};

/// KMS functionality.
#[cfg(feature = "kms")]
pub mod kms;

/// HTTP-through-vsock
#[cfg(feature = "http")]
pub mod http;

mod utils;
