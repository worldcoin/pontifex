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

/// Type-safe request-response association for pontifex.
///
/// This trait ensures compile-time safety by associating each request type
/// with its expected response type, eliminating runtime errors from mismatched
/// request/response pairs.
pub trait Request: Serialize + DeserializeOwned + Send + 'static {
	/// Stable string identifier for this request type.
	/// This should NEVER change once defined, as it affects client-server compatibility.
	/// Example: "health_check_v1", "initialize_v1"
	const ROUTE_ID: &'static str;

	/// The response type this request expects
	type Response: Serialize + DeserializeOwned + Send;

	/// Returns a hashed type ID from the stable ROUTE_ID
	fn type_id() -> u32 {
		// Use const FNV-1a hash of the stable route ID
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
