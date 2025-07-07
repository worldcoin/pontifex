#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![doc = include_str!("../README.md")]

/// Client-side functionality.
#[cfg(feature = "client")]
pub mod client;
#[cfg(feature = "client")]
pub use client::{ConnectionDetails, send};

/// Server-side functionality.
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "server")]
pub use server::{listen, listen_with_ctx};

/// Nitro Secure Module (NSM) functionality.
#[cfg(any(feature = "nsm", feature = "nsm-types"))]
pub mod nsm;
#[cfg(feature = "nsm")]
pub use nsm::SecureModule;
#[cfg(feature = "nsm-types")]
pub use nsm::{AttestationDoc, AttestationError};

/// KMS functionality.
#[cfg(feature = "kms")]
pub mod kms;

mod utils;
