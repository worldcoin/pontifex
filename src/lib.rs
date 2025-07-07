#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]
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
pub use server::listen;

#[cfg(any(feature = "nsm", feature = "nsm-types"))]
pub mod nsm;
#[cfg(feature = "nsm")]
pub use nsm::SecureModule;
#[cfg(feature = "nsm-types")]
pub use nsm::{AttestationDoc, AttestationError};

mod utils;
