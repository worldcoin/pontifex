//! Attestation document verification types and data structures.
//!
//! This module contains the core types used for AWS Nitro Enclave attestation
//! document parsing, verification, and PCR configuration management.

use serde::{Deserialize, Serialize};

/// Represents errors that can occur during enclave attestation verification
#[derive(Debug, thiserror::Error)]
pub enum EnclaveAttestationError {
	/// Failed to parse attestation document
	#[error("Failed to parse attestation document: {0}")]
	AttestationDocumentParseError(String),

	/// Certificate chain validation failed
	#[error("Certificate chain validation failed: {0}")]
	AttestationChainInvalid(String),

	/// Signature verification failed
	#[error("Signature verification failed: {0}")]
	AttestationSignatureInvalid(String),

	/// PCR value did not match the expected value
	#[error("PCR{pcr_index} value not trusted: {actual}")]
	CodeUntrusted {
		/// The index of the PCR value that failed validation
		pcr_index: u32,
		/// The actual value of the PCR that failed validation
		actual: String,
	},

	/// Attestation timestamp is too old
	#[error("Attestation is too old: {age_millis}ms (max: {max_age}ms)")]
	AttestationStale {
		/// The age of the attestation in milliseconds
		age_millis: u64,
		/// The maximum age of the attestation in milliseconds
		max_age: u64,
	},

	/// Invalid timestamp
	#[error("Invalid timestamp: {0}")]
	AttestationInvalidTimestamp(String),

	/// The authenticated `user_data` is missing or does not commit to the supplied key.
	#[error("Attestation user_data does not match the public key commitment")]
	KeyCommitmentMismatch,
}

/// Result type for enclave attestation operations
pub type EnclaveAttestationResult<T, E = EnclaveAttestationError> = Result<T, E>;

/// Metadata from a verified attestation document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedAttestation {
	/// Document creation time in milliseconds since the Unix epoch.
	pub timestamp: u64,
	/// Identifier of the Nitro module that issued the attestation.
	pub module_id: String,
}

impl VerifiedAttestation {
	/// Creates a new `VerifiedAttestation`.
	#[must_use]
	pub const fn new(timestamp: u64, module_id: String) -> Self {
		Self {
			timestamp,
			module_id,
		}
	}
}

/// Represents a PCR measurement with its index and value
/// Used to define expected PCR values for attestation verification
#[derive(Clone, Debug)]
pub struct PcrMeasurement {
	/// Index of the PCR measurement
	pub index: u32,
	/// Byte array representing the PCR value
	pub value: Vec<u8>,
}

impl PcrMeasurement {
	/// Creates a new `PcrMeasurement`
	///
	/// # Arguments
	/// * `index` - The index of the PCR
	/// * `value` - The expected value of the PCR
	#[must_use]
	pub fn new(index: u32, value: impl Into<Vec<u8>>) -> Self {
		Self {
			index,
			value: value.into(),
		}
	}
}
