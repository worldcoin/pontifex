pub use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest, ErrorCode, Request, Response};

use coset::{CborSerializable, CoseSign1};

#[cfg(feature = "nsm")]
use {
	aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request},
	serde_bytes::ByteBuf,
	std::{io, os::fd::RawFd},
	tokio::sync::OnceCell,
};

/// A global connection to the Nitro Secure Module (NSM).
#[cfg(feature = "nsm")]
pub(crate) static SECURE_MODULE_GLOBAL: OnceCell<SecureModule> = OnceCell::const_new();

/// A connection to the Nitro Secure Module (NSM).
#[cfg(feature = "nsm")]
pub struct SecureModule {
	fd: RawFd,
}

/// Errors that can occur when requesting an attestation document from the NSM.
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
	/// Failed to get attestation from NSM.
	#[error("AttestationError::Nsm: {0:?}")]
	Nsm(ErrorCode),
	/// Failed to decode the CBOR payload of an attestation document.
	#[error("AttestationError::Encoding: {0}")]
	Encoding(String),
	/// Failed to decode the COSE Sign1 envelope of an attestation document.
	#[error("AttestationError::Cose: {0}")]
	Cose(String),
}

/// Parse a raw attestation document into an `AttestationDoc`.
///
/// This only decodes the document — it does **not** verify the COSE signature, the certificate
/// chain, the PCR values or the timestamp. Use the `verify` module for that.
///
/// # Errors
/// Returns an error if the document cannot be decoded.
pub fn parse_raw_attestation_doc(document: &[u8]) -> Result<AttestationDoc, AttestationError> {
	parse_cose_attestation_doc(document).map(|(_, attestation_doc)| attestation_doc)
}

/// Parse a raw attestation document, returning the COSE Sign1 envelope alongside the decoded
/// payload. The envelope is what carries the signature, so verification needs both.
///
/// # Errors
/// Returns an error if the document cannot be decoded.
pub(crate) fn parse_cose_attestation_doc(
	document: &[u8],
) -> Result<(CoseSign1, AttestationDoc), AttestationError> {
	let cose_document =
		CoseSign1::from_slice(document).map_err(|e| AttestationError::Cose(e.to_string()))?;

	let payload = cose_document
		.payload
		.as_ref()
		.ok_or_else(|| AttestationError::Cose("missing payload in COSE Sign1".to_string()))?;

	let attestation_doc = ciborium::from_reader::<AttestationDoc, _>(payload.as_slice())
		.map_err(|e| AttestationError::Encoding(e.to_string()))?;

	Ok((cose_document, attestation_doc))
}

#[cfg(feature = "nsm")]
impl SecureModule {
	/// Connect to the NSM driver.
	///
	/// # Errors
	///
	/// Returns an error if a connection to the NSM driver cannot be established.
	pub fn connect() -> io::Result<Self> {
		let fd = nsm_init();

		if fd == -1 {
			return Err(io::Error::new(
				io::ErrorKind::ConnectionRefused,
				"Failed to initialize NSM",
			));
		}

		Ok(Self { fd })
	}

	/// Send a request to the NSM driver.
	#[must_use]
	pub fn send(&self, request: Request) -> Response {
		nsm_process_request(self.fd, request)
	}

	/// The `module_id` of this enclave, formatted `i-<instance-id>-enc<enclave-id>`.
	///
	/// # Errors
	///
	/// Returns an error if the NSM driver returns an error.
	pub fn module_id(&self) -> Result<String, AttestationError> {
		match self.send(Request::DescribeNSM) {
			Response::DescribeNSM { module_id, .. } => Ok(module_id),
			Response::Error(code) => Err(AttestationError::Nsm(code)),
			other => unreachable!("NSM answered DescribeNSM with {other:?}"),
		}
	}

	/// Create an attestation document, and return it as a binary blob.
	///
	/// # Errors
	///
	/// Returns an error if the NSM driver returns an error.
	pub fn raw_attest(
		&self,
		user_data: Option<impl Into<Vec<u8>>>,
		nonce: Option<impl Into<Vec<u8>>>,
		public_key: Option<impl Into<Vec<u8>>>,
	) -> Result<Vec<u8>, AttestationError> {
		let response = self.send(Request::Attestation {
			nonce: nonce.map(ByteBuf::from),
			user_data: user_data.map(ByteBuf::from),
			public_key: public_key.map(ByteBuf::from),
		});

		match response {
			Response::Error(code) => Err(AttestationError::Nsm(code)),
			Response::Attestation { document } => Ok(document),
			_ => unreachable!("Unexpected response type"),
		}
	}

	/// Create an `AttestationDoc` and sign it with it's private key to ensure authenticity.
	///
	/// # Errors
	///
	/// Returns an error if the NSM driver returns an error or if the response cannot be decoded.
	pub fn attest(
		&self,
		user_data: Option<impl Into<Vec<u8>>>,
		nonce: Option<impl Into<Vec<u8>>>,
		public_key: Option<impl Into<Vec<u8>>>,
	) -> Result<AttestationDoc, AttestationError> {
		let document = self.raw_attest(user_data, nonce, public_key)?;
		Self::parse_raw_attestation_doc(&document)
	}

	/// Parse a raw attestation document into an `AttestationDoc`.
	///
	/// # Errors
	/// Returns an error if the document cannot be decoded.
	pub fn parse_raw_attestation_doc(document: &[u8]) -> Result<AttestationDoc, AttestationError> {
		crate::nsm::parse_raw_attestation_doc(document)
	}

	/// Attempt to get the global NSM instance.
	pub fn try_global() -> Option<&'static Self> {
		SECURE_MODULE_GLOBAL.get()
	}

	/// Get the global NSM instance.
	///
	/// # Panics
	///
	/// Panics if the global NSM instance has not been initialized.
	#[must_use]
	pub fn global() -> &'static Self {
		Self::try_global().expect("NSM global not initialized")
	}

	/// Attempts to get global NSM instance, initializing it if necessary.
	///
	/// # Errors
	///
	/// Propagates `io::Error` if the connection to the NSM fails.
	pub async fn try_init_global() -> io::Result<&'static Self> {
		let nsm = Self::connect()?;

		let secure_module = SECURE_MODULE_GLOBAL.get_or_init(|| async { nsm }).await;

		Ok(secure_module)
	}

	/// Disconnect from the NSM driver.
	pub fn disconnect(self) {
		drop(self);
	}
}

#[cfg(feature = "nsm")]
impl Drop for SecureModule {
	fn drop(&mut self) {
		nsm_exit(self.fd);
	}
}

#[cfg(all(test, feature = "nsm"))]
mod tests {
	use super::*;

	/// Takes a COSE-signed attestation document and asserts that it can be properly parsed into an `AttestationDoc`.
	///
	/// The `mock-attestation-doc` is generated from a test Nitro enclave with some values sanitized.
	#[test]
	fn test_parse_raw_attestation_doc() {
		let document = include_bytes!("../tests/mock-attestation-doc.cose");
		let document: AttestationDoc = SecureModule::parse_raw_attestation_doc(document).unwrap();

		assert_eq!(document.module_id, "test");
		assert_eq!(document.timestamp, 1_748_469_829_761);
		assert_eq!(document.certificate, ByteBuf::from(vec![3, 4]));
		assert_eq!(document.nonce, Some(ByteBuf::from(b"some nonce")));
		assert_eq!(document.user_data, Some(ByteBuf::from(b"hello, world!")));
	}
}
