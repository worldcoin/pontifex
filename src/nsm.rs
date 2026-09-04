//! Enables low-level interfacing with the Nitro Secure Module (NSM).
//!
//! Some types are "*mirrored*" from `aws-nitro-enclaves-nsm-api` crate to avoid pulling in `libc` dep
//! and unmaintained `serde_cbor`. The [`nsm_api_compat`] module ensures no-divergence.
#[cfg(feature = "nsm")]
pub use aws_nitro_enclaves_nsm_api::api::{ErrorCode, Request, Response};
use std::collections::BTreeMap;

use coset::{CborSerializable, CoseSign1};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

/// The digest algorithm used for the PCR values. **Mirrored**.
#[derive(Debug, Serialize, Deserialize, Copy, Clone, PartialEq, Eq)]
pub enum Digest {
	/// SHA256
	SHA256,
	/// SHA384
	SHA384,
	/// SHA512
	SHA512,
}

/// A Nitro attestation document. **Mirrored**.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct AttestationDoc {
	/// Issuing NSM ID.
	pub module_id: String,
	/// The digest function used for the PCR values.
	pub digest: Digest,
	/// Creation time, in milliseconds since the Unix epoch.
	pub timestamp: u64,
	/// Every PCR locked at the moment the document was generated.
	pub pcrs: BTreeMap<usize, ByteBuf>,
	/// The infrastructure certificate that signed the document, DER encoded.
	pub certificate: ByteBuf,
	/// Issuing CA bundle for the infrastructure certificate.
	pub cabundle: Vec<ByteBuf>,
	/// Representation of a public key used to encrypt data to the enclave.
	pub public_key: Option<ByteBuf>,
	/// Additional signed user data, as defined by the protocol.
	pub user_data: Option<ByteBuf>,
	/// An optional consumer-provided nonce, proving the document was minted for this request.
	pub nonce: Option<ByteBuf>,
}

#[cfg(feature = "nsm")]
use {
	aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request},
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
#[non_exhaustive]
pub enum AttestationError {
	/// Failed to get attestation from NSM.
	#[cfg(feature = "nsm")]
	#[error("AttestationError::Nsm: {0:?}")]
	Nsm(ErrorCode),
	/// Failed to decode the CBOR payload of an attestation document.
	#[error("AttestationError::Encoding: {0}")]
	Encoding(String),
	/// Failed to decode the COSE Sign1 envelope of an attestation document.
	#[error("AttestationError::Cose: {0}")]
	Cose(String),
}

#[cfg(any(feature = "nsm", feature = "attestation"))]
impl AttestationDoc {
	/// Parses an attestation doc from raw bytes. Does **not** validate the signature.
	///
	/// # Errors
	/// Errors if the document is invalid or cannot be parsed.
	pub(crate) fn from_bytes(doc: &[u8]) -> Result<(Self, CoseSign1), AttestationError> {
		let cose_document =
			CoseSign1::from_slice(doc).map_err(|e| AttestationError::Cose(e.to_string()))?;

		let payload = cose_document
			.payload
			.as_ref()
			.ok_or_else(|| AttestationError::Cose("missing payload in COSE Sign1".to_string()))?;

		let mut remaining = payload.as_slice();
		let attestation_doc = ciborium::from_reader::<Self, _>(&mut remaining)
			.map_err(|e| AttestationError::Encoding(e.to_string()))?;
		if !remaining.is_empty() {
			return Err(AttestationError::Encoding(format!(
				"{} trailing bytes after the attestation document",
				remaining.len()
			)));
		}

		Ok((attestation_doc, cose_document))
	}
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

	/// Create an [`AttestationDoc`], and return it as a binary blob without verifying.
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

	/// Create an [`AttestationDoc`] for the provided inputs.
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
		let (doc, _sig) = AttestationDoc::from_bytes(&document)?; // signature not verified here
		Ok(doc)
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

/// Ensures **mirrored** types match the upstream `aws_nitro_enclaves_nsm_api` crate.
#[cfg(all(test, any(feature = "nsm", feature = "attestation")))]
mod nsm_api_compat {
	use aws_nitro_enclaves_nsm_api::api as upstream;

	use super::{AttestationDoc, Digest};

	#[allow(dead_code, reason = "exists to be type-checked, not called")]
	fn document_is_field_for_field_identical(doc: upstream::AttestationDoc) -> AttestationDoc {
		let upstream::AttestationDoc {
			module_id,
			digest,
			timestamp,
			pcrs,
			certificate,
			cabundle,
			public_key,
			user_data,
			nonce,
		} = doc;

		AttestationDoc {
			module_id,
			digest: digest_variants_match(digest),
			timestamp,
			pcrs,
			certificate,
			cabundle,
			public_key,
			user_data,
			nonce,
		}
	}

	const fn digest_variants_match(digest: upstream::Digest) -> Digest {
		match digest {
			upstream::Digest::SHA256 => Digest::SHA256,
			upstream::Digest::SHA384 => Digest::SHA384,
			upstream::Digest::SHA512 => Digest::SHA512,
		}
	}

	#[test]
	fn the_two_types_decode_a_real_document_identically() {
		let payload = super::AttestationDoc::from_bytes(super::tests::MOCK_DOC)
			.map(|(_, envelope)| envelope.payload.expect("fixture has a payload"))
			.expect("fixture parses");

		let ours: AttestationDoc = ciborium::from_reader(payload.as_slice()).expect("ours decodes");
		let theirs: upstream::AttestationDoc =
			ciborium::from_reader(payload.as_slice()).expect("upstream decodes");

		assert_eq!(ours, document_is_field_for_field_identical(theirs));
	}
}

#[cfg(all(test, any(feature = "nsm", feature = "attestation")))]
mod tests {
	use serde_bytes::ByteBuf;

	use super::*;

	pub(super) const MOCK_DOC: &[u8] = include_bytes!("../tests/mock-attestation-doc.cose");

	/// The `mock-attestation-doc` is generated from a test Nitro enclave with some values sanitized.
	#[test]
	fn test_parse_raw_attestation_doc() {
		let (document, _sig) = AttestationDoc::from_bytes(MOCK_DOC).unwrap();

		assert_eq!(document.module_id, "test");
		assert_eq!(document.timestamp, 1_748_469_829_761);
		assert_eq!(document.certificate, ByteBuf::from(vec![3, 4]));
		assert_eq!(document.nonce, Some(ByteBuf::from(b"some nonce")));
		assert_eq!(document.user_data, Some(ByteBuf::from(b"hello, world!")));
	}

	#[test]
	fn trailing_bytes_after_the_payload_are_rejected() {
		let (_, envelope) = AttestationDoc::from_bytes(MOCK_DOC).unwrap();
		let mut payload = envelope.payload.clone().unwrap();
		payload.push(0xf6);

		let tampered = CoseSign1 {
			payload: Some(payload),
			..envelope
		}
		.to_vec()
		.unwrap();

		assert!(matches!(
			AttestationDoc::from_bytes(&tampered),
			Err(AttestationError::Encoding(_))
		));
	}

	#[test]
	fn a_tagged_cose_sign1_is_rejected() {
		let mut tagged = vec![0xd2];
		tagged.extend_from_slice(MOCK_DOC);

		assert!(matches!(
			AttestationDoc::from_bytes(&tagged),
			Err(AttestationError::Cose(_))
		));
	}
}
