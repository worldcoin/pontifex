#[cfg(feature = "nsm")]
pub use aws_nitro_enclaves_nsm_api::api::{ErrorCode, Request, Response};
use std::collections::BTreeMap;

use coset::{CborSerializable, CoseSign1};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

/// The digest algorithm used for the PCR values.
///
/// Mirrors the NSM's own type so a client does not need `aws-nitro-enclaves-nsm-api` — and with it
/// `libc`, `log` and the unmaintained `serde_cbor` — merely to name it. `nsm_api_compat` below
/// fails to compile if the two ever diverge.
#[derive(Debug, Serialize, Deserialize, Copy, Clone, PartialEq, Eq)]
#[allow(
	clippy::upper_case_acronyms,
	reason = "wire format: the CBOR strings are uppercase"
)]
pub enum Digest {
	/// SHA256
	SHA256,
	/// SHA384
	SHA384,
	/// SHA512
	SHA512,
}

/// A Nitro attestation document, as carried in the payload of the COSE Sign1 envelope.
///
/// Field names and order are the wire format; see [`Digest`] on why this is defined here rather
/// than borrowed from `aws-nitro-enclaves-nsm-api`.
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
	/// An optional DER-encoded key the consumer can encrypt data to.
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

/// Parse a raw attestation document into an `AttestationDoc`.
///
/// This only decodes the document — it does **not** verify the COSE signature, the certificate
/// chain, the PCR values or the timestamp. Use the `verify` module for that.
///
/// Only untagged `COSE_Sign1` is accepted, which is what the NSM emits; CBOR tag 18 is rejected.
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

	// `from_reader` stops at the end of the first CBOR item; anything after it would be accepted
	// silently, leaving two decoders free to disagree on what the document says.
	let mut remaining = payload.as_slice();
	let attestation_doc = ciborium::from_reader::<AttestationDoc, _>(&mut remaining)
		.map_err(|e| AttestationError::Encoding(e.to_string()))?;
	if !remaining.is_empty() {
		return Err(AttestationError::Encoding(format!(
			"{} trailing bytes after the attestation document",
			remaining.len()
		)));
	}

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
		parse_raw_attestation_doc(&document)
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

/// Proves our mirrored document types still match `aws-nitro-enclaves-nsm-api`.
///
/// Nothing here runs — the value is that it stops compiling if AWS adds, removes, renames or
/// retypes a field, or adds a `Digest` variant. `aws-nitro-enclaves-nsm-api` is a dev-dependency
/// only, so this costs a client build nothing.
#[cfg(test)]
mod nsm_api_compat {
	use aws_nitro_enclaves_nsm_api::api as upstream;

	use super::{AttestationDoc, Digest};

	/// Exhaustive destructuring: an added, removed or renamed field fails to compile, and the
	/// struct literal fails if any field's type changed.
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

	/// Exhaustive match: a new upstream variant fails to compile.
	const fn digest_variants_match(digest: upstream::Digest) -> Digest {
		match digest {
			upstream::Digest::SHA256 => Digest::SHA256,
			upstream::Digest::SHA384 => Digest::SHA384,
			upstream::Digest::SHA512 => Digest::SHA512,
		}
	}

	/// Structure matching is not encoding matching, so decode the real document both ways.
	#[test]
	fn the_two_types_decode_a_real_document_identically() {
		let payload = super::parse_cose_attestation_doc(super::tests::MOCK_DOC)
			.map(|(envelope, _)| envelope.payload.expect("fixture has a payload"))
			.expect("fixture parses");

		let ours: AttestationDoc = ciborium::from_reader(payload.as_slice()).expect("ours decodes");
		let theirs: upstream::AttestationDoc =
			ciborium::from_reader(payload.as_slice()).expect("upstream decodes");

		assert_eq!(ours, document_is_field_for_field_identical(theirs));
	}
}

#[cfg(test)]
mod tests {
	use serde_bytes::ByteBuf;

	use super::*;

	pub(super) const MOCK_DOC: &[u8] = include_bytes!("../tests/mock-attestation-doc.cose");

	/// The `mock-attestation-doc` is generated from a test Nitro enclave with some values sanitized.
	#[test]
	fn test_parse_raw_attestation_doc() {
		let document = parse_raw_attestation_doc(MOCK_DOC).unwrap();

		assert_eq!(document.module_id, "test");
		assert_eq!(document.timestamp, 1_748_469_829_761);
		assert_eq!(document.certificate, ByteBuf::from(vec![3, 4]));
		assert_eq!(document.nonce, Some(ByteBuf::from(b"some nonce")));
		assert_eq!(document.user_data, Some(ByteBuf::from(b"hello, world!")));
	}

	#[test]
	fn trailing_bytes_after_the_payload_are_rejected() {
		let (envelope, _) = parse_cose_attestation_doc(MOCK_DOC).unwrap();
		let mut payload = envelope.payload.clone().unwrap();
		payload.push(0xf6);

		let tampered = CoseSign1 {
			payload: Some(payload),
			..envelope
		}
		.to_vec()
		.unwrap();

		assert!(matches!(
			parse_raw_attestation_doc(&tampered),
			Err(AttestationError::Encoding(_))
		));
	}

	#[test]
	fn a_tagged_cose_sign1_is_rejected() {
		let mut tagged = vec![0xd2];
		tagged.extend_from_slice(MOCK_DOC);

		assert!(matches!(
			parse_raw_attestation_doc(&tagged),
			Err(AttestationError::Cose(_))
		));
	}
}
