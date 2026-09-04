//! Verification of AWS Nitro Enclave attestation documents.
//!
//! Checks a document's COSE Sign1 signature, its certificate chain up to the AWS Nitro root, the
//! PCR values identifying the enclave's code, and the document's age. What the document *asserts*
//! — its `public_key`, `nonce` and `user_data` — is returned for the caller to interpret.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::STANDARD};
use coset::{Algorithm, CoseSign1, iana};
use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use serde::Serialize;
use webpki::{EndEntityCert, TrustAnchor};
use x509_cert::{Certificate, der::Decode};

use crate::nsm::{AttestationDoc, Digest, parse_cose_attestation_doc};

/// AWS Nitro Root Certificate (G1), in DER form.
///
/// Source: <https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip>
/// Stored at `src/aws_nitro_root_g1.der`
pub const AWS_NITRO_ROOT_CERT: &[u8] = include_bytes!("aws_nitro_root_g1.der");

/// Default maximum age for an attestation document.
///
/// Override with [`Verifier::with_max_age`].
pub const DEFAULT_MAX_ATTESTATION_AGE: Duration = Duration::from_hours(3);

/// Get the expected PCR length depending on the hashing algorithm used
/// As of right now, only SHA-384 is used
/// More info: <https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html>
#[must_use]
pub const fn get_expected_pcr_length(digest: Digest) -> usize {
	match digest {
		Digest::SHA384 => 48,
		Digest::SHA256 => 32,
		Digest::SHA512 => 64,
	}
}

/// Represents errors that can occur during enclave attestation verification
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
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
}

/// Verified attestation data from the enclave.
///
/// Only a verifier constructs this, so it deliberately does not implement `Deserialize`: a value
/// decoded from a request body would claim a verification that never happened.
#[derive(Debug, Clone, Serialize)]
pub struct VerifiedAttestation {
	/// The public key the enclave attested, if it carried one. Documents that bind a key by
	/// commitment instead leave this empty.
	pub enclave_public_key: Option<Vec<u8>>,

	/// The timestamp of the attestation
	pub timestamp: u64,
	/// The module ID of the enclave
	pub module_id: String,
	/// The signed nonce, if the enclave was asked for one. Compare it against the challenge you
	/// issued — the timestamp alone does not prove the document was minted for this session.
	pub nonce: Option<Vec<u8>>,
	/// The signed user data, if the enclave supplied any.
	pub user_data: Option<Vec<u8>>,
}

impl VerifiedAttestation {
	/// Creates a new `VerifiedAttestation`
	///
	/// # Arguments
	/// * `enclave_public_key` - The public key the enclave attested, if any
	/// * `timestamp` - The timestamp of the attestation
	/// * `module_id` - The module ID of the enclave
	/// * `nonce` - The signed nonce, if any
	/// * `user_data` - The signed user data, if any
	#[must_use]
	pub const fn new(
		enclave_public_key: Option<Vec<u8>>,
		timestamp: u64,
		module_id: String,
		nonce: Option<Vec<u8>>,
		user_data: Option<Vec<u8>>,
	) -> Self {
		Self {
			enclave_public_key,
			timestamp,
			module_id,
			nonce,
			user_data,
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

/// How far ahead of the verifier's clock an attestation may be dated before it is an error.
const CLOCK_SKEW_TOLERANCE_MILLIS: u64 = 60_000;

fn hex_encode(bytes: &[u8]) -> String {
	bytes.iter().fold(String::new(), |mut out, byte| {
		use std::fmt::Write as _;
		let _ = write!(out, "{byte:02x}");
		out
	})
}

/// Verifies AWS Nitro Enclave attestation documents
///
/// This struct performs comprehensive verification of attestation documents including:
/// - COSE Sign1 signature verification
/// - Certificate chain validation against AWS Nitro root certificates
/// - PCR (Platform Configuration Register) value validation
/// - Attestation document freshness checks
/// - Public key extraction
#[derive(Debug)]
pub struct Verifier {
	/// Allowed PCR configs for validation
	/// Each configuration is a list of (PCR index, expected value) pairs.
	///
	/// This allows for supporting multiple enclave software versions.
	allowed_pcr_configs: Vec<Vec<PcrMeasurement>>,
	root_certificate: Vec<u8>,
	max_age: Duration,
	#[cfg(test)]
	skip_certificate_time_check: bool,
}

impl Verifier {
	/// Creates a new `Verifier` trusting the AWS Nitro root certificate and
	/// [`DEFAULT_MAX_ATTESTATION_AGE`].
	///
	/// # Arguments
	/// * `allowed_pcr_configs` - Allowed PCR configurations. Verification succeeds if *any*
	///   configuration matches, which allows supporting multiple enclave software versions.
	#[must_use]
	pub fn new(allowed_pcr_configs: Vec<Vec<PcrMeasurement>>) -> Self {
		Self {
			allowed_pcr_configs,
			root_certificate: AWS_NITRO_ROOT_CERT.to_vec(),
			max_age: DEFAULT_MAX_ATTESTATION_AGE,
			#[cfg(test)]
			skip_certificate_time_check: false,
		}
	}

	/// Sets how old an attestation document may be before it is rejected as stale.
	#[must_use]
	pub const fn with_max_age(mut self, max_age: Duration) -> Self {
		self.max_age = max_age;
		self
	}

	/// Sets the DER-encoded root certificate the attestation chain must chain up to.
	#[must_use]
	pub fn with_root_certificate(mut self, root_certificate: Vec<u8>) -> Self {
		self.root_certificate = root_certificate;
		self
	}

	/// Verifies a base64-encoded attestation document
	///
	/// This is a convenience method that handles base64 decoding and then verifies the document
	///
	/// # Arguments
	/// * `attestation_doc_base64` - The base64-encoded attestation document
	///
	/// # Returns
	/// A verified attestation containing the enclave's public key and PCR values
	///
	/// # Errors
	/// Returns an error if the base64 decoding fails or the attestation document verification fails
	pub fn verify_attestation_document_base64(
		&self,
		attestation_doc_base64: &str,
	) -> Result<VerifiedAttestation, Error> {
		let attestation_doc_bytes = STANDARD.decode(attestation_doc_base64).map_err(|e| {
			Error::AttestationDocumentParseError(format!(
				"Failed to decode base64 attestation document: {e}"
			))
		})?;

		self.verify_attestation_document(&attestation_doc_bytes)
	}

	/// Verifies the attestation document from the enclave.
	///
	/// Follows the AWS Nitro Enclave Attestation Document Specification:
	/// <https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-attestation-document.html>
	///
	/// # Arguments
	/// * `attestation_doc_bytes` - The raw (COSE Sign1) attestation document
	///
	/// # Returns
	/// A verified attestation containing the enclave's public key and PCR values
	///
	/// # Errors
	/// Returns an error if any verification step fails
	pub fn verify_attestation_document(
		&self,
		attestation_doc_bytes: &[u8],
	) -> Result<VerifiedAttestation, Error> {
		// 1. Syntactical validation
		let (cose_sign1, attestation) = parse_cose_attestation_doc(attestation_doc_bytes)
			.map_err(|e| Error::AttestationDocumentParseError(e.to_string()))?;

		// 2. Semantic validation
		let leaf_cert = self.verify_certificate_chain(&attestation)?;

		// 3. Cryptographic validation
		Self::verify_cose_signature(&cose_sign1, &leaf_cert)?;
		self.validate_pcr_values(&attestation)?;
		self.check_attestation_freshness(&attestation)?;

		Ok(VerifiedAttestation::new(
			attestation.public_key.map(serde_bytes::ByteBuf::into_vec),
			attestation.timestamp,
			attestation.module_id,
			attestation.nonce.map(serde_bytes::ByteBuf::into_vec),
			attestation.user_data.map(serde_bytes::ByteBuf::into_vec),
		))
	}

	fn verify_certificate_chain(&self, attestation: &AttestationDoc) -> Result<Certificate, Error> {
		let root_cert_der = self.root_certificate.as_slice();

		let trust_anchor = TrustAnchor::try_from_cert_der(root_cert_der).map_err(|e| {
			Error::AttestationChainInvalid(format!(
				"Failed to create trust anchor from root certificate: {e}"
			))
		})?;

		let intermediate_certs: Vec<&[u8]> = attestation
			.cabundle
			.iter()
			.skip(1)
			.map(|cert| cert.as_slice())
			.collect();

		let should_skip_time_check = {
			#[cfg(test)]
			{
				self.skip_certificate_time_check
			}
			#[cfg(not(test))]
			{
				false
			}
		};

		let current_time = if should_skip_time_check {
			// Tests only: judge validity at the attestation's own time, so expired fixtures work.
			webpki::Time::from_seconds_since_unix_epoch(attestation.timestamp / 1000)
		} else {
			let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| {
				Error::AttestationInvalidTimestamp(format!("Failed to get current time: {e}"))
			})?;
			webpki::Time::from_seconds_since_unix_epoch(now.as_secs())
		};

		let end_entity_cert =
			EndEntityCert::try_from(attestation.certificate.as_slice()).map_err(|e| {
				Error::AttestationChainInvalid(format!("Failed to parse leaf certificate: {e}"))
			})?;

		end_entity_cert
			.verify_is_valid_tls_server_cert(
				&[&webpki::ECDSA_P384_SHA384],
				&webpki::TlsServerTrustAnchors(&[trust_anchor]),
				&intermediate_certs,
				current_time,
			)
			.map_err(|e| {
				Error::AttestationChainInvalid(format!("Certificate chain validation failed: {e}"))
			})?;

		Certificate::from_der(&attestation.certificate).map_err(|e| {
			Error::AttestationChainInvalid(format!(
				"Failed to parse leaf certificate for return: {e}"
			))
		})
	}

	fn verify_cose_signature(cose_sign1: &CoseSign1, leaf_cert: &Certificate) -> Result<(), Error> {
		let spki = &leaf_cert.tbs_certificate.subject_public_key_info;
		let public_key_bytes = spki.subject_public_key.as_bytes().ok_or_else(|| {
			Error::AttestationSignatureInvalid("Failed to extract public key bytes".to_string())
		})?;

		let verifying_key = VerifyingKey::from_sec1_bytes(public_key_bytes).map_err(|e| {
			Error::AttestationSignatureInvalid(format!("Failed to parse P-384 public key: {e}"))
		})?;

		// The spec fixes the algorithm at ES384; accepting a document that declares anything else
		// would let the header disagree with the P-384 check performed below.
		let alg = cose_sign1.protected.header.alg.as_ref();
		if alg != Some(&Algorithm::Assigned(iana::Algorithm::ES384)) {
			return Err(Error::AttestationSignatureInvalid(format!(
				"Expected ES384 in the protected header, got {alg:?}"
			)));
		}

		// coset substitutes an empty payload when there is none, which would verify a signature
		// over a document this function never saw.
		if cose_sign1.payload.is_none() {
			return Err(Error::AttestationSignatureInvalid(
				"Missing payload in COSE Sign1".to_string(),
			));
		}

		// `verify_signature` reconstructs the COSE Sign1 `Sig_structure`
		// (`["Signature1", protected, external_aad, payload]`) and hands it to the closure
		// alongside the signature. Nitro attestations carry no external AAD.
		cose_sign1.verify_signature(&[], |signature, signed_data| {
			let ecdsa_signature = Signature::try_from(signature).map_err(|e| {
				Error::AttestationSignatureInvalid(format!(
					"Failed to parse ECDSA signature (need 96 raw bytes): {e}"
				))
			})?;

			verifying_key
				.verify(signed_data, &ecdsa_signature)
				.map_err(|e| {
					Error::AttestationSignatureInvalid(format!(
						"Signature verification failed: {e}"
					))
				})
		})
	}

	fn validate_pcr_values(&self, attestation: &AttestationDoc) -> Result<(), Error> {
		if attestation.pcrs.is_empty() {
			return Err(Error::CodeUntrusted {
				pcr_index: 0,
				actual: "attestation carries no PCRs".to_string(),
			});
		}

		let expected_length = get_expected_pcr_length(attestation.digest);

		// An empty configuration compares nothing, so it would match every attestation and
		// silently disable PCR pinning. Never let one satisfy the policy.
		let configs = self
			.allowed_pcr_configs
			.iter()
			.filter(|config| !config.is_empty());

		// Supporting several enclave software versions at once means any one config may match.
		let mut first_mismatch = None;
		for config in configs {
			match Self::first_mismatch(attestation, config, expected_length) {
				None => return Ok(()),
				Some(mismatch) => first_mismatch.get_or_insert(mismatch),
			};
		}

		Err(first_mismatch.map_or_else(
			|| Error::CodeUntrusted {
				pcr_index: 0,
				actual: "no PCR configuration was supplied".to_string(),
			},
			|(pcr_index, actual)| Error::CodeUntrusted { pcr_index, actual },
		))
	}

	/// The first PCR in `config` that the attestation does not satisfy, as `(index, actual)`.
	fn first_mismatch(
		attestation: &AttestationDoc,
		config: &[PcrMeasurement],
		expected_length: usize,
	) -> Option<(u32, String)> {
		config.iter().find_map(|measurement| {
			let actual = attestation.pcrs.get(&(measurement.index as usize));
			match actual {
				Some(value)
					if value.len() == expected_length && value.as_slice() == measurement.value =>
				{
					None
				},
				Some(value) => Some((measurement.index, hex_encode(value))),
				None => Some((measurement.index, "missing".to_string())),
			}
		})
	}

	fn check_attestation_freshness(&self, attestation: &AttestationDoc) -> Result<(), Error> {
		let now = u64::try_from(
			SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.map_err(|e| {
					Error::AttestationInvalidTimestamp(format!("Failed to get current time: {e}"))
				})?
				.as_millis(),
		)
		.map_err(|e| {
			Error::AttestationInvalidTimestamp(format!(
				"Failed to convert current time to milliseconds: {e}"
			))
		})?;

		// Clocks drift between the enclave and the verifier, so a slightly future timestamp is
		// skew rather than a forgery. Beyond the tolerance it is a real error.
		let age = match now.checked_sub(attestation.timestamp) {
			Some(age) => age,
			None if attestation.timestamp - now <= CLOCK_SKEW_TOLERANCE_MILLIS => 0,
			None => {
				return Err(Error::AttestationInvalidTimestamp(format!(
					"Attestation timestamp is {} ms in the future",
					attestation.timestamp - now
				)));
			},
		};

		let max_age_millis = u64::try_from(self.max_age.as_millis()).unwrap_or(u64::MAX);
		if age > max_age_millis {
			return Err(Error::AttestationStale {
				age_millis: age,
				max_age: max_age_millis,
			});
		}

		Ok(())
	}
}

#[cfg(test)]
impl Verifier {
	/// Validates certificates against the attestation's own timestamp rather than the wall clock,
	/// so the expired fixtures stay usable.
	#[must_use]
	pub const fn with_skipped_certificate_time_check(mut self) -> Self {
		self.skip_certificate_time_check = true;
		self
	}

	/// Adds a custom PCR configuration, used for testing.
	pub fn add_allowed_pcr_config(&mut self, pcr_config: Vec<PcrMeasurement>) {
		self.allowed_pcr_configs.push(pcr_config);
	}
}

#[cfg(test)]
mod tests {
	use std::{
		collections::HashMap,
		time::{Duration, SystemTime, UNIX_EPOCH},
	};

	use coset::{CborSerializable, Header, ProtectedHeader};
	use serde_bytes::ByteBuf;

	use super::*;
	use crate::test_fixtures::{
		ATTESTED_PUBLIC_KEY, TEN_YEARS, real_attestation_bytes, real_attestation_verifier,
	};

	// This tests verifies a real attestation document with real PCR values.
	#[test]
	fn test_real_attestation_document() {
		let verified = real_attestation_verifier()
			.verify_attestation_document(&real_attestation_bytes())
			.expect("attestation verification failed");

		assert_eq!(
			verified.enclave_public_key.as_deref(),
			Some(ATTESTED_PUBLIC_KEY.as_slice())
		);
		assert_eq!(
			verified.module_id,
			"i-01b324f0b8b6c25ea-enc01997668bda38b2a"
		);
	}

	// Failure cases
	/// Configuration for generating basic fake attestation documents
	#[derive(Debug, Clone)]
	struct SimpleFakeAttestationConfig {
		/// Module ID for the attestation
		module_id: String,
		/// PCR values to include in the attestation
		pcr_values: HashMap<usize, Vec<u8>>,
		/// Custom timestamp (None = current time)
		timestamp: Option<u64>,
		/// DER bytes used for both the leaf certificate and the CA bundle
		certificate: Vec<u8>,
	}

	impl Default for SimpleFakeAttestationConfig {
		fn default() -> Self {
			Self {
				module_id: "i-test123456789abcdef0-enc0123456789abcdef0".to_string(),
				pcr_values: HashMap::new(),
				timestamp: None,
				certificate: vec![0x30, 0x82, 0x01, 0xFF],
			}
		}
	}

	/// Generate a minimal fake attestation document CBOR for testing
	/// This creates invalid attestation documents that can be used to test specific error conditions
	fn generate_simple_fake_attestation_self_signed(
		config: &SimpleFakeAttestationConfig,
	) -> Result<Vec<u8>, Error> {
		let timestamp = config.timestamp.unwrap_or_else(|| {
			u64::try_from(
				SystemTime::now()
					.duration_since(UNIX_EPOCH)
					.unwrap()
					.as_millis(),
			)
			.unwrap_or(u64::MAX)
		});

		let doc = AttestationDoc {
			module_id: config.module_id.clone(),
			digest: Digest::SHA384,
			timestamp,
			pcrs: config
				.pcr_values
				.iter()
				.map(|(index, value)| (*index, ByteBuf::from(value.clone())))
				.collect(),
			certificate: ByteBuf::from(config.certificate.clone()),
			cabundle: vec![ByteBuf::from(config.certificate.clone())],
			public_key: Some(ByteBuf::from(vec![0x04; 65])),
			user_data: None,
			nonce: None,
		};

		let mut payload = Vec::new();
		ciborium::into_writer(&doc, &mut payload).map_err(|e| {
			Error::AttestationDocumentParseError(format!(
				"Failed to serialize fake attestation document: {e}"
			))
		})?;

		// Built through coset so the envelope is structurally valid COSE_Sign1. A fixture that fails
		// at the parser cannot exercise the chain, signature or PCR stages it is named for.
		CoseSign1 {
			protected: ProtectedHeader::default(),
			unprotected: Header::default(),
			payload: Some(payload),
			signature: vec![0x00; 96],
		}
		.to_vec()
		.map_err(|e| {
			Error::AttestationDocumentParseError(format!("Failed to encode fake COSE Sign1: {e}"))
		})
	}

	/// Flip one bit of the real document's signature, leaving every other byte untouched.
	///
	/// The signature is the trailing 96-byte bstr of the `COSE_Sign1` array, so mutating the last byte
	/// cannot disturb the envelope, the certificate chain or the payload.
	fn real_attestation_with_tampered_signature() -> Vec<u8> {
		let mut bytes = real_attestation_bytes();
		*bytes.last_mut().expect("document is not empty") ^= 0x01;
		bytes
	}

	/// Flip one bit of a PCR value inside the real document's signed payload.
	///
	/// PCR bytes are covered by the signature but are read only after it is checked, so this reaches
	/// `verify_cose_signature` rather than failing earlier on the certificate chain.
	fn real_attestation_with_tampered_payload() -> Vec<u8> {
		let mut bytes = real_attestation_bytes();
		let (_, attestation) =
			crate::nsm::parse_cose_attestation_doc(&bytes).expect("real document parses");
		let pcr0 = attestation.pcrs.get(&0).expect("real document has PCR0");

		let offset = bytes
			.windows(pcr0.len())
			.position(|window| window == pcr0.as_slice())
			.expect("PCR0 appears verbatim in the encoded document");

		bytes[offset] ^= 0x01;
		bytes
	}

	/// A valid DER certificate that is not the Nitro root: the real document's own leaf.
	///
	/// Using it as the trust anchor exercises chain building against an untrusted root, rather than
	/// failing earlier on a malformed anchor.
	fn untrusted_root_certificate() -> Vec<u8> {
		let bytes = real_attestation_bytes();
		let (_, attestation) =
			crate::nsm::parse_cose_attestation_doc(&bytes).expect("real document parses");
		attestation.certificate.into_vec()
	}

	/// Generate a fake attestation with invalid certificate chain
	fn generate_fake_attestation_invalid_cert_chain() -> Vec<u8> {
		let config = SimpleFakeAttestationConfig {
			certificate: vec![0x00; 4],
			..Default::default()
		};

		generate_simple_fake_attestation_self_signed(&config).unwrap()
	}

	// ============================================================================
	// COMPREHENSIVE FAKE ATTESTATION TESTS
	// ============================================================================

	#[test]
	fn test_attestation_with_different_root_ca() {
		// The document is genuine; only the trust anchor is wrong.
		let attestation = real_attestation_bytes();

		let verifier = Verifier::new(vec![])
			.with_root_certificate(untrusted_root_certificate())
			.with_skipped_certificate_time_check();

		let result = verifier.verify_attestation_document(&attestation);
		assert!(
			matches!(result, Err(Error::AttestationChainInvalid(_))),
			"Should reject attestation that does not chain to the configured root, got {result:?}"
		);
	}

	/// A tampered signature must be rejected by `verify_cose_signature`.
	///
	/// Every other negative fixture fails at the certificate chain, so without this test the suite
	/// still passes with the signature check removed entirely.
	#[test]
	fn test_attestation_with_tampered_signature() {
		let verifier = real_attestation_verifier();

		let result =
			verifier.verify_attestation_document(&real_attestation_with_tampered_signature());
		assert!(
			matches!(result, Err(Error::AttestationSignatureInvalid(_))),
			"Should reject a tampered signature, got {result:?}"
		);
	}

	/// A tampered payload must be rejected too: the payload is part of the COSE `Sig_structure`.
	#[test]
	fn test_attestation_with_tampered_payload() {
		let verifier = real_attestation_verifier();

		let result =
			verifier.verify_attestation_document(&real_attestation_with_tampered_payload());
		assert!(
			matches!(result, Err(Error::AttestationSignatureInvalid(_))),
			"Should reject a tampered payload, got {result:?}"
		);
	}

	/// Trailing bytes after the COSE envelope are outside the signature, so they must be rejected.
	#[test]
	fn test_attestation_with_trailing_bytes() {
		let verifier = real_attestation_verifier();

		let mut attestation = real_attestation_bytes();
		attestation.extend_from_slice(&[0xf6, 0xf6, 0xf6]);

		let result = verifier.verify_attestation_document(&attestation);
		assert!(
			matches!(result, Err(Error::AttestationDocumentParseError(_))),
			"Should reject unsigned trailing data, got {result:?}"
		);
	}

	#[test]
	fn test_attestation_with_an_unparseable_leaf_certificate_is_rejected() {
		let fake_attestation = generate_fake_attestation_invalid_cert_chain();

		let verifier = Verifier::new(vec![]).with_skipped_certificate_time_check();

		let result = verifier.verify_attestation_document(&fake_attestation);
		assert!(
			matches!(result, Err(Error::AttestationChainInvalid(_))),
			"Should reject invalid certificate chain, got {result:?}"
		);
	}

	#[test]
	fn test_attestation_with_expired_certificate() {
		// The real document's certificates expired in 2025; every other test opts out of the check.
		let mut verifier = real_attestation_verifier();
		verifier.skip_certificate_time_check = false;

		let result = verifier.verify_attestation_document(&real_attestation_bytes());
		assert!(
			matches!(result, Err(Error::AttestationChainInvalid(_))),
			"Should reject expired certificate, got {result:?}"
		);
	}

	#[test]
	fn test_attestation_that_is_stale() {
		let verifier = real_attestation_verifier();
		let verifier = verifier.with_max_age(Duration::from_mins(1));

		let result = verifier.verify_attestation_document(&real_attestation_bytes());
		assert!(
			matches!(result, Err(Error::AttestationStale { .. })),
			"Should reject a stale attestation, got {result:?}"
		);
	}

	#[test]
	fn test_attestation_with_mismatched_pcrs() {
		// PCR validation runs after the chain and signature checks, so this needs the real document.
		let mut verifier = real_attestation_verifier();
		verifier.allowed_pcr_configs.clear();
		verifier.add_allowed_pcr_config(vec![
			PcrMeasurement::new(0, [0xAA; 48]),
			PcrMeasurement::new(1, [0xBB; 48]),
		]);

		let result = verifier.verify_attestation_document(&real_attestation_bytes());
		assert!(
			matches!(result, Err(Error::CodeUntrusted { .. })),
			"Should reject mismatched PCR values, got {result:?}"
		);
	}

	#[test]
	fn test_multiple_pcr_configurations_success() {
		// This test verifies that PCR validation succeeds when ANY configuration matches,
		// not requiring ALL configurations to match. This enables support for multiple
		// enclave versions with different PCR values.

		let mut verifier = real_attestation_verifier();

		// Clear existing configurations
		verifier.allowed_pcr_configs.clear();

		// Add the correct PCR configuration (from the real attestation)
		let correct_config = vec![
			PcrMeasurement::new(
				0,
				hex_literal::hex!(
					"108b32466f5dc0a9971e0bc8e3e4074e7821bb2dcad3841bdec9a08b30f173386f0394a01486df181f316b39443dab34"
				),
			),
			PcrMeasurement::new(
				1,
				hex_literal::hex!(
					"4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493"
				),
			),
			PcrMeasurement::new(
				2,
				hex_literal::hex!(
					"08c6b2cba2d0c0ab63f3533cb44e092fb211775323cd62cd571f871e127ae1844f0e948a54ba58ecd29fbe03a64d5edc"
				),
			),
			PcrMeasurement::new(
				8,
				hex_literal::hex!(
					"b38251662033340b540c2d7e5f49e7ec6d10afcb5f17c72132e20a7f0a54576dc4d2c6ce062ed2ed2b6ae01815d69c8d"
				),
			),
		];

		// Add a completely different configuration (simulating a different enclave version)
		// Each PCR value must be exactly 48 bytes (96 hex characters) for SHA-384
		let different_config = vec![
			PcrMeasurement::new(0, [0xff; 48]),
			PcrMeasurement::new(1, [0xee; 48]),
			PcrMeasurement::new(2, [0xdd; 48]),
			PcrMeasurement::new(8, [0xcc; 48]),
		];

		// Add both configurations - the attestation should succeed because ONE matches
		verifier.allowed_pcr_configs.push(different_config.clone());
		verifier.allowed_pcr_configs.push(correct_config);

		let attestation_doc_bytes = real_attestation_bytes();

		// This should SUCCEED because one configuration matches
		verifier
			.verify_attestation_document(&attestation_doc_bytes)
			.expect("one PCR configuration matches, so verification must succeed");

		// Now test with ONLY non-matching configurations - should fail
		verifier.allowed_pcr_configs.clear();
		verifier.allowed_pcr_configs.push(different_config);

		let another_different_config = vec![
			PcrMeasurement::new(0, [0xaa; 48]),
			PcrMeasurement::new(1, [0xbb; 48]),
			PcrMeasurement::new(2, [0x11; 48]),
			PcrMeasurement::new(8, [0x22; 48]),
		];
		verifier.allowed_pcr_configs.push(another_different_config);

		let result = verifier.verify_attestation_document(&attestation_doc_bytes);

		// This should FAIL because no configuration matches
		assert!(
			matches!(result, Err(Error::CodeUntrusted { .. })),
			"Should reject attestation when no PCR configuration matches, got {result:?}"
		);
	}

	/// An empty inner configuration compares nothing, so without a guard it matches every attestation
	/// and silently turns PCR pinning off.
	#[test]
	fn test_empty_pcr_configuration_does_not_match() {
		let verifier = Verifier::new(vec![vec![]])
			.with_max_age(TEN_YEARS)
			.with_skipped_certificate_time_check();

		let result = verifier.verify_attestation_document(&real_attestation_bytes());
		assert!(
			matches!(result, Err(Error::CodeUntrusted { .. })),
			"An empty PCR configuration must not satisfy the policy, got {result:?}"
		);
	}

	/// The protected header is signature-covered, so a document declaring another algorithm is
	/// rejected on the algorithm check before the P-384 verification it disagrees with.
	#[test]
	fn test_attestation_declaring_a_non_es384_algorithm_is_rejected() {
		let envelope =
			CoseSign1::from_slice(&real_attestation_bytes()).expect("real document parses");
		let tampered = CoseSign1 {
			protected: ProtectedHeader {
				original_data: None,
				header: Header {
					alg: Some(Algorithm::Assigned(iana::Algorithm::ES256)),
					..Header::default()
				},
			},
			..envelope
		}
		.to_vec()
		.expect("re-encodes");

		let result = real_attestation_verifier().verify_attestation_document(&tampered);
		assert!(
			matches!(
				result,
				Err(Error::AttestationSignatureInvalid(ref m)) if m.contains("ES384")
			),
			"A non-ES384 algorithm must be rejected by name, got {result:?}"
		);
	}

	#[test]
	fn test_base64_input_that_is_not_base64_is_rejected() {
		let result = real_attestation_verifier().verify_attestation_document_base64("not base64!!");
		assert!(
			matches!(result, Err(Error::AttestationDocumentParseError(_))),
			"got {result:?}"
		);
	}

	/// Clocks drift; a document a few milliseconds ahead of the verifier is skew, not a forgery.
	#[test]
	fn test_attestation_slightly_in_the_future_is_accepted() {
		let (_, doc) =
			crate::nsm::parse_cose_attestation_doc(&real_attestation_bytes()).expect("parses");
		let now = u64::try_from(
			SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.expect("clock is sane")
				.as_millis(),
		)
		.expect("fits in u64");

		let verifier = real_attestation_verifier();
		assert!(verifier.check_attestation_freshness(&doc).is_ok());

		let mut skewed = doc.clone();
		skewed.timestamp = now + 1_000;
		assert!(
			verifier.check_attestation_freshness(&skewed).is_ok(),
			"a second of skew must not be treated as a future timestamp"
		);

		let mut far_future = doc;
		far_future.timestamp = now + 10 * 60 * 1_000;
		assert!(matches!(
			verifier.check_attestation_freshness(&far_future),
			Err(Error::AttestationInvalidTimestamp(_))
		));
	}
}
