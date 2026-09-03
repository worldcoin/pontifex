use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::STANDARD};
use coset::{Algorithm, CoseSign1, Header, iana};
use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use webpki::{EndEntityCert, TrustAnchor};
use x509_cert::{Certificate, der::Decode};

use crate::nsm::{AttestationDoc, parse_cose_attestation_doc};

/// Constants for enclave verification
pub mod constants;

/// Types for enclave verification
pub mod types;

#[cfg(test)]
mod tests;

pub use types::{EnclaveAttestationError, PcrMeasurement, VerifiedAttestation};

use constants::{AWS_NITRO_ROOT_CERT, DEFAULT_MAX_ATTESTATION_AGE, get_expected_pcr_length};

/// Verifies AWS Nitro Enclave attestation documents
///
/// This struct performs comprehensive verification of attestation documents including:
/// - COSE Sign1 signature verification
/// - Certificate chain validation against AWS Nitro root certificates
/// - PCR (Platform Configuration Register) value validation
/// - Attestation document freshness checks
/// - Public key extraction
#[derive(Debug)]
pub struct EnclaveAttestationVerifier {
	/// Allowed PCR configs for validation
	/// This is a list of allowed PCR configurations, where each configuration is a list of (PCR index, expected value) tuples.
	///
	/// This allows for supporting multiple enclave software versions.
	allowed_pcr_configs: Vec<Vec<PcrMeasurement>>,
	root_certificate: Vec<u8>,
	max_age: Duration,
	#[cfg(test)]
	skip_certificate_time_check: bool,
}

impl EnclaveAttestationVerifier {
	/// Creates a new `EnclaveAttestationVerifier` trusting the AWS Nitro root certificate and
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
	) -> Result<VerifiedAttestation, EnclaveAttestationError> {
		let attestation_doc_bytes = STANDARD.decode(attestation_doc_base64).map_err(|e| {
			EnclaveAttestationError::AttestationDocumentParseError(format!(
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
	) -> Result<VerifiedAttestation, EnclaveAttestationError> {
		// 1. Syntactical validation
		let (cose_sign1, attestation) = Self::parse_attestation_doc(attestation_doc_bytes)?;

		// 2. Semantic validation
		let leaf_cert = self.verify_certificate_chain(&attestation)?;

		// 3. Cryptographic validation
		Self::verify_cose_signature(&cose_sign1, &leaf_cert)?;
		self.validate_pcr_values(&attestation)?;
		self.check_attestation_freshness(&attestation)?;
		let public_key = Self::extract_public_key(&attestation)?;

		Ok(VerifiedAttestation::new(
			public_key,
			attestation.timestamp,
			attestation.module_id,
		))
	}

	fn parse_attestation_doc(
		bytes: &[u8],
	) -> Result<(CoseSign1, AttestationDoc), EnclaveAttestationError> {
		// Validate before loading into buffer
		if bytes.is_empty() {
			return Err(EnclaveAttestationError::AttestationDocumentParseError(
				"Empty attestation document".to_string(),
			));
		}

		let first_byte = bytes[0];
		if !(0x80..=0x97).contains(&first_byte) && first_byte != 0x9f {
			return Err(EnclaveAttestationError::AttestationDocumentParseError(
				format!(
					"Invalid CBOR magic byte: expected array marker (0x80-0x97 or 0x9f), got 0x{first_byte:02x}"
				),
			));
		}

		parse_cose_attestation_doc(bytes)
			.map_err(|e| EnclaveAttestationError::AttestationDocumentParseError(e.to_string()))
	}

	fn verify_certificate_chain(
		&self,
		attestation: &AttestationDoc,
	) -> Result<Certificate, EnclaveAttestationError> {
		let root_cert_der = self.root_certificate.as_slice();

		// Create trust anchor from root certificate
		let trust_anchor = TrustAnchor::try_from_cert_der(root_cert_der).map_err(|e| {
			EnclaveAttestationError::AttestationChainInvalid(format!(
				"Failed to create trust anchor from root certificate: {e}"
			))
		})?;

		// Collect intermediate certificates from cabundle,
		let intermediate_certs: Vec<&[u8]> = attestation
			.cabundle
			.iter()
			.skip(1)
			.map(|cert| cert.as_slice())
			.collect();

		// Get current time for certificate validity checking
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
			// ONLY USED FOR TESTING
			// Use the attestation timestamp converted to seconds for certificate validation
			// This ensures we're using the same time context as when the attestation was created
			webpki::Time::from_seconds_since_unix_epoch(attestation.timestamp / 1000)
		} else {
			let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| {
				EnclaveAttestationError::AttestationInvalidTimestamp(format!(
					"Failed to get current time: {e}"
				))
			})?;
			webpki::Time::from_seconds_since_unix_epoch(now.as_secs())
		};

		// Create end entity certificate from the leaf certificate
		let end_entity_cert =
			EndEntityCert::try_from(attestation.certificate.as_slice()).map_err(|e| {
				EnclaveAttestationError::AttestationChainInvalid(format!(
					"Failed to parse leaf certificate: {e}"
				))
			})?;

		// Verify the certificate chain
		end_entity_cert
			.verify_is_valid_tls_server_cert(
				&[&webpki::ECDSA_P384_SHA384],
				&webpki::TlsServerTrustAnchors(&[trust_anchor]),
				&intermediate_certs,
				current_time,
			)
			.map_err(|e| {
				EnclaveAttestationError::AttestationChainInvalid(format!(
					"Certificate chain validation failed: {e}"
				))
			})?;

		// Parse the leaf certificate for return
		Certificate::from_der(&attestation.certificate).map_err(|e| {
			EnclaveAttestationError::AttestationChainInvalid(format!(
				"Failed to parse leaf certificate for return: {e}"
			))
		})
	}

	fn verify_cose_signature(
		cose_sign1: &CoseSign1,
		leaf_cert: &Certificate,
	) -> Result<(), EnclaveAttestationError> {
		// Extract public key from certificate
		let spki = &leaf_cert.tbs_certificate.subject_public_key_info;
		let public_key_bytes = spki.subject_public_key.as_bytes().ok_or_else(|| {
			EnclaveAttestationError::AttestationSignatureInvalid(
				"Failed to extract public key bytes".to_string(),
			)
		})?;

		let verifying_key = VerifyingKey::from_sec1_bytes(public_key_bytes).map_err(|e| {
			EnclaveAttestationError::AttestationSignatureInvalid(format!(
				"Failed to parse P-384 public key: {e}"
			))
		})?;

		// The spec fixes the algorithm at ES384; accepting a document that declares anything else
		// would let the header disagree with the P-384 check performed below.
		let alg = cose_sign1.protected.header.alg.as_ref();
		if alg != Some(&Algorithm::Assigned(iana::Algorithm::ES384)) {
			return Err(EnclaveAttestationError::AttestationSignatureInvalid(
				format!("Expected ES384 in the protected header, got {alg:?}"),
			));
		}

		// coset substitutes an empty payload when there is none, which would verify a signature
		// over a document this function never saw.
		if cose_sign1.payload.is_none() {
			return Err(EnclaveAttestationError::AttestationSignatureInvalid(
				"Missing payload in COSE Sign1".to_string(),
			));
		}

		// Nitro leaves the unprotected header empty. Anything in it is unsigned, so accepting it
		// would let a malleable copy of a document carry contradictory headers.
		if cose_sign1.unprotected != Header::default() {
			return Err(EnclaveAttestationError::AttestationSignatureInvalid(
				"Unprotected header must be empty".to_string(),
			));
		}

		// `verify_signature` reconstructs the COSE Sign1 `Sig_structure`
		// (`["Signature1", protected, external_aad, payload]`) and hands it to the closure
		// alongside the signature. Nitro attestations carry no external AAD.
		cose_sign1.verify_signature(&[], |signature, signed_data| {
			let ecdsa_signature = Signature::try_from(signature).map_err(|e| {
				EnclaveAttestationError::AttestationSignatureInvalid(format!(
					"Failed to parse ECDSA signature (need 96 raw bytes): {e}"
				))
			})?;

			verifying_key
				.verify(signed_data, &ecdsa_signature)
				.map_err(|e| {
					EnclaveAttestationError::AttestationSignatureInvalid(format!(
						"Signature verification failed: {e}"
					))
				})
		})
	}

	fn validate_pcr_values(
		&self,
		attestation: &AttestationDoc,
	) -> Result<(), EnclaveAttestationError> {
		if attestation.pcrs.is_empty() {
			return Err(EnclaveAttestationError::CodeUntrusted {
				pcr_index: 0,
				actual: "empty".to_string(),
			});
		}

		// Get the expected PCR length depending on the hashing algorithm used
		// As of right now, only SHA-384 is used
		let expected_pcr_length = get_expected_pcr_length(attestation.digest);

		// Try to find at least one allowed PCR configuration that matches
		// This allows supporting multiple enclave versions simultaneously
		for allowed_pcr_measurements in &self.allowed_pcr_configs {
			// An empty configuration compares nothing, so it would match every attestation and
			// silently disable PCR pinning. Never let one satisfy the policy.
			if allowed_pcr_measurements.is_empty() {
				continue;
			}

			let mut all_match = true;

			for pcr_measurement in allowed_pcr_measurements {
				// Get the PCR value from the attestation
				let Ok(attestation_pcr_value) =
					Self::get_pcr_value(attestation, pcr_measurement.index)
				else {
					all_match = false;
					break;
				};

				// Validate the PCR value length
				if attestation_pcr_value.len() != expected_pcr_length {
					all_match = false;
					break;
				}

				// Validate the PCR value matches the expected value
				if attestation_pcr_value.as_slice() != pcr_measurement.value.as_slice() {
					all_match = false;
					break;
				}
			}

			// If all PCRs in this configuration match, return success
			if all_match {
				return Ok(());
			}
		}

		// If we have no allowed configurations at all
		Err(EnclaveAttestationError::CodeUntrusted {
			pcr_index: 0,
			actual: "No allowed PCR configurations".to_string(),
		})
	}

	fn check_attestation_freshness(
		&self,
		attestation: &AttestationDoc,
	) -> Result<(), EnclaveAttestationError> {
		let now = u64::try_from(
			SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.map_err(|e| {
					EnclaveAttestationError::AttestationInvalidTimestamp(format!(
						"Failed to get current time: {e}"
					))
				})?
				.as_millis(),
		)
		.map_err(|e| {
			EnclaveAttestationError::AttestationInvalidTimestamp(format!(
				"Failed to convert current time to milliseconds: {e}"
			))
		})?;

		let age = now.checked_sub(attestation.timestamp).ok_or_else(|| {
			EnclaveAttestationError::AttestationInvalidTimestamp(format!(
				"Attestation timestamp is {} ms in the future",
				attestation.timestamp - now
			))
		})?;

		let max_age_millis = u64::try_from(self.max_age.as_millis()).unwrap_or(u64::MAX);
		if age > max_age_millis {
			return Err(EnclaveAttestationError::AttestationStale {
				age_millis: age,
				max_age: max_age_millis,
			});
		}

		Ok(())
	}

	fn extract_public_key(
		attestation: &AttestationDoc,
	) -> Result<Vec<u8>, EnclaveAttestationError> {
		attestation.public_key.clone().map_or_else(
			|| {
				Err(EnclaveAttestationError::InvalidEnclavePublicKey(
					"No public key in attestation document".to_string(),
				))
			},
			|key| Ok(key.into_vec()),
		)
	}

	fn get_pcr_value(
		attestation_doc: &AttestationDoc,
		pcr_index: u32,
	) -> Result<Vec<u8>, EnclaveAttestationError> {
		attestation_doc.pcrs.get(&(pcr_index as usize)).map_or_else(
			|| {
				Err(EnclaveAttestationError::CodeUntrusted {
					pcr_index,
					actual: "missing".to_string(),
				})
			},
			|value| Ok(value.to_vec()),
		)
	}
}

#[cfg(test)]
impl EnclaveAttestationVerifier {
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
