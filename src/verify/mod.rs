use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine, engine::general_purpose::STANDARD};
use coset::{Algorithm, CoseSign1, iana};
use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use webpki::{EndEntityCert, TrustAnchor};
use x509_cert::{Certificate, der::Decode};

use crate::{
	nsm::{AttestationDoc, parse_cose_attestation_doc},
	public_key_commitment,
};

/// Constants for enclave verification
pub mod constants;

/// Types for enclave verification
pub mod types;

#[cfg(test)]
mod tests;

pub use types::{EnclaveAttestationError, PcrMeasurement, VerifiedAttestation};

use constants::{AWS_NITRO_ROOT_CERT, DEFAULT_MAX_ATTESTATION_AGE, get_expected_pcr_length};

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
pub struct EnclaveAttestationVerifier {
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

	/// Verifies the attestation document and that it commits to `public_key`.
	///
	/// The NSM caps the document's `public_key` field at 1024 bytes, so a key too large for it
	/// (such as a 1216-byte X-Wing encapsulation key) is bound by attesting
	/// [`public_key_commitment`] in `user_data` and carrying the key alongside the document.
	///
	/// # Errors
	/// Returns an error if verification fails, or [`EnclaveAttestationError::KeyCommitmentMismatch`]
	/// if `user_data` is absent or does not equal the commitment to `public_key`.
	pub fn verify_attestation_document_with_key_commitment(
		&self,
		attestation_doc_bytes: &[u8],
		public_key: &[u8],
	) -> Result<VerifiedAttestation, EnclaveAttestationError> {
		let attestation = self.verify_attestation_document(attestation_doc_bytes)?;

		let expected = public_key_commitment(public_key);
		if attestation.user_data.as_deref() != Some(expected.as_slice()) {
			return Err(EnclaveAttestationError::KeyCommitmentMismatch);
		}

		Ok(attestation)
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
		let (cose_sign1, attestation) = parse_cose_attestation_doc(attestation_doc_bytes)
			.map_err(|e| EnclaveAttestationError::AttestationDocumentParseError(e.to_string()))?;

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

	fn verify_certificate_chain(
		&self,
		attestation: &AttestationDoc,
	) -> Result<Certificate, EnclaveAttestationError> {
		let root_cert_der = self.root_certificate.as_slice();

		let trust_anchor = TrustAnchor::try_from_cert_der(root_cert_der).map_err(|e| {
			EnclaveAttestationError::AttestationChainInvalid(format!(
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
				EnclaveAttestationError::AttestationInvalidTimestamp(format!(
					"Failed to get current time: {e}"
				))
			})?;
			webpki::Time::from_seconds_since_unix_epoch(now.as_secs())
		};

		let end_entity_cert =
			EndEntityCert::try_from(attestation.certificate.as_slice()).map_err(|e| {
				EnclaveAttestationError::AttestationChainInvalid(format!(
					"Failed to parse leaf certificate: {e}"
				))
			})?;

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
			|| EnclaveAttestationError::CodeUntrusted {
				pcr_index: 0,
				actual: "no PCR configuration was supplied".to_string(),
			},
			|(pcr_index, actual)| EnclaveAttestationError::CodeUntrusted { pcr_index, actual },
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

		// Clocks drift between the enclave and the verifier, so a slightly future timestamp is
		// skew rather than a forgery. Beyond the tolerance it is a real error.
		let age = match now.checked_sub(attestation.timestamp) {
			Some(age) => age,
			None if attestation.timestamp - now <= CLOCK_SKEW_TOLERANCE_MILLIS => 0,
			None => {
				return Err(EnclaveAttestationError::AttestationInvalidTimestamp(
					format!(
						"Attestation timestamp is {} ms in the future",
						attestation.timestamp - now
					),
				));
			},
		};

		let max_age_millis = u64::try_from(self.max_age.as_millis()).unwrap_or(u64::MAX);
		if age > max_age_millis {
			return Err(EnclaveAttestationError::AttestationStale {
				age_millis: age,
				max_age: max_age_millis,
			});
		}

		Ok(())
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
