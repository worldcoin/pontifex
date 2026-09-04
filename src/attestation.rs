//! Verification of AWS Nitro Enclave attestation documents.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use coset::{Algorithm, CoseSign1, iana};
use p384::ecdsa::{Signature, VerifyingKey, signature::Verifier as _};
use webpki::{EndEntityCert, TrustAnchor};
use x509_cert::{Certificate, der::Decode};

use crate::nsm::{AttestationDoc, Digest};

/// AWS Nitro Root Certificate (G1), in DER form.
///
/// Source: <https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip>
/// Stored at `src/aws_nitro_root_g1.der`
pub const AWS_NITRO_ROOT_CERT: &[u8] = include_bytes!("aws_nitro_root_g1.der");

/// The largest attestation document the spec allows
const MAX_DOCUMENT_BYTES: usize = 16384;

/// The PCR holding the hash of the enclave image file, which is what pins the code being run.
///
/// Reference: <https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html#where>
pub const PCR_ENCLAVE_IMAGE: u32 = 0;

/// Length of a Nitro PCR value (`ECDSA_P384_SHA384`).
pub const PCR_LENGTH: usize = 48;

/// How far ahead of the verifier's clock an attestation may be dated before it is an error.
const CLOCK_SKEW_TOLERANCE_MILLIS: u64 = 60_000;

/// Get the expected PCR length depending on the hashing algorithm used.
/// As of right now, only SHA-384 is used: <https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html>
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
#[non_exhaustive]
pub enum Error {
	/// Failed to parse attestation document
	#[error("Failed to parse attestation document: {0}")]
	ParseError(String),

	/// Certificate chain validation failed
	#[error("Certificate chain validation failed: {0}")]
	ChainInvalid(String),

	/// Signature verification failed
	#[error("Signature verification failed: {0}")]
	SignatureInvalid(String),

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
	Stale {
		/// The age of the attestation in milliseconds
		age_millis: u64,
		/// The maximum age of the attestation in milliseconds
		max_age: u64,
	},

	/// Invalid timestamp
	#[error("Invalid timestamp: {0}")]
	AttestationInvalidTimestamp(String),
}

/// An [`AttestationDoc`] that has been signature verified.
///
/// ```compile_fail,E0603
/// # use pontifex::{attestation::VerifiedAttestation, nsm::AttestationDoc};
/// # fn forge(parsed: AttestationDoc) {
/// let forged = VerifiedAttestation(parsed); // the field is private
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct VerifiedAttestation(AttestationDoc);

impl VerifiedAttestation {
	/// The verified [`AttestationDoc`].
	#[must_use]
	pub const fn document(&self) -> &AttestationDoc {
		&self.0
	}

	/// Consumes the proof, returning the verified [`AttestationDoc`].
	#[must_use]
	pub fn into_document(self) -> AttestationDoc {
		self.0
	}
}

/// Verifies AWS Nitro Enclave attestation documents: COSE signature, cert chain,
/// expected PCRs and freshness.
#[derive(Debug)]
pub struct Verifier {
	/// Allowed PCR configs for validation. Accepts multiple to support different versions.
	allowed_pcr_configs: Vec<PcrConfig>,
	root_certificate: Vec<u8>,
	max_age: Duration,
	#[cfg(test)]
	skip_certificate_time_check: bool,
}

impl Verifier {
	/// Creates a new `Verifier` from the AWS Nitro root certificate.
	///
	/// # Arguments
	/// * `allowed_pcr_configs` - Allowed PCR configurations. Verification succeeds if *any* one
	///   matches in full, which is how several enclave software versions are supported at once.
	/// * `max_age` - How old a document may be before it is rejected as stale.
	#[must_use]
	pub fn new(allowed_pcr_configs: Vec<PcrConfig>, max_age: Duration) -> Self {
		Self {
			allowed_pcr_configs,
			root_certificate: AWS_NITRO_ROOT_CERT.to_vec(),
			max_age,
			#[cfg(test)]
			skip_certificate_time_check: false,
		}
	}

	/// Sets the DER-encoded root certificate the attestation chain must chain up to.
	///
	/// # Warning
	/// This completely changes the root of trust. Don't use unless you know what you're doing.
	#[must_use]
	pub fn with_root_certificate(mut self, root_certificate: Vec<u8>) -> Self {
		self.root_certificate = root_certificate;
		self
	}

	/// Verifies the attestation document from the enclave.
	///
	/// Reference: <https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-attestation-document.html>
	///
	/// # Errors
	/// Returns an error if any verification step fails.
	pub fn verify_attestation_document(
		&self,
		attestation_doc_bytes: &[u8],
	) -> Result<VerifiedAttestation, Error> {
		if attestation_doc_bytes.len() > MAX_DOCUMENT_BYTES {
			return Err(Error::ParseError(format!(
				"Attestation document is {} bytes, over the {MAX_DOCUMENT_BYTES}-byte maximum",
				attestation_doc_bytes.len()
			)));
		}

		// 1. Syntactical validation
		let (attestation, cose_sign1) = AttestationDoc::from_bytes(attestation_doc_bytes)
			.map_err(|e| Error::ParseError(e.to_string()))?;

		// 2. Semantic validation
		let leaf_cert = self.verify_certificate_chain(&attestation)?;

		// 3. Cryptographic validation
		Self::verify_cose_signature(&cose_sign1, &leaf_cert)?;
		self.validate_pcr_values(&attestation)?;
		self.check_attestation_freshness(&attestation)?;

		Ok(VerifiedAttestation(attestation))
	}

	fn verify_certificate_chain(&self, attestation: &AttestationDoc) -> Result<Certificate, Error> {
		let root_cert_der = self.root_certificate.as_slice();

		let trust_anchor = TrustAnchor::try_from_cert_der(root_cert_der).map_err(|e| {
			Error::ChainInvalid(format!(
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
			webpki::Time::from_seconds_since_unix_epoch(attestation.timestamp / 1000)
		} else {
			let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| {
				Error::AttestationInvalidTimestamp(format!("Failed to get current time: {e}"))
			})?;
			webpki::Time::from_seconds_since_unix_epoch(now.as_secs())
		};

		let end_entity_cert = EndEntityCert::try_from(attestation.certificate.as_slice())
			.map_err(|e| Error::ChainInvalid(format!("Failed to parse leaf certificate: {e}")))?;

		end_entity_cert
			.verify_is_valid_tls_server_cert(
				&[&webpki::ECDSA_P384_SHA384],
				&webpki::TlsServerTrustAnchors(&[trust_anchor]),
				&intermediate_certs,
				current_time,
			)
			.map_err(|e| {
				Error::ChainInvalid(format!("Certificate chain validation failed: {e}"))
			})?;

		Certificate::from_der(&attestation.certificate).map_err(|e| {
			Error::ChainInvalid(format!("Failed to parse leaf certificate for return: {e}"))
		})
	}

	fn verify_cose_signature(cose_sign1: &CoseSign1, leaf_cert: &Certificate) -> Result<(), Error> {
		let spki = &leaf_cert.tbs_certificate.subject_public_key_info;
		let public_key_bytes = spki.subject_public_key.as_bytes().ok_or_else(|| {
			Error::SignatureInvalid("Failed to extract public key bytes".to_string())
		})?;

		let verifying_key = VerifyingKey::from_sec1_bytes(public_key_bytes).map_err(|e| {
			Error::SignatureInvalid(format!("Failed to parse P-384 public key: {e}"))
		})?;

		let alg = cose_sign1.protected.header.alg.as_ref();
		if alg != Some(&Algorithm::Assigned(iana::Algorithm::ES384)) {
			return Err(Error::SignatureInvalid(format!(
				"Expected ES384 in the protected header, got {alg:?}"
			)));
		}

		if cose_sign1.payload.is_none() {
			return Err(Error::SignatureInvalid(
				"Missing payload in COSE Sign1".to_string(),
			));
		}

		cose_sign1.verify_signature(&[], |signature, signed_data| {
			let ecdsa_signature = Signature::try_from(signature).map_err(|e| {
				Error::SignatureInvalid(format!(
					"Failed to parse ECDSA signature (need 96 raw bytes): {e}"
				))
			})?;

			verifying_key
				.verify(signed_data, &ecdsa_signature)
				.map_err(|e| Error::SignatureInvalid(format!("Signature verification failed: {e}")))
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

		if self
			.allowed_pcr_configs
			.iter()
			.any(|config| config.enclave_image == [0; PCR_LENGTH])
		{
			return Err(Error::CodeUntrusted {
				pcr_index: PCR_ENCLAVE_IMAGE,
				actual: "configuration pins an all-zero PCR0, which every debug-mode enclave \
				         reports regardless of the code it runs"
					.to_string(),
			});
		}

		let mut first_mismatch = None;
		for config in &self.allowed_pcr_configs {
			match Self::first_mismatch(attestation, config, expected_length) {
				None => return Ok(()),
				Some(mismatch) => first_mismatch.get_or_insert(mismatch),
			};
		}

		let (pcr_index, actual) = first_mismatch.unwrap_or_else(|| {
			(
				PCR_ENCLAVE_IMAGE,
				"no PCR configuration was supplied".to_string(),
			)
		});
		Err(Error::CodeUntrusted { pcr_index, actual })
	}

	/// The first PCR in `config` that the attestation does not satisfy, as `(index, actual)`.
	fn first_mismatch(
		attestation: &AttestationDoc,
		config: &PcrConfig,
		expected_length: usize,
	) -> Option<(u32, String)> {
		config.measurements().find_map(|(index, expected)| {
			match attestation.pcrs.get(&(index as usize)) {
				Some(value) if value.len() == expected_length && value.as_slice() == expected => {
					None
				},
				Some(value) => Some((index, hex_encode(value))),
				None => Some((index, "missing".to_string())),
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
			return Err(Error::Stale {
				age_millis: age,
				max_age: max_age_millis,
			});
		}

		Ok(())
	}
}

/// Represents expected PCR measurements with its index and value.
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

/// Accepted enclave build.
///
/// ```compile_fail,E0061
/// # use pontifex::attestation::PcrConfig;
/// let config = PcrConfig::new(); // PCR0 is not optional
/// ```
#[derive(Clone, Debug)]
pub struct PcrConfig {
	/// PCR0: Enclave image file. Always required to avoid implementation mistakes.
	enclave_image: [u8; PCR_LENGTH],
	additional: Vec<PcrMeasurement>,
}

impl PcrConfig {
	/// Init a config from a specific PCR.
	#[must_use]
	pub const fn new(enclave_image: [u8; PCR_LENGTH]) -> Self {
		Self {
			enclave_image,
			additional: Vec::new(),
		}
	}

	/// Pin a specific additional PCR measurement.
	#[must_use]
	pub fn with_pcr(mut self, index: u32, value: impl Into<Vec<u8>>) -> Self {
		self.additional.push(PcrMeasurement::new(index, value));
		self
	}

	fn measurements(&self) -> impl Iterator<Item = (u32, &[u8])> {
		std::iter::once((PCR_ENCLAVE_IMAGE, self.enclave_image.as_slice())).chain(
			self.additional
				.iter()
				.map(|m| (m.index, m.value.as_slice())),
		)
	}
}

fn hex_encode(bytes: &[u8]) -> String {
	bytes.iter().fold(String::new(), |mut out, byte| {
		use std::fmt::Write as _;
		let _ = write!(out, "{byte:02x}");
		out
	})
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
	pub fn add_allowed_pcr_config(&mut self, pcr_config: PcrConfig) {
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
		ATTESTED_PUBLIC_KEY, TEN_YEARS, pcr0_only, real_attestation_bytes,
		real_attestation_verifier, real_attestation_verifier_with_max_age,
	};

	#[test]
	fn test_real_attestation_document() {
		let verified = real_attestation_verifier()
			.verify_attestation_document(&real_attestation_bytes())
			.expect("attestation verification failed");

		assert_eq!(
			verified
				.document()
				.public_key
				.as_ref()
				.map(|k| k.as_slice()),
			Some(ATTESTED_PUBLIC_KEY.as_slice())
		);
		assert_eq!(
			verified.document().module_id,
			"i-01b324f0b8b6c25ea-enc01997668bda38b2a"
		);
	}

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
			Error::ParseError(format!(
				"Failed to serialize fake attestation document: {e}"
			))
		})?;

		CoseSign1 {
			protected: ProtectedHeader::default(),
			unprotected: Header::default(),
			payload: Some(payload),
			signature: vec![0x00; 96],
		}
		.to_vec()
		.map_err(|e| Error::ParseError(format!("Failed to encode fake COSE Sign1: {e}")))
	}

	fn real_attestation_with_tampered_signature() -> Vec<u8> {
		let mut bytes = real_attestation_bytes();
		*bytes.last_mut().expect("document is not empty") ^= 0x01;
		bytes
	}

	fn real_attestation_with_tampered_payload() -> Vec<u8> {
		let mut bytes = real_attestation_bytes();
		let (attestation, _) = AttestationDoc::from_bytes(&bytes).expect("real document parses");
		let pcr0 = attestation.pcrs.get(&0).expect("real document has PCR0");

		let offset = bytes
			.windows(pcr0.len())
			.position(|window| window == pcr0.as_slice())
			.expect("PCR0 appears verbatim in the encoded document");

		bytes[offset] ^= 0x01;
		bytes
	}

	fn untrusted_root_certificate() -> Vec<u8> {
		let bytes = real_attestation_bytes();
		let (attestation, _) = AttestationDoc::from_bytes(&bytes).expect("real document parses");
		attestation.certificate.into_vec()
	}

	fn generate_fake_attestation_invalid_cert_chain() -> Vec<u8> {
		let config = SimpleFakeAttestationConfig {
			certificate: vec![0x00; 4],
			..Default::default()
		};

		generate_simple_fake_attestation_self_signed(&config).unwrap()
	}

	#[test]
	fn test_attestation_with_different_root_ca() {
		let attestation = real_attestation_bytes();

		let verifier = Verifier::new(vec![pcr0_only()], TEN_YEARS)
			.with_root_certificate(untrusted_root_certificate())
			.with_skipped_certificate_time_check();

		let result = verifier.verify_attestation_document(&attestation);
		assert!(
			matches!(result, Err(Error::ChainInvalid(_))),
			"Should reject attestation that does not chain to the configured root, got {result:?}"
		);
	}

	#[test]
	fn test_attestation_with_tampered_signature() {
		let verifier = real_attestation_verifier();

		let result =
			verifier.verify_attestation_document(&real_attestation_with_tampered_signature());
		assert!(
			matches!(result, Err(Error::SignatureInvalid(_))),
			"Should reject a tampered signature, got {result:?}"
		);
	}

	#[test]
	fn test_attestation_with_tampered_payload() {
		let verifier = real_attestation_verifier();

		let result =
			verifier.verify_attestation_document(&real_attestation_with_tampered_payload());
		assert!(
			matches!(result, Err(Error::SignatureInvalid(_))),
			"Should reject a tampered payload, got {result:?}"
		);
	}

	#[test]
	fn test_attestation_with_trailing_bytes_is_rejected() {
		let verifier = real_attestation_verifier();

		let mut attestation = real_attestation_bytes();
		attestation.extend_from_slice(&[0xf6, 0xf6, 0xf6]);

		let result = verifier.verify_attestation_document(&attestation);
		assert!(
			matches!(result, Err(Error::ParseError(_))),
			"Should reject unsigned trailing data, got {result:?}"
		);
	}

	#[test]
	fn test_attestation_with_an_unparseable_leaf_certificate_is_rejected() {
		let fake_attestation = generate_fake_attestation_invalid_cert_chain();

		let verifier =
			Verifier::new(vec![pcr0_only()], TEN_YEARS).with_skipped_certificate_time_check();

		let result = verifier.verify_attestation_document(&fake_attestation);
		assert!(
			matches!(result, Err(Error::ChainInvalid(_))),
			"Should reject invalid certificate chain, got {result:?}"
		);
	}

	#[test]
	fn test_attestation_with_expired_certificate() {
		let mut verifier = real_attestation_verifier();
		verifier.skip_certificate_time_check = false;

		let result = verifier.verify_attestation_document(&real_attestation_bytes());
		assert!(
			matches!(result, Err(Error::ChainInvalid(_))),
			"Should reject expired certificate, got {result:?}"
		);
	}

	#[test]
	fn test_attestation_that_is_stale() {
		let verifier = real_attestation_verifier_with_max_age(Duration::from_mins(1));

		let result = verifier.verify_attestation_document(&real_attestation_bytes());
		assert!(
			matches!(result, Err(Error::Stale { .. })),
			"Should reject a stale attestation, got {result:?}"
		);
	}

	#[test]
	fn test_attestation_with_mismatched_pcrs() {
		let mut verifier = real_attestation_verifier();
		verifier.allowed_pcr_configs.clear();
		verifier.add_allowed_pcr_config(PcrConfig::new([0xAA; 48]).with_pcr(1, [0xBB; 48]));

		let result = verifier.verify_attestation_document(&real_attestation_bytes());
		assert!(
			matches!(result, Err(Error::CodeUntrusted { .. })),
			"Should reject mismatched PCR values, got {result:?}"
		);
	}

	#[test]
	fn test_multiple_pcr_configurations_success() {
		let mut verifier = real_attestation_verifier();
		verifier.allowed_pcr_configs.clear();

		let correct_config = PcrConfig::new(hex_literal::hex!(
			"108b32466f5dc0a9971e0bc8e3e4074e7821bb2dcad3841bdec9a08b30f173386f0394a01486df181f316b39443dab34"
		))
		.with_pcr(
			1,
			hex_literal::hex!(
				"4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493"
			),
		)
		.with_pcr(
			2,
			hex_literal::hex!(
				"08c6b2cba2d0c0ab63f3533cb44e092fb211775323cd62cd571f871e127ae1844f0e948a54ba58ecd29fbe03a64d5edc"
			),
		)
		.with_pcr(
			8,
			hex_literal::hex!(
				"b38251662033340b540c2d7e5f49e7ec6d10afcb5f17c72132e20a7f0a54576dc4d2c6ce062ed2ed2b6ae01815d69c8d"
			),
		);

		let different_config = PcrConfig::new([0xff; 48])
			.with_pcr(1, [0xee; 48])
			.with_pcr(2, [0xdd; 48])
			.with_pcr(8, [0xcc; 48]);

		verifier.allowed_pcr_configs.push(different_config.clone());
		verifier.allowed_pcr_configs.push(correct_config);

		let attestation_doc_bytes = real_attestation_bytes();

		verifier
			.verify_attestation_document(&attestation_doc_bytes)
			.expect("**one** (any) PCR configuration matches, so verification must succeed");

		// Now test with ONLY non-matching configurations
		verifier.allowed_pcr_configs.clear();
		verifier.allowed_pcr_configs.push(different_config);

		let another_different_config = PcrConfig::new([0xaa; 48])
			.with_pcr(1, [0xbb; 48])
			.with_pcr(2, [0x11; 48])
			.with_pcr(8, [0x22; 48]);
		verifier.allowed_pcr_configs.push(another_different_config);

		let result = verifier.verify_attestation_document(&attestation_doc_bytes);
		assert!(matches!(result, Err(Error::CodeUntrusted { .. })));
	}

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
				Err(Error::SignatureInvalid(ref m)) if m.contains("ES384")
			),
			"A non-ES384 algorithm must be rejected by name, got {result:?}"
		);
	}

	#[test]
	fn test_attestation_slightly_in_the_future_is_accepted() {
		let (doc, _) = AttestationDoc::from_bytes(&real_attestation_bytes()).expect("parses");
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

	#[test]
	fn test_no_pcr_configuration_is_rejected() {
		let verifier = Verifier::new(vec![], TEN_YEARS).with_skipped_certificate_time_check();

		let result = verifier.verify_attestation_document(&real_attestation_bytes());
		assert!(
			matches!(result, Err(Error::CodeUntrusted { .. })),
			"A verifier with no PCR configuration must reject, got {result:?}"
		);
	}

	#[test]
	fn test_an_oversized_document_is_rejected_before_parsing() {
		let mut oversized = real_attestation_bytes();
		assert!(
			oversized.len() < MAX_DOCUMENT_BYTES,
			"fixture is within the limit"
		);
		oversized.resize(MAX_DOCUMENT_BYTES + 1, 0);

		let result = real_attestation_verifier().verify_attestation_document(&oversized);
		assert!(
			matches!(result, Err(Error::ParseError(ref m)) if m.contains("maximum")),
			"got {result:?}"
		);
	}
}
