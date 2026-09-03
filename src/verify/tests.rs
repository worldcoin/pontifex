use std::{
	collections::HashMap,
	time::{Duration, SystemTime, UNIX_EPOCH},
};

use coset::{CborSerializable, Header, ProtectedHeader};
use serde_bytes::ByteBuf;

use super::*;
use crate::{
	nsm::Digest,
	test_support::{
		ATTESTED_PUBLIC_KEY, TEN_YEARS, real_attestation_bytes, real_attestation_verifier,
	},
};

// This tests verifies a real attestation document with real PCR values.
#[test]
fn test_real_attestation_document() {
	let verified = real_attestation_verifier()
		.verify_attestation_document(&real_attestation_bytes())
		.expect("attestation verification failed");

	assert_eq!(verified.enclave_public_key, ATTESTED_PUBLIC_KEY);
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
) -> Result<Vec<u8>, EnclaveAttestationError> {
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
		EnclaveAttestationError::AttestationDocumentParseError(format!(
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
		EnclaveAttestationError::AttestationDocumentParseError(format!(
			"Failed to encode fake COSE Sign1: {e}"
		))
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

	let verifier = EnclaveAttestationVerifier::new(vec![])
		.with_root_certificate(untrusted_root_certificate())
		.with_skipped_certificate_time_check();

	let result = verifier.verify_attestation_document(&attestation);
	assert!(
		matches!(
			result,
			Err(EnclaveAttestationError::AttestationChainInvalid(_))
		),
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

	let result = verifier.verify_attestation_document(&real_attestation_with_tampered_signature());
	assert!(
		matches!(
			result,
			Err(EnclaveAttestationError::AttestationSignatureInvalid(_))
		),
		"Should reject a tampered signature, got {result:?}"
	);
}

/// A tampered payload must be rejected too: the payload is part of the COSE `Sig_structure`.
#[test]
fn test_attestation_with_tampered_payload() {
	let verifier = real_attestation_verifier();

	let result = verifier.verify_attestation_document(&real_attestation_with_tampered_payload());
	assert!(
		matches!(
			result,
			Err(EnclaveAttestationError::AttestationSignatureInvalid(_))
		),
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
		matches!(
			result,
			Err(EnclaveAttestationError::AttestationDocumentParseError(_))
		),
		"Should reject unsigned trailing data, got {result:?}"
	);
}

#[test]
fn test_attestation_with_an_unparseable_leaf_certificate_is_rejected() {
	let fake_attestation = generate_fake_attestation_invalid_cert_chain();

	let verifier = EnclaveAttestationVerifier::new(vec![]).with_skipped_certificate_time_check();

	let result = verifier.verify_attestation_document(&fake_attestation);
	assert!(
		matches!(
			result,
			Err(EnclaveAttestationError::AttestationChainInvalid(_))
		),
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
		matches!(
			result,
			Err(EnclaveAttestationError::AttestationChainInvalid(_))
		),
		"Should reject expired certificate, got {result:?}"
	);
}

#[test]
fn test_attestation_that_is_stale() {
	let verifier = real_attestation_verifier();
	let verifier = verifier.with_max_age(Duration::from_mins(1));

	let result = verifier.verify_attestation_document(&real_attestation_bytes());
	assert!(
		matches!(
			result,
			Err(EnclaveAttestationError::AttestationStale { .. })
		),
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
		matches!(result, Err(EnclaveAttestationError::CodeUntrusted { .. })),
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
		matches!(result, Err(EnclaveAttestationError::CodeUntrusted { .. })),
		"Should reject attestation when no PCR configuration matches, got {result:?}"
	);
}

/// An empty inner configuration compares nothing, so without a guard it matches every attestation
/// and silently turns PCR pinning off.
#[test]
fn test_empty_pcr_configuration_does_not_match() {
	let verifier = EnclaveAttestationVerifier::new(vec![vec![]])
		.with_max_age(TEN_YEARS)
		.with_skipped_certificate_time_check();

	let result = verifier.verify_attestation_document(&real_attestation_bytes());
	assert!(
		matches!(result, Err(EnclaveAttestationError::CodeUntrusted { .. })),
		"An empty PCR configuration must not satisfy the policy, got {result:?}"
	);
}

/// The protected header is signature-covered, so a document declaring another algorithm is
/// rejected on the algorithm check before the P-384 verification it disagrees with.
#[test]
fn test_attestation_declaring_a_non_es384_algorithm_is_rejected() {
	let envelope = CoseSign1::from_slice(&real_attestation_bytes()).expect("real document parses");
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
			Err(EnclaveAttestationError::AttestationSignatureInvalid(ref m)) if m.contains("ES384")
		),
		"A non-ES384 algorithm must be rejected by name, got {result:?}"
	);
}

#[test]
fn test_attestation_without_a_public_key_is_rejected() {
	let (_, mut doc) =
		crate::nsm::parse_cose_attestation_doc(&real_attestation_bytes()).expect("parses");
	doc.public_key = None;

	assert!(matches!(
		EnclaveAttestationVerifier::extract_public_key(&doc),
		Err(EnclaveAttestationError::InvalidEnclavePublicKey(_))
	));
}

#[test]
fn test_base64_input_that_is_not_base64_is_rejected() {
	let result = real_attestation_verifier().verify_attestation_document_base64("not base64!!");
	assert!(
		matches!(
			result,
			Err(EnclaveAttestationError::AttestationDocumentParseError(_))
		),
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
		Err(EnclaveAttestationError::AttestationInvalidTimestamp(_))
	));
}
