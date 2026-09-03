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

/// Generate a fake attestation with self-signed certificate
fn generate_fake_attestation_self_signed() -> Vec<u8> {
	let config = SimpleFakeAttestationConfig::default();
	generate_simple_fake_attestation_self_signed(&config).unwrap()
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
fn test_attestation_doc_wrong_cert() {
	let attestation_doc_base64 = "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";

	let attestation_doc_bytes = STANDARD
		.decode(attestation_doc_base64)
		.expect("Failed to decode base64");

	// Create a custom verifier with extended max age to handle expired attestations for testing
	let pcr_configs = vec![]; // We'll add them below
	let bad_cert = b"-----BEGIN CERTIFICATE-----
    AIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
    MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
    VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
    MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
    DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
    BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
    48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
    h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
    R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
    MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
    rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
    IwLz3/Y=
    -----END CERTIFICATE-----"
		.to_vec();

	let mut verifier = EnclaveAttestationVerifier::new(pcr_configs)
		.with_root_certificate(bad_cert)
		.with_max_age(TEN_YEARS)
		.with_skipped_certificate_time_check();

	// These are real PCR values generated by an enclave in time
	verifier.add_allowed_pcr_config(vec![
		PcrMeasurement::new(
			0,
			hex_literal::hex!(
				"5b6111e5a72a5bfb60ae394baabbe1f0000046ce13f7f2f67fd69e1e212ba90fe53af95a01b9eee9e722795d06406b5d"
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
				"b7c615d9cf63c766db0d7368de89c92c61a4a592ba99d36ae224ce976c9942000d06fcad3f62be739989b326771c8c70"
			),
		),
	]);

	// Verify the attestation document
	let result = verifier.verify_attestation_document(&attestation_doc_bytes);

	assert!(result.is_err(), "Should have failed with bad certificate");
}

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

#[test]
fn test_attestation_with_self_signed_certificate() {
	let fake_attestation = generate_fake_attestation_self_signed();

	let verifier = EnclaveAttestationVerifier::new(vec![]).with_skipped_certificate_time_check();

	let result = verifier.verify_attestation_document(&fake_attestation);
	assert!(
		matches!(
			result,
			Err(EnclaveAttestationError::AttestationChainInvalid(_))
		),
		"Should reject self-signed certificate, got {result:?}"
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
fn test_attestation_with_invalid_certificate_chain() {
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
