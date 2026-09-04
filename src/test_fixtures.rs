//! Shared fixtures for the attestation tests.
//!
//! The document is a real one captured from a Nitro enclave, so its certificates and timestamp are
//! long expired. Verifiers built here widen the age limit and pin certificate validity to the
//! attestation's own timestamp; everything else is checked for real.

use base64::{Engine, engine::general_purpose::STANDARD};

use crate::attestation::{PcrConfig, Verifier};

/// A real attestation document, base64-encoded.
pub const REAL_ATTESTATION_DOC_B64: &str = include_str!("../tests/real-attestation-doc.b64");

/// The public key carried by [`REAL_ATTESTATION_DOC_B64`].
pub const ATTESTED_PUBLIC_KEY: [u8; 32] =
	hex_literal::hex!("43b986461bbdb752dd389e8f36312e5ebc3377f91e694d8125d1bc0079b2e122");

/// Long enough that the expired fixture document still passes the age check.
pub const TEN_YEARS: std::time::Duration = std::time::Duration::from_hours(10 * 365 * 24);

/// The raw bytes of [`REAL_ATTESTATION_DOC_B64`].
pub fn real_attestation_bytes() -> Vec<u8> {
	STANDARD
		.decode(REAL_ATTESTATION_DOC_B64.trim())
		.expect("fixture is valid base64")
}

/// The fixture enclave's PCR0, on its own — enough to satisfy the "must pin PCR0" rule for tests
/// that are exercising some other stage.
pub const fn pcr0_only() -> PcrConfig {
	PcrConfig::new(hex_literal::hex!(
		"108b32466f5dc0a9971e0bc8e3e4074e7821bb2dcad3841bdec9a08b30f173386f0394a01486df181f316b39443dab34"
	))
}

/// A verifier configured with the PCR values the fixture enclave actually reported.
pub fn real_attestation_verifier() -> Verifier {
	real_attestation_verifier_with_max_age(TEN_YEARS)
}

/// As [`real_attestation_verifier`], with a caller-chosen freshness window.
pub fn real_attestation_verifier_with_max_age(max_age: std::time::Duration) -> Verifier {
	let mut verifier = Verifier::new(vec![], max_age).with_skipped_certificate_time_check();

	verifier.add_allowed_pcr_config(
		pcr0_only()
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
			),
	);

	verifier
}
