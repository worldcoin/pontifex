//! A confidential channel between an enclave and a consumer.
//!
//! Enables a consumer to encrypt an arbitrary payload so only the enclave can read it. The consumer
//! also provides a key to receive an end-to-end encrypted response.
//!
//! Uses a `quantum_box` under the hood, which uses HPKE with X-Wing (Kyber KEM) for post-quantum hybrid
//! security.
//!
//!
//! # Important
//! 1. The enclave's seal key MUST remain in the enclave.
//! 2. The response from the enclave is **NOT** attested. Quantum boxes are anonymous, anyone
//!   could have encrypted a response to it with its public key. If the use case requires trusting
//!   the enclave response, add an additional attestation or signature mechanism.
//! 3. This module currently does **NOT** verify an attestation on the enclave's public key.

use quantum_box::{PublicKey, SecretKey};
use zeroize::ZeroizeOnDrop;

pub use quantum_box::Error as SealedBoxError;
pub use zeroize::Zeroizing;

/// Length of an X-Wing encapsulation key: ML-KEM-768 (1184) plus X25519 (32).
const RESPONSE_KEY_LEN: usize = 1216;

// Bound into the `info` so one key is never used for both directions.
const REQUEST: u8 = 0;
const RESPONSE: u8 = 1;

/// Why a channel operation did not complete.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChannelError {
	/// The request opened, but was too short to carry a response key.
	#[error("ChannelError::MissingResponseKey")]
	MissingResponseKey,
	/// The request carried a response key that is not a valid X-Wing encapsulation key.
	#[error("ChannelError::MalformedResponseKey")]
	MalformedResponseKey,
	/// A key, a seal, or an unseal failed.
	#[error("ChannelError::SealedBox: {0}")]
	SealedBox(#[from] SealedBoxError),
}

/// The protocol name bound into every seal on a channel.
///
/// A client and enclave that disagree on the name fail closed instead of exchanging plaintext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelDomain {
	name: &'static str,
}

impl ChannelDomain {
	/// Names a channel domain. A good idea is to anchor it on the enclave's `module_id` (e.g. hash).
	#[must_use]
	pub const fn new(name: &'static str) -> Self {
		Self { name }
	}

	fn info(&self, direction: u8) -> Vec<u8> {
		let mut info = self.name.as_bytes().to_vec();
		info.push(direction);
		info
	}
}

impl ZeroizeOnDrop for ChannelEnclave {}
impl ZeroizeOnDrop for ResponseOpener {} // remember to update if adding more secret info which is not a `SecretKey`

const _: () = {
	// Ensures ZeroizeOnDrop is present for `SecretKey`
	const fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
	assert_zeroize_on_drop::<SecretKey>();
};

/// The enclave side of a channel. Opens sealed requests and seals the matching responses.
pub struct ChannelEnclave {
	domain: ChannelDomain,
	secret_key: SecretKey,
}

impl ChannelEnclave {
	/// Generates a fresh keypair serving `domain`, once per boot.
	///
	/// # Errors
	///
	/// Fails if the operating system CSPRNG is unavailable.
	pub fn generate(domain: ChannelDomain) -> Result<Self, ChannelError> {
		Ok(Self {
			domain,
			secret_key: SecretKey::generate()?,
		})
	}

	/// The public key to which consumers seal.
	#[must_use]
	pub fn public_key(&self) -> Vec<u8> {
		self.secret_key.public_key().to_bytes()
	}

	/// Opens a sealed request, returning the plaintext and the sealer for its one response.
	///
	/// # Errors
	///
	/// Fails if the request was not sealed properly or carries no response key.
	pub fn open(
		&self,
		request: &[u8],
	) -> Result<(Zeroizing<Vec<u8>>, ResponseSealer), ChannelError> {
		let body = Zeroizing::new(SecretKey::unseal(
			&self.secret_key,
			request,
			Some(&self.domain.info(REQUEST)),
		)?);
		let Some((response_key, plaintext)) = body.split_first_chunk::<RESPONSE_KEY_LEN>() else {
			return Err(ChannelError::MissingResponseKey);
		};
		let response_key =
			PublicKey::from_bytes(response_key).map_err(|_| ChannelError::MalformedResponseKey)?;

		Ok((
			Zeroizing::new(plaintext.to_vec()),
			ResponseSealer {
				domain: self.domain,
				response_key,
			},
		))
	}
}

/// Seals a one-time response back to the consumer.
///
/// # Important
/// The sealed response is **NOT** attested by the enclave, and anyone could generate
/// a valid ciphertext for the consumer's public key. If the use case requires the response
/// to be trusted, add an additional attestation/signature to the response.
pub struct ResponseSealer {
	domain: ChannelDomain,
	response_key: PublicKey,
}

impl std::fmt::Debug for ResponseSealer {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ResponseSealer").finish_non_exhaustive()
	}
}

impl ResponseSealer {
	/// Seals the response to the key its request carried.
	///
	/// # Errors
	///
	/// Fails if the operating system CSPRNG is unavailable, or sealing unexpectedly fails.
	pub fn seal(self, plaintext: &[u8]) -> Result<Vec<u8>, ChannelError> {
		Ok(PublicKey::seal(
			&self.response_key,
			plaintext,
			Some(&self.domain.info(RESPONSE)),
		)?)
	}
}

/// The consumer side of a channel, which seals requests to one attested enclave boot.
///
/// Holds no secret: the response key belongs to the [`ResponseOpener`] each seal returns.
#[derive(Clone)]
pub struct ChannelConsumer {
	domain: ChannelDomain,
	enclave_public_key: PublicKey,
}

impl std::fmt::Debug for ChannelConsumer {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("ChannelConsumer")
			.field("domain", &self.domain)
			.finish_non_exhaustive()
	}
}

impl ChannelConsumer {
	/// Builds a consumer for the public key a verified attestation carried.
	///
	/// This does **not** verify that attestation. Verify it first — otherwise the key may be the
	/// untrusted parent's own, and it will read every request.
	///
	/// # Errors
	///
	/// Fails if `enclave_public_key` is not a valid X-Wing encapsulation key.
	pub fn new(domain: ChannelDomain, enclave_public_key: &[u8]) -> Result<Self, ChannelError> {
		Ok(Self {
			domain,
			enclave_public_key: PublicKey::from_bytes(enclave_public_key)?,
		})
	}

	/// Seals one request, returning the ciphertext bytes and the opener for its one response.
	///
	/// # Errors
	///
	/// Fails if the operating system CSPRNG is unavailable, or an unxpected seal error.
	pub fn seal_to_enclave(
		&self,
		plaintext: &[u8],
	) -> Result<(Vec<u8>, ResponseOpener), ChannelError> {
		let response_sk = SecretKey::generate()?;

		let mut body = Zeroizing::new(Vec::with_capacity(RESPONSE_KEY_LEN + plaintext.len()));
		body.extend_from_slice(&response_sk.public_key().to_bytes());
		body.extend_from_slice(plaintext);

		let request = PublicKey::seal(
			&self.enclave_public_key,
			&body,
			Some(&self.domain.info(REQUEST)),
		)?;

		Ok((
			request,
			ResponseOpener {
				domain: self.domain,
				response_sk,
			},
		))
	}
}

/// Opens the response from the enclave after a [`ChannelConsumer::seal_to_enclave`] call. One-time use.
///
/// ```compile_fail,E0382
/// # use pontifex::channel::{ChannelConsumer, ChannelDomain, ChannelEnclave};
/// # const DOMAIN: ChannelDomain = ChannelDomain::new("pontifex/doc");
/// # let enclave = ChannelEnclave::generate(DOMAIN)?;
/// # let consumer = ChannelConsumer::new(DOMAIN, &enclave.public_key())?;
/// # let (request, opener) = consumer.seal_to_enclave(b"inputs")?;
/// # let (_, sealer) = enclave.open(&request)?;
/// # let response = sealer.seal(b"result")?;
/// opener.open_from_enclave(&response)?;
/// opener.open_from_enclave(&response)?; // the opener was consumed above
/// # Ok::<(), pontifex::ChannelError>(())
/// ```
#[derive(Debug)]
pub struct ResponseOpener {
	domain: ChannelDomain,
	response_sk: SecretKey,
}

impl ResponseOpener {
	/// Opens the response to this request. Key is zeroized after use.
	///
	/// # Errors
	///
	/// Fails if the response was not sealed to this request under this domain. Retry by sealing
	/// a fresh request; the key for these bytes is gone.
	pub fn open_from_enclave(self, response: &[u8]) -> Result<Zeroizing<Vec<u8>>, ChannelError> {
		Ok(Zeroizing::new(SecretKey::unseal(
			&self.response_sk,
			response,
			Some(&self.domain.info(RESPONSE)),
		)?))
	}
}

#[cfg(test)]
mod tests {
	use super::{
		ChannelConsumer, ChannelDomain, ChannelEnclave, ChannelError, REQUEST, RESPONSE,
		RESPONSE_KEY_LEN, ResponseOpener, SealedBoxError,
	};
	use quantum_box::{PublicKey, SecretKey};

	const TEST_DOMAIN: ChannelDomain = ChannelDomain::new("pontifex/test");

	fn enclave() -> ChannelEnclave {
		ChannelEnclave::generate(TEST_DOMAIN).expect("CSPRNG available")
	}

	fn consumer_for(enclave: &ChannelEnclave, domain: ChannelDomain) -> ChannelConsumer {
		ChannelConsumer::new(domain, &enclave.public_key()).expect("attested key parses")
	}

	fn seal(consumer: &ChannelConsumer, plaintext: &[u8]) -> (Vec<u8>, ResponseOpener) {
		consumer.seal_to_enclave(plaintext).expect("seal")
	}

	fn seal_raw_body(enclave: &ChannelEnclave, body: &[u8]) -> Vec<u8> {
		PublicKey::seal(
			&enclave.secret_key.public_key(),
			body,
			Some(&TEST_DOMAIN.info(REQUEST)),
		)
		.expect("seal")
	}

	#[test]
	fn round_trips_a_request_and_its_response() {
		let enclave = enclave();
		let (request, opener) = seal(&consumer_for(&enclave, TEST_DOMAIN), b"inputs");

		let (plaintext, sealer) = enclave.open(&request).expect("open");
		assert_eq!(plaintext.as_slice(), b"inputs");

		let response = sealer.seal(b"result").expect("seal response");
		assert_eq!(
			opener
				.open_from_enclave(&response)
				.expect("open response")
				.as_slice(),
			b"result"
		);
	}

	#[test]
	fn round_trips_an_empty_body_in_both_directions() {
		let enclave = enclave();
		let (request, opener) = seal(&consumer_for(&enclave, TEST_DOMAIN), b"");

		let (plaintext, sealer) = enclave.open(&request).expect("open");
		assert!(plaintext.is_empty());

		let response = sealer.seal(b"").expect("seal response");
		assert!(
			opener
				.open_from_enclave(&response)
				.expect("open response")
				.is_empty()
		);
	}

	#[test]
	fn an_opener_rejects_the_response_to_another_request() {
		let enclave = enclave();
		let consumer = consumer_for(&enclave, TEST_DOMAIN);

		let (first, first_opener) = seal(&consumer, b"transfer 10");
		let (second, _) = seal(&consumer, b"transfer 10000");

		let (_, first_sealer) = enclave.open(&first).expect("open first");
		let (_, second_sealer) = enclave.open(&second).expect("open second");
		assert_ne!(
			first_sealer.response_key.to_bytes(),
			second_sealer.response_key.to_bytes(),
			"each request must mint its own response key"
		);

		let substituted = second_sealer.seal(b"ok").expect("seal response");
		assert_eq!(
			first_opener.open_from_enclave(&substituted).err(),
			Some(ChannelError::SealedBox(SealedBoxError::Unseal))
		);
	}

	#[test]
	fn a_response_key_is_exactly_the_framed_length() {
		let key = SecretKey::from_seed(&[0u8; 32]).public_key().to_bytes();
		assert_eq!(key.len(), RESPONSE_KEY_LEN);
	}

	#[test]
	fn info_binds_name_and_direction() {
		assert_eq!(
			TEST_DOMAIN.info(REQUEST),
			[b"pontifex/test".as_ref(), &[REQUEST]].concat()
		);
		assert_ne!(TEST_DOMAIN.info(REQUEST), TEST_DOMAIN.info(RESPONSE));
		assert_ne!(
			TEST_DOMAIN.info(REQUEST),
			ChannelDomain::new("pontifex/other").info(REQUEST)
		);
	}

	#[test]
	fn rejects_an_unparseable_key() {
		assert_eq!(
			ChannelConsumer::new(TEST_DOMAIN, &[0u8; 32]).err(),
			Some(ChannelError::SealedBox(SealedBoxError::KeyFormat))
		);
	}

	#[test]
	fn rejects_a_request_sealed_to_another_key() {
		let (request, _) = seal(&consumer_for(&enclave(), TEST_DOMAIN), b"inputs");

		assert_eq!(
			enclave().open(&request).err(),
			Some(ChannelError::SealedBox(SealedBoxError::Unseal))
		);
	}

	#[test]
	fn rejects_a_request_sealed_under_another_domain() {
		let enclave = enclave();
		let (request, _) = seal(
			&consumer_for(&enclave, ChannelDomain::new("pontifex/other")),
			b"inputs",
		);

		assert_eq!(
			enclave.open(&request).err(),
			Some(ChannelError::SealedBox(SealedBoxError::Unseal))
		);
	}

	#[test]
	fn rejects_a_tampered_request() {
		let enclave = enclave();
		let (mut request, _) = seal(&consumer_for(&enclave, TEST_DOMAIN), b"inputs");
		*request.last_mut().expect("non-empty") ^= 0x01;

		assert_eq!(
			enclave.open(&request).err(),
			Some(ChannelError::SealedBox(SealedBoxError::Unseal))
		);
	}

	#[test]
	fn rejects_a_truncated_request() {
		assert_eq!(
			enclave().open(&[]).err(),
			Some(ChannelError::SealedBox(SealedBoxError::EmptyCiphertext))
		);
		assert_eq!(
			enclave().open(b"short").err(),
			Some(ChannelError::SealedBox(SealedBoxError::Decode))
		);
	}

	#[test]
	fn rejects_a_request_carrying_no_response_key() {
		let enclave = enclave();

		for body in [
			b"".as_ref(),
			b"no response key here".as_ref(),
			&[0u8; RESPONSE_KEY_LEN - 1],
		] {
			let request = seal_raw_body(&enclave, body);
			assert_eq!(
				enclave.open(&request).err(),
				Some(ChannelError::MissingResponseKey),
				"body of {} bytes",
				body.len()
			);
		}
	}

	#[test]
	fn rejects_a_request_carrying_a_malformed_response_key() {
		let enclave = enclave();
		let request = seal_raw_body(&enclave, &[0xFF; RESPONSE_KEY_LEN]);

		assert_eq!(
			enclave.open(&request).err(),
			Some(ChannelError::MalformedResponseKey)
		);
	}

	#[test]
	fn rejects_a_tampered_response() {
		let enclave = enclave();
		let (request, opener) = seal(&consumer_for(&enclave, TEST_DOMAIN), b"inputs");

		let (_, sealer) = enclave.open(&request).expect("open");
		let mut response = sealer.seal(b"result").expect("seal response");
		*response.last_mut().expect("non-empty") ^= 0x01;

		assert_eq!(
			opener.open_from_enclave(&response).err(),
			Some(ChannelError::SealedBox(SealedBoxError::Unseal))
		);
	}

	#[test]
	fn rejects_a_truncated_response() {
		let enclave = enclave();
		let (_, opener) = seal(&consumer_for(&enclave, TEST_DOMAIN), b"inputs");

		assert_eq!(
			opener.open_from_enclave(&[]).err(),
			Some(ChannelError::SealedBox(SealedBoxError::EmptyCiphertext))
		);
	}

	#[test]
	fn rejects_a_response_sealed_under_the_request_direction() {
		let enclave = enclave();
		let (_, opener) = seal(&consumer_for(&enclave, TEST_DOMAIN), b"inputs");

		let response = PublicKey::seal(
			&opener.response_sk.public_key(),
			b"result",
			Some(&TEST_DOMAIN.info(REQUEST)),
		)
		.expect("seal");

		assert_eq!(
			opener.open_from_enclave(&response).err(),
			Some(ChannelError::SealedBox(SealedBoxError::Unseal))
		);
	}

	#[test]
	fn rejects_a_response_sealed_under_another_domain() {
		let enclave = enclave();
		let (_, opener) = seal(&consumer_for(&enclave, TEST_DOMAIN), b"inputs");

		let response = PublicKey::seal(
			&opener.response_sk.public_key(),
			b"result",
			Some(&ChannelDomain::new("pontifex/other").info(RESPONSE)),
		)
		.expect("seal");

		assert_eq!(
			opener.open_from_enclave(&response).err(),
			Some(ChannelError::SealedBox(SealedBoxError::Unseal))
		);
	}

	#[test]
	fn keys_are_generated_randomly() {
		assert_ne!(enclave().public_key(), enclave().public_key());
	}

	#[test]
	fn sealing_the_same_plaintext_twice_yields_different_bytes() {
		let consumer = consumer_for(&enclave(), TEST_DOMAIN);

		assert_ne!(seal(&consumer, b"inputs").0, seal(&consumer, b"inputs").0);
	}

	#[test]
	fn key_types_do_not_print_their_keys() {
		let enclave = enclave();
		let consumer = consumer_for(&enclave, TEST_DOMAIN);
		let (request, _) = seal(&consumer, b"inputs");
		let (_, sealer) = enclave.open(&request).expect("open");

		assert_eq!(
			format!("{consumer:?}"),
			r#"ChannelConsumer { domain: ChannelDomain { name: "pontifex/test" }, .. }"#
		);
		assert_eq!(format!("{sealer:?}"), "ResponseSealer { .. }");
	}
}
