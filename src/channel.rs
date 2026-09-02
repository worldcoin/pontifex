//! A confidential channel to a specific, measured enclave.
//!
//! Every message is a [`quantum_box`] sealed box — an anonymous HPKE seal over the X-Wing hybrid
//! KEM — so the untrusted parent instance forwarding the bytes never sees plaintext.
//!
//! The enclave generates a [`Responder`] per boot and attests its public key. A client verifies
//! the attestation, builds a [`Requester`] from the attested key, and seals to it. Each request
//! carries a fresh reply key that the enclave seals the one matching response to, so the response
//! needs no second round trip and only that requester can open it.
//!
//! Both sides must name the same [`ChannelDomain`], which is bound into every seal.

use quantum_box::{PublicKey, SecretKey};

/// Length of an X-Wing encapsulation key: ML-KEM-768 (1184) plus X25519 (32).
const REPLY_KEY_LEN: usize = 1216;

// Bound into the `info` so one key is never used for both directions.
const REQUEST: u8 = 0;
const RESPONSE: u8 = 1;

/// Why a channel operation did not complete.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ChannelError {
	/// The request opened, but was too short to carry a reply key.
	#[error("ChannelError::MissingReplyKey")]
	MissingReplyKey,
	/// A key, a seal, or an unseal failed.
	#[error("ChannelError::SealedBox: {0}")]
	SealedBox(#[from] quantum_box::Error),
}

/// A protocol name and the version of its wire contract, both bound into every seal.
///
/// Name one protocol per domain and never reuse it. Bumping the version fails every message
/// sealed under the old number, which is the lever for a breaking change to the sealed bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelDomain {
	name: &'static str,
	version: u8,
}

impl ChannelDomain {
	/// Names a channel domain at a wire version.
	#[must_use]
	pub const fn new(name: &'static str, version: u8) -> Self {
		Self { name, version }
	}

	fn info(&self, direction: u8) -> Vec<u8> {
		let mut info = self.name.as_bytes().to_vec();
		info.push(self.version);
		info.push(direction);
		info
	}
}

/// Responder-side boot keypair: opens sealed requests and seals the matching responses.
pub struct Responder {
	domain: ChannelDomain,
	secret_key: SecretKey,
}

impl Responder {
	/// Generates a fresh keypair serving `domain`.
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

	/// The public key requesters seal to for this boot. Attest these bytes.
	#[must_use]
	pub fn public_key(&self) -> Vec<u8> {
		self.secret_key.public_key().to_bytes()
	}

	/// Opens a sealed request, returning the plaintext and a sealer for its one response.
	///
	/// # Errors
	///
	/// Fails if the request was not sealed to this boot under this domain, or carries no reply
	/// key.
	pub fn open(&self, request: &[u8]) -> Result<(Vec<u8>, ResponseSealer), ChannelError> {
		let body = SecretKey::unseal(&self.secret_key, request, Some(&self.domain.info(REQUEST)))?;
		let Some((reply_key, plaintext)) = body.split_first_chunk::<REPLY_KEY_LEN>() else {
			return Err(ChannelError::MissingReplyKey);
		};

		Ok((
			plaintext.to_vec(),
			ResponseSealer {
				domain: self.domain,
				reply_key: PublicKey::from_bytes(reply_key)?,
			},
		))
	}
}

/// Requester-side handle built from an attested encryption key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Requester {
	domain: ChannelDomain,
	public_key: PublicKey,
}

impl Requester {
	/// Builds a requester for the public key a verified attestation carried.
	///
	/// # Errors
	///
	/// Fails if `public_key` is not a valid X-Wing encapsulation key.
	pub fn new(domain: ChannelDomain, public_key: &[u8]) -> Result<Self, ChannelError> {
		Ok(Self {
			domain,
			public_key: PublicKey::from_bytes(public_key)?,
		})
	}

	/// Seals one request, returning the wire bytes and an opener for its one response.
	///
	/// # Errors
	///
	/// Fails if the operating system CSPRNG is unavailable, or the box refuses to seal.
	pub fn seal(&self, plaintext: &[u8]) -> Result<(Vec<u8>, ResponseOpener), ChannelError> {
		let reply_key = SecretKey::generate()?;
		let mut body = reply_key.public_key().to_bytes();
		body.extend_from_slice(plaintext);

		let request = PublicKey::seal(&self.public_key, &body, Some(&self.domain.info(REQUEST)))?;

		Ok((
			request,
			ResponseOpener {
				domain: self.domain,
				reply_key,
			},
		))
	}
}

/// Opens the one response belonging to a [`Requester::seal`] call.
pub struct ResponseOpener {
	domain: ChannelDomain,
	reply_key: SecretKey,
}

impl ResponseOpener {
	/// Opens a sealed response.
	///
	/// # Errors
	///
	/// Fails if the response was not sealed to this request.
	pub fn open(&self, response: &[u8]) -> Result<Vec<u8>, ChannelError> {
		Ok(SecretKey::unseal(
			&self.reply_key,
			response,
			Some(&self.domain.info(RESPONSE)),
		)?)
	}
}

/// Seals the one response belonging to a [`Responder::open`] call.
pub struct ResponseSealer {
	domain: ChannelDomain,
	reply_key: PublicKey,
}

impl ResponseSealer {
	/// Seals one response.
	///
	/// # Errors
	///
	/// Fails if the operating system CSPRNG is unavailable, or the box refuses to seal.
	pub fn seal(self, plaintext: &[u8]) -> Result<Vec<u8>, ChannelError> {
		Ok(PublicKey::seal(
			&self.reply_key,
			plaintext,
			Some(&self.domain.info(RESPONSE)),
		)?)
	}
}

#[cfg(test)]
mod tests {
	use super::{
		ChannelDomain, ChannelError, REPLY_KEY_LEN, REQUEST, RESPONSE, Requester, Responder,
	};
	use quantum_box::{Error, SecretKey};

	const TEST_DOMAIN: ChannelDomain = ChannelDomain::new("pontifex/test", 1);

	fn responder() -> Responder {
		Responder::generate(TEST_DOMAIN).expect("CSPRNG available")
	}

	fn requester_for(responder: &Responder, domain: ChannelDomain) -> Requester {
		Requester::new(domain, &responder.public_key()).expect("attested key parses")
	}

	#[test]
	fn round_trips_a_request_and_its_response() {
		let responder = responder();
		let (request, opener) = requester_for(&responder, TEST_DOMAIN)
			.seal(b"inputs")
			.expect("seal");

		let (plaintext, sealer) = responder.open(&request).expect("open");
		assert_eq!(plaintext, b"inputs");

		let response = sealer.seal(b"result").expect("seal response");
		assert_eq!(opener.open(&response).expect("open response"), b"result");
	}

	/// Guards the framing constant against an X-Wing key size change upstream.
	#[test]
	fn a_reply_key_is_exactly_the_framed_length() {
		let key = SecretKey::from_seed(&[0u8; 32]).public_key().to_bytes();
		assert_eq!(key.len(), REPLY_KEY_LEN);
	}

	#[test]
	fn info_binds_name_version_and_direction() {
		assert_eq!(
			TEST_DOMAIN.info(REQUEST),
			[b"pontifex/test".as_ref(), &[1, REQUEST]].concat()
		);
		assert_ne!(TEST_DOMAIN.info(REQUEST), TEST_DOMAIN.info(RESPONSE));
		assert_ne!(
			TEST_DOMAIN.info(REQUEST),
			ChannelDomain::new("pontifex/other", 1).info(REQUEST)
		);
		assert_ne!(
			TEST_DOMAIN.info(REQUEST),
			ChannelDomain::new("pontifex/test", 2).info(REQUEST)
		);
	}

	#[test]
	fn rejects_an_unparseable_attested_key() {
		assert_eq!(
			Requester::new(TEST_DOMAIN, &[0u8; 32]),
			Err(ChannelError::SealedBox(Error::KeyFormat))
		);
	}

	#[test]
	fn rejects_a_request_sealed_to_another_boot() {
		let (request, _) = requester_for(&responder(), TEST_DOMAIN)
			.seal(b"inputs")
			.expect("seal");

		assert_eq!(
			responder().open(&request).err(),
			Some(ChannelError::SealedBox(Error::Unseal))
		);
	}

	#[test]
	fn rejects_a_request_sealed_under_another_domain() {
		let responder = responder();
		for domain in [
			ChannelDomain::new("pontifex/other", 1),
			ChannelDomain::new("pontifex/test", 2),
		] {
			let (request, _) = requester_for(&responder, domain)
				.seal(b"inputs")
				.expect("seal");
			assert_eq!(
				responder.open(&request).err(),
				Some(ChannelError::SealedBox(Error::Unseal)),
				"{domain:?}"
			);
		}
	}

	#[test]
	fn rejects_a_tampered_request() {
		let responder = responder();
		let (mut request, _) = requester_for(&responder, TEST_DOMAIN)
			.seal(b"inputs")
			.expect("seal");
		*request.last_mut().expect("non-empty") ^= 0x01;

		assert_eq!(
			responder.open(&request).err(),
			Some(ChannelError::SealedBox(Error::Unseal))
		);
	}

	#[test]
	fn rejects_a_truncated_request() {
		assert_eq!(
			responder().open(&[]).err(),
			Some(ChannelError::SealedBox(Error::EmptyCiphertext))
		);
		assert_eq!(
			responder().open(b"short").err(),
			Some(ChannelError::SealedBox(Error::Decode))
		);
	}

	/// The boot's key is public, so any sender can seal a body too short to carry a reply key.
	#[test]
	fn rejects_a_request_carrying_no_reply_key() {
		let responder = responder();
		let request = quantum_box::PublicKey::seal(
			&responder.secret_key.public_key(),
			b"no reply key here",
			Some(&TEST_DOMAIN.info(REQUEST)),
		)
		.expect("seal");

		assert_eq!(
			responder.open(&request).err(),
			Some(ChannelError::MissingReplyKey)
		);
	}

	#[test]
	fn rejects_a_tampered_response() {
		let responder = responder();
		let (request, opener) = requester_for(&responder, TEST_DOMAIN)
			.seal(b"inputs")
			.expect("seal");
		let (_, sealer) = responder.open(&request).expect("open");

		let mut response = sealer.seal(b"result").expect("seal response");
		*response.last_mut().expect("non-empty") ^= 0x01;

		assert_eq!(
			opener.open(&response),
			Err(ChannelError::SealedBox(Error::Unseal))
		);
	}

	#[test]
	fn another_requester_cannot_open_a_response() {
		let responder = responder();
		let requester = requester_for(&responder, TEST_DOMAIN);
		let (request, _) = requester.seal(b"inputs").expect("seal");
		let (_, eavesdropper) = requester.seal(b"unrelated").expect("seal");

		let (_, sealer) = responder.open(&request).expect("open");
		let response = sealer.seal(b"result").expect("seal response");

		assert_eq!(
			eavesdropper.open(&response),
			Err(ChannelError::SealedBox(Error::Unseal))
		);
	}

	#[test]
	fn separate_boots_advertise_separate_keys() {
		assert_ne!(responder().public_key(), responder().public_key());
	}

	#[test]
	fn sealing_the_same_plaintext_twice_yields_different_bytes() {
		let requester = requester_for(&responder(), TEST_DOMAIN);
		let (first, _) = requester.seal(b"inputs").expect("seal");
		let (second, _) = requester.seal(b"inputs").expect("seal");

		assert_ne!(first, second);
	}
}
