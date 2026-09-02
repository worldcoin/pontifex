//! A confidential channel to a specific, measured enclave.
//!
//! Requests use [RFC 9180](https://datatracker.ietf.org/doc/rfc9180/) `mode_base` directly.
//! Responses use the encapsulation construction of
//! [RFC 9458 §4.4](https://datatracker.ietf.org/doc/rfc9458/) — Oblivious HTTP — because it
//! solves exactly the problem a request-response enclave path has: replying to one HPKE request
//! without a second key exchange, and without reusing the request context in reverse, which
//! RFC 9180 §9.8 forbids.
//!
//! Both halves live in one module so the tests exercise the same code the enclave and the client
//! each run, rather than a test-only reimplementation of one side.
//!
//! # Domain separation
//!
//! Channels are opened under a caller-named [`ChannelDomain`] bound into the HPKE `info`, so
//! neither another protocol nor another wire version can open a channel's messages.
//!
//! # Relationship to RFC 9458 §4.4
//!
//! Followed as written. The one substitution is the caller's exporter label (see
//! [`ChannelDomain`]) in place of `"message/bhttp response"`. §4.4 step 1 points at §4.6,
//! *Repurposing the Encapsulation Format*, for alternative message formats, and §6.4, *Key
//! Management*, adds that the label was chosen for symmetry only and that designers reusing the
//! format should pick a different one for key diversity. No BHTTP is carried here, so this is a
//! substitution the RFC directs rather than a deviation from it.

use aes_gcm::{
	aead::{Aead, Nonce},
	Aes256Gcm, Key, KeyInit,
};
use channel_sha2::Sha256;
use hkdf::Hkdf;
use hpke::{
	aead::AeadCtxS, rand_core::CryptoRng, setup_receiver, setup_sender_with_rng, Deserializable,
	Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use zeroize::Zeroizing;

/// The channel ciphersuite, pinned at the type level so it cannot drift silently:
/// DHKEM(X25519, HKDF-SHA256) — RFC 9180 §7.1.
type Kem = hpke::kem::X25519HkdfSha256;
/// HKDF-SHA256 — RFC 9180 §7.2.
type Kdf = hpke::kdf::HkdfSha256;
/// AES-256-GCM — RFC 9180 §7.3, AEAD id `0x0002`.
type ChannelAead = hpke::aead::AesGcm256;

/// Length of an X25519 public key, which is what an enclave attests.
pub const ENCRYPTION_KEY_LEN: usize = 32;

/// Appended to a domain name to form the response exporter label.
const EXPORTER_LABEL_SUFFIX: &[u8] = b" response";

/// `Expand` info for the response AEAD key — RFC 9458 §4.4 step 4.
const INFO_KEY: &[u8] = b"key";

/// `Expand` info for the response AEAD nonce — RFC 9458 §4.4 step 5.
const INFO_NONCE: &[u8] = b"nonce";

/// Length of an HPKE encapsulated key under DHKEM(X25519, HKDF-SHA256) — RFC 9180 §7.1.
const ENCAPSULATED_KEY_LEN: usize = 32;

/// AES-256-GCM key length — RFC 9180 §7.3 `Nk`.
const AEAD_KEY_LEN: usize = 32;

/// AES-256-GCM nonce length — RFC 9180 §7.3 `Nn`.
const AEAD_NONCE_LEN: usize = 12;

/// GCM authentication tag length — RFC 9180 §7.3 `Nt`.
const AEAD_TAG_LEN: usize = 16;

/// `max(Nn, Nk)`, the length RFC 9458 §4.4 uses for both the exported secret (step 1) and the
/// `response_nonce` (step 2).
const RESPONSE_NONCE_LEN: usize = if AEAD_NONCE_LEN > AEAD_KEY_LEN {
	AEAD_NONCE_LEN
} else {
	AEAD_KEY_LEN
};

const _: () = assert!(RESPONSE_NONCE_LEN >= AEAD_KEY_LEN);
const _: () = assert!(RESPONSE_NONCE_LEN >= AEAD_NONCE_LEN);

/// Why a channel operation did not complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelError {
	/// A wire body was too short to hold its framing, a tag, and any plaintext.
	Truncated,
	/// The encapsulated key was malformed, or yielded the all-zero shared secret that
	/// RFC 9180 §7.1.4 requires the KEM to abort on.
	InvalidEncapsulatedKey,
	/// The advertised encryption public key was not a valid X25519 point.
	InvalidEncryptionKey,
	/// The ciphertext failed authentication under the derived key.
	OpenFailed,
	/// Exporting the response secret from the request context failed — RFC 9458 §4.4 step 1.
	ExportFailed,
	/// Deriving the response AEAD key or nonce failed — RFC 9458 §4.4 steps 3 to 5.
	DeriveFailed,
	/// The AEAD refused to seal, which a well-formed key and nonce make unreachable.
	SealFailed,
}

/// A protocol name and the version of its wire contract, both bound into the HPKE `info`.
///
/// Name one protocol per domain and never reuse it; the name also derives the RFC 9458 §4.4
/// exporter label as `"<name> response"`. Bumping the version fails every channel under the old
/// number at setup, which is the lever for a breaking change to the sealed bytes.
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

	/// Returns the protocol name.
	#[must_use]
	pub const fn name(&self) -> &'static str {
		self.name
	}

	/// Returns the wire version.
	#[must_use]
	pub const fn version(&self) -> u8 {
		self.version
	}

	/// HPKE `info`: name, wire version, and responder public key.
	///
	/// Both sides bind this into the key schedule, so a mismatched domain, version or boot fails
	/// at setup rather than decrypting garbage.
	fn info(&self, encryption_public_key: &[u8; ENCRYPTION_KEY_LEN]) -> Vec<u8> {
		let name = self.name.as_bytes();
		let mut info = Vec::with_capacity(name.len() + 1 + encryption_public_key.len());
		info.extend_from_slice(name);
		info.push(self.version);
		info.extend_from_slice(encryption_public_key);
		info
	}

	/// Exporter context for the response secret — RFC 9458 §4.4 step 1.
	fn exporter_label(&self) -> Vec<u8> {
		let name = self.name.as_bytes();
		let mut label = Vec::with_capacity(name.len() + EXPORTER_LABEL_SUFFIX.len());
		label.extend_from_slice(name);
		label.extend_from_slice(EXPORTER_LABEL_SUFFIX);
		label
	}
}

/// A sealed request on the wire: `enc || ciphertext`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedRequest(Vec<u8>);

impl SealedRequest {
	/// Wraps request bytes. Validation happens in [`Responder::open`].
	#[must_use]
	pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
		Self(bytes.into())
	}

	/// Returns the raw wire bytes.
	#[must_use]
	pub fn into_bytes(self) -> Vec<u8> {
		self.0
	}
}

impl AsRef<[u8]> for SealedRequest {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

/// A sealed response on the wire: `response_nonce || ciphertext`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedResponse(Vec<u8>);

impl SealedResponse {
	/// Wraps response bytes. Validation happens in [`ResponseOpener::open`].
	#[must_use]
	pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
		Self(bytes.into())
	}

	/// Returns the raw wire bytes.
	#[must_use]
	pub fn into_bytes(self) -> Vec<u8> {
		self.0
	}
}

impl AsRef<[u8]> for SealedResponse {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

type ResponseSecret = Zeroizing<[u8; RESPONSE_NONCE_LEN]>;

/// The `Extract`/`Expand` chain of RFC 9458 §4.4 steps 3 to 5, returning raw key material.
///
/// Split from [`derive_response_aead`] so a known-answer test can pin the derived bytes against
/// an independently computed vector; production code never sees the raw key outside this file.
fn derive_response_key_nonce(
	secret: &ResponseSecret,
	encapsulated_key: &[u8; ENCAPSULATED_KEY_LEN],
	response_nonce: &[u8; RESPONSE_NONCE_LEN],
) -> Result<(Zeroizing<[u8; AEAD_KEY_LEN]>, [u8; AEAD_NONCE_LEN]), ChannelError> {
	let mut salt = Vec::with_capacity(ENCAPSULATED_KEY_LEN + RESPONSE_NONCE_LEN);
	salt.extend_from_slice(encapsulated_key);
	salt.extend_from_slice(response_nonce);

	let hkdf = Hkdf::<Sha256>::new(Some(&salt), secret.as_slice());

	let mut key = Zeroizing::new([0u8; AEAD_KEY_LEN]);
	let mut nonce = [0u8; AEAD_NONCE_LEN];
	hkdf.expand(INFO_KEY, key.as_mut_slice())
		.and_then(|()| hkdf.expand(INFO_NONCE, &mut nonce))
		.map_err(|_| ChannelError::DeriveFailed)?;

	Ok((key, nonce))
}

fn derive_response_aead(
	secret: &ResponseSecret,
	encapsulated_key: &[u8; ENCAPSULATED_KEY_LEN],
	response_nonce: &[u8; RESPONSE_NONCE_LEN],
) -> Result<(Aes256Gcm, Nonce<Aes256Gcm>), ChannelError> {
	let (key, nonce) = derive_response_key_nonce(secret, encapsulated_key, response_nonce)?;

	Ok((
		Aes256Gcm::new(&Key::<Aes256Gcm>::from(*key)),
		Nonce::<Aes256Gcm>::from(nonce),
	))
}

/// Responder-side boot keypair. Opens sealed requests and seals responses.
pub struct Responder {
	domain: ChannelDomain,
	secret_key: <Kem as KemTrait>::PrivateKey,
	public_key: [u8; ENCRYPTION_KEY_LEN],
}

impl Responder {
	/// Generates a fresh keypair from `rng`, serving `domain`.
	///
	/// # Panics
	///
	/// Panics if the KEM produces a public key that is not [`ENCRYPTION_KEY_LEN`] bytes.
	#[must_use]
	pub fn generate(domain: ChannelDomain, rng: &mut impl CryptoRng) -> Self {
		let (secret_key, public_key) = Kem::gen_keypair_with_rng(rng);
		let public_key = public_key
			.to_bytes()
			.as_slice()
			.try_into()
			.expect("X25519 public keys are 32 bytes");

		Self {
			domain,
			secret_key,
			public_key,
		}
	}

	/// Returns the public key requesters seal to for this boot.
	#[must_use]
	pub const fn public_key(&self) -> [u8; ENCRYPTION_KEY_LEN] {
		self.public_key
	}

	/// Returns the domain this responder serves.
	#[must_use]
	pub const fn domain(&self) -> ChannelDomain {
		self.domain
	}

	/// Opens a sealed request and returns the plaintext plus a [`ResponseSealer`] for the reply.
	///
	/// # Errors
	///
	/// Returns [`ChannelError`] if the request is too short, the encapsulated key is unusable, the
	/// ciphertext fails authentication, or the response secret cannot be exported.
	pub fn open(
		&self,
		request: &SealedRequest,
	) -> Result<(Zeroizing<Vec<u8>>, ResponseSealer), ChannelError> {
		let body = request.as_ref();
		if body.len() <= ENCAPSULATED_KEY_LEN + AEAD_TAG_LEN {
			return Err(ChannelError::Truncated);
		}
		let (encapsulated, ciphertext) = body.split_at(ENCAPSULATED_KEY_LEN);
		let encapsulated_key: [u8; ENCAPSULATED_KEY_LEN] = encapsulated
			.try_into()
			.map_err(|_| ChannelError::Truncated)?;

		let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(encapsulated)
			.map_err(|_| ChannelError::InvalidEncapsulatedKey)?;

		let info = self.domain.info(&self.public_key);
		let mut context = setup_receiver::<ChannelAead, Kdf, Kem>(
			&OpModeR::Base,
			&self.secret_key,
			&encapped,
			&info,
		)
		.map_err(|_| ChannelError::InvalidEncapsulatedKey)?;

		let plaintext = context
			.open(ciphertext, &[])
			.map_err(|_| ChannelError::OpenFailed)?;

		let mut secret = Zeroizing::new([0u8; RESPONSE_NONCE_LEN]);
		context
			.export(&self.domain.exporter_label(), secret.as_mut_slice())
			.map_err(|_| ChannelError::ExportFailed)?;

		Ok((
			Zeroizing::new(plaintext),
			ResponseSealer {
				secret,
				encapsulated_key,
			},
		))
	}
}

/// Requester-side handle built from a verified encryption public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Requester {
	domain: ChannelDomain,
	public_key: [u8; ENCRYPTION_KEY_LEN],
}

impl Requester {
	/// Builds a requester from an attested encryption public key.
	///
	/// This is a format check, not point validation: every 32-byte string decodes as an X25519
	/// public key (RFC 7748 clamps on use), so a key yielding no valid shared secret — the
	/// all-zero point, for instance — is only rejected when [`Self::seal`] runs encapsulation.
	///
	/// # Errors
	///
	/// Returns [`ChannelError::InvalidEncryptionKey`] if `public_key` cannot be decoded.
	pub fn new(
		domain: ChannelDomain,
		public_key: [u8; ENCRYPTION_KEY_LEN],
	) -> Result<Self, ChannelError> {
		<Kem as KemTrait>::PublicKey::from_bytes(&public_key)
			.map_err(|_| ChannelError::InvalidEncryptionKey)?;
		Ok(Self { domain, public_key })
	}

	/// Builds a requester from the public key an attestation document carried.
	///
	/// # Errors
	///
	/// Returns [`ChannelError::InvalidEncryptionKey`] if `public_key` is not exactly
	/// [`ENCRYPTION_KEY_LEN`] bytes or cannot be decoded; see [`Self::new`] for what decoding
	/// does and does not validate.
	pub fn from_attestation(
		domain: ChannelDomain,
		public_key: &[u8],
	) -> Result<Self, ChannelError> {
		let public_key: [u8; ENCRYPTION_KEY_LEN] = public_key
			.try_into()
			.map_err(|_| ChannelError::InvalidEncryptionKey)?;
		Self::new(domain, public_key)
	}

	/// Returns the raw X25519 public key.
	#[must_use]
	pub const fn public_key(&self) -> [u8; ENCRYPTION_KEY_LEN] {
		self.public_key
	}

	/// Returns the domain this requester seals under.
	#[must_use]
	pub const fn domain(&self) -> ChannelDomain {
		self.domain
	}

	/// Seals one request, returning the wire body and a [`ResponseOpener`] for the reply.
	///
	/// # Errors
	///
	/// Returns [`ChannelError`] if the public key yields no shared secret, or the AEAD refuses to
	/// seal.
	pub fn seal(
		&self,
		plaintext: &[u8],
		rng: &mut impl CryptoRng,
	) -> Result<(SealedRequest, ResponseOpener), ChannelError> {
		let public_key = <Kem as KemTrait>::PublicKey::from_bytes(&self.public_key)
			.map_err(|_| ChannelError::InvalidEncryptionKey)?;

		let info = self.domain.info(&self.public_key);
		let (encapped, mut context) =
			setup_sender_with_rng::<ChannelAead, Kdf, Kem>(&OpModeS::Base, &public_key, &info, rng)
				.map_err(|_| ChannelError::InvalidEncryptionKey)?;

		let ciphertext = context
			.seal(plaintext, &[])
			.map_err(|_| ChannelError::SealFailed)?;

		let encapsulated = encapped.to_bytes();
		let encapsulated_key: [u8; ENCAPSULATED_KEY_LEN] = encapsulated
			.as_slice()
			.try_into()
			.map_err(|_| ChannelError::InvalidEncapsulatedKey)?;

		let mut body = encapsulated_key.to_vec();
		body.extend_from_slice(&ciphertext);

		Ok((
			SealedRequest(body),
			ResponseOpener {
				exporter_label: self.domain.exporter_label(),
				context,
				encapsulated_key,
			},
		))
	}
}

/// Opens the response belonging to one [`Requester::seal`] call.
pub struct ResponseOpener {
	exporter_label: Vec<u8>,
	context: AeadCtxS<ChannelAead, Kdf, Kem>,
	encapsulated_key: [u8; ENCAPSULATED_KEY_LEN],
}

impl ResponseOpener {
	/// Opens a sealed response.
	///
	/// # Errors
	///
	/// Returns [`ChannelError`] if the response is too short, the secret cannot be exported or
	/// expanded, or the ciphertext fails authentication.
	pub fn open(&self, response: &SealedResponse) -> Result<Zeroizing<Vec<u8>>, ChannelError> {
		let sealed = response.as_ref();
		if sealed.len() <= RESPONSE_NONCE_LEN + AEAD_TAG_LEN {
			return Err(ChannelError::Truncated);
		}
		let (response_nonce, ciphertext) = sealed.split_at(RESPONSE_NONCE_LEN);
		let response_nonce: [u8; RESPONSE_NONCE_LEN] = response_nonce
			.try_into()
			.map_err(|_| ChannelError::Truncated)?;

		let mut secret = Zeroizing::new([0u8; RESPONSE_NONCE_LEN]);
		self.context
			.export(&self.exporter_label, secret.as_mut_slice())
			.map_err(|_| ChannelError::ExportFailed)?;

		let (cipher, nonce) =
			derive_response_aead(&secret, &self.encapsulated_key, &response_nonce)?;

		let plaintext = cipher
			.decrypt(&nonce, ciphertext)
			.map_err(|_| ChannelError::OpenFailed)?;

		Ok(Zeroizing::new(plaintext))
	}
}

/// Seals the one response belonging to a [`Responder::open`] call.
pub struct ResponseSealer {
	secret: ResponseSecret,
	encapsulated_key: [u8; ENCAPSULATED_KEY_LEN],
}

impl ResponseSealer {
	/// Seals one response, per RFC 9458 §4.4.
	///
	/// # Errors
	///
	/// Returns [`ChannelError`] if the key or nonce cannot be expanded, or the AEAD refuses to
	/// seal.
	pub fn seal(
		self,
		plaintext: &[u8],
		rng: &mut impl CryptoRng,
	) -> Result<SealedResponse, ChannelError> {
		let mut response_nonce = [0u8; RESPONSE_NONCE_LEN];
		rng.fill_bytes(&mut response_nonce);

		let (cipher, nonce) =
			derive_response_aead(&self.secret, &self.encapsulated_key, &response_nonce)?;

		let ciphertext = cipher
			.encrypt(&nonce, plaintext)
			.map_err(|_| ChannelError::SealFailed)?;

		let mut sealed = response_nonce.to_vec();
		sealed.extend_from_slice(&ciphertext);

		Ok(SealedResponse(sealed))
	}
}

#[cfg(test)]
mod tests {
	use getrandom::SysRng;
	use hpke::rand_core::UnwrapErr;

	use super::{
		ChannelDomain, ChannelError, Requester, Responder, ResponseOpener, SealedRequest,
		SealedResponse, AEAD_TAG_LEN, ENCAPSULATED_KEY_LEN, EXPORTER_LABEL_SUFFIX,
		RESPONSE_NONCE_LEN,
	};

	const TEST_DOMAIN: ChannelDomain = ChannelDomain::new("pontifex/test", 1);

	fn seal_to(responder: &Responder, plaintext: &[u8]) -> (SealedRequest, ResponseOpener) {
		let requester =
			Requester::new(responder.domain(), responder.public_key()).expect("valid key");
		let mut rng = UnwrapErr(SysRng);
		let (request, opener) = requester
			.seal(plaintext, &mut rng)
			.expect("sealing should succeed");
		(request, opener)
	}

	fn test_rng() -> UnwrapErr<SysRng> {
		UnwrapErr(SysRng)
	}

	#[test]
	fn requester_from_attestation_matches_new() {
		let responder = Responder::generate(TEST_DOMAIN, &mut test_rng());
		let from_attestation = Requester::from_attestation(TEST_DOMAIN, &responder.public_key())
			.expect("should parse");
		let from_new = Requester::new(TEST_DOMAIN, responder.public_key()).expect("should parse");
		assert_eq!(from_attestation, from_new);
	}

	#[test]
	fn rejects_a_non_32_byte_attestation_key() {
		assert_eq!(
			Requester::from_attestation(TEST_DOMAIN, &[0u8; 31]).err(),
			Some(ChannelError::InvalidEncryptionKey)
		);
	}

	#[test]
	fn info_binds_name_version_and_key() {
		let key = [7u8; 32];
		let info = TEST_DOMAIN.info(&key);
		let (name, rest) = info.split_at(TEST_DOMAIN.name().len());
		assert_eq!(name, TEST_DOMAIN.name().as_bytes());
		assert_eq!(rest, [&[TEST_DOMAIN.version()][..], &key[..]].concat());
	}

	#[test]
	fn info_separates_names_versions_and_keys() {
		let key = [7u8; 32];
		let other_name = ChannelDomain::new("pontifex/other", TEST_DOMAIN.version());
		let next_version = ChannelDomain::new(TEST_DOMAIN.name(), TEST_DOMAIN.version() + 1);

		assert_ne!(TEST_DOMAIN.info(&key), other_name.info(&key));
		assert_ne!(TEST_DOMAIN.info(&key), next_version.info(&key));
		assert_ne!(TEST_DOMAIN.info(&key), TEST_DOMAIN.info(&[8u8; 32]));
	}

	#[test]
	fn exporter_label_follows_the_name() {
		assert_eq!(
			TEST_DOMAIN.exporter_label(),
			[TEST_DOMAIN.name().as_bytes(), EXPORTER_LABEL_SUFFIX].concat()
		);
		assert_ne!(
			TEST_DOMAIN.exporter_label(),
			ChannelDomain::new("pontifex/other", 1).exporter_label()
		);
	}

	#[test]
	fn separate_responders_receive_separate_public_keys() {
		assert_ne!(
			Responder::generate(TEST_DOMAIN, &mut test_rng()).public_key(),
			Responder::generate(TEST_DOMAIN, &mut test_rng()).public_key()
		);
	}

	#[test]
	fn public_key_is_stable_for_one_responder() {
		let responder = Responder::generate(TEST_DOMAIN, &mut test_rng());
		assert_eq!(responder.public_key(), responder.public_key());
	}

	#[test]
	fn round_trips_a_request_and_its_sealed_response() {
		let responder = Responder::generate(TEST_DOMAIN, &mut test_rng());
		let (request, opener) = seal_to(&responder, b"request inputs");

		let (plaintext, sealer) = responder.open(&request).expect("should open");
		assert_eq!(&plaintext[..], b"request inputs");

		let response = sealer
			.seal(b"statement", &mut test_rng())
			.expect("sealing should succeed");

		assert_eq!(&*opener.open(&response).unwrap(), b"statement".as_ref());
	}

	#[test]
	fn each_response_draws_a_fresh_nonce() {
		let responder = Responder::generate(TEST_DOMAIN, &mut test_rng());
		let (request, opener) = seal_to(&responder, b"request inputs");

		let (_, first_sealer) = responder.open(&request).expect("should open");
		let (_, second_sealer) = responder.open(&request).expect("should open");
		let first = first_sealer
			.seal(b"statement", &mut test_rng())
			.expect("should seal");
		let second = second_sealer
			.seal(b"statement", &mut test_rng())
			.expect("should seal");

		assert_ne!(
			first.as_ref()[..RESPONSE_NONCE_LEN],
			second.as_ref()[..RESPONSE_NONCE_LEN],
		);
		assert_ne!(
			first.as_ref()[RESPONSE_NONCE_LEN..],
			second.as_ref()[RESPONSE_NONCE_LEN..],
		);
		assert_eq!(&*opener.open(&first).unwrap(), b"statement".as_ref());
		assert_eq!(&*opener.open(&second).unwrap(), b"statement".as_ref());
	}

	#[test]
	fn rejects_a_request_sealed_to_another_boot() {
		let responder = Responder::generate(TEST_DOMAIN, &mut test_rng());
		let other = Responder::generate(TEST_DOMAIN, &mut test_rng());
		let (request, _) = seal_to(&other, b"request inputs");

		assert_eq!(
			responder.open(&request).err(),
			Some(ChannelError::OpenFailed)
		);
	}

	#[test]
	fn rejects_a_request_bound_to_another_channel_version() {
		let responder = Responder::generate(TEST_DOMAIN, &mut test_rng());
		let next_version = ChannelDomain::new(TEST_DOMAIN.name(), TEST_DOMAIN.version() + 1);
		let requester = Requester::new(next_version, responder.public_key()).expect("valid key");
		let (request, _) = requester
			.seal(b"request inputs", &mut test_rng())
			.expect("sealing should succeed");

		assert_eq!(
			responder.open(&request).err(),
			Some(ChannelError::OpenFailed)
		);
	}

	#[test]
	fn rejects_a_request_sealed_under_another_domain_name() {
		let responder = Responder::generate(TEST_DOMAIN, &mut test_rng());
		let other_name = ChannelDomain::new("pontifex/other", TEST_DOMAIN.version());
		let requester = Requester::new(other_name, responder.public_key()).expect("valid key");
		let (request, _) = requester
			.seal(b"request inputs", &mut test_rng())
			.expect("sealing should succeed");

		assert_eq!(
			responder.open(&request).err(),
			Some(ChannelError::OpenFailed)
		);
	}

	#[test]
	fn rejects_a_low_order_encapsulated_key() {
		let responder = Responder::generate(TEST_DOMAIN, &mut test_rng());
		let (request, _) = seal_to(&responder, b"request inputs");
		let mut body = request.into_bytes();
		body[..ENCAPSULATED_KEY_LEN].fill(0);

		assert_eq!(
			responder.open(&SealedRequest(body)).err(),
			Some(ChannelError::InvalidEncapsulatedKey)
		);
	}

	#[test]
	fn rejects_a_truncated_request_body() {
		let responder = Responder::generate(TEST_DOMAIN, &mut test_rng());

		for length in [0, ENCAPSULATED_KEY_LEN, ENCAPSULATED_KEY_LEN + AEAD_TAG_LEN] {
			assert_eq!(
				responder
					.open(&SealedRequest::from_bytes(vec![0u8; length]))
					.err(),
				Some(ChannelError::Truncated),
				"length {length}"
			);
		}
	}

	#[test]
	fn rejects_a_tampered_request_ciphertext() {
		let responder = Responder::generate(TEST_DOMAIN, &mut test_rng());
		let (request, _) = seal_to(&responder, b"request inputs");
		let mut body = request.into_bytes();
		body[ENCAPSULATED_KEY_LEN] ^= 0x01;

		assert_eq!(
			responder.open(&SealedRequest(body)).err(),
			Some(ChannelError::OpenFailed)
		);
	}

	#[test]
	fn rejects_a_truncated_response() {
		let responder = Responder::generate(TEST_DOMAIN, &mut test_rng());

		for length in [0, RESPONSE_NONCE_LEN, RESPONSE_NONCE_LEN + AEAD_TAG_LEN] {
			let (_, opener) = seal_to(&responder, b"request inputs");
			assert_eq!(
				opener
					.open(&SealedResponse::from_bytes(vec![0u8; length]))
					.err(),
				Some(ChannelError::Truncated),
				"length {length}"
			);
		}
	}

	#[test]
	fn a_second_request_to_the_same_key_cannot_open_the_response() {
		let responder = Responder::generate(TEST_DOMAIN, &mut test_rng());
		let (request, _) = seal_to(&responder, b"request inputs");
		let (_, eavesdropper) = seal_to(&responder, b"unrelated");

		let (_, sealer) = responder.open(&request).expect("should open");
		let response = sealer
			.seal(b"statement", &mut test_rng())
			.expect("sealing should succeed");

		assert_eq!(
			eavesdropper.open(&response).err(),
			Some(ChannelError::OpenFailed)
		);
	}

	#[test]
	fn rejects_a_tampered_response_ciphertext() {
		let responder = Responder::generate(TEST_DOMAIN, &mut test_rng());
		let (request, opener) = seal_to(&responder, b"request inputs");
		let (_, sealer) = responder.open(&request).expect("should open");

		let response = sealer
			.seal(b"statement", &mut test_rng())
			.expect("sealing should succeed");
		let mut body = response.into_bytes();
		body[RESPONSE_NONCE_LEN] ^= 0x01;

		assert_eq!(
			opener.open(&SealedResponse(body)).err(),
			Some(ChannelError::OpenFailed)
		);
	}

	#[test]
	fn rejects_a_tampered_response_nonce() {
		let responder = Responder::generate(TEST_DOMAIN, &mut test_rng());
		let (request, opener) = seal_to(&responder, b"request inputs");
		let (_, sealer) = responder.open(&request).expect("should open");

		let response = sealer
			.seal(b"statement", &mut test_rng())
			.expect("sealing should succeed");
		let mut body = response.into_bytes();
		body[0] ^= 0x01;

		assert_eq!(
			opener.open(&SealedResponse(body)).err(),
			Some(ChannelError::OpenFailed)
		);
	}

	#[test]
	fn rejects_an_invalid_encryption_key() {
		// All-zero encodes as a point but yields no valid shared secret at encapsulation.
		let requester = Requester::new(TEST_DOMAIN, [0u8; 32]).expect("all-zero key encodes");
		let result = requester.seal(b"request inputs", &mut test_rng());

		assert_eq!(result.err(), Some(ChannelError::InvalidEncryptionKey));
	}
}

/// Known-answer tests.
///
/// Three layers, each guarding a different failure mode:
///
/// 1. **Official RFC 9180 vector** for this module's exact suite — `mode_base`,
///    DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM — taken from the reference vector set
///    the `hpke` crate ships (`test-vectors/origrfc-5f503c5.json`; the RFC's own appendix has no
///    vector for this AEAD with X25519). Catches a broken build of the suite itself: upstream's
///    vector tests never run in this repository's CI.
/// 2. **Independent HKDF vector** for the response derivation, computed with a stdlib-only
///    Python HMAC implementation that shares no code with the `hkdf` crate. Pins the
///    `enc || response_nonce` salt construction and the `"key"`/`"nonce"` labels.
/// 3. **Deterministic wire vectors** for the full channel under a fixed RNG. Self-generated, so
///    they verify nothing about correctness — they freeze the wire contract (the `info`
///    construction, the exporter label, the suite, framing) so any accidental change fails a
///    test instead of shipping silently.
#[cfg(test)]
mod kat {
	use core::convert::Infallible;

	use hex_literal::hex;
	use hpke::rand_core::{TryCryptoRng, TryRng};

	use super::*;

	/// Yields exactly the queued bytes, in order. Panics when drained, so a test that consumes
	/// more randomness than its vector provides fails loudly instead of diverging silently.
	struct FixedRng(Vec<u8>);

	impl FixedRng {
		fn new(bytes: &[u8]) -> Self {
			Self(bytes.to_vec())
		}
	}

	impl TryRng for FixedRng {
		type Error = Infallible;

		fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
			let mut bytes = [0u8; 4];
			self.try_fill_bytes(&mut bytes)?;
			Ok(u32::from_le_bytes(bytes))
		}

		fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
			let mut bytes = [0u8; 8];
			self.try_fill_bytes(&mut bytes)?;
			Ok(u64::from_le_bytes(bytes))
		}

		fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
			assert!(
				self.0.len() >= dst.len(),
				"FixedRng drained: the test consumed more randomness than its vector provides"
			);
			let rest = self.0.split_off(dst.len());
			dst.copy_from_slice(&self.0);
			self.0 = rest;
			Ok(())
		}
	}

	impl TryCryptoRng for FixedRng {}

	// RFC 9180 reference vector: mode_base, kem_id 0x0020, kdf_id 0x0001, aead_id 0x0002.
	// Source: the `hpke` crate's `test-vectors/origrfc-5f503c5.json`.
	const IKM_E: [u8; 32] =
		hex!("2cd7c601cefb3d42a62b04b7a9041494c06c7843818e0ce28a8f704ae7ab20f9");
	const IKM_R: [u8; 32] =
		hex!("dac33b0e9db1b59dbbea58d59a14e7b5896e9bdf98fad6891e99d1686492b9ee");
	const PK_RM: [u8; 32] =
		hex!("430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c");
	const ENC: [u8; 32] = hex!("6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256");
	/// "Ode on a Grecian Urn"
	const VECTOR_INFO: &[u8] = &hex!("4f6465206f6e2061204772656369616e2055726e");
	/// "Beauty is truth, truth beauty"
	const VECTOR_PT: &[u8] = &hex!("4265617574792069732074727574682c20747275746820626561757479");
	/// "Count-0"
	const VECTOR_AAD: &[u8] = &hex!("436f756e742d30");
	const VECTOR_CT: &[u8] = &hex!(
		"e5d84cd531cfb583096e7cfa9641bd3079cf3a91cda813c52deb5f512be9931980a41de125a925cdad859d5b7a"
	);
	const EXPORT_EMPTY_CONTEXT: [u8; 32] =
		hex!("ded6cffafaea6b812cbf3e241e88332adbc077aca81512914213810ee291770a");
	const EXPORT_TEST_CONTEXT: [u8; 32] =
		hex!("7c5ded445732c14fe09727d29b4251c0fd38455fe8440571e687f0886aac94d2");

	/// Layer 1: the `hpke` crate, built with this crate's feature set, reproduces the official
	/// vector for the exact suite this module pins.
	///
	/// The ephemeral is reproducible because DHKEM's `encap_with_rng` is
	/// `DeriveKeyPair(random(Nsk))`: feeding the RNG the vector's `ikmE` yields the vector's
	/// ephemeral key.
	#[test]
	fn hpke_suite_matches_the_official_vector() {
		// Recipient keypair from ikmR.
		let (sk_r, pk_r) = <Kem as KemTrait>::derive_keypair(&IKM_R);
		assert_eq!(pk_r.to_bytes().as_slice(), PK_RM, "pkRm");

		// Sender: ephemeral from ikmE, then seal the vector's first plaintext.
		let pk_recip = <Kem as KemTrait>::PublicKey::from_bytes(&PK_RM).expect("pkRm decodes");
		let mut rng = FixedRng::new(&IKM_E);
		let (encapped, mut sender) = setup_sender_with_rng::<ChannelAead, Kdf, Kem>(
			&OpModeS::Base,
			&pk_recip,
			VECTOR_INFO,
			&mut rng,
		)
		.expect("sender setup");
		assert_eq!(encapped.to_bytes().as_slice(), ENC, "enc");
		let ciphertext = sender.seal(VECTOR_PT, VECTOR_AAD).expect("seal");
		assert_eq!(ciphertext.as_slice(), VECTOR_CT, "ct[0]");

		// Receiver: open the vector ciphertext.
		let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&ENC).expect("enc decodes");
		let mut receiver =
			setup_receiver::<ChannelAead, Kdf, Kem>(&OpModeR::Base, &sk_r, &encapped, VECTOR_INFO)
				.expect("receiver setup");
		assert_eq!(
			receiver
				.open(VECTOR_CT, VECTOR_AAD)
				.expect("open")
				.as_slice(),
			VECTOR_PT,
			"pt[0]"
		);

		// Exporter, both sides.
		let mut exported = [0u8; 32];
		receiver.export(b"", &mut exported).expect("export");
		assert_eq!(exported, EXPORT_EMPTY_CONTEXT, "export(\"\")");
		sender
			.export(b"TestContext", &mut exported)
			.expect("export");
		assert_eq!(exported, EXPORT_TEST_CONTEXT, "export(\"TestContext\")");
	}

	/// Layer 2: the response `Extract`/`Expand` chain matches a vector computed with a
	/// stdlib-only Python HMAC implementation — independent of the `hkdf` crate.
	///
	/// ```text
	/// prk   = HMAC-SHA256(salt = enc || response_nonce, ikm = secret)
	/// key   = HKDF-Expand(prk, "key", 32)
	/// nonce = HKDF-Expand(prk, "nonce", 12)
	/// ```
	#[test]
	fn response_derivation_matches_an_independent_hkdf() {
		let secret: ResponseSecret =
			Zeroizing::new(core::array::from_fn(|i| u8::try_from(i).unwrap()));
		let encapsulated_key: [u8; ENCAPSULATED_KEY_LEN] =
			core::array::from_fn(|i| u8::try_from(0x20 + i).unwrap());
		let response_nonce: [u8; RESPONSE_NONCE_LEN] =
			core::array::from_fn(|i| u8::try_from(0x40 + i).unwrap());

		let (key, nonce) = derive_response_key_nonce(&secret, &encapsulated_key, &response_nonce)
			.expect("derivation");

		assert_eq!(
			*key,
			hex!("40ec528847cd4e928449f2ed1a70a7d1e8ee317d5e900424fc1dd5b0475b97f7")
		);
		assert_eq!(nonce, hex!("f8b0ce9466f27aa6243c65f9"));
	}

	const PINNED_DOMAIN: ChannelDomain = ChannelDomain::new("pontifex/kat", 1);

	/// Layer 3 (regression, self-generated): the full channel under a fixed RNG produces these
	/// exact wire bytes. Freezes the `info` construction, the exporter label, the suite, and
	/// framing — any of them changing alters the bytes and fails this test, which is the point:
	/// the wire contract only moves together with the domain's version.
	#[test]
	fn wire_bytes_are_frozen_under_a_fixed_rng() {
		let responder = Responder::generate(PINNED_DOMAIN, &mut FixedRng::new(&[0x11; 32]));
		assert_eq!(responder.public_key(), PINNED_PUBLIC_KEY, "responder key");

		let requester = Requester::new(PINNED_DOMAIN, responder.public_key()).expect("valid key");
		let (request, opener) = requester
			.seal(b"request", &mut FixedRng::new(&[0x22; 32]))
			.expect("seal");
		assert_eq!(request.as_ref(), PINNED_REQUEST, "request bytes");

		let (plaintext, sealer) = responder
			.open(&SealedRequest::from_bytes(PINNED_REQUEST.to_vec()))
			.expect("open");
		assert_eq!(&plaintext[..], b"request");

		let response = sealer
			.seal(b"response", &mut FixedRng::new(&[0x33; 32]))
			.expect("seal response");
		assert_eq!(response.as_ref(), PINNED_RESPONSE, "response bytes");

		assert_eq!(
			&*opener
				.open(&SealedResponse::from_bytes(PINNED_RESPONSE.to_vec()))
				.expect("open response"),
			b"response".as_ref()
		);
	}

	const PINNED_PUBLIC_KEY: [u8; 32] =
		hex!("1a239249ea74403babc01f32df9931a16f71ac8972c461d69fed15640e310639");
	const PINNED_REQUEST: [u8; 55] = hex!(
		"e3b9708aaa21a7f1e62a95ee28d1e5d60b0fceed6c68599013a54b318e9e0b15"
		"87b0e1436d37cefc7e16eaad8c44b8ed52167a1590ea1d"
	);
	const PINNED_RESPONSE: [u8; 56] = hex!(
		// The leading 32 bytes are the response_nonce exactly as drawn from the fixed RNG,
		// confirming the `response_nonce || ciphertext` layout of RFC 9458 section 4.4 step 7.
		"3333333333333333333333333333333333333333333333333333333333333333"
		"2e6fd9ad62e341764bf330365541c95455743e6f683bda87"
	);
}
