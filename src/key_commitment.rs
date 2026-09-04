//! A short, attestable stand-in for a public key.
//!
//! The NSM caps the attestation document's `public_key` field at 1024 bytes, which a 1216-byte
//! X-Wing encapsulation key does not fit. Attesting a digest instead keeps the binding inside the
//! signed document while staying well under every field limit.

use sha2::{Digest as _, Sha256};

/// Domain separator, versioned so a future commitment format cannot be confused with this one.
const DOMAIN: &[u8] = b"pontifex/public-key-commitment/v1\0";

/// Returns the 32-byte commitment to `public_key`.
///
/// Computes `SHA-256(DOMAIN || public_key)` over the raw key bytes, before any transport
/// encoding. The key's encoding and algorithm are not validated — this commits to bytes.
#[must_use]
pub fn public_key_commitment(public_key: &[u8]) -> [u8; 32] {
	Sha256::new()
		.chain_update(DOMAIN)
		.chain_update(public_key)
		.finalize()
		.into()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn a_commitment_is_stable() {
		// Pinned so a change to the domain separator or hash is a deliberate, visible break.
		assert_eq!(
			public_key_commitment(b"key"),
			hex_literal::hex!("77634addf9ae031e3d621410d643d1f13b7d426876627b53d89ea0f7bba71cfb")
		);
	}

	#[test]
	fn distinct_keys_commit_differently() {
		assert_ne!(
			public_key_commitment(b"key-a"),
			public_key_commitment(b"key-b")
		);
	}

	/// The separator must be part of the preimage, or a commitment could be replayed as a digest
	/// computed for some other purpose.
	#[test]
	fn the_domain_separator_is_covered() {
		assert_ne!(
			public_key_commitment(b"key"),
			Sha256::digest(b"key").as_slice()
		);
	}
}
