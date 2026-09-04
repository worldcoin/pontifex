use sha2::{Digest as _, Sha256};

/// Returns the 32-byte public key commitment.
///
/// Computes `SHA-256(b"pontifex/public-key-commitment/v1\0" || public_key)`.
/// The prefix identifies the purpose and version of the commitment format.
/// Use the exact key bytes before transport encoding; key encoding and algorithm
/// are not validated.
#[must_use]
pub fn public_key_commitment(public_key: &[u8]) -> [u8; 32] {
	Sha256::new()
		.chain_update(b"pontifex/public-key-commitment/v1\0")
		.chain_update(public_key)
		.finalize()
		.into()
}
