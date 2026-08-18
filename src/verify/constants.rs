//! Constants used when verifying AWS Nitro Enclave attestation documents.

use crate::nsm::Digest;

/// AWS Nitro Root Certificate (G1), in DER form.
///
/// Source: <https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip>
/// Stored at `src/verify/aws_nitro_root_g1.der`
pub const AWS_NITRO_ROOT_CERT: &[u8] = include_bytes!("aws_nitro_root_g1.der");

/// Maximum age for attestation documents (in milliseconds)
pub const MAX_ATTESTATION_AGE_MILLISECONDS: u64 = 3 * 60 * 60 * 1000; // 3 hours

/// Get the expected PCR length depending on the hashing algorithm used
/// As of right now, only SHA-384 is used
/// More info: <https://docs.aws.amazon.com/enclaves/latest/user/set-up-attestation.html>
#[must_use]
pub const fn get_expected_pcr_length(digest: Digest) -> usize {
	match digest {
		Digest::SHA384 => 48,
		Digest::SHA256 => 32,
		Digest::SHA512 => 64,
	}
}
