//! Wire format for temporary AWS credentials sent from the host to its enclave.
//!
//! One frame per connection: a big-endian `u32` length, then a `MessagePack` map. The length is
//! capped before anything is allocated. Errors never carry credential bytes.

use std::{
	io,
	time::{Duration, SystemTime, UNIX_EPOCH},
};

use aws_credential_types::Credentials;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const VERSION: u8 = 1;
const MAX_FRAME: usize = 16 * 1024;
const MAX_KEY_LEN: usize = 128;
const MAX_TOKEN_LEN: usize = 12 * 1024;
/// Credentials closer than this to expiring are not worth sending.
pub const MIN_REMAINING_VALIDITY: Duration = Duration::from_secs(60);

/// Why a frame was not sent or not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
	/// The length prefix is zero or above the frame cap.
	#[error("credential frame length {0} is outside 1..={MAX_FRAME}")]
	Length(usize),
	/// The frame does not decode.
	#[error("credential frame is malformed")]
	Malformed,
	/// The frame was written by an incompatible version.
	#[error("unsupported credential frame version {0}")]
	Version(u8),
	/// The credentials have no session token or no expiry, so they are not temporary.
	#[error("credentials are not temporary")]
	NotTemporary,
	/// The credentials expire within [`MIN_REMAINING_VALIDITY`].
	#[error("credentials expire too soon")]
	NearExpiry,
	/// A field is empty or larger than any AWS credential.
	#[error("credential field has an invalid size")]
	FieldSize,
}

impl From<FrameError> for io::Error {
	fn from(error: FrameError) -> Self {
		Self::new(io::ErrorKind::InvalidData, error)
	}
}

#[derive(Serialize, Deserialize)]
struct WireCredentials {
	version: u8,
	access_key_id: String,
	secret_access_key: String,
	session_token: String,
	expires_at: u64,
}

impl Drop for WireCredentials {
	fn drop(&mut self) {
		self.access_key_id.zeroize();
		self.secret_access_key.zeroize();
		self.session_token.zeroize();
	}
}

impl WireCredentials {
	fn validated_expiry(&self) -> Result<SystemTime, FrameError> {
		if self.version != VERSION {
			return Err(FrameError::Version(self.version));
		}
		let sizes_valid = (1..=MAX_KEY_LEN).contains(&self.access_key_id.len())
			&& (1..=MAX_KEY_LEN).contains(&self.secret_access_key.len())
			&& (1..=MAX_TOKEN_LEN).contains(&self.session_token.len());
		if !sizes_valid {
			return Err(FrameError::FieldSize);
		}
		let expiry = UNIX_EPOCH
			.checked_add(Duration::from_secs(self.expires_at))
			.ok_or(FrameError::Malformed)?;
		let remaining = expiry.duration_since(SystemTime::now()).unwrap_or_default();
		if remaining < MIN_REMAINING_VALIDITY {
			return Err(FrameError::NearExpiry);
		}

		Ok(expiry)
	}
}

/// Writes one frame. The caller bounds the time this takes.
///
/// # Errors
///
/// [`FrameError`] (as `InvalidData`) for credentials that are not temporary or expire too soon,
/// and any I/O failure.
#[cfg(any(feature = "credentials", test))]
pub async fn write(
	stream: &mut (impl tokio::io::AsyncWrite + Unpin),
	credentials: &Credentials,
) -> io::Result<()> {
	use tokio::io::AsyncWriteExt;

	let expiry = credentials.expiry().ok_or(FrameError::NotTemporary)?;
	let wire = WireCredentials {
		version: VERSION,
		access_key_id: credentials.access_key_id().to_owned(),
		secret_access_key: credentials.secret_access_key().to_owned(),
		session_token: credentials
			.session_token()
			.ok_or(FrameError::NotTemporary)?
			.to_owned(),
		expires_at: expiry
			.duration_since(UNIX_EPOCH)
			.map_err(|_| FrameError::NearExpiry)?
			.as_secs(),
	};
	wire.validated_expiry()?;
	let bytes = Zeroizing::new(rmp_serde::to_vec_named(&wire).map_err(|_| FrameError::Malformed)?);
	let length = u32::try_from(bytes.len())
		.ok()
		.filter(|&length| length as usize <= MAX_FRAME)
		.ok_or(FrameError::Length(bytes.len()))?;

	stream.write_u32(length).await?;
	stream.write_all(&bytes).await?;
	stream.shutdown().await
}

/// Reads one frame. The caller bounds the time this takes.
///
/// # Errors
///
/// [`FrameError`] (as `InvalidData`) for an oversized, malformed, unsupported or expiring frame,
/// and any I/O failure.
#[cfg(any(feature = "kms", test))]
pub async fn read(
	stream: &mut (impl tokio::io::AsyncRead + Unpin),
	provider_name: &'static str,
) -> io::Result<Credentials> {
	use tokio::io::AsyncReadExt;

	let length = stream.read_u32().await? as usize;
	if length == 0 || length > MAX_FRAME {
		return Err(FrameError::Length(length).into());
	}
	let mut bytes = Zeroizing::new(vec![0; length]);
	stream.read_exact(&mut bytes).await?;
	let wire: WireCredentials = rmp_serde::from_slice(&bytes).map_err(|_| FrameError::Malformed)?;
	let expiry = wire.validated_expiry()?;

	Ok(Credentials::new(
		&wire.access_key_id,
		&wire.secret_access_key,
		Some(wire.session_token.clone()),
		Some(expiry),
		provider_name,
	))
}

#[cfg(test)]
mod tests {
	use std::{
		io,
		time::{Duration, SystemTime, UNIX_EPOCH},
	};

	use aws_credential_types::Credentials;
	use serde::Serialize;

	use super::{FrameError, MAX_FRAME, VERSION, WireCredentials, read, write};

	fn temporary(valid_for: Duration) -> Credentials {
		Credentials::new(
			"synthetic-id",
			"synthetic-secret",
			Some("synthetic-token".into()),
			Some(SystemTime::now() + valid_for),
			"test",
		)
	}

	fn frame_error(error: &io::Error) -> Option<FrameError> {
		error.get_ref()?.downcast_ref::<FrameError>().copied()
	}

	async fn read_bytes(payload: &[u8]) -> io::Result<Credentials> {
		let mut framed = u32::try_from(payload.len()).unwrap().to_be_bytes().to_vec();
		framed.extend_from_slice(payload);

		read(&mut framed.as_slice(), "test").await
	}

	fn encoded(wire: &impl Serialize) -> Vec<u8> {
		rmp_serde::to_vec_named(wire).unwrap()
	}

	fn wire_credentials(expires_in: Duration) -> WireCredentials {
		WireCredentials {
			version: VERSION,
			access_key_id: "id".into(),
			secret_access_key: "secret".into(),
			session_token: "token".into(),
			expires_at: (SystemTime::now() + expires_in)
				.duration_since(UNIX_EPOCH)
				.unwrap()
				.as_secs(),
		}
	}

	#[tokio::test]
	async fn temporary_credentials_round_trip() {
		let (mut host, mut enclave) = tokio::io::duplex(MAX_FRAME);
		let sent = temporary(Duration::from_secs(3600));

		write(&mut host, &sent).await.unwrap();
		let received = read(&mut enclave, "parent").await.unwrap();

		assert_eq!(received.access_key_id(), sent.access_key_id());
		assert_eq!(received.secret_access_key(), sent.secret_access_key());
		assert_eq!(received.session_token(), sent.session_token());
		let seconds = |credentials: &Credentials| {
			credentials
				.expiry()
				.unwrap()
				.duration_since(UNIX_EPOCH)
				.unwrap()
				.as_secs()
		};
		assert_eq!(seconds(&received), seconds(&sent));
	}

	#[tokio::test]
	async fn static_or_expiring_credentials_are_not_sent() {
		let without_token = Credentials::new(
			"id",
			"secret",
			None,
			Some(SystemTime::now() + Duration::from_secs(3600)),
			"test",
		);
		let without_expiry = Credentials::new("id", "secret", Some("token".into()), None, "test");
		let cases = [
			(without_token, FrameError::NotTemporary),
			(without_expiry, FrameError::NotTemporary),
			(temporary(Duration::from_secs(30)), FrameError::NearExpiry),
		];

		for (credentials, expected) in cases {
			let error = write(&mut tokio::io::sink(), &credentials)
				.await
				.unwrap_err();
			assert_eq!(frame_error(&error), Some(expected));
		}
	}

	#[tokio::test]
	async fn the_length_is_checked_before_allocating() {
		for length in [0, 16 * 1024 + 1, u32::MAX] {
			let error = read(&mut length.to_be_bytes().as_slice(), "test")
				.await
				.unwrap_err();
			assert_eq!(
				frame_error(&error),
				Some(FrameError::Length(length as usize))
			);
		}
	}

	#[tokio::test]
	async fn invalid_frames_are_rejected_without_echoing_their_contents() {
		let mut wrong_version = wire_credentials(Duration::from_secs(3600));
		wrong_version.version = 2;
		let mut empty_secret = wire_credentials(Duration::from_secs(3600));
		empty_secret.secret_access_key.clear();
		let mut far_future = wire_credentials(Duration::from_secs(3600));
		far_future.expires_at = u64::MAX;
		let cases = [
			(b"sensitive-garbage".to_vec(), FrameError::Malformed),
			(encoded(&wrong_version), FrameError::Version(2)),
			(encoded(&empty_secret), FrameError::FieldSize),
			(
				encoded(&wire_credentials(Duration::from_secs(30))),
				FrameError::NearExpiry,
			),
			(encoded(&far_future), FrameError::Malformed),
		];

		for (payload, expected) in cases {
			let error = read_bytes(&payload).await.unwrap_err();
			assert_eq!(frame_error(&error), Some(expected));
			assert!(!format!("{error:?}").contains("sensitive"));
			assert!(!format!("{error:?}").contains("secret"));
		}
	}
}
