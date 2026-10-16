//! Temporary AWS credentials, served by the host to its enclave as a Pontifex route.
//!
//! The enclave has no credentials of its own. Its [`crate::kms`] client signs with the host's
//! temporary workload credentials: `kms::ParentCredentials` sends [`GetCredentials`] to the host's
//! `router` and the SDK asks again before they expire. Credentials authorize requests; they
//! cannot redirect them, and the host already holds them.
//!
//! ```rust,ignore
//! // Host. Answers only `enclave_cid`: vsock is not namespaced, so other pods could ask too.
//! credentials::router(provider, enclave_cid, |result| record_metric(result))
//!     .serve(CREDENTIALS_PORT)
//!     .await?;
//! ```

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_credential_types::Credentials;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::Request;

/// Credentials closer than this to expiring are refused.
pub const MIN_REMAINING_VALIDITY: Duration = Duration::from_secs(60);
const MAX_KEY_LEN: usize = 128;
const MAX_TOKEN_LEN: usize = 12 * 1024;

/// Asks the host for its current temporary credentials.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GetCredentials;

impl Request for GetCredentials {
	const ROUTE_ID: &'static str = "aws_credentials_v1";
	type Response = Result<WireCredentials, CredentialsUnavailable>;
}

/// Temporary credentials as sent to the enclave. Zeroized on drop; has no `Debug`.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct WireCredentials {
	access_key_id: String,
	secret_access_key: String,
	session_token: String,
	expires_at: u64,
}

/// Why credentials were refused. Never contains credential bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum InvalidCredentials {
	/// No session token or no expiry, so they are not temporary.
	#[error("credentials are not temporary")]
	NotTemporary,
	/// They expire within [`MIN_REMAINING_VALIDITY`].
	#[error("credentials expire too soon")]
	NearExpiry,
	/// A field is empty or larger than any AWS credential.
	#[error("credential field has an invalid size")]
	FieldSize,
	/// The expiry is not a representable time.
	#[error("credential expiry is invalid")]
	InvalidExpiry,
}

/// Why the host could not serve credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum CredentialsUnavailable {
	/// The host's credential provider failed.
	#[error("the host's credential provider failed")]
	ProviderFailed,
	/// The host's credential provider took too long.
	#[error("the host's credential provider timed out")]
	TimedOut,
	/// The provider returned credentials that are never sent.
	#[error(transparent)]
	Invalid(#[from] InvalidCredentials),
}

impl WireCredentials {
	fn validated_expiry(&self) -> Result<SystemTime, InvalidCredentials> {
		let sizes_valid = (1..=MAX_KEY_LEN).contains(&self.access_key_id.len())
			&& (1..=MAX_KEY_LEN).contains(&self.secret_access_key.len())
			&& (1..=MAX_TOKEN_LEN).contains(&self.session_token.len());
		if !sizes_valid {
			return Err(InvalidCredentials::FieldSize);
		}
		let expiry = UNIX_EPOCH
			.checked_add(Duration::from_secs(self.expires_at))
			.ok_or(InvalidCredentials::InvalidExpiry)?;
		let remaining = expiry.duration_since(SystemTime::now()).unwrap_or_default();
		if remaining < MIN_REMAINING_VALIDITY {
			return Err(InvalidCredentials::NearExpiry);
		}

		Ok(expiry)
	}

	/// Validates received credentials and converts them for the AWS SDK.
	///
	/// # Errors
	///
	/// [`InvalidCredentials`] for a bad field size or credentials that expire too soon.
	pub fn into_credentials(
		self,
		provider_name: &'static str,
	) -> Result<Credentials, InvalidCredentials> {
		let expiry = self.validated_expiry()?;

		Ok(Credentials::new(
			&self.access_key_id,
			&self.secret_access_key,
			Some(self.session_token.clone()),
			Some(expiry),
			provider_name,
		))
	}
}

impl TryFrom<&Credentials> for WireCredentials {
	type Error = InvalidCredentials;

	fn try_from(credentials: &Credentials) -> Result<Self, InvalidCredentials> {
		let expiry = credentials
			.expiry()
			.ok_or(InvalidCredentials::NotTemporary)?;
		let wire = Self {
			access_key_id: credentials.access_key_id().to_owned(),
			secret_access_key: credentials.secret_access_key().to_owned(),
			session_token: credentials
				.session_token()
				.ok_or(InvalidCredentials::NotTemporary)?
				.to_owned(),
			expires_at: expiry
				.duration_since(UNIX_EPOCH)
				.map_err(|_| InvalidCredentials::NearExpiry)?
				.as_secs(),
		};
		wire.validated_expiry()?;

		Ok(wire)
	}
}

#[cfg(feature = "credentials")]
pub use host::{PROVIDER_TIMEOUT, router};

#[cfg(feature = "credentials")]
mod host {
	use std::{sync::Arc, time::Duration};

	use aws_credential_types::provider::{ProvideCredentials, SharedCredentialsProvider};
	use aws_smithy_types::error::display::DisplayErrorContext;

	use super::{CredentialsUnavailable, GetCredentials, WireCredentials};
	use crate::Router;

	/// Bounds one provider call, below the enclave's 3 second fetch deadline.
	pub const PROVIDER_TIMEOUT: Duration = Duration::from_secs(2);

	struct State<F> {
		provider: SharedCredentialsProvider,
		on_result: F,
	}

	/// A router answering [`GetCredentials`] from `provider`, only for `enclave_cid`.
	///
	/// `on_result` runs once per request, for metrics; failures are also logged at `warn`,
	/// without credential material.
	pub fn router<F>(
		provider: SharedCredentialsProvider,
		enclave_cid: u32,
		on_result: F,
	) -> Router<impl Clone + Send + Sync + 'static>
	where
		F: Fn(Result<(), CredentialsUnavailable>) + Send + Sync + 'static,
	{
		Router::with_state(Arc::new(State {
			provider,
			on_result,
		}))
		.route::<GetCredentials, _, _>(|state, _| async move { handle(&state).await })
		.allowed_cid(enclave_cid)
	}

	async fn handle<F>(state: &State<F>) -> Result<WireCredentials, CredentialsUnavailable>
	where
		F: Fn(Result<(), CredentialsUnavailable>) + Sync,
	{
		let result = fetch(&state.provider).await;
		if let Err(error) = &result {
			tracing::warn!(%error, "failed to serve credentials to the enclave");
		}
		(state.on_result)(result.as_ref().map(|_| ()).map_err(|error| *error));

		result
	}

	async fn fetch(
		provider: &SharedCredentialsProvider,
	) -> Result<WireCredentials, CredentialsUnavailable> {
		let credentials = tokio::time::timeout(PROVIDER_TIMEOUT, provider.provide_credentials())
			.await
			.map_err(|_| CredentialsUnavailable::TimedOut)?
			.map_err(|error| {
				tracing::warn!(error = %DisplayErrorContext(&error), "workload credential provider failed");
				CredentialsUnavailable::ProviderFailed
			})?;

		Ok(WireCredentials::try_from(&credentials)?)
	}

	#[cfg(test)]
	mod tests {
		use std::{
			sync::{Arc, Mutex},
			time::{Duration, SystemTime},
		};

		use aws_credential_types::{
			Credentials,
			provider::{
				ProvideCredentials, SharedCredentialsProvider, error::CredentialsError, future,
			},
		};

		use super::{State, handle};
		use crate::credentials::{CredentialsUnavailable, InvalidCredentials};

		type Seen = Vec<Result<(), CredentialsUnavailable>>;

		#[derive(Debug)]
		struct Failing;

		impl ProvideCredentials for Failing {
			fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
			where
				Self: 'a,
			{
				future::ProvideCredentials::ready(Err(CredentialsError::not_loaded_no_source()))
			}
		}

		#[derive(Debug)]
		struct Hanging;

		impl ProvideCredentials for Hanging {
			fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
			where
				Self: 'a,
			{
				future::ProvideCredentials::new(std::future::pending())
			}
		}

		/// Serves one request; returns the response and what `on_result` saw.
		async fn serve_one(
			provider: impl ProvideCredentials + 'static,
		) -> (Result<(), CredentialsUnavailable>, Seen) {
			let seen = Arc::new(Mutex::new(Vec::new()));
			let sink = Arc::clone(&seen);
			let state = State {
				provider: SharedCredentialsProvider::new(provider),
				on_result: move |result| sink.lock().unwrap().push(result),
			};

			let response = handle(&state).await.map(|_| ());
			let seen = seen.lock().unwrap().clone();
			(response, seen)
		}

		#[tokio::test]
		async fn temporary_credentials_are_served() {
			let provider = Credentials::new(
				"synthetic-id",
				"synthetic-secret",
				Some("synthetic-token".into()),
				Some(SystemTime::now() + Duration::from_secs(3600)),
				"test",
			);

			assert_eq!(serve_one(provider).await, (Ok(()), vec![Ok(())]));
		}

		#[tokio::test]
		async fn a_failing_provider_is_answered_and_reported() {
			let expected = Err(CredentialsUnavailable::ProviderFailed);

			assert_eq!(serve_one(Failing).await, (expected, vec![expected]));
		}

		#[tokio::test]
		async fn static_credentials_are_refused_and_reported() {
			let expected = Err(CredentialsUnavailable::Invalid(
				InvalidCredentials::NotTemporary,
			));

			assert_eq!(
				serve_one(Credentials::for_tests()).await,
				(expected, vec![expected])
			);
		}

		#[test]
		fn the_router_answers_only_the_enclave() {
			let router = super::router(
				SharedCredentialsProvider::new(Credentials::for_tests()),
				16,
				|_| {},
			);

			assert!(router.admits(16));
			for stranger in [1, 2, 3, 17] {
				assert!(!router.admits(stranger));
			}
		}

		#[tokio::test(start_paused = true)]
		async fn a_hanging_provider_times_out() {
			let expected = Err(CredentialsUnavailable::TimedOut);

			assert_eq!(serve_one(Hanging).await, (expected, vec![expected]));
		}
	}
}

#[cfg(test)]
mod tests {
	use std::time::{Duration, SystemTime, UNIX_EPOCH};

	use aws_credential_types::Credentials;

	use super::{CredentialsUnavailable, GetCredentials, InvalidCredentials, WireCredentials};
	use crate::Request;

	type Response = <GetCredentials as Request>::Response;

	fn temporary(valid_for: Duration) -> Credentials {
		Credentials::new(
			"synthetic-id",
			"synthetic-secret",
			Some("synthetic-token".into()),
			Some(SystemTime::now() + valid_for),
			"test",
		)
	}

	fn wire_credentials() -> WireCredentials {
		WireCredentials::try_from(&temporary(Duration::from_secs(3600))).unwrap()
	}

	/// Encodes and decodes a response as the router and `send` do.
	fn over_the_wire(response: &Response) -> Response {
		rmp_serde::from_slice(&rmp_serde::to_vec(response).unwrap()).unwrap()
	}

	#[test]
	fn temporary_credentials_round_trip() {
		let sent = temporary(Duration::from_secs(3600));

		let received = over_the_wire(&Ok(WireCredentials::try_from(&sent).unwrap()))
			.unwrap()
			.into_credentials("parent")
			.unwrap();

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

	#[test]
	fn the_reason_for_a_refusal_reaches_the_enclave() {
		let refused: Response = Err(CredentialsUnavailable::Invalid(
			InvalidCredentials::NearExpiry,
		));

		assert_eq!(over_the_wire(&refused).err(), refused.err());
	}

	#[test]
	fn static_or_expiring_credentials_are_not_sent() {
		let without_token = Credentials::new(
			"id",
			"secret",
			None,
			Some(SystemTime::now() + Duration::from_secs(3600)),
			"test",
		);
		let without_expiry = Credentials::new("id", "secret", Some("token".into()), None, "test");
		let cases = [
			(without_token, InvalidCredentials::NotTemporary),
			(without_expiry, InvalidCredentials::NotTemporary),
			(
				temporary(Duration::from_secs(30)),
				InvalidCredentials::NearExpiry,
			),
		];

		for (credentials, expected) in cases {
			assert_eq!(
				WireCredentials::try_from(&credentials).err(),
				Some(expected)
			);
		}
	}

	#[test]
	fn invalid_received_credentials_are_rejected() {
		let mut empty_secret = wire_credentials();
		empty_secret.secret_access_key.clear();
		let mut far_future = wire_credentials();
		far_future.expires_at = u64::MAX;
		let mut expired = wire_credentials();
		expired.expires_at = 0;
		let cases = [
			(empty_secret, InvalidCredentials::FieldSize),
			(far_future, InvalidCredentials::InvalidExpiry),
			(expired, InvalidCredentials::NearExpiry),
		];

		for (wire, expected) in cases {
			assert_eq!(wire.into_credentials("parent").err(), Some(expected));
		}
	}
}
