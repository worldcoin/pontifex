use aws_sdk_kms::config::SharedCredentialsProvider;
use aws_types::SdkConfig;
use tokio_vsock::VsockAddr;

use crate::utils::kms::vsock_proxy;

pub const VSOCK_PROXY_CID: u32 = 3;

pub struct Credentials {
	access_key_id: String,
	secret_access_key: String,
	session_token: Option<String>,
}

impl Credentials {
	pub fn new(
		access_key_id: impl Into<String>,
		secret_access_key: impl Into<String>,
		session_token: Option<String>,
	) -> Self {
		Self {
			session_token,
			access_key_id: access_key_id.into(),
			secret_access_key: secret_access_key.into(),
		}
	}
}

#[must_use]
pub fn client(
	config: &SdkConfig,
	credentials: Credentials,
	vsock_proxy_port: u32,
) -> aws_sdk_kms::Client {
	let builder = config
		.to_builder()
		.credentials_provider(SharedCredentialsProvider::new(
			aws_sdk_kms::config::Credentials::new(
				credentials.access_key_id,
				credentials.secret_access_key,
				credentials.session_token,
				None,
				"SDK",
			),
		))
		.http_client(vsock_proxy(VsockAddr::new(
			VSOCK_PROXY_CID,
			vsock_proxy_port,
		)))
		.build();

	aws_sdk_kms::Client::new(&builder)
}
