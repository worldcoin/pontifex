use serde::{Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub use crate::utils::CodingKey;
use crate::utils::Stream;

/// Details about a connection.
#[derive(Debug, Clone, Copy)]
pub struct ConnectionDetails {
    /// The CID of the connection.
    pub cid: u32,
    /// The port of the connection.
    pub port: u32,
}

impl ConnectionDetails {
    /// Create a new `ConnectionDetails` instance.
    #[must_use]
    pub const fn new(cid: u32, port: u32) -> Self {
        Self { cid, port }
    }
}

/// Errors that can occur when sending a request.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to connect to the enclave.
    #[error("connection failed: {0}")]
    Connection(io::Error),
    /// Failed to encode the request payload.
    #[error("encoding failed: {0}")]
    Encoding(rmp_serde::encode::Error),
    /// Failed to decode the response payload.
    #[error("decoding failed: {0}")]
    Decoding(rmp_serde::decode::Error),
    /// Failed to send the request.
    #[error("failed to write {0}: {1}")]
    Writing(CodingKey, io::Error),
    /// Failed to receive the response.
    #[error("failed to read {0}: {1}")]
    Reading(CodingKey, io::Error),
}

/// Send a request to the enclave and receive a response.
///
/// # Errors
///
/// - If the connection fails.
/// - If the request fails to be encoded.
/// - If the response fails to be decoded.
/// - If the request fails to be sent.
/// - If the response fails to be received.
pub async fn send<Req, Res>(connection: ConnectionDetails, payload: &Req) -> Result<Res, Error>
where
    Req: Serialize + Sync,
    Res: for<'de> Deserialize<'de>,
{
    let mut stream = Stream::connect(connection.cid, connection.port)
        .await
        .map_err(Error::Connection)?;

    tracing::debug!("established connection to enclave");

    let request = rmp_serde::to_vec(payload).map_err(Error::Encoding)?;

    tracing::debug!(payload =? request, "encoded request payload");

    stream
        .write_u64(request.len() as u64)
        .await
        .map_err(|e| Error::Writing(CodingKey::Length, e))?;

    tracing::debug!(length = request.len(), "sent request length");

    stream
        .write_all(&request)
        .await
        .map_err(|e| Error::Writing(CodingKey::Payload, e))?;

    tracing::debug!(payload =? request, "sent encoded request payload");

    let len = stream
        .read_u64()
        .await
        .map_err(|e| Error::Reading(CodingKey::Length, e))?;

    tracing::debug!(length = len, "received response length");

    let response = stream
        .read_exact(len)
        .await
        .map_err(|e| Error::Reading(CodingKey::Payload, e))?;

    tracing::debug!(payload =? response, "received encoded response payload");

    rmp_serde::from_slice(&response).map_err(Error::Decoding)
}
