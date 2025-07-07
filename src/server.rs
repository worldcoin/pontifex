use serde::{Deserialize, Serialize};
use std::{io, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_vsock::{VsockAddr, VsockListener};

pub use crate::utils::CodingKey;
use crate::utils::Stream;

const VMADDR_CID_ANY: u32 = 0xFFFF_FFFF;

/// Errors that can occur when running the server.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to bind to vsock address.
    #[error("Failed to bind to vsock address: {0}")]
    Bind(io::Error),
    /// Failed to connect to NSM.
    #[cfg(feature = "nsm")]
    #[error("Failed to connect to NSM: {0}")]
    NsmConnect(io::Error),
    /// Failed to encode the request payload.
    #[error("encoding failed: {0}")]
    Encoding(rmp_serde::encode::Error),
    /// Failed to decode the request payload.
    #[error("decoding failed: {0}")]
    Decoding(rmp_serde::decode::Error),
    /// Failed to write a payload to the stream.
    #[error("failed to write {0}: {1}")]
    Writing(CodingKey, io::Error),
    /// Failed to read a payload from the stream.
    #[error("failed to read {0}: {1}")]
    Reading(CodingKey, io::Error),
}

/// Listen and process incoming connections on the given port.
///
/// The `process` function is called for each incoming connection and should return a response.
///
/// # Errors
///
/// Errors are returned if the server fails to bind to the given port.
/// Errors will be logged (but not returned) if the server fails to accept a connection or if processing fails.
pub async fn listen<Req, Res, Fut>(
    port: u32,
    process: impl Fn(Req) -> Fut + Send + Sync + 'static,
) -> Result<(), Error>
where
    Res: Serialize + Send,
    Req: for<'de> Deserialize<'de>,
    Fut: Future<Output = Res> + Send,
{
    let listener =
        VsockListener::bind(VsockAddr::new(VMADDR_CID_ANY, port)).map_err(Error::Bind)?;

    tracing::info!("started listening on port {port}");

    // Initialize the secure module global if the feature is enabled.
    #[cfg(feature = "nsm")]
    {
        match crate::SecureModule::connect() {
            Ok(nsm) => {
                crate::nsm::SECURE_MODULE_GLOBAL
                    .get_or_init(|| async { nsm })
                    .await
            }
            Err(e) => {
                return Err(Error::NsmConnect(e));
            }
        };
    }

    let process = Arc::new(process);
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => Stream::new(stream),
            Err(e) => {
                tracing::debug!("failed to accept connection: {e}");
                continue;
            }
        };

        tracing::trace!("spawning new task to handle connection");

        let process = process.clone();
        tokio::spawn(async move {
            match process_request(stream, process).await {
                Ok(()) => tracing::debug!("request processed successfully"),
                Err(e) => tracing::error!("failed to process request: {e}"),
            }
        });
    }
}

async fn process_request<Req, Res, Fut>(
    mut stream: Stream,
    process: Arc<impl Fn(Req) -> Fut + Send + Sync>,
) -> Result<(), Error>
where
    Res: Serialize + Send,
    Req: for<'de> Deserialize<'de>,
    Fut: Future<Output = Res> + Send,
{
    let len = stream
        .read_u64()
        .await
        .map_err(|e| Error::Reading(CodingKey::Length, e))?;
    let payload = stream
        .read_exact(len)
        .await
        .map_err(|e| Error::Reading(CodingKey::Payload, e))?;

    let request = rmp_serde::from_slice(&payload).map_err(Error::Decoding)?;

    let response = process(request).await;

    let payload = rmp_serde::to_vec(&response).map_err(Error::Encoding)?;
    stream
        .write_u64(payload.len() as u64)
        .await
        .map_err(|e| Error::Writing(CodingKey::Length, e))?;

    stream
        .write_all(&payload)
        .await
        .map_err(|e| Error::Writing(CodingKey::Payload, e))
}
