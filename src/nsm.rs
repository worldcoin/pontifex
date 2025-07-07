pub use aws_nitro_enclaves_nsm_api::api::{AttestationDoc, Digest, ErrorCode, Request, Response};

#[cfg(feature = "nsm")]
use {
    aws_nitro_enclaves_cose::{
        CoseSign1,
        crypto::{Hash, MessageDigest},
        error::CoseError,
    },
    aws_nitro_enclaves_nsm_api::api::Error,
    aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request},
    serde_bytes::ByteBuf,
    sha2::{Digest as _, Sha256, Sha384, Sha512},
    std::{io, os::fd::RawFd},
    tokio::sync::OnceCell,
};

/// A global connection to the Nitro Secure Module (NSM).
#[cfg(feature = "nsm")]
pub(crate) static SECURE_MODULE_GLOBAL: OnceCell<SecureModule> = OnceCell::const_new();

/// A connection to the Nitro Secure Module (NSM).
#[cfg(feature = "nsm")]
pub struct SecureModule {
    fd: RawFd,
}

/// Errors that can occur when requesting an attestation document from the NSM.
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    /// Failed to get attestation from NSM.
    #[error("AttestationError::Nsm: {0:?}")]
    Nsm(ErrorCode),
    /// Failed to decode attestation document.
    #[error("AttestationError::Encoding: {0}")]
    Encoding(serde_cbor::error::Error),
    /// Failed to decode attestation document.
    #[error("AttestationError::Cose: {0}")]
    Cose(aws_nitro_enclaves_cose::error::CoseError),
}

#[cfg(feature = "nsm")]
struct Sha2Hasher;

#[cfg(feature = "nsm")]
impl Hash for Sha2Hasher {
    fn hash(digest: MessageDigest, data: &[u8]) -> Result<Vec<u8>, CoseError> {
        Ok(match digest {
            MessageDigest::Sha256 => Sha256::digest(data).to_vec(),
            MessageDigest::Sha384 => Sha384::digest(data).to_vec(),
            MessageDigest::Sha512 => Sha512::digest(data).to_vec(),
        })
    }
}

#[cfg(feature = "nsm")]
impl SecureModule {
    /// Connect to the NSM driver.
    ///
    /// # Errors
    ///
    /// Returns an error if a connection to the NSM driver cannot be established.
    pub fn connect() -> io::Result<Self> {
        let fd = nsm_init();

        if fd == -1 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "Failed to initialize NSM",
            ));
        }

        Ok(Self { fd })
    }

    /// Send a request to the NSM driver.
    #[must_use]
    pub fn send(&self, request: Request) -> Response {
        nsm_process_request(self.fd, request)
    }

    /// Create an attestation document, and return it as a binary blob.
    ///
    /// # Errors
    ///
    /// Returns an error if the NSM driver returns an error.
    pub fn raw_attest(
        &self,
        user_data: Option<impl Into<Vec<u8>>>,
        nonce: Option<impl Into<Vec<u8>>>,
        public_key: Option<impl Into<Vec<u8>>>,
    ) -> Result<Vec<u8>, AttestationError> {
        let response = self.send(Request::Attestation {
            nonce: nonce.map(ByteBuf::from),
            user_data: user_data.map(ByteBuf::from),
            public_key: public_key.map(ByteBuf::from),
        });

        match response {
            Response::Error(code) => Err(AttestationError::Nsm(code)),
            Response::Attestation { document } => Ok(document),
            _ => unreachable!("Unexpected response type"),
        }
    }

    /// Create an `AttestationDoc` and sign it with it's private key to ensure authenticity.
    ///
    /// # Errors
    ///
    /// Returns an error if the NSM driver returns an error or if the response cannot be decoded.
    pub fn attest(
        &self,
        user_data: Option<impl Into<Vec<u8>>>,
        nonce: Option<impl Into<Vec<u8>>>,
        public_key: Option<impl Into<Vec<u8>>>,
    ) -> Result<AttestationDoc, AttestationError> {
        let document = self.raw_attest(user_data, nonce, public_key)?;
        Self::parse_raw_attestation_doc(&document)
    }

    fn parse_raw_attestation_doc(document: &[u8]) -> Result<AttestationDoc, AttestationError> {
        let cose_document = CoseSign1::from_bytes(document).map_err(AttestationError::Cose)?;

        let cbor_attestation_doc = cose_document
            .get_payload::<Sha2Hasher>(None)
            .map_err(AttestationError::Cose)?;

        AttestationDoc::from_binary(&cbor_attestation_doc).map_err(|e| match e {
            Error::Cbor(e) => AttestationError::Encoding(e),
            Error::Io(_) => {
                unreachable!("AttestationDoc::from_binary should not return an IO error")
            }
        })
    }

    /// Attempt to get the global NSM instance.
    pub fn try_global() -> Option<&'static Self> {
        SECURE_MODULE_GLOBAL.get()
    }

    /// Get the global NSM instance.
    ///
    /// # Panics
    ///
    /// Panics if the global NSM instance has not been initialized.
    #[must_use]
    pub fn global() -> &'static Self {
        Self::try_global().expect("NSM global not initialized")
    }

    /// Disconnect from the NSM driver.
    pub fn disconnect(self) {
        drop(self);
    }
}

#[cfg(feature = "nsm")]
impl Drop for SecureModule {
    fn drop(&mut self) {
        nsm_exit(self.fd);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Takes a COSE-signed attestation document and asserts that it can be properly parsed into an `AttestationDoc`.
    ///
    /// The `mock-attestation-doc` is generated from a test Nitro enclave with some values sanitized.
    #[test]
    fn test_parse_raw_attestation_doc() {
        let document = include_bytes!("../tests/mock-attestation-doc.cose");
        let document: AttestationDoc = SecureModule::parse_raw_attestation_doc(document).unwrap();

        assert_eq!(document.module_id, "test");
        assert_eq!(document.timestamp, 1_748_469_829_761);
        assert_eq!(document.certificate, ByteBuf::from(vec![3, 4]));
        assert_eq!(document.nonce, Some(ByteBuf::from(b"some nonce")));
        assert_eq!(document.user_data, Some(ByteBuf::from(b"hello, world!")));
    }
}
