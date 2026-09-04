# Pontifex

> Pontifex (noun): Originally meaning "bridge-builder" in Latin

Pontifex is a Rust library for building and interacting with AWS Nitro enclaves.

## Usage

### Common Types

Define request/response pairs that both client and server use:

```rust,ignore
use serde::{Deserialize, Serialize};
use pontifex::Request;

#[derive(Serialize, Deserialize)]
struct HealthCheck;

#[derive(Serialize, Deserialize)]
struct HealthStatus {
    healthy: bool,
}

impl Request for HealthCheck {
    const ROUTE_ID: &'static str = "health_check_v1";
    type Response = HealthStatus;
}
```

### Server

```rust,ignore
use pontifex::Router;
use std::sync::Arc;

const ENCLAVE_PORT: u32 = 1000;

// Stateless server
let router = Router::new()
    .route::<HealthCheck, _, _>(|_state, _req| async {
        HealthStatus { healthy: true }
    });

// Or with state
#[derive(Clone)]
struct AppState {
    db: Database,
}

// ⚠️ Warning: Remember to wrap expensive states with Arc
let router = Router::with_state(Arc::new(AppState { db: Database::new() }))
    .route::<GetUser, _, _>(|state: Arc<AppState>, req| async move {
        // Handlers receive Arc<State> for cheap cloning
        state.db.get_user(req.id).await
    });

router.serve(ENCLAVE_PORT).await?;
```

### Client

```rust,ignore
use pontifex::{ConnectionDetails, send};

const ENCLAVE_CID: u32 = 100;
const ENCLAVE_PORT: u32 = 1000;

let connection = ConnectionDetails::new(ENCLAVE_CID, ENCLAVE_PORT);
let response: HealthStatus = send(connection, &HealthCheck).await?;
```

### Attestation Verification

The `verify` feature checks an attestation document's COSE signature, certificate chain,
PCR values and age, then verifies its `user_data` commitment to the supplied public key.

```rust,ignore
use pontifex::{EnclaveAttestationVerifier, PcrMeasurement};

// Any matching PCR configuration is accepted.
let verifier = EnclaveAttestationVerifier::new(vec![vec![
    PcrMeasurement::new(0, pcr0),
    PcrMeasurement::new(1, pcr1),
    PcrMeasurement::new(2, pcr2),
]]);

let attestation = verifier.verify_attestation_document_with_key_commitment(
    &document,
    &public_key,
)?;
```

Use `pontifex::public_key_commitment(&public_key)` to compute a commitment for any key.
It takes raw key bytes before transport encoding. The verifier rejects missing or
mismatched commitments with `KeyCommitmentMismatch`.

### Sealed Channel

The `channel` feature allows establishing an end-to-end encrypted channel, so a client can send data directly to the enclave without anyone else (chiefly the untrusted parent host) being able to read it. Every message is a [`quantum-box`](https://docs.rs/quantum-box) sealed box over X-Wing, a hybrid post-quantum KEM.

The channel's X-Wing public key exceeds [NSM's public-key field limit](https://github.com/aws/aws-nitro-enclaves-nsm-api/blob/main/docs/attestation_process.md#22-attestation-document-specification). Include its commitment in `user_data` and return the public key alongside the attestation document.

The default flow looks as follows:

```rust,ignore
use pontifex::{ChannelConsumer, ChannelDomain, ChannelEnclave, SecureModule};

// Use the same protocol name and version on both sides.
const DOMAIN: ChannelDomain = ChannelDomain::new("my-protocol/match_v1");

// Enclave: generate the keypair and attest its commitment.
let enclave = ChannelEnclave::generate(DOMAIN)?;
let public_key = enclave.public_key();
let document = SecureModule::connect()?.raw_attest(
    Some(enclave.public_key_commitment()),
    None::<Vec<u8>>,
    None::<Vec<u8>>,
)?;
// Return `document` and `public_key` to the consumer.

// Consumer: use the verifier configured above to authenticate the key.
verifier.verify_attestation_document_with_key_commitment(&document, &public_key)?;
let consumer = ChannelConsumer::new(DOMAIN, &public_key)?;
let (sealed_request, opener) = consumer.seal_to_enclave(b"inputs")?;

// Enclave: open the request, seal the one reply it belongs to.
let (plaintext, sealer) = enclave.open(&sealed_request)?;
let sealed_response = sealer.seal(b"result")?;

// End consumer: only this opener can open that response.
let result = opener.open_from_enclave(&sealed_response)?;
```

## Releases

Releases are automated with [release-plz](https://release-plz.dev)

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/worldcoin/pontifex/blob/main/LICENSE) file for details.
