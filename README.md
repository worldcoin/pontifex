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

### Sealed Channel

The `channel` feature allows establishing an end-to-end encrypted channel, so a client can send data directly to the enclave without anyone else (chiefly the untrusted parent host) being able to read it. Every message is a [`quantum-box`](https://docs.rs/quantum-box) sealed box over X-Wing, a hybrid post-quantum KEM.

The enclave usually generates a keypair per boot and attests a commitment to its public key. The client verifies the attestation against that key before sealing to it. Each request mints its own response key to receive an encrypted response.

The default flow looks as follows:

```rust,ignore
use pontifex::{SecureModule, channel::{ChannelConsumer, ChannelDomain, ChannelEnclave}};

// The name is the only lever for a breaking wire change, so carry a version in it.
const DOMAIN: ChannelDomain = ChannelDomain::new("my-protocol/match_v1");

// Enclave (usually once per boot). The X-Wing key is larger than the attestation document's
// `public_key` field allows, so attest its commitment and hand the key out alongside.
let enclave = ChannelEnclave::generate(DOMAIN)?;
let attestation_doc = SecureModule::global().raw_attest(
    Some(enclave.public_key_commitment()), // user_data
    None::<Vec<u8>>,
    None::<Vec<u8>>,
)?;
let enclave_public_key = enclave.public_key();

// End consumer: one call verifies the attestation, checks it commits to this key, and
// builds the consumer. There is no way to skip the check and still get a consumer.
let (consumer, attestation) =
    ChannelConsumer::from_attestation(DOMAIN, &verifier, &attestation_doc, &enclave_public_key)?;
let (sealed_request, opener) = consumer.seal_to_enclave(b"inputs")?;

// Enclave: open the request, seal the one reply it belongs to.
let (plaintext, sealer) = enclave.open(&sealed_request)?;
let sealed_response = sealer.seal(b"result")?;

// End consumer: only this opener can open that response.
let result = opener.open_from_enclave(&sealed_response)?;
```

### Attestation Verification

Outside the enclave, the `attestation` feature checks an attestation document produced by the NSM:
COSE Sign1 signature, certificate chain up to the AWS Nitro root, PCR values, and freshness. The
`channel` feature turns it on, so a sealed channel keys off a verified attestation.

```rust,ignore
use pontifex::attestation::{Verifier, PcrMeasurement};

// Verification succeeds if *any* of the allowed configurations matches,
// which allows supporting multiple enclave software versions at once.
let verifier = Verifier::new(vec![vec![
    PcrMeasurement::new(0, pcr0),
    PcrMeasurement::new(1, pcr1),
    PcrMeasurement::new(2, pcr2),
]]);

// Defaults to a three-hour freshness window; override with `.with_max_age(..)`.
// Takes the raw COSE bytes: how the document reached you is your protocol's business.
let attestation = verifier.verify_attestation_document(&attestation_doc)?;
println!("enclave module: {}", attestation.document().module_id);
```

`VerifiedAttestation` wraps the whole signed document — `nonce`, `user_data`, PCRs and all —
and only the verifier can construct one, so the type is itself proof the document was checked. Binding a key too large for the document's
1024-byte `public_key` field is what `channel` does with
`pontifex::channel::public_key_commitment`; see below.

## Releases

Releases are automated with [release-plz](https://release-plz.dev)

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/worldcoin/pontifex/blob/main/LICENSE) file for details.
