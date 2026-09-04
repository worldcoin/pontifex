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

The `attestation` feature allows a consumer to check an attestation issued by the NSM of a Nitro Enclave. It is what the `channel` feature uses underneath to verify public keys are attested but using this module directly enables a consumer to receive arbitrarily attested data.

```rust,ignore
use pontifex::attestation::{PcrConfig, Verifier};
use std::time::Duration;

// Verification succeeds if *any* of the allowed configurations matches, which allows
// supporting multiple enclave software versions at once. There is no default freshness
// window: only you know how the document reaches you and how long a replay stays useful.
let verifier = Verifier::new(
    vec![PcrConfig::new(pcr0).with_pcr(1, pcr1).with_pcr(2, pcr2)],
    Duration::from_secs(3 * 60 * 60),
);

// Takes the raw COSE bytes: how the document reached you is your protocol's business.
let attestation = verifier.verify_attestation_document(&attestation_doc)?;
println!("enclave module: {}", attestation.document().module_id);
```

`VerifiedAttestation` wraps the whole signed document — `nonce`, `user_data`, PCRs and all — and
only the verifier can construct one, so the type is itself proof the document was checked.

#### Choosing PCRs

PCR0, the hash of the whole enclave image, is a required argument to `PcrConfig::new` rather than
an entry in a list — a configuration that pins no code identity does not compile. Every other PCR
is optional. Listing several configurations means "any one of these releases", and each is matched
in full, so values from different releases can never be mixed.

| PCR | measures | pin it? |
| --- | --- | --- |
| 0 | the entire enclave image | **required** |
| 1 | kernel and bootstrap | usually |
| 2 | application ramdisk | usually |
| 3 | parent IAM role | only to tie the enclave to one role |
| 4 | parent instance ID | rarely — this pins one EC2 instance |
| 8 | enclave image signing certificate | if you sign your enclaves |

PCRs you do not list are not checked. PCR0 already covers the image as a whole, so pinning 1 and 2
alongside it is defence in depth rather than a separate guarantee.

#### Field sizes

The document has three application-controlled fields, and they are not the same size:

| field | limit | used by |
| --- | --- | --- |
| `public_key` | 1024 bytes | `channel`, for its key commitment |
| `user_data` | 512 bytes | yours |
| `nonce` | 512 bytes | yours, for replay protection |

A key of 1024 bytes or less goes straight in `public_key` and needs no commitment. `channel` only
uses one because an X-Wing key is 1216 bytes.

### Sealed Channel

The `channel` feature allows establishing an end-to-end encrypted channel, so a client can send data directly to the enclave without anyone else (chiefly the untrusted parent host) being able to read it. Every message is a [`quantum-box`](https://docs.rs/quantum-box) sealed box over X-Wing, a hybrid post-quantum KEM.

The enclave usually generates a keypair per boot and attests a commitment to its public key. The client verifies the attestation against that key before sealing to it. Each request mints its own response key to receive an encrypted response.

The default flow looks as follows:

```rust,ignore
use pontifex::{SecureModule, channel::{ChannelConsumer, ChannelDomain, ChannelEnclave}};

// The name is the only lever for a breaking wire change, so carry a version in it.
const DOMAIN: ChannelDomain = ChannelDomain::new("my-protocol/match_v1");

// Enclave (usually once per boot): generate a channel key and attest a commitment to it.
let enclave = ChannelEnclave::generate(DOMAIN)?;
let attestation_doc = SecureModule::global().raw_attest(
    None::<Vec<u8>>,                       // user_data — left free for your protocol
    None::<Vec<u8>>,                       // nonce
    Some(enclave.public_key_commitment()), // public_key
)?;
let enclave_public_key = enclave.public_key();

// End consumer: `verifier` is the one built above. This single call verifies the document,
// checks it commits to this key, and hands back the channel — the check cannot be skipped.
let (consumer, attestation) =
    ChannelConsumer::from_attestation(DOMAIN, &verifier, &attestation_doc, &enclave_public_key)?;
let (sealed_request, opener) = consumer.seal_to_enclave(b"inputs")?;

// Enclave: open the request, seal the one reply it belongs to.
let (plaintext, sealer) = enclave.open(&sealed_request)?;
let sealed_response = sealer.seal(b"result")?;

// End consumer: open the enclave's response.
let result = opener.open_from_enclave(&sealed_response)?;
```

## Releases

Releases are automated with [release-plz](https://release-plz.dev)

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/worldcoin/pontifex/blob/main/LICENSE) file for details.
