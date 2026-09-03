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

The enclave usually generates a keypair per boot and attests its public key. The client then verifies the attestation and seals to the key it carried. Each request mints its own response key to receive an encrypted response.

The default flow looks as follows:

```rust,ignore
use pontifex::channel::{ChannelConsumer, ChannelDomain, ChannelEnclave};

// The name is the only lever for a breaking wire change, so carry a version in it.
const DOMAIN: ChannelDomain = ChannelDomain::new("my-protocol/match_v1");

// Enclave (usually once per boot): Attest `enclave.public_key()`, then hand those bytes out.
let enclave = ChannelEnclave::generate(DOMAIN)?;

// End consumer: uses an *attested* public key. NOTE: attestation is currently not verified here.
let consumer = ChannelConsumer::new(DOMAIN, &attested_public_key)?;
let (sealed_request, opener) = consumer.seal_to_enclave(b"inputs")?;

// Enclave: open the request, seal the one reply it belongs to.
let (plaintext, sealer) = enclave.open(&sealed_request)?;
let sealed_response = sealer.seal(b"result")?;

// End consumer: only this opener can open that response.
let result = opener.open_from_enclave(&sealed_response)?;
```

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/worldcoin/pontifex/blob/main/LICENSE) file for details.
