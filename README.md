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

The `channel` feature adds an end-to-end encrypted channel to a specific enclave boot, so the
untrusted parent instance forwarding the bytes never sees the plaintext. Requests use HPKE
(RFC 9180) `mode_base`; responses use the encapsulation construction of RFC 9458 §4.4, which
replies to one request without a second key exchange.

The enclave generates a keypair per boot and attests its public key; the client verifies the
attestation and seals to the key it carried. Both sides name the same `ChannelDomain`.

```rust,ignore
use pontifex::channel::{ChannelDomain, Requester, Responder, UnwrapErr};

const DOMAIN: ChannelDomain = ChannelDomain::new("my-protocol/match", 1);

// Enclave, once per boot. Attest `responder.public_key()`.
let responder = Responder::generate(DOMAIN, &mut UnwrapErr(getrandom::SysRng));

// Client, per request, against the key the verified attestation carried.
let requester = Requester::from_attestation(DOMAIN, attested_public_key)?;
let (sealed_request, opener) = requester.seal(b"inputs", &mut UnwrapErr(getrandom::SysRng))?;

// Enclave: open the request, seal the one reply it belongs to.
let (plaintext, sealer) = responder.open(&sealed_request)?;
let sealed_response = sealer.seal(b"result", &mut UnwrapErr(getrandom::SysRng))?;

// Client: only this requester can open that response.
let result = opener.open(&sealed_response)?;
```

## Example

See the [`example`](example) directory for a complete working example.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
