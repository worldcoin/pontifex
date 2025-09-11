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

## Example

See the [`example`](example) directory for a complete working example.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
