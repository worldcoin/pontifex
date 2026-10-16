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
// supporting multiple enclave software versions at once.
let verifier = Verifier::new(
    vec![PcrConfig::new(pcr0).with_pcr(1, pcr1).with_pcr(2, pcr2)],
    Duration::from_secs(3 * 60 * 60),
);

let attestation = verifier.verify_attestation_document(&attestation_doc)?;
println!("enclave module: {}", attestation.document().module_id);
```

For development only, `dangerously_skip_measurements()` disables all PCR checks,
including rejection of Nitro debug measurements. No PCR configuration is required;
any supplied pins are ignored:

```rust,ignore
let verifier = Verifier::new(vec![], max_age).dangerously_skip_measurements();
```

This accepts any enclave code with otherwise valid attestation. Certificate chain,
signature, and freshness checks remain enabled, and `ChannelConsumer::from_attestation`
still verifies the public-key commitment. Never enable this in production. Without
this explicit opt-in, measurement checks remain mandatory and zero PCR0 is rejected.

### Sealed Channel

The `channel` feature allows establishing an end-to-end encrypted channel, so a client can send data directly to the enclave without anyone else (chiefly the untrusted parent host) being able to read it. Every message is a [`quantum-box`](https://docs.rs/quantum-box) sealed box over X-Wing, a hybrid post-quantum KEM.

The enclave usually generates a keypair per boot and attests a commitment to its public key. The client verifies the attestation against that key before sealing to it. Each request mints its own response key to receive an encrypted response.

The default flow looks as follows:

```rust,ignore
use pontifex::{SecureModule, channel::{ChannelConsumer, ChannelDomain, ChannelEnclave}};

const DOMAIN: ChannelDomain = ChannelDomain::new("my-protocol/match_v1");

// Enclave (usually once per boot): generate a channel key and attest the public key used for it.
let enclave = ChannelEnclave::generate(DOMAIN)?;
let attestation_doc = SecureModule::global().raw_attest(
    None::<Vec<u8>>,                       // user_data
    None::<Vec<u8>>,                       // nonce
    Some(enclave.public_key_commitment()), // public_key
)?;
let enclave_public_key = enclave.public_key();

// End consumer: establish the channel from the enclave's attested public key
let (consumer, attestation) =
    ChannelConsumer::from_attestation(DOMAIN, &verifier, &attestation_doc, &enclave_public_key)?;
let (sealed_request, opener) = consumer.seal_to_enclave(b"inputs")?;

// Enclave: open the request, seal the one reply it belongs to.
let (plaintext, sealer) = enclave.open(&sealed_request)?;
let sealed_response = sealer.seal(b"result")?;

// End consumer: open the enclave's response.
let result = opener.open_from_enclave(&sealed_response)?;
```

### Outbound Proxy

The `proxy` feature runs on the parent instance and forwards the enclave's outbound vsock connections, such as those of the `http` and `kms` clients, to one fixed TCP destination. It replaces a separate `vsock-proxy` process: it runs inside the host's own process, can restrict connections to the enclave's CID (`allowed_cid`), bounds concurrent connections, and reports every outcome for metrics.

TLS terminates inside the enclave, so the proxy only relays ciphertext.

```rust,ignore
use pontifex::proxy::{self, Config, Event};

let mut config = Config::new(8000, "kms.eu-central-1.amazonaws.com", 443);
config.allowed_cid = Some(enclave_cid);

// Only returns on an invalid configuration or a failed bind.
proxy::serve(config, |event| match event {
    Event::Closed { outcome, duration } => { /* count `outcome`, record `duration` */ },
    other => { /* count rejections and accept failures */ },
}).await?;
```

### KMS From the Enclave

The `kms` feature builds an AWS KMS client inside the enclave. TLS terminates in the enclave and the traffic leaves through the [outbound proxy](#outbound-proxy). The enclave has no AWS credentials of its own: with the `aws-credentials` feature, the host serves its temporary workload credentials as a Pontifex route, and `aws_credentials::ParentCredentials` fetches and renews them, for KMS or any other AWS SDK client.

```rust,ignore
// Host. Answers only `enclave_cid`: vsock is not namespaced, so other pods could ask too.
aws_credentials::router(aws_config.credentials_provider().unwrap(), enclave_cid, |result| { /* count `result` */ })
    .serve(CREDENTIALS_PORT)
    .await?;

// Enclave
use pontifex::{aws_credentials::ParentCredentials, kms};

let client = kms::client_with_credentials(&sdk_config, ParentCredentials::new(CREDENTIALS_PORT), PROXY_PORT);
```

Only temporary credentials with at least 60 seconds of validity are sent; static ones are refused on both sides. `Router::allowed_cid` works for any router on the host.

## Releases

Releases are automated with [release-plz](https://release-plz.dev)

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/worldcoin/pontifex/blob/main/LICENSE) file for details.
