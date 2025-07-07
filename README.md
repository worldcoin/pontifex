# Pontifex

> Pontifex (noun): Originally meaning "bridge-builder" in Latin

Pontifex is a Rust library for building and interacting with AWS Nitro enclaves. It provides a simple abstraction for building enclaves and interacting with them using the AWS Nitro Enclaves SDK.

## Usage

First, add `pontifex` to your enclave's `Cargo.toml` with the `server` feature. Then, you can build your enclave as follows:

```rust
const ENCLAVE_PORT: u32 = 1000;

#[derive(serde::Deserialize)]
struct RequestPayload {}

#[derive(serde::Serialize)]
struct ResponsePayload {}

#[tokio::main]
async fn main() {
    // setup tracing, etc.

    tracing::info!("🦀 Starting server...");

    if let Err(e) = pontifex::listen(ENCLAVE_PORT, process).await {
        eprintln!("Failed to start server: {e}");
    }
}

async fn process(request: RequestPayload) -> ResponsePayload {
    // handle request

    ResponsePayload {}
}
```

Then, on your client, add `pontifex` to your `Cargo.toml` with the `client` feature. You can then interact with your enclave as follows:

```rust
use pontifex::ConnectionDetails;

const ENCLAVE_CID: u32 = 100;
const ENCLAVE_PORT: u32 = 1024;

#[derive(serde::Serialize)]
struct RequestPayload {}

#[derive(serde::Deserialize)]
struct ResponsePayload {}

#[tokio::main]
async fn main() {

    let request = RequestPayload {};

    let result = pontifex::send::<RequestPayload, ResponsePayload>(ConnectionDetails::new(ENCLAVE_CID, ENCLAVE_PORT), &request).await;

    if let Ok(response) = result {
        println!("Response received");
    }
}

```

For convenience, you can define a common crate that both your enclave and client depend on, which contains your request and response types.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
