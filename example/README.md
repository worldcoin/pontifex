# Pontifex Example - AWS Nitro Enclave Demo

A complete example demonstrating secure communication between a host and an AWS Nitro Enclave using Pontifex.

## Prerequisites

This example assumes you're running on:

- **AWS EC2 instance** with Nitro Enclave support enabled
- **Amazon Linux 2023** or similar
- **Required dependencies installed:**
  - Rust toolchain (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
  - Docker (`sudo yum install docker`)
  - AWS Nitro CLI (`sudo amazon-linux-extras install aws-nitro-enclaves-cli`)
  - Build essentials (`sudo yum groupinstall "Development Tools"`)
  - jq for JSON parsing (`sudo yum install jq`)

## Project Structure

```
example/
├── Cargo.toml           # Single crate configuration
├── Dockerfile.enclave   # Enclave image (Amazon Linux 2023 minimal)
├── Makefile            # Automation for enclave operations
├── README.md           # This file
└── src/
    ├── lib.rs          # Re-exports the types module
    ├── types.rs        # Shared request/response types (Echo, HealthCheck)
    └── bin/
        ├── enclave.rs  # Server running inside the Nitro Enclave
        └── client.rs   # Client running on the host EC2 instance
```

## Make Commands

### Order of Operations

```bash
# 1. Build the Rust binaries
make build

# 2. Deploy the enclave (builds Docker image, creates EIF, starts enclave)
make deploy

# 3. Test the enclave with the client
make client

# Or do it all in one step:
make all     # Clean, build, and deploy
make client  # Then test
```

### Help

```bash
make help
```

## How It Works

1. **Build Phase**:
   - `cargo build --release` creates binaries in `target/release/`
2. **Docker Phase**:

   - Dockerfile copies the enclave binary into an Amazon Linux 2023 minimal container
   - Creates a Docker image tagged as `enclave:latest`

3. **EIF Creation**:
   - `nitro-cli build-enclave` converts the Docker image to an Enclave Image File (`.eif`)
4. **Deployment**:

   - `nitro-cli run-enclave` starts the enclave with:
     - CID: 16 (configurable via `ENCLAVE_CID`)
     - Memory: 1024 MB
     - CPU: 1 core
     - Debug mode enabled (for `console` access)

5. **Testing**:
   - Client connects to enclave at CID 16, Port 1000
   - Sends health check request
   - Sends echo messages to verify communication

## Notes

- The enclave runs without network access (vsock communication only)
- State is not persisted between enclave restarts
- Debug mode allows console access but should be disabled in production
