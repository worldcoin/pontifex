//! Echo server - runs inside the enclave

// Include the types module from parent
#[path = "../types.rs"]
mod types;

use pontifex::Router;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use types::*;

const ENCLAVE_PORT: u32 = 1000;

#[tokio::main]
async fn main() {
	// Simple logging
	println!("🚀 Starting echo server on port {ENCLAVE_PORT}...");

	// Create a stateless router
	let router = Router::new()
		.route::<Echo, _, _>(handle_echo)
		.route::<HealthCheck, _, _>(handle_health);

	// Start serving
	if let Err(e) = router.serve(ENCLAVE_PORT).await {
		eprintln!("❌ Server error: {e}");
	}
}

async fn handle_echo(_state: Arc<()>, req: Echo) -> EchoResponse {
	let timestamp = SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap()
		.as_secs();

	println!("📥 Received: {}", req.message);

	EchoResponse {
		echoed: format!("You said: {}", req.message),
		timestamp,
	}
}

async fn handle_health(_state: Arc<()>, _req: HealthCheck) -> HealthStatus {
	println!("💚 Health check");

	HealthStatus {
		healthy: true,
		version: env!("CARGO_PKG_VERSION").to_string(),
	}
}
