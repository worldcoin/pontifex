//! Echo client - runs on the host

// Include the types module from parent
#[path = "../types.rs"]
mod types;

use pontifex::{ConnectionDetails, send};
use types::*;

// Default enclave CID - adjust based on your setup
const ENCLAVE_CID: u32 = 16;
const ENCLAVE_PORT: u32 = 1000;

#[tokio::main]
async fn main() {
	println!("🔌 Connecting to enclave CID={ENCLAVE_CID} PORT={ENCLAVE_PORT}");

	let connection = ConnectionDetails::new(ENCLAVE_CID, ENCLAVE_PORT);

	// First, check health
	println!("\n📍 Checking enclave health...");
	match send(connection, &HealthCheck).await {
		Ok(status) => {
			println!("✅ Healthy: {}", status.healthy);
			println!("📦 Version: {}", status.version);
		},
		Err(e) => {
			eprintln!("❌ Health check failed: {e}");
			return;
		},
	}

	// Send some echo messages
	let messages = ["Hello, Enclave!", "How are you?", "Goodbye!"];

	for msg in messages {
		println!("\n📤 Sending: {msg}");

		let request = Echo {
			message: msg.to_string(),
		};

		match send(connection, &request).await {
			Ok(response) => {
				println!("📥 Response: {}", response.echoed);
				println!("🕐 Timestamp: {}", response.timestamp);
			},
			Err(e) => {
				eprintln!("❌ Echo failed: {e}");
			},
		}
	}

	println!("\n✨ Done!");
}
