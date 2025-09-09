//! Shared types between client and server

use pontifex::Request;
use serde::{Deserialize, Serialize};

/// Simple echo request
#[derive(Serialize, Deserialize)]
pub struct Echo {
	pub message: String,
}

/// Echo response
#[derive(Serialize, Deserialize)]
pub struct EchoResponse {
	pub echoed: String,
	pub timestamp: u64,
}

impl Request for Echo {
	const ROUTE_ID: &'static str = "echo_v1";
	type Response = EchoResponse;
}

/// Health check request
#[derive(Serialize, Deserialize)]
pub struct HealthCheck;

/// Health status response
#[derive(Serialize, Deserialize)]
pub struct HealthStatus {
	pub healthy: bool,
	pub version: String,
}

impl Request for HealthCheck {
	const ROUTE_ID: &'static str = "health_v1";
	type Response = HealthStatus;
}
