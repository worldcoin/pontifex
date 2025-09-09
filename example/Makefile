# Makefile for fast enclave development

# Variables
ENCLAVE_CID ?= 16
DEBUG_MODE ?= true

# Colors for output
GREEN := \033[0;32m
YELLOW := \033[1;33m
NC := \033[0m

.PHONY: help build deploy client clean console status kill all quick test

help:
	@echo "Fast Enclave Development Commands:"
	@echo "  make build   - Build enclave binary locally"
	@echo "  make deploy  - Build and deploy enclave"
	@echo "  make client  - Run the client to test the enclave"
	@echo "  make all     - Clean, build, and deploy"
	@echo "  make console - Connect to enclave console"
	@echo "  make status  - Show enclave status"
	@echo "  make kill    - Terminate all enclaves"
	@echo "  make clean   - Clean build artifacts"

# Build the binary locally 
build:
	@echo "$(YELLOW)Building ...$(NC)"
	@cargo build --release --bin enclave
	@echo "$(GREEN)✓ Build complete$(NC)"

# Deploy enclave
deploy: build
	@echo "$(YELLOW)Building Docker image...$(NC)"
	@sudo docker build -t enclave:latest -f Dockerfile.enclave . 
	@echo "$(YELLOW)Building EIF...$(NC)"
	@sudo nitro-cli build-enclave --docker-uri enclave:latest --output-file enclave.eif 
	@echo "$(YELLOW)Deploying enclave...$(NC)"
	@sudo nitro-cli terminate-enclave --all 2>/dev/null || true
	@sleep 1
	@sudo nitro-cli run-enclave \
		--cpu-count 2 \
		--memory 1024 \
		--enclave-cid $(ENCLAVE_CID) \
		--eif-path enclave.eif \
		$(if $(filter true,$(DEBUG_MODE)),--debug-mode,)
	@echo "$(GREEN)✓ Enclave deployed!$(NC)"
	@sudo nitro-cli describe-enclaves | jq -r '.[0] | "ID: \(.EnclaveID)\nCID: \(.EnclaveCID)"'

# Run the client to test the enclave
client:
	@echo "$(YELLOW)Building client...$(NC)"
	@cargo build --release --bin client
	@echo "$(YELLOW)Running client...$(NC)"
	@./target/release/client
	@echo "$(GREEN)✓ Client test complete$(NC)"

# Full cycle: clean, build, deploy
all: kill clean deploy

# Connect to console
console:
	@ENCLAVE_ID=$$(sudo nitro-cli describe-enclaves | jq -r '.[0].EnclaveID'); \
	if [ "$$ENCLAVE_ID" != "null" ]; then \
		sudo nitro-cli console --enclave-id $$ENCLAVE_ID; \
	else \
		echo "No running enclave found"; \
	fi

# Show status
status:
	@sudo nitro-cli describe-enclaves | jq '.'

# Kill all enclaves
kill:
	@echo "$(YELLOW)Terminating all enclaves...$(NC)"
	@sudo nitro-cli terminate-enclave --all 2>/dev/null || true
	@echo "$(GREEN)✓ Done$(NC)"

# Clean build artifacts
clean:
	@echo "$(YELLOW)Cleaning...$(NC)"
	@rm -f enclave.eif
	@cargo clean 2>/dev/null || true
	@echo "$(GREEN)✓ Clean complete$(NC)"

# Quick rebuild and deploy (most common during development)
quick: deploy
