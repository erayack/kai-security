# Set default target
.DEFAULT_GOAL := help

# Help command
help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  install - Install ALL dependencies (uv + Python packages + Foundry)"
	@echo "  help    - Show this help message"
	@echo ""
	@echo "Quick Start:"
	@echo "  make install"

# Complete installation: uv, Python dependencies, and Foundry
install:
	@bash scripts/install.sh
	@if [ -f "$$HOME/.foundry/bin/forge" ] && ! command -v forge > /dev/null 2>&1; then \
		export PATH="$$HOME/.foundry/bin:$$PATH"; \
		echo "════════════════════════════════════════════════════════════════"; \
		echo "  🚀 Ready! To use Foundry in THIS shell, run:"; \
		echo "════════════════════════════════════════════════════════════════"; \
		echo ""; \
		echo "  export PATH=\"\$$HOME/.foundry/bin:\$$PATH\""; \
		echo ""; \
	fi