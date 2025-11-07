# Set default target
.DEFAULT_GOAL := help

# Help command
help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  1. help              - Show this help message"
	@echo "  2. install           - Install ALL dependencies (uv + Python packages + Foundry)"
	@echo "  3. run               - Run the scaffold"
	@echo ""
	@echo "Benchmark Targets:"
	@echo "  4. extract-metrics   - Extract and analyze metrics from benchmark results"
	@echo "  5. analyse-costs     - Comprehensive cost analysis with OpenRouter data"
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

run:
	uv run run_scaffold.py

extract-metrics:
	cd benchmark && uv run extract_metrics.py

analyse-costs:
	cd benchmark && uv run analyse_costs.py