# Set default target
.DEFAULT_GOAL := help

# Help command
help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  1. help                - Show this help message"
	@echo "  2. install             - Install ALL dependencies (uv + Python packages + Foundry)"
	@echo "  3. run                 - Run dispatcher playground (requires REPO_PATH)"
	@echo "  4. run-exploration     - Run dispatcher with exploration enabled"
	@echo "  5. run-iterative       - Run dispatcher in iterative mode"
	@echo "  6. run-no-fixer        - Run dispatcher with fixer disabled"
	@echo "  7. test                - Run test suite"
	@echo "  8. lint                - Run Ruff lint checks"
	@echo "  9. typecheck           - Run type checks with ty"
	@echo "  10. format             - Format code with Ruff"
	@echo ""
	@echo "Quick Start:"
	@echo "  make install"
	@echo "  make run REPO_PATH=./path/to/contracts"
	@echo ""
	@echo "For dispatcher CLI options, run:"
	@echo "  uv run python scripts/playground_dispatcher.py --help"

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
	@if [ -z "$(REPO_PATH)" ]; then \
		echo "Error: REPO_PATH is not set"; \
		echo "Usage: make run REPO_PATH=./path/to/contracts [MODEL=openai/gpt-5.2-codex]"; \
		exit 1; \
	fi
	@if [ -n "$(MODEL)" ]; then \
		uv run python scripts/playground_dispatcher.py --repo-path "$(REPO_PATH)" --model "$(MODEL)"; \
	else \
		uv run python scripts/playground_dispatcher.py --repo-path "$(REPO_PATH)"; \
	fi

run-exploration:
	@if [ -z "$(REPO_PATH)" ]; then \
		echo "Error: REPO_PATH is not set"; \
		echo "Usage: make run-exploration REPO_PATH=./path/to/contracts"; \
		exit 1; \
	fi
	@if [ -n "$(MODEL)" ]; then \
		uv run python scripts/playground_dispatcher.py --repo-path "$(REPO_PATH)" --exploration --model "$(MODEL)"; \
	else \
		uv run python scripts/playground_dispatcher.py --repo-path "$(REPO_PATH)" --exploration; \
	fi

run-iterative:
	@if [ -z "$(REPO_PATH)" ]; then \
		echo "Error: REPO_PATH is not set"; \
		echo "Usage: make run-iterative REPO_PATH=./path/to/contracts"; \
		exit 1; \
	fi
	@if [ -n "$(MODEL)" ]; then \
		uv run python scripts/playground_dispatcher.py --repo-path "$(REPO_PATH)" --iterative --model "$(MODEL)"; \
	else \
		uv run python scripts/playground_dispatcher.py --repo-path "$(REPO_PATH)" --iterative; \
	fi

run-no-fixer:
	@if [ -z "$(REPO_PATH)" ]; then \
		echo "Error: REPO_PATH is not set"; \
		echo "Usage: make run-no-fixer REPO_PATH=./path/to/contracts"; \
		exit 1; \
	fi
	@if [ -n "$(MODEL)" ]; then \
		uv run python scripts/playground_dispatcher.py --repo-path "$(REPO_PATH)" --no-fixer --model "$(MODEL)"; \
	else \
		uv run python scripts/playground_dispatcher.py --repo-path "$(REPO_PATH)" --no-fixer; \
	fi

test:
	uv run pytest -q

lint:
	uv run ruff check src tests

typecheck:
	uv run ty check src

format:
	uv run ruff format src tests scripts
