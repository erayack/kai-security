# Default target
.DEFAULT_GOAL := help

PYTEST := PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 uv run pytest -q -p pytest_asyncio.plugin
PYTHON := uv run python

.PHONY: help install run run-recipe run-no-fixer run-no-iterative test lint typecheck format check

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  help              Show this help message"
	@echo "  install           Install Python dependencies and Foundry"
	@echo "  run               Run full pipeline with REPO_PATH=<path>"
	@echo "  run-recipe        Run pipeline from RECIPE=<path>"
	@echo "  run-no-fixer      Run pipeline without fixer agent"
	@echo "  run-no-iterative  Run pipeline without iterative re-verification"
	@echo "  test              Run the test suite"
	@echo "  lint              Run Ruff lint checks"
	@echo "  typecheck         Run ty type checks"
	@echo "  format            Format code with Ruff"
	@echo "  check             Run lint, typecheck, and tests"
	@echo ""
	@echo "Examples:"
	@echo "  make run REPO_PATH=/path/to/repo"
	@echo "  make run REPO_PATH=/path/to/repo ARGS=\"--verbose --no-state\""
	@echo "  make run-recipe RECIPE=output/recipe.json"

install:
	@bash scripts/install.sh

run:
	@if [ -z "$(REPO_PATH)" ]; then \
		echo "Error: REPO_PATH is not set"; \
		echo "Usage: make run REPO_PATH=/path/to/repo [ARGS=\"--verbose\"]"; \
		exit 1; \
	fi
	$(PYTHON) -m kai.main pipeline --repo-path "$(REPO_PATH)" $(ARGS)

run-recipe:
	@if [ -z "$(RECIPE)" ]; then \
		echo "Error: RECIPE is not set"; \
		echo "Usage: make run-recipe RECIPE=output/recipe.json [ARGS=\"--verbose\"]"; \
		exit 1; \
	fi
	$(PYTHON) -m kai.main pipeline --recipe "$(RECIPE)" $(ARGS)

run-no-fixer:
	@if [ -z "$(REPO_PATH)" ]; then \
		echo "Error: REPO_PATH is not set"; \
		echo "Usage: make run-no-fixer REPO_PATH=/path/to/repo [ARGS=\"--verbose\"]"; \
		exit 1; \
	fi
	$(PYTHON) -m kai.main pipeline --repo-path "$(REPO_PATH)" --skip-fixer $(ARGS)

run-no-iterative:
	@if [ -z "$(REPO_PATH)" ]; then \
		echo "Error: REPO_PATH is not set"; \
		echo "Usage: make run-no-iterative REPO_PATH=/path/to/repo [ARGS=\"--verbose\"]"; \
		exit 1; \
	fi
	$(PYTHON) -m kai.main pipeline --repo-path "$(REPO_PATH)" --no-iterative $(ARGS)

test:
	$(PYTEST)

lint:
	uv run ruff check src tests evaluation

typecheck:
	uv run ty check src evaluation

format:
	uv run ruff format src tests scripts evaluation

check: lint typecheck test
