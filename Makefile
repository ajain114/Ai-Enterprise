# Makefile — enterprise-mcp-ai-platform
# =======================================
# Common development commands.
#
# Usage:
#   make install      Install all dependencies
#   make up           Start local infrastructure
#   make test         Run all tests
#   make lint         Run linter
#   make demo         Run the end-to-end demo

.PHONY: install install-dev up down test test-unit test-integration lint format clean demo

# ── Setup ────────────────────────────────────────────────────────────────────
install:
	pip install -r requirements.txt
	python -m spacy download en_core_web_lg

install-dev:
	pip install -r requirements-dev.txt
	python -m spacy download en_core_web_lg
	pre-commit install

# ── Infrastructure ────────────────────────────────────────────────────────────
up:
	docker-compose up -d
	@echo "Waiting for services to be healthy..."
	@sleep 5
	@docker-compose ps

down:
	docker-compose down

down-clean:
	docker-compose down -v
	@echo "All volumes removed."

# ── Database ─────────────────────────────────────────────────────────────────
db-setup:
	docker-compose exec pgvector psql -U rag_reader -d ai_rag_platform -f /docker-entrypoint-initdb.d/01_setup.sql

db-seed:
	python scripts/seed_demo_data.py

# ── Testing ───────────────────────────────────────────────────────────────────
test:
	python -m pytest tests/ -v --tb=short

test-unit:
	python -m pytest tests/test_pii_shield.py tests/test_prompt_guard.py -v

test-integration:
	python -m pytest tests/test_rag_server.py tests/test_feature_store.py -v

test-e2e:
	python tests/test_guardrail_pipeline.py

test-cov:
	python -m pytest tests/ --cov=src --cov-report=html --cov-report=term-missing
	@echo "Coverage report: htmlcov/index.html"

# ── Demo ──────────────────────────────────────────────────────────────────────
demo:
	@echo "Running end-to-end guardrail pipeline demo..."
	python tests/test_guardrail_pipeline.py

demo-rag:
	@echo "Running RAG server demo..."
	python -m src.servers.rag_server

# ── Code Quality ─────────────────────────────────────────────────────────────
lint:
	ruff check src/ tests/

format:
	ruff format src/ tests/
	ruff check --fix src/ tests/

type-check:
	mypy src/ --ignore-missing-imports

# ── Servers ───────────────────────────────────────────────────────────────────
run-rag:
	python -m src.servers.rag_server

run-features:
	python -m src.servers.feature_store_server

run-governance:
	python -m src.servers.governance_server

# ── Cleanup ───────────────────────────────────────────────────────────────────
clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete
	find . -name "*.pyo" -delete
	rm -rf .pytest_cache htmlcov .coverage build dist *.egg-info

help:
	@echo ""
	@echo "  Enterprise MCP AI Platform — Available Commands"
	@echo "  ─────────────────────────────────────────────────"
	@echo "  make install        Install production dependencies"
	@echo "  make install-dev    Install dev + test dependencies"
	@echo "  make up             Start local Docker services"
	@echo "  make down           Stop Docker services"
	@echo "  make demo           Run end-to-end pipeline demo"
	@echo "  make test           Run full test suite"
	@echo "  make lint           Run code linter"
	@echo "  make clean          Remove build artifacts"
	@echo ""
