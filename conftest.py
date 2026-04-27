"""
conftest.py
============
Pytest configuration and shared fixtures for the Enterprise MCP AI Platform.

This file makes the project pytest-compatible while keeping all tests
runnable as plain Python scripts (no pytest required).

When pytest IS installed:
    python -m pytest tests/ -v
    python -m pytest tests/test_pii_shield.py -v -k "test_block"

When pytest is NOT installed:
    python scripts/run_tests.py          # master runner
    python tests/test_pii_shield.py      # individual suite
"""

from __future__ import annotations

import os
import sys

# Ensure src/ is importable from all test contexts
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest

from src.guardrails.pii_shield import (
    PIIConfig,
    PIIEntityConfig,
    PIIEntityType,
    PIIMode,
    PIIShield,
)
from src.guardrails.prompt_guard import PromptGuard, ResponseGuard


# ── Shared fixtures ───────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def default_pii_config() -> PIIConfig:
    """Standard PII config used across most tests."""
    return PIIConfig(
        entities=[
            PIIEntityConfig(PIIEntityType.SSN,            PIIMode.BLOCK, 0.70),
            PIIEntityConfig(PIIEntityType.CREDIT_CARD,    PIIMode.BLOCK, 0.75),
            PIIEntityConfig(PIIEntityType.EMAIL,          PIIMode.MASK,  0.90,
                            allowed_agent_roles=["collections-agent", "servicing-agent"]),
            PIIEntityConfig(PIIEntityType.PHONE,          PIIMode.MASK,  0.75,
                            allowed_agent_roles=["collections-agent"]),
            PIIEntityConfig(PIIEntityType.ACCOUNT_NUMBER, PIIMode.TOKEN, 0.85,
                            allowed_agent_roles=["fraud-agent"]),
            PIIEntityConfig(PIIEntityType.PERSON_NAME,    PIIMode.MASK,  0.80),
            PIIEntityConfig(PIIEntityType.ADDRESS,        PIIMode.MASK,  0.75),
        ],
        global_mode=PIIMode.MASK,
        block_on_unknown_agent=True,
        audit_all_events=False,
    )


@pytest.fixture(scope="session")
def pii_shield(default_pii_config) -> PIIShield:
    """Shared PIIShield instance (session-scoped — immutable after creation)."""
    return PIIShield(config=default_pii_config)


@pytest.fixture
def prompt_guard_strict(pii_shield) -> PromptGuard:
    """PromptGuard in strict mode (raises on detection)."""
    return PromptGuard(pii_shield=pii_shield, strict_mode=True)


@pytest.fixture
def prompt_guard_lenient(pii_shield) -> PromptGuard:
    """PromptGuard in non-strict mode (sanitizes, does not raise)."""
    return PromptGuard(pii_shield=pii_shield, strict_mode=False)


@pytest.fixture
def response_guard_blocking(pii_shield) -> ResponseGuard:
    """ResponseGuard that blocks (raises PIILeakageError) on detection."""
    return ResponseGuard(pii_shield=pii_shield, block_on_never_patterns=True)


@pytest.fixture
def response_guard_logging(pii_shield) -> ResponseGuard:
    """ResponseGuard that logs but does not block — for assertion testing."""
    return ResponseGuard(pii_shield=pii_shield, block_on_never_patterns=False)


@pytest.fixture
def rag_server():
    """Initialised RAGServer with demo stubs."""
    from src.servers.rag_server import RAGServer
    s = RAGServer()
    s.startup()
    return s


@pytest.fixture
def feature_store_server():
    """Initialised FeatureStoreServer."""
    from src.servers.feature_store_server import FeatureStoreServer
    return FeatureStoreServer()


# ── Pytest markers ────────────────────────────────────────────────────────────

def pytest_configure(config):
    config.addinivalue_line("markers", "unit: fast unit tests with no external dependencies")
    config.addinivalue_line("markers", "integration: tests that use server components")
    config.addinivalue_line("markers", "e2e: full end-to-end pipeline tests")
    config.addinivalue_line("markers", "guardrail: PII guardrail correctness tests — must never skip")


# ── Common test data ──────────────────────────────────────────────────────────

CLEAN_TEXTS = [
    "The dispute resolution process takes 10 business days.",
    "Review the merchant's refund policy before escalating.",
    "Payment amount was $127.50 for a restaurant charge on 2024-01-15.",
    "Account opened in Q3 2022 with standard credit terms.",
    "Risk assessment complete. No issues found at this time.",
    "",
]

PII_TEXTS = {
    "ssn":         "Customer SSN is 123-45-6789.",
    "credit_card": "Card number 4532-0151-1283-0366 was declined.",
    "email":       "Contact user@example.com for follow-up.",
    "phone":       "Call 415-555-1234 for support.",
    "account":     "Account ENT-1234567890 is flagged.",
}

AGENT_ROLES = {
    "standard":    "analyst",
    "collections": "collections-agent",
    "servicing":   "servicing-agent",
    "fraud":       "fraud-agent",
    "ml":          "ml-service",
    "public":      "public",
}
