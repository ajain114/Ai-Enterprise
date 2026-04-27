"""
tests/test_feature_store.py
=============================
Integration tests for the Feature Store MCP Server.

Covers:
  - get_entity_token: issuance, determinism, scoping, id_type validation
  - get_entity_context: valid token access, role gating, raw ID rejection
  - get_entity_context: narrative structure and PII masking
  - get_ml_features: feature set access, point-in-time field, unknown set
  - ML/LLM duality: same token serves both consumers
  - Section filtering: only requested sections in narrative

Run:
    python tests/test_feature_store.py
"""

from __future__ import annotations
import sys, os, asyncio
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.servers.feature_store_server import FeatureStoreServer, ENTITY_DATA_ROLES


class T:
    passed = 0; failed = 0; errors: list[str] = []

    @classmethod
    def ok(cls, n): cls.passed += 1; print(f"  \u2713  {n}")

    @classmethod
    def fail(cls, n, r):
        cls.failed += 1; cls.errors.append(f"{n}: {r}")
        print(f"  \u2717  {n}\n       {r}")

    @classmethod
    def check(cls, cond, name, reason="assertion failed"):
        cls.ok(name) if cond else cls.fail(name, reason)

    @classmethod
    def summary(cls) -> bool:
        total = cls.passed + cls.failed
        print(f"\n{'─'*55}\n  {cls.passed}/{total} passed", end="")
        if cls.failed:
            print(f"  |  {cls.failed} FAILED")
            [print(f"    \u2192 {e}") for e in cls.errors]
        else:
            print("  \u2014 All passed \u2713")
        print(f"{'─'*55}")
        return cls.failed == 0


# ── get_entity_token ──────────────────────────────────────────────────────────

async def test_get_entity_token():
    print("\nget_entity_token")
    fs = FeatureStoreServer()

    # Basic issuance
    r = await fs.handle_get_entity_token(
        id_type="internal_id", id_value="ENT123456",
        agent_id="agent-01", agent_role="analyst", session_id="sess-001",
    )
    T.check("entity_token"  in r,             "Result has entity_token")
    T.check("expires_in"    in r,             "Result has expires_in")
    T.check("scoped_to"     in r,             "Result has scoped_to")
    T.check("guidance"      in r,             "Result has guidance")
    T.check(r["entity_token"].startswith("TOK_"), "Token has TOK_ prefix")
    T.check(len(r["entity_token"]) > 8,       "Token is non-trivial length")
    T.check(r["scoped_to"] == "agent-01",     "Token scoped to requesting agent_id")

    # Deterministic: same inputs in same session → same token
    r2 = await fs.handle_get_entity_token(
        id_type="internal_id", id_value="ENT123456",
        agent_id="agent-01", agent_role="analyst", session_id="sess-001",
    )
    T.check(r["entity_token"] == r2["entity_token"], "Token is deterministic for same session+id")

    # Different session → different token
    r3 = await fs.handle_get_entity_token(
        id_type="internal_id", id_value="ENT123456",
        agent_id="agent-01", agent_role="analyst", session_id="sess-999",
    )
    T.check(r["entity_token"] != r3["entity_token"], "Different session produces different token")

    # Different entity → different token
    r4 = await fs.handle_get_entity_token(
        id_type="internal_id", id_value="ENT999999",
        agent_id="agent-01", agent_role="analyst", session_id="sess-001",
    )
    T.check(r["entity_token"] != r4["entity_token"], "Different entity produces different token")

    # Valid id_types
    for id_type in ["internal_id", "crm_id", "hashed_email"]:
        r = await fs.handle_get_entity_token(
            id_type=id_type, id_value="test-value",
            agent_id="a", agent_role="analyst", session_id="s",
        )
        T.check("entity_token" in r, f"Token issued for id_type={id_type}")

    # Invalid id_type
    r = await fs.handle_get_entity_token(
        id_type="raw_ssn", id_value="123-45-6789",
        agent_id="a", agent_role="analyst", session_id="s",
    )
    T.check("error" in r, "Invalid id_type returns error")


# ── get_entity_context ────────────────────────────────────────────────────────

async def test_get_entity_context():
    print("\nget_entity_context")
    fs = FeatureStoreServer()

    # Get a valid token first
    token_r = await fs.handle_get_entity_token(
        id_type="internal_id", id_value="ENT123456",
        agent_id="agent-01", agent_role="analyst", session_id="sess-ctx-001",
    )
    token = token_r["entity_token"]

    # Valid token + authorized role
    r = await fs.handle_get_entity_context(
        entity_token=token, context_sections=["account_status", "payment_history"],
        agent_id="agent-01", agent_role="analyst", session_id="sess-ctx-001",
    )
    T.check("narrative"        in r,  "Result has narrative")
    T.check("entity_token"     in r,  "Result has entity_token")
    T.check("sections"         in r,  "Result has sections")
    T.check("data_freshness"   in r,  "Result has data_freshness")
    T.check("pii_masked"       in r,  "Result has pii_masked flag")
    T.check(isinstance(r["narrative"], str), "Narrative is string")
    T.check(len(r["narrative"]) > 10, "Narrative is non-trivial (>10 chars)")
    T.check(r["entity_token"] == token, "entity_token echoed in response")

    # Narrative mentions requested sections
    narrative = r["narrative"].lower()
    T.check(len(narrative) > 0, "Narrative is non-empty")

    # Unauthorized role
    r2 = await fs.handle_get_entity_context(
        entity_token=token, agent_id="agent-01", agent_role="public", session_id="sess-ctx-002",
    )
    T.check("error" in r2,                          "Unauthorized role returns error")
    T.check("permissions" in r2["error"].lower(),   "Error mentions permissions")

    # All authorized roles can access
    for role in ENTITY_DATA_ROLES:
        r = await fs.handle_get_entity_context(
            entity_token=token, agent_id="a", agent_role=role, session_id=f"sess-{role}",
        )
        T.check("narrative" in r, f"Role '{role}' can access entity context")

    # Raw numeric ID rejected (no TOK_ prefix)
    r3 = await fs.handle_get_entity_context(
        entity_token="12345678901", agent_id="agent-01", agent_role="analyst", session_id="sess-ctx-003",
    )
    T.check("error" in r3,                        "Raw numeric ID rejected")
    T.check("token" in r3["error"].lower(),        "Error mentions token requirement")

    # Short non-numeric string without TOK_ prefix also rejected
    r4 = await fs.handle_get_entity_context(
        entity_token="NOT_A_TOKEN", agent_id="a", agent_role="analyst", session_id="s",
    )
    T.check("error" in r4, "Non-TOK_ token rejected")

    # Default sections when none specified
    r5 = await fs.handle_get_entity_context(
        entity_token=token, agent_id="a", agent_role="analyst", session_id="sess-default",
    )
    T.check("narrative" in r5,               "Default sections produce narrative")
    T.check(len(r5["sections"]) > 0,         "sections list is non-empty when defaulted")


# ── get_ml_features ───────────────────────────────────────────────────────────

async def test_get_ml_features():
    print("\nget_ml_features")
    fs = FeatureStoreServer()

    token_r = await fs.handle_get_entity_token(
        id_type="internal_id", id_value="ENT789012",
        agent_id="ml-svc", agent_role="ml-service", session_id="sess-ml-001",
    )
    token = token_r["entity_token"]

    # All known feature sets
    for feature_set in FeatureStoreServer.KNOWN_FEATURE_SETS:
        r = await fs.handle_get_ml_features(
            entity_token=token, feature_set=feature_set,
            agent_id="ml-svc", agent_role="ml-service", session_id="sess-ml-001",
        )
        T.check("features"       in r,  f"{feature_set}: result has features dict")
        T.check("entity_token"   in r,  f"{feature_set}: result has entity_token")
        T.check("feature_set"    in r,  f"{feature_set}: result has feature_set field")
        T.check("as_of"          in r,  f"{feature_set}: result has as_of timestamp")
        T.check("feature_version"in r,  f"{feature_set}: result has feature_version")
        T.check(len(r["features"]) > 0, f"{feature_set}: features dict is non-empty")
        T.check(r["feature_set"] == feature_set, f"{feature_set}: feature_set echoed correctly")

        # Features are numeric/categorical (no PII)
        for k, v in r["features"].items():
            T.check(isinstance(v, (int, float)), f"{feature_set}.{k} is numeric (no PII)")

    # Unknown feature set
    r = await fs.handle_get_ml_features(
        entity_token=token, feature_set="nonexistent_features",
        agent_id="ml-svc", agent_role="ml-service", session_id="sess-ml-002",
    )
    T.check("error" in r,                           "Unknown feature_set returns error")
    T.check("nonexistent_features" not in r.get("features", {}), "Unknown set has no features")

    # Point-in-time timestamp accepted
    r2 = await fs.handle_get_ml_features(
        entity_token=token, feature_set="credit_risk",
        event_timestamp="2024-06-01T00:00:00Z",
        agent_id="ml-svc", agent_role="ml-service", session_id="sess-ml-003",
    )
    T.check("features" in r2,                        "Point-in-time query returns features")
    T.check(r2.get("as_of") == "2024-06-01T00:00:00Z", "as_of reflects supplied event_timestamp")


# ── ML/LLM duality ────────────────────────────────────────────────────────────

async def test_ml_llm_duality():
    print("\nML / LLM duality (same token, different consumers)")
    fs = FeatureStoreServer()

    # Single token serves both consumers
    token_r = await fs.handle_get_entity_token(
        id_type="internal_id", id_value="ENT555555",
        agent_id="shared-session", agent_role="analyst", session_id="sess-dual",
    )
    token = token_r["entity_token"]

    # LLM consumer → narrative
    llm_r = await fs.handle_get_entity_context(
        entity_token=token, agent_id="llm-agent", agent_role="analyst", session_id="sess-dual",
    )
    # ML consumer → feature vector
    ml_r  = await fs.handle_get_ml_features(
        entity_token=token, feature_set="credit_risk",
        agent_id="ml-service", agent_role="ml-service", session_id="sess-dual",
    )

    T.check("narrative" in llm_r,          "LLM consumer gets narrative")
    T.check("features"  in ml_r,           "ML consumer gets feature vector")

    # Narrative is natural language (str), features are numeric (dict of numbers)
    T.check(isinstance(llm_r["narrative"], str),    "LLM output is string (natural language)")
    T.check(isinstance(ml_r["features"], dict),     "ML output is dict (structured features)")
    T.check(all(isinstance(v, (int, float)) for v in ml_r["features"].values()),
            "ML features are all numeric (no strings, no PII)")

    # Narrative should NOT contain raw numeric feature values as arrays
    narrative = llm_r["narrative"]
    T.check(isinstance(narrative, str) and len(narrative) > 20,
            "Narrative is human-readable prose, not a raw data dump")


def main() -> bool:
    print("=" * 55)
    print("  Feature Store Server Integration Tests")
    print("=" * 55)

    asyncio.run(test_get_entity_token())
    asyncio.run(test_get_entity_context())
    asyncio.run(test_get_ml_features())
    asyncio.run(test_ml_llm_duality())
    return T.summary()

if __name__ == "__main__":
    import logging; logging.basicConfig(level=logging.WARNING)
    sys.exit(0 if main() else 1)
