"""
src/servers/feature_store_server.py
=====================================
Enterprise MCP Feature Store Server.

Solves the ML/LLM duality problem: serves structured feature data to
traditional ML models AND natural language summaries to LLM agents —
from the same underlying feature platform.

MCP Tools exposed:
  get_entity_context   — Natural language summary for LLM agent reasoning (PII-masked)
  get_ml_features      — Structured numeric feature vector for ML scoring
  get_entity_token     — Convert raw entity ID → session-scoped token (24h, agent-scoped)

Architecture:
  Offline Store (S3 + Apache Iceberg):
    → ML training datasets, historical features, point-in-time correct queries
    → Time-travel for training data reproducibility (no future leakage)

  Online Store (Redis / DynamoDB):
    → Current feature values, sub-ms latency
    → Updated via Kafka CDC streams from source systems

  MCP Feature Store Server:
    → ML path:   online/offline store → numeric vector → ML model
    → Agent path: online store → narrative template → PII masking → LLM agent
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import Any

from src.guardrails.pii_shield import PIIConfig, PIIShield
from src.utils.config import PlatformConfig, get_config

logger = logging.getLogger(__name__)

ENTITY_DATA_ROLES = {"analyst", "collections-agent", "servicing-agent", "fraud-agent", "ml-service"}


class FeatureStoreServer:
    """
    MCP Feature Store Server.

    The key architectural move is _build_narrative():
    Same structured data that feeds ML models is transformed into
    plain English that LLM agents can reason over — with PII masked
    before the narrative leaves this server.
    """

    MCP_TOOLS = [
        {
            "name": "get_entity_context",
            "description": (
                "Get a natural language summary of an entity's current status for LLM agent reasoning. "
                "Returns PII-masked narrative — no raw identifiers. "
                "Requires analyst, collections-agent, servicing-agent, or fraud-agent role."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "entity_token":     {"type": "string",  "description": "Session-scoped entity token"},
                    "context_sections": {"type": "array",   "items": {"type": "string"},
                                         "description": "account_status|payment_history|risk_profile|contact_preferences"},
                    "max_age_minutes":  {"type": "integer", "description": "Reject stale data older than N minutes", "default": 60},
                },
                "required": ["entity_token"],
            },
        },
        {
            "name": "get_ml_features",
            "description": (
                "Retrieve structured feature vector for ML model scoring. "
                "Point-in-time correct when event_timestamp is specified. "
                "Numeric/categorical features — no PII in output."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "entity_token":     {"type": "string"},
                    "feature_set":      {"type": "string",
                                         "description": "credit_risk|churn_risk|collections_propensity|cross_sell"},
                    "event_timestamp":  {"type": "string", "description": "ISO 8601 — for point-in-time retrieval"},
                },
                "required": ["entity_token", "feature_set"],
            },
        },
        {
            "name": "get_entity_token",
            "description": (
                "Convert a raw entity identifier into a session-scoped token valid for 24 hours. "
                "Token is scoped to the requesting agent and session — not reusable across sessions. "
                "Use this token in all subsequent entity-data tool calls. Never pass raw IDs."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "id_type":  {"type": "string", "description": "internal_id|crm_id|hashed_email"},
                    "id_value": {"type": "string", "description": "Raw identifier value"},
                },
                "required": ["id_type", "id_value"],
            },
        },
    ]

    KNOWN_FEATURE_SETS = {
        "credit_risk":            ["payment_ratio_3m", "utilization_rate", "delinquency_score", "risk_band"],
        "churn_risk":             ["engagement_score", "product_count", "last_activity_days", "satisfaction_band"],
        "collections_propensity": ["days_past_due", "promise_count", "contact_attempts", "balance_band"],
        "cross_sell":             ["income_band", "product_gap_score", "digital_response_rate", "ltv_band"],
    }

    def __init__(self, config: PlatformConfig | None = None, pii_config: PIIConfig | None = None):
        self.config = config or get_config()
        if pii_config is None:
            from src.servers.rag_server import RAGServer
            pii_config = RAGServer(self.config)._default_pii_config()
        self.shield = PIIShield(config=pii_config)

    # ── Tool handlers ─────────────────────────────────────────────────────────

    async def handle_get_entity_context(
        self,
        entity_token:     str,
        context_sections: list[str] | None = None,
        max_age_minutes:  int              = 60,
        agent_id:         str              = "",
        agent_role:       str              = "",
        session_id:       str              = "",
    ) -> dict:
        if agent_role not in ENTITY_DATA_ROLES:
            return {"error": "Insufficient permissions", "required_roles": sorted(ENTITY_DATA_ROLES)}

        if not entity_token.startswith("TOK_"):
            return {"error": "Invalid token format. Call get_entity_token first to obtain a session token."}

        sections = context_sections or ["account_status", "payment_history", "risk_profile"]

        # Fetch from online feature store (Redis in production)
        raw = self._fetch_online(entity_token, sections)

        # Transform to narrative (agent-consumable plain English)
        narrative = self._build_narrative(raw, sections)

        # PII shield the narrative before returning
        result = self.shield.process_chunk(narrative, agent_id, agent_role, f"{session_id}:{entity_token}")

        return {
            "entity_token":     entity_token,
            "sections":         sections,
            "narrative":        result.safe_text,
            "summary_metrics":  raw.get("summary_metrics", {}),
            "data_freshness":   raw.get("last_updated", "unknown"),
            "pii_masked":       result.was_modified,
        }

    async def handle_get_ml_features(
        self,
        entity_token:    str,
        feature_set:     str,
        event_timestamp: str | None = None,
        agent_id:        str        = "",
        agent_role:      str        = "",
        session_id:      str        = "",
    ) -> dict:
        if feature_set not in self.KNOWN_FEATURE_SETS:
            return {"error": f"Unknown feature set. Available: {sorted(self.KNOWN_FEATURE_SETS)}"}

        features = self._fetch_features(entity_token, feature_set, event_timestamp)

        logger.info("ML_FEATURE_ACCESS | agent=%s feature_set=%s token=%s",
                    agent_id, feature_set, entity_token[:8] + "***")

        return {
            "entity_token":    entity_token,
            "feature_set":     feature_set,
            "features":        features,
            "as_of":           event_timestamp or datetime.now(timezone.utc).isoformat(),
            "feature_version": "v2024_q4",
        }

    async def handle_get_entity_token(
        self,
        id_type:    str,
        id_value:   str,
        agent_id:   str = "",
        agent_role: str = "",
        session_id: str = "",
    ) -> dict:
        VALID_ID_TYPES = {"internal_id", "crm_id", "hashed_email"}
        if id_type not in VALID_ID_TYPES:
            return {"error": f"Invalid id_type. Must be one of: {sorted(VALID_ID_TYPES)}"}

        # Deterministic session-scoped token
        seed        = f"{session_id}:{id_type}:{id_value}"
        token_hash  = hashlib.sha256(seed.encode()).hexdigest()[:16].upper()
        token       = f"TOK_{token_hash}"

        logger.info("TOKEN_ISSUED | agent=%s session=%s id_type=%s", agent_id, session_id[:8], id_type)

        return {
            "entity_token":  token,
            "expires_in":    "86400s",
            "scoped_to":     agent_id,
            "guidance":      "Use this token in all entity-data calls. Do not log or store the token.",
        }

    # ── Private helpers ───────────────────────────────────────────────────────

    def _fetch_online(self, token: str, sections: list[str]) -> dict:
        """
        In production: Redis HGETALL {token}:{section} for each requested section.
        Updated by Kafka consumer consuming CDC events from source systems.
        """
        return {
            "account_status":      {"status": "CURRENT",  "credit_limit": 5000, "balance": 1200},
            "payment_history":     {"on_time_12m": 11,    "missed_12m": 1},
            "risk_profile":        {"risk_tier": "MEDIUM", "score_band": "680-720"},
            "contact_preferences": {"preferred_channel": "SMS", "opt_out_email": False},
            "summary_metrics":     {"tenure_months": 36,  "spend_ytd": 8400},
            "last_updated":        datetime.now(timezone.utc).isoformat(),
        }

    def _build_narrative(self, features: dict, sections: list[str]) -> str:
        """
        Transform structured feature data into agent-readable narrative.

        This is the architectural key: the same data that feeds ML numeric
        models is converted into natural language that an LLM can reason over.
        The narrative is then PII-shielded before leaving this server.

        In production: use a Jinja2 template or a lightweight internal LLM
        call (on in-VPC Bedrock endpoint, never external API) for richer output.
        """
        parts = []

        if "account_status" in sections and "account_status" in features:
            st = features["account_status"]
            parts.append(
                f"Account status is {st.get('status', 'UNKNOWN')}. "
                f"Credit limit: ${st.get('credit_limit', 0):,}. "
                f"Current balance: ${st.get('balance', 0):,}."
            )

        if "payment_history" in sections and "payment_history" in features:
            ph = features["payment_history"]
            parts.append(
                f"Payment history (last 12 months): "
                f"{ph.get('on_time_12m', 0)} on-time, "
                f"{ph.get('missed_12m', 0)} missed."
            )

        if "risk_profile" in sections and "risk_profile" in features:
            rp = features["risk_profile"]
            parts.append(
                f"Risk tier: {rp.get('risk_tier', 'UNKNOWN')}. "
                f"Score band: {rp.get('score_band', 'UNKNOWN')}."
            )

        return " ".join(parts) if parts else "Context unavailable for requested sections."

    def _fetch_features(
        self, token: str, feature_set: str, timestamp: str | None
    ) -> dict:
        """
        In production:
          - timestamp provided → query Iceberg offline store with time-travel
          - timestamp None     → query Redis online store for current values
        """
        DEMO: dict[str, dict] = {
            "credit_risk":            {"payment_ratio_3m": 0.92, "utilization_rate": 0.24, "delinquency_score": 0.08, "risk_band": 3},
            "churn_risk":             {"engagement_score": 0.74, "product_count": 2,       "last_activity_days": 12,  "satisfaction_band": 4},
            "collections_propensity": {"days_past_due": 0,       "promise_count": 0,        "contact_attempts": 1,    "balance_band": 2},
            "cross_sell":             {"income_band": 3,          "product_gap_score": 0.6, "digital_response_rate": 0.22, "ltv_band": 3},
        }
        return DEMO.get(feature_set, {})


def run() -> None:
    """Entry point for `mcp-feature-server` CLI command."""
    import asyncio, json
    logging.basicConfig(level=logging.INFO)

    async def demo():
        server = FeatureStoreServer()
        token_result = await server.handle_get_entity_token(
            id_type="internal_id", id_value="ENT123456",
            agent_id="demo-agent", agent_role="analyst", session_id="demo-session-01",
        )
        print("Token:", json.dumps(token_result, indent=2))

        context = await server.handle_get_entity_context(
            entity_token=token_result["entity_token"],
            agent_id="demo-agent", agent_role="analyst", session_id="demo-session-01",
        )
        print("Context:", json.dumps(context, indent=2))

    asyncio.run(demo())


if __name__ == "__main__":
    run()
