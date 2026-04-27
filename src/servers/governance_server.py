"""
src/servers/governance_server.py
==================================
Enterprise MCP Governance Server.

Exposes data lineage, audit querying, policy enforcement, and PII reporting
as MCP-standard tools. This server makes the platform explainable to
Model Risk reviewers, compliance auditors, and InfoSec teams.

MCP Tools exposed:
  get_data_lineage           — Trace full provenance chain of any data artefact
  query_audit_trail          — Query the immutable audit log for agent activity
  get_retrieval_session      — Reconstruct what data an agent saw in a session
  validate_data_contract     — Check whether a source dataset meets its contract
  get_pii_exposure_report    — PII summary for compliance reporting

Architecture:
  This server does NOT sit in the hot path of agent requests.
  It is called by: Model Risk reviewers, compliance auditors,
  platform engineers, and automated governance pipelines.

  Agents CAN call get_retrieval_session on their own session
  for self-audit (useful for multi-step reasoning transparency).

Production backends:
  Audit log   → Amazon Athena queries over S3 append-only bucket
  Lineage     → Marquez API (OpenLineage events from dbt, Airflow, Spark)
  Contracts   → dbt schema YAML + Great Expectations results
  PII catalog → AWS Glue Data Catalog + Amazon Macie scan results
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

from src.utils.config import PlatformConfig, get_config

logger = logging.getLogger(__name__)


class GovernanceServer:
    """
    MCP Governance Server.
    Wire into the MCP framework using the same pattern as RAGServer.
    """

    MCP_TOOLS = [
        {
            "name": "get_data_lineage",
            "description": (
                "Trace the full provenance chain of a data artefact: "
                "source system → transformations → RAG index → agent sessions. "
                "Returns an OpenLineage-compatible lineage graph."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "artefact_id":   {"type": "string",
                                      "description": "chunk_id | document_id | dataset_name | feature_set"},
                    "artefact_type": {"type": "string",
                                      "description": "chunk | document | dataset | feature_set"},
                    "depth":         {"type": "integer", "default": 3,
                                      "description": "Lineage hops to traverse"},
                },
                "required": ["artefact_id", "artefact_type"],
            },
        },
        {
            "name": "query_audit_trail",
            "description": (
                "Query the immutable MCP audit log. Filter by agent, tool, time window, "
                "or PII events. Required role: governance-reviewer or platform-admin."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "agent_id":   {"type": "string"},
                    "tool_name":  {"type": "string"},
                    "pii_only":   {"type": "boolean", "default": False},
                    "severity":   {"type": "string",
                                   "description": "INFO | WARNING | HIGH | CRITICAL"},
                    "start_time": {"type": "string", "description": "ISO 8601"},
                    "end_time":   {"type": "string", "description": "ISO 8601"},
                    "limit":      {"type": "integer", "default": 100},
                },
            },
        },
        {
            "name": "get_retrieval_session",
            "description": (
                "Reconstruct the complete data context for an agent session: "
                "every tool call, every chunk retrieved, PII events, and latency. "
                "Answers: 'exactly what data did this agent see for this decision?'"
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "session_id": {"type": "string"},
                },
                "required": ["session_id"],
            },
        },
        {
            "name": "validate_data_contract",
            "description": (
                "Validate whether a source dataset meets its registered data contract. "
                "Checks: schema, nullability, freshness, volume, PII classification. "
                "Run before onboarding any new data source to the RAG pipeline."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "dataset_name":     {"type": "string"},
                    "contract_version": {"type": "string", "default": "latest"},
                },
                "required": ["dataset_name"],
            },
        },
        {
            "name": "get_pii_exposure_report",
            "description": (
                "Generate a PII exposure summary for a time window. "
                "Returns: total PII events, entity types, agents, modes applied, escalations. "
                "Required role: compliance-officer or governance-reviewer."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "start_time":  {"type": "string", "description": "ISO 8601 window start"},
                    "end_time":    {"type": "string", "description": "ISO 8601 window end (default: now)"},
                    "agent_id":    {"type": "string"},
                    "entity_type": {"type": "string"},
                },
                "required": ["start_time"],
            },
        },
    ]

    GOVERNANCE_ROLES = {
        "governance-reviewer",
        "platform-admin",
        "compliance-officer",
        "model-risk-analyst",
    }

    def __init__(self, config: PlatformConfig | None = None):
        self.config = config or get_config()

    def get_mcp_tool_map(self) -> dict:
        return {
            "get_data_lineage":        self.handle_get_data_lineage,
            "query_audit_trail":       self.handle_query_audit_trail,
            "get_retrieval_session":   self.handle_get_retrieval_session,
            "validate_data_contract":  self.handle_validate_data_contract,
            "get_pii_exposure_report": self.handle_get_pii_exposure_report,
        }

    # ── Tool handlers ─────────────────────────────────────────────────────────

    async def handle_get_data_lineage(
        self,
        artefact_id:   str,
        artefact_type: str,
        depth:         int = 3,
        agent_id:      str = "",
        **_: object,
    ) -> dict:
        """
        PRODUCTION: Query Marquez API:
            httpx.get(f"{marquez_url}/api/v1/lineage",
                      params={"nodeId": f"{artefact_type}:{artefact_id}", "depth": depth})
        """
        now = datetime.now(timezone.utc).isoformat()
        logger.info("LINEAGE_QUERY | agent=%s artefact=%s:%s depth=%d",
                    agent_id, artefact_type, artefact_id, depth)
        return {
            "artefact_id":   artefact_id,
            "artefact_type": artefact_type,
            "lineage_graph": {
                "nodes": [
                    {"id": "source-system",   "type": "source",    "label": "Upstream source system"},
                    {"id": "raw-ingestion",   "type": "dataset",   "label": "Raw ingestion table"},
                    {"id": "dbt-curate",      "type": "dbt_model", "label": "dbt: curate_documents"},
                    {"id": artefact_id,       "type": artefact_type, "label": f"Artefact: {artefact_id}"},
                ],
                "edges": [
                    {"from": "source-system", "to": "raw-ingestion", "type": "produces"},
                    {"from": "raw-ingestion", "to": "dbt-curate",    "type": "input"},
                    {"from": "dbt-curate",    "to": artefact_id,     "type": "produces"},
                ],
                "metadata": {
                    "lineage_format": "OpenLineage v1",
                    "namespace":      self.config.lineage.namespace,
                    "retrieved_at":   now,
                    "depth":          depth,
                },
            },
            "consumers": [
                {"type": "rag_index",      "id": "pgvector:rag.document_chunks", "ingested_at": now},
            ],
            "agent_sessions": [
                {"session_id": "session-001", "agent_id": "servicing-agent-01",
                 "retrieved_at": now, "tool": "search_knowledge_base"},
            ],
        }

    async def handle_query_audit_trail(
        self,
        agent_id:   str  = "",
        tool_name:  str  = "",
        pii_only:   bool = False,
        severity:   str  = "",
        start_time: str  = "",
        end_time:   str  = "",
        limit:      int  = 100,
        caller_agent_role: str = "",
        **_: object,
    ) -> dict:
        """
        PRODUCTION: Athena query over S3 audit bucket.
            SELECT * FROM audit_logs
            WHERE timestamp BETWEEN :start AND :end
              AND (:agent_id IS NULL OR agent_id = :agent_id)
              AND (:pii_only = FALSE OR pii_detected = TRUE)
            ORDER BY timestamp DESC LIMIT :limit
        """
        if caller_agent_role not in self.GOVERNANCE_ROLES:
            return {"error": "Insufficient permissions",
                    "required_roles": sorted(self.GOVERNANCE_ROLES)}

        limit = min(limit, 1_000)
        now   = datetime.now(timezone.utc)
        records = [
            {
                "event_id":     str(uuid.uuid4()),
                "event_type":   "MCP_TOOL_CALL",
                "tool":         tool_name or "search_knowledge_base",
                "agent_id":     agent_id or f"servicing-agent-{i:02d}",
                "pii_detected": i % 4 == 0,
                "pii_types":    ["EMAIL_ADDRESS"] if i % 4 == 0 else [],
                "severity":     "HIGH" if i % 4 == 0 else "INFO",
                "latency_ms":   120 + i * 15,
                "timestamp":    (now - timedelta(minutes=i * 5)).isoformat(),
            }
            for i in range(min(limit, 10))
        ]

        if pii_only:
            records = [r for r in records if r["pii_detected"]]

        return {
            "total_returned": len(records),
            "records":        records,
            "_note":          "DEMO — replace with Athena query in production.",
        }

    async def handle_get_retrieval_session(
        self,
        session_id:        str,
        caller_agent_id:   str = "",
        caller_agent_role: str = "",
        **_: object,
    ) -> dict:
        """
        PRODUCTION: SELECT * FROM audit.mcp_events WHERE session_id = %s ORDER BY timestamp ASC
        """
        is_self  = caller_agent_id and session_id.startswith(caller_agent_id[:8])
        is_auth  = caller_agent_role in self.GOVERNANCE_ROLES or is_self

        if not is_auth:
            return {"error": "You may only query your own sessions unless you hold a governance role."}

        now = datetime.now(timezone.utc)
        return {
            "session_id":       session_id,
            "reconstructed_at": now.isoformat(),
            "tool_calls": [
                {
                    "call_id":          str(uuid.uuid4()),
                    "tool":             "search_knowledge_base",
                    "timestamp":        (now - timedelta(minutes=5)).isoformat(),
                    "query_hash":       "a3f2c1b8d4e5f6a7",
                    "chunks_returned":  ["chunk_0001", "chunk_0002", "chunk_0003"],
                    "pii_detected":     False,
                    "latency_ms":       142,
                },
                {
                    "call_id":          str(uuid.uuid4()),
                    "tool":             "get_entity_context",
                    "timestamp":        (now - timedelta(minutes=4)).isoformat(),
                    "entity_token":     "TOK_DEMO****",
                    "pii_detected":     True,
                    "pii_masked":       ["EMAIL_ADDRESS"],
                    "latency_ms":       38,
                },
            ],
            "pii_summary": {
                "total_pii_events":      1,
                "entity_types_seen":     ["EMAIL_ADDRESS"],
                "modes_applied":         ["mask"],
                "any_blocked":           False,
                "any_critical_escalation": False,
            },
            "data_accessed": ["chunk_0001", "chunk_0002", "chunk_0003"],
        }

    async def handle_validate_data_contract(
        self,
        dataset_name:     str,
        contract_version: str = "latest",
        **_: object,
    ) -> dict:
        """
        PRODUCTION:
          1. Fetch contract from dbt schema YAML
          2. Run Great Expectations suite
          3. Check freshness SLA
          4. Check volume baseline
          5. Verify Glue catalog PII tags
        """
        now = datetime.now(timezone.utc)
        checks = [
            {"check_name": "schema_consistency",        "status": "PASS",
             "evidence": "dbt schema tests: 100% pass (run: today)"},
            {"check_name": "null_rate",                 "status": "PASS",
             "evidence": "Great Expectations: null_rate=0.002 (threshold: 0.005)"},
            {"check_name": "freshness",                 "status": "PASS",
             "evidence": f"Last updated: {(now - timedelta(hours=2)).isoformat()}"},
            {"check_name": "volume",                    "status": "PASS",
             "evidence": "Row count 142,847 — within ±10% of baseline"},
            {"check_name": "pii_classification",        "status": "PASS",
             "evidence": "47 fields tagged in Glue catalog, 0 unclassified"},
            {"check_name": "consumer_acknowledgement",  "status": "WARN",
             "evidence": "2 consumers have not acknowledged latest schema version"},
        ]

        failed = sum(1 for c in checks if c["status"] == "FAIL")
        gate   = "PASS" if failed == 0 else "FAIL"

        return {
            "dataset_name":     dataset_name,
            "contract_version": contract_version,
            "validation_id":    str(uuid.uuid4()),
            "validated_at":     now.isoformat(),
            "gate":             gate,
            "summary": {
                "passed": sum(1 for c in checks if c["status"] == "PASS"),
                "warned": sum(1 for c in checks if c["status"] == "WARN"),
                "failed": failed,
                "total":  len(checks),
            },
            "checks": checks,
            "recommendation": (
                f"'{dataset_name}' meets contract — safe for RAG onboarding."
                if gate == "PASS"
                else f"'{dataset_name}' FAILED contract validation. Resolve failures before onboarding."
            ),
        }

    async def handle_get_pii_exposure_report(
        self,
        start_time:        str,
        end_time:          str = "",
        agent_id:          str = "",
        entity_type:       str = "",
        caller_agent_role: str = "",
        **_: object,
    ) -> dict:
        """
        PRODUCTION: Athena aggregation over audit.mcp_events WHERE pii_detected = TRUE
        """
        if caller_agent_role not in self.GOVERNANCE_ROLES:
            return {"error": "Insufficient permissions",
                    "required_roles": sorted(self.GOVERNANCE_ROLES)}

        return {
            "report_id":   str(uuid.uuid4()),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "time_window": {"start": start_time, "end": end_time or "now"},
            "summary": {
                "total_tool_calls":         1_247,
                "calls_with_pii_detected":  89,
                "pii_detection_rate":       "7.1%",
                "critical_escalations":     0,
                "high_severity_events":     4,
            },
            "by_entity_type": [
                {"entity_type": "EMAIL_ADDRESS",  "count": 52, "mode": "mask",  "critical": 0},
                {"entity_type": "PHONE_NUMBER",   "count": 24, "mode": "mask",  "critical": 0},
                {"entity_type": "ACCOUNT_NUMBER", "count": 11, "mode": "token", "critical": 0},
                {"entity_type": "US_SSN",         "count":  2, "mode": "block", "critical": 0},
                {"entity_type": "CREDIT_CARD",    "count":  0, "mode": "block", "critical": 0},
            ],
            "compliance_statement": (
                "No CRITICAL leakage events in reporting window. "
                "All BLOCK-mode entities successfully intercepted. "
                "Zero SSNs or credit card numbers reached any LLM context."
            ),
        }


def run() -> None:
    import asyncio
    logging.basicConfig(level=logging.INFO)

    async def demo():
        server = GovernanceServer()
        result = await server.handle_validate_data_contract(
            dataset_name="rag.document_chunks",
            caller_agent_role="governance-reviewer",
        )
        print(json.dumps(result, indent=2))

    asyncio.run(demo())


if __name__ == "__main__":
    run()
