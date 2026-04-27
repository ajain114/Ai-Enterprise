"""
src/utils/openlineage_client.py
=================================
OpenLineage event emitter for MCP server lineage tracking.

Captures lineage at every stage of the AI data pipeline:
  - Source system → raw ingestion
  - dbt transformation → curated dataset
  - Chunking + embedding → RAG index
  - Agent retrieval → context assembly
  - Context assembly → LLM call (prompt lineage)

OpenLineage spec: https://openlineage.io/spec/

In production: configure OPENLINEAGE_URL to point to Marquez,
Apache Atlas, or another OpenLineage-compatible backend.

Usage:
    client = LineageClient(config=get_config())

    # Emit a dataset lineage event (e.g. from dbt run)
    client.emit_dataset_event(
        job_name="curate_documents",
        input_datasets=["raw.document_ingestion"],
        output_datasets=["rag.document_chunks"],
    )

    # Emit a retrieval lineage event (from RAG server)
    client.emit_retrieval_event(
        session_id="session-001",
        agent_id="servicing-agent-01",
        query_hash="a3f2c1b8",
        chunk_ids=["chunk_0001", "chunk_0002"],
    )
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from src.utils.config import PlatformConfig, get_config

logger = logging.getLogger(__name__)


class LineageClient:
    """
    OpenLineage event emitter.

    In production: POSTs structured OpenLineage RunEvents to the
    configured OPENLINEAGE_URL endpoint (Marquez / Atlas).

    Locally: logs events as structured JSON for debugging.
    """

    OPENLINEAGE_VERSION = "1.0.0"

    def __init__(self, config: PlatformConfig | None = None):
        self.config    = config or get_config()
        self.namespace = self.config.lineage.namespace
        self.url       = self.config.lineage.url
        self._client   = None  # httpx.AsyncClient in production

    # ── High-level emitters ────────────────────────────────────────────────────

    def emit_dataset_event(
        self,
        job_name:        str,
        input_datasets:  list[str],
        output_datasets: list[str],
        run_id:          str | None = None,
        metadata:        dict       = {},
    ) -> str:
        """
        Emit a dataset transformation lineage event.
        Use when dbt models run, Airflow tasks complete, or Spark jobs finish.
        """
        run_id  = run_id or str(uuid.uuid4())
        event   = self._build_event(
            event_type="COMPLETE",
            job_name=job_name,
            run_id=run_id,
            inputs=[self._dataset(ds) for ds in input_datasets],
            outputs=[self._dataset(ds) for ds in output_datasets],
            metadata=metadata,
        )
        self._emit(event)
        return run_id

    def emit_retrieval_event(
        self,
        session_id:  str,
        agent_id:    str,
        query_hash:  str,
        chunk_ids:   list[str],
        tool_name:   str = "search_knowledge_base",
        metadata:    dict = {},
    ) -> str:
        """
        Emit a RAG retrieval lineage event.
        Called by the MCP RAG server on every tool invocation.
        Links: agent session → retrieved chunks → source documents.
        """
        run_id = str(uuid.uuid4())
        event  = self._build_event(
            event_type="COMPLETE",
            job_name=f"mcp.{tool_name}",
            run_id=run_id,
            inputs=[self._dataset(f"pgvector:rag.document_chunks:{cid}") for cid in chunk_ids],
            outputs=[self._dataset(f"mcp:agent_context:{session_id}")],
            metadata={
                "agent_id":   agent_id,
                "query_hash": query_hash,
                "session_id": session_id,
                "chunk_count": len(chunk_ids),
                **metadata,
            },
        )
        self._emit(event)
        return run_id

    def emit_prompt_event(
        self,
        session_id:       str,
        agent_id:         str,
        prompt_hash:      str,
        chunk_ids:        list[str],
        llm_model_id:     str,
        pii_was_detected: bool,
    ) -> str:
        """
        Emit prompt assembly lineage event.
        Links: retrieved chunks → assembled prompt → LLM call.
        This is the critical event for 'what data was in the context window' audits.
        """
        run_id = str(uuid.uuid4())
        event  = self._build_event(
            event_type="COMPLETE",
            job_name="mcp.prompt_assembly",
            run_id=run_id,
            inputs=[self._dataset(f"pgvector:chunk:{cid}") for cid in chunk_ids],
            outputs=[self._dataset(f"bedrock:{llm_model_id}:prompt:{session_id}")],
            metadata={
                "agent_id":         agent_id,
                "prompt_hash":      prompt_hash,   # SHA256, never plaintext
                "session_id":       session_id,
                "pii_detected":     pii_was_detected,
                "llm_model_id":     llm_model_id,
            },
        )
        self._emit(event)
        return run_id

    # ── Event builder ─────────────────────────────────────────────────────────

    def _build_event(
        self,
        event_type: str,
        job_name:   str,
        run_id:     str,
        inputs:     list[dict],
        outputs:    list[dict],
        metadata:   dict = {},
    ) -> dict:
        return {
            "eventType":  event_type,
            "eventTime":  datetime.now(timezone.utc).isoformat(),
            "schemaURL":  f"https://openlineage.io/spec/{self.OPENLINEAGE_VERSION}/OpenLineage.json",
            "producer":   "enterprise-mcp-ai-platform",
            "run": {
                "runId":   run_id,
                "facets":  {"mcp_metadata": {"_producer": "enterprise-mcp", **metadata}},
            },
            "job": {
                "namespace": self.namespace,
                "name":      job_name,
                "facets":    {},
            },
            "inputs":  inputs,
            "outputs": outputs,
        }

    def _dataset(self, name: str) -> dict:
        """Build an OpenLineage dataset reference."""
        # Infer namespace from dataset name prefix
        parts     = name.split(":", 1)
        namespace = parts[0] if len(parts) > 1 else self.namespace
        ds_name   = parts[1] if len(parts) > 1 else name

        return {
            "namespace": namespace,
            "name":      ds_name,
            "facets":    {},
        }

    def _emit(self, event: dict) -> None:
        """
        PRODUCTION: POST to Marquez API
            async with httpx.AsyncClient() as client:
                await client.post(
                    f"{self.url}/api/v1/lineage",
                    json=event,
                    headers={"Content-Type": "application/json"},
                )
        """
        logger.info(
            "OPENLINEAGE_EVENT | job=%s type=%s run=%s",
            event["job"]["name"], event["eventType"], event["run"]["runId"],
        )
        # Uncomment to see full event in development:
        # logger.debug("OPENLINEAGE_PAYLOAD | %s", json.dumps(event, indent=2))
