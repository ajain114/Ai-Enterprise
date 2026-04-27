"""
src/servers/rag_server.py
==========================
Enterprise MCP RAG Server.

Exposes the RAG pipeline as MCP-standard tools that any agent can discover
and call without direct database access. All tool calls flow through the
seven-layer PII guardrail pipeline.

MCP Tools exposed:
  search_knowledge_base        — Hybrid semantic search across document corpus
  get_document_context         — Fetch full document by ID with access check
  search_entity_history        — Entity-scoped search (requires elevated role)
  evaluate_retrieval_quality   — RAGAS-powered retrieval quality scoring

Production dependencies:
    pip install mcp psycopg2-binary pgvector boto3 ragas

PRODUCTION WIRE-UP:
    Replace the commented `mcp` imports and the `main()` function body with:

        from mcp.server import Server
        from mcp.server.stdio import stdio_server
        from mcp.server.models import InitializationOptions
        from mcp.types import Tool, TextContent, CallToolResult

        app = Server("enterprise-rag-server")

        @app.list_tools()
        async def list_tools() -> list[Tool]:
            return [Tool(**t) for t in RAGServer.MCP_TOOLS]

        @app.call_tool()
        async def call_tool(name: str, arguments: dict) -> list[TextContent]:
            handler = server.get_mcp_tool_map()[name]
            result  = await handler(**arguments, **ctx_from_mcp_request())
            return [TextContent(type="text", text=json.dumps(result))]

        async def main():
            server = RAGServer()
            server.startup()
            async with stdio_server() as (r, w):
                await app.run(r, w, InitializationOptions(
                    server_name="enterprise-rag-server",
                    server_version="1.0.0",
                ))
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import uuid
from datetime import datetime, timezone
from typing import Any

from src.guardrails.pii_shield import PIIConfig, PIIShield, PIIViolationError
from src.guardrails.prompt_guard import PromptGuard, ResponseGuard
from src.utils.config import PlatformConfig, get_config

logger = logging.getLogger(__name__)


# ── Database client (pgvector) ────────────────────────────────────────────────

class PGVectorClient:
    """
    Manages pgvector hybrid search (dense cosine + sparse BM25).

    Metadata filters are applied BEFORE vector search to reduce corpus size
    and improve latency. This is the critical performance pattern for
    production RAG at scale.

    PRODUCTION REPLACEMENT for hybrid_search():
    -------------------------------------------
    SELECT
        c.chunk_id, c.document_id, c.chunk_text, c.metadata,
        c.pii_classification,
        1 - (c.embedding <=> %s::vector)                            AS dense_score,
        ts_rank(c.ts_vector, plainto_tsquery('english', %s))        AS sparse_score
    FROM rag.document_chunks c
    WHERE
        (%s IS NULL OR c.domain = ANY(%s))
        AND c.data_class NOT IN ('RESTRICTED')
        AND c.is_active = TRUE
        AND c.updated_at >= NOW() - INTERVAL '%s days'
    ORDER BY
        (1.0 / (60 + RANK() OVER (ORDER BY dense_score DESC))) +
        (1.0 / (60 + RANK() OVER (ORDER BY sparse_score DESC))) DESC
    LIMIT %s
    """

    def __init__(self, config: PlatformConfig):
        self.config = config
        self._conn  = None

    def connect(self) -> None:
        """
        PRODUCTION:
            import psycopg2
            from pgvector.psycopg2 import register_vector
            self._conn = psycopg2.connect(self.config.db.dsn)
            register_vector(self._conn)
        """
        logger.info("PGVectorClient: connected to %s:%s/%s",
                    self.config.db.host, self.config.db.port, self.config.db.database)

    def hybrid_search(
        self,
        query_embedding: list[float],
        query_text:      str,
        top_k:           int,
        filters:         dict[str, Any],
        agent_role:      str,
    ) -> list[dict]:
        """Demo — replace with real pgvector + tsvector hybrid query."""
        return [
            {
                "chunk_id":           f"chunk_{i:04d}",
                "document_id":        f"doc_{i // 3:04d}",
                "chunk_text":         f"[DEMO] Chunk {i}: relevant content for '{query_text[:40]}'.",
                "metadata":           {"domain": filters.get("domain", "general"), "version": "2024-Q4"},
                "pii_classification": "STANDARD",
                "dense_score":        round(0.95 - i * 0.05, 4),
                "sparse_score":       round(0.88 - i * 0.04, 4),
                "combined_score":     round(0.92 - i * 0.04, 4),
            }
            for i in range(min(top_k, 8))
        ]

    def get_document(self, document_id: str, agent_role: str) -> dict | None:
        """Demo — replace with parameterized SELECT with Lake Formation row-level filter."""
        return {
            "document_id": document_id,
            "title":       f"Document {document_id}",
            "content":     f"[DEMO] Full document content for {document_id}. Contains policy details.",
            "metadata":    {"created_at": "2024-01-15", "domain": "general"},
            "pii_classification": "STANDARD",
        }


# ── Embedding client ─────────────────────────────────────────────────────────

class EmbeddingClient:
    """
    Bedrock Titan Embeddings wrapper.

    PRODUCTION REPLACEMENT for embed():
        import boto3, json
        client = boto3.client("bedrock-runtime", region_name=config.aws.region)
        response = client.invoke_model(
            modelId=config.aws.embed_model_id,
            body=json.dumps({"inputText": text}),
        )
        return json.loads(response["body"].read())["embedding"]
    """

    def __init__(self, config: PlatformConfig):
        self.config  = config
        self._client = None  # boto3 client in production

    def embed(self, text: str) -> list[float]:
        """Demo — returns zero vector. Replace with Bedrock Titan call."""
        return [0.0] * self.config.server.embedding_dim


# ── Re-ranker ─────────────────────────────────────────────────────────────────

class Reranker:
    """
    Cross-encoder re-ranking via Bedrock Rerank API.

    PRODUCTION REPLACEMENT for rerank():
        response = self._client.invoke_model(
            modelId=config.aws.rerank_model_id,
            body=json.dumps({
                "query": query,
                "documents": [{"text": c["chunk_text"]} for c in chunks],
                "numberOfResults": top_k,
            }),
        )
        # Map ranked indices back to original chunks
    """

    def __init__(self, config: PlatformConfig):
        self.config = config

    def rerank(self, query: str, chunks: list[dict], top_k: int) -> list[dict]:
        """Demo — returns top_k by combined_score. Replace with Bedrock Rerank."""
        return sorted(chunks, key=lambda c: c.get("combined_score", 0), reverse=True)[:top_k]


# ── Audit logger ──────────────────────────────────────────────────────────────

class AuditLogger:
    """
    Append-only audit trail for all MCP tool calls.
    In production: writes to S3 append-only bucket + emits OpenLineage events.
    Query_hash logs SHA256 of the query, never plaintext.
    """

    def __init__(self, config: PlatformConfig):
        self.config = config

    def log_tool_call(
        self,
        tool_name:    str,
        agent_id:     str,
        agent_role:   str,
        session_id:   str,
        query:        str,
        chunk_ids:    list[str],
        pii_detected: bool,
        latency_ms:   int,
    ) -> str:
        event_id = str(uuid.uuid4())
        event = {
            "event_id":     event_id,
            "event_type":   "MCP_TOOL_CALL",
            "tool":         tool_name,
            "agent_id":     agent_id,
            "agent_role":   agent_role,
            "session_id":   session_id,
            "query_hash":   hashlib.sha256(query.encode()).hexdigest(),
            "chunk_ids":    chunk_ids,
            "pii_detected": pii_detected,
            "latency_ms":   latency_ms,
            "timestamp":    datetime.now(timezone.utc).isoformat(),
        }
        # Production: s3_client.put_object(Bucket=..., Key=f"audit/{event_id}.json", Body=json.dumps(event))
        logger.info("AUDIT | %s", json.dumps(event))
        return event_id

    def emit(self, event: dict) -> None:
        logger.info("AUDIT_EVENT | %s", json.dumps(event))


# ═══════════════════════════════════════════════════════════════
# MCP RAG SERVER
# ═══════════════════════════════════════════════════════════════

class RAGServer:
    """
    Enterprise MCP RAG Server.
    Wire this into the MCP framework using the pattern in the module docstring.
    """

    MCP_TOOLS = [
        {
            "name": "search_knowledge_base",
            "description": (
                "Semantic search across the curated knowledge base. "
                "Returns PII-safe, re-ranked chunks relevant to the query. "
                "Use for policy documents, procedures, product guides, and reference material."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query":          {"type": "string",  "description": "Natural language search query"},
                    "domain":         {"type": "string",  "description": "Domain filter (or 'all')", "default": "all"},
                    "top_k":          {"type": "integer", "description": "Results to return (max 20)", "default": 5},
                    "freshness_days": {"type": "integer", "description": "Only return documents updated within N days", "default": 90},
                },
                "required": ["query"],
            },
        },
        {
            "name": "get_document_context",
            "description": (
                "Retrieve full document content by ID. "
                "Access is enforced by agent role. PII is masked per role permissions."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "document_id": {"type": "string", "description": "Document ID from search results"},
                },
                "required": ["document_id"],
            },
        },
        {
            "name": "search_entity_history",
            "description": (
                "Search historical records scoped to a tokenized entity identifier. "
                "Requires elevated agent role. All returned data is PII-masked per role permissions."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "entity_token":    {"type": "string",  "description": "Session-scoped token (obtain via Feature Store get_entity_token)"},
                    "query":           {"type": "string",  "description": "What to search for in entity history"},
                    "date_range_days": {"type": "integer", "description": "Look back N days", "default": 180},
                    "record_types":    {"type": "array",   "items": {"type": "string"}},
                },
                "required": ["entity_token", "query"],
            },
        },
        {
            "name": "evaluate_retrieval_quality",
            "description": (
                "Evaluate RAG retrieval quality using RAGAS metrics. "
                "Returns faithfulness, answer relevancy, context precision, and context recall scores."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query":   {"type": "string"},
                    "chunks":  {"type": "array", "items": {"type": "string"}},
                    "answer":  {"type": "string"},
                },
                "required": ["query", "chunks", "answer"],
            },
        },
    ]

    # Roles permitted to access entity history
    ENTITY_HISTORY_ROLES = {"analyst", "collections-agent", "servicing-agent", "fraud-agent"}

    def __init__(self, config: PlatformConfig | None = None):
        self.config   = config or get_config()
        pii_cfg       = self._load_pii_config()
        self.audit    = AuditLogger(self.config)
        self.shield   = PIIShield(config=pii_cfg, audit_logger=self.audit)
        self.pgvector = PGVectorClient(self.config)
        self.embedder = EmbeddingClient(self.config)
        self.reranker = Reranker(self.config)
        self.pg       = PromptGuard(pii_shield=self.shield, strict_mode=True)
        self.rg       = ResponseGuard(pii_shield=self.shield, block_on_never_patterns=True)

    def startup(self) -> None:
        self.pgvector.connect()
        logger.info("RAGServer started | version=1.0.0")

    def get_mcp_tool_map(self) -> dict:
        return {
            "search_knowledge_base":      self.handle_search_knowledge_base,
            "get_document_context":       self.handle_get_document_context,
            "search_entity_history":      self.handle_search_entity_history,
            "evaluate_retrieval_quality": self.handle_evaluate_retrieval_quality,
        }

    # ── Tool handlers ─────────────────────────────────────────────────────────

    async def handle_search_knowledge_base(
        self,
        query:          str,
        domain:         str  = "all",
        top_k:          int  = 5,
        freshness_days: int  = 90,
        agent_id:       str  = "",
        agent_role:     str  = "",
        session_id:     str  = "",
    ) -> dict:
        import time
        start   = time.time()
        top_k   = min(top_k, self.config.server.max_top_k)

        # Stage 1 — Sanitize query.
        # Queries containing BLOCK-mode PII (e.g. SSN) are handled gracefully:
        # we regex-redact the query rather than aborting the search entirely,
        # because the agent may have accidentally echoed user input verbatim.
        # The redaction event is logged for audit. BLOCK applies to retrieved
        # data going TO the LLM — not to the search query itself.
        try:
            q_result   = self.shield.process_chunk(query, agent_id, agent_role, session_id)
            safe_query = q_result.safe_text
        except PIIViolationError as e:
            import re as _re
            safe_query = query
            for _pat in [r'\b\d{3}-\d{2}-\d{4}\b', r'\b(?:\d{4}[\s\-]?){3}\d{4}\b']:
                safe_query = _re.sub(_pat, "[REDACTED]", safe_query)
            logger.warning("QUERY_PII_REDACTED | agent=%s entities=%s", agent_id, e.entity_types)

        # Stage 2 — Embed
        embedding  = self.embedder.embed(safe_query)

        # Stage 3 — Hybrid retrieval with pre-filters
        raw_chunks = self.pgvector.hybrid_search(
            query_embedding=embedding, query_text=safe_query,
            top_k=self.config.server.default_top_k,
            filters={"domain": domain if domain != "all" else None, "freshness_days": freshness_days},
            agent_role=agent_role,
        )

        # Stage 4 — PII shield every chunk
        safe_chunks  = []
        pii_detected = False
        for chunk in raw_chunks:
            c_result = self.shield.process_chunk(
                text=chunk["chunk_text"], agent_id=agent_id,
                agent_role=agent_role, context_id=f"{session_id}:{chunk['chunk_id']}",
            )
            pii_detected = pii_detected or c_result.was_modified
            safe_chunks.append({**chunk, "chunk_text": c_result.safe_text, "pii_masked": c_result.was_modified})

        # Stage 5 — Re-rank
        reranked = self.reranker.rerank(safe_query, safe_chunks, min(top_k, self.config.server.rerank_top_k))

        # Stage 6 — Audit
        latency_ms = int((time.time() - start) * 1000)
        self.audit.log_tool_call(
            tool_name="search_knowledge_base", agent_id=agent_id, agent_role=agent_role,
            session_id=session_id, query=safe_query,
            chunk_ids=[c["chunk_id"] for c in reranked],
            pii_detected=pii_detected, latency_ms=latency_ms,
        )

        return {
            "query":       safe_query,
            "total_found": len(raw_chunks),
            "returned":    len(reranked),
            "latency_ms":  latency_ms,
            "chunks": [
                {
                    "chunk_id":    c["chunk_id"],
                    "document_id": c["document_id"],
                    "text":        c["chunk_text"],
                    "score":       round(c.get("combined_score", 0.0), 4),
                    "metadata":    c["metadata"],
                    "pii_masked":  c["pii_masked"],
                }
                for c in reranked
            ],
        }

    async def handle_get_document_context(
        self,
        document_id: str,
        agent_id:    str = "",
        agent_role:  str = "",
        session_id:  str = "",
    ) -> dict:
        doc = self.pgvector.get_document(document_id, agent_role)
        if not doc:
            return {"error": "Document not found or access denied", "document_id": document_id}

        result = self.shield.process_chunk(doc["content"], agent_id, agent_role, f"{session_id}:doc:{document_id}")
        self.audit.log_tool_call(
            "get_document_context", agent_id, agent_role, session_id,
            document_id, [document_id], result.was_modified, 0,
        )
        return {
            "document_id": document_id,
            "title":       doc["title"],
            "content":     result.safe_text,
            "metadata":    doc["metadata"],
            "pii_masked":  result.was_modified,
        }

    async def handle_search_entity_history(
        self,
        entity_token:    str,
        query:           str,
        date_range_days: int        = 180,
        record_types:    list[str]  = None,
        agent_id:        str        = "",
        agent_role:      str        = "",
        session_id:      str        = "",
    ) -> dict:
        if agent_role not in self.ENTITY_HISTORY_ROLES:
            logger.warning("UNAUTHORIZED | agent=%s role=%s tool=search_entity_history", agent_id, agent_role)
            return {"error": "Insufficient permissions", "required_roles": sorted(self.ENTITY_HISTORY_ROLES)}

        if entity_token.isdigit() and len(entity_token) > 8:
            return {"error": "Raw entity IDs are not accepted. Use session-scoped token from Feature Store."}

        # Demo records — replace with real database query
        records = [
            {
                "record_id":   f"rec_{i:06d}",
                "record_type": (record_types or ["event"])[0],
                "summary":     f"[DEMO] Entity activity record {i} matching '{query[:30]}'",
                "date":        "2024-01-15",
            }
            for i in range(3)
        ]

        safe_records = []
        for rec in records:
            r = self.shield.process_chunk(rec["summary"], agent_id, agent_role, f"{session_id}:{rec['record_id']}")
            safe_records.append({**rec, "summary": r.safe_text})

        self.audit.log_tool_call(
            "search_entity_history", agent_id, agent_role, session_id,
            f"entity:{entity_token[:8]}:{query[:40]}",
            [r["record_id"] for r in safe_records], True, 0,
        )
        return {"entity_token": entity_token, "records": safe_records, "total": len(safe_records)}

    async def handle_evaluate_retrieval_quality(
        self,
        query:      str,
        chunks:     list[str],
        answer:     str,
        agent_id:   str = "",
        session_id: str = "",
    ) -> dict:
        """
        RAGAS-powered retrieval quality evaluation.

        PRODUCTION REPLACEMENT:
            from ragas import evaluate
            from ragas.metrics import faithfulness, answer_relevancy, context_precision, context_recall
            from datasets import Dataset

            dataset = Dataset.from_dict({
                "question": [query], "contexts": [chunks], "answer": [answer]
            })
            result = evaluate(dataset, metrics=[faithfulness, answer_relevancy, context_precision, context_recall])
        """
        # Demo scores — replace with real RAGAS call
        random.seed(hash(query + "".join(chunks)) % 2**31)
        scores = {
            "faithfulness":     round(0.70 + random.random() * 0.30, 3),
            "answer_relevancy": round(0.65 + random.random() * 0.35, 3),
            "context_precision":round(0.60 + random.random() * 0.40, 3),
            "context_recall":   round(0.55 + random.random() * 0.45, 3),
        }
        quality_gate = "PASS" if all(v >= 0.70 for v in scores.values()) else "REVIEW_REQUIRED"

        return {
            "evaluation_id": str(uuid.uuid4()),
            "query":         query,
            "num_chunks":    len(chunks),
            "scores":        scores,
            "quality_gate":  quality_gate,
            "recommendation": (
                "Retrieval quality meets threshold for agent use."
                if quality_gate == "PASS"
                else "Review chunking strategy or re-ranking configuration."
            ),
        }

    def _load_pii_config(self) -> PIIConfig:
        path = self.config.server.pii_config_path
        if os.path.exists(path):
            return PIIConfig.from_yaml(path)
        return self._default_pii_config()

    def _default_pii_config(self) -> PIIConfig:
        """Fallback config when no YAML is found (e.g. in tests)."""
        from src.guardrails.pii_shield import PIIEntityConfig, PIIEntityType, PIIMode
        return PIIConfig(
            entities=[
                PIIEntityConfig(PIIEntityType.SSN,           PIIMode.BLOCK),
                PIIEntityConfig(PIIEntityType.CREDIT_CARD,   PIIMode.BLOCK),
                PIIEntityConfig(PIIEntityType.BANK_ACCOUNT,  PIIMode.MASK),
                PIIEntityConfig(PIIEntityType.ACCOUNT_NUMBER,PIIMode.TOKEN, allowed_agent_roles=["fraud-agent"]),
                PIIEntityConfig(PIIEntityType.EMAIL,         PIIMode.MASK,  allowed_agent_roles=["collections-agent", "servicing-agent"]),
                PIIEntityConfig(PIIEntityType.PHONE,         PIIMode.MASK,  allowed_agent_roles=["collections-agent"]),
                PIIEntityConfig(PIIEntityType.PERSON_NAME,   PIIMode.MASK),
                PIIEntityConfig(PIIEntityType.ADDRESS,       PIIMode.MASK),
            ],
            global_mode=PIIMode.MASK,
            block_on_unknown_agent=True,
            audit_all_events=False,
        )


async def main() -> None:
    """Demo runner — replace body with MCP stdio_server() wire-up for production."""
    logging.basicConfig(level=logging.INFO)
    server = RAGServer()
    server.startup()

    result = await server.handle_search_knowledge_base(
        query="What is the dispute resolution procedure?",
        domain="all", top_k=3,
        agent_id="demo-agent-01", agent_role="servicing-agent", session_id="demo-001",
    )
    print(json.dumps(result, indent=2))


def run() -> None:
    """Entry point for `mcp-rag-server` CLI command."""
    import asyncio
    asyncio.run(main())


if __name__ == "__main__":
    run()
