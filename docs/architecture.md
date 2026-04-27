# Architecture Deep Dive

## Overview

The Enterprise MCP AI Platform solves a fundamental problem in enterprise AI: how do you give multiple AI agents access to governed, PII-safe, high-quality data — without rebuilding integration, governance, and security logic for every agent?

The answer is Model Context Protocol (MCP) as the central architectural primitive.

---

## Core Architectural Decisions

### Decision 1: MCP as the Integration Layer, Not the Data Layer

MCP servers sit between agents and data stores. They do not replace the data stores — they standardise the interface to them.

```
Agent → MCP Server → [pgvector | Redis | Iceberg | Redshift]
```

This means:
- The data stores can be swapped (pgvector → OpenSearch) without changing agent code
- All governance (PII, access control, lineage) is enforced at the MCP layer — once
- New agents get governed data access by connecting to existing MCP servers

### Decision 2: Defence in Depth for PII

PII protection has seven independent layers. Any one of them catching PII prevents exposure. All seven must fail for a leak to occur.

This is intentional over-engineering — in regulated industries the cost of a PII leak vastly exceeds the cost of defensive redundancy.

### Decision 3: The ML/LLM Feature Duality

Traditional ML models and LLM agents have incompatible data consumption patterns:

| Dimension | ML Model | LLM Agent |
|-----------|----------|-----------|
| Format | Numeric vectors | Natural language |
| Freshness | Point-in-time correct | Current state |
| Latency | Sub-second (batch OK) | Sub-second (always) |
| Volume | All features | Selected context |
| PII | Excluded by feature engineering | Excluded by PIIShield |

The Feature Store Server handles this duality: same underlying data, two transformation paths, appropriate format for each consumer.

### Decision 4: Data Preparation Over Retrieval Optimisation

RAGAS evaluation consistently shows that data preparation quality (chunking strategy, metadata richness, PII-clean embeddings) has a larger impact on retrieval quality than retrieval algorithm choice.

This platform therefore invests heavily in the data preparation pipeline (dbt curation, chunk metadata, PII-clean embeddings) and treats retrieval algorithm selection as a secondary optimisation.

---

## Component Architecture

### MCP RAG Server — Retrieval Pipeline

```
Query received
    │
    ├─ 1. PIIShield.process_chunk(query)
    │        Sanitize PII in the query itself before embedding.
    │        User queries frequently contain raw PII that should not
    │        influence the embedding or appear in audit logs.
    │
    ├─ 2. EmbeddingClient.embed(safe_query)
    │        Bedrock Titan Embed v2 (1536 dimensions).
    │        Embedding is computed on the sanitized query.
    │        PII is not encoded into the embedding space.
    │
    ├─ 3. PGVectorClient.hybrid_search(...)
    │        Pre-filter by metadata BEFORE vector search.
    │        Filtering on domain, data_class, freshness before ANN search
    │        dramatically reduces search space and improves latency.
    │        Hybrid: dense cosine (pgvector HNSW) + sparse BM25 (tsvector).
    │        Reciprocal Rank Fusion combines both scores.
    │
    ├─ 4. PIIShield.process_chunk(chunk) × N
    │        Process every retrieved chunk independently.
    │        PII in source documents is masked/blocked/tokenized
    │        before chunks enter agent context.
    │        Each chunk gets an independent processing_id for audit.
    │
    ├─ 5. Reranker.rerank(...)
    │        Cross-encoder re-ranking (Bedrock Rerank API).
    │        Improves relevance ordering of top candidates.
    │        Runs on PII-safe chunks — never on raw retrieved text.
    │
    ├─ 6. PromptGuard.inspect(assembled_context)
    │        Final gate before LLM call.
    │        Catches anything that slipped through chunk-level processing.
    │        In strict_mode (production): blocks on any PII detection.
    │
    ├─ 7. LLM.invoke(safe_prompt)
    │        Bedrock Claude call within the VPC.
    │        No PII-containing prompt ever leaves the VPC boundary.
    │
    ├─ 8. ResponseGuard.inspect(llm_response)
    │        Post-LLM inspection. Catches hallucinated PII.
    │        CRITICAL escalation triggered on any NEVER-pattern detection.
    │
    └─ 9. AuditLogger.log_tool_call(...)
             Immutable event: agent_id, query_hash (not query text),
             chunk_ids, pii_detected flag, latency_ms, timestamp.
             Written to S3 append-only bucket.
```

### pgvector Schema Design

```sql
-- HNSW index for approximate nearest neighbour search
-- m=16: connections per node (higher = better recall, more memory)
-- ef_construction=64: build-time search width (higher = better quality, slower build)
CREATE INDEX ON rag.document_chunks USING hnsw (embedding vector_cosine_ops)
WITH (m = 16, ef_construction = 64);

-- GIN index for full-text search (BM25-style)
CREATE INDEX ON rag.document_chunks USING gin(ts_vector);

-- Composite index for metadata pre-filtering
-- Applied BEFORE vector search to reduce ANN search space
CREATE INDEX ON rag.document_chunks (domain, data_class, is_active);
```

**Hybrid search SQL pattern:**

```sql
SELECT
    chunk_id, chunk_text, metadata,
    1 - (embedding <=> $1::vector)                     AS dense_score,
    ts_rank(ts_vector, plainto_tsquery('english', $2)) AS sparse_score
FROM rag.document_chunks
WHERE
    domain = ANY($3)              -- Metadata pre-filter (applied BEFORE vector search)
    AND data_class IN ('STANDARD', 'INTERNAL')
    AND is_active = TRUE
    AND updated_at >= NOW() - INTERVAL '90 days'
ORDER BY
    -- Reciprocal Rank Fusion
    (1.0 / (60 + dense_rank))  + (1.0 / (60 + sparse_rank)) DESC
LIMIT $4
```

### PII Protection — Token Vault

TOKEN mode generates deterministic hashes per session, stored in AWS Secrets Manager:

```
Original: "ENT-1234567890"
         ↓
SHA256("session-001:ACCOUNT_NUMBER:ENT-1234567890")[:8].upper()
         ↓
Token: "[ACCOUNT_NUMBER:A3F2C1B8]"
```

Properties:
- **Deterministic**: same original in same session always produces same token
- **One-way**: token cannot be reversed without vault access
- **Session-scoped**: different sessions produce different tokens for the same original
- **Recognisable**: format `[TYPE:HASH]` signals "this is a token, not real data" to both humans and LLMs
- **Reversible**: authorised systems call `detokenize()` with the processing_id to recover original values

### Lineage — Three-Layer Capture

```
Layer 1: Dataset lineage (OpenLineage)
  source_system → raw_table → dbt_model → curated_dataset → rag_index
  Captured by: dbt + Airflow + Spark → OpenLineage → Marquez

Layer 2: Retrieval lineage (MCP audit log)
  agent_session → tool_call → chunk_ids → document_ids
  Captured by: AuditLogger.log_tool_call() on every MCP invocation

Layer 3: Prompt lineage (custom)
  chunk_ids → prompt_assembly → llm_call
  Captured by: hash(assembled_prompt) stored with processing_ids
  Enables: "what data was in the context window for this LLM call?"
```

The union of all three layers allows a complete answer to:
> "Customer X filed a complaint about advice they received. What data did the agent have access to when it generated that response?"

---

## Production Deployment Checklist

Refer to `docs/production_checklist.md` for the complete pre-production checklist.

Key items:
1. Replace all demo stubs (marked `# PRODUCTION:`) with real client calls
2. Install spaCy model: `python -m spacy download en_core_web_lg`
3. Configure Lake Formation row-level security on all Iceberg tables
4. Enable Amazon Macie PII auto-classification on S3 buckets
5. Set up S3 append-only bucket policy (deny `s3:DeleteObject`)
6. Configure Marquez for OpenLineage event ingestion
7. Set RAGAS quality gate thresholds in governance documentation
8. Run load test to validate p95 retrieval latency < 800ms
