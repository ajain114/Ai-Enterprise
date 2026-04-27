-- scripts/setup_pgvector.sql
-- ===========================
-- Initializes the pgvector schema for the enterprise MCP AI platform.
-- Run automatically by docker-compose on first startup.
-- For production: apply via your database migration tool (Flyway, Alembic).

-- ── Extension ────────────────────────────────────────────────────────────────
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pg_trgm;    -- Trigram index for text search
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- ── Schema ────────────────────────────────────────────────────────────────────
CREATE SCHEMA IF NOT EXISTS rag;
CREATE SCHEMA IF NOT EXISTS features;
CREATE SCHEMA IF NOT EXISTS audit;

-- ── Document Chunks (RAG corpus) ─────────────────────────────────────────────
-- Stores chunked, embedded document corpus for semantic retrieval.
-- Each row = one chunk from one document version.
CREATE TABLE IF NOT EXISTS rag.document_chunks (
    chunk_id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id         UUID        NOT NULL,
    document_version    TEXT        NOT NULL DEFAULT 'v1',
    chunk_index         INTEGER     NOT NULL,           -- Position within document
    chunk_text          TEXT        NOT NULL,           -- Raw text (pre-PII-masking)
    chunk_text_safe     TEXT,                           -- PII-masked version (for audit)
    embedding           vector(1536),                  -- Bedrock Titan Embed v2 dimension
    ts_vector           tsvector,                      -- Full-text search index
    domain              TEXT        NOT NULL,           -- servicing|fraud|collections|risk|hr
    data_class          TEXT        NOT NULL DEFAULT 'STANDARD',  -- STANDARD|INTERNAL|RESTRICTED
    pii_classification  TEXT[]      DEFAULT '{}',       -- Array of PII types found in chunk
    metadata            JSONB       DEFAULT '{}',
    source_uri          TEXT,                           -- S3 path to source document
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    updated_at          TIMESTAMPTZ DEFAULT NOW(),
    embedding_model_id  TEXT        DEFAULT 'amazon.titan-embed-text-v2:0',
    is_active           BOOLEAN     DEFAULT TRUE
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_chunks_embedding
    ON rag.document_chunks USING hnsw (embedding vector_cosine_ops)
    WITH (m = 16, ef_construction = 64);

CREATE INDEX IF NOT EXISTS idx_chunks_tsv
    ON rag.document_chunks USING gin(ts_vector);

CREATE INDEX IF NOT EXISTS idx_chunks_domain
    ON rag.document_chunks (domain, data_class, is_active);

CREATE INDEX IF NOT EXISTS idx_chunks_document
    ON rag.document_chunks (document_id, document_version);

-- Auto-update ts_vector from chunk_text
CREATE OR REPLACE FUNCTION rag.update_ts_vector()
RETURNS TRIGGER AS $$
BEGIN
    NEW.ts_vector = to_tsvector('english', COALESCE(NEW.chunk_text, ''));
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_update_ts_vector
    BEFORE INSERT OR UPDATE ON rag.document_chunks
    FOR EACH ROW EXECUTE FUNCTION rag.update_ts_vector();

-- ── Documents (metadata registry) ────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rag.documents (
    document_id     UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    title           TEXT        NOT NULL,
    domain          TEXT        NOT NULL,
    data_class      TEXT        NOT NULL DEFAULT 'STANDARD',
    source_uri      TEXT,
    version         TEXT        DEFAULT 'v1',
    total_chunks    INTEGER     DEFAULT 0,
    metadata        JSONB       DEFAULT '{}',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    updated_at      TIMESTAMPTZ DEFAULT NOW(),
    created_by      TEXT,
    is_active       BOOLEAN     DEFAULT TRUE
);

-- ── Feature Store (online — current values) ──────────────────────────────────
-- Stores current feature values for LLM agent context assembly.
-- In production: mirror to Redis for sub-ms latency.
CREATE TABLE IF NOT EXISTS features.online_features (
    entity_token    TEXT        NOT NULL,              -- Tokenized entity identifier
    feature_set     TEXT        NOT NULL,              -- credit_risk|churn_risk|etc
    features        JSONB       NOT NULL,              -- Feature key-value pairs
    as_of           TIMESTAMPTZ DEFAULT NOW(),
    expires_at      TIMESTAMPTZ,
    source          TEXT,                              -- dbt model name that produced this
    PRIMARY KEY (entity_token, feature_set)
);

CREATE INDEX IF NOT EXISTS idx_online_features_expiry
    ON features.online_features (expires_at)
    WHERE expires_at IS NOT NULL;

-- ── Audit Log (append-only) ───────────────────────────────────────────────────
-- Immutable record of all MCP tool calls and PII events.
-- In production: also replicate to S3 append-only bucket.
CREATE TABLE IF NOT EXISTS audit.mcp_events (
    event_id            UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    event_type          TEXT        NOT NULL,          -- MCP_TOOL_CALL|PII_PROCESSED|PII_BLOCKED|PII_LEAKAGE
    tool_name           TEXT,
    agent_id            TEXT        NOT NULL,
    agent_role          TEXT,
    session_id          TEXT,
    query_hash          TEXT,                          -- SHA256 of query — never plaintext
    chunk_ids           TEXT[],
    pii_detected        BOOLEAN     DEFAULT FALSE,
    pii_entity_types    TEXT[],
    pii_modes_applied   TEXT[],
    latency_ms          INTEGER,
    severity            TEXT        DEFAULT 'INFO',    -- INFO|WARNING|HIGH|CRITICAL
    timestamp           TIMESTAMPTZ DEFAULT NOW()
);

-- Append-only enforcement: no UPDATE or DELETE allowed on audit table
CREATE RULE audit_no_update AS ON UPDATE TO audit.mcp_events DO INSTEAD NOTHING;
CREATE RULE audit_no_delete AS ON DELETE TO audit.mcp_events DO INSTEAD NOTHING;

CREATE INDEX IF NOT EXISTS idx_audit_agent
    ON audit.mcp_events (agent_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_pii
    ON audit.mcp_events (pii_detected, severity, timestamp DESC)
    WHERE pii_detected = TRUE;

-- ── Row-Level Security (simulate Lake Formation for local dev) ────────────────
-- In production: enforce via AWS Lake Formation column/row-level policies.
-- Locally: RLS policies simulate agent-role-based access.
ALTER TABLE rag.document_chunks ENABLE ROW LEVEL SECURITY;

-- Standard agents can read STANDARD and INTERNAL data
CREATE POLICY rls_standard_agent ON rag.document_chunks
    FOR SELECT
    USING (data_class IN ('STANDARD', 'INTERNAL'));

-- Default: enforce RLS for all non-superuser connections
ALTER TABLE rag.document_chunks FORCE ROW LEVEL SECURITY;

-- ── Seed: demo domain categories ─────────────────────────────────────────────
INSERT INTO rag.documents (title, domain, data_class, source_uri, created_by)
VALUES
    ('Dispute Resolution Policy v2.3',   'servicing',   'INTERNAL', 's3://demo/docs/dispute-policy.pdf',   'seed'),
    ('Collections Procedures Manual',    'collections', 'INTERNAL', 's3://demo/docs/collections-manual.pdf', 'seed'),
    ('Fraud Detection Guidelines',       'fraud',       'RESTRICTED','s3://demo/docs/fraud-guidelines.pdf', 'seed'),
    ('Product Terms and Conditions',     'servicing',   'STANDARD', 's3://demo/docs/product-terms.pdf',    'seed'),
    ('Risk Scoring Methodology',         'risk',        'INTERNAL', 's3://demo/docs/risk-scoring.pdf',     'seed')
ON CONFLICT DO NOTHING;
