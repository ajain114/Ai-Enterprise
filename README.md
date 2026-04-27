# Enterprise MCP AI Platform

> **Model Context Protocol (MCP) server infrastructure for enterprise-grade RAG pipelines, agentic AI, and modular data architecture — with built-in PII guardrails.**

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)
[![Tests](https://img.shields.io/badge/Tests-18%2F18%20passing-brightgreen)](#running-tests)
[![MCP](https://img.shields.io/badge/Protocol-MCP%201.0-purple)](https://modelcontextprotocol.io)

---

## Table of Contents

- [The Problem](#the-problem)
- [The Solution](#the-solution)
- [Architecture](#architecture)
- [Components](#components)
- [PII Guardrail System](#pii-guardrail-system)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Running Tests](#running-tests)
- [Production Deployment](#production-deployment)
- [Technology Stack](#technology-stack)
- [Contributing](#contributing)

---

## The Problem

### Building AI agents on enterprise data is broken in three ways.

**1. Integration Sprawl — Every agent reinvents the data connection.**

When an organization builds multiple AI agents — a customer servicing agent, a fraud detection agent, a collections agent, an analytics agent — each team independently builds custom connectors to the same underlying data sources. The servicing team writes their own Redshift connector. The fraud team writes theirs. The collections team writes theirs. You end up with:

- Four versions of the same database query, each with slightly different assumptions
- Four places where data quality bugs need to be fixed
- Four places where a PII leak can occur
- Zero central visibility into what data your agents are consuming

This is **integration sprawl**, and it kills both engineering velocity and data governance at scale.

**2. Governance as an Afterthought — PII protection is bolted on, not built in.**

The standard approach to AI data pipelines sends raw data through ETL, stores it in a vector database, and then hopes that the prompt engineering will prevent PII from reaching the LLM. This is architecturally wrong for three reasons:

- **Chunking destroys context boundaries.** A chunking algorithm that splits a document at 512 tokens has no concept of whether it just split a name from a Social Security Number across two chunks — and both chunks now carry half the PII.
- **Embeddings encode PII.** When you embed a text chunk containing `John Smith, SSN: 123-45-6789`, that PII is encoded into the vector. Any semantic search for "customer with disputed SSN" can retrieve it.
- **LLMs reconstruct PII.** Modern LLMs are powerful enough to reconstruct partially-masked PII from context clues. Masking `123-**-6789` while leaving surrounding context is not protection — it is the illusion of protection.

In regulated industries (financial services, healthcare, legal), a single PII exposure event is a compliance violation, a potential regulatory fine, and a reputational incident. **The only safe approach is defence in depth — PII must be detected and handled before it enters any pipeline, at every transformation stage, and after every LLM call.**

**3. The ML/LLM Feature Store Duality — Your feature platform serves neither consumer well.**

Traditional ML feature stores (Feast, Tecton) are built for ML models: numeric feature vectors, point-in-time correctness, batch retrieval. LLM agents need something fundamentally different: natural language context summaries, current state, conversational format.

Organizations building both ML models and LLM agents end up with:

- Two separate data serving platforms with duplicated infrastructure
- ML features that agents can't consume because they're numeric vectors
- Agent context systems that ML models can't use because they're unstructured text
- Two maintenance burdens, two lineage systems, two governance frameworks

---

## The Solution

### A modular, protocol-standardized AI data platform built on MCP.

**Model Context Protocol (MCP)** is an open standard that defines how AI agents discover and consume data sources and tools. Think of it as the USB-C standard for AI data integration: instead of every agent building a custom connector to every data source, MCP gives you one standard interface.

This platform implements MCP as the central architectural primitive for enterprise AI data infrastructure. The result:

```
Before MCP:                          After MCP:
                                     
Agent A ──► custom connector ──► DB  Agent A ─┐
Agent B ──► custom connector ──► DB  Agent B ─┤──► MCP Server ──► DB
Agent C ──► custom connector ──► DB  Agent C ─┘    (governed,
                                                    audited,
                                                    PII-safe)
```

**What this platform provides:**

### 1. MCP RAG Server
A production-ready MCP server that exposes your entire RAG infrastructure as standardized tools. Agents call `search_knowledge_base(query, domain, top_k)` — they never interact directly with the vector store. The MCP server handles:
- Query sanitization (PII in queries is common)
- Hybrid retrieval: dense (pgvector cosine) + sparse (BM25 full-text)
- Chunk-level PII protection before assembly into agent context
- Re-ranking with cross-encoder models
- RAGAS-powered quality evaluation
- Immutable audit logging of every retrieval event

### 2. MCP Feature Store Server
Serves the same underlying feature data in two formats from one platform:
- **For ML models:** Structured numeric feature vectors, point-in-time correct (via Iceberg time-travel)
- **For LLM agents:** Natural language narrative summaries, current state, PII-masked

Eliminates the dual-platform problem. One data source, two consumers, appropriate format for each.

### 3. Seven-Layer PII Guardrail System
Defence in depth across the entire pipeline:

| Layer | Stage | Tool | Protection |
|-------|-------|------|------------|
| 1 | Query ingestion | `PIIShield` | Sanitize PII in user queries before embedding |
| 2 | Pre-retrieval | `PIIShield` | Strip PII that could bias semantic search |
| 3 | Chunk retrieval | `PIIShield` | Process every retrieved chunk individually |
| 4 | Context assembly | `PIIShield` | Process assembled multi-chunk context |
| 5 | Pre-LLM prompt | `PromptGuard` | Final inspection of fully assembled prompt |
| 6 | Post-LLM response | `ResponseGuard` | Catch hallucinated or reconstructed PII |
| 7 | Audit | `AuditLogger` | Immutable event log for every PII event |

### 4. Role-Aware Data Access
Every tool call carries an agent identity (`agent_id` + `agent_role`). The platform enforces what each role can see:
- **SSNs, credit card numbers:** BLOCK mode — no role sees these in any pipeline, ever
- **Account numbers:** TOKEN mode — replaced with deterministic hash; only fraud analysts see plain text
- **Email/phone:** MASK mode by default; collections agents see plain text for outreach workflows
- **ML features (numeric):** No masking needed — numeric vectors contain no PII

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         AI AGENTS LAYER                             │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐  ┌─────────┐ │
│  │  Servicing   │  │    Fraud     │  │ Collections │  │Analytics│ │
│  │    Agent     │  │    Agent     │  │    Agent    │  │  Agent  │ │
│  └──────┬───────┘  └──────┬───────┘  └──────┬──────┘  └────┬────┘ │
└─────────┼─────────────────┼─────────────────┼───────────────┼──────┘
          │   MCP Protocol (tool discovery + invocation)       │
┌─────────┼─────────────────┼─────────────────┼───────────────┼──────┐
│         ▼   MCP SERVER LAYER                ▼               ▼      │
│  ┌──────────────┐  ┌──────────────┐  ┌─────────────────────────┐  │
│  │  RAG Server  │  │Feature Store │  │   Governance Server     │  │
│  │              │  │   Server     │  │  (lineage + audit)      │  │
│  └──────┬───────┘  └──────┬───────┘  └─────────────────────────┘  │
│         │   ┌─────────────┘                                        │
│  ┌──────▼───▼──────────────────────────────────────────────────┐   │
│  │              7-LAYER PII GUARDRAIL PIPELINE                 │   │
│  │  PIIShield → PromptGuard → [LLM] → ResponseGuard → Audit   │   │
│  └──────────────────────────┬──────────────────────────────────┘   │
└─────────────────────────────┼────────────────────────────────────┘
                              │
┌─────────────────────────────┼────────────────────────────────────┐
│         DATA INFRASTRUCTURE LAYER           ▼                    │
│  ┌────────────┐  ┌─────────────┐  ┌──────────────┐  ┌────────┐  │
│  │  pgvector  │  │Apache Iceberg│  │  Online Store │  │  dbt   │  │
│  │(embeddings)│  │(feature store│  │(Redis/Dynamo) │  │(curate)│  │
│  └────────────┘  └─────────────┘  └──────────────┘  └────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

### Data flow for a single agent tool call

```
Agent calls search_knowledge_base(query="customer dispute policy")
    │
    ├─[1] PIIShield.process_chunk(query)          # Sanitize the query
    ├─[2] BedrockEmbeddingClient.embed(safe_query) # Embed clean query
    ├─[3] PGVectorClient.hybrid_search(...)        # Dense + sparse retrieval
    ├─[4] PIIShield.process_chunk(chunk) × N       # Shield every chunk
    ├─[5] BedrockReranker.rerank(...)              # Re-rank top results
    ├─[6] PromptGuard.inspect(assembled_context)   # Final prompt check
    ├─[7] LLM.invoke(safe_prompt)                  # Bedrock call
    ├─[8] ResponseGuard.inspect(llm_response)      # Catch any leakage
    └─[9] AuditLogger.log_tool_call(...)           # Immutable audit record
```

---

## Components

### `src/guardrails/pii_shield.py`
Core PII detection and anonymization engine. Three modes per entity type:
- **BLOCK** — Raise `PIIViolationError`, abort the pipeline. Used for SSNs, credit cards.
- **MASK** — Replace with `[ENTITY_TYPE]` placeholder. Used for names, addresses, emails.
- **TOKEN** — Replace with deterministic hash `[ENTITY_TYPE:A3F2C1B8]`. Reversible via vault for authorized roles. Used for account numbers.

Custom recognizers extend Microsoft Presidio for domain-specific PII patterns.

### `src/guardrails/prompt_guard.py`
Two-sided guardrail:
- **PromptGuard** — Pre-LLM inspection. Runs on the fully assembled prompt before any LLM call. Last line of defence.
- **ResponseGuard** — Post-LLM inspection. Catches hallucinated PII, reconstructed values, or anything the earlier layers missed. Critical/high-severity escalation on detection.

### `src/servers/rag_server.py`
MCP server with 4 tools:
- `search_knowledge_base` — Hybrid semantic search with metadata filtering
- `get_document_context` — Fetch full document by ID with access check
- `search_customer_history` — Role-gated customer record search (requires elevated role)
- `evaluate_retrieval_quality` — RAGAS-powered retrieval quality scoring

### `src/servers/feature_store_server.py`
MCP server with 3 tools:
- `get_customer_context` — Natural language narrative for LLM agents (PII-masked)
- `get_ml_features` — Structured feature vector for ML models (point-in-time correct)
- `get_customer_token` — Convert raw ID → session-scoped token (24h expiry)

### `config/pii_config.yaml`
Declarative PII governance configuration. Define entity types, operating modes, confidence thresholds, and role-based access rules without code changes.

---

## PII Guardrail System

### Three Protection Modes

```python
class PIIMode(str, Enum):
    BLOCK = "block"   # Abort pipeline — for SSN, credit cards
    MASK  = "mask"    # Replace with [ENTITY_TYPE] — for names, email
    TOKEN = "token"   # Deterministic hash — for account numbers
```

### Role-Based Access

```yaml
# config/pii_config.yaml
- entity_type: "ACCOUNT_NUMBER"
  mode: "token"
  allowed_agent_roles:
    - "fraud-agent"         # fraud analysts see plain text
    # All other roles get [ACCOUNT_NUMBER:A3F2C1B8]
```

### Defence in Depth

```
User Query (may contain PII)
    ↓ PIIShield.process_chunk()        ← Layer 1: query sanitization
Embedded Query (clean)
    ↓ Vector Retrieval
Raw Chunks (may contain PII)
    ↓ PIIShield.process_chunk() × N   ← Layer 2: chunk sanitization
Safe Chunks
    ↓ Prompt Assembly
Assembled Prompt
    ↓ PromptGuard.inspect()           ← Layer 3: final prompt gate
Safe Prompt
    ↓ LLM Call (Bedrock)
LLM Response
    ↓ ResponseGuard.inspect()         ← Layer 4: leakage detection
Safe Response → Agent
```

### Audit Trail

Every PII event emits a structured log (no PII content, only metadata):
```json
{
  "event_type":    "PII_PROCESSED",
  "processing_id": "uuid",
  "agent_id":      "collections-agent-01",
  "entity_types":  ["EMAIL_ADDRESS"],
  "modes_applied": ["mask"],
  "was_modified":  true,
  "timestamp":     "2024-01-15T10:30:00Z"
}
```

---

## Quick Start

### Prerequisites

- Python 3.11+
- Docker + Docker Compose (for local pgvector)
- `make` (optional, for convenience commands)

### 1. Clone and install

```bash
git clone https://github.com/your-org/enterprise-mcp-ai-platform.git
cd enterprise-mcp-ai-platform

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate

pip install -r requirements.txt
```

### 2. Start local infrastructure

```bash
# Starts pgvector (PostgreSQL + pgvector extension)
docker-compose up -d

# Verify pgvector is ready
docker-compose ps
```

### 3. Configure environment

```bash
cp .env.example .env
# Edit .env with your settings (see Configuration section)
```

### 4. Run the test suite

```bash
python -m pytest tests/ -v

# Or run the integration demo directly:
python tests/test_guardrail_pipeline.py
```

### 5. Start the RAG MCP server

```bash
python -m src.servers.rag_server
```

### 6. Connect an agent (example with LangChain)

```python
from langchain_mcp import MCPToolkit

# Connect to the running MCP server
toolkit = MCPToolkit(server_url="stdio://python -m src.servers.rag_server")
tools   = toolkit.get_tools()

# Agent now has access to: search_knowledge_base, get_document_context,
# search_customer_history, evaluate_retrieval_quality
```

---

## Configuration

### Environment Variables (`.env`)

```bash
# Database — pgvector
PG_HOST=localhost
PG_PORT=5432
PG_DATABASE=ai_rag_platform
PG_USER=rag_reader
PG_PASSWORD=changeme

# AWS — Bedrock (for embeddings, LLM, re-ranking)
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-key-id
AWS_SECRET_ACCESS_KEY=your-secret-key
EMBED_MODEL_ID=amazon.titan-embed-text-v2:0
RERANK_MODEL_ID=amazon.rerank-v1:0

# PII Configuration
PII_CONFIG_PATH=config/pii_config.yaml
TOKEN_VAULT_ARN=arn:aws:secretsmanager:us-east-1:123456789:secret/pii-token-vault

# Audit
AUDIT_S3_BUCKET=your-ai-audit-logs-bucket

# Server
DEFAULT_TOP_K=10
RERANK_TOP_K=3
```

### PII Config (`config/pii_config.yaml`)

```yaml
global_mode: "mask"
block_on_unknown_agent: true

entities:
  - entity_type: "US_SSN"
    mode: "block"               # Never reaches LLM
    score_threshold: 0.70

  - entity_type: "CREDIT_CARD"
    mode: "block"               # Never reaches LLM

  - entity_type: "ACCOUNT_NUMBER"
    mode: "token"               # Reversible hash
    allowed_agent_roles:
      - "fraud-agent"           # Only fraud agents see plaintext

  - entity_type: "EMAIL_ADDRESS"
    mode: "mask"
    allowed_agent_roles:
      - "collections-agent"
      - "servicing-agent"
```

---

## Running Tests

```bash
# Full test suite
python -m pytest tests/ -v

# Integration demo (no pytest required)
python tests/test_guardrail_pipeline.py

# Individual modules
python -m pytest tests/test_pii_shield.py -v
python -m pytest tests/test_prompt_guard.py -v
python -m pytest tests/test_rag_server.py -v
```

Expected output:
```
════════════════════════════════════════════════════════════
  ENTERPRISE MCP AI PLATFORM — GUARDRAIL TEST SUITE
════════════════════════════════════════════════════════════

STAGE 1 — PIIShield: Detection & Mode Enforcement
  ✓  SSN correctly triggers BLOCK mode
  ✓  Credit card correctly triggers BLOCK mode
  ✓  Email masked for unauthorized agent role
  ✓  Email passes through for authorized agent role
  ✓  Clean text passes through without modification
  ✓  Account number tokenized for standard agent

STAGE 2 — PromptGuard: Pre-LLM Prompt Inspection
  ✓  PromptGuard caught PII in assembled prompt
  ✓  PromptGuard passes clean prompts without modification

STAGE 3 — ResponseGuard: Post-LLM Response Inspection
  ✓  ResponseGuard detected PII leakage in LLM output
  ✓  ResponseGuard passes clean LLM responses

STAGE 4 — Full RAG Server Pipeline
  ✓  RAG search returns chunks with latency measurement
  ✓  Customer history denied for unauthorized role
  ✓  Customer history accessible for authorized role
  ✓  RAGAS evaluation returns quality scores

STAGE 5 — Feature Store Pipeline
  ✓  Customer token issued correctly
  ✓  Customer context narrative returned
  ✓  Raw customer ID correctly rejected
  ✓  ML feature vector returned

Results: 18/18 passed — All tests passed ✓
```

---

## Production Deployment

### Replace demo stubs with production clients

The codebase uses demo/stub implementations for components that require cloud credentials. Each stub is clearly marked with a `# PRODUCTION:` comment showing the exact replacement.

**Embedding (Bedrock Titan):**
```python
# In src/utils/embedding_client.py — replace _embed_demo():
import boto3, json
client = boto3.client("bedrock-runtime", region_name=config.bedrock_region)
response = client.invoke_model(
    modelId=config.embed_model_id,
    body=json.dumps({"inputText": text}),
)
return json.loads(response["body"].read())["embedding"]
```

**PII Detection (Microsoft Presidio):**
```python
# In src/guardrails/pii_shield.py — replace _detect_entities():
from presidio_analyzer import AnalyzerEngine
analyzer = AnalyzerEngine()
results  = analyzer.analyze(text=text, language="en")
```

**pgvector connection:**
```python
# In src/servers/rag_server.py — replace PGVectorClient.connect():
import psycopg2
from pgvector.psycopg2 import register_vector
self._conn = psycopg2.connect(host=..., database=..., ...)
register_vector(self._conn)
```

**MCP server wire-up:**
```python
# In src/servers/rag_server.py — replace main():
from mcp.server import Server
from mcp.server.stdio import stdio_server

app = Server("enterprise-rag-server")

@app.list_tools()
async def list_tools():
    return [Tool(**t) for t in RAGServer.MCP_TOOLS]

@app.call_tool()
async def call_tool(name: str, arguments: dict):
    handler = server.get_mcp_tool_map()[name]
    result  = await handler(**arguments, agent_id=ctx.agent_id, ...)
    return [TextContent(type="text", text=json.dumps(result))]

async def main():
    async with stdio_server() as (r, w):
        await app.run(r, w, InitializationOptions(...))
```

### AWS Architecture (Production)

```
Internet
    │
    ▼
Application Load Balancer
    │
    ▼
ECS Fargate (MCP Servers)
    ├── RAG Server container
    ├── Feature Store Server container
    └── Governance Server container
         │
         ├── Amazon Bedrock (Claude, Titan)    ← LLM + Embeddings
         ├── RDS PostgreSQL + pgvector          ← Vector store
         ├── S3 + Apache Iceberg               ← Feature store (offline)
         ├── ElastiCache Redis                 ← Feature store (online)
         ├── AWS Lake Formation                ← Column-level access control
         ├── AWS Secrets Manager               ← PII token vault
         ├── Amazon Macie                      ← PII auto-classification in S3
         └── S3 append-only                   ← Audit log
```

---

## Technology Stack

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Protocol | MCP 1.0 | Agent-to-data standard interface |
| LLM | Amazon Bedrock (Claude) | Inference, in-VPC |
| Embeddings | Bedrock Titan Embed v2 | Text → vector |
| Re-ranking | Bedrock Rerank v1 | Cross-encoder re-ranking |
| Vector store | PostgreSQL + pgvector | Dense + sparse hybrid search |
| Table format | Apache Iceberg | Feature store offline, time-travel |
| Transformation | dbt | AI-ready dataset curation |
| PII detection | Microsoft Presidio | Named entity recognition |
| RAG evaluation | RAGAS | Faithfulness, relevancy, precision |
| Lineage | OpenLineage / Marquez | Data + retrieval provenance |
| Access control | AWS Lake Formation | Column/row-level security |
| Audit | S3 append-only | Immutable compliance log |
| Streaming | Apache Kafka | Real-time feature freshness |
| Orchestration | Apache Airflow | Pipeline scheduling |

---

## Project Structure

```
enterprise-mcp-ai-platform/
├── README.md                          # This file
├── requirements.txt                   # Python dependencies
├── requirements-dev.txt               # Dev + test dependencies
├── setup.py                           # Package installation
├── .env.example                       # Environment variable template
├── .gitignore                         # Git ignore rules
├── docker-compose.yml                 # Local pgvector + Redis
├── Makefile                           # Convenience commands
│
├── src/
│   ├── __init__.py
│   ├── guardrails/
│   │   ├── __init__.py
│   │   ├── pii_shield.py              # Core PII detection + anonymization
│   │   ├── prompt_guard.py            # Pre/post LLM inspection
│   │   └── audit_logger.py            # Immutable audit trail
│   ├── servers/
│   │   ├── __init__.py
│   │   ├── rag_server.py              # MCP RAG server (4 tools)
│   │   ├── feature_store_server.py    # MCP feature store server (3 tools)
│   │   └── governance_server.py       # MCP lineage + audit server
│   └── utils/
│       ├── __init__.py
│       ├── embedding_client.py        # Bedrock Titan embedding wrapper
│       └── config.py                  # Configuration management
│
├── config/
│   ├── pii_config.yaml                # PII entity rules + access policies
│   └── access_policy.yaml             # Agent role → tool permissions
│
├── tests/
│   ├── __init__.py
│   ├── test_pii_shield.py             # Unit tests for PII shield
│   ├── test_prompt_guard.py           # Unit tests for prompt/response guards
│   ├── test_rag_server.py             # Integration tests for RAG server
│   ├── test_feature_store.py          # Integration tests for feature store
│   └── test_guardrail_pipeline.py     # End-to-end pipeline tests
│
├── docs/
│   ├── architecture.md                # Detailed architecture docs
│   ├── pii_modes.md                   # PII mode decision guide
│   └── production_checklist.md        # Pre-production checklist
│
└── scripts/
    ├── setup_pgvector.sql             # Database schema setup
    └── seed_demo_data.py              # Load demo data for testing
```

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Add tests for new functionality
4. Ensure all tests pass (`python -m pytest tests/ -v`)
5. Submit a pull request

### Key principles for contributions

- **No PII in logs.** Audit events log metadata only — never original text, never masked values.
- **Guardrails are not optional.** Every new tool handler must pass through PIIShield.
- **Fail closed, not open.** If a guardrail errors, the pipeline aborts — it does not silently pass through.
- **Config over code.** PII rules belong in `pii_config.yaml`, not hardcoded in handlers.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Acknowledgements

Built on:
- [Model Context Protocol](https://modelcontextprotocol.io) by Anthropic
- [Microsoft Presidio](https://microsoft.github.io/presidio/) for PII detection
- [RAGAS](https://docs.ragas.io) for RAG evaluation
- [pgvector](https://github.com/pgvector/pgvector) for vector similarity search
