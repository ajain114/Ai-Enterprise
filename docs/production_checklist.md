# Production Deployment Checklist

Work through this checklist before going live. Every item marked **REQUIRED**
must be complete. Items marked **RECOMMENDED** are strongly advised for
regulated-industry deployments.

---

## 1. PII Guardrail Configuration

### REQUIRED

- [ ] `config/pii_config.yaml` reviewed and signed off by your Data Protection Officer
- [ ] All high-risk entity types (`US_SSN`, `CREDIT_CARD`, `US_PASSPORT`) are in **BLOCK** mode
- [ ] `token_vault_arn` points to a real AWS Secrets Manager secret (not empty string)
- [ ] `block_on_unknown_agent: true` — unknown agent roles see nothing
- [ ] `audit_all_events: true` — all PII events are logged

### Replace demo stubs with Presidio

The demo uses regex patterns. Production requires Microsoft Presidio:

```bash
pip install presidio-analyzer presidio-anonymizer
python -m spacy download en_core_web_lg
```

In `src/guardrails/pii_shield.py`, replace `_detect_entities()`:

```python
from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

provider = NlpEngineProvider(nlp_configuration={
    "nlp_engine_name": "spacy",
    "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
})
analyzer = AnalyzerEngine(nlp_engine=provider.create_engine())

def _detect_entities(self, text: str) -> list[dict]:
    results = analyzer.analyze(text=text, language="en")
    return [
        {
            "entity_type":   r.entity_type,
            "start":         r.start,
            "end":           r.end,
            "score":         r.score,
            "original_text": text[r.start:r.end],
        }
        for r in results
    ]
```

### RECOMMENDED

- [ ] Custom domain entity recognizers added for your organisation's ID formats
- [ ] Presidio confidence thresholds tuned on a sample of your actual data
- [ ] Regular expression fallbacks added for patterns Presidio may miss
- [ ] PII config tested against a labelled dataset of representative documents

---

## 2. AWS Infrastructure

### REQUIRED

- [ ] All MCP servers run inside a **VPC** — no public endpoints
- [ ] Bedrock inference runs in the same account/region (no cross-account LLM calls)
- [ ] Lake Formation enabled on the Glue Data Catalog
- [ ] Column-level security configured for all tables containing PII
- [ ] IAM roles created for each agent type with least-privilege policies
- [ ] S3 audit bucket has **Object Lock** enabled (COMPLIANCE mode, 7-year retention)
- [ ] S3 audit bucket has **no DELETE permissions** for any IAM principal
- [ ] AWS Secrets Manager secret created for PII token vault
- [ ] Secret rotation enabled (90-day rotation recommended)

### RECOMMENDED

- [ ] AWS Macie enabled on S3 buckets containing source documents
- [ ] Macie findings piped to CloudWatch Events → SNS alert
- [ ] GuardDuty enabled in the account
- [ ] CloudTrail enabled and logs shipped to the audit S3 bucket
- [ ] VPC Flow Logs enabled

---

## 3. pgvector (Vector Store)

### REQUIRED

Replace `PGVectorClient.connect()` in `src/servers/rag_server.py`:

```python
import psycopg2
from psycopg2 import pool
from pgvector.psycopg2 import register_vector

self._pool = pool.ThreadedConnectionPool(
    minconn=2, maxconn=20,
    host=config.db.host,
    port=config.db.port,
    database=config.db.database,
    user=config.db.user,
    password=config.db.password,
    sslmode="require",          # REQUIRED for production
)
with self._pool.getconn() as conn:
    register_vector(conn)
```

Replace `hybrid_search()` with the full SQL from the docstring comments.

- [ ] SSL enabled on the RDS/Aurora PostgreSQL instance (`sslmode=require`)
- [ ] pgvector HNSW index created (see `scripts/setup_pgvector.sql`)
- [ ] Read replica created for RAG query traffic (separate from write primary)
- [ ] Connection pooling configured (PgBouncer or RDS Proxy)
- [ ] Automated backups enabled (7-day minimum retention)
- [ ] Row-Level Security policies reviewed and tested for each agent role

### RECOMMENDED

- [ ] Performance baseline measured: p50, p95, p99 retrieval latency
- [ ] Slow query logging enabled (> 100ms threshold)
- [ ] Index rebuild scheduled for off-peak (HNSW degrades without maintenance)

---

## 4. Bedrock (LLM + Embeddings)

### Replace stubs

In `src/utils/embedding_client.py`:

```python
import boto3, json

self._client = boto3.client(
    "bedrock-runtime",
    region_name=config.aws.region,
)

def embed(self, text: str) -> list[float]:
    response = self._client.invoke_model(
        modelId=self.config.embed_model_id,
        body=json.dumps({"inputText": text}),
    )
    return json.loads(response["body"].read())["embedding"]
```

- [ ] Bedrock model access granted in AWS console for your account/region
- [ ] Embedding model ID verified (`amazon.titan-embed-text-v2:0`)
- [ ] LLM model ID verified and appropriate for use case
- [ ] Bedrock VPC endpoint created (keeps inference traffic inside your VPC)
- [ ] Bedrock throttling limits reviewed and Service Quota increases requested
- [ ] Retry logic implemented (exponential backoff on `ThrottlingException`)

### RECOMMENDED

- [ ] Embedding cache implemented (Redis) for frequent query patterns
- [ ] Embedding model version pinned and upgrade process documented
- [ ] Cost alerting configured (Bedrock usage by model)

---

## 5. MCP Server Deployment (Amazon ECS Fargate)

### REQUIRED

Replace `main()` in each server with MCP stdio/SSE wire-up:

```python
# For stdio (local AgentCore):
from mcp.server.stdio import stdio_server
async def main():
    async with stdio_server() as (r, w):
        await app.run(r, w, InitializationOptions(...))

# For SSE (remote agents over HTTP):
from mcp.server.sse import SseServerTransport
async def main():
    transport = SseServerTransport("/messages")
    async with transport.connect_sse(scope, receive, send) as (r, w):
        await app.run(r, w, InitializationOptions(...))
```

- [ ] ECS task definition created with appropriate CPU/memory
- [ ] Task role has least-privilege IAM policy (Bedrock, S3 audit, Secrets Manager)
- [ ] Secrets injected via ECS Secrets Manager integration (not environment variables)
- [ ] Health check endpoint implemented (`/health`)
- [ ] Application Load Balancer configured with mTLS for agent authentication
- [ ] ECS service auto-scaling configured (target tracking on CPU/request count)
- [ ] Container image scanned for vulnerabilities (ECR scan on push)

### RECOMMENDED

- [ ] Blue/green deployment configured for zero-downtime updates
- [ ] Canary deployment for MCP server updates (10% traffic → 100%)
- [ ] Distributed tracing enabled (AWS X-Ray)

---

## 6. OpenLineage / Audit Trail

### REQUIRED

Replace stub in `src/utils/openlineage_client.py`:

```python
from openlineage.client import OpenLineageClient
from openlineage.client.transport.http import HttpConfig, HttpTransport

client = OpenLineageClient(
    transport=HttpTransport(
        HttpConfig(url=config.lineage.url, endpoint="api/v1/lineage")
    )
)
```

- [ ] Marquez (or Apache Atlas) deployed and accessible from MCP servers
- [ ] OpenLineage namespace configured (`config.lineage.namespace`)
- [ ] Lineage events emitted for: data ingestion, dbt runs, embedding jobs, RAG retrievals
- [ ] Audit log S3 bucket verified append-only with Object Lock
- [ ] Athena table created over audit S3 bucket (for Model Risk queries)
- [ ] Sample audit query validated: reconstruct agent session context

### RECOMMENDED

- [ ] Lineage retention policy documented (7 years for regulated data)
- [ ] Marquez UI access restricted to Model Risk and Compliance teams
- [ ] Automated lineage completeness check (alert if lineage gap > 1 hour)

---

## 7. Monitoring & Alerting

### REQUIRED

- [ ] CloudWatch dashboard created: latency (p50/p95/p99), error rate, PII event rate
- [ ] Alert: `PII_LEAKAGE_DETECTED` events → PagerDuty (CRITICAL severity)
- [ ] Alert: `PROMPT_BLOCKED` rate > 0.1% of requests → investigation
- [ ] Alert: RAG p95 latency > 2 seconds → investigation
- [ ] Alert: Audit log write failures → CRITICAL (compliance gap)
- [ ] Alert: Bedrock error rate > 1% → investigation

### RECOMMENDED

- [ ] RAGAS scores tracked in CloudWatch as custom metrics
- [ ] Weekly RAGAS quality report automated
- [ ] Model Risk dashboard built on Athena + QuickSight over audit logs
- [ ] Runbook written for each alert type

---

## 8. Data Governance

### REQUIRED

- [ ] `config/access_policy.yaml` reviewed by InfoSec and signed off
- [ ] Data contracts documented for every source system feeding the RAG corpus
- [ ] PII classification validated on a representative sample (not just config)
- [ ] Data retention policy implemented (chunks, embeddings, audit logs)
- [ ] GDPR/CCPA deletion process: procedure documented for removing an entity's data
- [ ] Model Risk sign-off obtained on RAG evaluation framework (RAGAS thresholds)

### RECOMMENDED

- [ ] Data lineage review with Model Risk team (walk through a full agent session)
- [ ] Red team exercise: attempt to extract PII from the system
- [ ] Penetration test on MCP server endpoints

---

## 9. Go-Live Gate

All REQUIRED items above must be checked before production traffic.

Final sign-offs required from:
- [ ] Engineering lead
- [ ] InfoSec / Security team
- [ ] Data Protection Officer
- [ ] Model Risk (for financial/regulated deployments)
- [ ] Legal / Compliance

Document the sign-off date and the version of this checklist used.
Archive the completed checklist in your compliance record system.
