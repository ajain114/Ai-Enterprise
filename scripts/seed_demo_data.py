"""
scripts/seed_demo_data.py
==========================
Seed demo data into the local development stack for testing.

Seeds:
  - pgvector: sample document chunks with embeddings
  - PostgreSQL: sample documents in the rag.documents table
  - Redis: sample online feature values

Run:
    python scripts/seed_demo_data.py

    # Or via make:
    make db-seed

Prerequisites:
    docker-compose up -d    # Start pgvector and Redis
    python scripts/seed_demo_data.py
"""

from __future__ import annotations

import json
import logging
import os
import random
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)


# ── Demo data ─────────────────────────────────────────────────────────────────

DEMO_DOCUMENTS = [
    {
        "title":   "Dispute Resolution Policy v2.3",
        "domain":  "servicing",
        "class":   "INTERNAL",
        "chunks": [
            "Customers must file disputes within 60 days of the statement date showing the transaction.",
            "Upon receiving a dispute, the team has 10 business days to provide a provisional resolution.",
            "Disputes are investigated by reviewing merchant communication, transaction logs, and authorization records.",
            "Provisional credits are issued within 5 business days of a dispute being accepted for investigation.",
            "If the dispute is found in the customer's favour, the credit becomes permanent and the merchant is debited.",
        ],
    },
    {
        "title":   "Collections Outreach Procedures",
        "domain":  "collections",
        "class":   "INTERNAL",
        "chunks": [
            "Initial outreach begins when an account reaches 30 days past due.",
            "Collections agents must follow the Fair Debt Collection Practices Act in all communications.",
            "Promise-to-pay arrangements must be documented in the collections system within 24 hours.",
            "Accounts more than 90 days past due are referred to the recovery team for escalated handling.",
            "All contact attempts must be logged with timestamp, channel, and outcome.",
        ],
    },
    {
        "title":   "Risk Scoring Methodology v4.1",
        "domain":  "risk",
        "class":   "INTERNAL",
        "chunks": [
            "Credit risk scores are computed using a combination of bureau data and internal behavioural signals.",
            "The primary risk model uses payment ratio, utilization rate, and delinquency history as key inputs.",
            "Risk tiers range from LOW (score >= 0.80) to HIGH (score < 0.40).",
            "Model performance is reviewed quarterly against a holdout validation set.",
            "Feature drift is monitored weekly — alerts fire when PSI exceeds 0.20 for any feature.",
        ],
    },
    {
        "title":   "Product Terms and Conditions",
        "domain":  "servicing",
        "class":   "STANDARD",
        "chunks": [
            "The annual percentage rate (APR) for purchases is variable and tied to the Prime Rate.",
            "Minimum payment due is the greater of $25 or 2% of the outstanding balance.",
            "Late payment fees apply when the minimum payment is not received by the due date.",
            "The grace period for new purchases is 21 days from the statement closing date.",
            "Balance transfers are subject to a fee of 3% of the transferred amount.",
        ],
    },
    {
        "title":   "Fraud Detection Guidelines",
        "domain":  "fraud",
        "class":   "INTERNAL",
        "chunks": [
            "Transactions flagged by the real-time fraud model require manual review within 2 hours.",
            "Card-not-present transactions above the threshold trigger step-up authentication.",
            "Velocity checks monitor for more than 5 transactions in a 10-minute window.",
            "Accounts with suspected synthetic identity fraud are placed in enhanced monitoring.",
            "Confirmed fraud cases are reported to the appropriate regulatory bodies within 72 hours.",
        ],
    },
]

DEMO_FEATURE_TOKENS = [
    "TOK_DEMO_ENT001",
    "TOK_DEMO_ENT002",
    "TOK_DEMO_ENT003",
]

DEMO_FEATURES = {
    "credit_risk": {
        "payment_ratio_3m":   0.92,
        "utilization_rate":   0.24,
        "delinquency_score":  0.08,
        "risk_band":          3,
    },
    "churn_risk": {
        "engagement_score":    0.74,
        "product_count":       2,
        "last_activity_days":  12,
        "satisfaction_band":   4,
    },
    "collections_propensity": {
        "days_past_due":    0,
        "promise_count":    0,
        "contact_attempts": 1,
        "balance_band":     2,
    },
    "cross_sell": {
        "income_band":           3,
        "product_gap_score":     0.6,
        "digital_response_rate": 0.22,
        "ltv_band":              3,
    },
}


# ── Seeders ───────────────────────────────────────────────────────────────────

def seed_postgres() -> None:
    """
    Seed pgvector with demo document chunks.

    In production: replace with real Bedrock Titan embeddings.
    Demo uses random unit vectors as placeholders.
    """
    try:
        import psycopg2
        from psycopg2.extras import execute_values

        conn = psycopg2.connect(
            host     = os.getenv("PG_HOST",     "localhost"),
            port     = int(os.getenv("PG_PORT", "5432")),
            dbname   = os.getenv("PG_DATABASE", "ai_rag_platform"),
            user     = os.getenv("PG_USER",     "rag_reader"),
            password = os.getenv("PG_PASSWORD", "changeme"),
        )
        cur = conn.cursor()

        # Check pgvector extension
        cur.execute("SELECT 1 FROM pg_extension WHERE extname = 'vector'")
        if not cur.fetchone():
            logger.warning("pgvector extension not installed — run setup_pgvector.sql first")
            conn.close()
            return

        chunk_count = 0
        for doc in DEMO_DOCUMENTS:
            doc_id = str(uuid.uuid4())

            # Insert document record
            cur.execute(
                """
                INSERT INTO rag.documents (document_id, title, domain, data_class, created_by)
                VALUES (%s, %s, %s, %s, %s)
                ON CONFLICT DO NOTHING
                """,
                (doc_id, doc["title"], doc["domain"], doc["class"], "seed_script"),
            )

            # Insert chunks with demo embeddings
            for idx, chunk_text in enumerate(doc["chunks"]):
                # Demo embedding: random unit vector (replace with Bedrock Titan in production)
                random.seed(hash(chunk_text) % 2**31)
                raw_vec  = [random.gauss(0, 1) for _ in range(1536)]
                mag      = sum(x**2 for x in raw_vec) ** 0.5
                embedding = [x / mag for x in raw_vec]

                cur.execute(
                    """
                    INSERT INTO rag.document_chunks
                        (document_id, chunk_index, chunk_text, embedding, domain, data_class)
                    VALUES (%s, %s, %s, %s::vector, %s, %s)
                    ON CONFLICT DO NOTHING
                    """,
                    (doc_id, idx, chunk_text, embedding, doc["domain"], doc["class"]),
                )
                chunk_count += 1

        conn.commit()
        cur.close()
        conn.close()
        logger.info("✓ PostgreSQL/pgvector: inserted %d chunks across %d documents",
                    chunk_count, len(DEMO_DOCUMENTS))

    except ImportError:
        logger.warning("psycopg2 not installed — skipping PostgreSQL seed (pip install psycopg2-binary)")
    except Exception as e:
        logger.error("PostgreSQL seed failed: %s", e)
        logger.info("  Is docker-compose up? Run: docker-compose up -d")


def seed_redis() -> None:
    """Seed online feature store with demo entity features."""
    try:
        import redis as redis_lib

        r = redis_lib.Redis(
            host     = os.getenv("REDIS_HOST",     "localhost"),
            port     = int(os.getenv("REDIS_PORT", "6379")),
            password = os.getenv("REDIS_PASSWORD", "") or None,
            decode_responses=True,
        )
        r.ping()

        for token in DEMO_FEATURE_TOKENS:
            for feature_set, features in DEMO_FEATURES.items():
                key = f"{token}:{feature_set}"
                r.hset(key, mapping={k: str(v) for k, v in features.items()})
                r.expire(key, 86400)  # 24h TTL

        logger.info("✓ Redis: seeded %d feature sets for %d tokens",
                    len(DEMO_FEATURES), len(DEMO_FEATURE_TOKENS))

    except ImportError:
        logger.warning("redis not installed — skipping Redis seed (pip install redis)")
    except Exception as e:
        logger.error("Redis seed failed: %s", e)
        logger.info("  Is docker-compose up? Run: docker-compose up -d")


def seed_minio() -> None:
    """Create MinIO buckets for local development."""
    try:
        import boto3
        from botocore.exceptions import ClientError

        endpoint = os.getenv("AWS_ENDPOINT_URL", "http://localhost:9000")
        s3 = boto3.client(
            "s3",
            endpoint_url         = endpoint,
            aws_access_key_id    = os.getenv("AWS_ACCESS_KEY_ID",     "admin"),
            aws_secret_access_key= os.getenv("AWS_SECRET_ACCESS_KEY", "changeme123"),
        )

        buckets = ["ai-audit-logs", "ai-feature-store", "ai-model-artifacts"]
        for bucket in buckets:
            try:
                s3.create_bucket(Bucket=bucket)
                logger.info("✓ MinIO: created bucket '%s'", bucket)
            except ClientError as e:
                if e.response["Error"]["Code"] == "BucketAlreadyOwnedByYou":
                    logger.info("  MinIO: bucket '%s' already exists", bucket)
                else:
                    raise

    except ImportError:
        logger.warning("boto3 not installed — skipping MinIO seed (pip install boto3)")
    except Exception as e:
        logger.error("MinIO seed failed: %s | Is docker-compose up?", e)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    logger.info("=" * 50)
    logger.info("  Enterprise MCP AI Platform — Demo Data Seeder")
    logger.info("=" * 50)

    from dotenv import load_dotenv
    load_dotenv()

    seed_postgres()
    seed_redis()
    seed_minio()

    logger.info("")
    logger.info("Seed complete. Run tests with: python tests/test_guardrail_pipeline.py")


if __name__ == "__main__":
    main()
