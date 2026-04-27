"""
src/utils/config.py
====================
Centralised configuration management.
Loads from environment variables + .env file.
All server components import from here — never from os.getenv() directly.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from functools import lru_cache

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class DatabaseConfig:
    host:     str = field(default_factory=lambda: os.getenv("PG_HOST", "localhost"))
    port:     int = field(default_factory=lambda: int(os.getenv("PG_PORT", "5432")))
    database: str = field(default_factory=lambda: os.getenv("PG_DATABASE", "ai_rag_platform"))
    user:     str = field(default_factory=lambda: os.getenv("PG_USER", "rag_reader"))
    password: str = field(default_factory=lambda: os.getenv("PG_PASSWORD", "changeme"))
    schema:   str = field(default_factory=lambda: os.getenv("PG_SCHEMA", "rag"))

    @property
    def dsn(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.database}"


@dataclass(frozen=True)
class AWSConfig:
    region:          str = field(default_factory=lambda: os.getenv("AWS_REGION", "us-east-1"))
    embed_model_id:  str = field(default_factory=lambda: os.getenv("EMBED_MODEL_ID", "amazon.titan-embed-text-v2:0"))
    rerank_model_id: str = field(default_factory=lambda: os.getenv("RERANK_MODEL_ID", "amazon.rerank-v1:0"))
    llm_model_id:    str = field(default_factory=lambda: os.getenv("LLM_MODEL_ID", "anthropic.claude-3-5-sonnet-20241022-v2:0"))
    audit_s3_bucket: str = field(default_factory=lambda: os.getenv("AUDIT_S3_BUCKET", "ai-audit-logs"))
    token_vault_arn: str = field(default_factory=lambda: os.getenv("TOKEN_VAULT_ARN", ""))


@dataclass(frozen=True)
class RedisConfig:
    host:     str = field(default_factory=lambda: os.getenv("REDIS_HOST", "localhost"))
    port:     int = field(default_factory=lambda: int(os.getenv("REDIS_PORT", "6379")))
    password: str = field(default_factory=lambda: os.getenv("REDIS_PASSWORD", ""))


@dataclass(frozen=True)
class LineageConfig:
    url:       str = field(default_factory=lambda: os.getenv("OPENLINEAGE_URL", "http://localhost:5000"))
    namespace: str = field(default_factory=lambda: os.getenv("OPENLINEAGE_NAMESPACE", "mcp-ai-platform"))


@dataclass(frozen=True)
class ServerConfig:
    embedding_dim:    int = field(default_factory=lambda: int(os.getenv("EMBEDDING_DIM", "1536")))
    embedding_table:  str = field(default_factory=lambda: os.getenv("EMBEDDING_TABLE", "document_chunks"))
    default_top_k:    int = field(default_factory=lambda: int(os.getenv("DEFAULT_TOP_K", "10")))
    rerank_top_k:     int = field(default_factory=lambda: int(os.getenv("RERANK_TOP_K", "3")))
    max_top_k:        int = field(default_factory=lambda: int(os.getenv("MAX_TOP_K", "20")))
    pii_config_path:  str = field(default_factory=lambda: os.getenv("PII_CONFIG_PATH", "config/pii_config.yaml"))
    access_policy:    str = field(default_factory=lambda: os.getenv("ACCESS_POLICY_PATH", "config/access_policy.yaml"))
    log_level:        str = field(default_factory=lambda: os.getenv("LOG_LEVEL", "INFO"))
    server_name:      str = "enterprise-mcp-ai-platform"
    server_version:   str = "1.0.0"


@dataclass(frozen=True)
class PlatformConfig:
    db:      DatabaseConfig = field(default_factory=DatabaseConfig)
    aws:     AWSConfig      = field(default_factory=AWSConfig)
    redis:   RedisConfig    = field(default_factory=RedisConfig)
    lineage: LineageConfig  = field(default_factory=LineageConfig)
    server:  ServerConfig   = field(default_factory=ServerConfig)


@lru_cache(maxsize=1)
def get_config() -> PlatformConfig:
    """Singleton config — loaded once, cached for the process lifetime."""
    return PlatformConfig()
