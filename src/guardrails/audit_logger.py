"""
src/guardrails/audit_logger.py
================================
Centralised, structured audit logger for all MCP platform events.

Design principles:
  1. Append-only  — events are never updated or deleted.
  2. PII-free     — only metadata is logged; original text is never stored.
  3. Structured   — all events are JSON with consistent schema.
  4. Correlated   — every event carries session_id for cross-event tracing.
  5. Escalating   — CRITICAL events trigger immediate notification callbacks.

Event types emitted:
  MCP_TOOL_CALL       — every agent tool invocation
  PII_PROCESSED       — chunk/prompt where PII was detected and handled
  PII_BLOCKED         — pipeline aborted due to BLOCK-mode PII
  PROMPT_INSPECTED    — PromptGuard result
  PROMPT_BLOCKED      — PromptGuard blocked a prompt
  RESPONSE_INSPECTED  — ResponseGuard result
  PII_LEAKAGE         — ResponseGuard detected PII in LLM output (CRITICAL)
  DATA_POLICY_CHECK   — Governance server policy validation

In production, events flow to:
  → S3 append-only bucket (compliance archive, queryable via Athena)
  → OpenLineage / Marquez (lineage correlation)
  → CloudWatch Logs (operational monitoring)
  → SNS → SIEM (CRITICAL events only, e.g. PII_LEAKAGE)

Usage:
    logger = AuditLogger.from_config(config)

    # Log a tool call
    logger.log_tool_call(tool_name="search_knowledge_base", agent_id="a-01", ...)

    # Log a PII event
    logger.log_pii_event(event_type="PII_PROCESSED", agent_id="a-01", ...)

    # Register a callback for CRITICAL events (e.g. SNS publisher)
    logger.register_escalation_callback(my_sns_publisher)
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from src.utils.config import PlatformConfig, get_config

logger = logging.getLogger(__name__)


class AuditEvent:
    """Immutable structured audit event."""

    VALID_TYPES = {
        "MCP_TOOL_CALL",
        "PII_PROCESSED",
        "PII_BLOCKED",
        "PROMPT_INSPECTED",
        "PROMPT_BLOCKED",
        "RESPONSE_INSPECTED",
        "PII_LEAKAGE",
        "DATA_POLICY_CHECK",
        "TOKEN_ISSUED",
        "UNAUTHORIZED_ACCESS",
    }

    SEVERITY_LEVELS = {"DEBUG", "INFO", "WARNING", "HIGH", "CRITICAL"}

    def __init__(
        self,
        event_type:     str,
        agent_id:       str,
        agent_role:     str     = "",
        session_id:     str     = "",
        tool_name:      str     = "",
        severity:       str     = "INFO",
        metadata:       dict    = None,
    ):
        if event_type not in self.VALID_TYPES:
            raise ValueError(f"Invalid event_type: {event_type}. Must be one of {self.VALID_TYPES}")
        if severity not in self.SEVERITY_LEVELS:
            raise ValueError(f"Invalid severity: {severity}")

        self.event_id   = str(uuid.uuid4())
        self.event_type = event_type
        self.agent_id   = agent_id
        self.agent_role = agent_role
        self.session_id = session_id
        self.tool_name  = tool_name
        self.severity   = severity
        self.metadata   = metadata or {}
        self.timestamp  = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        return {
            "event_id":   self.event_id,
            "event_type": self.event_type,
            "agent_id":   self.agent_id,
            "agent_role": self.agent_role,
            "session_id": self.session_id,
            "tool_name":  self.tool_name,
            "severity":   self.severity,
            "timestamp":  self.timestamp,
            **self.metadata,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class AuditLogger:
    """
    Centralised audit logger for all MCP platform events.

    Backends:
      - Structured log output (always active, goes to CloudWatch in production)
      - S3 append-only bucket (production)
      - OpenLineage emitter (production)
      - Escalation callbacks for CRITICAL severity (production: SNS)
    """

    def __init__(
        self,
        config:               PlatformConfig | None      = None,
        escalation_callbacks: list[Callable]             = None,
    ):
        self.config    = config or get_config()
        self._callbacks: list[Callable] = escalation_callbacks or []
        self._s3_client = None     # boto3 client in production
        self._ol_client = None     # OpenLineage client in production

    @classmethod
    def from_config(cls, config: PlatformConfig) -> "AuditLogger":
        return cls(config=config)

    def register_escalation_callback(self, callback: Callable) -> None:
        """Register a callback invoked for CRITICAL severity events."""
        self._callbacks.append(callback)

    # ── High-level log methods ────────────────────────────────────────────────

    def log_tool_call(
        self,
        tool_name:    str,
        agent_id:     str,
        agent_role:   str,
        session_id:   str,
        query:        str,            # Will be hashed — never stored in plaintext
        chunk_ids:    list[str],
        pii_detected: bool,
        latency_ms:   int,
    ) -> str:
        """Log an MCP tool invocation. Returns event_id for correlation."""
        event = AuditEvent(
            event_type="MCP_TOOL_CALL",
            agent_id=agent_id,
            agent_role=agent_role,
            session_id=session_id,
            tool_name=tool_name,
            severity="INFO",
            metadata={
                "query_hash":   hashlib.sha256(query.encode()).hexdigest(),
                "chunk_ids":    chunk_ids,
                "pii_detected": pii_detected,
                "latency_ms":   latency_ms,
            },
        )
        self._emit(event)
        return event.event_id

    def log_pii_event(
        self,
        event_type:    str,        # PII_PROCESSED | PII_BLOCKED | PII_LEAKAGE
        agent_id:      str,
        session_id:    str,
        entity_types:  list[str],
        modes_applied: list[str],
        was_modified:  bool,
        severity:      str = "INFO",
        context_id:    str = "",
    ) -> str:
        """Log a PII detection/handling event. Returns event_id."""
        event = AuditEvent(
            event_type=event_type,
            agent_id=agent_id,
            session_id=session_id,
            severity=severity,
            metadata={
                "entity_types":  entity_types,
                "modes_applied": modes_applied,
                "was_modified":  was_modified,
                "context_id":    context_id,
                # NEVER log original_text or safe_text here
            },
        )
        self._emit(event)
        return event.event_id

    def log_policy_check(
        self,
        dataset_name: str,
        use_case:     str,
        agent_id:     str,
        agent_role:   str,
        approved:     bool,
    ) -> str:
        event = AuditEvent(
            event_type="DATA_POLICY_CHECK",
            agent_id=agent_id,
            agent_role=agent_role,
            severity="INFO",
            metadata={
                "dataset_name": dataset_name,
                "use_case":     use_case,
                "approved":     approved,
            },
        )
        self._emit(event)
        return event.event_id

    def log_unauthorized(self, agent_id: str, agent_role: str, tool: str) -> str:
        event = AuditEvent(
            event_type="UNAUTHORIZED_ACCESS",
            agent_id=agent_id,
            agent_role=agent_role,
            tool_name=tool,
            severity="HIGH",
            metadata={"denied_tool": tool},
        )
        self._emit(event)
        return event.event_id

    # ── Generic emit (used by PIIShield and guards) ───────────────────────────

    def emit(self, raw_event: dict) -> None:
        """Accept a raw event dict from PIIShield / PromptGuard / ResponseGuard."""
        level = {
            "CRITICAL": logging.CRITICAL,
            "HIGH":     logging.WARNING,
            "WARNING":  logging.WARNING,
        }.get(raw_event.get("severity", "INFO"), logging.INFO)

        logger.log(level, "AUDIT | %s", json.dumps(raw_event))

        if raw_event.get("severity") == "CRITICAL":
            for cb in self._callbacks:
                try:
                    cb(raw_event)
                except Exception as e:
                    logger.error("Escalation callback failed: %s", e)

    # ── Internal emit ─────────────────────────────────────────────────────────

    def _emit(self, event: AuditEvent) -> None:
        level = {
            "CRITICAL": logging.CRITICAL,
            "HIGH":     logging.WARNING,
            "WARNING":  logging.WARNING,
        }.get(event.severity, logging.INFO)

        logger.log(level, "AUDIT | %s", event.to_json())

        # Production: write to S3
        # self._write_to_s3(event)

        # Production: emit to OpenLineage
        # self._emit_openlineage(event)

        # Escalate CRITICAL events
        if event.severity == "CRITICAL":
            for cb in self._callbacks:
                try:
                    cb(event.to_dict())
                except Exception as e:
                    logger.error("Escalation callback failed: %s", e)

    def _write_to_s3(self, event: AuditEvent) -> None:
        """
        In production:
            key = f"audit/{event.timestamp[:10]}/{event.event_id}.json"
            self._s3_client.put_object(
                Bucket=self.config.aws.audit_s3_bucket,
                Key=key,
                Body=event.to_json(),
                ContentType="application/json",
                # Enforce append-only via bucket policy (no DeleteObject permission)
            )
        """

    def _emit_openlineage(self, event: AuditEvent) -> None:
        """
        In production (using openlineage-python):
            from openlineage.client import OpenLineageClient
            from openlineage.client.run import RunEvent, RunState, Run, Job

            client = OpenLineageClient(url=self.config.lineage.url)
            client.emit(RunEvent(
                eventType=RunState.COMPLETE,
                eventTime=event.timestamp,
                run=Run(runId=event.event_id),
                job=Job(namespace=self.config.lineage.namespace, name=event.tool_name),
                inputs=[], outputs=[],
            ))
        """
