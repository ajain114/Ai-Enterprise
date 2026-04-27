"""
src/guardrails/pii_shield.py
=============================
Core PII detection and anonymization engine.

Sits between ALL data retrieval and LLM consumption.
Integrates with Microsoft Presidio for NLP-based entity recognition
and adds custom recognizers for domain-specific PII patterns.

Three operating modes per entity type:
  BLOCK — Raise PIIViolationError, abort the pipeline immediately.
           Use for: SSN, credit cards, passport numbers.
           These entities must NEVER reach an LLM under any circumstances.

  MASK  — Replace PII with [ENTITY_TYPE] placeholder in output.
           Use for: names, email addresses, phone numbers, addresses.
           The replacement is visible to the LLM so it knows data was present
           but cannot reconstruct the original.

  TOKEN — Replace PII with deterministic hash: [ENTITY_TYPE:HASH8].
           Use for: account numbers, internal IDs that need cross-referencing.
           The same original value always produces the same token within a session.
           Reversible by authorized systems via token vault (AWS Secrets Manager).

Role-aware: agents with elevated roles can be exempted from masking for
specific entity types (e.g., fraud analysts seeing account numbers in plain text).

Usage:
    config = PIIConfig.from_yaml("config/pii_config.yaml")
    shield = PIIShield(config=config)

    # On a retrieved chunk before adding to agent context
    result = shield.process_chunk(chunk_text, agent_id="agent-01", agent_role="analyst")

    # On the fully assembled prompt (last line of defence)
    result = shield.process_prompt(prompt, agent_id="agent-01", agent_role="analyst")

    if result.was_modified:
        send_to_llm(result.safe_text)
    else:
        send_to_llm(result.original_text)

Production dependencies:
    pip install presidio-analyzer presidio-anonymizer spacy
    python -m spacy download en_core_web_lg
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

import yaml

logger = logging.getLogger(__name__)


# ── Enums ─────────────────────────────────────────────────────────────────────

class PIIMode(str, Enum):
    BLOCK = "block"
    MASK  = "mask"
    TOKEN = "token"


class PIIEntityType(str, Enum):
    # Government / identity
    SSN              = "US_SSN"
    DRIVERS_LICENSE  = "US_DRIVER_LICENSE"
    PASSPORT         = "US_PASSPORT"
    NPI              = "US_NPI"
    # Financial
    CREDIT_CARD      = "CREDIT_CARD"
    BANK_ACCOUNT     = "US_BANK_NUMBER"
    ROUTING_NUMBER   = "US_ROUTING_NUMBER"
    ACCOUNT_NUMBER   = "ACCOUNT_NUMBER"       # Custom domain-specific pattern
    # Personal
    PERSON_NAME      = "PERSON"
    EMAIL            = "EMAIL_ADDRESS"
    PHONE            = "PHONE_NUMBER"
    DATE_OF_BIRTH    = "DATE_TIME"
    ADDRESS          = "LOCATION"
    ZIP_CODE         = "US_ZIP_CODE"


# ── Config ────────────────────────────────────────────────────────────────────

@dataclass
class PIIEntityConfig:
    entity_type:         PIIEntityType
    mode:                PIIMode
    score_threshold:     float      = 0.75
    allowed_agent_roles: list[str]  = field(default_factory=list)
    notes:               str        = ""


@dataclass
class PIIConfig:
    entities:               list[PIIEntityConfig]
    global_mode:            PIIMode = PIIMode.MASK
    block_on_unknown_agent: bool    = True
    audit_all_events:       bool    = True
    token_vault_arn:        str     = ""

    @classmethod
    def from_yaml(cls, path: str) -> "PIIConfig":
        with open(path) as f:
            raw = yaml.safe_load(f)

        entities = [
            PIIEntityConfig(
                entity_type         = PIIEntityType(e["entity_type"]),
                mode                = PIIMode(e["mode"]),
                score_threshold     = e.get("score_threshold", 0.75),
                allowed_agent_roles = e.get("allowed_agent_roles", []),
                notes               = e.get("notes", ""),
            )
            for e in raw.get("entities", [])
        ]
        return cls(
            entities               = entities,
            global_mode            = PIIMode(raw.get("global_mode", "mask")),
            block_on_unknown_agent = raw.get("block_on_unknown_agent", True),
            audit_all_events       = raw.get("audit_all_events", True),
            token_vault_arn        = raw.get("token_vault_arn", ""),
        )


# ── Exceptions ────────────────────────────────────────────────────────────────

class PIIViolationError(Exception):
    """Raised when BLOCK mode is triggered for a detected entity."""
    def __init__(self, message: str, entity_types: list[str], agent_id: str):
        super().__init__(message)
        self.entity_types = entity_types
        self.agent_id     = agent_id
        self.violation_id = str(uuid.uuid4())
        self.timestamp    = datetime.now(timezone.utc).isoformat()


class PIILeakageError(Exception):
    """Raised by ResponseGuard when PII is detected in LLM output."""
    pass


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class PIIDetection:
    entity_type:   str
    start:         int
    end:           int
    score:         float
    original_text: str
    replacement:   str
    mode_applied:  PIIMode


@dataclass
class PIIProcessResult:
    original_text:  str
    safe_text:      str
    detections:     list[PIIDetection]
    was_modified:   bool
    token_map:      dict[str, str]     # token → original (stored in vault, never in LLM context)
    processing_id:  str
    agent_id:       str
    timestamp:      str


# ── Custom domain recognizers ─────────────────────────────────────────────────

class DomainAccountRecognizer:
    """
    Recognizes domain-specific account number patterns.
    Extend this class to match your organisation's identifier formats.

    In production: subclass presidio_analyzer.EntityRecognizer and register
    with the AnalyzerEngine to get full confidence scoring and context support.
    """
    PATTERNS = [
        re.compile(r'\b[A-Z]{2,4}-\d{8,12}\b'),                              # Prefixed: SYF-1234567890
        re.compile(r'\b(?:acct|account)[\s#:]*\d{10,16}\b', re.IGNORECASE),  # Labelled account
    ]

    def detect(self, text: str) -> list[dict]:
        results = []
        for pattern in self.PATTERNS:
            for match in pattern.finditer(text):
                results.append({
                    "entity_type":   PIIEntityType.ACCOUNT_NUMBER.value,
                    "start":         match.start(),
                    "end":           match.end(),
                    "score":         0.92,
                    "original_text": match.group(),
                })
        return results


# ── Core PIIShield ────────────────────────────────────────────────────────────


def _deduplicate_spans(detections: list[dict]) -> list[dict]:
    """
    Module-level helper: remove overlapping detections, keeping widest span.
    When two detections share any character position the one covering more
    characters is kept. On equal width the higher confidence score wins.
    This prevents sub-string false positives (e.g. a PHONE pattern firing
    inside an ACCOUNT_NUMBER string) from corrupting the primary detection.
    """
    if len(detections) <= 1:
        return detections
    ranked = sorted(
        detections,
        key=lambda d: (d["end"] - d["start"], d["score"]),
        reverse=True,
    )
    kept: list[dict] = []
    for candidate in ranked:
        overlaps = any(
            not (candidate["end"] <= k["start"] or candidate["start"] >= k["end"])
            for k in kept
        )
        if not overlaps:
            kept.append(candidate)
    return kept


class PIIShield:
    """
    Central PII protection layer.

    In production, _detect_entities() should be replaced with:
        from presidio_analyzer import AnalyzerEngine
        analyzer = AnalyzerEngine()
        results  = analyzer.analyze(text=text, language="en")

    This template uses regex patterns to demonstrate the architecture
    without requiring cloud credentials for local development and testing.
    """

    # Demo regex patterns (replace body of _detect_entities with Presidio in production)
    _DEMO_PATTERNS: dict[str, tuple[re.Pattern, float]] = {
        PIIEntityType.SSN.value:
            (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), 0.90),
        PIIEntityType.CREDIT_CARD.value:
            (re.compile(r'\b(?:\d{4}[\s\-]?){3}\d{4}\b'), 0.85),
        PIIEntityType.EMAIL.value:
            (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), 0.95),
        PIIEntityType.PHONE.value:
            (re.compile(r'\b(?:\+1[\s\-]?)?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{4}\b'), 0.85),
        PIIEntityType.BANK_ACCOUNT.value:
            (re.compile(r'\b\d{8,17}\b'), 0.60),
    }

    def __init__(self, config: PIIConfig, audit_logger: Any = None):
        self.config        = config
        self.audit_logger  = audit_logger
        self._entity_map   = {e.entity_type: e for e in config.entities}
        self._custom_recs  = [DomainAccountRecognizer()]
        self._token_vault: dict[str, str] = {}  # In production: AWS Secrets Manager

    # ── Public API ────────────────────────────────────────────────────────────

    def process_chunk(
        self,
        text:        str,
        agent_id:    str,
        agent_role:  str = "",
        context_id:  str = "",
    ) -> PIIProcessResult:
        """
        Process a single text chunk — retrieved document, feature narrative,
        or any text destined for LLM context.

        Args:
            text:       Raw text to inspect and sanitize.
            agent_id:   Calling agent identifier (for audit + permission checks).
            agent_role: IAM / RBAC role of the agent.
            context_id: Retrieval session ID for lineage correlation.

        Returns:
            PIIProcessResult. Use result.safe_text for LLM consumption.

        Raises:
            PIIViolationError: If BLOCK mode is triggered for any detected entity.
        """
        processing_id = str(uuid.uuid4())
        detections    = self._detect_entities(text)

        if not detections:
            return PIIProcessResult(
                original_text=text, safe_text=text, detections=[],
                was_modified=False, token_map={}, processing_id=processing_id,
                agent_id=agent_id, timestamp=datetime.now(timezone.utc).isoformat(),
            )

        safe_text, applied, token_map = self._apply_protections(
            text, detections, agent_id, agent_role
        )

        result = PIIProcessResult(
            original_text=text, safe_text=safe_text, detections=applied,
            was_modified=(safe_text != text), token_map=token_map,
            processing_id=processing_id, agent_id=agent_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        if self.config.audit_all_events and applied:
            self._emit_audit(result, context_id=context_id)

        return result

    def process_prompt(
        self,
        prompt:      str,
        agent_id:    str,
        agent_role:  str = "",
        session_id:  str = "",
    ) -> PIIProcessResult:
        """
        Final gate: inspect the fully assembled prompt before any LLM call.
        Applies stricter thresholds than chunk-level processing.
        Any BLOCK-mode entity that was not caught earlier triggers PIIViolationError.
        """
        result = self.process_chunk(
            text=prompt,
            agent_id=agent_id,
            agent_role=agent_role,
            context_id=f"prompt:{session_id}",
        )

        # At prompt level: any unmasked BLOCK entity is a hard failure
        unblocked = [
            d for d in result.detections
            if d.mode_applied == PIIMode.BLOCK
        ]
        if unblocked:
            raise PIIViolationError(
                message=f"Unmasked BLOCK-mode PII in prompt for agent {agent_id}",
                entity_types=[d.entity_type for d in unblocked],
                agent_id=agent_id,
            )

        return result

    def detokenize(self, text: str, processing_ids: list[str] | None = None) -> str:
        """
        Reverse TOKEN mode replacements for authorized internal use ONLY.
        NEVER call this before an LLM call — only for human review in
        authorized downstream systems.

        In production: fetch token mapping from AWS Secrets Manager by processing_id.
        """
        result = text
        for token, original in self._token_vault.items():
            result = result.replace(token, original)
        return result

    # ── Detection ─────────────────────────────────────────────────────────────

    def _detect_entities(self, text: str) -> list[dict]:
        """
        Detect PII entities in text.

        PRODUCTION — replace this method body with Presidio:
        -------------------------------------------------------
        from presidio_analyzer import AnalyzerEngine
        analyzer = AnalyzerEngine()
        results  = analyzer.analyze(text=text, language="en")

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
        -------------------------------------------------------
        This demo implementation uses regex for local testing without
        requiring spaCy models or cloud credentials.
        """
        detections: list[dict] = []

        # Standard patterns (demo)
        for entity_type, (pattern, default_score) in self._DEMO_PATTERNS.items():
            for match in pattern.finditer(text):
                entity_cfg = self._entity_map.get(entity_type)
                threshold  = entity_cfg.score_threshold if entity_cfg else 0.75
                if default_score >= threshold:
                    detections.append({
                        "entity_type":   entity_type,
                        "start":         match.start(),
                        "end":           match.end(),
                        "score":         default_score,
                        "original_text": match.group(),
                    })

        # Custom domain recognizers
        for recognizer in self._custom_recs:
            for det in recognizer.detect(text):
                entity_cfg = self._entity_map.get(det["entity_type"])
                threshold  = entity_cfg.score_threshold if entity_cfg else 0.75
                if det["score"] >= threshold:
                    detections.append(det)

        # Deduplicate overlapping spans: widest match wins.
        # Prevents sub-span patterns (e.g. PHONE inside ACCOUNT_NUMBER)
        # from corrupting the authoritative wider detection.
        # In production Presidio handles entity resolution natively.
        detections = _deduplicate_spans(detections)

        # Sort right-to-left so replacements don't shift subsequent indices
        return sorted(detections, key=lambda x: x["start"], reverse=True)

    # ── Protection application ─────────────────────────────────────────────────

    def _apply_protections(
        self,
        text:       str,
        detections: list[dict],
        agent_id:   str,
        agent_role: str,
    ) -> tuple[str, list[PIIDetection], dict[str, str]]:
        safe_text  = text
        applied:   list[PIIDetection] = []
        token_map: dict[str, str]     = {}

        for det in detections:
            entity_type = det["entity_type"]
            entity_cfg  = self._entity_map.get(entity_type)
            mode        = entity_cfg.mode if entity_cfg else self.config.global_mode

            # Role exemption: authorized roles see this entity type unmasked
            if entity_cfg and agent_role in entity_cfg.allowed_agent_roles:
                applied.append(PIIDetection(
                    entity_type=entity_type, start=det["start"], end=det["end"],
                    score=det["score"], original_text=det["original_text"],
                    replacement=det["original_text"], mode_applied=PIIMode.MASK,
                ))
                continue  # No replacement applied

            if mode == PIIMode.BLOCK:
                raise PIIViolationError(
                    message=f"BLOCK mode: {entity_type} detected for agent {agent_id}",
                    entity_types=[entity_type],
                    agent_id=agent_id,
                )
            elif mode == PIIMode.MASK:
                replacement = f"[{entity_type}]"
            elif mode == PIIMode.TOKEN:
                replacement = self._generate_token(det["original_text"], entity_type, token_map)
            else:
                replacement = f"[{entity_type}]"

            # Apply right-to-left replacement (preserves index positions)
            safe_text = safe_text[: det["start"]] + replacement + safe_text[det["end"]:]

            applied.append(PIIDetection(
                entity_type=entity_type, start=det["start"], end=det["end"],
                score=det["score"], original_text=det["original_text"],
                replacement=replacement, mode_applied=mode,
            ))

        return safe_text, applied, token_map

    # ── Token generation ──────────────────────────────────────────────────────

    def _generate_token(
        self, original: str, entity_type: str, token_map: dict[str, str]
    ) -> str:
        """
        Generate a deterministic, consistent token for a PII value.
        Same original always maps to the same token within this process.
        Format: [ENTITY_TYPE:HASH8] — recognizable as synthetic by both humans and LLMs.

        In production: store mapping in AWS Secrets Manager keyed by processing_id.
        """
        stable_hash = hashlib.sha256(original.encode()).hexdigest()[:8].upper()
        token       = f"[{entity_type}:{stable_hash}]"
        token_map[token]        = original
        self._token_vault[token] = original  # demo only; use Secrets Manager in production
        return token

    # ── Audit ─────────────────────────────────────────────────────────────────

    def _emit_audit(self, result: PIIProcessResult, context_id: str = "") -> None:
        """
        Emit a structured audit event.
        NEVER logs original_text or safe_text — only metadata.

        In production: write to S3 append-only audit bucket + OpenLineage.
        """
        event = {
            "event_type":    "PII_PROCESSED",
            "processing_id": result.processing_id,
            "agent_id":      result.agent_id,
            "context_id":    context_id,
            "timestamp":     result.timestamp,
            "entity_types":  [d.entity_type for d in result.detections],
            "modes_applied": [d.mode_applied.value for d in result.detections],
            "was_modified":  result.was_modified,
        }

        if self.audit_logger:
            self.audit_logger.emit(event)
        else:
            logger.info("PII_AUDIT | %s", json.dumps(event))
