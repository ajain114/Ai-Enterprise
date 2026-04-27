"""
src/guardrails/prompt_guard.py
================================
Two-sided LLM guardrail:

  PromptGuard   — Pre-LLM inspection on the fully assembled prompt.
                  Last line of defence before any LLM call.

  ResponseGuard — Post-LLM inspection on the model response.
                  Catches hallucinated or reconstructed PII in LLM output.
                  Escalates CRITICAL alerts on detection.

Both classes use PIIShield internally for detection and emit to the audit trail.

Usage:
    prompt_guard   = PromptGuard(pii_shield=shield, strict_mode=True)
    response_guard = ResponseGuard(pii_shield=shield, block_on_never_patterns=True)

    # Before LLM call
    safe = prompt_guard.inspect(prompt, agent_id=agent_id, session_id=session_id)
    llm_response = call_llm(safe.safe_prompt)

    # After LLM call
    checked = response_guard.inspect(llm_response, agent_id=agent_id, session_id=session_id)
    return checked.safe_response
"""

from __future__ import annotations

import json
import logging
import re
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from src.guardrails.pii_shield import PIILeakageError, PIIShield, PIIViolationError

logger = logging.getLogger(__name__)


# ── Result types ──────────────────────────────────────────────────────────────

@dataclass
class PromptInspectionResult:
    original_prompt: str
    safe_prompt:     str
    pii_detected:    bool
    entities_found:  list[str]
    action_taken:    str       # "passed" | "sanitized" | "blocked"
    inspection_id:   str
    token_map:       dict[str, str]


@dataclass
class ResponseInspectionResult:
    original_response:  str
    safe_response:      str
    leakage_detected:   bool
    entities_found:     list[str]
    action_taken:       str    # "passed" | "sanitized" | "blocked"
    inspection_id:      str
    leakage_risk_score: float  # 0.0–1.0


# ═══════════════════════════════════════════════════════════════
# PROMPT GUARD
# ═══════════════════════════════════════════════════════════════

class PromptGuard:
    """
    Pre-LLM prompt inspection.

    Runs on the fully assembled prompt after all retrieval and context assembly
    is complete, immediately before the LLM API call. Catches PII that:
      - Was in the user query (not caught by chunk-level processing)
      - Was in the system prompt template (configuration error)
      - Slipped through chunk-level processing due to threshold misses

    Architecture position:
        RAG chunks (PII-scrubbed)
            → Prompt assembly (LangChain / LlamaIndex)
                → PromptGuard.inspect()     ← THIS CLASS
                    → LLM call (Bedrock)

    strict_mode=True  (production default):
        Any BLOCK-mode PII detected → raise PIIViolationError, abort call.

    strict_mode=False (testing / graceful degradation):
        Sanitize via regex and continue. Log the event.
    """

    # Fast regex patterns for quick pre-scan before full Presidio analysis
    _QUICK_SCAN_PATTERNS = [
        re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),                                # SSN
        re.compile(r'\b(?:\d{4}[\s\-]?){3}\d{4}\b'),                         # Credit card
        re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),# Email
        re.compile(r'\b[A-Z]{2,4}-\d{8,12}\b'),                              # Domain account
        re.compile(r'\b\d{3}-\d{3}-\d{4}\b'),                                # Phone
    ]

    def __init__(self, pii_shield: PIIShield, strict_mode: bool = True):
        self.shield      = pii_shield
        self.strict_mode = strict_mode

    def inspect(
        self,
        prompt:      str,
        agent_id:    str,
        agent_role:  str = "",
        session_id:  str = "",
    ) -> PromptInspectionResult:
        """
        Inspect the fully assembled prompt before sending to LLM.

        Returns:
            PromptInspectionResult — use .safe_prompt for the LLM call.

        Raises:
            PIIViolationError: In strict_mode if any BLOCK-mode PII is detected.
        """
        inspection_id = str(uuid.uuid4())

        # Fast path: quick regex scan to decide if full analysis is needed
        if not self._quick_scan(prompt):
            return PromptInspectionResult(
                original_prompt=prompt, safe_prompt=prompt, pii_detected=False,
                entities_found=[], action_taken="passed",
                inspection_id=inspection_id, token_map={},
            )

        # Full PII shield processing
        try:
            result = self.shield.process_prompt(
                prompt=prompt, agent_id=agent_id,
                agent_role=agent_role, session_id=session_id,
            )

        except PIIViolationError as e:
            self._log_block(inspection_id, agent_id, session_id, e.entity_types)

            if self.strict_mode:
                raise

            # Non-strict: fallback regex sanitization, then continue
            safe_prompt = self._regex_redact(prompt)
            self._log_inspection(inspection_id, agent_id, session_id, e.entity_types, "sanitized")
            return PromptInspectionResult(
                original_prompt=prompt, safe_prompt=safe_prompt, pii_detected=True,
                entities_found=e.entity_types, action_taken="sanitized",
                inspection_id=inspection_id, token_map={},
            )

        action = "sanitized" if result.was_modified else "passed"
        self._log_inspection(
            inspection_id, agent_id, session_id,
            [d.entity_type for d in result.detections], action,
        )

        return PromptInspectionResult(
            original_prompt=prompt, safe_prompt=result.safe_text,
            pii_detected=result.was_modified,
            entities_found=[d.entity_type for d in result.detections],
            action_taken=action, inspection_id=inspection_id,
            token_map=result.token_map,
        )

    def _quick_scan(self, text: str) -> bool:
        """Return True if any quick-scan pattern matches (triggers full analysis)."""
        return any(p.search(text) for p in self._QUICK_SCAN_PATTERNS)

    def _regex_redact(self, text: str) -> str:
        """Fallback regex-based redaction for non-strict mode."""
        for pattern in self._QUICK_SCAN_PATTERNS:
            text = pattern.sub("[REDACTED]", text)
        return text

    def _log_block(
        self, inspection_id: str, agent_id: str, session_id: str, entities: list[str],
    ) -> None:
        logger.warning("PROMPT_GUARD_BLOCK | %s", json.dumps({
            "event_type":    "PROMPT_BLOCKED",
            "inspection_id": inspection_id,
            "agent_id":      agent_id,
            "session_id":    session_id,
            "entities":      entities,
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "severity":      "HIGH",
        }))

    def _log_inspection(
        self, inspection_id: str, agent_id: str,
        session_id: str, entities: list[str], action: str,
    ) -> None:
        level = logging.WARNING if entities else logging.INFO
        logger.log(level, "PROMPT_GUARD | %s", json.dumps({
            "event_type":    "PROMPT_INSPECTED",
            "inspection_id": inspection_id,
            "agent_id":      agent_id,
            "session_id":    session_id,
            "entities":      entities,
            "action":        action,
            "timestamp":     datetime.now(timezone.utc).isoformat(),
        }))


# ═══════════════════════════════════════════════════════════════
# RESPONSE GUARD
# ═══════════════════════════════════════════════════════════════

class ResponseGuard:
    """
    Post-LLM response inspection.

    Inspects every LLM response before returning it to the agent.
    Catches PII that the model may have:
      (a) Hallucinated   — fabricated plausible-looking PII from training data
      (b) Reconstructed  — inferred PII from partial context clues
      (c) Leaked         — somehow extracted from masked/tokenized values

    This is NOT expected to fire frequently when PromptGuard is working.
    When it fires, it is a signal of a deeper issue that needs investigation.

    Architecture position:
        LLM call (Bedrock)
            → ResponseGuard.inspect()    ← THIS CLASS
                → Agent response returned

    escalation_callback: Optional async function called on high-severity events.
    Signature: async def callback(event: dict) -> None
    """

    # Patterns that should NEVER appear in LLM output in a production system
    _NEVER_PATTERNS: list[tuple[re.Pattern, str]] = [
        (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),              "SSN"),
        (re.compile(r'\b(?:\d{4}[\s\-]?){3}\d{4}\b'),       "CREDIT_CARD"),
        (re.compile(r'\b[A-Z]{2,4}-\d{8,12}\b'),            "DOMAIN_ACCOUNT"),
        (re.compile(r'\b\d{3}-\d{3}-\d{4}\b'),              "PHONE"),
    ]

    # Patterns that are suspicious and should be logged (elevated risk, not auto-block)
    _SUSPICIOUS_PATTERNS: list[tuple[re.Pattern, str]] = [
        (re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'), "EMAIL"),
        (re.compile(r'\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b'), "DATE"),
    ]

    def __init__(
        self,
        pii_shield:                 PIIShield,
        block_on_never_patterns:    bool               = True,
        escalation_callback:        Callable | None    = None,
    ):
        self.shield                  = pii_shield
        self.block_on_never_patterns = block_on_never_patterns
        self.escalation_callback     = escalation_callback

    def inspect(
        self,
        response:              str,
        agent_id:              str,
        session_id:            str = "",
        prompt_inspection_id:  str = "",
    ) -> ResponseInspectionResult:
        """
        Inspect LLM response before returning to agent.

        Returns:
            ResponseInspectionResult. Check .leakage_detected and use .safe_response.

        Raises:
            PIILeakageError: If a NEVER pattern is found and block_on_never_patterns=True.
        """
        inspection_id = str(uuid.uuid4())
        entities:     list[str] = []
        risk_score:   float     = 0.0
        safe_response:str       = response

        # Check NEVER patterns
        never_hits = [
            label for pattern, label in self._NEVER_PATTERNS
            if pattern.search(response)
        ]

        if never_hits:
            entities.extend(never_hits)
            risk_score = 1.0
            self._escalate(inspection_id, agent_id, session_id, prompt_inspection_id, never_hits)

            if self.block_on_never_patterns:
                raise PIILeakageError(
                    f"CRITICAL: PII leakage in LLM response | "
                    f"agent={agent_id} | entities={never_hits} | id={inspection_id}"
                )

            # Non-blocking: regex redact
            for pattern, _ in self._NEVER_PATTERNS:
                safe_response = pattern.sub("[REDACTED]", safe_response)
            action = "sanitized"

        else:
            # Check suspicious patterns — log, don't block
            for pattern, label in self._SUSPICIOUS_PATTERNS:
                if pattern.search(response):
                    entities.append(label)
                    risk_score = max(risk_score, 0.6)

            action = "logged" if entities else "passed"

        self._log(inspection_id, agent_id, session_id, entities, action, risk_score)

        return ResponseInspectionResult(
            original_response=response, safe_response=safe_response,
            leakage_detected=bool(never_hits), entities_found=entities,
            action_taken=action, inspection_id=inspection_id,
            leakage_risk_score=risk_score,
        )

    def _escalate(
        self, inspection_id: str, agent_id: str, session_id: str,
        prompt_inspection_id: str, entities: list[str],
    ) -> None:
        """
        Escalate high-severity leakage events.
        In production: post to SNS → SIEM (Splunk / CloudWatch CRITICAL alert).
        """
        event = {
            "event_type":           "PII_LEAKAGE_DETECTED",
            "severity":             "CRITICAL",
            "inspection_id":        inspection_id,
            "prompt_inspection_id": prompt_inspection_id,
            "agent_id":             agent_id,
            "session_id":           session_id,
            "entities_leaked":      entities,
            "risk_score":           1.0,
            "timestamp":            datetime.now(timezone.utc).isoformat(),
            "action_required":      "IMMEDIATE_REVIEW",
        }
        logger.critical("RESPONSE_GUARD_ESCALATION | %s", json.dumps(event))

        if self.escalation_callback:
            try:
                self.escalation_callback(event)
            except Exception as cb_err:
                logger.error("Escalation callback failed: %s", cb_err)

    def _log(
        self, inspection_id: str, agent_id: str,
        session_id: str, entities: list[str], action: str, risk_score: float,
    ) -> None:
        level = logging.WARNING if entities else logging.INFO
        logger.log(level, "RESPONSE_GUARD | %s", json.dumps({
            "event_type":    "RESPONSE_INSPECTED",
            "inspection_id": inspection_id,
            "agent_id":      agent_id,
            "session_id":    session_id,
            "entities":      entities,
            "action":        action,
            "risk_score":    risk_score,
            "timestamp":     datetime.now(timezone.utc).isoformat(),
        }))
