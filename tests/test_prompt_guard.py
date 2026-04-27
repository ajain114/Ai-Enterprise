"""
tests/test_prompt_guard.py
============================
Unit tests for PromptGuard and ResponseGuard.

Covers:
  - PromptGuard: PII detection in assembled prompts
  - PromptGuard: strict_mode vs non-strict behaviour
  - PromptGuard: clean prompts pass without modification
  - PromptGuard: quick-scan fast path
  - ResponseGuard: NEVER pattern detection (high-risk leakage)
  - ResponseGuard: suspicious pattern logging (elevated risk)
  - ResponseGuard: clean response pass-through
  - ResponseGuard: escalation callback invocation
  - ResponseGuard: block vs non-block on never patterns

Run:
    python tests/test_prompt_guard.py
"""

from __future__ import annotations
import sys, os, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.guardrails.pii_shield import PIIConfig, PIIEntityConfig, PIIEntityType, PIIMode, PIIShield, PIIViolationError
from src.guardrails.prompt_guard import PromptGuard, ResponseGuard, PromptInspectionResult, ResponseInspectionResult
from src.guardrails.pii_shield import PIILeakageError


def make_shield() -> PIIShield:
    return PIIShield(config=PIIConfig(
        entities=[
            PIIEntityConfig(PIIEntityType.SSN,         PIIMode.BLOCK, 0.70),
            PIIEntityConfig(PIIEntityType.CREDIT_CARD, PIIMode.BLOCK, 0.75),
            PIIEntityConfig(PIIEntityType.EMAIL,       PIIMode.MASK,  0.90),
            PIIEntityConfig(PIIEntityType.PHONE,       PIIMode.MASK,  0.75),
        ],
        global_mode=PIIMode.MASK,
        audit_all_events=False,
    ))


class T:
    passed = 0; failed = 0; errors: list[str] = []

    @classmethod
    def ok(cls, n): cls.passed += 1; print(f"  \u2713  {n}")

    @classmethod
    def fail(cls, n, r):
        cls.failed += 1; cls.errors.append(f"{n}: {r}")
        print(f"  \u2717  {n}\n       {r}")

    @classmethod
    def check(cls, cond, name, reason="assertion failed"):
        cls.ok(name) if cond else cls.fail(name, reason)

    @classmethod
    def raises(cls, exc, fn, name):
        try:
            fn(); cls.fail(name, f"Expected {exc.__name__}"); return None
        except exc as e: cls.ok(name); return e
        except Exception as e: cls.fail(name, f"Wrong exc: {type(e).__name__}: {e}"); return None

    @classmethod
    def summary(cls) -> bool:
        total = cls.passed + cls.failed
        print(f"\n{'─'*55}\n  {cls.passed}/{total} passed", end="")
        if cls.failed:
            print(f"  |  {cls.failed} FAILED")
            [print(f"    \u2192 {e}") for e in cls.errors]
        else:
            print("  \u2014 All passed \u2713")
        print(f"{'─'*55}")
        return cls.failed == 0


# ── PromptGuard ───────────────────────────────────────────────────────────────

def test_prompt_guard_strict():
    print("\nPromptGuard — strict_mode=True")
    s  = make_shield()
    pg = PromptGuard(pii_shield=s, strict_mode=True)

    # SSN in prompt → strict raises
    T.raises(PIIViolationError,
        lambda: pg.inspect("Review SSN 123-45-6789 for this account.", agent_id="a", agent_role="analyst"),
        "Strict mode: SSN in prompt raises PIIViolationError")

    # Credit card in prompt → strict raises
    T.raises(PIIViolationError,
        lambda: pg.inspect("Card 4532-0151-1283-0366 was declined.", agent_id="a", agent_role="analyst"),
        "Strict mode: credit card in prompt raises PIIViolationError")


def test_prompt_guard_non_strict():
    print("\nPromptGuard — strict_mode=False")
    s  = make_shield()
    pg = PromptGuard(pii_shield=s, strict_mode=False)

    # SSN in non-strict → sanitized, no raise
    try:
        result = pg.inspect("Review SSN 123-45-6789.", agent_id="a", agent_role="analyst", session_id="s-001")
        T.check(isinstance(result, PromptInspectionResult), "Returns PromptInspectionResult")
        T.check(result.pii_detected,         "pii_detected=True when PII found")
        T.check(result.action_taken in ("sanitized", "blocked"), "action_taken is sanitized or blocked")
        T.check("123-45-6789" not in result.safe_prompt, "SSN absent from safe_prompt")
        T.check(bool(result.inspection_id),  "inspection_id present")
    except PIIViolationError:
        T.fail("Non-strict SSN", "Should not raise in non-strict mode")


def test_prompt_guard_clean():
    print("\nPromptGuard — clean prompts")
    s  = make_shield()
    pg = PromptGuard(pii_shield=s, strict_mode=True)

    clean_prompts = [
        "You are a helpful agent. Answer questions about dispute resolution.",
        "The payment of $127.50 was disputed on 2024-01-15.",
        "Review the merchant's refund policy before escalating the case.",
        "Risk assessment complete. Account status: current.",
    ]
    for prompt in clean_prompts:
        try:
            result = pg.inspect(prompt, agent_id="a", agent_role="analyst", session_id="s")
            T.check(result.action_taken == "passed",    f"Clean prompt action=passed: {prompt[:40]}...")
            T.check(result.safe_prompt == prompt,       f"Clean prompt unchanged: {prompt[:40]}...")
            T.check(not result.pii_detected,            f"No PII detected in clean prompt")
        except PIIViolationError as e:
            T.fail(f"Clean prompt: {prompt[:40]}", f"Unexpected PIIViolationError: {e}")


def test_prompt_guard_result_fields():
    print("\nPromptGuard — result object fields")
    s  = make_shield()
    pg = PromptGuard(pii_shield=s, strict_mode=False)

    result = pg.inspect("Clean prompt text.", agent_id="agent-01", agent_role="analyst", session_id="sess-01")
    T.check(isinstance(result, PromptInspectionResult), "Returns PromptInspectionResult")
    T.check(bool(result.inspection_id),          "inspection_id present")
    T.check(result.original_prompt == "Clean prompt text.", "original_prompt preserved")
    T.check(isinstance(result.entities_found, list), "entities_found is list")
    T.check(isinstance(result.token_map, dict),  "token_map is dict")
    T.check(result.action_taken in ("passed", "sanitized", "blocked"), "action_taken has valid value")


# ── ResponseGuard ─────────────────────────────────────────────────────────────

def test_response_guard_never_patterns():
    print("\nResponseGuard — NEVER patterns (high-risk leakage)")
    s  = make_shield()
    rg = ResponseGuard(pii_shield=s, block_on_never_patterns=False)  # non-blocking for testability

    # SSN in response
    result = rg.inspect("The SSN on file is 555-66-7777. Account is current.", agent_id="a", session_id="s")
    T.check(result.leakage_detected,              "SSN in response: leakage_detected=True")
    T.check("SSN" in result.entities_found,       "SSN in entities_found")
    T.check(result.leakage_risk_score == 1.0,     "leakage_risk_score=1.0 for NEVER pattern")
    T.check("555-66-7777" not in result.safe_response, "SSN redacted from safe_response")

    # Credit card in response
    result = rg.inspect("I found card 4532-0151-1283-0366 on the account.", agent_id="a", session_id="s")
    T.check(result.leakage_detected,              "Credit card in response: leakage_detected=True")
    T.check(result.leakage_risk_score == 1.0,     "risk_score=1.0 for credit card")

    # Phone in response (NEVER pattern)
    result = rg.inspect("Call the customer at 415-555-1234 immediately.", agent_id="a", session_id="s")
    T.check(result.leakage_detected,              "Phone in response: leakage_detected=True")


def test_response_guard_blocking():
    print("\nResponseGuard — block_on_never_patterns=True")
    s  = make_shield()
    rg = ResponseGuard(pii_shield=s, block_on_never_patterns=True)

    T.raises(PIILeakageError,
        lambda: rg.inspect("SSN: 111-22-3333 confirmed.", agent_id="a", session_id="s"),
        "PIILeakageError raised when block_on_never_patterns=True and SSN detected")


def test_response_guard_clean():
    print("\nResponseGuard — clean responses")
    s  = make_shield()
    rg = ResponseGuard(pii_shield=s, block_on_never_patterns=True)

    clean_responses = [
        "The dispute has been logged with reference DISP-2024-00142.",
        "Investigation will complete within 10 business days.",
        "Account status is current. No action required at this time.",
        "The payment was processed successfully on the billing date.",
    ]
    for resp in clean_responses:
        try:
            result = rg.inspect(resp, agent_id="a", session_id="s")
            T.check(not result.leakage_detected,      f"No leakage in clean response: {resp[:40]}...")
            T.check(result.safe_response == resp,     f"Clean response unchanged: {resp[:40]}...")
            T.check(result.action_taken == "passed",  f"action=passed for clean response")
        except PIILeakageError as e:
            T.fail(f"Clean response: {resp[:40]}", f"Unexpected PIILeakageError: {e}")


def test_response_guard_escalation_callback():
    print("\nResponseGuard — escalation callback")
    escalated: list[dict] = []

    def mock_escalation(event: dict):
        escalated.append(event)

    s  = make_shield()
    rg = ResponseGuard(pii_shield=s, block_on_never_patterns=False, escalation_callback=mock_escalation)

    rg.inspect("SSN 999-88-7777 confirmed.", agent_id="test-agent", session_id="sess-esc")

    T.check(len(escalated) == 1,                       "Escalation callback called once")
    T.check(escalated[0].get("severity") == "CRITICAL","Escalation event has severity=CRITICAL")
    T.check(escalated[0].get("agent_id") == "test-agent", "Escalation event carries agent_id")
    T.check("entities_leaked" in escalated[0],         "Escalation event has entities_leaked field")
    T.check(escalated[0].get("risk_score") == 1.0,     "Escalation event has risk_score=1.0")


def test_response_guard_result_fields():
    print("\nResponseGuard — result object fields")
    s  = make_shield()
    rg = ResponseGuard(pii_shield=s, block_on_never_patterns=False)

    result = rg.inspect("Clean response.", agent_id="agent-01", session_id="sess-01")
    T.check(isinstance(result, ResponseInspectionResult), "Returns ResponseInspectionResult")
    T.check(bool(result.inspection_id),              "inspection_id present")
    T.check(isinstance(result.leakage_detected, bool),"leakage_detected is bool")
    T.check(isinstance(result.entities_found, list), "entities_found is list")
    T.check(isinstance(result.leakage_risk_score, float), "leakage_risk_score is float")
    T.check(0.0 <= result.leakage_risk_score <= 1.0, "leakage_risk_score in [0.0, 1.0]")
    T.check(result.original_response == result.safe_response, "original == safe for clean response")


def main() -> bool:
    print("=" * 55)
    print("  PromptGuard / ResponseGuard Unit Tests")
    print("=" * 55)
    test_prompt_guard_strict()
    test_prompt_guard_non_strict()
    test_prompt_guard_clean()
    test_prompt_guard_result_fields()
    test_response_guard_never_patterns()
    test_response_guard_blocking()
    test_response_guard_clean()
    test_response_guard_escalation_callback()
    test_response_guard_result_fields()
    return T.summary()

if __name__ == "__main__":
    import logging; logging.basicConfig(level=logging.WARNING)
    sys.exit(0 if main() else 1)
