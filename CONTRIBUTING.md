# Contributing to Enterprise MCP AI Platform

Thank you for contributing. This guide covers everything you need to
get a pull request merged cleanly and quickly.

---

## Table of Contents

- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Code Standards](#code-standards)
- [Testing Requirements](#testing-requirements)
- [Non-Negotiable Rules](#non-negotiable-rules)
- [Adding New MCP Tools](#adding-new-mcp-tools)
- [Adding New PII Entity Types](#adding-new-pii-entity-types)
- [Pull Request Checklist](#pull-request-checklist)

---

## Development Setup

```bash
git clone https://github.com/your-org/enterprise-mcp-ai-platform.git
cd enterprise-mcp-ai-platform

python -m venv .venv
source .venv/bin/activate

pip install -r requirements-dev.txt
python -m spacy download en_core_web_lg

pre-commit install          # installs ruff + mypy hooks

make up                     # start local Docker stack
make db-setup               # initialise pgvector schema
make test                   # verify everything passes before you start
```

---

## Project Structure

```
src/
  guardrails/    PII detection, prompt/response inspection, audit logging
  servers/       MCP server implementations (RAG, Feature Store, Governance)
  utils/         Shared utilities (config, embeddings, lineage)
config/          YAML configuration (PII rules, access policy)
tests/           All test suites — each runnable as plain Python script
scripts/         CLI tools (run_tests, seed_demo_data, setup_pgvector)
docs/            Architecture and operational documentation
.github/         CI workflows
```

**The guardrail layer is the most critical part of this codebase.**
Every change to `src/guardrails/` requires extra review and test coverage.

---

## Code Standards

### Style

This project uses **ruff** for linting and formatting. Config is in `pyproject.toml`.

```bash
make lint     # check
make format   # auto-fix
```

Key rules:
- Line length: 100 characters
- Import ordering: stdlib → third-party → local
- No unused imports, no `print()` in library code (use `logging`)
- All public functions must have docstrings

### Type Annotations

New code must be fully type-annotated. Check with:

```bash
mypy src/ --ignore-missing-imports
```

### Logging

Use `structlog` or the standard `logging` module. Never use `print()`.

```python
import logging
logger = logging.getLogger(__name__)

logger.info("Tool called | tool=%s agent=%s", tool_name, agent_id)
logger.warning("PII detected | entity=%s mode=%s", entity_type, mode)
logger.critical("PII leakage | agent=%s session=%s", agent_id, session_id)
```

**Logging rules — strictly enforced:**
- **Never log PII content.** Log metadata only (entity_type, agent_id, hash).
- **Never log prompt text or response text.** Log hashes only.
- Use structured key=value format in log messages.

---

## Testing Requirements

Every pull request must:

1. **Pass all existing tests** — `python scripts/run_tests.py`
2. **Add tests for new functionality** — no test, no merge
3. **All tests must be runnable without pytest** — use the standalone runner pattern

### Standalone test pattern

All test files must be self-contained and runnable with `python tests/test_*.py`:

```python
# At the top of every test file
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# At the bottom
def main() -> bool:
    # ... run tests, return True if all passed
    return T.summary()

if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.WARNING)
    sys.exit(0 if main() else 1)
```

This pattern ensures tests run in CI without pytest, in Docker without pip extras,
and as standalone scripts during local development.

### Test naming conventions

| File | Content |
|------|---------|
| `tests/test_pii_shield.py` | PIIShield unit tests |
| `tests/test_prompt_guard.py` | PromptGuard / ResponseGuard unit tests |
| `tests/test_rag_server.py` | RAG server tool integration tests |
| `tests/test_feature_store.py` | Feature store tool integration tests |
| `tests/test_guardrail_pipeline.py` | Full end-to-end pipeline |

---

## Non-Negotiable Rules

These rules are enforced in CI and are not subject to exceptions:

### 1. Guardrails are always on

**Every MCP tool handler must call PIIShield on all text that will reach an LLM.**
There is no "performance mode" or "trusted mode" that bypasses the guardrail.

```python
# CORRECT
result = self.shield.process_chunk(text, agent_id, agent_role)
safe_text = result.safe_text

# WRONG — never do this
safe_text = text  # bypassing guardrail for "performance"
```

### 2. Fail closed, not open

If a guardrail raises an exception, the pipeline aborts. It does not silently
pass data through to the LLM.

```python
# CORRECT
try:
    result = self.shield.process_chunk(text, agent_id, agent_role)
except PIIViolationError:
    return {"error": "Content policy violation — request aborted."}

# WRONG — swallowing exceptions
try:
    result = self.shield.process_chunk(text, agent_id, agent_role)
except PIIViolationError:
    pass  # never do this
    result = some_fallback_with_raw_text
```

### 3. PII never in logs

No log message may contain raw PII. If you need to reference a value, hash it.

```python
import hashlib

# CORRECT
query_hash = hashlib.sha256(query.encode()).hexdigest()[:16]
logger.info("Query processed | hash=%s", query_hash)

# WRONG
logger.info("Query: %s", query)   # may contain PII
```

### 4. Config over code

PII rules belong in `config/pii_config.yaml`. Role permissions belong in
`config/access_policy.yaml`. New entity types or role changes must go through
config, not hardcoded in handler logic.

```yaml
# CORRECT — add to config/pii_config.yaml
- entity_type: "NEW_ENTITY_TYPE"
  mode: "mask"
  score_threshold: 0.80
```

```python
# WRONG — hardcoding in handler
if "social_security" in text.lower():
    text = "[REDACTED]"
```

### 5. Audit every tool call

Every MCP tool handler must call `self.audit.log_tool_call()` before returning.
The audit log is append-only and forms the compliance record for every agent action.

---

## Adding New MCP Tools

1. **Define the tool schema** in `MCP_TOOLS` list of the server class:
   ```python
   {
       "name": "your_tool_name",
       "description": "What this tool does and when to use it.",
       "inputSchema": {
           "type": "object",
           "properties": { ... },
           "required": [...],
       },
   }
   ```

2. **Implement the handler** as `async def handle_your_tool_name(self, ...) -> dict`

3. **Register it** in `get_mcp_tool_map()`

4. **Apply the full guardrail pipeline:**
   - Shield the input (any text from the user or agent)
   - Shield retrieved chunks
   - Shield assembled context
   - Audit the call

5. **Write tests** covering:
   - Happy path (authorized role, clean input)
   - Unauthorized role
   - PII in input (should be sanitized or rejected)
   - Invalid parameters (missing required fields, wrong types)

---

## Adding New PII Entity Types

1. Add the entity type to `PIIEntityType` enum in `src/guardrails/pii_shield.py`
2. Add a regex pattern to `_DEMO_PATTERNS` (for local dev testing)
3. Register a Presidio recognizer for production detection
4. Add the entity config to `config/pii_config.yaml`
5. Add tests in `tests/test_pii_shield.py` covering:
   - Detection at threshold
   - Correct mode application (BLOCK / MASK / TOKEN)
   - Role exemption if applicable
   - Clean text is not falsely detected

---

## Pull Request Checklist

Before opening a PR, confirm all of these:

```
[ ] python scripts/run_tests.py exits 0 (all 5 suites passing)
[ ] New functionality has tests covering: happy path, error cases, edge cases
[ ] All test files runnable with: python tests/test_*.py
[ ] No PII in log statements (reviewed every logger.* call added)
[ ] No guardrail bypasses (reviewed every place text flows toward LLM)
[ ] Config changes go in YAML, not hardcoded
[ ] Docstrings on all new public functions
[ ] PRODUCTION: comment on every demo stub that needs a real implementation
[ ] ruff check src/ tests/ exits clean
[ ] PR description explains: what changed, why, and how it was tested
```

---

## Questions?

Open a GitHub Discussion or raise an issue tagged `question`.
For security-related concerns (PII handling, access control), use the
private security disclosure process described in `SECURITY.md`.
