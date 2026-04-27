# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Yes    |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability — particularly one involving:

- PII guardrail bypass (a way to get PII into an LLM context)
- Authentication or authorisation bypass in MCP tool access
- Audit log tampering or suppression
- Token vault exposure
- Injection attacks on prompt assembly

Please disclose it privately:

1. **Email:** security@your-org.com
2. **Subject:** `[SECURITY] enterprise-mcp-ai-platform — <brief description>`
3. **Include:** Steps to reproduce, impact assessment, suggested fix if known

We will acknowledge your report within **48 hours** and provide a timeline
for remediation within **5 business days**.

## Security Design Principles

This codebase is built on defence-in-depth. The guardrail system implements
**seven independent layers** — a vulnerability in one layer should not
compromise the entire pipeline.

| Layer | Mechanism | What it prevents |
|-------|-----------|-----------------|
| 1 | Query PIIShield | PII in agent queries reaching the embedding model |
| 2 | Chunk PIIShield | PII in retrieved documents reaching LLM context |
| 3 | Context PIIShield | PII surviving to the assembled multi-chunk context |
| 4 | PromptGuard | PII in the final assembled prompt before LLM call |
| 5 | LLM boundary | In-VPC Bedrock inference (no PII leaves the VPC) |
| 6 | ResponseGuard | Hallucinated/reconstructed PII in LLM responses |
| 7 | Audit log | Immutable record of all PII events for forensics |

## Known Limitations (Demo Mode)

The demo/development version uses **regex patterns** instead of Microsoft Presidio
for PII detection. These patterns have known limitations:

- They may miss unusual formatting (SSN with spaces: `123 45 6789`)
- They may produce false positives on some numeric patterns
- They do not perform contextual analysis (Presidio does)

**Production deployments must replace the demo regex engine with Presidio.**
See `docs/production_checklist.md` for the replacement instructions.

## Dependency Security

We use `bandit` for static security analysis of Python code.
Run `bandit -r src/` before any pull request.

Dependencies are pinned in `requirements.txt`. Run `pip audit` regularly
to check for known vulnerabilities in pinned versions.
