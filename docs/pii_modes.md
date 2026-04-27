# PII Mode Decision Guide

This guide helps you decide which PII protection mode to apply to each
entity type in `config/pii_config.yaml`.

---

## The Three Modes

### BLOCK — Abort the pipeline

```yaml
mode: "block"
```

The pipeline raises `PIIViolationError` and **stops immediately**.
No data reaches the LLM. The event is logged at HIGH severity.

**When to use:**
- Absolute highest-risk PII where any LLM exposure is a compliance violation
- Entities that provide zero reasoning value to the agent
- Any entity type where your legal/compliance team says "never"

**Examples:**
| Entity | Why BLOCK |
|--------|-----------|
| SSN (`US_SSN`) | No business justification for an LLM to see a Social Security Number |
| Credit card number (`CREDIT_CARD`) | PCI-DSS scope; a single exposure is a reportable incident |
| Passport number (`US_PASSPORT`) | Identity theft risk; agents never need the raw number |
| Driver's license (`US_DRIVER_LICENSE`) | Same rationale as passport |

**Effect on agent behaviour:**
The agent receives an error response and must handle it. Design your agent
prompt to expect `{"error": "Content policy violation"}` and respond gracefully.

---

### MASK — Replace with placeholder

```yaml
mode: "mask"
```

The PII is replaced with `[ENTITY_TYPE]` before the text reaches the LLM.
The LLM knows that a value was present (it sees the placeholder) but cannot
reconstruct or use the original value.

**When to use:**
- PII that provides contextual value to the agent ("there is an email address here")
  but where the raw value adds no reasoning value
- Entities where some agent roles need the value (use `allowed_agent_roles`)

**Examples:**
| Entity | Why MASK |
|--------|----------|
| Name (`PERSON`) | Agent can reason "customer" without knowing the individual's name |
| Address (`LOCATION`) | Geographic context can be preserved at region level, not street level |
| Email (`EMAIL_ADDRESS`) | Agent knows contact method is email; doesn't need `john.doe@example.com` |
| Phone (`PHONE_NUMBER`) | Agent knows contact method is phone; doesn't need the digits |
| Date of birth | Agent can reason about age band without the raw birthdate |

**Role exemptions** — add `allowed_agent_roles` to let specific roles see the original:
```yaml
- entity_type: "EMAIL_ADDRESS"
  mode: "mask"
  allowed_agent_roles:
    - "collections-agent"    # needs email for outreach
    - "servicing-agent"      # needs email for correspondence
```

**Effect on agent behaviour:**
The LLM sees `Contact [PERSON] at [EMAIL_ADDRESS] regarding account [ACCOUNT_NUMBER:A3F2].`
This is enough context for most reasoning tasks.

---

### TOKEN — Deterministic reversible hash

```yaml
mode: "token"
```

The PII is replaced with `[ENTITY_TYPE:HASH8]` — a deterministic token
where `HASH8` is the first 8 characters of the SHA-256 hash of the original value.

**Properties:**
- **Consistent:** The same original value always produces the same token within a session
- **Cross-referenceable:** If two chunks contain the same account number, both get the same token — the agent can tell they refer to the same entity
- **Reversible:** Authorized systems can look up the original in the token vault (AWS Secrets Manager)
- **Not reversible by the LLM:** The LLM sees the token but cannot reverse it

**When to use:**
- Identifiers that an agent needs to cross-reference across multiple retrieved chunks
- Values that downstream systems need to look up (case numbers, internal IDs)
- PII where you want auditability of which agent "touched" which value

**Examples:**
| Entity | Why TOKEN |
|--------|-----------|
| Account number | Agent may see the same account in 3 different chunks; TOKEN lets it correlate them |
| Case reference ID | Agent needs to reference the case ID in its response without exposing raw format |
| Internal transaction ID | Cross-chunk correlation needed; reversible for downstream lookup |

**Token format:**
```
[ACCOUNT_NUMBER:A3F2C1B8]
 ─────────────  ────────
 Entity type    SHA-256 hash (first 8 chars, uppercase)
```

**Role exemptions** work the same as MASK — add `allowed_agent_roles` to let
authorized roles see the original value (e.g. fraud analysts need plaintext account numbers).

---

## Decision Flowchart

```
Is this PII something the LLM should EVER see in plain text?
│
├── No, under any circumstances ──────────────────► BLOCK
│   (SSN, credit card, passport, driver's license)
│
└── Yes, potentially
    │
    ├── Does the LLM need the EXACT value for reasoning?
    │   │
    │   ├── No (just needs to know "there's a value here") ──► MASK
    │   │   (names, addresses, generic contact info)
    │   │
    │   └── Yes, but only for cross-reference (not display)
    │       │
    │       ├── Is it an internal identifier that needs
    │       │   to stay consistent across chunks? ──────────► TOKEN
    │       │   (account numbers, case IDs)
    │       │
    │       └── Is it contact info some roles legitimately need?
    │           ├── Add allowed_agent_roles ────────────────► MASK + role exemption
    │           └── All roles need it ──────────────────────► TOKEN or MASK (review with legal)
```

---

## Score Thresholds

The `score_threshold` controls how confident the detection must be before
the protection is applied. It maps to Presidio's confidence score (0.0–1.0).

| Threshold | Sensitivity | False positive rate | Recommended for |
|-----------|-------------|---------------------|-----------------|
| 0.60–0.70 | Very high   | Higher | Hardcoded patterns (SSN, credit card) |
| 0.70–0.80 | High        | Moderate | BLOCK-mode entities (better safe than sorry) |
| 0.80–0.90 | Medium      | Low | Standard MASK entities |
| 0.90–0.95 | Low         | Very low | MASK with role exemptions (fewer false blocks) |
| 0.95–1.00 | Very low    | Near zero | Only when false positives are very costly |

**General rule:**
- BLOCK-mode entities: use **lower** thresholds (0.70) — cost of a miss is too high
- MASK-mode entities: use **higher** thresholds (0.85–0.90) — avoid masking legitimate text
- TOKEN-mode entities: use **medium** thresholds (0.80–0.85)

---

## Configuration Examples

### Minimal secure configuration

```yaml
global_mode: "mask"
block_on_unknown_agent: true
audit_all_events: true

entities:
  - entity_type: "US_SSN"
    mode: "block"
    score_threshold: 0.70

  - entity_type: "CREDIT_CARD"
    mode: "block"
    score_threshold: 0.75

  - entity_type: "EMAIL_ADDRESS"
    mode: "mask"
    score_threshold: 0.90
```

### Financial services configuration (full)

See `config/pii_config.yaml` for the full recommended configuration
for financial services deployments.

---

## Common Mistakes

**❌ Setting everything to MASK instead of BLOCK**
MASK still sends the placeholder to the LLM. For SSNs and credit cards,
the right answer is BLOCK — abort the pipeline entirely.

**❌ Setting thresholds too high for BLOCK-mode entities**
If SSN threshold is 0.95, a slightly unusual SSN format (e.g. with spaces)
might score 0.88 and slip through. Keep BLOCK thresholds at 0.70.

**❌ Using TOKEN mode for entities that need BLOCK**
TOKEN still sends a token to the LLM. For SSNs, you don't want any representation
in the LLM context — use BLOCK.

**❌ Forgetting that MASK still tells the LLM something**
`[PERSON] disputed the charge` tells the LLM there is a person's name here.
This is usually fine. But if the presence of the entity itself is sensitive
(e.g. `[US_NPI]` revealing that a medical provider is involved in a case),
consider whether BLOCK is more appropriate.

**❌ Not testing thresholds on representative data**
Thresholds set without testing will either miss real PII or mask legitimate
text (like dollar amounts being detected as phone numbers). Always validate
on a sample of your actual documents before going live.
