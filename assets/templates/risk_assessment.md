# Agentic AI Risk Assessment Questionnaire

> **Note:** Complete this questionnaire before deploying any autonomous agent, and re-run it after any material change to the agent's tools, autonomy, or data access. It produces a recommended classification (A/B/C/D) and highlights control gaps. Use it alongside the [production checklist](../checklist.md) and the [threat model](../threat-model.md).

**Agent under assessment:** ________________  **Assessor:** ________________  **Date:** ________________

---

## How to use this questionnaire

1. Answer every question in sections 1 to 7.
2. Score each section using the guidance in section 8.
3. Combine the impact and autonomy scores to derive the classification.
4. Record any "No" answer in a control-gap register with an owner and due date.

---

## Section 1: Agent Profile

| # | Question | Answer |
|---|----|----|
| 1.1 | What is the agent's primary business function? | |
| 1.2 | Which architecture pattern is used (ReAct, Plan-and-Execute, Multi-Agent, Hierarchical)? | |
| 1.3 | Is the agent customer-facing? | Yes / No |
| 1.4 | Does the agent operate autonomously, or only on explicit human trigger? | Autonomous / Triggered / Hybrid |
| 1.5 | Does the agent maintain persistent memory across sessions? | Yes / No |
| 1.6 | Does the agent coordinate with, or delegate to, other agents? | Yes / No |
| 1.7 | Which base model(s) and provider(s) does it use? | |
| 1.8 | Is the base model fine-tuned in-house? (If yes, EU AI Act "provider" duties may apply) | Yes / No |

---

## Section 2: Impact Assessment

| # | Question | Answer |
|---|----|----|
| 2.1 | Maximum financial value at risk per single action ($) | |
| 2.2 | Maximum aggregate value at risk per day ($) | |
| 2.3 | Are the agent's actions reversible? | Reversible / Partially / Irreversible |
| 2.4 | Worst-case regulatory consequence of an erroneous action | |
| 2.5 | Could a single error cascade across connected systems? | Yes / No |
| 2.6 | Does the agent touch safety-of-life or market-integrity functions? | Yes / No |

**Impact score (see section 8):** ______

---

## Section 3: Autonomy Assessment

| # | Question | Answer |
|---|----|----|
| 3.1 | Can the agent execute high-impact actions without human approval? | Yes / No |
| 3.2 | How many unapproved actions can it take per session? | |
| 3.3 | How complex are its tool chains (max tools per task)? | |
| 3.4 | Can it acquire new capabilities at runtime (e.g. dynamic tool discovery, MCP)? | Yes / No |
| 3.5 | Can it modify its own memory, goals, or plans? | Yes / No |

**Autonomy score (see section 8):** ______

---

## Section 4: Data Flow

| # | Question | Answer |
|---|----|----|
| 4.1 | What data does the agent read? Classify each source (public/internal/confidential/PII). | |
| 4.2 | What data does the agent write or modify? | |
| 4.3 | Does the agent transmit data to external endpoints? List approved destinations. | |
| 4.4 | Is egress filtering enforced against an allow-list? | Yes / No |
| 4.5 | Is persistent memory encrypted at rest? | Yes / No |
| 4.6 | Is retrieved content (RAG, tool output) treated as untrusted and scanned? | Yes / No |

---

## Section 5: Identity and Secrets

| # | Question | Answer |
|---|----|----|
| 5.1 | Does the agent have its own workload identity (e.g. SPIFFE ID), not a shared human account? | Yes / No |
| 5.2 | Are credentials short-lived and task-scoped? | Yes / No |
| 5.3 | Is there a Joiner-Mover-Leaver process owning this identity's lifecycle? | Yes / No |
| 5.4 | Do sub-agents inherit broad parent tokens? (A "Yes" is a finding) | Yes / No |
| 5.5 | Are all static secrets rotated on a defined schedule? | Yes / No |

---

## Section 6: Controls

| # | Question | Answer |
|---|----|----|
| 6.1 | Are tool permissions least-privilege, default-deny? | Yes / No |
| 6.2 | Are approval gates configured for high-impact actions? At what thresholds? | |
| 6.3 | Is a circuit breaker implemented, with defined thresholds? | Yes / No |
| 6.4 | Is a kill switch available at agent, category, and system levels? | Yes / No |
| 6.5 | Is prompt-injection detection applied to input and retrieved content? | Yes / No |
| 6.6 | Is output validated/encoded before downstream use? | Yes / No |
| 6.7 | Are MCP servers authenticated and tool definitions pinned? | Yes / No / N/A |

---

## Section 7: Testing and Monitoring

| # | Question | Answer |
|---|----|----|
| 7.1 | Has the adversarial test suite (T01-T50) been executed? Pass rate? | |
| 7.2 | Is a monitoring dashboard configured with real-time alerts? | Yes / No |
| 7.3 | Is a decision trace captured for every action? | Yes / No |
| 7.4 | Is there a denial-of-wallet (cost) ceiling and alert? | Yes / No |
| 7.5 | Is there an incident response playbook specific to this agent? | Yes / No |

---

## Section 8: Scoring and Classification

**Impact score:** count "high-impact" indicators from section 2.
- Value at risk > $10,000 per action, or irreversible, or regulatory consequence, or cascading, or safety/market-integrity = **High impact**.
- Otherwise = **Low impact**.

**Autonomy score:** from section 3.
- Executes high-impact actions without approval, or acquires capabilities at runtime, or self-modifies = **High autonomy**.
- Otherwise = **Low autonomy**.

**Classification matrix:**

| | Low impact | High impact |
|---|----|----|
| **Low autonomy** | Class A (standard oversight) | Class B (enhanced oversight) |
| **High autonomy** | Class C (active monitoring) | Class D (strict governance) |

**Recommended classification:** Class ______

**Rationale:**

________________________________________________________________

---

## Section 9: Control-Gap Register

Record every "No" answer that should be a "Yes" for the recommended classification.

| # | Gap | Section ref | Risk if unaddressed | Owner | Due date |
|---|----|----|----|----|----|
| 1 | | | | | |
| 2 | | | | | |
| 3 | | | | | |

---

## Section 10: Sign-Off

| Role | Name | Date | Decision (Approve / Approve with conditions / Reject) |
|----|----|----|----|
| Assessor | | | |
| Security engineering | | | |
| Compliance (required for Class C/D) | | | |
| Business sponsor | | | |

---

*Questionnaire version 2.0 - 2026 | Mervin Pearce, Pearce.Academy | CC-BY-4.0*
