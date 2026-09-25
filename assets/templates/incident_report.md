# Agent Security Incident Report

> **Note:** Complete this report for any incident involving an autonomous AI agent. For Class C/D agents, or any incident with financial, data-protection, or regulatory impact, this report feeds your DORA major-incident notification (initial notification within the regulator's deadline) and, where personal data is affected, your GDPR Article 33 assessment (72-hour clock). See [chapter 12, Incident Response](../../handbook/12-incident-response.md).

Store the completed report in the agent's runbook directory and link it from the incident ticket.

---

## 1. Incident Summary

| Field | Value |
|----|----|
| Incident ID | INC-________ |
| Report status | Draft / Under review / Final |
| Date/time detected (UTC) | ____ |
| Date/time contained (UTC) | ____ |
| Date/time resolved (UTC) | ____ |
| Reported by | ____ |
| Incident commander | ____ |
| Severity | SEV-1 / SEV-2 / SEV-3 / SEV-4 |
| Current state | Detecting / Containing / Investigating / Resolving / Closed |

**One-paragraph summary** (what happened, in plain language):

________________________________________________________________

---

## 2. Affected Agent(s)

| Field | Value |
|----|----|
| Agent ID | ____ |
| Agent version | ____ |
| Classification (A/B/C/D) | ____ |
| Architecture pattern | ReAct / Plan-and-Execute / Multi-Agent / Hierarchical |
| Owner team | ____ |
| Workload identity (SPIFFE ID or equivalent) | ____ |
| Environment | Production / Staging |

---

## 3. Classification of Incident

Tick all that apply. Map to the incident taxonomy in [chapter 01](../../handbook/01-threat-landscape.md).

- [ ] Prompt injection (direct)
- [ ] Prompt injection (indirect / retrieved content)
- [ ] Excessive agency / tool abuse (LLM06)
- [ ] Data exfiltration
- [ ] Sensitive information disclosure (LLM02)
- [ ] System prompt leakage (LLM07)
- [ ] Supply chain compromise (LLM03)
- [ ] Memory / data poisoning (LLM04)
- [ ] Improper output handling (LLM05)
- [ ] Unbounded consumption / denial-of-wallet (LLM10)
- [ ] MCP tool poisoning / rug pull
- [ ] Non-human identity / credential compromise
- [ ] Multi-agent escalation
- [ ] Other: ____

---

## 4. Timeline

Record events in UTC. Include the trigger, detection signal, each containment action, and recovery. Pull timestamps from the agent decision trace and audit log.

| Time (UTC) | Actor | Event | Source (trace ID / log) |
|----|----|----|----|
| | | | |
| | | | |
| | | | |

---

## 5. Impact Assessment

| Dimension | Detail |
|----|----|
| Financial impact (actual / potential) | ____ |
| Records/data affected (count and classification) | ____ |
| PII involved? | Yes / No / Unknown |
| Actions taken by agent (reversible?) | ____ |
| Customers affected | ____ |
| Systems reached beyond intended scope | ____ |
| Regulatory reportability | DORA: Y/N; GDPR: Y/N; other: ____ |

> **Warning:** If actions were irreversible (payments, trades, deletions), quantify the exposure precisely and escalate to the business sponsor immediately. Do not wait for the full investigation to notify.

---

## 6. Detection

| Field | Value |
|----|----|
| How was it detected? | Automated alert / Circuit breaker / Manual / Third party |
| Detecting control | ____ (e.g. UnusualEgressVolume alert, injection detector) |
| Time from onset to detection | ____ |
| Was the decision trace complete? | Yes / No / Partial |

---

## 7. Containment Actions

| Action | Taken? | Time (UTC) | By |
|----|----|----|----|
| Agent-level kill switch | ☐ | | |
| Category-level kill switch | ☐ | | |
| System-level kill switch (manual mode) | ☐ | | |
| Credentials revoked / rotated | ☐ | | |
| Affected tool disabled | ☐ | | |
| MCP server isolated / removed | ☐ | | |
| Decision traces and logs preserved | ☐ | | |

---

## 8. Root Cause Analysis

State the root cause as a testable hypothesis, then the evidence that confirms it. Avoid blaming "the model" without a mechanism.

**Hypothesised root cause:**

________________________________________________________________

**Evidence (trace excerpts, log lines, reproduction):**

________________________________________________________________

**Contributing factors** (missing control, misconfiguration, gap in coverage):

________________________________________________________________

---

## 9. Resolution and Recovery

| Field | Value |
|----|----|
| Fix applied | Prompt change / Permission change / Guardrail update / Version rollback / Other |
| Description of fix | ____ |
| Validated in staging? | Yes / No |
| Adversarial suite re-run? | Yes / No (pass rate: ___%) |
| Production resumed at (UTC) | ____ |
| Enhanced monitoring in place? | Yes / No |

---

## 10. Corrective and Preventive Actions

| # | Action | Owner | Due date | Status |
|---|----|----|----|----|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |

- [ ] New test case added to [adversarial test suite](../test-suite.md) reflecting this failure mode
- [ ] Agent classification reviewed and updated if impact was underestimated
- [ ] [Threat model](../threat-model.md) updated with the new vector
- [ ] Runbook updated with the containment steps that worked

---

## 11. Regulatory Notifications

| Regulator / party | Required? | Deadline | Submitted (UTC) | Reference |
|----|----|----|----|----|
| Financial regulator (DORA major incident) | Y/N | | | |
| Data protection authority (GDPR Art. 33) | Y/N | 72h | | |
| Affected customers | Y/N | | | |
| Cyber insurer | Y/N | | | |

---

## 12. Sign-Off

| Role | Name | Date | Signature |
|----|----|----|----|
| Incident commander | | | |
| Security engineering lead | | | |
| Compliance officer | | | |
| Business sponsor | | | |

---

*Template version 2.0 - 2026 | Mervin Pearce, Pearce.Academy | CC-BY-4.0*
