# Production Deployment Checklist - Agentic AI Systems

*Standalone checklist for pre-deployment security review of autonomous agents.*

> **Note:** Complete each item before promoting an agent to production. Mark status and add notes. File the completed checklist in your agent's runbook directory. This checklist expands the 12-point review in [chapter 10](../handbook/10-production-deployment.md) into 7 sections and 63 items. Items marked **[C/D]** are mandatory for Class C and Class D agents.

**Agent:** ________________  **Version:** ________  **Classification:** ______  **Reviewer:** ________________  **Date:** ________

---

## 1. Agent Classification and Governance

| # | Check | Status | Notes |
|---|----|----|----|
| 1.1 | Impact assessed: financial value at risk per action quantified ($____) | ☐ | |
| 1.2 | Reversibility determined: reversible / partially / irreversible | ☐ | |
| 1.3 | Autonomy level documented: autonomous / triggered / hybrid | ☐ | |
| 1.4 | Classification assigned (A/B/C/D) via impact x autonomy matrix | ☐ | Class ___ |
| 1.5 | EU AI Act risk level determined (high / limited / minimal) | ☐ | |
| 1.6 | Provider vs deployer status confirmed (fine-tuning triggers provider duties) | ☐ | |
| 1.7 | DORA scope and ICT risk-register entry confirmed | ☐ | |
| 1.8 | Named accountable owner and approver recorded | ☐ | |
| 1.9 | **[C/D]** Governance committee review completed | ☐ | |

## 2. Identity and Secrets

| # | Check | Status | Notes |
|---|----|----|----|
| 2.1 | Agent has a dedicated workload identity (not a shared human account) | ☐ | |
| 2.2 | Credentials are short-lived and task-scoped (no long-lived API keys) | ☐ | TTL: ___ |
| 2.3 | Secret rotation schedule defined and automated | ☐ | Every ___ |
| 2.4 | Joiner-Mover-Leaver ownership assigned for this identity | ☐ | Owner: ___ |
| 2.5 | Sub-agents do not inherit broad parent tokens | ☐ | |
| 2.6 | No secrets committed to source control (scanner passing) | ☐ | |
| 2.7 | **[C/D]** Workload identity federated via SPIFFE/SPIRE or equivalent | ☐ | |

## 3. Tool Permissions

| # | Check | Status | Notes |
|---|----|----|----|
| 3.1 | Default-deny permission model in force | ☐ | |
| 3.2 | Each tool listed with permission type (read-only / write-specific / execute-limited) | ☐ | |
| 3.3 | Least-privilege applied: no broader permissions than the function requires | ☐ | |
| 3.4 | Tool scope defined (databases, file paths, API endpoints, symbol/amount limits) | ☐ | |
| 3.5 | Network egress restricted to an approved allow-list | ☐ | Approved: ___ |
| 3.6 | Approval gates mapped per action type (Gate 0-3) | ☐ | |
| 3.7 | Dangerous commands/tools on the deny-list | ☐ | |
| 3.8 | Runtime permission enforcement tested (denied calls actually blocked) | ☐ | |

## 4. Memory, Data, and Supply Chain

| # | Check | Status | Notes |
|---|----|----|----|
| 4.1 | Memory data classification defined (public / internal / confidential / PII) per field | ☐ | |
| 4.2 | Encryption at rest enabled for persistent memory | ☐ | Algorithm: ___ |
| 4.3 | Retention policy configured per classification tier | ☐ | Standard: ___ days |
| 4.4 | Memory write permissions restricted by agent role | ☐ | |
| 4.5 | Retrieved content (RAG, tool output) treated as untrusted and scanned | ☐ | |
| 4.6 | Egress filtering configured for data leaving the agent system | ☐ | |
| 4.7 | Model and dependency provenance verified (signed artefacts / SBOM) | ☐ | |
| 4.8 | Framework dependencies pinned and scanned for known CVEs | ☐ | |
| 4.9 | MCP servers authenticated; tool definitions pinned against rug pulls | ☐ | N/A ☐ |

## 5. Runtime Controls

| # | Check | Status | Notes |
|---|----|----|----|
| 5.1 | Circuit breaker implemented with failure threshold and window | ☐ | ___ fails / ___ s |
| 5.2 | Kill switch tested at agent level | ☐ | Date: ___ |
| 5.3 | Kill switch tested at category level | ☐ | Date: ___ |
| 5.4 | Kill switch tested at system level (revert to manual) | ☐ | Date: ___ |
| 5.5 | Kill switch access is independent of the agent system | ☐ | |
| 5.6 | Guardrails configuration reviewed and approved | ☐ | Config: ___ |
| 5.7 | Prompt-injection detection enabled on input and retrieved content | ☐ | |
| 5.8 | Output handling validated/encoded before downstream use (LLM05) | ☐ | |
| 5.9 | Denial-of-wallet cost ceiling and alert configured (LLM10) | ☐ | Ceiling: $___ |

## 6. Testing and Validation

| # | Check | Status | Notes |
|---|----|----|----|
| 6.1 | Adversarial test suite executed (T01-T50) | ☐ | Pass rate: ___% |
| 6.2 | Injection resistance score documented (>90% target) | ☐ | Score: ___% |
| 6.3 | Tool abuse tests completed (privilege escalation, lateral movement) | ☐ | |
| 6.4 | Excessive-agency scenarios tested (unauthorised high-impact action) | ☐ | |
| 6.5 | Partial-failure scenario tested (tool fails mid-execution) | ☐ | |
| 6.6 | Resource-exhaustion / unbounded-loop scenario tested | ☐ | |
| 6.7 | Rollback procedure tested with previous agent version | ☐ | Rolled to: ___ |
| 6.8 | **[C/D]** Independent red-team exercise completed | ☐ | |

## 7. Monitoring, Documentation, and Operations

| # | Check | Status | Notes |
|---|----|----|----|
| 7.1 | Decision trace logging enabled for all actions | ☐ | Format: JSONL |
| 7.2 | Audit log is tamper-evident (hash chain or WORM store) | ☐ | |
| 7.3 | Metrics dashboard configured with real-time alerts | ☐ | URL: ___ |
| 7.4 | Anomaly-detection thresholds set (call rate, data volume, tool diversity) | ☐ | |
| 7.5 | Alert routing confirmed to on-call and escalation contacts | ☐ | Channels: ___ |
| 7.6 | Audit log retention configured (minimum 365 days) | ☐ | Retention: ___ |
| 7.7 | Agent runbook documents normal operation and failure modes | ☐ | Location: ___ |
| 7.8 | Incident response playbook specific to this agent type | ☐ | |
| 7.9 | Escalation procedures defined per gate level | ☐ | |
| 7.10 | Version management process established (deploy, upgrade, sunset) | ☐ | |
| 7.11 | Stakeholder notification matrix defined by impact level | ☐ | |
| 7.12 | **[C/D]** Regulatory notification workflow tested (DORA/GDPR timers) | ☐ | |

---

## Sign-Off

| Role | Name | Signature | Date |
|----|----|----|----|
| Security engineer | | | |
| Platform engineer | | | |
| Product owner / business sponsor | | | |
| Compliance officer (required for Class C/D) | | | |

**Deployment decision:** Approve ☐  Approve with conditions ☐  Reject ☐

---

*Checklist version 2.0 - 2026 | Mervin Pearce, Pearce.Academy | CC-BY-4.0*
