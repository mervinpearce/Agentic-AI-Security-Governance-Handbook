# Agentic AI Security & Governance Handbook

**A practical field guide for securing autonomous AI agents in production.**

[![License: CC BY 4.0](https://img.shields.io/badge/License-CC--BY--4.0-lightgrey.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.0-blue.svg)]()
[![Status](https://img.shields.io/badge/status-active-success.svg)]()
[![Chapters](https://img.shields.io/badge/chapters-13-informational.svg)](handbook/)
[![OWASP LLM Top 10](https://img.shields.io/badge/aligned-OWASP%20LLM%20Top%2010%202025-orange.svg)](handbook/01-threat-landscape.md)
[![EU AI Act](https://img.shields.io/badge/mapped-EU%20AI%20Act%202026-blueviolet.svg)](handbook/11-regulatory-alignment.md)

> Autonomous agents do not just answer questions. They act: they move money, change records, call APIs, and talk to other agents. This handbook is about keeping that autonomy safe, governed, and defensible in a regulated environment.

---

## Why this handbook

In 2025 and 2026 the risk stopped being theoretical. Zero-click prompt injection exfiltrated data from Microsoft 365 Copilot ([EchoLeak, CVE-2025-32711](handbook/01-threat-landscape.md)). Autonomous trading agents with excessive permissions caused a reported USD 40m loss at Step Finance. A state-sponsored operation used AI agents to run the majority of a real espionage campaign. Meanwhile the EU AI Act became fully enforceable for high-risk systems on 2 August 2026.

This is a working reference for the people who have to secure these systems: security engineers, architects, and CISOs, with a bias towards financial services where the margin for error is smallest.

---

## Quick links

| Asset | Description |
|----|----|
| [Full handbook (13 chapters)](handbook/) | The complete guide, from threat landscape to incident response |
| [Production checklist](assets/checklist.md) | 7-section, 63-item pre-deployment review |
| [Adversarial test suite](assets/test-suite.md) | 50 tests across 5 attack dimensions |
| [STRIDE threat model](assets/threat-model.md) | Reusable threat model for agentic systems |
| [Red team playbook](assets/red-team-playbook.md) | Structured red-team exercise guide |
| [Config template](assets/templates/agent_security_config.yaml) | Full guardrails configuration |
| [Working Python controls](code/python/) | Circuit breaker, validators, permission enforcer, audit logger |

---

## Chapter navigation

| # | Chapter | Focus |
|---|----|----|
| 00 | [Preface](handbook/00-preface.md) | Why this book, how to read it |
| 01 | [The Agentic Threat Landscape](handbook/01-threat-landscape.md) | OWASP LLM Top 10 2025, real incidents, denial-of-wallet |
| 02 | [Agent Architecture & Security](handbook/02-architecture-security.md) | ReAct, Plan-and-Execute, multi-agent, memory |
| 03 | [Governance Framework](handbook/03-governance-framework.md) | Four-layer model, classification, approval gates |
| 04 | [Security Controls Playbook](handbook/04-security-controls.md) | Injection defence, permissions, output handling, monitoring |
| 05 | [Identity & Secrets](handbook/05-identity-and-secrets.md) | Non-human identity, SPIFFE/SPIRE, ephemeral credentials |
| 06 | [Supply Chain Security](handbook/06-supply-chain-security.md) | Models, dependencies, provenance, SBOM |
| 07 | [Framework Security](handbook/07-framework-security.md) | LangChain, LangGraph, AutoGen, CrewAI |
| 08 | [MCP & Agent Protocols](handbook/08-mcp-and-protocols.md) | MCP and A2A threat models and controls |
| 09 | [Testing & Evaluation](handbook/09-testing-evaluation.md) | Adversarial testing, metrics, continuous evaluation |
| 10 | [Production Deployment](handbook/10-production-deployment.md) | Guardrails, kill switches, rollout |
| 11 | [Regulatory Alignment](handbook/11-regulatory-alignment.md) | EU AI Act 2026, DORA, NIST AI RMF, ISO 42001 |
| 12 | [Incident Response](handbook/12-incident-response.md) | Detection, containment, forensics, reporting |

---

## How to use it

- **Designing a new agent?** Start with [chapter 03 (Governance)](handbook/03-governance-framework.md), run the [risk assessment](assets/templates/risk_assessment.md), then work through the [controls playbook](handbook/04-security-controls.md).
- **Reviewing before go-live?** Use the [production checklist](assets/checklist.md) and run the [test suite](assets/test-suite.md).
- **Responding to an incident?** Jump to [chapter 12](handbook/12-incident-response.md) and the [incident report template](assets/templates/incident_report.md).
- **Building controls?** The [Python modules](code/python/) are importable and runnable, not pseudocode.

---

## Repository structure

```
agentic-ai-security-handbook/
├── README.md                       # This file
├── CONTRIBUTING.md
├── CHANGELOG.md
├── LICENSE                         # CC BY 4.0
├── handbook/                       # 13 chapters (00-12)
├── assets/                         # Checklist, test suite, threat model, red-team playbook
│   └── templates/                  # Config, incident report, risk assessment
├── code/
│   ├── python/                     # Working security control implementations
│   └── configs/                    # OpenTelemetry monitoring config
└── diagrams/                       # Notes on the Mermaid diagrams used throughout
```

## Why GitHub-native

- **Bookmarkable** - reference specific sections during design reviews.
- **Copy-paste ready** - YAML templates, checklists, and Python run directly.
- **Version-controlled** - update as architectures and regulations evolve.
- **Open** - CC BY 4.0 for community contribution.

Mermaid diagrams and tables render natively on GitHub, so the handbook is readable in the browser with no build step.

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) first. In short: open an issue to discuss, follow the British-English house style (no em dashes in running prose), keep claims specific and sourced, and test any YAML or Python you touch.

## Author

**Mervin Pearce** - Pearce.Academy (DORA-401 / MSC-401 / FS-401). Financial services cybersecurity and agentic AI advisory.

## Disclaimer

This handbook is guidance, not legal advice. CVE identifiers, incident details, and regulatory dates reflect information available at the time of writing (2026). Verify against primary sources before relying on any specific detail for a compliance decision.

---

*Last updated: 2026 | Version 2.0 | Licensed under [CC BY 4.0](LICENSE)*
