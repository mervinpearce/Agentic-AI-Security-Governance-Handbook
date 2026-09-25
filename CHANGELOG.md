# Changelog

All notable changes to this handbook are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project uses
semantic-style versioning for content releases.

## [2.0] - 2026

Major expansion from a single-file handbook into a full GitHub-native publication.

### Added
- Five new chapters: **Identity & Secrets** (05), **Supply Chain Security** (06),
  **Framework Security** (07), **MCP & Agent Protocols** (08), and
  **Incident Response** (12).
- New **Preface** (chapter 00) covering purpose, audience, and how to read the book.
- Full alignment with the **OWASP LLM Top 10 (2025)** across the threat chapters.
- Coverage of 2025-2026 incidents: EchoLeak (CVE-2025-32711), the Step Finance
  loss, the Mexican government breach, agent sandbox escapes, the Vercel breach,
  Gemini CLI RCE, LangGrinch (CVE-2025-68664), and GTG-1002.
- **Model Context Protocol (MCP)** and **Google A2A** security chapters, including
  tool poisoning, rug pulls, cross-server shadowing, the STDIO transport flaw, and
  the MAESTRO threat model.
- **Non-human identity (NHI)** guidance: SPIFFE/SPIRE, ephemeral credentials, and
  Joiner-Mover-Leaver for machine identities.
- Working Python control implementations in `code/python/`: circuit breaker,
  input validator, injection detector, tool permission enforcer, and a
  tamper-evident audit logger.
- OpenTelemetry-compatible monitoring configuration in `code/configs/`.
- New assets: STRIDE **threat model** and a **red team playbook**.
- New templates: **incident report** and **risk assessment questionnaire**.
- Enhanced **README**, **CONTRIBUTING**, this **CHANGELOG**, and a full
  **CC BY 4.0** licence file.

### Changed
- Expanded the adversarial **test suite** from 30 to 50 tests across 5 dimensions.
- Expanded the production **checklist** from 12 items to 7 sections and 63 items.
- Enhanced the **agent security config** template with identity, MCP, output
  handling, and denial-of-wallet controls.
- Updated the **regulatory alignment** chapter for the EU AI Act 2026 enforcement
  milestone, the provider/deployer divide, ISO 42001, and a shared control graph.
- Rewrote existing chapters (threat landscape, architecture, governance, controls,
  testing, deployment) with current data, Mermaid diagrams, and cross-references.

## [1.0] - September 2026

### Added
- Initial release: single-file handbook with eight chapters, a 12-point
  production checklist, a 30-test adversarial suite, and a YAML config template.
