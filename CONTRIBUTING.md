# Contributing

Thank you for considering a contribution to the Agentic AI Security & Governance Handbook. This is a practitioner reference, so accuracy and specificity matter more than volume.

## Ground rules

1. **Open an issue first.** Describe the change, the gap it fills, and any sources. This avoids duplicated effort and keeps scope tight.
2. **One topic per pull request.** Small, focused changes are reviewed faster.
3. **Cite specifics.** Every factual claim (CVE, CVSS score, incident, statistic, regulatory date) must be traceable to a primary source. Vague claims ("many organisations", "experts agree") will be asked for revision.

## House style

- **British English** throughout (organise, behaviour, licence as a noun).
- **No em dashes in running prose.** Use a hyphen with spaces, a comma, or restructure the sentence.
- **Short paragraphs**, three to four sentences maximum.
- **Lead with the "so what".** Tell the reader why a point matters before the detail.
- **Callout boxes** for emphasis: `> **Warning:**`, `> **Note:**`, `> **Tip:**`.
- **Tables** for structured comparisons; **fenced code blocks** with a language tag (`python`, `yaml`, `json`, `bash`).
- **Mermaid** for diagrams (```mermaid fenced blocks); verify they render on GitHub before submitting.
- **Cross-reference** other chapters with relative links, for example `[chapter 04](handbook/04-security-controls.md)`.
- Every chapter ends with a **Previous | Next** navigation footer.

## Code contributions

- Target **Python 3.11+**. Include type hints and docstrings.
- Code must run. Each module in `code/python/` has a `__main__` demonstration; keep it working.
- No heavy third-party dependencies in the control modules; they should run in a restricted sandbox.
- Validate YAML with a parser before submitting.

## Review checklist

Before opening a pull request, confirm:

- [ ] British English, no em dashes in prose.
- [ ] Claims are specific and sourced.
- [ ] Links resolve; navigation footer present on chapters.
- [ ] Mermaid diagrams render on GitHub.
- [ ] Python compiles and the `__main__` demo runs.
- [ ] YAML parses.
- [ ] No secrets, credentials, or real customer data anywhere in the change.

## Licensing

By contributing, you agree that your contributions are licensed under [CC BY 4.0](LICENSE), the same licence as the rest of the handbook.

## Contact

Raise an issue for anything unclear. For sensitive security matters, use a private disclosure channel rather than a public issue.
