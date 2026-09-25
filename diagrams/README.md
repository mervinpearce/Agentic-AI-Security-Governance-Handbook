# Diagrams

All diagrams in this handbook are written in [Mermaid](https://mermaid.js.org/) and embedded directly in the Markdown chapters using fenced ```mermaid code blocks. There are no binary image files to manage.

## Why Mermaid

- **Renders natively on GitHub.** GitHub renders Mermaid in Markdown, so diagrams appear in the browser with no build step.
- **Version-controllable.** Diagrams are plain text, so changes show up in diffs and pull requests like any other content.
- **Copy-paste portable.** The same blocks render in many Markdown tools (GitLab, Obsidian, VS Code with an extension, and the Mermaid Live Editor).

## Where the diagrams live

Diagrams are inline in the chapters, not in this folder. Notable ones include:

| Diagram | Location |
|----|----|
| Governance four-layer model | [chapter 03](../handbook/03-governance-framework.md) |
| Governance lifecycle | [chapter 03](../handbook/03-governance-framework.md) |
| Data flow with trust boundaries | [assets/threat-model.md](../assets/threat-model.md) |
| Data-exfiltration attack tree | [assets/threat-model.md](../assets/threat-model.md) |
| Excessive-agency attack tree | [assets/threat-model.md](../assets/threat-model.md) |
| MCP tool-poisoning flow | [chapter 08](../handbook/08-mcp-and-protocols.md) |
| A2A delegation and token inheritance | [chapter 08](../handbook/08-mcp-and-protocols.md) |
| NHI lifecycle (Joiner-Mover-Leaver) | [chapter 05](../handbook/05-identity-and-secrets.md) |
| Incident response flow | [chapter 12](../handbook/12-incident-response.md) |
| Continuous evaluation pipeline | [chapter 09](../handbook/09-testing-evaluation.md) |

## Rendering locally

If you want to render a diagram outside GitHub:

1. Copy the contents of a ```mermaid block.
2. Paste it into the [Mermaid Live Editor](https://mermaid.live/).
3. Export to SVG or PNG if you need a static image for a slide deck.

## Editing conventions

- Prefer `flowchart` for process and data-flow diagrams and `sequenceDiagram` for protocol exchanges.
- Keep node labels short; put detail in the surrounding prose.
- Test every diagram in the Mermaid Live Editor before committing, because a single syntax error stops the whole block from rendering on GitHub.
- Avoid parentheses and unescaped special characters inside node labels, which are a common cause of render failures.
