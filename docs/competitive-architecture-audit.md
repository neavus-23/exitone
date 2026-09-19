# Competitive Architecture Audit

> Audit date: 2026-09-19  
> Scope: ExitOne architecture/codebase compared with Strix, Shannon, PentAGI, PentestGPT and CAI.  
> Method: repository metadata plus targeted code/document searches. This is an architecture/code-evidence audit, not a claim of exhaustive source-code equivalence across every project.

## Executive conclusion

The hypothesis that ExitOne is differentiated simply because it has persistent memory, context, graphs, hypotheses and next-action recommendations is **not defensible**.

The repositories reviewed already demonstrate overlapping capabilities:

- Strix: multi-agent orchestration, TODOs/notes as shared working memory, coverage tracking and strategy coordination.
- PentAGI: persistent episodic memory, knowledge graph integration, historical-memory retrieval and explicit information-gathering strategy.
- Shannon: resumable workspaces and information-reduction-oriented pentesting workflow.
- PentestGPT: persistent multi-stage task/session concepts and task-tree-oriented reasoning.
- CAI: research around agent trajectories, strategy and evaluation.

ExitOne's stronger differentiation is narrower:

> **A temporal, evidence-grounded investigation state in which events, evidence, observations, entities, objectives, hypotheses, actions, decisions and outcomes are first-class objects, and new evidence can change the validity of prior investigative conclusions. Candidate actions are generated from that state and remain behind an explicit human execution boundary.**

This is a product/architecture hypothesis, not a claim that no other project implements any equivalent behavior.

## Current ExitOne strengths verified in the repository

### 1. First-class investigation state

ExitOne's schema explicitly models:

`session → event → evidence → observation → entity/relationship`

and separately:

`objective/path → candidate → action → decision_context → outcome`

This is stronger than storing a transcript or a generic agent scratchpad.

### 2. Temporal hypothesis lifecycle

Hypotheses have explicit states including `UNTESTED`, `SUPPORTED`, `DISPUTED`, `REFUTED`, `CONFIRMED` and `REOPENED`.

The reopening model is structurally tied to observations and action assumptions rather than simply interpreting a later natural-language message.

### 3. Provenance

Evidence keeps the raw-output reference and producing event. Observations retain their evidence relationship. Hypotheses point to concrete observations.

This gives ExitOne an auditable chain:

`Hypothesis → Observation → Evidence → Event`

### 4. Decision context

ExitOne persists the known-facts snapshot, known-unknowns snapshot, motivating objective and rationale at the time an action is selected.

This is important because the system can reconstruct not only **what was done**, but **what was known when the decision was made**.

### 5. Outcome-driven strategy

The outcome model tracks new entities, new relationships, hypothesis changes, contradictions resolved and a computed information-gain heuristic.

The code deliberately calls this a utility/heuristic score rather than pretending it is formal Shannon information gain.

### 6. Stale strategy protection

`strategy_job.revision` is tied to the session state revision. Exploration results can therefore be discarded when the investigation changed while the LLM was reasoning.

### 7. Human execution boundary

The command engine renders suggestions but does not execute the stored command. `Ctrl+Space` inserts the suggestion into the shell buffer; Enter remains the operator's action.

### 8. Rabbit-hole detection

ExitOne detects repeated low-yield attempts and can surface a real alternative path without requiring ML.

## Competitive findings

| Capability | ExitOne | Strix | Shannon | PentAGI | PentestGPT | CAI |
|---|---|---|---|---|---|---|
| Persistent session/workspace | Yes | Yes | Yes | Yes | Yes | Research/agent sessions |
| Working/history memory | Yes | Yes | Yes | Yes | Yes | Yes |
| Knowledge graph | Yes | Partial/agent state | Attack-path/state concepts | Yes | Task tree/state | Research/agent graph concepts |
| Explicit hypotheses | Yes | Findings/validation | Attack paths | Agent reasoning/state | Tasks/objectives | Research trajectories |
| Action/outcome model | **First-class** | Agent/tool execution | Workflow stages | Flow/tool execution | Task execution | Agent trajectories |
| Temporal reopening | **Yes** | Not established by this audit | Not established | State/memory, not equivalent verified | Not established | Not established |
| Decision snapshot | **Yes** | Working notes/todos | Workspace context | Execution context | Session/task context | Agent traces |
| Evidence provenance chain | **Explicit** | Findings/tool artifacts | Findings/PoCs | Tool/result history | Session outputs | Trajectories |
| Information-gain/utility signal | **Explicit heuristic** | Strategy/coverage | Information-reduction framing | Information-gathering strategy | Task progression | Research/evaluation |
| Human command execution boundary | **Yes** | Autonomous execution is central | Autonomous execution is central | Autonomous execution is central | Agent execution | Agent execution |
| Terminal-native human workflow | **Core** | CLI + agent runtime | CLI/workspace | Web/API + runtime | CLI/interactive | Agent framework |
| Reproducible investigation replay | **Architecture supports it** | Historical runs | Resumable workspace | Persistent flow/history | Session persistence | Trajectory data |

Rows marked "not established" mean the targeted repository search did not provide sufficient evidence to claim equivalence; they are not claims that the feature does not exist.

## What ExitOne should NOT do

The audit weakens the case for adding generic AI-agent features merely because competitors have them.

Avoid turning ExitOne into:

- another autonomous pentest orchestrator;
- another generic ReAct loop;
- another multi-agent tool runner;
- another vector-memory wrapper;
- another attack-chain visualizer without temporal semantics;
- another chatbot with a shell.

Those areas already have strong projects.

## P0-1 — Stabilization and pentester-first hardening

Before adding new research capabilities, stabilize the functionality that already exists and make the current workflow reliable enough for daily use by a pentester in 2026.

This is intentionally the first priority. The objective is not to add more AI features; it is to make the existing investigation loop predictable, fast, observable and trustworthy.

### P0-1.1 Functional stabilization

Audit every currently exposed workflow end-to-end:

- workspace/session creation and resume;
- Control Console navigation and context stack;
- TUI PTY lifecycle and shell interaction;
- Zsh command/output capture;
- manual and automatic ingestion;
- deterministic parsers and generic extraction;
- entity/relationship correlation;
- objectives and objective paths;
- hypotheses, contradiction handling and reopening;
- candidate generation/ranking;
- accept, action registration and action-event association;
- outcome creation and state revision;
- next, why, guide, ask, explain, resolve;
- Graph, Vault and Chat views;
- scope and focus behavior;
- rabbit-hole detection;
- report generation;
- sensitive-data masking and history filtering.

Every path should have deterministic regression tests for success, failure, cancellation, duplicate ingestion, stale state and restart/resume behavior.

### P0-1.2 Fix correctness before intelligence

Prioritize defects that can make ExitOne remember or recommend something incorrectly:

1. duplicate events/evidence;
2. incorrect action ↔ event association;
3. stale candidate acceptance after state changes;
4. incorrect hypothesis reopening;
5. entity merge collisions;
6. ambiguous provenance;
7. parser false positives;
8. parser failures that silently discard evidence;
9. race conditions between ingestion and strategy jobs;
10. TUI/PTY lifecycle leaks;
11. inconsistent state after process restart;
12. discrepancies between the canonical embedded schema and db/schema.sql.

The invariant is:

> ExitOne must never become more confident because its internal state became less correct.

### P0-1.3 Pentester UX hardening

Optimize the current workflow around how an experienced operator actually works:

- suggestions must be visible without stealing terminal focus;
- Ctrl+Space must remain instantaneous and must never execute;
- commands should be copyable/editable before execution;
- candidates should show intent → why now → expected evidence → risk → assumptions;
- distinguish confirmed values from inferred values at every UI surface;
- make failed attempts useful rather than visually noisy;
- make already-tested information immediately discoverable;
- allow fast drill-down from a candidate to its evidence and previous attempts;
- keep the default OVERVIEW compact enough for an active terminal session;
- preserve keyboard-first operation and minimize modal interaction;
- make stale/reopened paths prominent but non-blocking;
- keep Chat subordinate to structured investigation state rather than making it the primary interface.

### P0-1.4 Investigation memory quality

Validate that the existing memory model actually answers the pentester's most important questions:

- What do I know?
- How do I know it?
- What have I already tried?
- What failed?
- What changed since then?
- What assumptions were true when I made that decision?
- What is still unknown?
- Which previous conclusion is no longer safe to treat as closed?
- Why is ExitOne suggesting this now?
- What evidence would make this suggestion successful or irrelevant?

If a workflow cannot answer these questions deterministically from stored state, fix that before adding another LLM capability.

### P0-1.5 2026 pentesting coverage baseline

Expand the current methodology and command registry around modern pentesting workflows, without turning ExitOne into a hard-coded attack playbook.

Prioritize coverage for:

- web/API reconnaissance and endpoint mapping;
- authentication and authorization testing;
- session/cookie/token analysis;
- REST and GraphQL API patterns;
- TLS/HTTP security metadata;
- DNS and cloud-facing attack surface;
- SMB/LDAP/Kerberos/WinRM/SSH;
- identity and credential discovery;
- file shares and secrets exposure;
- container/Kubernetes/cloud identity surfaces;
- common Active Directory investigation paths;
- vulnerability validation and evidence collection;
- post-access enumeration and privilege/access analysis;
- AI-enabled application surfaces where relevant: prompt injection, indirect prompt injection, retrieval/tool boundaries and agent permissions.

The goal is not to encode exploit recipes. The goal is to make methodology objectives, evidence types, command capabilities and provenance rich enough that ExitOne can reason across these surfaces.

### P0-1.6 Safety and trust baseline

The human execution boundary should be tested as a security invariant, not merely documented. Current 2026 guidance around autonomous pentesting emphasizes scope enforcement, human oversight, auditability and safe autonomy boundaries. This aligns with ExitOne's human-in-the-loop architecture. 

Add regression tests proving that:

- no candidate path can execute a target command implicitly;
- LLM output cannot directly invoke the shell;
- inferred parameters cannot silently become confirmed facts;
- out-of-scope assets remain visible as exclusions;
- stale candidates cannot bypass current scope/state;
- sensitive credentials remain masked by default;
- provenance survives LLM-assisted extraction;
- all operator-approved actions remain auditable.

### P0-1.7 Definition of Done

P0-1 is complete only when:

- the current major workflows have automated regression coverage;
- known correctness bugs are closed or explicitly documented;
- a fresh installation can reproduce the same core workflow reliably;
- restart/resume preserves investigation state correctly;
- a pentester can conduct a realistic lab engagement without falling back to manual bookkeeping for basic state reconstruction;
- every suggestion has traceable evidence/objective/action basis;
- no LLM-generated content can silently mutate authoritative investigation state;
- performance remains responsive during active terminal use;
- the current feature set is documented according to actual behavior, not intended behavior.

P0-1 deliberately precedes the research-heavy P0 work below. Stabilize the instrument before measuring whether its intelligence is novel.
## What should be strengthened

### P0 — Make the investigation-state model measurable

Add a formal test/evaluation suite for:

1. `STATE → ACTION → OUTCOME → STATE CHANGE → REPLAN`
2. contradictory evidence;
3. reopening after a previous conclusion;
4. stale candidate invalidation;
5. repeated failed actions;
6. newly discovered identities reopening previously tested authentication paths;
7. provenance reconstruction;
8. decision reconstruction.

The objective is to demonstrate that ExitOne changes its recommendations because the **investigation state changed**, not merely because an LLM produced a different answer.

### P0 — Add Investigation Replay

Implement:

`exitone replay <session>`

Output should reconstruct:

- chronological events;
- evidence introduced;
- entities/relationships created;
- objectives opened/answered;
- hypotheses opened/changed/reopened;
- candidates proposed;
- operator decisions;
- actions executed;
- outcomes;
- strategy changes;
- why the next direction became relevant.

This would turn ExitOne's temporal model into a directly observable capability.

### P1 — Add Context Resolver as a first-class subsystem

Do not send the entire SQLite database to the LLM.

Resolve a compact context from:

- current event;
- related entities;
- supporting/contradicting observations;
- previous attempts;
- open objectives;
- reopened hypotheses;
- contradictions;
- similar actions;
- historical outcomes.

Then pass only that bounded context to `guide`, `ask`, `explain` and exploratory strategy.

### P1 — Separate strategy learning from LLM reasoning

The long-term learning target should remain:

`STATE → ACTION INTENT → OUTCOME`

Store abstract state features, not target-specific writeups or machine identities.

Useful learning signals:

- information gained;
- hypotheses resolved;
- new entities;
- new relationships;
- contradictions resolved;
- dead ends eliminated;
- objective progress;
- time spent;
- repeated actions.

### P1 — Make "information gain" terminology precise

Current implementation is intentionally heuristic. Keep that honesty.

Prefer UI language such as:

- Utility
- Expected information gain
- Investigation value

and expose the contributing factors through `exitone why`.

Do not present the current scalar as mathematically formal information gain.

### P2 — Add a competitive benchmark fixture

Create synthetic investigations where competing architectures can be evaluated on identical state transitions.

Example:

1. SSH discovered.
2. Admin authentication tested and fails.
3. New identity `j.smith` discovered.
4. Prior SSH conclusion becomes incomplete.
5. Candidate generation should reopen identity-specific authentication coverage.
6. Operator rejects the candidate.
7. A web discovery reveals a related credential clue.
8. Strategy should re-plan from the changed graph.

The benchmark should assert state transitions and candidate-basis provenance, not exact LLM wording.

## P-CONFIG — Configuration and AI Provider Control Center

Add a dedicated **CONFIG** tab to the TUI so ExitOne's operational configuration can be inspected and changed without editing files manually.

The TUI becomes:

`OVERVIEW | GRAPH | VAULT | CHAT | REPORT | CONFIG`

### Pentest engagement context

CONFIG should also be the central place to define the contextual information that ExitOne uses throughout an investigation. This is not limited to technical application settings: it should capture the operator's explicit engagement context so recommendations are grounded in the actual assignment.

Include, where applicable:

- **Scope / Rules of Engagement** — in-scope assets, explicit exclusions, domains, IP ranges, applications, APIs, environments and permitted test windows;
- **Engagement objectives** — what the pentester is expected to establish or validate;
- **Testing constraints** — prohibited techniques, rate limits, production restrictions, authentication constraints and other operational boundaries;
- **Environment context** — lab, staging, production or other environment classification;
- **Known information** — information supplied by the client before testing;
- **Pentester notes** — free-form comments, observations and working context supplied explicitly by the operator;
- **Assumptions** — assumptions the operator wants ExitOne to consider until evidence confirms or disproves them;
- **Known unknowns** — questions the operator already knows remain unresolved;
- **Priority/focus** — explicit areas the operator wants investigated first;
- **Client terminology** — application names, business functions, asset aliases and other vocabulary that improves correlation;
- **Assessment metadata** — engagement name, assessment type, environment, dates, team/operator information and report metadata;
- **Evidence handling preferences** — retention, redaction and reporting rules supported by the implementation.

### Operator context versus evidence

A critical distinction should be preserved:

`Operator Context ≠ Evidence`

A pentester comment such as “the client says this account should be disabled” is contextual information, not proof that the account is disabled. ExitOne may use it to formulate objectives, hypotheses or suggestions, but it must not silently promote it to an observed fact.

Represent contextual inputs with explicit provenance and status, for example:

`OPERATOR_NOTE → CONTEXT → HYPOTHESIS/OBJECTIVE → EVIDENCE → OBSERVATION`

This allows the LLM to use the pentester's knowledge without contaminating the authoritative evidence graph.

### Scope as a first-class control

The existing scope model should be surfaced and expanded through CONFIG rather than requiring CLI-only management. The operator should be able to add, edit, disable and remove scope rules, including explicit exclusions.

Scope should be evaluated before candidate presentation and remain visible in the investigation UI. An asset should not become in-scope merely because an LLM inferred a relationship to an in-scope asset.

Where technically supported, scope entries should distinguish:

- exact asset;
- hostname/domain;
- IP/CIDR;
- URL/application/API;
- wildcard/pattern;
- explicit exclusion;
- note/reason;
- validity period.

### LLM context policy

CONFIG should provide a clear policy for which contextual information each AI capability receives.

For example:

`Strategy = scope + objectives + relevant evidence + hypotheses + operator context`

`Report = investigation state + validated evidence + selected operator context`

`Explain = methodology + relevant investigation state`

The system should not blindly send all configuration or all notes to every model. Context should be resolved according to capability and least-necessary information.

### Session context controls

The operator should be able to distinguish:

- **Persistent engagement context** — survives across sessions/workspace resume;
- **Workspace context** — applies to a particular engagement/workspace;
- **Session context** — applies only to the current run;
- **Ephemeral note** — temporary working context that should not become part of the permanent investigation record.

This prevents a temporary thought from becoming permanent institutional memory accidentally.

### Context lifecycle

Operator context should support:

1. create;
2. edit;
3. pin/unpin;
4. mark as resolved;
5. supersede;
6. archive;
7. delete;
8. inspect provenance;
9. control which AI capabilities may consume it.

### Definition of Done — context and scope

This part of P-CONFIG is complete when a pentester can configure the engagement scope, exclusions, objectives, constraints, environment, notes, assumptions, known unknowns and other relevant context from CONFIG; ExitOne uses that information to improve investigation guidance; and the system still keeps operator-provided context clearly separated from authoritative evidence and observations.

### Configuration domains

Expose supported configuration for AI/LLM providers, active and fallback models, local LLM endpoints, OpenAI-compatible endpoints, generation parameters, extraction, strategy, GraphRAG, guide/explain, command generation, parsers, ingestion, Zsh/tmux/PTY capture, workspace/session defaults, scope, candidate ranking, rabbit-hole thresholds, reporting, UI preferences, logging, storage and privacy/security.

Only settings actually supported by the current implementation should be active controls. Planned settings should be clearly marked as planned or disabled.

### AI provider management

Allow the operator to create, edit, duplicate, enable/disable, test, select, reorder and delete provider configurations. Support multiple independent providers, including local llama-server, Ollama and OpenAI-compatible/self-hosted endpoints, with room for additional adapters.

Provider fields should include, where applicable: name, endpoint/base URL, model identifier, credential reference, connection mode, timeout, context window, generation parameters, enabled state, capabilities, priority and fallback eligibility.

### Role-based model assignment

Allow different models/providers to be assigned to logical ExitOne capabilities such as:

`Extraction → Strategy → Guide → Explain → GraphRAG → Report`

This allows lightweight local models to handle deterministic-adjacent tasks while stronger models can be assigned to reasoning or report narration, subject to implemented capabilities.

### Configuration CRUD

The operator should be able to create, edit, duplicate, enable/disable, test connectivity, test a model, assign capabilities, reorder priority, delete configurations and restore safe defaults. Destructive actions require confirmation.

### Secrets

API keys, tokens and other secrets must be masked by default, support controlled temporary reveal, never enter command history or ordinary logs, and never be included in prompts, reports or telemetry. Provider credentials should remain separate from investigation evidence so exported reports cannot accidentally contain them.

### Configuration scope and provenance

Support explicit configuration scope where implemented:

`Global → Workspace → Session`

The effective value should show its source, such as `workspace override` or `global default`. AI-assisted operations should be able to record the provider/model configuration that influenced them, without recording secrets.

### Validation and safe activation

Validate schema/types, provider connectivity, model availability, capability compatibility, timeouts, parameters, endpoint safety and required credentials before activation. A failed configuration test must not replace the currently working configuration.

### Auditability

Configuration changes that affect investigation behavior should record timestamp, configuration key, safe previous/new values, operator/session context, provider/model identifier and optional change note. Secret values must never enter the audit trail.

### Competitive redesign: CONFIG as an Engagement Control Plane

The comparison changes the design recommendation. CONFIG should not become a generic "settings page". Shannon already combines configuration with authenticated testing, scope guidance, rules of engagement and report filtering; Strix exposes structured LLM/context/runtime settings and supports many providers through LiteLLM; PentAGI exposes provider profiles, per-agent model/runtime options, prompt management and provider tests in its web console. citeturn0search1turn0search2turn0search3turn0search6

Therefore ExitOne should treat CONFIG as an **Engagement Control Plane** with two clearly separated layers:

```
CONFIG
├── ENGAGEMENT
│   ├── Scope
│   ├── Rules of Engagement
│   ├── Objectives
│   ├── Constraints
│   ├── Environment
│   ├── Client Context
│   ├── Pentester Notes
│   ├── Assumptions
│   └── Known Unknowns
│
├── AI
│   ├── Providers
│   ├── Models
│   ├── Capability Routing
│   ├── Context Policy
│   ├── Fallbacks
│   └── Model Tests
│
├── INVESTIGATION
│   ├── Methodology
│   ├── Candidate Ranking
│   ├── Rabbit-hole Thresholds
│   ├── Ingestion / Parsers
│   └── Evidence Policy
│
├── INTERFACE
│   ├── TUI
│   ├── Capture
│   ├── Notifications
│   └── Report Preferences
│
└── SYSTEM
    ├── Storage
    ├── Logging
    ├── Diagnostics
    └── Security
```

### What ExitOne should borrow

**From Shannon:** make engagement context a first-class configuration object rather than forcing the operator to reconstruct it through environment variables or scattered files. Its current configuration explicitly includes authenticated testing, scope guidance, rules of engagement and report filtering. citeturn0search1

**From Strix:** separate LLM, context-window and runtime configuration, and use a provider abstraction rather than implementing every provider as a bespoke ExitOne subsystem. Strix currently uses LiteLLM's provider/model format and supports local OpenAI-compatible servers as well as many hosted providers. citeturn0search0turn0search6

**From PentAGI:** provider profiles should include per-agent/model/runtime configuration and provider test actions. This maps well to ExitOne's capability-oriented routing such as Extraction, Strategy and Report. citeturn0search3turn0search10

### What ExitOne should do differently

Do **not** copy a large server-admin settings console. ExitOne is local, terminal-native and investigation-centric.

The key object should be:

`EngagementProfile`

It should reference:

`Scope + ROE + Objectives + Constraints + Context + AI Policy + Investigation Policy + Report Policy`

A workspace/session then resolves an **Effective Configuration** from that profile plus explicit overrides.

### Effective Configuration

Every important setting should expose:

`value + source + scope + last_changed + safe provenance`

Example:

```
Strategy model       qwen-local-9b
Source               Workspace override
Context policy       Investigation-aware
Scope                10.10.10.0/24 + app.example.com
ROE                  Production-safe
Rabbit-hole threshold 3 low-yield attempts
```

This is more useful to a pentester than simply showing a collection of editable fields.

### AI Capability Router

Instead of configuring only a single "default LLM", define logical capabilities:

```
Extraction      → local fast model
Strategy        → reasoning model
Guide           → local/fast model
GraphRAG        → local model
Report          → stronger narrative model
Fallback        → secondary provider
```

The operator can change these mappings without changing the investigation itself. Shannon currently uses one model setting across the scan, while PentAGI supports more granular provider/agent configuration; ExitOne should adopt the latter concept but keep it tied to its smaller set of explicit cognitive capabilities. citeturn0search4turn0search10

### Context Policy Editor

Add a dedicated policy editor defining what each capability may consume:

```
Strategy:
  ✓ scope
  ✓ objectives
  ✓ evidence
  ✓ hypotheses
  ✓ previous attempts
  ✓ operator notes
  ✗ raw secrets by default
  ✗ unrelated workspace history

Report:
  ✓ validated findings
  ✓ provenance
  ✓ timeline
  ✓ selected operator context
  ✗ unresolved speculation as fact
```

This turns the user's request for "comments so the LLM has context" into a controlled architectural mechanism rather than a large prompt textbox.

### Engagement Templates

Add reusable local templates for common assessment types:

- Web/API;
- Internal network;
- Active Directory;
- External perimeter;
- Cloud;
- Mobile/API;
- AI application assessment;
- CTF/lab.

Templates should populate defaults for methodology and context, but **never silently change scope or authorization**.

### Import / Export

An EngagementProfile should be exportable as a sanitized configuration package so an engagement can be reproduced on another ExitOne installation without exporting investigation evidence or secrets.

Provide:

`export config --sanitized`

and a corresponding import workflow with validation and explicit confirmation.

### Configuration snapshots

Before a material configuration change, store a versioned snapshot. This allows ExitOne to answer:

> "Which configuration and model policy were active when this candidate was generated?"

That becomes particularly valuable for report reproducibility and research evaluation.

### Revised P-CONFIG priority

P-CONFIG should therefore be implemented in this order:

1. **EngagementProfile + Effective Configuration**
2. **Scope / ROE / constraints**
3. **Pentester context and notes**
4. **AI Capability Router**
5. **Context Policy**
6. **Provider/model CRUD and testing**
7. **Investigation policy controls**
8. **Interface/system settings**
9. **Versioning, snapshots and sanitized import/export**

This makes CONFIG a strategic part of ExitOne rather than a conventional settings menu.

### Definition of Done

P-CONFIG is complete when an operator can manage ExitOne's supported configuration entirely from CONFIG, maintain multiple AI providers/models, assign them to logical capabilities, safely test and activate configurations, disable or remove them, understand the effective configuration and reproduce which provider/model configuration influenced an investigation decision.

Configuration management remains separate from investigation evidence and must never provide a path for an LLM to execute shell commands or silently alter authoritative investigation state.


## P-VAULT — Sensitive Knowledge and Credential State

VAULT remains a first-class TUI surface. Its purpose is operational access to sensitive investigation knowledge; CONFIG governs the policies that control how that knowledge is handled.

The separation is:

CONFIG → SENSITIVE DATA POLICY → VAULT → INVESTIGATION STATE

Do not turn Vault into another Settings screen.

### Scope

Vault should manage sensitive objects such as:

- credentials;
- identities and account relationships;
- tokens;
- cookies/session artifacts;
- API keys;
- certificates/private keys where appropriate;
- discovered secrets;
- sensitive evidence references.

The current credential model already stores a secret, fingerprint, identity/service references, source reference and status. P-VAULT extends that model so status changes become provenance-bearing investigation events rather than unstructured metadata.

### Credential and identity state

Credential state must distinguish discovery from validation and compromise.

Recommended lifecycle:

DISCOVERED → EXPOSED → VALIDATED → COMPROMISED

Alternate states include INVALID, REVOKED, STALE and UNKNOWN.

| State | Meaning |
|---|---|
| DISCOVERED | A credential was identified in evidence, but its usability is unknown. |
| EXPOSED | The secret was exposed through an observed source. |
| VALIDATED | The credential was successfully validated for an allowed service/context. |
| COMPROMISED | Evidence demonstrates authenticated access using the credential. |
| INVALID | Evidence demonstrates that the credential does not work for the tested service/context. |
| REVOKED | Evidence demonstrates that the credential has been revoked or disabled. |
| STALE | The credential may have been valid previously but is no longer treated as current. |
| UNKNOWN | Available evidence is insufficient to establish a stronger state. |

The implementation must not require every credential to pass through every state.

### State transitions require provenance

Every authoritative state transition should be represented explicitly:

credential_status_transition
- credential_id
- from_status
- to_status
- actor
- source_type
- source_id
- reason
- confidence
- timestamp

Possible source types:

- MANUAL
- EVIDENCE
- ACTION_OUTCOME
- LLM_SUGGESTION
- SYSTEM

Critical invariant:

> LLM_SUGGESTION may propose a transition, but must never silently become an authoritative credential state.

### Human confirmation boundary

Example:

Potential state update

Credential: j.smith / password  
Evidence: SSH authentication succeeded  
Suggested state: COMPROMISED  
Confidence: 0.97

[Mark compromised] [Dismiss]

The operator explicitly confirms the transition.

This preserves ExitOne's existing boundary:

LLM → proposes  
Human → decides  
ExitOne → records

Automated evidence processing may create a proposed transition, but authoritative state mutation must follow the configured policy and remain auditable.

### Reveal

Reveal is an explicit Vault operation for temporarily displaying a secret.

Rules:

- it must never change credential compromise state;
- it should create a secret_revealed audit event;
- the revealed value must remain excluded from ordinary logs and reports;
- prompts should receive masked values by default;
- Reveal should be subject to the configured sensitive-data policy;
- the operator should be able to trace when and why a secret was revealed without storing the secret itself in the audit record.

Therefore:

REVEAL ≠ VALIDATE ≠ COMPROMISE

### Mark compromised

The operator should be able to manually mark a credential as compromised when engagement evidence supports that conclusion.

The transition must record previous state, new state, operator/session, timestamp, reason, supporting evidence/action/outcome reference and confidence where applicable.

Example:

DISCOVERED
  ↓
MARK COMPROMISED
  ↓
CredentialStatusChanged
  previous = discovered
  new = compromised
  actor = operator
  source = manual
  reason = "Successful authenticated access"
  evidence = EVD-0312

### Evidence-driven proposal

ExitOne should also detect when an action outcome provides strong evidence for a state transition.

Authentication action
  ↓
successful authentication
  ↓
ActionOutcome
  ↓
proposed credential transition
  ↓
operator confirmation
  ↓
COMPROMISED

This should be implemented as a deterministic evidence-to-proposal rule before relying on an LLM to infer the transition. The LLM can then explain the proposal, identify supporting evidence, or point out contradictions.

### Identity state

Identity and credential state should remain related but not conflated.

Example:

Identity: j.smith
- password → COMPROMISED
- SSH key → DISCOVERED
- API token → REVOKED

Do not automatically mark an entire identity COMPROMISED merely because one credential is compromised. Identity-level status should be defined separately and backed by relevant evidence.

### Investigation Graph integration

Credential state changes should create or update graph relationships:

Identity j.smith
  ├── HAS_CREDENTIAL → password
  ├── DISCOVERED_BY → Evidence EVD-0182
  ├── VALIDATED_BY → SSH authentication
  └── GRANTS_ACCESS_TO → Host 10.10.10.25

This makes Vault state useful to Strategy, Hypotheses and Reporting rather than treating Vault as isolated storage.

### Hypothesis reopening

Credential state changes must participate in ExitOne's temporal investigation model.

Example:

Hypothesis H-021: "SSH does not provide a viable access path."
Status: REFUTED / CLOSED

Later:
j.smith credential discovered
  ↓
credential validated
  ↓
SSH authentication succeeds
  ↓
H-021 becomes stale/incomplete
  ↓
REOPEN / REPLAN

Reopening should be structural: the new observation/action outcome changes an assumption or contradicts the prior conclusion. Do not reopen hypotheses merely because a credential entity of some type appeared.

### Strategy integration

Credential state becomes a context feature for candidate generation.

j.smith password = COMPROMISED  
SSH service = exposed  
Previous SSH test = admin failed  
  ↓
Context Resolver
  ↓
Strategy
  ↓
identity-specific authentication coverage

Candidate basis should retain the credential/identity state references that caused the candidate to become relevant.

### Report integration

Reports should consume authoritative Vault state without exposing secrets.

Example:

Compromised identities

j.smith
- Credential type: Password
- Validation: SSH
- Target: 10.10.10.25
- Evidence: EVD-0312
- Status: Compromised

A report statement should be traceable:

Finding → Credential → Identity → Evidence → Action → Outcome

The report must distinguish credential discovered, exposed, validated, authenticated access demonstrated, invalid/revoked/stale and unresolved states.

Secrets remain masked unless the engagement/report policy explicitly defines otherwise.

### LLM exposure policy

The LLM should normally receive credential metadata, not secret values.

Allowed by default:
- identity = j.smith
- credential_type = password
- status = compromised
- service = ssh
- evidence = EVD-0312

Denied by default:
- password = <secret>
- token = <secret>
- cookie = <secret>

A capability-specific policy may permit controlled secret access for a future workflow, but that must be explicit and auditable.

### Vault UI

Recommended actions:

VAULT
────────────────────────────────
j.smith
Password
Status: COMPROMISED
Source: EVD-0182

[R] Reveal
[M] Mark compromised
[V] Validate
[I] Mark invalid
[T] Trace
[H] History

The UI should show status, confidence, source, related identity/service, supporting evidence, last validation, state history and provenance. The secret remains masked.

### State history

Do not overwrite status without preserving history.

Example:

j.smith / password

10:32  DISCOVERED
       source: smb output

10:41  VALIDATED
       source: SSH authentication
       evidence: EVD-0312

10:41  COMPROMISED
       actor: operator
       reason: authenticated access demonstrated

11:55  STALE
       source: credential validation
       evidence: EVD-0441

This temporal history is important for report reproducibility and for understanding why a strategy was valid at a particular point in the engagement.

### Security invariants

1. Reveal never implies compromise.
2. Discovery never implies validity.
3. LLM suggestion never silently becomes authoritative state.
4. Every authoritative state transition has provenance.
5. Credential state changes can affect hypotheses and strategy only through traceable investigation state.
6. Reports consume Vault state but never require raw secrets.
7. Raw secrets remain masked in normal LLM context, logs, telemetry and exports.
8. A later state change must not erase the historical state that influenced an earlier decision.

### Schema direction

The current credential.status field should evolve from a simple mutable status into a current-state projection backed by transition history.

Conceptual model:

credential
  - current_status
  - secret_fingerprint
  - identity_entity_id
  - service_entity_id
  - source_ref

credential_status_transition
  - credential_id
  - from_status
  - to_status
  - actor
  - source_type
  - source_id
  - reason
  - confidence
  - created_at

Existing credential_attempt remains useful as service-validation history, while status transitions provide the authoritative lifecycle audit.

### P-VAULT priority

1. State model and transition history
2. Manual Reveal / Mark compromised / Mark invalid
3. Deterministic evidence-driven transition proposals
4. Identity/credential graph integration
5. Hypothesis reopening integration
6. Strategy/context integration
7. Report integration
8. Capability-specific LLM exposure policy
9. Vault history and advanced audit UX

### Definition of Done

P-VAULT is complete when:

- a pentester can inspect credentials without exposing secrets by default;
- Reveal is explicit, auditable and never changes compromise state;
- credentials have a provenance-backed lifecycle;
- the operator can mark a credential compromised or invalid;
- strong authentication outcomes can produce state-transition proposals;
- LLMs can reason over credential metadata without receiving raw secrets by default;
- credential state changes are visible to hypotheses and strategy;
- prior conclusions can be reopened when a new credential invalidates their assumptions;
- reports can document credential exposure/validation/compromise with evidence references while masking secrets;
- historical state remains reconstructable.

## P-FINAL — Live Investigation Report,,This is intentionally the **last product priority**. Reporting should consume the investigation model rather than becoming another source of truth.,,### Objective,,Add a dedicated **REPORT** tab to the TUI that continuously builds the final engagement report from the authoritative investigation state while the pentest is happening.,,The operator should be able to open the report at any point and see what the final deliverable would look like **right now**, without waiting for the engagement to finish.,,### Live report tab,,The new tab should present a continuously updated report draft with sections such as:,,- Executive Summary;,- Scope and Rules of Engagement;,- Attack Surface / Assets;,- Methodology and Coverage;,- Findings;,- Evidence and provenance;,- Validation / Exploitation evidence;,- Credentials and access obtained, with secrets masked by default;,- Attack paths / relationships;,- Timeline of relevant investigation events;,- Hypotheses tested and their final status;,- Actions performed and important failed attempts;,- Risk/impact context;,- Recommendations / remediation;,- Limitations and unresolved questions;,- Appendix / technical evidence references.,,The report should distinguish **confirmed findings**, **observations**, **hypotheses**, **operator notes** and **unresolved items**. A generated narrative must never silently turn an inference into a confirmed finding.,,### Real-time generation model,,Use the existing investigation state as the source of truth:,,`Event → Evidence → Observation → Entity/Relationship → Objective/Hypothesis → Action → Outcome → Report Section`,,Report generation should be incremental. A new validated observation should update only the affected report sections rather than regenerating the entire document unnecessarily.,,LLM narration may improve readability, executive summaries and technical explanations, but deterministic state and provenance must remain authoritative.,,### Export,,The operator should be able to export the current report at any moment and export the final version when the engagement is complete.,,Minimum export targets:,,- Markdown;,- HTML;,- PDF;,- JSON/structured report data for machine processing.,,Exported reports should include a generation timestamp and investigation/session identifier, preserve evidence references, and clearly identify sections that are incomplete or based on unresolved hypotheses.,,### Finalization,,Provide an explicit report finalization action that creates a stable report snapshot. After finalization, subsequent investigation changes should not silently modify that exported snapshot.,,Example workflow:,,```text,REPORT,  Live draft,      ↓,  Operator reviews,      ↓,  Export now (optional),      ↓,  Investigation continues,      ↓,  Finalize report,      ↓,  Immutable report snapshot,```,,### Pentester UX,,The report tab should not interrupt the terminal workflow. It should support:,,- live refresh;,- section navigation;,- finding/evidence drill-down;,- jump from a report statement to its provenance;,- visible incomplete/unresolved sections;,- export without ending the session;,- finalization only when the operator chooses it.,,### Definition of Done,,P-FINAL is complete when a pentester can start an engagement, work normally in the terminal, open REPORT at any point, see a coherent report generated from the current investigation state, trace statements back to evidence, export an intermediate version, continue working, and finally produce a stable final report without manually reconstructing the engagement history.,
## Most defensible positioning

Avoid:

> "ExitOne is the first AI pentest tool with memory/context/graphs."

Use:

> "ExitOne models security research as a persistent investigation state: it records what happened, what evidence supports each conclusion, what was already tested, what changed, and why a new investigative direction became relevant."

And the strongest technical claim is:

> "The core unit of reasoning is not the prompt or the exploit. It is the state transition of the investigation."

## External repositories audited

- Strix — `usestrix/strix`
- Shannon — `KeygraphHQ/shannon`
- PentAGI — `vxcontrol/pentagi`
- PentestGPT — `GreyDGL/PentestGPT`
- CAI — `aliasrobotics/cai`

The audit intentionally treats README claims and repository search results as evidence of architecture direction, not proof that every advertised feature is implemented at the same maturity level.
