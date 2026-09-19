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
