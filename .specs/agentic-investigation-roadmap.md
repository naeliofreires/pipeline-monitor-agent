# Agentic Investigation Roadmap

| Field        | Value                                                        |
| ------------ | ----------------------------------------------------------- |
| Author       | @naelio.freires                                             |
| Status       | Proposed                                                    |
| Created      | 2026-06-30                                                  |
| Drives       | ADR-0009 (proposed) — give the LLM read-only investigation tools |
| Builds on    | [anomaly-enrichment-roadmap](anomaly-enrichment-roadmap.md) |
| Glossary     | [CONTEXT.md](../CONTEXT.md)                                  |
| Supersedes   | The fixed `enrich → classify` step, for the investigation path only |

## Why this roadmap exists

After the enrichment roadmap, the agent is a solid **Level 2** triager: code
gathers a fixed bundle of Evidence (`enrich_anomaly`,
`src/modules/enrichment/enricher.py:190`) and the LLM classifies over it once
(`classify_anomaly`, `src/modules/classification/classifier.py`). The LLM has no
say in *what* gets gathered — it fills in `risk` / `explanation` /
`recommended_action` and nothing more.

That is the single non-agentic seam in the system. Every read the LLM might want
already exists on the adapter, but the model can't reach for them: a volume drop
and a RED flow both get the same fixed enrichment, even though they want
different evidence. A volume drop wants `get_run_metrics` and run-summary
history; a RED flow wants `get_flow_error_logs` first.

This roadmap turns the **investigation** into a tool-calling loop: the LLM is
given the read-only adapter verbs as tools and decides which to call, in what
order, until it can classify. It is the smallest change that gives the LLM real
agency — and it does so **without** touching detection or granting any write
power.

## What stays off the table (deliberately)

This roadmap gives the LLM agency over **investigation only**. It does **not**:

- Touch detection. Code still decides what counts as an Anomaly
  ([ADR-0002](../docs/adr/0002-deterministic-detection-llm-classification.md)).
  A hallucination still cannot invent or hide a failure.
- Expose any write verb. `pause_flow` / `activate_flow` are **never** registered
  as tools; they stay behind human Slack confirmation
  ([ADR-0007](../docs/adr/0007-supervised-slack-flow-controls.md),
  [ADR-0001](../docs/adr/0001-read-only-agent.md)).
- Advance the agent toward Levels 4–5 (action). It deepens Level 2/3 *triage
  quality* by making the evidence-gathering adaptive.

## Project rules these plans follow

From `docs/tdd.md`, the enrichment roadmap, and the existing code:

- **Adapters** are the only place that talks to an external service. The new
  tools wrap existing read-only `NexlaAdapter` methods; no new SDK surface.
- **Modules** hold business logic. The tool registry and the investigation
  orchestration are modules; they use the injected adapter, never `import
  nexla_sdk`.
- **Detection stays deterministic; the LLM runs only after code finds a problem**
  ([ADR-0002](../docs/adr/0002-deterministic-detection-llm-classification.md)).
- **The agent never acts on a flow**
  ([ADR-0001](../docs/adr/0001-read-only-agent.md)). Every registered tool is
  read-only.
- **Redact before the LLM sees it**
  ([ADR-0006](../docs/adr/0006-redact-error-text-before-alert-and-llm.md)). Tool
  outputs pass through `redact()` before re-entering the prompt, same as
  `_payload` does today.
- **Never drop an Anomaly.** If the loop fails or exhausts its step budget, a
  real detected Anomaly fails safe to `high` (mirroring `uncertain → high` and
  the `HIGH_RISK_FALLBACK_TYPES` rule in `classifier.py`), still produces an
  Alert, and the Alert still carries the raw message.

## Glossary additions (update `CONTEXT.md`)

- **Investigation**: the tool-calling step where the LLM, given read-only flow
  tools, decides which reads to make to gather Evidence before it classifies an
  Anomaly. Replaces the fixed Enrichment step on this path. _Avoid_: agent loop,
  ReAct, reasoning.
- **Tool**: a single read-only flow read (e.g. `get_flow_health`,
  `get_error_logs`) exposed to the LLM with a JSON schema and bound to one
  `flow_id`. _Avoid_: function, capability, action (reserved for write verbs).
- **Step Budget**: the maximum number of tool-calling rounds the LLM may take in
  one Investigation before it must classify or fail safe. _Avoid_: max iterations,
  loop limit.

---

## Sequencing

```
AI-1 (tool registry)  ──►  AI-2 (tool-calling loop in adapters)  ──►  AI-3 (investigation module)  ──►  AI-4 (wire into monitor)
        │                                                                      │
        └──────────────────────────────────────────────────────────────────► AI-5 (guardrails) closes each item
AI-0 (docs/glossary + ADR-0009) runs alongside; AI-6 (tests/validation) closes each item.
```

AI-1 unblocks everything: the loop (AI-2) and the module (AI-3) both depend on a
registry that maps tool names → bound read-only handlers + schemas. AI-5 is not a
phase but a checklist applied to AI-2 and AI-3.

---

## AI-0 — ADR and docs (run alongside)

**Why.** Giving the LLM agency over investigation is a real trade-off — it costs
more tokens and more latency per Anomaly than a fixed bundle, in exchange for
adaptive, cheaper-to-extend evidence gathering. That decision deserves an ADR
before code, in the spirit of ADR-0002/0003.

**How.**
- Write **ADR-0009**: "Give the LLM read-only investigation tools." Record the
  trade-off (adaptive evidence + easy to add a new read as a tool, vs. token/latency
  cost and a non-deterministic number of SDK calls per tick), and state plainly
  that detection and write power are untouched. Mark it `Proposed` until AI-4 lands.
- Add the *Investigation*, *Tool*, and *Step Budget* terms to `CONTEXT.md`.
- Update the `docs/tdd.md` data-flow diagram: the fixed `enrich → classify` box
  becomes a single `investigate` box driven by the LLM + read-only tools.

**Acceptance.** ADR-0009 exists and is referenced from this roadmap and the TDD;
CONTEXT.md carries the three new terms.

---

## AI-1 — Read-only tool registry

**Why.** The loop needs a single place that maps a tool name to (a) a JSON schema
the LLM sees and (b) a handler bound to one `flow_id` that calls the existing
adapter method and redacts the result. Centralizing it keeps the allowlist of
*what the LLM can reach* in one auditable spot.

**How.**
- New module `src/modules/investigation/tools.py` exposing
  `build_tool_registry(nexla_adapter, flow_id) -> (handlers, schemas)`.
- Register only these existing **read-only** `NexlaAdapter` methods, each wrapped
  so the output passes through `redact()` before it can return to the prompt:
  - `get_flow_health(flow_id)` (`nexla_adapter.py:179`)
  - `get_run_status(flow_id, run_id)` (`nexla_adapter.py:207`)
  - `get_flow_error_logs(flow_id, run_id, limit)` (`nexla_adapter.py:215`)
  - `get_run_metrics(...)` (`nexla_adapter.py:225`)
  - `get_run_summary(...)` (`nexla_adapter.py:270`)
  - `get_flow(flow_id)` (`nexla_adapter.py:121`)
- Each schema declares its parameters (e.g. `get_error_logs` takes `run_id` and
  optional `limit`); tools that need no args declare an empty object.
- A handler that raises returns a structured `{"error": "..."}` to the model
  rather than crashing the loop, so the LLM can try another read.

**Acceptance.**
- The registry exposes **only** the six read-only verbs above — no `pause_flow` /
  `activate_flow`, asserted by a test.
- Every handler is bound to the one `flow_id` it was built for and redacts its
  output.
- A failing handler yields `{"error": ...}`, never an exception out of the registry.

---

## AI-2 — Tool-calling loop in the LLM adapters

**Why.** The adapter is the only layer allowed to talk to the LLM service. The
loop — send messages, receive tool calls, execute handlers, feed results back,
repeat until the model emits a final verdict — lives here, alongside the existing
`classify_anomaly`.

**How.**
- Add `investigate_anomaly(anomaly_seed, handlers, schemas, max_steps=6) -> dict`
  to `OpenAIAdapter` (`src/adapters/openai_adapter.py:32`) and, for provider
  parity, to `OpencodeAdapter`.
- Loop: call the chat completion with `tools=schemas, tool_choice="auto"`; if the
  response has no tool calls, parse and return its JSON verdict
  (`risk_classification`, `explanation`, `recommended_action`) — the **same
  contract** `classify_anomaly` returns today, so nothing downstream changes. If
  it has tool calls, run each handler, append the (redacted) results as `tool`
  messages, and continue.
- A new `NEXLA_ANOMALY_INVESTIGATION_PROMPT` instructs the model: use the tools
  to gather evidence, cite the specific run status / errors / counts it found in
  `explanation`, base `recommended_action` on them, and emit the strict JSON
  verdict when done.
- **Step Budget**: if the loop reaches `max_steps` without a final verdict, return
  the high-risk fail-safe verdict (`risk_classification="high"`, a "did not
  converge" explanation, `SAFE_RECOMMENDED_ACTION`). The loop is never unbounded.

**Acceptance.**
- A flow whose first tool result already explains the failure terminates in one
  round; a flow needing health → run-status → logs terminates in three.
- Exhausting `max_steps` returns the high fail-safe verdict, never raises.
- The returned dict matches the existing classifier contract exactly.
- Both adapters expose `investigate_anomaly`.

---

## AI-3 — The Investigation module

**Why.** Choosing the investigation path, building the registry, seeding the loop,
and mapping its verdict onto a `ClassificationResult` is orchestration — business
logic, so it lives in a module, mirroring how `classify_anomaly` wraps the raw
adapter call.

**How.**
- New module `src/modules/investigation/investigator.py` exposing
  `investigate_anomaly(anomaly, nexla_adapter, llm_adapter) -> ClassificationResult`
  (reuse the existing `ClassificationResult` dataclass from `classifier.py`).
- Flow: if `anomaly.flow_id is None`, skip the loop and return the existing
  message-only fallback (`classifier._fallback`) — no tools to bind. Otherwise
  build the registry (AI-1), assemble the seed payload from the Anomaly fields
  (same redaction as `_payload`), run `llm_adapter.investigate_anomaly(...)`, and
  map the verdict to `ClassificationResult`, applying the `uncertain → high` and
  invalid-verdict-→-fallback rules already in `classifier.py`.
- Define an `AnomalyInvestigator` Protocol for the adapter dependency, mirroring
  the `AnomalyClassifier` Protocol pattern.
- The module does not `import nexla_sdk`; it uses only the injected adapter.

**Acceptance.**
- An Anomaly with `flow_id=None` returns the message-only fallback without calling
  the loop.
- An invalid / failed loop verdict for a real Anomaly returns `high` + raw message
  + safe action (parity with `classifier._fallback`).
- No `import nexla_sdk` in the module.

---

## AI-4 — Wire investigation into `monitor_once`

**Why.** The investigation is worthless if the pipeline still calls the fixed
`enrich → classify` pair. This is the switch-over.

**How.**
- In `monitor_once` (`src/monitor.py`), replace the `enrich_anomaly(...)` +
  `classify_anomaly(...)` pair on each Anomaly with a single
  `investigate_anomaly(anomaly, nexla_adapter, llm_adapter)` call. Suppression,
  alert building, and mark-read are unchanged — they consume the same
  `ClassificationResult`.
- Keep the deterministic enricher in the tree behind a config flag
  (`investigation.enabled`, default off) so the fixed path remains the safe
  default and the loop can be A/B'd against it before becoming the default.
- The Alert text (`src/modules/alerting/alert.py`) is unchanged: it already renders
  `risk` / `explanation` / `recommended_action`.

**Acceptance.**
- With `investigation.enabled: true`, a detected Anomaly is triaged via the loop
  and produces an Alert identical in shape to today's.
- With the flag off (default), behavior is byte-for-byte the current fixed path.
- No flow action method is reachable from the investigation path (sentinel test).

---

## AI-5 — Guardrails (checklist applied to AI-2 and AI-3)

Not a phase — the invariants every reviewer checks on the loop:

- **Read-only allowlist.** The registry can only ever contain the six read verbs;
  a test asserts `pause_flow` / `activate_flow` are absent.
- **Bounded loop.** `max_steps` caps tool rounds; exhaustion → high fail-safe.
- **Redaction.** Every tool output is redacted before re-entering the prompt.
- **Never drop an Anomaly.** Any failure degrades to the message-only fallback (or
  high fail-safe for a real Anomaly), still alerting.
- **Cost visibility.** Log the tool-call count and step count per Investigation at
  `DEBUG`, so a runaway prompt is observable, not silent.

---

## AI-6 — Tests & validation (run alongside)

Mirror the existing convention (`tests/test_*` + `.specs/features/<name>/`):

- Unit: registry exposes only read verbs and binds `flow_id`; loop terminates in
  N rounds with a mocked tool-calling client; loop exhaustion returns high
  fail-safe; investigator fallback on `flow_id=None` and on invalid verdict.
- Integration: `monitor_once` with `investigation.enabled` on and a mocked Nexla
  adapter — full path detect → investigate → suppress → alert → mark-read, plus a
  `ForbiddenFlows` sentinel proving no flow action is ever called inside the loop.
- A `spec.md` + evidence-based `validation.md` under
  `.specs/features/agentic-investigation/`, matching `explicit-failure-alert`.
- Gates: `PYTHONPATH=src python -m unittest discover -s tests` and
  `PYTHONPATH=src python -m compileall src tests` must pass.

---

## What level the agent reaches after this roadmap

Using the maturity scale from
[anomaly-enrichment-roadmap](anomaly-enrichment-roadmap.md):

| Level | Name | This roadmap |
| ----- | ---- | ------------ |
| 1 | Reactive relay | — |
| 2 | Evidence-grounded triage | **Deepened** — evidence is now gathered adaptively per Anomaly, not from a fixed bundle. |
| 3 | Proactive detection | Unaffected (detection stays code). |
| 4 | Supervised action | Still blocked by ADR-0001/0007. |
| 5 | Autonomous remediation | Out of scope. |

This roadmap does **not** move the agent up a level — it makes it genuinely
*agentic within Level 2*. It is the first place the LLM drives its own control
flow rather than filling a template. That is the architectural milestone: the
system goes from "LLM as a classification field" to "LLM as an investigator,"
while detection and action stay exactly where ADR-0001 and ADR-0002 put them.

**Next, if this proves out:** the same tool-calling seam is what a future Level 4
would extend — by adding *write* tools behind the existing Slack confirmation
gate. This roadmap deliberately stops short of that; it earns the right to
consider it by first proving the loop is bounded, redacted, and read-only.
