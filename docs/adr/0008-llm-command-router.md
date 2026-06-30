# The LLM routes user commands; a deterministic parser is the fallback

When an operator types a plain-language request (terminal `--ask`/`--chat`, and later Slack), the message is sent to the LLM with a catalog of the agent's behaviors as tools. The LLM picks one tool to run — scan a flow, scan the org, list a flow's latest runs, or manage continuous monitoring — and code executes it. If the LLM is unavailable, returns an unknown tool, or gives unusable arguments, routing degrades to the deterministic `parse_intent` (`src/modules/controls/intent.py`) so the terminal keeps working offline and cheaply. This mirrors the `classify_anomaly` fail-safe: the LLM is an enhancement, never a hard dependency.

This is the first place the LLM decides *control flow* rather than only filling a field. It does **not** change two earlier decisions:

- **Detection stays deterministic** ([ADR-0002](0002-deterministic-detection-llm-classification.md)). The LLM routes a human's explicit command; it does not decide what counts as an Anomaly. The scans it triggers still detect with code.
- **No write power** ([ADR-0001](0001-read-only-agent.md), [ADR-0007](0007-supervised-slack-flow-controls.md)). `pause`/`activate` are deliberately absent from the tool catalog (`src/modules/controls/router_tools.py`); they remain behind the human-confirmation button. A test asserts the catalog contains only the four read-only/supervised-safe tools.

The router runs **one tool per message** (no multi-step loop), and the tool layer is injected with the existing behavior callbacks (like `SlackCommandExecutor`), so `modules/controls` never imports `monitor` and the same core serves the terminal now and Slack later.

**Consequence**: each routed message costs one LLM call when routing is enabled (`router.enabled`, default true). A wrong tool choice is bounded — it can only run a read-only/supervised behavior, and bad/unknown choices fall back to the deterministic parser. The richer agentic direction (the LLM chaining read-only investigation tools to diagnose one Anomaly) is tracked separately in `.specs/agentic-investigation-roadmap.md` (proposed ADR-0009).
