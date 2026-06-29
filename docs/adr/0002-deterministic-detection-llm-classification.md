# Code detects problems; LLM classifies and explains

The agent uses regular code to find anomalies — it checks Nexla's `read` flag for Explicit Failures and compares volume numbers for Silent Failures (a drop of 40% or more vs the same window yesterday). The LLM is only called after code has already found a problem — to say how serious it is and to write the explanation in plain language.

The original plan was to send all flow data to the LLM every cycle and let it decide what looked wrong. We dropped this because it gets expensive and slow as the number of flows grows. A flow with `status == 'failed'` does not need AI to be spotted.

**Consequence**: how well the agent finds Silent Failures depends on the volume threshold setting. Flows that naturally vary a lot may trigger false alerts — this is the trade-off we accepted to keep the LLM out of the detection step.

**Update**: [ADR-0003](0003-enrich-anomalies-before-classification.md) adds a deterministic enrichment step between detection and classification. It does not change this decision — the LLM is still called only after code finds a problem — it just gathers flow health, run status, and error logs (in code) so the LLM classifies over real evidence instead of the notification message alone.
