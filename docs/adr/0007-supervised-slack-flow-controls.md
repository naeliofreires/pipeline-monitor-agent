# ADR 0007: Supervised Slack Flow Controls

## Status

Accepted

## Decision

ADR 0001 remains true for autonomous behavior: monitor detection, enrichment, and LLM classification must not mutate Nexla Flows. This ADR narrowly permits only verified, authorized, user-initiated Slack controls.

Pause/activate controls are disabled by default, require Slack signature verification, authorized users, allowed actions, and non-protected Flows.

The preferred production setup is a separate `nexla.control_service_key`, so the monitoring `nexla.service_key` can remain read-only. For the current prototype, if `nexla.control_service_key` is empty, the controls path temporarily falls back to `nexla.service_key`.

## Consequences

Slack interaction requests enqueue mutations for background execution and return quickly. Accepted, denied, no-op, and failed attempts are audited without persisting raw Slack payloads or response URLs.

This fallback is a known security gap: the same Nexla key may be used by both the automatic monitor and the supervised control path. Before production use, create a separate control service key and keep the monitor key read-only.
