# Suppression Window & Blocklist

Keep a small amount of persistent state in SQLite so the agent does not re-alert on the same problem every tick, and let the operator silence known-noisy flows through a Blocklist in `config.yaml`. Both checks run in code before enrichment and the LLM call, so a suppressed or blocklisted Anomaly costs no Nexla read calls and no LLM spend. See [ADR-0004](../../../docs/adr/0004-sqlite-state-suppression-window.md).

This introduces the **Repositories** layer (the only code that touches SQLite); detection stays deterministic and the agent never acts on a flow.

Acceptance:

- A new `repositories/suppression_repository.py` stores one row per emitted Alert (`flow_id`, `anomaly_type`, `alerted_at`, `suppressed_until`) and answers `is_suppressed(flow_id, anomaly_type, now)` from an indexed lookup.
- After an Alert is emitted, the same `(flow_id, anomaly_type)` is suppressed for `monitoring.suppression_window_hours` (default 2h); once the window elapses, it may alert again.
- Flows listed in `blocklist:` in `config.yaml` never produce an Alert.
- Suppression keys on `flow_id`; an Anomaly with no resolved `flow_id` is not suppressed by this layer (Explicit Failures in that state are still deduped by Nexla's notification `read` flag).
- A persistently RED flow returned by the org health sweep on consecutive ticks alerts only once within the window.
- The SQLite file persists across container restarts via a Docker volume; the suppression module never touches SQLite directly — the repository is injected.
