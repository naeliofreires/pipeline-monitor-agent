# TDD - Pipeline Monitoring Agent

| Field          | Value                                  |
| -------------- | -------------------------------------- |
| Tech Lead      | @naelio.freires                        |
| Team           | Data Engineering                       |
| Status         | Draft — implementation started         |
| Created        | 2026-06-26                             |
| Last updated   | 2026-06-29                             |
| ADRs           | [0001](../docs/adr/0001-read-only-agent.md) · [0002](../docs/adr/0002-deterministic-detection-llm-classification.md) · [0003](../docs/adr/0003-enrich-anomalies-before-classification.md) · [0004](../docs/adr/0004-sqlite-state-suppression-window.md) · [0005](../docs/adr/0005-silent-failure-volume-detection.md) · [0006](../docs/adr/0006-redact-error-text-before-alert-and-llm.md) · [0007](../docs/adr/0007-supervised-slack-flow-controls.md) |
| Glossary       | [CONTEXT.md](../CONTEXT.md)           |

---

## Context

Nexla manages data pipelines called flows. Each flow moves and transforms data from a source to a destination. When a flow breaks or slows down without making noise, the operator has to rely on Nexla's built-in alerts — but those only catch hard failures. They do not detect when a flow is still running but processing far less data than usual.

Right now there is no single place to see the health of all flows at once. There are also no plain-language explanations of what went wrong or what to do next. Finding the cause of a problem means opening the Nexla UI, reading logs, and checking metrics across different screens by hand.

## Problem Statement

- **Silent failures go unnoticed**: A flow that processes 95% fewer records than yesterday does not trigger any alert. The problem only shows up later when downstream data is out of date.
- **Built-in alerts do not explain**: Nexla tells you a flow failed, but not why it likely failed or what you should do about it.
- **Context is scattered**: Diagnosing a flow means switching between notifications, audit logs, and metrics tabs in the UI.

### Why now?

The number of flows to monitor keeps growing and checking them by hand does not scale. A single operator cannot regularly check dozens of flows while doing everything else they need to do.

### Impact of not solving this

- Stale data reaches downstream systems without any warning
- Silent failures can go undetected for hours or even days
- Operators spend time diagnosing problems that the agent could have already explained

---

## Scope

### 🚀 MVP — Demo (5 days)

The first goal is a working end-to-end demo. One detection type, one alert channel, no persistent state beyond Nexla's own `read` flag.

- Detect **Explicit Failures** from unread Nexla SDK notifications
- Mark notifications as `read` after processing (basic dedup via Nexla's own flag)
- Classify risk using the LLM (`low` / `high` / `uncertain`)
- Generate a plain-language explanation and a Recommended Action using the LLM
- Print an Alert to the console during development
- Run as a Docker container on a local machine

### Current Implementation State

Implemented now:

- Python package skeleton with `main.py`, `monitor.py`, adapters, and module folders
- CLI entrypoint with `--config`, `--smoke nexla`, and `--smoke slack`
- Config loading with environment-variable expansion
- APScheduler loop that calls `monitor_once()` every 300 seconds
- Nexla adapter smoke probe using `flows.list()`
- Dockerfile and Docker Compose local runner
- Alert delivery seam (`AlertSender`) with console output as the default destination
- Optional Slack bot delivery (`SlackBotAlertSender`) using Slack `chat.postMessage` via Python stdlib `urllib`; no Slack SDK dependency
- Slack delivery is opt-in through `config.yaml` (`slack.enabled`, `slack.bot_token`, `slack.channel_id`) and falls back to console when disabled or incomplete
- Slack smoke probe sends one safe test message to the configured channel; verified with real bot token/channel configuration
- Explicit Failure detection from unread Nexla notifications
- Marking processed Nexla notifications as `read`
- opencode.ai Zen adapter for LLM classification/explanation
- Classifier fallback behavior: invalid/failed LLM responses still produce an Alert with `risk_classification: "unknown"`
- `uncertain` LLM risk is normalized to `high`
- Alert formatting with Risk Classification, plain-language explanation, and Recommended Action
- Full Explicit Failure loop wired in `monitor_once()`: fetch unread notifications → detect anomalies → classify → send Alert via configured sender → mark read
- Enrichment before classification with flow health, latest run status, per-run metrics, optional run-summary trends, and ERROR log checks across the latest/recent runs
- Org health sweep for RED flows, deduped against notification anomalies
- Repositories layer with SQLite Suppression Window (`repositories/suppression_repository.py`)
- Suppression module: per-`(flow_id, anomaly_type)` window and `config.yaml` Blocklist, checked before enrichment and the LLM call
- Silent Failure detection: day-over-day per-flow volume comparison (`modules/detection/silent_failure.py`), org-health volume read (`adapters/nexla_adapter.py::list_flow_volumes`), and the metric-snapshot repository (`repositories/snapshot_repository.py`)
- Per-flow volume threshold overrides and `min_baseline_records` guard in `config.yaml`
- Redaction of credentials / connection strings in error text before the Alert and the LLM payload (`modules/redaction.py`)
- Unit tests and feature validation for the Explicit Failure alert path, alert sender seam, Slack smoke path, Suppression Window / Blocklist, Silent Failure detection, and redaction

Not implemented yet:

- Docker Compose end-to-end run with real Nexla and opencode.ai credentials
- Controlled real-alert monitor tick with Slack enabled
- Intra-day (hourly) volume windows and a rolling multi-day baseline (v1 uses day-over-day)
- Broader test coverage beyond the alert, suppression, and Silent Failure paths

### ✅ In Scope (v1 — after demo)

Everything in the MVP, plus:

- Detect **Silent Failures** by comparing volume in the current time window vs the same window yesterday (threshold: -40%)
- Block repeated alerts for the same issue for 2 hours (Suppression Window)
- Track seen problems using a local SQLite database
- Support a Blocklist of flows that should never trigger alerts
- Allow the volume threshold to be set per flow via `config.yaml`

### ❌ Out of Scope (v1)

- Automatic actions on flows (`flows.pause()`, `flows.activate()`) — the automatic monitor only watches and reports; supervised, user-initiated Slack controls are the ADR 0007 exception, preferably with a separate service key
- Instatus integration (status page) — planned for v2, after checking detection quality
- Email alerts — console and optional Slack bot delivery are enough during development
- Web interface or dashboard
- Multi-tenant support (multiple Nexla accounts)
- Escalating alerts to different channels over time
- Historical volume baseline using a rolling average (needs 7+ days of data)

### 🔮 Future (v2+)

- Supervised Slack flow controls where the operator explicitly initiates the control action (ADR 0007)
- Instatus integration to open and close incidents automatically
- Escalating from console output to PagerDuty after X hours without resolution

---

## Technical Solution

### Overview

A Python service running inside a Docker container. It checks for problems every 5 minutes. Detection is done by code: unread Nexla notifications for hard failures, volume comparison for quiet ones, and an org health sweep for RED flows without an already-processed Nexla notification. The LLM is only called after a problem is found — to classify how serious it is and to write the Alert explanation.

### Target Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Docker Container                                                │
│                                                                  │
│  ┌──────────────┐    tick/5min    ┌────────────────────────┐    │
│  │ APScheduler  │ ─────────────► │   Monitoring Loop      │    │
│  └──────────────┘                └───────────┬────────────┘    │
│                                              │                  │
│                              ┌───────────────┼──────────────┐  │
│                              ▼               ▼              ▼  │
│                    ┌──────────────┐  ┌──────────────┐          │
│                    │  Nexla SDK   │  │  Nexla SDK   │          │
│                    │ notifications│  │    metrics   │          │
│                    │  .list()     │  │ .get_daily() │          │
│                    └──────┬───────┘  └──────┬───────┘          │
│                           │                 │                  │
│                    Explicit Failures   Silent Failures          │
│                           │                 │                  │
│                           └────────┬────────┘                  │
│                                    ▼                            │
│                        ┌───────────────────────┐               │
│                        │  Dedup / Suppression   │               │
│                        │  SQLite + read flag    │               │
│                        └───────────┬───────────┘               │
│                                    │ new anomaly?               │
│                                    ▼                            │
│                        ┌───────────────────────┐               │
│                        │  opencode.ai Zen API   │               │
│                        │   (big-pickle)         │               │
│                        │   classify + explain   │               │
│                        └───────────┬───────────┘               │
│                                    ▼                            │
│                        ┌───────────────────────┐               │
│                        │   Alert Sender         │               │
│                        │   Console or Slack     │               │
│                        └───────────────────────┘               │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

This is the target data flow. The current code implements it end-to-end: the Explicit Failure path, the org health sweep, Silent Failure detection by day-over-day volume comparison (step 3), the SQLite Suppression Window and Blocklist filtering (steps 4–5), enrichment, classification, and Alert delivery through the console/Slack sender seam.

1. **APScheduler** runs the loop every 300 seconds
2. **Primary layer** — fetches unread notifications from the last hour via `client.notifications.list(read=0, from_timestamp=...)`; each one is a possible Explicit Failure
3. **Volume and health layers** — reads per-flow record volume for today's and yesterday's UTC date windows via `flows.get_org_health_flows(from_date, to_date)` and flags flows whose volume dropped at least `detection.volume_threshold_pct` (default 40%); also fetches RED flows via Nexla org health and creates a `health_sweep` Anomaly only when there is no already-processed Nexla notification for that Flow
4. **Dedup check** — for Explicit Failures: checks if the notification is already marked as `read`; for Silent Failures and `health_sweep`: checks SQLite for an existing alert record for `(flow_id, anomaly_type)` within the Suppression Window
5. **Blocklist check** — drops any problem from flows listed in `config.yaml`
6. **Enrichment** — gathers Evidence for each Anomaly: flow health, latest run status, record/error counts, optional run-summary trends, and ERROR log check results for the latest/recent runs
7. **LLM call** — for each new problem, sends the Anomaly plus Evidence and gets back `risk_classification`, `explanation`, `recommended_action`; the explanation must state whether latest/recent Flow run logs were checked, what Nexla ERROR log Anomalies were found, whether none were found, or whether the log check was inconclusive
8. **Alert** — builds the message and prints it to the console during development
9. **State update** — marks the Nexla notification as `read`; saves a record to SQLite with `suppressed_until = now + suppression_window`

### Project Structure

The code is organized in three layers:

- **Modules** — business logic: detection rules, enrichment orchestration, classification, alert building. This layer does not talk to any external service directly.
- **Repositories** — all reads and writes to SQLite. The rest of the code never touches the database directly.
- **Adapters** — wrappers around external services (Nexla SDK, opencode.ai Zen API). One adapter per service.

```
pipeline-monitor/
├── Dockerfile
├── docker-compose.yml
├── config.yaml                          # operator settings
├── pyproject.toml
├── src/
│   ├── main.py                          # entrypoint + APScheduler
│   ├── monitor.py                       # main loop — calls modules, repos, adapters
│   │
│   ├── modules/
│   │   ├── detection/
│   │   │   ├── explicit_failure.py      # logic to identify Explicit Failures
│   │   │   ├── health_sweep.py          # RED org-health flow sweep
│   │   │   └── silent_failure.py        # day-over-day volume-drop detection
│   │   ├── enrichment/
│   │   │   └── enricher.py              # Evidence orchestration before classification
│   │   ├── suppression/
│   │   │   └── suppression.py           # Suppression Window + Blocklist policy (no SQLite)
│   │   ├── classification/
│   │   │   └── classifier.py            # builds LLM input, interprets output
│   │   ├── alerting/
│   │   │   └── alert.py                 # builds the Alert message
│   │   └── redaction.py                 # masks credentials/connection strings before output
│   │
│   ├── repositories/
│   │   ├── suppression_repository.py    # SQLite Suppression Window records
│   │   └── snapshot_repository.py       # SQLite per-flow daily volume snapshots
│   │
│   └── adapters/
│       ├── nexla_adapter.py             # wraps Nexla SDK calls
│       └── opencode_adapter.py          # wraps opencode.ai Zen API calls
│
├── data/                                # planned for v1
│   └── state.db                         # planned: SQLite (Docker volume)
└── tests/                               # planned
    ├── modules/
    ├── repositories/
    └── adapters/
```

### Configuration (`config.yaml`)

Current development config:

```yaml
nexla:
  service_key: "${NEXLA_SERVICE_KEY}"
  api_url: "${NEXLA_API_URL}"

monitoring:
  poll_interval_seconds: 300
  notification_lookback_hours: 24
  suppression_window_hours: 2
  state_db_path: "data/state.db"

detection:
  volume_threshold_pct: 40
  min_baseline_records: 100
  flows: []

blocklist: []

# Disabled by default. When enabled and configured, Alerts are sent to Slack;
# otherwise the agent keeps using console output.
slack:
  enabled: false
  bot_token: "${SLACK_BOT_TOKEN}"
  channel_id: "${SLACK_CHANNEL_ID}"
#  api_url: "https://slack.com/api/chat.postMessage"

opencode:
  model: "big-pickle"
  base_url: "https://opencode.ai/zen/v1"
```

Slack smoke test:

```bash
uv run pipeline-monitor --config config.yaml --smoke slack
```

It sends exactly one message: `Pipeline monitor Slack smoke test passed.`

Current v1 detection and noise-control config shape:

```yaml
nexla:
  service_key: "${NEXLA_SERVICE_KEY}"
  api_url: "${NEXLA_API_URL}"

monitoring:
  poll_interval_seconds: 300
  suppression_window_hours: 2

detection:
  volume_threshold_pct: 40      # alert if volume drops >= 40% vs previous window
  min_baseline_records: 100     # ignore flows whose baseline is below this (too small/variable)
  flows:                         # per-flow overrides
    - flow_id: 789
      volume_threshold_pct: 60  # flow with high natural variance

blocklist:
  - flow_id: 456
    reason: "High natural variance — not actionable"

slack:
  enabled: true
  bot_token: "${SLACK_BOT_TOKEN}"
  channel_id: "${SLACK_CHANNEL_ID}"

opencode:
  model: "big-pickle"
  base_url: "https://opencode.ai/zen/v1"
```

### SQLite Schema

Both tables are implemented. `suppression` stores `alerted_at` / `suppressed_until` as ISO-8601 UTC text. `metric_snapshots` stores one row per `(flow_id, window_start)` — `window_start` is the date (YYYY-MM-DD, UTC) and `captured_at` the ISO-8601 UTC instant — upserted each tick, with a `UNIQUE (flow_id, window_start)` constraint.

```sql
CREATE TABLE suppression (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  flow_id          INTEGER  NOT NULL,
  anomaly_type     TEXT     NOT NULL,  -- 'explicit_failure' | 'silent_failure' | 'health_sweep'
  alerted_at       DATETIME NOT NULL,
  suppressed_until DATETIME NOT NULL
);

CREATE INDEX idx_suppression_lookup
  ON suppression (flow_id, anomaly_type, suppressed_until);

CREATE TABLE metric_snapshots (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  flow_id       INTEGER  NOT NULL,
  window_start  DATETIME NOT NULL,
  record_count  INTEGER  NOT NULL,
  captured_at   DATETIME NOT NULL
);
```

### LLM Contract

**Input** (sent to the LLM):
```json
{
  "flow_id": 123,
  "flow_name": "CRM Sync — Salesforce to Snowflake",
  "anomaly_type": "explicit_failure",
  "notification_message": "Connection timeout to Salesforce API after 3 retries",
  "recent_failures_count": 3,
  "window": "last 60 minutes"
}
```

**Expected output** (structured output via tool use):
```json
{
  "risk_classification": "high",
  "explanation": "The flow failed 3 times in the last hour due to a timeout on the Salesforce API. The retry pattern suggests the connection is unstable or the source is rate-limiting requests.",
  "recommended_action": "Check the Salesforce API status. If it looks fine, review the connector credentials and consider pausing the flow to stop the error from building up."
}
```

- `uncertain` is treated as `high` by the classifier
- If the LLM call fails, the agent still sends the Alert with `risk_classification: "unknown"` and the raw notification message as the explanation — the problem is never silently dropped

### Alert Format (Console)

```
🔴 [HIGH] Flow "CRM Sync" — Explicit Failure
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Explanation: The flow failed 3 times in the last hour due to a timeout on the Salesforce API.
Recommended action: Check the Salesforce API status and review the connector credentials.

Flow ID: 123 | Detected: 14:35 UTC | Nexla ↗
```

```
🟡 [LOW] Flow "Orders Daily Export" — Silent Failure
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Volume today: 1,200 records | Yesterday (same window): 8,400 records (-86%)
Explanation: Big volume drop with no hard failure. The flow is running but processing much less than expected.
Recommended action: Check the data source and confirm there is no problem further upstream.

Flow ID: 456 | Detected: 09:10 UTC | Nexla ↗
```

---

## Risks

| Risk | Impact | Probability | How to reduce it |
|------|--------|-------------|------------------|
| False alerts for flows with naturally changing volume | Medium — alert noise, loss of trust in the agent | High — any flow with a morning peak will fire outside peak hours | Per-flow threshold in config; Blocklist; 2h Suppression Window reduces repeat noise |
| Nexla API rate limiting with many flows | High — cycles fail silently | Low — depends on number of flows | Add retry with exponential backoff; log all API failures |
| opencode.ai Zen API cost growing with many alerts | Medium — unexpected spend | Medium if many anomalies fire at once | LLM only called when a problem is found, not every cycle; log a warning if estimated cost passes a threshold |
| SQLite lost if container is removed without a mounted volume | High — Suppression Window resets, flood of repeat alerts | Low if docker-compose sets up the volume correctly | Declare the Docker volume explicitly in `docker-compose.yml`; document this clearly |
| LLM gives a wrong risk classification | Medium — but agent never acts, only recommends | Medium — unusual error messages can confuse the model | Fall back to `unknown` if the response is bad; operator always sees the raw context in the Alert |
| Container stops when the laptop closes | High — monitoring stops | High (personal laptop) | Scope is dev/prototype; move to a server or cloud in v2 |

---

## Security

### Secrets

All sensitive values come from environment variables — never from `config.yaml` or the code itself:

| Secret | Environment variable | When to rotate |
|--------|----------------------|----------------|
| Nexla service key | `NEXLA_SERVICE_KEY` | If compromised |
| opencode.ai API key | `OPENCODE_API_KEY` | Every 90 days |

`config.yaml` uses `"${VAR}"` placeholders — never plain text values. A `.env` file (not committed to git) provides the values locally.

### Nexla access

The automatic monitor uses a **service key**, not a personal user account. The key should have the minimum permissions needed: read access to flows, metrics, and notifications, plus notification read-state update if Nexla's `mark_read` API is used for demo deduplication. It must not have flow write permissions (create, update, delete, pause, activate). Supervised, user-initiated Slack flow controls are the ADR 0007 exception and should preferably use a separate service key.

### What not to log

- No credentials or API keys should ever appear in logs
- Nexla error messages may contain table names or connection strings — log these at `DEBUG` level only, never at `INFO` or above in production

---

## Testing Strategy

| Type | What it covers | Coverage goal |
|------|---------------|---------------|
| **Unit** | Detectors, classifier, suppression logic | > 80% |
| **Integration** | Main loop with a mocked Nexla SDK | Happy path + error cases |
| **Contract** | Console Alert format, LLM output schema | 100% of defined contracts |

### Key test cases

**Detection**:
- Flow with `status = failed` → detected as Explicit Failure
- Flow with volume = 0 today vs 5,000 yesterday → detected as Silent Failure
- Flow appears RED in org health with no already-processed notification → detected as `health_sweep`
- Flow in Blocklist → no Alert sent
- Flow already alerted 30 min ago → suppressed by Suppression Window

**LLM**:
- Valid response → Alert with classification and explanation
- LLM API timeout → Alert sent with classification `unknown` and raw message
- `risk_classification = uncertain` → treated as `high`

**State**:
- Container restart → Suppression Window still works because SQLite is on a mounted volume
- Nexla notification → marked as `read` after the Alert is sent

---

## Implementation Plan

### 🚀 MVP — Demo (5 days)

| Day | Task | Status |
|-----|------|--------|
| **1** | Project structure, Docker, Nexla SDK auth working, smoke output working | Implemented; Nexla and Slack smoke paths exist; live scheduler starts successfully when env vars are loaded |
| **2** | `adapters/nexla_adapter.py` + `modules/detection/explicit_failure.py` — fetch unread notifications, mark as `read` | Implemented; verified with compile + local fake-notification smoke tests |
| **3** | `adapters/opencode_adapter.py` + `modules/classification/classifier.py` — LLM call, structured output, fallback | Implemented; unit-tested with valid, `uncertain`, invalid, and failing LLM responses |
| **4** | `modules/alerting/alert.py` + `modules/alerting/sender.py` + `monitor.py` — build Alert, send through console/Slack sender seam, wire full loop | Implemented for Explicit Failures; verified with orchestration tests, sender tests, and feature validation |
| **5** | Docker Compose working end-to-end, smoke tests, polish alert message format | Partially implemented; Slack smoke passed with real bot/channel config, Docker files exist, but Docker Compose end-to-end with real Nexla/opencode credentials still needs verification |

### v1 — After Demo (~5 more days)

| Phase | Task | Estimate | Status |
|-------|------|----------|--------|
| **1 — Silent Failures** | `modules/detection/silent_failure.py` — volume comparison with threshold | 1d | Implemented; unit-tested (threshold, min-baseline, per-flow override, exclude) |
| | `adapters/nexla_adapter.py` — add volume fetch (`list_flow_volumes`) | 0.5d | Implemented; org-health window read, degrades to `[]` |
| **2 — State** | `repositories/snapshot_repository.py` — save/read metric snapshots | 1d | Implemented; unit-tested (upsert, lookup, purge) |
| | `repositories/suppression_repository.py` — SQLite Suppression Window | 1d | Implemented; unit-tested incl. cross-tick health-sweep dedup, with a Docker volume for persistence |
| **3 — Config** | Per-flow threshold overrides, Blocklist in `config.yaml` | 0.5d | Implemented; Blocklist, global + per-flow `volume_threshold_pct`, `min_baseline_records` |
| **4 — Tests** | Unit + integration tests, Nexla SDK mocks | 2d | Implemented for the alert, alert sender/Slack smoke, suppression, and Silent Failure paths (56 tests); real monitor tick with Slack enabled still pending |

**Total estimate**: ~10 days (5 MVP + 5 v1)

**Order matters**:
- v1 Phase 2 needs v1 Phase 1 done first
- v1 Phase 3 can run in parallel with Phase 2

---

## Alternatives Considered

| Decision made | Alternative dropped | Why it was dropped |
|---------------|---------------------|--------------------|
| LLM called only after code finds a problem | LLM looks at all flows every cycle | Cost and speed get worse as the number of flows grows; `status == 'failed'` does not need AI to be spotted |
| Automatic monitor stays read-only, with supervised Slack controls as an ADR 0007 exception | Automatic actions (pause/activate) from v1 | We do not know the false alert rate yet; a false positive that pauses a real flow has immediate impact. Slack controls must be explicitly user-initiated and preferably use a separate service key. |
| Window-to-window volume comparison | Rolling average over 7 days | Needs 7+ days of data before it works; a simple threshold is enough for v1 and easy to tune |
| SQLite for state | No state (re-alert every cycle) | A broken flow would flood the console; the Nexla `read` flag alone does not cover Silent Failures |
| Console output plus opt-in Slack bot during development | Instatus from day one | An incident on a public status page is visible to end users; a false positive there creates unnecessary alarm; validate detection first |

---

## Dependencies

| Dependency | Type | Status |
|------------|------|--------|
| `nexla-sdk` (Python) | External library | Added to project dependencies |
| `openai` SDK | External library | Added to project dependencies |
| Nexla service key with read permissions | Credential | Read from `NEXLA_SERVICE_KEY`; live smoke verification pending |
| Docker Desktop (local) | Infrastructure | Compose file exists; end-to-end run pending |

---

## Open Questions

| # | Question | Status |
|---|----------|--------|
| 1 | Which `user_id` to use for `get_daily_metrics()`? Service account or personal user? | 🔴 Open |
| 2 | Does the Nexla SDK return `record_count` broken down by hour, or only by day? | 🔴 Open — affects how well Silent Failures are detected within the same day |
| 3 | Is there a documented rate limit for `notifications.list()`? | 🔴 Open |
