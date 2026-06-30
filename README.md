# Pipeline Monitor Agent

A **read-only monitoring agent for Nexla data flows**. It polls your Nexla
org on a fixed interval, deterministically detects flow problems, asks an LLM
to label severity and write a plain-language explanation, and posts an Alert
to Slack (or the console). It never mutates flows on its own — the only writes
it can perform are explicit, human-confirmed pause/activate controls driven
from Slack.

The design split is deliberate (see `docs/adr/0002-deterministic-detection-llm-classification.md`):

> **Code decides what is an anomaly. The LLM only labels severity and writes the prose.**

An LLM hallucination therefore cannot invent a failure that didn't happen, nor
hide one that did.

## What the agent analyzes

Every poll runs the pipeline **detect → enrich → classify → suppress → alert**
(orchestrated in `src/monitor.py:monitor_once()`).

### Detection (deterministic — no LLM)

| Analysis | What it catches | Source |
|---|---|---|
| **Explicit failure** | Nexla notifications with level `ERROR` / `CRITICAL` / `FATAL`. Lower levels are ignored and marked read. | `src/modules/detection/explicit_failure.py` |
| **Health sweep** | Flows that Nexla's own org-health reports as `RED` and that aren't already covered by an explicit failure. | `src/modules/detection/health_sweep.py` |
| **Silent failure** | A flow whose **latest run moved far fewer records than its previous run** (default ≥40% drop) while still looking healthy — the failure mode that produces no error at all. Compared **run-over-run** against the last stored snapshot. | `src/modules/detection/silent_failure.py` |

Silent-failure detection is guarded by `min_baseline_records` (ignore flows too
small to be statistically meaningful) and a "looks running" status check, and is
calibrated run-over-run against live Nexla org-health volume
(`docs/adr/0005-silent-failure-volume-detection.md`).

### Enrichment

For each detected anomaly the agent pulls supporting evidence — flow health,
latest run id / record / error counts, run summary, and recent `ERROR` log lines
(`src/modules/enrichment/enricher.py`). Each read is best-effort: if a depended-on
read genuinely fails the Alert is marked **partial** rather than dropped, so the
agent never silently swallows an anomaly.

### Classification (LLM)

The enriched anomaly goes to an LLM (`src/modules/classification/classifier.py`
via `src/adapters/llm_factory.py`) which assigns a severity (`high` / `medium` /
`low`) and writes the human-readable explanation and recommended action. If the
LLM call fails or returns a bad shape, a deterministic fallback escalates real
anomalies to `high` — a transient LLM outage can never downgrade a real failure.

### Suppression

A SQLite-backed suppression window (default 2h) prevents the same flow from
re-alerting every poll. Credentials are redacted before anything leaves the
process (Alert + LLM egress, `src/modules/redaction.py`).

### Slack controls (opt-in, human-confirmed)

Beyond alerting, the agent answers Slack slash commands —
`scan`, `scan FLOW_ID`, `monitoring FLOW_ID`, `monitoring list/remove` — and can
**pause/activate** a flow only after explicit confirmation, within an allow-list
and a TTL (`src/modules/controls/`).

> A deeper, continuously-updated trust assessment of every analysis above lives
> in `.notebook/analysis-pipeline-reliability.md`.

## How to run

Requires **Python ≥ 3.12**. The project uses [`uv`](https://docs.astral.sh/uv/)
for the virtualenv.

### 1. Configure secrets

Copy the example env file and fill it in:

```bash
cp .env.example .env
```

| Variable | Required | Purpose |
|---|---|---|
| `NEXLA_SERVICE_KEY` | ✅ | Nexla service key the agent reads with |
| `NEXLA_API_URL` | ✅ | Nexla API base URL (e.g. `https://dataops.nexla.io/nexla-api`) |
| `NEXLA_CONTROL_SERVICE_KEY` | only for pause/activate | Separate key used for human-confirmed flow controls |
| `OPENAI_API_KEY` / `OPENCODE_API_KEY` | ✅ (matching `llm.provider`) | LLM used for classification |
| `SLACK_BOT_TOKEN`, `SLACK_CHANNEL_ID`, `SLACK_SIGNING_SECRET` | only for Slack | Slack alert delivery + slash commands |

Non-secret behavior (poll interval, thresholds, blocklist, Slack/controls
toggles, LLM provider) is in `config.yaml`.

### 2. Smoke-test connectivity (recommended first run)

```bash
uv run pipeline-monitor --smoke nexla    # verify the Nexla key + base URL
uv run pipeline-monitor --smoke slack     # verify Slack delivery (if enabled)
```

### 3. Run the agent

```bash
uv run pipeline-monitor --config config.yaml
```

This starts the scheduler: it runs one poll immediately, then every
`monitoring.poll_interval_seconds` (default 300s). If Slack controls are enabled
it also starts the interaction server for slash commands and confirmation
buttons. A failing tick is logged and retried on the next interval — it never
crashes the process.

### Run with Docker

```bash
docker compose up --build
```

The SQLite state (suppression window, snapshots, monitored flows) is persisted
in the `pipeline-monitor-state` volume across restarts.

### Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

(The real-LLM integration test is skipped unless `OPENCODE_API_KEY` is set.)
