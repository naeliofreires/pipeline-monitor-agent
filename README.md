# Pipeline Monitor Agent

A read-only monitoring agent for Nexla data flows. Every few minutes it checks
your Nexla org for flows that have failed, gone red, or quietly stopped moving
data. When it finds one, an LLM writes up what happened and how serious it is,
and the agent posts that to Slack (or prints it to the console).

It will not touch your flows on its own. The only writes it can do are pause and
activate, and only after a human clicks confirm in Slack.

One rule shapes the whole design (ADR-0002): code decides what counts as a
problem, and the LLM only labels severity and writes the explanation. So a model
hallucination can't invent a failure that never happened, or hide a real one.
The detection is deterministic; only the prose isn't.

## What the agent analyzes

Each poll runs the same pipeline: detect, enrich, classify, suppress, alert.
It's wired together in `src/monitor.py:monitor_once()`.

```
   detect   ──▶   enrich   ──▶   classify   ──▶   suppress   ──▶   alert
 (find the      (gather the     (LLM rates       (skip if        (Slack or
  anomaly)       evidence)       + explains)      seen lately)     console)
    code           code             LLM              code            code
```

Only the classify step touches the LLM. Everything that decides whether
something is wrong is plain code.

### Detection (deterministic, no LLM)

| Analysis | What it catches | Source |
|---|---|---|
| Explicit failure | Nexla notifications at level `ERROR`, `CRITICAL`, or `FATAL`. Lower levels are ignored and marked read. | `src/modules/detection/explicit_failure.py` |
| Health sweep | Flows that Nexla's own org-health reports as `RED` and that an explicit failure hasn't already flagged. | `src/modules/detection/health_sweep.py` |
| Silent failure | A flow whose latest run moved far fewer records than its previous run (default 40% or more) while still looking healthy. This is the failure that throws no error at all, so it's the one worth catching. Compared run-over-run against the last stored snapshot. | `src/modules/detection/silent_failure.py` |

Silent-failure detection skips flows whose baseline is below `min_baseline_records`
(too small to read anything into) and flows that don't look like they're running.
The thresholds are calibrated against live Nexla org-health volume, run over run.
See `docs/adr/0005-silent-failure-volume-detection.md`.

### Enrichment

For each anomaly the agent gathers the evidence a human would want: flow health,
the latest run's id and record and error counts, a run summary, and the recent
`ERROR` log lines (`src/modules/enrichment/enricher.py`). If one of those reads
fails, the Alert goes out marked `partial` instead of being dropped. The agent
would rather tell you it couldn't see something than stay quiet about it.

### Classification (LLM)

The enriched anomaly goes to an LLM (`src/modules/classification/classifier.py`,
via `src/adapters/llm_factory.py`), which picks a severity (`high`, `medium`, or
`low`) and writes the explanation and recommended action. If the call fails or
comes back malformed, a fallback kicks in and marks real anomalies `high`. A
flaky LLM can escalate a failure, but it can never quietly downgrade one.

### Suppression

A SQLite suppression window (2h by default) keeps the same flow from re-alerting
on every poll. Credentials are redacted before anything leaves the process,
covering both the Alert and the LLM call (`src/modules/redaction.py`).

### Slack controls (opt-in, human-confirmed)

The agent also answers Slack slash commands: `scan`, `scan FLOW_ID`,
`monitoring FLOW_ID`, and `monitoring list`/`remove`. It can pause or activate a
flow too, but only after someone confirms, only for flows on the allow-list, and
only within a TTL (`src/modules/controls/`).

> If you want the long version of how far each analysis can be trusted, that
> lives in `.notebook/analysis-pipeline-reliability.md` and gets updated as we
> learn more.

## How to run

You'll need Python 3.12 or newer. The project uses
[`uv`](https://docs.astral.sh/uv/) for the virtualenv.

### 1. Configure secrets

Copy the example env file and fill it in:

```bash
cp .env.example .env
```

| Variable | Required | Purpose |
|---|---|---|
| `NEXLA_SERVICE_KEY` | Yes | Nexla service key the agent reads with |
| `NEXLA_API_URL` | Yes | Nexla API base URL (e.g. `https://dataops.nexla.io/nexla-api`) |
| `NEXLA_CONTROL_SERVICE_KEY` | Only for pause/activate | Separate key for the human-confirmed flow controls |
| `OPENAI_API_KEY` / `OPENCODE_API_KEY` | Yes, whichever matches `llm.provider` | The LLM that classifies anomalies |
| `SLACK_BOT_TOKEN`, `SLACK_CHANNEL_ID`, `SLACK_SIGNING_SECRET` | Only for Slack | Alert delivery and slash commands |

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

This starts the scheduler. It runs one poll right away, then again every
`monitoring.poll_interval_seconds` (300s by default). With Slack controls
enabled it also brings up the interaction server for slash commands and the
confirmation buttons. If a tick fails it's logged and retried on the next
interval, so a bad poll won't crash the process.

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
