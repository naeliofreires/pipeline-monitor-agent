# Pipeline Monitor Agent

A read-only monitoring agent for Nexla data flows. Every few minutes it checks
your org for flows that failed, went red, or quietly stopped moving data, then
posts an LLM-written summary to Slack (or the console).

It won't change your flows on its own. The only writes it can do are pause and
activate, and only after a human confirms in Slack.

## How it works

```
detect ──▶ enrich ──▶ classify ──▶ suppress ──▶ alert
 code       code         LLM          code        code
```

Code decides what counts as a problem; the LLM only rates severity and writes
the explanation (ADR-0002). So a hallucination can't invent or hide a failure.

The three detectors (all deterministic):

| Detector | What it catches |
|---|---|
| Explicit failure | Nexla notifications at level `ERROR`, `CRITICAL`, or `FATAL`. |
| Health sweep | Flows Nexla's org-health reports as `RED`. |
| Silent failure | A flow whose latest run moved far fewer records than its previous run (default ≥40% drop) while still looking healthy. |

Source lives in `src/modules/detection/`, `enrichment/`, `classification/`, and
`controls/`; the pipeline is orchestrated in `src/monitor.py:monitor_once()`.
For how far each detector can be trusted, see
`.notebook/analysis-pipeline-reliability.md`.

## Running it

Needs Python 3.12+ and [`uv`](https://docs.astral.sh/uv/).

```bash
cp .env.example .env                          # fill in the keys below
uv run pipeline-monitor --smoke nexla         # check Nexla connectivity
uv run pipeline-monitor --config config.yaml  # start the scheduler
```

The scheduler polls immediately, then every `poll_interval_seconds` (300s by
default). A failing tick is logged and retried, never fatal. With Slack controls
on, it also serves slash commands (`scan`, `monitoring …`) and confirm buttons.

Required env keys (non-secret tuning — thresholds, intervals, toggles — is in
`config.yaml`):

| Variable | When |
|---|---|
| `NEXLA_SERVICE_KEY`, `NEXLA_API_URL` | Always |
| `OPENAI_API_KEY` or `OPENCODE_API_KEY` | Whichever matches `llm.provider` |
| `NEXLA_CONTROL_SERVICE_KEY` | Only for pause/activate |
| `SLACK_BOT_TOKEN`, `SLACK_CHANNEL_ID`, `SLACK_SIGNING_SECRET` | Only for Slack |

### Docker

```bash
docker compose up --build
```

SQLite state persists in the `pipeline-monitor-state` volume.

### Tests

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

[DEMO VIDEO](https://drive.google.com/file/d/1CWkorhdjnX5TP_FAPEVD8DSY6xEG40sn/view?usp=sharing)
