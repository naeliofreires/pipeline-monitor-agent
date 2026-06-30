from __future__ import annotations

import argparse
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # minimal fallback for tests/dev without PyYAML
    yaml = None  # type: ignore[assignment]
try:
    from apscheduler.schedulers.background import BackgroundScheduler
except ModuleNotFoundError:
    BackgroundScheduler = None  # type: ignore[assignment]
try:
    from dotenv import load_dotenv
except ModuleNotFoundError:
    def load_dotenv(path: Path) -> None:
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                if "=" in line and not line.strip().startswith("#"):
                    k, v = line.split("=", 1); os.environ.setdefault(k, v)

from config import require_str
from adapters.llm_factory import build_llm_adapter
from modules.alerting.sender import build_alert_sender
from modules.controls.commands import SlackCommandExecutor
from modules.controls.intent import Intent, parse_intent
from modules.controls.config import ControlConfigError, controls_enabled, validate_control_config
from modules.controls.executor import ControlExecutor
from modules.controls.router import route_message
from modules.controls.router_tools import RouterCallbacks, RouterContext
from modules.controls.server import start_interaction_server
from monitor import build_nexla_adapter, handle_monitoring_command, latest_runs, monitor_once, scan_flow
from repositories.control_audit_repository import ControlAuditRepository

logger = logging.getLogger(__name__)


logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

# Serializes monitoring work between the interactive chat command and its background watcher so
# the two never run a tick at the same time (avoids duplicate alerts and SQLite write contention).
_MONITOR_LOCK = threading.Lock()


class ConfigError(RuntimeError):
    pass


_ENV_PATTERN = re.compile(r"\$\{([A-Z0-9_]+)\}")


def _expand_env(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _expand_env(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_expand_env(item) for item in value]
    if isinstance(value, str):
        return _ENV_PATTERN.sub(lambda match: os.getenv(match.group(1), ""), value)
    return value


def load_config(path: str) -> dict[str, Any]:
    config_path = Path(path)
    load_dotenv(config_path.parent / ".env")
    with config_path.open("r", encoding="utf-8") as config_file:
        if yaml is not None:
            loaded = yaml.safe_load(config_file) or {}
        else:
            loaded = _simple_yaml_load(config_file.read())
    if not isinstance(loaded, dict):
        raise ConfigError("config.yaml must contain a YAML mapping")
    return _expand_env(loaded)


def _simple_yaml_load(text: str) -> dict[str, Any]:
    root: dict[str, Any] = {}; current = root
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" ") and line.rstrip().endswith(":"):
            key = line.strip()[:-1]; root[key] = {}; current = root[key]
        elif ":" in line:
            key, value = line.strip().split(":", 1); value = value.strip().strip('"')
            current[key] = value
    return root


def require_secret(config: dict[str, Any], path: tuple[str, ...], label: str) -> str:
    return require_str(
        config,
        path,
        f"Missing required secret for {label}; set the matching environment variable",
        ConfigError,
    )


def run_nexla_smoke(config: dict[str, Any]) -> None:
    service_key = require_secret(config, ("nexla", "service_key"), "Nexla smoke test")
    count = build_nexla_adapter(config, service_key).smoke_test_flows_list()
    print(f"Nexla auth smoke test passed; flows.list returned {count} item(s)")


def run_slack_smoke(config: dict[str, Any]) -> None:
    slack_config = config.get("slack", {})
    if not isinstance(slack_config, dict) or not slack_config.get("enabled"):
        raise ConfigError("Slack smoke test requires slack.enabled: true")
    require_secret(config, ("slack", "bot_token"), "Slack smoke test bot token")
    require_secret(config, ("slack", "channel_id"), "Slack smoke test channel ID")

    build_alert_sender(config).send("Pipeline monitor Slack smoke test passed.")
    print("Slack smoke test passed; message sent to configured channel")


def dispatch_monitor_once(config: dict[str, Any]) -> None:
    print("Starting pipeline monitor sync")
    try:
        monitor_once(config)
    except Exception:
        print("Pipeline monitor sync failed; waiting for the next scheduled sync")
        raise
    print("Pipeline monitor sync finished; waiting for the next scheduled sync")


INTENT_HELP = (
    "Try: `scan` (check every flow), `scan flow 1234` (one flow), `help`, or `quit`."
)


def reply_for_intent(config: dict[str, Any], intent: Intent) -> str:
    """Run a parsed Intent against the existing scan callbacks and return a reply line."""
    if intent.action == "help":
        return INTENT_HELP
    if intent.action == "unknown":
        return f"I didn't catch a request in that. {INTENT_HELP}"
    if intent.action == "scan":
        if intent.flow_id is not None:
            return scan_flow(config, intent.flow_id)
        monitor_once(config)
        return "Scan finished; any anomalies were printed above."
    return INTENT_HELP


def handle_message(config: dict[str, Any], message: str) -> str:
    """Route one plain-English message: the LLM decides which behavior to run, with the
    deterministic parser as fallback when the LLM is unavailable or its choice is unusable."""
    deterministic = lambda text: reply_for_intent(config, parse_intent(text))  # noqa: E731
    if not config.get("router", {}).get("enabled", True):
        return deterministic(message)
    try:
        llm_adapter = build_llm_adapter(config)
    except Exception:
        logger.warning("LLM adapter unavailable; using deterministic routing", exc_info=True)
        return deterministic(message)
    context = RouterContext(config=config, channel_id="cli", user_id=None)
    callbacks = RouterCallbacks(
        scan_flow=scan_flow, scan_org=monitor_once, latest_runs=latest_runs, monitoring=handle_monitoring_command
    )
    return route_message(message, context, callbacks, llm_adapter, deterministic)


class _ChatWatchSender:
    """AlertSender for interactive chat: prints background-monitor anomalies above the prompt.

    The chat REPL blocks on ``input()``, so without this nothing reaches the terminal between
    user turns. The watcher feeds anomalies here as they are detected, then the prompt is
    redrawn so the session stays usable.
    """

    def send(self, text: str, metadata: Any = None) -> None:
        print(f"\n🔔 Background monitor — new anomaly:\n{text}\n", flush=True)
        print("> ", end="", flush=True)


def _start_chat_watcher(config: dict[str, Any], stop_event: threading.Event) -> threading.Thread | None:
    """Poll the monitor on the configured interval and print new anomalies above the chat prompt.

    Returns the daemon watcher thread, or None when disabled via ``monitoring.chat_watch_enabled``.
    Suppression state (shared with the scheduler) keeps a still-open anomaly from reprinting every
    tick, so the session only surfaces genuinely new problems.
    """
    monitoring = config.get("monitoring", {}) or {}
    if not monitoring.get("chat_watch_enabled", True):
        return None
    interval = int(monitoring.get("poll_interval_seconds", 300))
    sender = _ChatWatchSender()

    def loop() -> None:
        # Wait one interval before the first tick so startup output stays clean; only surface
        # anomalies that appear (or stay open) while the session is running.
        while not stop_event.wait(interval):
            with _MONITOR_LOCK:
                try:
                    monitor_once(config, sender)
                except Exception:
                    logger.warning("Background chat watcher tick failed; retrying next interval", exc_info=True)

    thread = threading.Thread(target=loop, name="chat-watcher", daemon=True)
    thread.start()
    return thread


def run_chat(config: dict[str, Any]) -> None:
    """Read plain-English requests from the terminal until EOF, quit, or Ctrl-C.

    A background watcher polls the monitor on the configured interval and prints any new
    anomalies above the prompt, so problems surface without the user having to ask.
    """
    print(f"Pipeline monitor — type a request in plain English. {INTENT_HELP}")
    stop_watcher = threading.Event()
    _start_chat_watcher(config, stop_watcher)
    try:
        while True:
            try:
                text = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            if not text:
                continue
            if parse_intent(text).action == "quit":
                return
            try:
                with _MONITOR_LOCK:
                    reply = handle_message(config, text)
            except Exception as exc:  # a failed scan must not kill the session
                print(f"Sorry, that request failed: {exc}")
                continue
            if reply:
                print(reply)
    finally:
        stop_watcher.set()


def run_scheduler(config: dict[str, Any]) -> None:
    validate_control_config(config)
    control_server = None
    audit = None
    if controls_enabled(config):
        audit = ControlAuditRepository(str(config.get("monitoring", {}).get("state_db_path", "data/state.db")))
        control_service_key = str(config.get("nexla", {}).get("control_service_key") or "").strip()
        if not control_service_key:
            control_service_key = require_secret(config, ("nexla", "service_key"), "Nexla service key for temporary flow controls")
        adapter = build_nexla_adapter(config, control_service_key)
        control_server = start_interaction_server(
            config,
            audit,
            ControlExecutor(adapter, audit),
            SlackCommandExecutor(config, monitor_once, scan_flow, handle_monitoring_command),
        )
        print("Slack flow control interaction server started")
    interval = int(config.get("monitoring", {}).get("poll_interval_seconds", 300))
    if BackgroundScheduler is None:
        raise ConfigError("APScheduler is required to run the scheduler")
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        lambda: dispatch_monitor_once(config),
        "interval",
        seconds=interval,
        id="monitor_once",
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()
    print(f"Pipeline monitor scheduler started with {interval}s interval")
    # A transient failure on the first tick must not crash the process; the interval retries.
    try:
        dispatch_monitor_once(config)
    except Exception:
        logger.warning("First monitoring tick failed; the scheduler will retry", exc_info=True)
    try:
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        if control_server:
            control_server.shutdown()
        if audit:
            audit.close()
        scheduler.shutdown()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Pipeline Monitoring Agent")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--smoke", choices=("nexla", "slack"), help="Run a Day 1 smoke test and exit")
    parser.add_argument("--ask", metavar="TEXT", help='Run one plain-English request and exit, e.g. --ask "scan flow 1234"')
    parser.add_argument("--chat", action="store_true", help="Start an interactive plain-English terminal session")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        config = load_config(args.config)
        if args.smoke == "nexla":
            run_nexla_smoke(config)
        elif args.smoke == "slack":
            run_slack_smoke(config)
        elif args.ask is not None:
            print(handle_message(config, args.ask))
        elif args.chat:
            run_chat(config)
        else:
            run_scheduler(config)
    except (ConfigError, ControlConfigError) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
