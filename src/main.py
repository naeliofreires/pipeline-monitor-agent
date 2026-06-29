from __future__ import annotations

import argparse
import logging
import os
import re
import time
from pathlib import Path
from typing import Any

import yaml
from apscheduler.schedulers.background import BackgroundScheduler
from dotenv import load_dotenv

from config import require_str
from modules.alerting.sender import build_alert_sender
from monitor import build_nexla_adapter, monitor_once

logger = logging.getLogger(__name__)


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
        loaded = yaml.safe_load(config_file) or {}
    if not isinstance(loaded, dict):
        raise ConfigError("config.yaml must contain a YAML mapping")
    return _expand_env(loaded)


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


def run_scheduler(config: dict[str, Any]) -> None:
    interval = int(config.get("monitoring", {}).get("poll_interval_seconds", 300))
    scheduler = BackgroundScheduler()
    scheduler.add_job(
        lambda: monitor_once(config),
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
        monitor_once(config)
    except Exception:
        logger.warning("First monitoring tick failed; the scheduler will retry", exc_info=True)
    try:
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Pipeline Monitoring Agent")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--smoke", choices=("nexla", "slack"), help="Run a Day 1 smoke test and exit")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    try:
        config = load_config(args.config)
        if args.smoke == "nexla":
            run_nexla_smoke(config)
        elif args.smoke == "slack":
            run_slack_smoke(config)
        else:
            run_scheduler(config)
    except ConfigError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
