"""Shared helpers of the RabbitMQ tests: repository paths and policy values."""

import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
DEPLOY_DIR = REPO_ROOT / "deploy" / "rabbitmq"
MAIN_QUEUE_PATTERN = r"^analisis\.noticias$"


def main_queue_policy_value(key: str):
    """Value of `key` in the policy of the main queue (definitions.json).

    The broker policy is the single source of truth for the limits the tests
    exercise. A missing policy or key fails with a clear message.
    """
    definitions = json.loads((DEPLOY_DIR / "definitions.json").read_text("utf-8"))
    matches = [p for p in definitions["policies"] if p["pattern"] == MAIN_QUEUE_PATTERN]
    assert len(matches) == 1, f"expected one policy for {MAIN_QUEUE_PATTERN!r}"
    definition = matches[0]["definition"]
    assert key in definition, f"policy {matches[0]['name']!r} has no {key!r}"
    return definition[key]
