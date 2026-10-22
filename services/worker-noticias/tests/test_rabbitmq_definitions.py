"""Static checks of the RabbitMQ definitions file (no broker needed).

The definitions are imported by the broker at boot (ADR 0008). These tests pin
the least-privilege model of threat 18 and the queue limits of threat 19, so a
careless edit of the JSON fails in review before it reaches a broker.
"""

import json
import re
import shlex
import subprocess

import pytest

from tests.brokersupport import DEPLOY_DIR, REPO_ROOT

VHOST = "h4tt3r"
INIT_SCRIPT = REPO_ROOT / "scripts" / "rabbitmq-dev-init.sh"
EXPECTED_PERMISSIONS = {
    "worker_noticias": ("^$", "^noticias$", "^$"),
    "worker_analisis": ("^$", "^$", r"^analisis\.noticias$"),
    "h4tt3r_admin": (".*", ".*", ".*"),
}


def _script_permissions() -> dict[str, tuple[str, ...]]:
    granted: dict[str, tuple[str, ...]] = {}
    for line in INIT_SCRIPT.read_text(encoding="utf-8").splitlines():
        if line.lstrip().startswith("rmq set_permissions"):
            words = shlex.split(line)
            assert words[2:4] == ["-p", VHOST], line
            user, patterns = words[4], tuple(words[5:])
            assert user not in granted, f"duplicate set_permissions for {user}"
            granted[user] = patterns
    return granted


def test_the_init_script_grants_exactly_the_adr_permissions():
    assert _script_permissions() == EXPECTED_PERMISSIONS


def test_only_the_dev_admin_gets_broad_permissions_in_the_script():
    broad = {u for u, p in _script_permissions().items() if ".*" in p}
    assert broad == {"h4tt3r_admin"}


def test_the_init_script_has_no_default_passwords_and_removes_guest():
    text = INIT_SCRIPT.read_text(encoding="utf-8")
    assert "set -euo pipefail" in text
    for name in (
        "RABBITMQ_WORKER_NOTICIAS_PASSWORD",
        "RABBITMQ_WORKER_ANALISIS_PASSWORD",
        "RABBITMQ_ADMIN_PASSWORD",
    ):
        assert f"${{{name}:?" in text, name
    assert "delete_user guest" in text


@pytest.fixture(scope="module")
def definitions() -> dict:
    return json.loads((DEPLOY_DIR / "definitions.json").read_text(encoding="utf-8"))


def test_definitions_carry_no_users_permissions_or_passwords(definitions):
    """Users and passwords are created by scripts/rabbitmq-dev-init.sh instead."""
    assert "users" not in definitions
    assert "permissions" not in definitions

    def keys(node):
        if isinstance(node, dict):
            for key, value in node.items():
                yield key
                yield from keys(value)
        elif isinstance(node, list):
            for item in node:
                yield from keys(item)

    assert not [k for k in keys(definitions) if "pass" in k.lower() or "hash" in k]


def test_the_only_vhost_is_h4tt3r(definitions):
    assert [v["name"] for v in definitions["vhosts"]] == [VHOST]


def test_topology_exchanges_queues_and_bindings(definitions):
    exchanges = {e["name"]: e for e in definitions["exchanges"]}
    assert exchanges["noticias"]["type"] == "direct"
    assert exchanges["noticias"]["durable"] is True
    assert exchanges["noticias.dlx"]["durable"] is True
    assert set(exchanges) == {"noticias", "noticias.dlx"}
    queues = {q["name"]: q for q in definitions["queues"]}
    assert set(queues) == {"analisis.noticias", "analisis.noticias.dlq"}
    for queue in queues.values():
        assert queue["durable"] is True
        assert queue["arguments"]["x-queue-type"] == "quorum"
    bindings = {
        (b["source"], b["destination"], b["routing_key"])
        for b in definitions["bindings"]
    }
    assert ("noticias", "analisis.noticias", "news.saved") in bindings
    assert any(
        src == "noticias.dlx" and dst == "analisis.noticias.dlq"
        for src, dst, _ in bindings
    )
    assert len(bindings) == 2


def test_queue_limits_come_from_policies_with_the_adr_values(definitions):
    policies = {p["name"]: p for p in definitions["policies"]}
    main = next(p for p in policies.values() if p["pattern"] == r"^analisis\.noticias$")
    assert main["apply-to"] == "queues"
    assert main["definition"] == {
        "max-length": 10000,
        "overflow": "drop-head",
        "message-ttl": 86400000,
        "delivery-limit": 3,
        "dead-letter-exchange": "noticias.dlx",
    }
    dlq = next(
        p for p in policies.values() if p["pattern"] == r"^analisis\.noticias\.dlq$"
    )
    assert dlq["definition"]["max-length"] == 10000
    assert dlq["definition"]["overflow"] == "drop-head"
    assert "dead-letter-exchange" not in dlq["definition"]
    assert all(p["vhost"] == VHOST for p in policies.values())


def test_the_broker_config_imports_the_definitions_at_boot():
    conf = (DEPLOY_DIR / "rabbitmq.conf").read_text(encoding="utf-8")
    lines = {ln.strip() for ln in conf.splitlines() if not ln.startswith("#")}
    assert "definitions.import_backend = local_filesystem" in lines
    assert any(ln.startswith("definitions.local.path = ") for ln in lines)
    assert not any("management" in ln for ln in lines)


def test_compose_pins_a_fixed_hostname_for_the_broker():
    """RabbitMQ keys its data directory by node name (derived from the hostname).

    A random container hostname would make a recreated container boot with an
    empty node directory and lose the users created by the init script.
    """
    compose = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    block = re.search(r"^  rabbitmq:\n((?:    .*\n|\n)+)", compose, re.MULTILINE)
    assert block, "rabbitmq service not found in docker-compose.yml"
    assert re.search(r"^    hostname: rabbitmq$", block.group(1), re.MULTILINE)


def _run_init_script(tmp_path, *, list_users_fails: bool):
    """Run the init script with a stub `docker` on PATH; return (result, calls)."""
    log = tmp_path / "docker-calls.log"
    stub = tmp_path / "docker"
    stub.write_text(
        "#!/usr/bin/env bash\n"
        'printf \'%s\\n\' "$*" >> "$STUB_LOG"\n'
        'if [[ "$*" == *list_users* ]]; then\n'
        f"  {'echo broker-down >&2; exit 1' if list_users_fails else 'exit 0'}\n"
        "fi\n",
        encoding="utf-8",
    )
    stub.chmod(0o700)
    env = {
        "PATH": f"{tmp_path}:/usr/bin:/bin",
        "STUB_LOG": str(log),
        "RABBITMQ_WORKER_NOTICIAS_PASSWORD": "-starts-with-dash",
        "RABBITMQ_WORKER_ANALISIS_PASSWORD": "x",
        "RABBITMQ_ADMIN_PASSWORD": "x",
    }
    result = subprocess.run(  # noqa: S603 - fixed local script and stub
        ["/usr/bin/env", "bash", str(INIT_SCRIPT)],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    calls = log.read_text(encoding="utf-8") if log.exists() else ""
    return result, calls


def test_the_init_script_aborts_when_the_user_listing_fails(tmp_path):
    """A broker that cannot list users must not be read as "user missing"."""
    result, calls = _run_init_script(tmp_path, list_users_fails=True)
    assert result.returncode != 0
    assert "cannot list" in result.stderr
    assert "add_user" not in calls
    assert "change_password" not in calls


def test_the_init_script_passes_passwords_after_an_option_terminator(tmp_path):
    """A password starting with `-` must not be parsed as an rabbitmqctl option."""
    result, calls = _run_init_script(tmp_path, list_users_fails=False)
    assert result.returncode == 0, result.stderr
    add_user_calls = [ln for ln in calls.splitlines() if "add_user" in ln]
    assert len(add_user_calls) == 3
    for line in add_user_calls:
        assert 'add_user -- "$0"' in line
