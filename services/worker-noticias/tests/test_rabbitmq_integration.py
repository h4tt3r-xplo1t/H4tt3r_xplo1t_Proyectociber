"""Tests against a real RabbitMQ started from docker-compose.yml (ADR 0008).

They need WORKER_NOTICIAS_TEST_AMQP_HOST pointing at a LOOPBACK address (the
compose service publishes AMQP on 127.0.0.1:5672 only). Without it they are
skipped with a reason locally and fail in CI (`CI=true`), where the job always
starts the broker: a silent skip would hide the proof of threats 18 and 19.

The users are created by scripts/rabbitmq-dev-init.sh from these variables,
which hold DEVELOPMENT/CI-ONLY throwaway passwords (never committed):
RABBITMQ_WORKER_NOTICIAS_PASSWORD, RABBITMQ_WORKER_ANALISIS_PASSWORD and
RABBITMQ_ADMIN_PASSWORD.
"""

import os
import time
import uuid

import pika
import pytest
from pika.exceptions import (
    AMQPConnectionError,
    ChannelClosedByBroker,
    ProbableAuthenticationError,
)

AMQP_PORT = 5672
VHOST = "h4tt3r"
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
PASSWORD_VARIABLES = {
    "worker_noticias": "RABBITMQ_WORKER_NOTICIAS_PASSWORD",
    "worker_analisis": "RABBITMQ_WORKER_ANALISIS_PASSWORD",
    "h4tt3r_admin": "RABBITMQ_ADMIN_PASSWORD",
}
MAIN_QUEUE = "analisis.noticias"
DEAD_LETTER_QUEUE = "analisis.noticias.dlq"
MAX_LENGTH = 10000
ACCESS_REFUSED = 403


@pytest.fixture(scope="module")
def amqp_host() -> str:
    host = os.environ.get("WORKER_NOTICIAS_TEST_AMQP_HOST")
    missing = [
        name
        for name in ("WORKER_NOTICIAS_TEST_AMQP_HOST", *PASSWORD_VARIABLES.values())
        if not os.environ.get(name)
    ]
    if missing:
        if os.environ.get("CI") == "true":
            pytest.fail(f"{', '.join(missing)} must be set in CI")
        pytest.skip(
            f"{', '.join(missing)} not set: export the passwords, start the "
            "broker with `docker compose up -d --wait rabbitmq`, run "
            "scripts/rabbitmq-dev-init.sh and set the host to 127.0.0.1 "
            "(see deploy/rabbitmq/README.md)"
        )
    if host not in LOOPBACK_HOSTS:
        pytest.fail(f"refusing to run: {host!r} is not a loopback address")
    return host


def _credentials(user: str) -> tuple[str, str]:
    return user, os.environ[PASSWORD_VARIABLES[user]]


@pytest.fixture
def connect(amqp_host):
    opened: list[pika.BlockingConnection] = []

    def _connect(user: str | tuple[str, str]) -> pika.BlockingConnection:
        params = pika.ConnectionParameters(
            host=amqp_host,
            port=AMQP_PORT,
            virtual_host=VHOST,
            credentials=pika.PlainCredentials(
                *(user if isinstance(user, tuple) else _credentials(user))
            ),
            connection_attempts=1,
            socket_timeout=5,
        )
        connection = pika.BlockingConnection(params)
        opened.append(connection)
        return connection

    yield _connect
    for connection in opened:
        if connection.is_open:
            connection.close()


@pytest.fixture
def admin(connect):
    """Admin channel; both queues are emptied before and after each test."""
    channel = connect("h4tt3r_admin").channel()
    for queue in (MAIN_QUEUE, DEAD_LETTER_QUEUE):
        channel.queue_purge(queue)
    yield channel
    for queue in (MAIN_QUEUE, DEAD_LETTER_QUEUE):
        if channel.connection.is_open:
            channel.queue_purge(queue)


def _count(admin, queue: str) -> int:
    return admin.queue_declare(queue, passive=True).method.message_count


def _wait_for(predicate, timeout: float = 20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.1)
    return predicate()


def _publish_confirmed(channel, body: bytes) -> None:
    channel.confirm_delivery()
    channel.basic_publish(
        "noticias",
        "news.saved",
        body,
        pika.BasicProperties(content_type="application/json", delivery_mode=2),
        mandatory=True,
    )


def test_guest_cannot_connect(connect):
    with pytest.raises((ProbableAuthenticationError, AMQPConnectionError)):
        connect(("guest", "guest"))


def test_publisher_message_reaches_the_analysis_queue_with_confirms(connect, admin):
    channel = connect("worker_noticias").channel()
    _publish_confirmed(channel, b'{"schema": "test"}')
    assert _wait_for(lambda: _count(admin, MAIN_QUEUE) == 1)
    _, _, body = admin.basic_get(MAIN_QUEUE, auto_ack=True)
    assert body == b'{"schema": "test"}'


def test_publisher_cannot_declare_a_queue(connect):
    channel = connect("worker_noticias").channel()
    with pytest.raises(ChannelClosedByBroker) as refused:
        channel.queue_declare(f"evil.{uuid.uuid4().hex}")
    assert refused.value.reply_code == ACCESS_REFUSED


def test_publisher_cannot_declare_an_exchange(connect):
    channel = connect("worker_noticias").channel()
    with pytest.raises(ChannelClosedByBroker) as refused:
        channel.exchange_declare(f"evil.{uuid.uuid4().hex}", exchange_type="direct")
    assert refused.value.reply_code == ACCESS_REFUSED


def test_publisher_cannot_consume(connect):
    channel = connect("worker_noticias").channel()
    with pytest.raises(ChannelClosedByBroker) as refused:
        channel.basic_consume(MAIN_QUEUE, on_message_callback=lambda *a: None)
    assert refused.value.reply_code == ACCESS_REFUSED


def test_publisher_cannot_publish_to_another_exchange(connect, admin):
    channel = connect("worker_noticias").channel()
    channel.confirm_delivery()
    with pytest.raises(ChannelClosedByBroker) as refused:
        channel.basic_publish("noticias.dlx", "news.saved", b"forged")
    assert refused.value.reply_code == ACCESS_REFUSED
    assert _count(admin, DEAD_LETTER_QUEUE) == 0


def test_consumer_credentials_cannot_publish_to_noticias(connect, admin):
    """Threat 18, criterion 6: another service's credentials are rejected."""
    channel = connect("worker_analisis").channel()
    channel.confirm_delivery()
    with pytest.raises(ChannelClosedByBroker) as refused:
        channel.basic_publish("noticias", "news.saved", b"forged")
    assert refused.value.reply_code == ACCESS_REFUSED
    assert _count(admin, MAIN_QUEUE) == 0


def test_consumer_cannot_declare_a_queue(connect):
    channel = connect("worker_analisis").channel()
    with pytest.raises(ChannelClosedByBroker) as refused:
        channel.queue_declare(f"evil.{uuid.uuid4().hex}")
    assert refused.value.reply_code == ACCESS_REFUSED


def test_consumer_can_consume_the_analysis_queue(connect, admin):
    _publish_confirmed(connect("worker_noticias").channel(), b"hello")
    consumer = connect("worker_analisis").channel()
    got = _wait_for(lambda: consumer.basic_get(MAIN_QUEUE, auto_ack=False)[0])
    assert got is not None
    consumer.basic_ack(got.delivery_tag)


def test_full_queue_drops_the_head_into_the_dead_letter_queue(connect, admin):
    """Threat 19, criterion 7: the max-length policy applies on a full queue."""
    channel = connect("worker_noticias").channel()
    total = MAX_LENGTH + 3
    for n in range(total):
        channel.basic_publish("noticias", "news.saved", str(n).encode())
    assert _wait_for(lambda: _count(admin, DEAD_LETTER_QUEUE) >= 3, timeout=60)
    assert _wait_for(lambda: _count(admin, MAIN_QUEUE) == MAX_LENGTH, timeout=60)
    _, _, oldest = admin.basic_get(DEAD_LETTER_QUEUE, auto_ack=True)
    assert oldest == b"0"
    assert _count(admin, MAIN_QUEUE) <= MAX_LENGTH


def test_a_rejected_message_goes_to_the_dead_letter_queue(connect, admin):
    _publish_confirmed(connect("worker_noticias").channel(), b"poison")
    consumer = connect("worker_analisis").channel()
    got = _wait_for(lambda: consumer.basic_get(MAIN_QUEUE, auto_ack=False)[0])
    consumer.basic_nack(got.delivery_tag, requeue=False)
    assert _wait_for(lambda: _count(admin, DEAD_LETTER_QUEUE) == 1)
    _, _, body = admin.basic_get(DEAD_LETTER_QUEUE, auto_ack=True)
    assert body == b"poison"


def test_a_message_over_the_delivery_limit_goes_to_the_dead_letter_queue(
    connect, admin
):
    """A consumer that keeps dying on the same message does not loop forever.

    The broker counts a delivery as failed when the consumer disconnects
    without settling it (a crash); `basic.nack` with requeue is not counted.
    """
    _publish_confirmed(connect("worker_noticias").channel(), b"retried")
    for _ in range(6):
        connection = connect("worker_analisis")
        channel = connection.channel()
        got = _wait_for(
            lambda ch=channel: ch.basic_get(MAIN_QUEUE, auto_ack=False)[0], timeout=2
        )
        connection.close()
        if got is None:
            break
    assert _wait_for(lambda: _count(admin, DEAD_LETTER_QUEUE) == 1)
    assert _count(admin, MAIN_QUEUE) == 0
