
"""HTTP service integration tests."""

import http.client
import json
import threading
from contextlib import contextmanager
from pathlib import Path

import pytest

from redactor.service import create_server


ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = ROOT / "rules.yaml"


@contextmanager
def running_server(rules_path=RULES_PATH):
    """Start a real HTTP server on a temporary local port."""

    server = create_server(
        host="127.0.0.1",
        port=0,
        rules_path=rules_path,
    )

    thread = threading.Thread(
        target=server.serve_forever,
        daemon=True,
    )
    thread.start()

    try:
        yield server.server_address[1]

    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def request(port, method, path, body=None):
    """Send an HTTP request and return the status and bytes."""

    connection = http.client.HTTPConnection(
        "127.0.0.1",
        port,
        timeout=5,
    )

    try:
        connection.request(
            method,
            path,
            body=body,
        )

        response = connection.getresponse()

        return response.status, response.read()

    finally:
        connection.close()


def ndjson(*records):
    return b"".join(
        (
            json.dumps(record, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        for record in records
    )


def test_health_endpoint():
    with running_server() as port:
        status, body = request(port, "GET", "/health")

    assert status == 200
    assert json.loads(body) == {"status": "ok"}


def test_unknown_endpoint_returns_404():
    with running_server() as port:
        status, body = request(port, "GET", "/unknown")

    assert status == 404
    assert json.loads(body) == {"error": "not_found"}


def test_post_redact_streams_multiple_records():
    data = ndjson(
        {
            "headers": {
                "Authorization": "Bearer secret"
            },
            "body": {
                "password": "hunter2",
                "email": "alice@example.com",
            },
        },
        {
            "body": {
                "card_number": "4111111111111111",
            }
        },
    )

    with running_server() as port:
        status, body = request(
            port,
            "POST",
            "/redact",
            data,
        )

    rows = [
        json.loads(line)
        for line in body.splitlines()
    ]

    assert status == 200
    assert len(rows) == 2

    assert rows[0]["headers"]["Authorization"] == "****"
    assert rows[0]["body"]["password"] == "****"
    assert rows[0]["body"]["email"].startswith("sha256:")
    assert rows[1]["body"]["card_number"].endswith("1111")

    assert b"hunter2" not in body
    assert b"alice@example.com" not in body
    assert b"4111111111111111" not in body


def test_invalid_record_fails_closed_and_stream_continues():
    data = (
        ndjson({"body": {"password": "first"}})
        + b'{"password":"private", broken}\n'
        + ndjson({"body": {"password": "last"}})
    )

    with running_server() as port:
        status, body = request(
            port,
            "POST",
            "/redact",
            data,
        )

    rows = [
        json.loads(line)
        for line in body.splitlines()
    ]

    assert status == 200
    assert len(rows) == 3

    assert rows[0]["body"]["password"] == "****"
    assert rows[1] == {"error": "redaction_failed"}
    assert rows[2]["body"]["password"] == "****"

    assert b"private" not in body


def test_missing_rules_prevent_server_startup(tmp_path):
    missing = tmp_path / "missing-rules.yaml"

    with pytest.raises((OSError, ValueError)):
        create_server(
            port=0,
            rules_path=missing,
        )


def test_invalid_rules_prevent_server_startup(tmp_path):
    invalid = tmp_path / "invalid-rules.yaml"
    invalid.write_text(
        "version: 999\n",
        encoding="utf-8",
    )

    with pytest.raises((OSError, ValueError)):
        create_server(
            port=0,
            rules_path=invalid,
        )


def test_request_without_content_length_is_rejected():
    with running_server() as port:
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            port,
            timeout=5,
        )

        try:
            connection.putrequest("POST", "/redact")
            connection.endheaders()

            response = connection.getresponse()
            status = response.status
            body = response.read()

        finally:
            connection.close()

    assert status == 411
    assert json.loads(body) == {
        "error": "content_length_required"
    }


def test_chunked_request_body_is_rejected():
    with running_server() as port:
        connection = http.client.HTTPConnection(
            "127.0.0.1",
            port,
            timeout=5,
        )

        try:
            connection.request(
                "POST",
                "/redact",
                body=[b'{"body":{"password":"secret"}}\n'],
                encode_chunked=True,
                headers={
                    "Transfer-Encoding": "chunked",
                },
            )

            response = connection.getresponse()
            status = response.status
            body = response.read()

        finally:
            connection.close()

    assert status == 400
    assert json.loads(body) == {
        "error": "unsupported_transfer_encoding"
    }


def test_http_redaction_is_idempotent():
    data = ndjson(
        {
            "headers": {
                "Authorization": "Bearer secret"
            },
            "body": {
                "password": "hunter2",
                "email": "alice@example.com",
            },
        },
        {
            "body": {
                "debug": "password=anotherSecret"
            }
        },
    )

    with running_server() as port:
        first_status, first_body = request(
            port,
            "POST",
            "/redact",
            data,
        )

        second_status, second_body = request(
            port,
            "POST",
            "/redact",
            first_body,
        )

    assert first_status == 200
    assert second_status == 200
    assert first_body == second_body
