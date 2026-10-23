
"""Safety and idempotency tests for Issue #5."""

import io
import json
from pathlib import Path

from redactor.cli import ERROR_RECORD, process_stream
from redactor.engine import RedactionEngine
from redactor.rules import load_and_validate_rules


RULES_PATH = Path(__file__).resolve().parents[1] / "rules.yaml"


def run_input(data):
    """Run NDJSON through the real CLI processing function."""
    rules = load_and_validate_rules(RULES_PATH)
    engine = RedactionEngine(rules)

    output = io.BytesIO()
    errors = io.StringIO()

    status = process_stream(
        io.BytesIO(data),
        output,
        errors,
        engine,
    )

    return status, output.getvalue(), errors.getvalue()


def test_malformed_json_fails_closed():
    data = b'{"body":{"password":"secret"}, broken}\n'

    status, output, errors = run_input(data)

    assert status == 1
    assert output == ERROR_RECORD
    assert "secret" not in errors


def test_duplicate_keys_are_rejected():
    data = (
        b'{"body":{"token":"secret1",'
        b'"token":"secret2"}}\n'
    )

    status, output, errors = run_input(data)

    assert status == 1
    assert output == ERROR_RECORD
    assert "secret1" not in errors
    assert "secret2" not in errors


def test_nan_is_rejected():
    status, output, _ = run_input(b'{"value":NaN}\n')

    assert status == 1
    assert output == ERROR_RECORD


def test_infinity_is_rejected():
    status, output, _ = run_input(b'{"value":Infinity}\n')

    assert status == 1
    assert output == ERROR_RECORD


def test_nonfinite_numeric_overflow_is_rejected():
    status, output, _ = run_input(b'{"value":1e9999}\n')

    assert status == 1
    assert output == ERROR_RECORD


def test_invalid_utf8_fails_closed():
    status, output, errors = run_input(
        b'{"body":"\xff\xfe"}\n'
    )

    assert status == 1
    assert output == ERROR_RECORD
    assert "failed: 1" in errors


def test_binary_like_data_is_preserved():
    record = {
        "response": {
            "headers": {
                "Content-Type": "application/octet-stream"
            },
            "body": "UEsDBBQAAAAIAA==",
        }
    }

    data = (json.dumps(record) + "\n").encode("utf-8")
    status, output, _ = run_input(data)

    assert status == 0
    assert json.loads(output)["response"]["body"] == (
        "UEsDBBQAAAAIAA=="
    )


def test_full_stream_is_idempotent():
    """Redacting the output again must produce identical bytes."""
    records = [
        {
            "headers": {"Authorization": "Bearer secret"},
            "body": {
                "password": "hunter2",
                "email": "user@example.com",
                "card_number": "4111111111111111",
            },
        },
        {
            "path": "/reset?token=abc123",
            "body": {
                "debug": "login attempt password=hunter2"
            },
        },
        {
            "response": {
                "headers": {
                    "Content-Type": "application/octet-stream"
                },
                "body": "UEsDBBQAAAAIAA==",
            },
        },
    ]

    original = b"".join(
        (json.dumps(record) + "\n").encode("utf-8")
        for record in records
    )

    first_status, first_output, _ = run_input(original)
    second_status, second_output, _ = run_input(first_output)

    assert first_status == 0
    assert second_status == 0
    assert first_output == second_output
    assert b"hunter2" not in first_output
    assert b"abc123" not in first_output


def test_invalid_record_does_not_stop_stream():
    data = (
        b'{"body":{"password":"first"}}\n'
        b'{"body":broken}\n'
        b'{"body":{"password":"second"}}\n'
    )

    status, output, errors = run_input(data)

    records = [
        json.loads(line)
        for line in output.splitlines()
    ]

    assert status == 1
    assert len(records) == 3
    assert records[0]["body"]["password"] == "****"
    assert records[1] == {"error": "redaction_failed"}
    assert records[2]["body"]["password"] == "****"
    assert "records: 3; failed: 1" in errors


def test_error_record_is_idempotent():
    """A previously rejected record remains unchanged on reprocessing."""
    first_status, first_output, _ = run_input(b'{invalid}\n')
    second_status, second_output, _ = run_input(first_output)

    assert first_status == 1
    assert second_status == 0
    assert first_output == second_output == ERROR_RECORD
