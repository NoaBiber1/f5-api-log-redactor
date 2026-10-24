
"""Tests for CLI streaming and fail-closed processing."""

import io
import json
from pathlib import Path

from redactor.cli import (
    MAX_LINE_BYTES,
    main,
    process_stream,
)
from redactor.engine import RedactionEngine
from redactor.rules import load_and_validate_rules


RULES_PATH = (
    Path(__file__).resolve().parents[1] / "rules.yaml"
)


def run_stream(data, max_line_bytes=MAX_LINE_BYTES):
    """Process test input using in-memory streams."""

    rules = load_and_validate_rules(RULES_PATH)
    engine = RedactionEngine(rules)

    output = io.BytesIO()
    errors = io.StringIO()

    status = process_stream(
        io.BytesIO(data),
        output,
        errors,
        engine,
        max_line_bytes,
    )

    return status, output.getvalue(), errors.getvalue()


def test_stream_multiple_records_and_counts():
    """Process multiple records and count redactions."""

    first = json.dumps({
        "body": {"password": "abc"}
    }).encode() + b"\n"

    second = json.dumps({
        "body": "contact a@b.com"
    }).encode() + b"\n"

    status, output, errors = run_stream(first + second)

    rows = [
        json.loads(line)
        for line in output.splitlines()
    ]

    assert status == 0
    assert rows[0]["body"]["password"] == "****"
    assert "a@b.com" not in rows[1]["body"]

    assert "secret-fields: 1" in errors
    assert "email: 1" in errors
    assert "records: 2; failed: 0" in errors


def test_malformed_input_does_not_leak_and_processing_continues():
    """Reject malformed JSON and continue processing."""

    secret = b'{"body":"secret-value", broken}\n'
    valid = b'{"body":{"password":"pass"}}\n'

    status, output, errors = run_stream(secret + valid)

    rows = [
        json.loads(line)
        for line in output.splitlines()
    ]

    assert status == 1

    assert rows[0] == {
        "error": "redaction_failed"
    }

    assert rows[1]["body"]["password"] == "****"

    # Sensitive input must never appear in the output or logs.
    assert b"secret-value" not in output
    assert "secret-value" not in errors

    assert "record 1" in errors


def test_non_object_and_invalid_unicode_fail_closed():
    """Reject invalid record types and invalid UTF-8."""

    status, output, errors = run_stream(
        b'[1,2]\n\xff\n'
    )

    assert status == 1

    assert output == (
        b'{"error":"redaction_failed"}\n' * 2
    )

    assert "failed: 2" in errors


def test_oversized_line_does_not_leak():
    """Reject oversized records without exposing their contents."""

    data = (
        b'XXXXPRIVATEPASSWORDXXXX\n'
        b'{"body":{"password":"123"}}\n'
    )

    status, output, errors = run_stream(
        data,
        max_line_bytes=10,
    )

    assert status == 1

    assert output == (
        b'{"error":"redaction_failed"}\n' * 2
    )

    assert "PRIVATEPASSWORD" not in errors
    assert "oversized" in errors


def test_no_final_newline():
    """Process the last record even without a trailing newline."""

    data = b'{"body":{"password":"secret"}}'

    status, output, errors = run_stream(data)

    assert status == 0

    result = json.loads(output)

    assert result["body"]["password"] == "****"


def test_rules_failure_returns_error_without_echo(capsys):
    """Reject missing rules before processing traffic."""

    status = main([
        "--rules",
        "nonexistent.yaml",
    ])

    captured = capsys.readouterr()

    assert status == 2

    assert (
        "Unable to load valid redaction rules"
        in captured.err
    )


def test_file_argument(tmp_path, monkeypatch):
    """Read NDJSON from a file through the CLI."""

    source = tmp_path / "input.ndjson"

    source.write_text(
        '{"body":{"password":"123"}}\n',
        encoding="utf-8",
    )

    class FakeStdout:
        def __init__(self):
            self.buffer = io.BytesIO()

    import redactor.cli as cli

    fake = FakeStdout()

    monkeypatch.setattr(
        cli.sys,
        "stdout",
        fake,
    )

    status = main([
        "--rules",
        str(RULES_PATH),
        str(source),
    ])

    assert status == 0

    result = json.loads(
        fake.buffer.getvalue()
    )

    assert result["body"]["password"] == "****"



def test_query_parameters_redacted():
    """Redact secrets inside URL query parameters."""
    record = {
        "path": "/reset?token=abc123&email=gina%40example.com",
        "body": None
    }

    status, data, _ = run_stream(
        (json.dumps(record) + "\n").encode()
    )

    output = json.loads(data)

    assert status == 0
    assert "abc123" not in output["path"]
    assert "gina%40example.com" not in output["path"]
    assert "sha256" in output["path"]



def test_urlencoded_password_redacted():
    """Redact sensitive values in form-urlencoded bodies."""
    record = {
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        "body": (
            "email=bob%40example.com"
            "&password=hunter2"
            "&remember=on"
        )
    }

    status, data, _ = run_stream(
        (json.dumps(record) + "\n").encode()
    )

    output = json.loads(data)

    assert status == 0
    assert "hunter2" not in output["body"]
    assert "bob%40example.com" not in output["body"]
    assert "remember=on" in output["body"]
    assert "password=%2A%2A%2A%2A" in output["body"]



def test_urlencoded_idempotent():
    """Redacting form data and URLs twice gives identical results."""
    rules = load_and_validate_rules(RULES_PATH)
    engine = RedactionEngine(rules)

    record = {
        "path": "/reset?token=abc123&email=gina%40example.com",
        "body": "email=bob%40example.com&password=hunter2"
    }

    first = engine.redact_transaction(record)
    second = engine.redact_transaction(first)

    assert first == second


def test_base64url_jwt_redacted_in_embedded_body():
    """Regression test: JWTs containing Base64URL '-' and '_' must be redacted."""
    token = (
        "eyJhbGciOiJIUzI1NiJ9."
        "eyJhIjoiPz8_In0."
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    )

    record = {
        "response": {
            "body": json.dumps({
                "access_token": token
            })
        }
    }

    status, data, _ = run_stream(
        (json.dumps(record) + "\n").encode()
    )

    assert status == 0
    assert token not in data.decode()



def test_password_inside_free_text_is_masked():
    """Mask a password appearing inside an ordinary sentence."""
    record = {
        "body": {
            "debug": "login attempt password=hunter2 for user=zed"
        }
    }

    status, data, _ = run_stream(
        (json.dumps(record) + "\n").encode()
    )

    result = json.loads(data)

    assert status == 0
    assert result["body"]["debug"] == (
        "login attempt password=**** for user=zed"
    )


def test_binary_like_text_is_preserved():
    """Do not treat ordinary Base64 text as form data."""
    record = {
        "response": {
            "headers": {
                "Content-Type": "application/octet-stream"
            },
            "body": "UEsDBBQAAAAIAA=="
        }
    }

    status, data, _ = run_stream(
        (json.dumps(record) + "\n").encode()
    )

    result = json.loads(data)

    assert status == 0
    assert result["response"]["body"] == "UEsDBBQAAAAIAA=="


def test_real_form_data_is_still_redacted():
    """Redact sensitive values in a declared form body."""
    record = {
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        "body": "email=bob%40example.com&password=hunter2&remember=on"
    }

    status, data, _ = run_stream(
        (json.dumps(record) + "\n").encode()
    )

    result = json.loads(data)

    assert status == 0
    assert "hunter2" not in result["body"]
    assert "bob%40example.com" not in result["body"]
    assert "remember=on" in result["body"]


def test_content_type_is_case_insensitive():
    """Recognize Content-Type regardless of capitalization."""
    record = {
        "headers": {
            "content-type": (
                "Application/X-Www-Form-Urlencoded; charset=UTF-8"
            )
        },
        "body": "password=hunter2&remember=on"
    }

    status, data, _ = run_stream(
        (json.dumps(record) + "\n").encode()
    )

    result = json.loads(data)

    assert status == 0
    assert "hunter2" not in result["body"]
    assert "remember=on" in result["body"]


def test_unrelated_text_with_equals_is_preserved():
    """Preserve non-sensitive strings containing equals signs."""
    record = {
        "body": {
            "message": "formula x=10 and y=20",
            "encoded": "abc123=="
        }
    }

    status, data, _ = run_stream(
        (json.dumps(record) + "\n").encode()
    )

    result = json.loads(data)

    assert status == 0
    assert result["body"]["message"] == "formula x=10 and y=20"
    assert result["body"]["encoded"] == "abc123=="


def test_embedded_password_redaction_is_idempotent():
    """Running redaction twice must produce the same result."""
    rules = load_and_validate_rules(RULES_PATH)
    engine = RedactionEngine(rules)

    record = {
        "body": {
            "debug": "login attempt password=hunter2 for user=zed"
        },
        "response": {
            "headers": {
                "Content-Type": "application/octet-stream"
            },
            "body": "UEsDBBQAAAAIAA=="
        }
    }

    first = engine.redact_transaction(record)
    second = engine.redact_transaction(first)

    assert first == second
    assert "hunter2" not in str(first)


def test_request_and_response_use_own_content_types():
    """Use separate Content-Type headers for request and response."""
    record = {
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        "body": "password=hunter2&remember=on",
        "response": {
            "headers": {
                "Content-Type": "application/octet-stream"
            },
            "body": "UEsDBBQAAAAIAA=="
        }
    }

    status, data, _ = run_stream(
        (json.dumps(record) + "\n").encode()
    )

    result = json.loads(data)

    assert status == 0
    assert "hunter2" not in result["body"]
    assert result["response"]["body"] == "UEsDBBQAAAAIAA=="
