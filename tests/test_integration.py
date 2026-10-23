
"""End-to-end integration tests for the redaction CLI."""

import json
import subprocess
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
RULES = ROOT / "rules.yaml"


def run_cli(data: bytes, input_file: Path | None = None):
    """Run the actual CLI in a separate Python process."""
    command = [
        sys.executable,
        "-m",
        "redactor.cli",
        "--rules",
        str(RULES),
    ]

    if input_file is not None:
        command.append(str(input_file))

    return subprocess.run(
        command,
        input=None if input_file else data,
        capture_output=True,
        cwd=ROOT,
        timeout=15,
        check=False,
    )


def as_ndjson(*records):
    """Encode dictionaries as newline-separated JSON records."""
    return b"".join(
        (
            json.dumps(record, ensure_ascii=False) + "\n"
        ).encode("utf-8")
        for record in records
    )


def test_cli_stdin_nested_rules_and_luhn():
    """Exercise stdin, rule matching, nesting and card validation."""
    valid_card = "4111111111111111"
    invalid_card = "4111111111111112"

    record = {
        "headers": {
            "Authorization": "Bearer top-secret",
        },
        "body": {
            "users": [
                {
                    "password": "hunter2",
                    "email": "alice@example.com",
                    "card_number": valid_card,
                    "cvv": "123",
                },
                {
                    "note": (
                        f"valid {valid_card}, "
                        f"invalid {invalid_card}"
                    )
                },
            ]
        },
    }

    result = run_cli(as_ndjson(record))

    assert result.returncode == 0, result.stderr.decode(
        "utf-8", errors="replace"
    )

    rows = [
        json.loads(line)
        for line in result.stdout.splitlines()
    ]

    assert len(rows) == 1
    output = rows[0]

    assert output["headers"]["Authorization"] == "****"

    user = output["body"]["users"][0]
    assert user["password"] == "****"
    assert user["email"].startswith("sha256:")
    assert user["card_number"].endswith("1111")
    assert valid_card not in user["card_number"]
    assert "cvv" not in user

    note = output["body"]["users"][1]["note"]
    assert valid_card not in note
    assert invalid_card in note

    assert b"hunter2" not in result.stdout
    assert b"alice@example.com" not in result.stdout

    errors = result.stderr.decode("utf-8")
    assert "auth-headers:" in errors
    assert "secret-fields:" in errors
    assert "credit-card:" in errors
    assert "records: 1; failed: 0" in errors


def test_cli_file_input_and_malformed_record(tmp_path):
    """A malformed record must not leak or stop file processing."""
    source = tmp_path / "sample.ndjson"

    source.write_bytes(
        as_ndjson({"body": {"password": "first-secret"}})
        + b'{"body":"hidden-value", broken}\n'
        + as_ndjson({"body": {"password": "last-secret"}})
    )

    result = run_cli(b"", input_file=source)

    assert result.returncode == 1

    rows = [
        json.loads(line)
        for line in result.stdout.splitlines()
    ]

    assert len(rows) == 3
    assert rows[0]["body"]["password"] == "****"
    assert rows[1] == {"error": "redaction_failed"}
    assert rows[2]["body"]["password"] == "****"

    assert b"hidden-value" not in result.stdout
    assert b"first-secret" not in result.stdout
    assert b"last-secret" not in result.stdout

    errors = result.stderr.decode("utf-8")
    assert "records: 3; failed: 1" in errors
    assert "hidden-value" not in errors


def test_cli_full_stream_idempotency():
    """Running CLI twice must produce byte-identical output."""
    data = as_ndjson(
        {
            "headers": {"Authorization": "Bearer secret"},
            "path": "/reset?token=abc123",
            "body": {
                "email": "test@example.com",
                "password": "hunter2",
                "card_number": "4111111111111111",
            },
        },
        {
            "headers": {
                "Content-Type": "application/x-www-form-urlencoded"
            },
            "body": "password=another-secret&remember=on",
            "response": {
                "headers": {
                    "Content-Type": "application/octet-stream"
                },
                "body": "UEsDBBQAAAAIAA==",
            },
        },
    )

    first = run_cli(data)
    second = run_cli(first.stdout)

    assert first.returncode == 0
    assert second.returncode == 0
    assert first.stdout == second.stdout

    assert b"hunter2" not in first.stdout
    assert b"abc123" not in first.stdout
    assert b"another-secret" not in first.stdout


@pytest.mark.parametrize(
    "invalid_record",
    [
        b"{invalid json}\n",
        b'{"body":{"password":"secret",'
        b'"password":"other"}}\n',
        b'{"value":NaN}\n',
        b'["not", "an", "object"]\n',
        b'{"body":"\xff"}\n',
    ],
)
def test_cli_rejects_unsafe_records(invalid_record):
    """Unsafe records must produce a safe error marker."""
    result = run_cli(invalid_record)

    assert result.returncode == 1
    assert result.stdout == b'{"error":"redaction_failed"}\n'
    assert b"secret" not in result.stdout

    errors = result.stderr.decode("utf-8")
    assert "record 1:" in errors
    assert "records: 1; failed: 1" in errors
