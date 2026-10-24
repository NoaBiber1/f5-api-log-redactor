
"""Stream NDJSON through the redaction engine, one record at a time."""

import argparse
import json
import sys
from contextlib import nullcontext

from .engine import RedactionEngine, RedactionError
from .rules import load_and_validate_rules


MAX_LINE_BYTES = 8 * 1024 * 1024
ERROR_RECORD = b'{"error":"redaction_failed"}\n'


def reject_constant(value):
    """Reject non-standard JSON constants such as NaN and Infinity."""
    raise ValueError("Invalid JSON constant")


def reject_duplicate_keys(pairs):
    """Prevent duplicate JSON keys from silently overwriting data."""
    result = {}

    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key")
        result[key] = value

    return result


def process_stream(
    source,
    output,
    errors,
    engine,
    max_line_bytes=MAX_LINE_BYTES,
):
    """Redact NDJSON without buffering the entire input."""

    failed = 0
    total = 0

    while True:
        # Read at most one bounded NDJSON record (+1 byte to detect overflow).
        # This prevents an unbounded line from exhausting memory.
        raw = source.readline(max_line_bytes + 1)

        if not raw:
            break

        total += 1

        # Discard oversized records without storing their contents.
        if len(raw) > max_line_bytes:
            while raw and not raw.endswith(b"\n"):
                raw = source.readline(65536)

            output.write(ERROR_RECORD)
            failed += 1

            errors.write(
                f"record {total}: oversized input; redaction failed\n"
            )
            continue

        # Snapshot counters so failed records cannot affect redaction statistics.
        previous_counts = engine.counts.copy()

        try:
            # Decode and parse a single JSON transaction.
            
            transaction = json.loads(
            raw.decode("utf-8"),
            parse_constant=reject_constant,
            object_pairs_hook=reject_duplicate_keys,
        )


            if not isinstance(transaction, dict):
                raise ValueError("Expected a JSON object")

            # Redact sensitive information.
            result = engine.redact_transaction(transaction)

            # Serialize the redacted transaction as one NDJSON line.
            encoded = (
                json.dumps(
                    result,
                    ensure_ascii=False,
                    separators=(",", ":"),
                    allow_nan=False,
                ) + "\n"
            ).encode("utf-8")

        except (
            ValueError,
            UnicodeError,
            TypeError,
            RecursionError,
            OverflowError,
            RedactionError,
        ):
            # Fail closed: replace the entire record with a safe error response.
            # Never fall back to the original potentially sensitive input.
            engine.counts.clear()
            engine.counts.update(previous_counts)

            
            encoded = ERROR_RECORD
            failed += 1

            errors.write(
                f"record {total}: invalid or unsafe input; "
                "redaction failed\n"
            )

        # Write each record immediately.
        output.write(encoded)

    # Print redaction statistics to stderr.
    for name, count in sorted(engine.counts.items()):
        errors.write(f"{name}: {count}\n")

    errors.write(
        f"records: {total}; failed: {failed}\n"
    )

    return 1 if failed else 0


def main(argv=None):
    """Parse command-line arguments and start processing."""

    parser = argparse.ArgumentParser(
        description="Redact sensitive data in NDJSON traffic logs"
    )

    parser.add_argument(
        "--rules",
        default="rules.yaml",
        help="Path to the YAML rules configuration",
    )

    parser.add_argument(
        "input_file",
        nargs="?",
        help="NDJSON input file (default: stdin)",
    )

    args = parser.parse_args(argv)

    # Load and validate rules before processing any traffic.
    try:
        rules = load_and_validate_rules(args.rules)
        engine = RedactionEngine(rules)

    except (OSError, ValueError, TypeError):
        print(
            "Unable to load valid redaction rules",
            file=sys.stderr,
        )
        return 2

    try:
        # Use a file if provided; otherwise read from stdin.
        stream = (
            open(args.input_file, "rb")
            if args.input_file
            else nullcontext(sys.stdin.buffer)
        )

        with stream as source:
            return process_stream(
                source,
                sys.stdout.buffer,
                sys.stderr,
                engine,
            )

    except OSError:
        print(
            "Unable to read input or write output",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())



def test_password_inside_free_text_is_masked():
    """A password inside a debug sentence must not leak."""
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
    assert "hunter2" not in result["body"]["debug"]
    assert result["body"]["debug"] == (
        "login attempt password=**** for user=zed"
    )


def test_binary_like_text_is_preserved():
    """Unrelated Base64-like content must not be parsed as a form."""
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
    """A declared URL-encoded request body must be protected."""
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

    result = json.loads(data)
    body = result["body"]

    assert status == 0
    assert "hunter2" not in body
    assert "bob%40example.com" not in body
    assert "remember=on" in body
    assert "password=%2A%2A%2A%2A" in body


def test_content_type_is_case_insensitive():
    """Content-Type header names must be case-insensitive."""
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
    """Equals signs alone must not trigger form parsing."""
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
    """Running the engine twice must not change masked debug text."""
    rules = load_and_validate_rules(RULES_PATH)
    engine = RedactionEngine(rules)

    record = {
        "body": {
            "debug": "login attempt password=hunter2 for user=zed",
            "message": "formula x=10"
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
    assert first["response"]["body"] == "UEsDBBQAAAAIAA=="


def test_request_and_response_use_own_content_types():
    """Request form parsing must not affect the response body."""
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
