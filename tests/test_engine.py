
"""Tests for the redaction engine using F5's rules."""

import json
from pathlib import Path

import pytest

from redactor.engine import RedactionEngine, RedactionError
from redactor.rules import load_and_validate_rules


@pytest.fixture
def engine():
    """Create an engine with the original F5 configuration."""
    config = Path(__file__).resolve().parents[1] / "rules.yaml"
    return RedactionEngine(load_and_validate_rules(config))


def test_nested_headers_and_arrays(engine):
    """Redact sensitive data recursively in HTTP headers and nested arrays."""
    data = {
        "headers": {
            "authorization": "Bearer secret",
            "X-Api-Key": "abc"
        },
        "body": {
            "users": [
                {"password": "abc", "email": "a@b.com"},
                {"cvv": "123", "nested": {"token": "secret"}}
            ]
        }
    }

    out = engine.redact_transaction(data)

    assert out["headers"]["authorization"] == "****"
    assert out["headers"]["X-Api-Key"].startswith("sha256:")
    assert out["body"]["users"][0]["password"] == "****"
    assert out["body"]["users"][0]["email"].startswith("sha256:")
    assert "cvv" not in out["body"]["users"][1]

    # Verify the original input was not modified.
    assert data["body"]["users"][0]["password"] == "abc"


def test_value_inside_free_text(engine):
    """Redact sensitive patterns appearing inside ordinary text."""
    out = engine.redact_transaction({
        "body": "email a@b.com, key sk_live_abc123"
    })

    assert "a@b.com" not in out["body"]
    assert "sk_live_abc123" not in out["body"]
    assert "email " in out["body"]


def test_luhn_validation(engine):
    """Redact Luhn-valid card numbers while preserving invalid candidates."""
    assert engine.valid_luhn("4111111111111111")
    assert not engine.valid_luhn("4111111111111112")

    result = engine.redact_transaction({
        "body": "valid 4111111111111111 invalid 4111111111111112"
    })

    assert "4111111111111111" not in result["body"]
    assert "4111111111111112" in result["body"]


def test_embedded_json_and_response_headers(engine):
    """Redact sensitive response headers and JSON embedded in strings."""
    data = {
        "response": {
            "headers": {"Set-Cookie": "secret"},
            "body": '{"user":{"password":"secret"}}'
        }
    }

    out = engine.redact_transaction(data)

    assert out["response"]["headers"]["Set-Cookie"] == "****"

    parsed = json.loads(out["response"]["body"])
    assert parsed["user"]["password"] == "****"


def test_non_json_body_and_scalars(engine):
    """Redact text values while preserving unrelated scalar data types."""
    out = engine.redact_transaction({
        "body": "email=a@b.com",
        "status": 200,
        "ok": True,
        "missing": None
    })

    assert "a@b.com" not in out["body"]
    assert out["status"] == 200
    assert out["ok"] is True
    assert out["missing"] is None


def test_idempotent(engine):
    """Ensure redacting a transaction twice produces the same result."""
    data = {
        "headers": {
            "Authorization": "Bearer abc",
            "X-Api-Key": "abc"
        },
        "body": {
            "password": "secret",
            "card_number": "4111111111111111",
            "email": "a@b.com",
            "cvv": "123"
        }
    }

    once = engine.redact_transaction(data)
    twice = engine.redact_transaction(once)

    assert once == twice


def test_rule_counters(engine):
    """Count each successful redaction under its matching rule name."""
    engine.redact_transaction({
        "body": {
            "password": "a",
            "another": "b@c.com"
        }
    })

    assert engine.counts["secret-fields"] == 1
    assert engine.counts["email"] == 1


def test_remove_value_rule(engine):
    """Remove matched sensitive text when a value rule uses remove."""
    config = Path(__file__).resolve().parents[1] / "rules.yaml"
    rules = load_and_validate_rules(config)
    rules["value_rules"][0]["action"] = "remove"

    result = RedactionEngine(rules).redact_transaction({
        "body": "hi a@b.com!"
    })

    assert result["body"] == "hi !"


def test_reject_non_object(engine):
    """Reject transactions that are not JSON objects."""
    with pytest.raises(RedactionError):
        engine.redact_transaction(["not a transaction"])


def test_formatted_credit_cards(engine):
    """Detect credit cards containing spaces or hyphens."""
    data = {
        "body": "4111 1111 1111 1111 and 4111-1111-1111-1111"
    }

    result = engine.redact_transaction(data)

    assert "4111 1111 1111 1111" not in result["body"]
    assert "4111-1111-1111-1111" not in result["body"]


def test_formatted_card_idempotency(engine):
    """Ensure formatted card numbers remain unchanged after re-redaction."""
    data = {
        "body": "pay with 4111 1111 1111 1111"
    }

    first = engine.redact_transaction(data)
    second = engine.redact_transaction(first)

    assert first == second


def test_overlapping_value_matches_do_not_double_replace(engine):
    """Ensure overlapping rules do not redact or count the same text twice."""
    config = Path(__file__).resolve().parents[1] / "rules.yaml"
    rules = load_and_validate_rules(config)

    rules["value_rules"].insert(
        0,
        {
            "name": "custom",
            "pattern": r"a@b\.com",
            "action": "mask"
        }
    )

    custom = RedactionEngine(rules)
    result = custom.redact_transaction({
        "body": "a@b.com"
    })

    assert result["body"] == "****"
    assert custom.counts["custom"] == 1
    assert custom.counts["email"] == 0


def test_headers_only_scope(engine):
    """Apply header-specific rules only to actual HTTP header fields."""
    data = {
        "headers": {"Authorization": "Bearer 123"},
        "body": {"Authorization": "ordinary"}
    }

    result = engine.redact_transaction(data)

    assert result["headers"]["Authorization"] == "****"
    assert result["body"]["Authorization"] == "ordinary"


def test_body_headers_named_field_not_http_headers(engine):
    """Do not treat a nested body field named 'headers' as HTTP headers."""
    data = {
        "body": {
            "headers": {
                "Authorization": "not an HTTP header"
            }
        }
    }

    out = engine.redact_transaction(data)

    assert (
        out["body"]["headers"]["Authorization"]
        == "not an HTTP header"
    )


def test_key_hash_idempotent(engine):
    """Avoid hashing an already-hashed sensitive header a second time."""
    data = {
        "headers": {"X-Api-Key": "abcd1234"}
    }

    first = engine.redact_transaction(data)

    assert first == engine.redact_transaction(first)


def test_key_remove_idempotent(engine):
    """Keep removed fields absent when redacting the same record again."""
    data = {
        "body": {
            "cvv": "123",
            "safe": "ok"
        }
    }

    first = engine.redact_transaction(data)

    assert first == engine.redact_transaction(first)
    assert "cvv" not in first["body"]


def test_masked_email_is_not_present(engine):
    """Ensure the original email address is absent from redacted output."""
    out = engine.redact_transaction({
        "body": "write a@b.com"
    })

    assert "a@b.com" not in out["body"]
