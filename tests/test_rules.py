
"""Tests for rule configuration loading and validation."""

from copy import deepcopy
from pathlib import Path

import pytest

from redactor.rules import (
    RulesConfigError,
    load_and_validate_rules,
    validate_rules,
)


@pytest.fixture
def valid_rules():
    """Create a valid rules configuration for testing."""
    return {
        "version": 1,
        "settings": {
            "mask": {"replacement": "****"},
            "partial": {"keep_last": 4, "fill": "*"},
            "hash": {"algorithm": "sha256"},
        },
        "key_rules": [
            {
                "name": "secret",
                "scope": "body",
                "match": {"exact": ["password"]},
                "action": "mask",
            }
        ],
        "value_rules": [
            {
                "name": "email",
                "pattern": r"\w+@\w+\.com",
                "action": "hash",
            },
            {
                "name": "card",
                "pattern": r"\d+",
                "action": "partial",
                "validator": "luhn",
            },
        ],
    }


def test_valid_rules(valid_rules):
    """Ensure valid configuration passes validation."""
    assert validate_rules(valid_rules) is None


def test_load_original_rules():
    """Ensure the original F5 rules file loads successfully."""
    path = Path(__file__).resolve().parents[1] / "rules.yaml"

    assert path.exists(), "Original F5 rules.yaml is missing"

    loaded = load_and_validate_rules(path)

    assert loaded["version"] == 1
    assert len(loaded["key_rules"]) == 5
    assert len(loaded["value_rules"]) == 4


@pytest.mark.parametrize("mutation", [
    lambda r: r.update(version=2),
    lambda r: r.update(settings=None),
    lambda r: r["settings"]["partial"].update(keep_last=True),
    lambda r: r["settings"]["hash"].update(algorithm="md5"),
    lambda r: r["key_rules"][0].update(scope="unknown"),
    lambda r: r["key_rules"][0].update(action="delete_everything"),
    lambda r: r["key_rules"][0].update(match={"exact": [], "regex": ".*"}),
    lambda r: r["key_rules"][0].update(match={"exact": [123]}),
    lambda r: r["key_rules"][0].update(match={"regex": "("}),
    lambda r: r["value_rules"][0].update(pattern="["),
    lambda r: r["value_rules"][1].update(validator="other"),
    lambda r: r["value_rules"][0].update(name="secret"),
    lambda r: r.update(key_rules="not a list"),
])
def test_reject_invalid_rules(valid_rules, mutation):
    """Ensure invalid rule configurations are rejected."""
    changed = deepcopy(valid_rules)
    mutation(changed)

    with pytest.raises(RulesConfigError):
        validate_rules(changed)


def test_missing_file_error_is_safe(tmp_path):
    """Ensure missing files produce a controlled error."""
    with pytest.raises(
        RulesConfigError,
        match="Unable to read rules configuration",
    ):
        load_and_validate_rules(tmp_path / "missing.yaml")


def test_malformed_yaml_error_is_safe(tmp_path):
    """Ensure YAML errors do not reveal sensitive contents."""
    path = tmp_path / "bad.yaml"

    path.write_text(
        'secret: "do-not-log-me"\ninvalid: [',
        encoding="utf-8",
    )

    with pytest.raises(RulesConfigError) as exc:
        load_and_validate_rules(path)

    assert "do-not-log-me" not in str(exc.value)
