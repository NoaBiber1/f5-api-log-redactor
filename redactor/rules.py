
"""Load and validate the redaction rules configuration."""

import re
from pathlib import Path

import yaml

SUPPORTED_VERSION = 1
VALID_ACTIONS = {"mask", "partial", "hash", "remove"}
VALID_SCOPES = {"headers", "body", "any"}


class RulesConfigError(ValueError):
    """Raised when a redaction configuration cannot be used safely."""


def load_rules(file_path: str | Path) -> dict:
    """Read YAML data without validating its structure."""
    try:
        with Path(file_path).open("r", encoding="utf-8") as file:
            return yaml.safe_load(file)
    except (OSError, UnicodeError, yaml.YAMLError):
        # Never expose file contents in error messages.
        raise RulesConfigError("Unable to read rules configuration") from None


def validate_regex(pattern: object) -> None:
    """Check that a regex is a non-empty, valid string."""
    if not isinstance(pattern, str) or not pattern:
        raise RulesConfigError("Regex must be a non-empty string")

    # Validate regex patterns before processing traffic so invalid
    # rules cannot cause runtime redaction failures.
    try:
        re.compile(pattern)
    except re.error:
        raise RulesConfigError("Invalid regex in rules configuration") from None


def validate_key_match(match: object) -> None:
    """Require exactly one valid key-matching strategy."""
    if not isinstance(match, dict):
        raise RulesConfigError("Key rule match must be a dictionary")

    has_exact = "exact" in match
    has_regex = "regex" in match

    if has_exact == has_regex or set(match) - {"exact", "regex"}:
        raise RulesConfigError("Key rule must define exactly one of exact or regex")

    if has_exact:
        names = match["exact"]

        if not isinstance(names, list) or not names:
            raise RulesConfigError("Exact match must be a non-empty list")

        for name in names:
            if not isinstance(name, str) or not name.strip():
                raise RulesConfigError("Exact match names must be non-empty strings")
    else:
        validate_regex(match["regex"])


def validate_settings(settings: object) -> None:
    """Check settings for supported redaction actions."""
    if not isinstance(settings, dict):
        raise RulesConfigError("Settings must be a dictionary")

    if set(settings) != {"mask", "partial", "hash"}:
        raise RulesConfigError("Settings must define mask, partial, and hash")

    # Validate mask settings.
    mask = settings["mask"]

    if not isinstance(mask, dict) or set(mask) != {"replacement"}:
        raise RulesConfigError("Invalid mask settings")

    if not isinstance(mask["replacement"], str) or not mask["replacement"]:
        raise RulesConfigError("Mask replacement must be a non-empty string")

    # Validate partial masking settings.
    partial = settings["partial"]

    if not isinstance(partial, dict) or set(partial) != {"keep_last", "fill"}:
        raise RulesConfigError("Invalid partial settings")

    keep_last = partial["keep_last"]
    if type(keep_last) is not int or keep_last < 0:
        raise RulesConfigError("keep_last must be a non-negative integer")

    if not isinstance(partial["fill"], str) or not partial["fill"]:
        raise RulesConfigError("Partial fill must be a non-empty string")

    # Validate hashing settings.
    hashing = settings["hash"]

    if not isinstance(hashing, dict):
        raise RulesConfigError("Invalid hash settings")

    if hashing != {"algorithm": "sha256"}:
        raise RulesConfigError("Only SHA-256 hashing is supported")


def validate_rules(rules: object) -> None:
    """Validate the configuration structure and rule definitions."""
    if not isinstance(rules, dict):
        raise RulesConfigError("Rules configuration must be a dictionary")

    expected_fields = {"version", "settings", "key_rules", "value_rules"}

    # Reject unknown or missing fields to prevent configuration mistakes
    # from silently weakening redaction rules.
    if set(rules) != expected_fields:
        raise RulesConfigError("Invalid top-level configuration fields")

    if type(rules["version"]) is not int or rules["version"] != SUPPORTED_VERSION:
        raise RulesConfigError("Unsupported rules version")

    validate_settings(rules["settings"])

    # Track rule names to prevent duplicates.
    seen_names = set()

    for rule_type in ("key_rules", "value_rules"):
        rule_list = rules[rule_type]

        if not isinstance(rule_list, list):
            raise RulesConfigError(f"{rule_type} must be a list")

        for rule in rule_list:
            if not isinstance(rule, dict):
                raise RulesConfigError("Each rule must be a dictionary")

            name = rule.get("name")

            if not isinstance(name, str) or not name.strip():
                raise RulesConfigError("Every rule must have a non-empty name")

            if name in seen_names:
                raise RulesConfigError("Duplicate rule name")

            seen_names.add(name)

            if not isinstance(rule.get("action"), str):
                raise RulesConfigError("Unsupported rule action")

            if rule["action"] not in VALID_ACTIONS:
                raise RulesConfigError("Unsupported rule action")

            # Key rules match field or header names.
            if rule_type == "key_rules":
                expected = {"name", "action", "scope", "match"}

                if set(rule) != expected:
                    raise RulesConfigError("Invalid key rule fields")

                if not isinstance(rule["scope"], str):
                    raise RulesConfigError("Unsupported key rule scope")

                if rule["scope"] not in VALID_SCOPES:
                    raise RulesConfigError("Unsupported key rule scope")

                validate_key_match(rule["match"])

            # Value rules match string contents.
            else:
                allowed = {"name", "action", "pattern", "validator"}
                required = {"name", "action", "pattern"}

                if set(rule) - allowed or not required <= set(rule):
                    raise RulesConfigError("Invalid value rule fields")

                validate_regex(rule["pattern"])

                if "validator" in rule:
                    if rule["validator"] != "luhn":
                        raise RulesConfigError("Unsupported value validator")


def load_and_validate_rules(file_path: str | Path) -> dict:
    """Load rules and validate them before processing traffic."""
    rules = load_rules(file_path)
    validate_rules(rules)
    return rules
