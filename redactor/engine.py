
"""Recursive, rule-driven redaction of HTTP transactions."""

from collections import Counter
import hashlib
import json
import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .rules import validate_rules


class RedactionError(ValueError):
    """Raised when a transaction cannot be processed safely."""


class RedactionEngine:
    """Apply configured key and value redaction rules."""

    # Matches key=value pairs embedded in ordinary text.
    # The key must still match a configured sensitive key rule.
    ASSIGNMENT_PATTERN = re.compile(
        r"""(?<![\w-])([A-Za-z_][\w-]*)\s*=\s*(["']?)([^\s&;,"']+)\2"""
    )

    HASH_MARKER = re.compile(r"sha256:[0-9a-f]{64}\Z")

    def __init__(self, rules: dict):
        """Initialize the engine with validated rules.

        Compile regex patterns once and initialize redaction counters
        for tracking successful rule applications.
        """
        validate_rules(rules)

        self.settings = rules["settings"]
        self.counts = Counter()

        self.key_rules = [
            (
                rule,
                re.compile(rule["match"]["regex"])
                if "regex" in rule["match"]
                else None,
            )
            for rule in rules["key_rules"]
        ]

        self.value_rules = [
            (rule, re.compile(rule["pattern"]))
            for rule in rules["value_rules"]
        ]

    @staticmethod
    def valid_luhn(text: str) -> bool:
        """Validate 13-19 digit card numbers with optional separators."""
        digits = re.sub(r"[ -]", "", text)

        if not (
            digits.isascii()
            and digits.isdigit()
            and 13 <= len(digits) <= 19
        ):
            return False

        total = 0

        for index, character in enumerate(reversed(digits)):
            digit = int(character)

            if index % 2:
                digit *= 2
                if digit > 9:
                    digit -= 9

            total += digit

        return total % 10 == 0

    def _apply(self, text: str, action: str) -> str:
        """Apply a mask, hash, partial mask, or removal."""

        if action == "mask":
            return self.settings["mask"]["replacement"]

        if action == "remove":
            return ""
        # Preserve existing SHA-256 markers to maintain idempotency.
        if action == "hash":
            if self.HASH_MARKER.fullmatch(text):
                return text

            digest = hashlib.sha256(
                text.encode("utf-8")
            ).hexdigest()

            return "sha256:" + digest

        if action == "partial":
            keep = self.settings["partial"]["keep_last"]
            fill = self.settings["partial"]["fill"]

            if keep:
                prefix = text[:-keep]
                suffix = text[-keep:]
            else:
                prefix = text
                suffix = ""

            if prefix and all(
                character == fill for character in prefix
            ):
                return text

            return fill * len(prefix) + suffix

        raise RedactionError("Unsupported redaction action")

    def _match_key(self, key: str, scope: str):
        """Return the first applicable key rule."""

        for rule, regex in self.key_rules:
            if rule["scope"] not in (scope, "any"):
                continue

            if regex is not None:
                matched = regex.search(key) is not None
            else:
                names = rule["match"]["exact"]

                if scope == "headers":
                    matched = any(
                        key.casefold() == name.casefold()
                        for name in names
                    )
                else:
                    matched = key in names

            if matched:
                return rule

        return None

    def _already_redacted(self, text: str, action: str) -> bool:
        """Avoid changing an existing redaction marker."""

        if action == "mask":
            return text == self.settings["mask"]["replacement"]

        if action == "hash":
            return self.HASH_MARKER.fullmatch(text) is not None

        if action == "partial":
            keep = self.settings["partial"]["keep_last"]
            fill = self.settings["partial"]["fill"]

            prefix = text[:-keep] if keep else text

            return bool(prefix) and all(
                character == fill for character in prefix
            )

        return False

    def _redact_text(self, text: str) -> str:
        """Redact sensitive text while retaining surrounding content."""

        candidates = []

        # Recognize sensitive key=value assignments in free text.
        for match in self.ASSIGNMENT_PATTERN.finditer(text):
            key = match.group(1)
            rule = self._match_key(key, "body")

            if rule is None:
                continue

            candidates.append(
                (
                    match.start(3),
                    -1,
                    match.end(3),
                    rule,
                    match.group(3),
                )
            )

        # Apply configured value rules such as email, JWT, and PAN.
        for priority, (rule, pattern) in enumerate(self.value_rules):
            for match in pattern.finditer(text):
                original = match.group(0)

                if not original:
                    continue

                if (
                    rule.get("validator") == "luhn"
                    and not self.valid_luhn(original)
                ):
                    continue

                candidates.append(
                    (
                        match.start(),
                        priority,
                        match.end(),
                        rule,
                        original,
                    )
                )

        # Resolve overlapping matches deterministically:
        # prefer the leftmost match, then key rules over value rules.
        candidates.sort(
            key=lambda item: (item[0], item[1])
        )

        parts = []
        cursor = 0

        for start, _, end, rule, original in candidates:
            if start < cursor:
                continue

            action = rule["action"]
            replacement = self._apply(original, action)

            parts.append(text[cursor:start])
            parts.append(replacement)

            if replacement != original:
                self.counts[rule["name"]] += 1

            cursor = end

        parts.append(text[cursor:])

        return "".join(parts)

    def _redact_parameters(self, text: str) -> str:
        """Redact URL-encoded form/query parameters."""

        parameters = parse_qsl(
            text,
            keep_blank_values=True,
        )

        result = []

        for key, value in parameters:
            rule = self._match_key(key, "body")

            if rule is None:
                redacted = self._redact_text(value)
                result.append((key, redacted))
                continue

            if rule["action"] == "remove":
                self.counts[rule["name"]] += 1
                continue

            redacted = self._apply(
                value,
                rule["action"],
            )

            if redacted != value:
                self.counts[rule["name"]] += 1

            result.append((key, redacted))

        return urlencode(result)

    def _redact_path(self, text: str) -> str:
        """Redact a URL path and its query parameters."""

        if "?" not in text:
            return self._redact_text(text)

        parts = urlsplit(text)

        query = self._redact_parameters(parts.query)

        return urlunsplit(
            (
                parts.scheme,
                parts.netloc,
                self._redact_text(parts.path),
                query,
                self._redact_text(parts.fragment),
            )
        )

    @staticmethod
    def _content_type(headers) -> str:
        """Read Content-Type case-insensitively."""

        if not isinstance(headers, dict):
            return ""

        for key, value in headers.items():
            if (
                isinstance(key, str)
                and key.casefold() == "content-type"
                and isinstance(value, str)
            ):
                return value.split(";", 1)[0].strip().lower()

        return ""

    def _redact_string(
        self,
        text: str,
        content_type: str = "",
    ) -> str:
        """Redact embedded JSON, declared form data, or free text."""

        # Decode JSON carried as a string inside the transaction.
        if text.lstrip().startswith(("{", "[")):
            try:
                decoded = json.loads(text)
            except (ValueError, UnicodeError):
                pass
            else:
                if isinstance(decoded, (dict, list)):
                    redacted = self._walk(decoded, "body")

                    return json.dumps(
                        redacted,
                        ensure_ascii=False,
                        separators=(",", ":"),
                    )

        # Only a declared form body is parsed as a form.
        if content_type == "application/x-www-form-urlencoded":
            return self._redact_parameters(text)

        # Ordinary strings are preserved except for redaction matches.
        return self._redact_text(text)

    def _redact_field(self, value, rule):
        """Apply a key rule to the entire field value."""

        if isinstance(value, str):
            original = value
        else:
            original = json.dumps(
                value,
                ensure_ascii=False,
            )

        action = rule["action"]

        if self._already_redacted(original, action):
            return original

        redacted = self._apply(original, action)

        if redacted != original:
            self.counts[rule["name"]] += 1

        return redacted

    def _walk(self, value, scope: str):
        """Recursively process nested dictionaries and arrays."""

        if isinstance(value, list):
            return [
                self._walk(item, scope)
                for item in value
            ]

        if isinstance(value, dict):
            result = {}

            for key, item in value.items():
                if not isinstance(key, str):
                    raise RedactionError(
                        "Unsupported non-string key"
                    )

                rule = self._match_key(key, scope)

                if rule is not None:
                    if rule["action"] == "remove":
                        self.counts[rule["name"]] += 1
                        continue

                    result[key] = self._redact_field(item, rule)
                    continue

                result[key] = self._walk(item, scope)

            return result

        if isinstance(value, str):
            return self._redact_string(value)

        return value

    def _walk_http(self, transaction: dict):
        """Process HTTP request and response envelope semantics."""

        result = {}

        content_type = self._content_type(
            transaction.get("headers")
        )

        for key, value in transaction.items():
            if not isinstance(key, str):
                raise RedactionError(
                    "Unsupported non-string key"
                )

            if key == "headers":
                result[key] = self._walk(
                    value,
                    "headers",
                )

            elif key == "path" and isinstance(value, str):
                result[key] = self._redact_path(value)

            elif key == "body" and isinstance(value, str):
                result[key] = self._redact_string(
                    value,
                    content_type,
                )
            # Process responses independently so request Content-Type
            # does not affect response body parsing.
            elif key == "response" and isinstance(value, dict):
                result[key] = self._walk_http(value)

            else:
                result[key] = self._walk(
                    value,
                    "body",
                )

        return result

    def redact_transaction(self, transaction: dict) -> dict:
        """Return a redacted copy, or fail without exposing input."""

        if not isinstance(transaction, dict):
            raise RedactionError(
                "Transaction must be a JSON object"
            )
        # Keep redaction statistics transactional:
        # failed records must not contribute to rule counters.
        previous_counts = self.counts.copy()

        try:
            return self._walk_http(transaction)

        except (
            ValueError,
            TypeError,
            UnicodeError,
            RecursionError,
            OverflowError,
        ):
            self.counts.clear()
            self.counts.update(previous_counts)

            raise RedactionError(
                "Transaction cannot be redacted safely"
            ) from None
