
"""Rule-driven redaction of one HTTP transaction at a time."""

from collections import Counter
import hashlib
import json
import re

from .rules import validate_rules


class RedactionError(ValueError):
    """An input could not be processed safely; do not emit the original input."""


class RedactionEngine:
    """Apply validated key and value rules in configuration order."""

    def __init__(self, rules: dict):
        validate_rules(rules)
        self.settings = rules["settings"]

        # Compile matching patterns once.
        self.key_rules = [
            (
                rule,
                re.compile(rule["match"]["regex"])
                if "regex" in rule["match"]
                else None
            )
            for rule in rules["key_rules"]
        ]

        self.value_rules = [
            (rule, re.compile(rule["pattern"]))
            for rule in rules["value_rules"]
        ]

        self.counts = Counter()

    @staticmethod
    def valid_luhn(text: str) -> bool:
        """Validate a 13-19 digit card number, ignoring spaces and hyphens."""
        digits = re.sub(r"[ -]", "", text)

        if not (
            digits.isascii()
            and digits.isdigit()
            and 13 <= len(digits) <= 19
        ):
            return False

        total = 0

        for index, char in enumerate(reversed(digits)):
            number = int(char)

            if index % 2:
                number *= 2
                if number > 9:
                    number -= 9

            total += number

        return total % 10 == 0

    def _apply(self, text: str, action: str) -> str:
        """Apply a redaction action to a matched value."""

        if action == "mask":
            return self.settings["mask"]["replacement"]

        if action == "remove":
            return ""

        if action == "hash":
            # Avoid hashing an already redacted value.
            if re.fullmatch(r"sha256:[0-9a-f]{64}", text):
                return text

            digest = hashlib.sha256(
                text.encode("utf-8")
            ).hexdigest()

            return "sha256:" + digest

        # Partial masking keeps the final N characters.
        keep = self.settings["partial"]["keep_last"]
        fill = self.settings["partial"]["fill"]

        hidden = fill * max(0, len(text) - keep)
        suffix = text[-keep:] if keep else ""

        return hidden + suffix

    def _match_key(self, key: str, scope: str):
        """Find the first matching key rule."""

        for rule, regex in self.key_rules:
            if rule["scope"] not in (scope, "any"):
                continue

            if regex is not None:
                matched = regex.search(key) is not None
            else:
                names = rule["match"]["exact"]

                # HTTP header names are case-insensitive.
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

    def _redact_text(self, text: str) -> str:
        """Match original text without reprocessing replacements."""

        candidates = []

        for priority, (rule, regex) in enumerate(self.value_rules):
            for match in regex.finditer(text):
                original = match.group(0)

                if not original:
                    continue

                # Validate possible credit card numbers.
                if rule.get("validator") == "luhn":
                    if not self.valid_luhn(original):
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

        # Earlier matches win; rule order resolves overlaps.
        candidates.sort(
            key=lambda item: (item[0], item[1])
        )

        output = []
        cursor = 0

        for start, _, end, rule, original in candidates:
            if start < cursor:
                continue

            replacement = self._apply(
                original, rule["action"]
            )

            output.append(text[cursor:start])
            output.append(replacement)

            if replacement != original:
                self.counts[rule["name"]] += 1

            cursor = end

        output.append(text[cursor:])

        return "".join(output)

    def _redact_string(self, text: str) -> str:
        """Process embedded JSON or redact free text."""

        if text.lstrip().startswith(("{", "[")):
            try:
                embedded = json.loads(text)
            except (ValueError, UnicodeError):
                pass
            else:
                if isinstance(embedded, (dict, list)):
                    redacted = self._walk(
                        embedded, "body"
                    )

                    return json.dumps(
                        redacted,
                        ensure_ascii=False,
                        separators=(",", ":")
                    )

        return self._redact_text(text)

    def _walk(self, value, scope: str):
        """Recursively process dictionaries, arrays and strings."""

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
                        "Unsupported input structure"
                    )

                key_rule = self._match_key(key, scope)

                if key_rule is not None:
                    action = key_rule["action"]

                    # Remove the entire field.
                    if action == "remove":
                        self.counts[key_rule["name"]] += 1
                        continue

                    raw = (
                        item
                        if isinstance(item, str)
                        else json.dumps(
                            item,
                            ensure_ascii=False
                        )
                    )

                    # Avoid masking already masked values.
                    if (
                        action == "mask"
                        and raw == self.settings["mask"]["replacement"]
                    ):
                        result[key] = raw
                        continue

                    # Avoid applying partial masking twice.
                    if action == "partial":
                        fill = self.settings["partial"]["fill"]
                        keep = self.settings["partial"]["keep_last"]

                        prefix = raw[:-keep] if keep else raw

                        if (
                            prefix
                            and prefix == fill * len(prefix)
                        ):
                            result[key] = raw
                            continue

                    replacement = self._apply(
                        raw, action
                    )

                    if replacement != raw:
                        self.counts[key_rule["name"]] += 1

                    result[key] = replacement

                else:
                    # Header scope applies only to HTTP envelopes.
                    child_scope = (
                        "headers"
                        if key.lower() == "headers"
                        and scope == "transaction"
                        else "body"
                    )

                    if (
                        key == "response"
                        and scope == "transaction"
                        and isinstance(item, dict)
                    ):
                        result[key] = self._walk_response(item)
                    else:
                        result[key] = self._walk(
                            item, child_scope
                        )

            return result

        if isinstance(value, str):
            return self._redact_string(value)

        # Preserve numeric, boolean and null values.
        return value

    def _walk_response(self, response: dict):
        """Process response headers and body separately."""

        result = {}

        for key, value in response.items():
            if key == "headers":
                result[key] = self._walk(
                    value, "headers"
                )
            else:
                result[key] = self._walk(
                    {key: value}, "body"
                )[key]

        return result

    def redact_transaction(self, transaction: dict) -> dict:
        """Return a redacted copy of one HTTP transaction."""

        if not isinstance(transaction, dict):
            raise RedactionError(
                "Transaction must be an object"
            )

        try:
            return self._walk(
                transaction, "transaction"
            )

        except (
            RecursionError,
            UnicodeError,
            TypeError,
            ValueError,
            OverflowError,
        ):
            # Never return unprocessed input after failure.
            raise RedactionError(
                "Transaction cannot be processed safely"
            ) from None
