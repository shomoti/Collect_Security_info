from __future__ import annotations

from typing import Any


REQUIRED_RULE_KEYS = ("title", "logsource", "detection", "condition")


def validate_sigma_rules(
    rules: list[dict[str, Any]],
    target_backends: list[str],
    drop_invalid_rules: bool,
) -> tuple[list[dict[str, Any]], list[str]]:
    valid_rules: list[dict[str, Any]] = []
    errors: list[str] = []

    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            errors.append(f"sigma_rules[{idx}] must be object")
            continue
        missing = [k for k in REQUIRED_RULE_KEYS if k not in rule]
        if missing:
            errors.append(f"sigma_rules[{idx}] missing keys: {missing}")
            continue
        if not isinstance(rule.get("logsource"), dict):
            errors.append(f"sigma_rules[{idx}].logsource must be object")
            continue
        if not isinstance(rule.get("detection"), dict):
            errors.append(f"sigma_rules[{idx}].detection must be object")
            continue
        if not str(rule.get("condition", "")).strip():
            errors.append(f"sigma_rules[{idx}].condition must be non-empty")
            continue

        # Lightweight backend gate: ensure selection-like keys exist for practical conversion.
        if target_backends:
            detection = rule.get("detection", {})
            if not any(k.startswith("selection") or k == "keywords" for k in detection.keys()):
                errors.append(f"sigma_rules[{idx}] may not be convertible for backends={target_backends}")
                continue

        valid_rules.append(rule)

    if drop_invalid_rules:
        return valid_rules, errors
    return rules, errors
