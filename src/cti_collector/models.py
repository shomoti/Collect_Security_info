from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import re


CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass
class ValidationResult:
    ok: bool
    errors: list[str]


REQUIRED_TOP_LEVEL = {
    "title",
    "source",
    "source_url",
    "published_at",
    "language",
    "tldr",
    "key_points",
    "content_type",
    "platforms",
    "cves",
    "products",
    "exploit_status",
    "iocs",
    "detection_notes",
    "recommended_actions",
    "tags",
    "impact_score",
    "impact_score_factors",
    "confidence",
    "confidence_score",
    "confidence_factors",
    "evidence",
    "sigma_rules",
}


IOC_REQUIRED_KEYS = {"ips", "domains", "urls", "hashes", "emails", "files", "registry", "mutexes"}


def validate_llm_output(payload: dict[str, Any], allowed_tags: set[str]) -> ValidationResult:
    errors: list[str] = []

    missing = REQUIRED_TOP_LEVEL - set(payload.keys())
    if missing:
        errors.append(f"missing keys: {sorted(missing)}")

    tags = payload.get("tags", [])
    if not isinstance(tags, list):
        errors.append("tags must be list")
    else:
        if not (1 <= len(tags) <= 12):
            errors.append("tags length must be 1..12")
        unknown = [t for t in tags if t not in allowed_tags]
        if unknown:
            errors.append(f"unknown tags: {unknown}")

    cves = payload.get("cves", [])
    if isinstance(cves, list):
        invalid_cves = [c for c in cves if not CVE_RE.match(str(c))]
        if invalid_cves:
            errors.append(f"invalid CVEs: {invalid_cves}")

    score = payload.get("impact_score")
    if not isinstance(score, int) or not (0 <= score <= 100):
        errors.append("impact_score must be int 0..100")

    confidence_score = payload.get("confidence_score")
    if not isinstance(confidence_score, int) or not (0 <= confidence_score <= 100):
        errors.append("confidence_score must be int 0..100")

    iocs = payload.get("iocs")
    if not isinstance(iocs, dict):
        errors.append("iocs must be object")
    else:
        missing_ioc_keys = IOC_REQUIRED_KEYS - set(iocs.keys())
        if missing_ioc_keys:
            errors.append(f"iocs missing keys: {sorted(missing_ioc_keys)}")
        for key in IOC_REQUIRED_KEYS:
            value = iocs.get(key, [])
            if not isinstance(value, list):
                errors.append(f"iocs.{key} must be list")

    sigma_rules = payload.get("sigma_rules", [])
    if not isinstance(sigma_rules, list) or len(sigma_rules) < 1:
        errors.append("sigma_rules must contain at least 1 rule")
    else:
        for idx, rule in enumerate(sigma_rules):
            if not isinstance(rule, dict):
                errors.append(f"sigma_rules[{idx}] must be object")
                continue
            for key in ("title", "logsource", "detection", "condition"):
                if key not in rule:
                    errors.append(f"sigma_rules[{idx}] missing {key}")

    return ValidationResult(ok=not errors, errors=errors)
