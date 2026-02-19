from __future__ import annotations

import re
from typing import Any


IOC_KEYS = ("ips", "domains", "urls", "hashes", "emails", "files", "registry", "mutexes")

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE)
URL_RE = re.compile(r"\bhttps?://[^\s\"'<>]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
HASH_RE = re.compile(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b")
FILE_RE = re.compile(r"\b[A-Za-z0-9_.-]+\.(?:exe|dll|ps1|bat|vbs|js|jar|zip|rar|7z)\b", re.IGNORECASE)
REGISTRY_RE = re.compile(r"\b(?:HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\[^\s\"']+\b", re.IGNORECASE)
MUTEX_RE = re.compile(r"\b(?:Global\\|Local\\)[A-Za-z0-9_.-]+\b")


def _normalize_text(text: str) -> str:
    return text.replace("[.]", ".").replace("(.)", ".").replace("hxxp://", "http://").replace("hxxps://", "https://")


def _dedupe(items: list[str], case_insensitive: bool, max_items: int) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for item in items:
        normalized = item.strip()
        if not normalized:
            continue
        key = normalized.lower() if case_insensitive else normalized
        if key in seen:
            continue
        seen.add(key)
        out.append(normalized)
        if len(out) >= max_items:
            break
    return out


def extract_iocs(text: str) -> dict[str, list[str]]:
    normalized = _normalize_text(text)
    return {
        "ips": IP_RE.findall(normalized),
        "domains": DOMAIN_RE.findall(normalized),
        "urls": URL_RE.findall(normalized),
        "hashes": HASH_RE.findall(normalized),
        "emails": EMAIL_RE.findall(normalized),
        "files": FILE_RE.findall(normalized),
        "registry": REGISTRY_RE.findall(normalized),
        "mutexes": MUTEX_RE.findall(normalized),
    }


def normalize_iocs(raw: dict[str, Any], case_insensitive: bool, max_items_per_type: int) -> dict[str, list[str]]:
    normalized: dict[str, list[str]] = {}
    for key in IOC_KEYS:
        value = raw.get(key, [])
        if not isinstance(value, list):
            value = [value] if value else []
        normalized[key] = _dedupe([str(v) for v in value], case_insensitive, max_items_per_type)
    return normalized


def merge_iocs(
    llm_iocs: dict[str, Any],
    article_text: str,
    enable_regex_extraction: bool,
    case_insensitive: bool,
    max_items_per_type: int,
) -> dict[str, list[str]]:
    merged = normalize_iocs(llm_iocs if isinstance(llm_iocs, dict) else {}, case_insensitive, max_items_per_type)
    if not enable_regex_extraction:
        return merged
    extracted = extract_iocs(article_text)
    for key in IOC_KEYS:
        merged[key] = _dedupe(merged[key] + extracted.get(key, []), case_insensitive, max_items_per_type)
    return merged
