from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import os

import yaml


@dataclass
class JiraConfig:
    base_url: str
    email_env: str
    token_env: str
    project_key: str
    issue_types: dict[str, str]
    fields: dict[str, dict[str, str]]


@dataclass
class LLMConfig:
    base_url: str
    model: str
    api_key_env: str
    temperature: float
    timeout_seconds: int
    max_retries: int


@dataclass
class RSSConfig:
    timeout_seconds: int
    max_articles_per_run: int
    content_max_chars: int
    sources: list[dict[str, str]]


@dataclass
class SigmaConfig:
    output_format: str
    max_rules_per_article: int
    enable_validation: bool
    drop_invalid_rules: bool
    target_backends: list[str]


@dataclass
class RuntimeConfig:
    db_path: str
    log_level: str
    run_actor: str


@dataclass
class RetryConfig:
    jira_max_retries: int
    jira_backoff_seconds: int


@dataclass
class DedupeConfig:
    enable_content_hash: bool
    enable_title_similarity: bool
    title_similarity_threshold: float
    content_similarity_threshold: float
    min_title_length: int


@dataclass
class ImpactScoringConfig:
    base_score: int
    vulnerability_bonus: int
    exploit_bonus: int
    cve_per_item_bonus: int
    cve_max_bonus: int
    in_the_wild_bonus: int
    poc_bonus: int


@dataclass
class UpdateStrategyConfig:
    enable_issue_update: bool
    match_order: list[str]
    update_mode: str
    min_score_delta_for_comment: int


@dataclass
class IOCConfig:
    enable_regex_extraction: bool
    dedupe_case_insensitive: bool
    max_items_per_type: int


@dataclass
class ConfidenceScoringConfig:
    base: int
    source_reputation_bonus: int
    cve_present_bonus: int
    evidence_count_bonus: int
    has_poc_bonus: int
    in_the_wild_bonus: int
    max_score: int
    source_reputation: dict[str, int]


@dataclass
class AppConfig:
    jira: JiraConfig
    llm: LLMConfig
    rss: RSSConfig
    sigma: SigmaConfig
    runtime: RuntimeConfig
    retry: RetryConfig
    dedupe: DedupeConfig
    impact_scoring: ImpactScoringConfig
    confidence_scoring: ConfidenceScoringConfig
    update_strategy: UpdateStrategyConfig
    ioc: IOCConfig


def _load_yaml(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ValueError(f"Config file must be a mapping: {path}")
    return data


def load_app_config(path: str) -> AppConfig:
    raw = _load_yaml(Path(path))
    dedupe_raw = raw.get("dedupe", {})
    if not isinstance(dedupe_raw, dict):
        raise ValueError("dedupe must be a mapping")
    dedupe_defaults = {
        "enable_content_hash": True,
        "enable_title_similarity": True,
        "title_similarity_threshold": 0.92,
        "content_similarity_threshold": 0.90,
        "min_title_length": 24,
    }
    dedupe_defaults.update(dedupe_raw)
    impact_raw = raw.get("impact_scoring", {})
    if not isinstance(impact_raw, dict):
        raise ValueError("impact_scoring must be a mapping")
    impact_defaults = {
        "base_score": 20,
        "vulnerability_bonus": 20,
        "exploit_bonus": 30,
        "cve_per_item_bonus": 5,
        "cve_max_bonus": 20,
        "in_the_wild_bonus": 25,
        "poc_bonus": 10,
    }
    impact_defaults.update(impact_raw)
    sigma_raw = raw.get("sigma", {})
    if not isinstance(sigma_raw, dict):
        raise ValueError("sigma must be a mapping")
    sigma_defaults = {
        "output_format": "yaml",
        "max_rules_per_article": 3,
        "enable_validation": True,
        "drop_invalid_rules": True,
        "target_backends": [],
    }
    sigma_defaults.update(sigma_raw)
    update_raw = raw.get("update_strategy", {})
    if not isinstance(update_raw, dict):
        raise ValueError("update_strategy must be a mapping")
    update_defaults = {
        "enable_issue_update": True,
        "match_order": ["source_url", "cve", "title_content_similarity"],
        "update_mode": "merge",
        "min_score_delta_for_comment": 10,
    }
    update_defaults.update(update_raw)
    ioc_raw = raw.get("ioc", {})
    if not isinstance(ioc_raw, dict):
        raise ValueError("ioc must be a mapping")
    ioc_defaults = {
        "enable_regex_extraction": True,
        "dedupe_case_insensitive": True,
        "max_items_per_type": 200,
    }
    ioc_defaults.update(ioc_raw)
    confidence_raw = raw.get("confidence_scoring", {})
    if not isinstance(confidence_raw, dict):
        raise ValueError("confidence_scoring must be a mapping")
    confidence_defaults = {
        "base": 40,
        "source_reputation_bonus": 15,
        "cve_present_bonus": 15,
        "evidence_count_bonus": 10,
        "has_poc_bonus": 10,
        "in_the_wild_bonus": 15,
        "max_score": 100,
        "source_reputation": {},
    }
    confidence_defaults.update(confidence_raw)
    return AppConfig(
        jira=JiraConfig(**raw["jira"]),
        llm=LLMConfig(**raw["llm"]),
        rss=RSSConfig(**raw["rss"]),
        sigma=SigmaConfig(**sigma_defaults),
        runtime=RuntimeConfig(**raw["runtime"]),
        retry=RetryConfig(**raw["retry"]),
        dedupe=DedupeConfig(**dedupe_defaults),
        impact_scoring=ImpactScoringConfig(**impact_defaults),
        confidence_scoring=ConfidenceScoringConfig(**confidence_defaults),
        update_strategy=UpdateStrategyConfig(**update_defaults),
        ioc=IOCConfig(**ioc_defaults),
    )


def load_allowed_tags(path: str) -> set[str]:
    raw = _load_yaml(Path(path))
    tags = raw.get("allowed_tags", [])
    if not isinstance(tags, list):
        raise ValueError("allowed_tags must be a list")
    return {str(t) for t in tags}


def getenv_required(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value
