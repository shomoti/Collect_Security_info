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
class AppConfig:
    jira: JiraConfig
    llm: LLMConfig
    rss: RSSConfig
    sigma: SigmaConfig
    runtime: RuntimeConfig
    retry: RetryConfig
    dedupe: DedupeConfig
    impact_scoring: ImpactScoringConfig


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
    return AppConfig(
        jira=JiraConfig(**raw["jira"]),
        llm=LLMConfig(**raw["llm"]),
        rss=RSSConfig(**raw["rss"]),
        sigma=SigmaConfig(**raw["sigma"]),
        runtime=RuntimeConfig(**raw["runtime"]),
        retry=RetryConfig(**raw["retry"]),
        dedupe=DedupeConfig(**dedupe_defaults),
        impact_scoring=ImpactScoringConfig(**impact_defaults),
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
