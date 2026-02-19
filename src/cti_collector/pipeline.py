from __future__ import annotations

from dataclasses import dataclass
import json
import logging
from pathlib import Path
import re
from typing import Any
from difflib import SequenceMatcher

from .config import AppConfig, ImpactScoringConfig, getenv_required
from .jira import JiraClient
from .llm import LLMClient
from .models import validate_llm_output
from .rss import Article, collect_articles
from .storage import StateStore
from .url_utils import normalize_url


@dataclass
class RunStats:
    fetched: int = 0
    processed: int = 0
    created: int = 0
    skipped: int = 0
    failed: int = 0


CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
TEXT_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def _build_user_prompt(article: Article, allowed_tags: set[str], sigma_output_format: str, sigma_max_rules: int) -> str:
    return (
        "Analyze the following security article and return JSON only.\\n"
        "Use only allowed tags.\\n"
        "Write 'title', 'tldr' and 'key_points' in Japanese.\\n"
        f"allowed_tags={sorted(allowed_tags)}\\n"
        f"sigma_output_format={sigma_output_format}\\n"
        f"sigma_max_rules={sigma_max_rules}\\n\\n"
        f"source={article.source}\\n"
        f"title={article.title}\\n"
        f"url={article.url}\\n"
        f"published_at={article.published_at}\\n"
        f"content:\\n{article.content[:20000]}"
    )


def _normalize_title(title: str) -> str:
    lowered = title.lower()
    normalized = re.sub(r"[^a-z0-9\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff\s]", " ", lowered)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def _title_similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a, b).ratio()


def _content_fingerprint(text: str, max_tokens: int = 120) -> str:
    cleaned = re.sub(r"\s+", " ", text.lower())
    tokens = re.findall(r"[a-z0-9\u3040-\u30ff\u3400-\u4dbf\u4e00-\u9fff]{3,}", cleaned)
    unique_sorted = sorted(set(tokens))
    return " ".join(unique_sorted[:max_tokens])


def _content_similarity(a_fp: str, b_fp: str) -> float:
    if not a_fp or not b_fp:
        return 0.0
    return SequenceMatcher(None, a_fp, b_fp).ratio()


def _ensure_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [v.strip() for v in value.split("\n") if v.strip()]
    return []


def _truncate_text(text: str, max_len: int) -> str:
    return text.strip()[:max_len]


def _first_sentences(text: str, limit: int) -> list[str]:
    normalized = re.sub(r"\s+", " ", text).strip()
    if not normalized:
        return []
    parts = re.split(r"(?<=[.!?。！？])\s+", normalized)
    items = [p.strip() for p in parts if p.strip()]
    return items[:limit]


def _extract_cves_from_text(text: str) -> list[str]:
    found = {m.group(0).upper() for m in TEXT_CVE_RE.finditer(text)}
    return sorted(found)


def _infer_content_type(text: str) -> str:
    lower = text.lower()
    if any(k in lower for k in ["cve-", "vulnerability", "advisory", "patch"]):
        return "vulnerability"
    if any(k in lower for k in ["exploit", "poc", "in the wild"]):
        return "exploit"
    if any(k in lower for k in ["malware", "ransomware", "trojan"]):
        return "malware"
    if any(k in lower for k in ["incident", "breach"]):
        return "incident"
    if any(k in lower for k in ["detection", "sigma", "yara"]):
        return "detection"
    if any(k in lower for k in ["research", "analysis", "report"]):
        return "research"
    return "other"


def _infer_platforms(text: str) -> list[str]:
    lower = text.lower()
    platforms: list[str] = []
    keyword_map = {
        "windows": ["windows", "powershell", "msiexec"],
        "linux": ["linux", "ubuntu", "debian", "redhat"],
        "macos": ["macos", "osx"],
        "cloud": ["aws", "azure", "gcp", "cloud"],
        "network": ["router", "firewall", "switch", "ics", "scada"],
        "mobile": ["android", "ios", "iphone"],
        "iot": ["iot", "embedded", "firmware"],
    }
    for name, keywords in keyword_map.items():
        if any(k in lower for k in keywords):
            platforms.append(name)
    return platforms


def _infer_exploit_status(text: str) -> str:
    lower = text.lower()
    if "in the wild" in lower or "actively exploited" in lower or "known exploited" in lower:
        return "in_the_wild"
    if "poc" in lower or "proof of concept" in lower or "exploit code" in lower:
        return "poc"
    return "unknown"


def _infer_impact_score(
    content_type: str,
    exploit_status: str,
    cves: list[str],
    scoring: ImpactScoringConfig,
) -> int:
    score = scoring.base_score
    if content_type == "vulnerability":
        score += scoring.vulnerability_bonus
    if content_type == "exploit":
        score += scoring.exploit_bonus
    if cves:
        score += min(scoring.cve_max_bonus, len(cves) * scoring.cve_per_item_bonus)
    if exploit_status == "in_the_wild":
        score += scoring.in_the_wild_bonus
    elif exploit_status == "poc":
        score += scoring.poc_bonus
    return max(0, min(100, score))


def _to_int(value: Any, default: int = 0) -> int:
    try:
        if isinstance(value, bool):
            return default
        return int(value)
    except Exception:
        return default


def _coerce_sigma_rules(value: Any, max_rules: int) -> list[dict[str, Any]]:
    items = _ensure_list(value)
    out: list[dict[str, Any]] = []
    for item in items[:max_rules]:
        if isinstance(item, dict):
            out.append(
                {
                    "title": item.get("title", "Generated Sigma Rule"),
                    "logsource": item.get("logsource", {"product": "windows"}),
                    "detection": item.get("detection", {"selection": {"raw": "placeholder"}}),
                    "condition": item.get("condition", "selection"),
                }
            )
        elif isinstance(item, str):
            text = item.strip()[:200]
            if not text:
                continue
            out.append(
                {
                    "title": text.splitlines()[0][:120],
                    "logsource": {"product": "windows"},
                    "detection": {"selection": {"raw": text}},
                    "condition": "selection",
                }
            )
    if not out:
        out.append(
            {
                "title": "Generated Sigma Rule",
                "logsource": {"product": "windows"},
                "detection": {"selection": {"raw": "placeholder"}},
                "condition": "selection",
            }
        )
    return out


def _normalize_llm_result(
    llm_result: dict[str, Any],
    article: Article,
    allowed_tags: set[str],
    sigma_max_rules: int,
    impact_scoring: ImpactScoringConfig,
) -> dict[str, Any]:
    data = dict(llm_result) if isinstance(llm_result, dict) else {}
    article_text = f"{article.title}\n{article.summary}\n{article.content}"

    title = data.get("title") or article.title
    source = data.get("source") or article.source
    source_url = data.get("source_url") or data.get("url") or article.url
    published_at = data.get("published_at") or article.published_at
    language = data.get("language") or "unknown"
    tldr = data.get("tldr") or data.get("summary") or _truncate_text(article.summary or article.content, 350)
    key_points = _ensure_list(data.get("key_points"))
    if not key_points:
        key_points = _ensure_list(data.get("important_points"))
    if not key_points:
        key_points = _first_sentences(article.content or article.summary, 4)

    tags = [str(t) for t in _ensure_list(data.get("tags")) if str(t) in allowed_tags]
    if not tags:
        if "type_research" in allowed_tags:
            tags = ["type_research"]
        elif allowed_tags:
            tags = [sorted(allowed_tags)[0]]
    tags = tags[:12]

    cves = [str(c).upper() for c in _ensure_list(data.get("cves")) if CVE_RE.match(str(c).upper())]
    if not cves:
        cves = _extract_cves_from_text(article_text)
    platforms = [str(p) for p in _ensure_list(data.get("platforms"))]
    if not platforms:
        platforms = _infer_platforms(article_text)
    products = [str(p) for p in _ensure_list(data.get("products"))]
    detection_notes = [str(x) for x in _ensure_list(data.get("detection_notes"))][:8]
    recommended_actions = [str(x) for x in _ensure_list(data.get("recommended_actions"))][:8]
    if not recommended_actions:
        recommended_actions = ["Assess exposure and prioritize patching or mitigations.", "Create detection/monitoring rule and validate in environment."]

    evidence = data.get("evidence") if isinstance(data.get("evidence"), list) else []
    if not evidence:
        evidence = [{"claim": "Derived from article text", "basis": _truncate_text(article.summary or article.content, 400)}]
    impact_score_factors = data.get("impact_score_factors") if isinstance(data.get("impact_score_factors"), list) else []
    if not impact_score_factors:
        impact_score_factors = [{"factor": "article_context", "weight": 10, "reason": "Fallback factor from parsed article context"}]

    iocs = data.get("iocs")
    if not isinstance(iocs, dict):
        iocs = {
            "ips": [],
            "domains": [],
            "urls": [],
            "hashes": [],
            "emails": [],
            "files": [],
            "registry": [],
            "mutexes": [],
        }

    content_type = data.get("content_type") or _infer_content_type(article_text)
    exploit_status = data.get("exploit_status") or _infer_exploit_status(article_text)
    impact_score_raw = _to_int(data.get("impact_score"), -1)
    if impact_score_raw < 0:
        impact_score_raw = _infer_impact_score(content_type, exploit_status, cves, impact_scoring)
    impact_score = max(0, min(100, impact_score_raw))

    return {
        "title": title,
        "source": source,
        "source_url": source_url,
        "published_at": published_at,
        "language": language,
        "tldr": _truncate_text(str(tldr), 400),
        "key_points": key_points[:7],
        "content_type": content_type,
        "platforms": platforms,
        "cves": cves,
        "products": products,
        "exploit_status": exploit_status,
        "iocs": iocs,
        "detection_notes": detection_notes,
        "recommended_actions": recommended_actions,
        "tags": tags,
        "impact_score": impact_score,
        "impact_score_factors": impact_score_factors,
        "confidence": data.get("confidence") or "medium",
        "evidence": evidence,
        "sigma_rules": _coerce_sigma_rules(data.get("sigma_rules"), sigma_max_rules),
    }


def _build_repair_prompt(article: Article, current_output: dict[str, Any], errors: list[str]) -> str:
    return (
        "Repair the JSON so it fully satisfies the required schema. Return JSON object only.\\n"
        f"validation_errors={errors}\\n"
        f"article_title={article.title}\\n"
        f"article_url={article.url}\\n"
        "current_json=\\n"
        f"{json.dumps(current_output, ensure_ascii=False)}"
    )


def _quality_issues(result: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    if not str(result.get("tldr", "")).strip():
        issues.append("tldr is empty")
    if len(_ensure_list(result.get("key_points"))) < 3:
        issues.append("key_points must have at least 3 items")
    if int(result.get("impact_score", 0) or 0) <= 0:
        issues.append("impact_score should be greater than 0 for triage usefulness")
    if not _ensure_list(result.get("platforms")):
        issues.append("platforms should not be empty")
    return issues


def _add_duplicate_comment(
    logger: logging.Logger,
    jira: JiraClient,
    intel_key: str,
    article: Article,
    reason: str,
    matched_url: str,
    title_similarity: float | None = None,
    content_similarity: float | None = None,
) -> None:
    parts = [
        "重複検知により新規Issue作成をスキップしました。",
        f"- reason: {reason}",
        f"- new_url: {article.url}",
        f"- new_title: {article.title}",
        f"- matched_url: {matched_url}",
    ]
    if title_similarity is not None:
        parts.append(f"- title_similarity: {title_similarity:.3f}")
    if content_similarity is not None:
        parts.append(f"- content_similarity: {content_similarity:.3f}")
    message = "\n".join(parts)
    try:
        jira.add_comment(intel_key, message)
    except Exception as exc:
        logger.warning(
            "failed to add duplicate comment",
            extra={"extra": {"intel_key": intel_key, "url": article.url, "error": str(exc)}},
        )


def _build_issue_payloads(summary_data: dict[str, Any], article: Article) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    intel_summary = f"[{summary_data.get('source', article.source)}] {summary_data.get('title', article.title)}"
    intel_description = (
        f"TLDR: {summary_data.get('tldr', '')}\\n"
        f"Key points: {summary_data.get('key_points', [])}\\n"
        f"Source URL: {summary_data.get('source_url', article.url)}\\n"
        f"Sigma: {summary_data.get('sigma_rules', [])}"
    )

    validation_summary = "PENDING_INTEL_KEY Validation: " + summary_data.get("title", article.title)
    validation_description = (
        f"Validation plan for article: {summary_data.get('title', article.title)}\\n"
        f"Platforms: {summary_data.get('platforms', [])}\\n"
        f"Recommended actions: {summary_data.get('recommended_actions', [])}"
    )

    intel_fields = {
        "source": summary_data.get("source", article.source),
        "source_url": summary_data.get("source_url", article.url),
        "published_at": summary_data.get("published_at", article.published_at),
        "language": summary_data.get("language", "unknown"),
        "content_type": summary_data.get("content_type", "other"),
        "cve_list": summary_data.get("cves", []),
        "products": summary_data.get("products", []),
        "exploit_status": summary_data.get("exploit_status", "unknown"),
        "impact_score": summary_data.get("impact_score", 0),
        "confidence": summary_data.get("confidence", "medium"),
        "tldr": summary_data.get("tldr", ""),
        "key_points": summary_data.get("key_points", []),
        "sigma_rule": summary_data.get("sigma_rules", []),
    }

    validation_fields = {
        "target_platform": ", ".join(summary_data.get("platforms", [])),
        "validation_type": summary_data.get("content_type", "other"),
        "cve_primary": (summary_data.get("cves", []) or [""])[0],
        "affected_product": ", ".join(summary_data.get("products", [])),
        "exploit_status": summary_data.get("exploit_status", "unknown"),
        "impact_score": summary_data.get("impact_score", 0),
        "scope": "auto",
        "auto_route": "triage",
        "result": "pending",
    }

    return intel_fields, validation_fields, intel_summary, intel_description + "\n" + validation_description + "\n" + validation_summary


def run_daily(config: AppConfig, allowed_tags: set[str], prompt_path: str, enable_jql_fallback: bool = True) -> RunStats:
    logger = logging.getLogger(__name__)
    stats = RunStats()

    system_prompt = Path(prompt_path).read_text(encoding="utf-8")
    llm = LLMClient(
        base_url=config.llm.base_url,
        model=config.llm.model,
        api_key=getenv_required(config.llm.api_key_env),
        temperature=config.llm.temperature,
        timeout_seconds=config.llm.timeout_seconds,
        max_retries=config.llm.max_retries,
        system_prompt=system_prompt,
    )
    jira = JiraClient(
        base_url=config.jira.base_url,
        email=getenv_required(config.jira.email_env),
        token=getenv_required(config.jira.token_env),
        project_key=config.jira.project_key,
        issue_types=config.jira.issue_types,
        fields=config.jira.fields,
        max_retries=config.retry.jira_max_retries,
        backoff_seconds=config.retry.jira_backoff_seconds,
    )
    store = StateStore(config.runtime.db_path)

    try:
        articles = collect_articles(
            sources=config.rss.sources,
            timeout_seconds=config.rss.timeout_seconds,
            content_max_chars=config.rss.content_max_chars,
            max_articles_per_run=config.rss.max_articles_per_run,
        )
        stats.fetched = len(articles)

        for article in articles:
            normalized = normalize_url(article.url)
            title_norm = _normalize_title(article.title)
            content_fp = _content_fingerprint(article.content or article.summary)
            existing = store.get(normalized)
            if existing and existing.jira_validation_key:
                stats.skipped += 1
                continue

            if config.dedupe.enable_content_hash:
                by_hash = store.find_by_content_hash(article.content_hash)
                if by_hash and by_hash.jira_validation_key:
                    _add_duplicate_comment(
                        logger=logger,
                        jira=jira,
                        intel_key=by_hash.jira_intel_key,
                        article=article,
                        reason="content_hash",
                        matched_url=by_hash.normalized_url,
                    )
                    store.save(
                        normalized_url=normalized,
                        jira_intel_key=by_hash.jira_intel_key,
                        jira_validation_key=by_hash.jira_validation_key,
                        content_hash=article.content_hash,
                        source=article.source,
                        title_norm=title_norm,
                        content_fp=content_fp,
                    )
                    logger.info(
                        "skip duplicate by content hash",
                        extra={"extra": {"url": normalized, "matched_url": by_hash.normalized_url}},
                    )
                    stats.skipped += 1
                    continue

            if config.dedupe.enable_title_similarity and len(title_norm) >= config.dedupe.min_title_length:
                candidates = store.iter_by_source(article.source)
                matched = None
                matched_sim = 0.0
                matched_content_sim = 0.0
                for c in candidates:
                    if not c.title_norm or not c.jira_validation_key:
                        continue
                    sim = _title_similarity(title_norm, c.title_norm)
                    content_sim = _content_similarity(content_fp, c.content_fp)
                    if sim >= config.dedupe.title_similarity_threshold and content_sim >= config.dedupe.content_similarity_threshold:
                        matched = c
                        matched_sim = sim
                        matched_content_sim = content_sim
                        break
                if matched:
                    _add_duplicate_comment(
                        logger=logger,
                        jira=jira,
                        intel_key=matched.jira_intel_key,
                        article=article,
                        reason="title_and_content_similarity",
                        matched_url=matched.normalized_url,
                        title_similarity=matched_sim,
                        content_similarity=matched_content_sim,
                    )
                    store.save(
                        normalized_url=normalized,
                        jira_intel_key=matched.jira_intel_key,
                        jira_validation_key=matched.jira_validation_key,
                        content_hash=article.content_hash,
                        source=article.source,
                        title_norm=title_norm,
                        content_fp=content_fp,
                    )
                    logger.info(
                        "skip duplicate by title similarity",
                        extra={"extra": {"url": normalized, "matched_url": matched.normalized_url}},
                    )
                    stats.skipped += 1
                    continue

            try:
                if enable_jql_fallback:
                    source_field = config.jira.fields.get("intel", {}).get("source_url", "")
                    if source_field:
                        try:
                            existing_key = jira.search_existing_intel_by_source_url(
                                issue_type=config.jira.issue_types["intel"],
                                source_url=normalized,
                                source_field_id=source_field,
                            )
                            if existing_key:
                                _add_duplicate_comment(
                                    logger=logger,
                                    jira=jira,
                                    intel_key=existing_key,
                                    article=article,
                                    reason="jql_source_url_match",
                                    matched_url=normalized,
                                )
                                stats.skipped += 1
                                continue
                        except Exception as exc:
                            logger.warning(
                                "jql duplicate check failed; continue without jql fallback",
                                extra={"extra": {"url": normalized, "error": str(exc)}},
                            )

                user_prompt = _build_user_prompt(
                    article=article,
                    allowed_tags=allowed_tags,
                    sigma_output_format=config.sigma.output_format,
                    sigma_max_rules=config.sigma.max_rules_per_article,
                )
                llm_result = llm.summarize(user_prompt)
                llm_result = _normalize_llm_result(
                    llm_result=llm_result,
                    article=article,
                    allowed_tags=allowed_tags,
                    sigma_max_rules=config.sigma.max_rules_per_article,
                    impact_scoring=config.impact_scoring,
                )

                validation = validate_llm_output(llm_result, allowed_tags)
                quality_errors = _quality_issues(llm_result)
                if (not validation.ok) or quality_errors:
                    all_errors = validation.errors + quality_errors
                    repair_prompt = _build_repair_prompt(article=article, current_output=llm_result, errors=all_errors)
                    repaired = llm.summarize(repair_prompt)
                    llm_result = _normalize_llm_result(
                        llm_result=repaired,
                        article=article,
                        allowed_tags=allowed_tags,
                        sigma_max_rules=config.sigma.max_rules_per_article,
                        impact_scoring=config.impact_scoring,
                    )
                    validation = validate_llm_output(llm_result, allowed_tags)
                    quality_errors = _quality_issues(llm_result)
                    if (not validation.ok) or quality_errors:
                        raise ValueError(f"LLM output validation failed: {validation.errors + quality_errors}")

                tags = llm_result.get("tags", [])
                intel_fields, validation_fields, intel_summary, combined_desc = _build_issue_payloads(llm_result, article)

                intel_key = jira.create_intel_issue(
                    summary=intel_summary,
                    description=combined_desc,
                    labels=tags,
                    intel=intel_fields,
                )
                validation_summary = f"[{intel_key}] Validation: {llm_result.get('title', article.title)}"
                validation_key = jira.create_validation_issue(
                    summary=validation_summary,
                    description=combined_desc,
                    labels=tags,
                    validation=validation_fields,
                )
                jira.link_validation_to_intel(validation_key=validation_key, intel_key=intel_key)
                store.save(
                    normalized_url=normalized,
                    jira_intel_key=intel_key,
                    jira_validation_key=validation_key,
                    content_hash=article.content_hash,
                    source=article.source,
                    title_norm=title_norm,
                    content_fp=content_fp,
                )

                stats.processed += 1
                stats.created += 1
            except Exception as exc:
                logger.error(
                    "article processing failed",
                    extra={
                        "extra": {
                            "url": article.url,
                            "normalized_url": normalized,
                            "error": str(exc),
                        }
                    },
                )
                stats.failed += 1

        logger.info("run summary", extra={"extra": json.loads(json.dumps(stats.__dict__))})
        return stats
    finally:
        store.close()
