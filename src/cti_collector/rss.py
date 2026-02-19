from __future__ import annotations

from dataclasses import dataclass
import hashlib
import logging

import feedparser
import requests
import trafilatura


@dataclass
class Article:
    source: str
    title: str
    url: str
    published_at: str
    summary: str
    content: str
    content_hash: str


def _hash_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def _extract_content(url: str, fallback_summary: str, timeout: int, max_chars: int) -> str:
    try:
        resp = requests.get(url, timeout=timeout)
        resp.raise_for_status()
        text = trafilatura.extract(resp.text, include_comments=False, include_tables=False) or ""
        if not text.strip():
            text = fallback_summary
    except Exception:
        text = fallback_summary
    return text[:max_chars]


def collect_articles(
    sources: list[dict[str, str]],
    timeout_seconds: int,
    content_max_chars: int,
    max_articles_per_run: int,
) -> list[Article]:
    logger = logging.getLogger(__name__)
    articles: list[Article] = []

    for src in sources:
        name = src.get("name", "unknown")
        url = src.get("url", "")
        if not url:
            logger.warning("rss source missing url", extra={"extra": {"source": name}})
            continue

        try:
            feed = feedparser.parse(url)
        except Exception as exc:
            logger.error("rss parse failed", extra={"extra": {"source": name, "error": str(exc)}})
            continue

        for entry in feed.entries:
            if len(articles) >= max_articles_per_run:
                return articles
            link = entry.get("link", "")
            title = entry.get("title", "(no title)")
            summary = entry.get("summary", "")
            published_at = entry.get("published", "")
            content = _extract_content(link, summary, timeout_seconds, content_max_chars)
            articles.append(
                Article(
                    source=name,
                    title=title,
                    url=link,
                    published_at=published_at,
                    summary=summary,
                    content=content,
                    content_hash=_hash_text(content),
                )
            )

    return articles
