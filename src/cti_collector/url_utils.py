from __future__ import annotations

from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse


def normalize_url(url: str) -> str:
    parsed = urlparse(url)
    filtered_query = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        lower = key.lower()
        if lower.startswith("utm_"):
            continue
        if lower in {"fbclid", "gclid", "mc_cid", "mc_eid"}:
            continue
        filtered_query.append((key, value))

    filtered_query.sort(key=lambda x: (x[0], x[1]))
    normalized = parsed._replace(
        query=urlencode(filtered_query, doseq=True),
        fragment="",
    )
    return urlunparse(normalized)
