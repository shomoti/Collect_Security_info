from pathlib import Path
from types import SimpleNamespace

from cti_collector.pipeline import run_daily
from cti_collector.pipeline import _normalize_llm_result
from cti_collector.rss import Article


def _make_config(tmp_path):
    return SimpleNamespace(
        jira=SimpleNamespace(
            base_url="https://example.atlassian.net",
            email_env="JIRA_EMAIL",
            token_env="JIRA_API_TOKEN",
            project_key="CTI",
            issue_types={"intel": "Intel Item", "validation": "Validation"},
            fields={"intel": {"source_url": "customfield_10011"}, "validation": {}},
        ),
        llm=SimpleNamespace(
            base_url="http://localhost:8000/v1",
            model="local-model",
            api_key_env="LLM_API_KEY",
            temperature=0.2,
            timeout_seconds=30,
            max_retries=2,
        ),
        rss=SimpleNamespace(
            timeout_seconds=10,
            max_articles_per_run=10,
            content_max_chars=20000,
            sources=[{"name": "A", "url": "https://example.com/feed"}],
        ),
        sigma=SimpleNamespace(output_format="yaml", max_rules_per_article=2, enable_validation=True),
        runtime=SimpleNamespace(db_path=str(tmp_path / "state.db"), log_level="INFO", run_actor="tester"),
        retry=SimpleNamespace(jira_max_retries=1, jira_backoff_seconds=1),
        dedupe=SimpleNamespace(
            enable_content_hash=True,
            enable_title_similarity=True,
            title_similarity_threshold=0.92,
            content_similarity_threshold=0.9,
            min_title_length=24,
        ),
        impact_scoring=SimpleNamespace(
            base_score=20,
            vulnerability_bonus=20,
            exploit_bonus=30,
            cve_per_item_bonus=5,
            cve_max_bonus=20,
            in_the_wild_bonus=25,
            poc_bonus=10,
        ),
    )


def _llm_result(url: str) -> dict:
    return {
        "title": "Article",
        "source": "A",
        "source_url": url,
        "published_at": "2026-02-19",
        "language": "en",
        "tldr": "x",
        "key_points": ["k1", "k2", "k3"],
        "content_type": "vulnerability",
        "platforms": ["windows"],
        "cves": ["CVE-2025-1234"],
        "products": ["p"],
        "exploit_status": "poc",
        "iocs": {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": [], "files": [], "registry": [], "mutexes": []},
        "detection_notes": [],
        "recommended_actions": [],
        "tags": ["plat_windows", "type_vuln"],
        "impact_score": 50,
        "impact_score_factors": [{"factor": "f", "weight": 10, "reason": "r"}],
        "confidence": "medium",
        "evidence": [{"claim": "c", "basis": "b"}],
        "sigma_rules": [{"title": "r1", "logsource": {"product": "windows"}, "detection": {"a": 1}, "condition": "a"}],
    }


def test_run_daily_creates_and_links_issues(monkeypatch, tmp_path) -> None:
    config = _make_config(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("system", encoding="utf-8")

    article = Article(
        source="A",
        title="T",
        url="https://example.com/post?utm_source=x",
        published_at="2026-02-19",
        summary="s",
        content="content",
        content_hash="h",
    )

    monkeypatch.setattr("cti_collector.pipeline.getenv_required", lambda name: "dummy")
    monkeypatch.setattr("cti_collector.pipeline.collect_articles", lambda **kwargs: [article])

    class DummyLLM:
        def summarize(self, user_prompt: str):
            return _llm_result("https://example.com/post")

    class DummyJira:
        def __init__(self):
            self.calls = []

        def search_existing_intel_by_source_url(self, issue_type, source_url, source_field_id):
            self.calls.append(("search", source_url))
            return None

        def create_intel_issue(self, summary, description, labels, intel):
            self.calls.append(("create_intel", summary, labels, intel))
            return "CTI-1"

        def create_validation_issue(self, summary, description, labels, validation):
            self.calls.append(("create_validation", summary, labels, validation))
            return "CTI-2"

        def link_validation_to_intel(self, validation_key, intel_key):
            self.calls.append(("link", validation_key, intel_key))

        def add_comment(self, issue_key, text):
            self.calls.append(("comment", issue_key, text))

    jira = DummyJira()
    monkeypatch.setattr("cti_collector.pipeline.LLMClient", lambda **kwargs: DummyLLM())
    monkeypatch.setattr("cti_collector.pipeline.JiraClient", lambda **kwargs: jira)

    stats = run_daily(config, {"plat_windows", "type_vuln"}, str(prompt_path), enable_jql_fallback=True)

    assert stats.fetched == 1
    assert stats.created == 1
    assert stats.failed == 0
    assert any(c[0] == "create_intel" for c in jira.calls)
    assert any(c[0] == "create_validation" for c in jira.calls)
    assert any(c[0] == "link" for c in jira.calls)


def test_run_daily_skips_when_already_processed(monkeypatch, tmp_path) -> None:
    config = _make_config(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("system", encoding="utf-8")

    article = Article(
        source="A",
        title="T",
        url="https://example.com/post",
        published_at="2026-02-19",
        summary="s",
        content="content",
        content_hash="h",
    )

    monkeypatch.setattr("cti_collector.pipeline.getenv_required", lambda name: "dummy")
    monkeypatch.setattr("cti_collector.pipeline.collect_articles", lambda **kwargs: [article])

    class DummyLLM:
        def summarize(self, user_prompt: str):
            raise AssertionError("should not be called")

    class DummyJira:
        def search_existing_intel_by_source_url(self, issue_type, source_url, source_field_id):
            return "CTI-EXIST"

        def add_comment(self, issue_key, text):
            return None

    monkeypatch.setattr("cti_collector.pipeline.LLMClient", lambda **kwargs: DummyLLM())
    monkeypatch.setattr("cti_collector.pipeline.JiraClient", lambda **kwargs: DummyJira())

    stats = run_daily(config, {"plat_windows", "type_vuln"}, str(prompt_path), enable_jql_fallback=True)

    assert stats.fetched == 1
    assert stats.skipped == 1
    assert stats.created == 0


def test_normalize_llm_result_fills_missing_required_fields() -> None:
    article = Article(
        source="CISA",
        title="Test advisory",
        url="https://example.com/a",
        published_at="2026-02-19",
        summary="s",
        content="c",
        content_hash="h",
    )
    raw = {
        "sigma_rules": ["title: test rule"],
        "tags": [],
        "impact_score": "42",
    }
    normalized = _normalize_llm_result(
        llm_result=raw,
        article=article,
        allowed_tags={"type_research", "plat_windows"},
        sigma_max_rules=3,
        impact_scoring=SimpleNamespace(
            base_score=20,
            vulnerability_bonus=20,
            exploit_bonus=30,
            cve_per_item_bonus=5,
            cve_max_bonus=20,
            in_the_wild_bonus=25,
            poc_bonus=10,
        ),
    )

    assert normalized["title"] == "Test advisory"
    assert normalized["source"] == "CISA"
    assert normalized["source_url"] == "https://example.com/a"
    assert normalized["impact_score"] == 42
    assert normalized["tags"] == ["type_research"]
    assert isinstance(normalized["sigma_rules"], list)
    assert isinstance(normalized["sigma_rules"][0], dict)


def test_normalize_llm_result_infers_cve_platforms_and_key_points() -> None:
    article = Article(
        source="CISA",
        title="Windows vulnerability advisory",
        url="https://example.com/b",
        published_at="2026-02-19",
        summary="Advisory references CVE-2026-1111.",
        content="CVE-2026-1111 is actively exploited in the wild. Windows systems are impacted. Patch immediately.",
        content_hash="h2",
    )
    normalized = _normalize_llm_result(
        llm_result={"tags": ["type_vuln"], "sigma_rules": ["rule text"]},
        article=article,
        allowed_tags={"type_vuln", "plat_windows"},
        sigma_max_rules=2,
        impact_scoring=SimpleNamespace(
            base_score=20,
            vulnerability_bonus=20,
            exploit_bonus=30,
            cve_per_item_bonus=5,
            cve_max_bonus=20,
            in_the_wild_bonus=25,
            poc_bonus=10,
        ),
    )

    assert "CVE-2026-1111" in normalized["cves"]
    assert "windows" in normalized["platforms"]
    assert len(normalized["key_points"]) >= 1
    assert normalized["impact_score"] > 0


def test_run_daily_skips_duplicate_by_content_hash(monkeypatch, tmp_path) -> None:
    config = _make_config(tmp_path)
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("system", encoding="utf-8")

    a1 = Article(
        source="A",
        title="Title one",
        url="https://example.com/a1",
        published_at="2026-02-19",
        summary="s1",
        content="same content",
        content_hash="samehash",
    )
    a2 = Article(
        source="A",
        title="Title two",
        url="https://example.com/a2",
        published_at="2026-02-19",
        summary="s2",
        content="same content",
        content_hash="samehash",
    )
    monkeypatch.setattr("cti_collector.pipeline.getenv_required", lambda name: "dummy")
    monkeypatch.setattr("cti_collector.pipeline.collect_articles", lambda **kwargs: [a1, a2])

    calls = {"llm": 0}

    class DummyLLM:
        def summarize(self, user_prompt: str):
            calls["llm"] += 1
            return _llm_result("https://example.com/a1")

    class DummyJira:
        def search_existing_intel_by_source_url(self, issue_type, source_url, source_field_id):
            return None

        def create_intel_issue(self, summary, description, labels, intel):
            return "CTI-1"

        def create_validation_issue(self, summary, description, labels, validation):
            return "CTI-2"

        def link_validation_to_intel(self, validation_key, intel_key):
            return None

        def add_comment(self, issue_key, text):
            return None

    monkeypatch.setattr("cti_collector.pipeline.LLMClient", lambda **kwargs: DummyLLM())
    monkeypatch.setattr("cti_collector.pipeline.JiraClient", lambda **kwargs: DummyJira())

    stats = run_daily(config, {"plat_windows", "type_vuln"}, str(prompt_path), enable_jql_fallback=False)
    assert stats.fetched == 2
    assert stats.created == 1
    assert stats.skipped == 1
    assert calls["llm"] == 1


def test_run_daily_skips_duplicate_by_title_similarity(monkeypatch, tmp_path) -> None:
    config = _make_config(tmp_path)
    config.dedupe.title_similarity_threshold = 0.8
    config.dedupe.content_similarity_threshold = 0.8
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text("system", encoding="utf-8")

    a1 = Article(
        source="A",
        title="Critical Vulnerability in Product X Allows RCE",
        url="https://example.com/t1",
        published_at="2026-02-19",
        summary="s1",
        content="same core content token alpha beta gamma",
        content_hash="hash1",
    )
    a2 = Article(
        source="A",
        title="Critical Vulnerability in Product X Enables RCE",
        url="https://example.com/t2",
        published_at="2026-02-19",
        summary="s2",
        content="same core content token alpha beta gamma",
        content_hash="hash2",
    )
    monkeypatch.setattr("cti_collector.pipeline.getenv_required", lambda name: "dummy")
    monkeypatch.setattr("cti_collector.pipeline.collect_articles", lambda **kwargs: [a1, a2])

    calls = {"llm": 0}

    class DummyLLM:
        def summarize(self, user_prompt: str):
            calls["llm"] += 1
            return _llm_result("https://example.com/t1")

    class DummyJira:
        def __init__(self):
            self.comments = []

        def search_existing_intel_by_source_url(self, issue_type, source_url, source_field_id):
            return None

        def create_intel_issue(self, summary, description, labels, intel):
            return "CTI-1"

        def create_validation_issue(self, summary, description, labels, validation):
            return "CTI-2"

        def link_validation_to_intel(self, validation_key, intel_key):
            return None

        def add_comment(self, issue_key, text):
            self.comments.append((issue_key, text))

    jira = DummyJira()
    monkeypatch.setattr("cti_collector.pipeline.LLMClient", lambda **kwargs: DummyLLM())
    monkeypatch.setattr("cti_collector.pipeline.JiraClient", lambda **kwargs: jira)

    stats = run_daily(config, {"plat_windows", "type_vuln"}, str(prompt_path), enable_jql_fallback=False)
    assert stats.fetched == 2
    assert stats.created == 1
    assert stats.skipped == 1
    assert calls["llm"] == 1
    assert len(jira.comments) == 1
    assert jira.comments[0][0] == "CTI-1"
