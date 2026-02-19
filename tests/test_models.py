from cti_collector.models import validate_llm_output


def _valid_payload() -> dict:
    return {
        "title": "T",
        "source": "S",
        "source_url": "https://example.com/a",
        "published_at": "2026-02-19T00:00:00Z",
        "language": "en",
        "tldr": "summary",
        "key_points": ["a", "b", "c"],
        "content_type": "vulnerability",
        "platforms": ["windows"],
        "cves": ["CVE-2025-1234"],
        "products": ["ProductA"],
        "exploit_status": "poc",
        "iocs": {"ips": [], "domains": [], "urls": [], "hashes": [], "emails": [], "files": [], "registry": [], "mutexes": []},
        "detection_notes": [],
        "recommended_actions": [],
        "tags": ["plat_windows", "type_vuln"],
        "impact_score": 70,
        "impact_score_factors": [{"factor": "public exploit", "weight": 20, "reason": "PoC exists"}],
        "confidence": "high",
        "evidence": [{"claim": "PoC available", "basis": "article text"}],
        "sigma_rules": [{"title": "Rule1", "logsource": {"product": "windows"}, "detection": {"selection": {"EventID": 1}}, "condition": "selection"}],
    }


def test_validate_llm_output_accepts_valid_payload() -> None:
    allowed_tags = {"plat_windows", "type_vuln"}
    result = validate_llm_output(_valid_payload(), allowed_tags)
    assert result.ok
    assert result.errors == []


def test_validate_llm_output_rejects_unknown_tags_and_sigma_missing_keys() -> None:
    payload = _valid_payload()
    payload["tags"] = ["unknown_tag"]
    payload["sigma_rules"] = [{"title": "bad"}]
    allowed_tags = {"plat_windows", "type_vuln"}

    result = validate_llm_output(payload, allowed_tags)

    assert not result.ok
    assert any("unknown tags" in e for e in result.errors)
    assert any("missing logsource" in e for e in result.errors)
    assert any("missing detection" in e for e in result.errors)
    assert any("missing condition" in e for e in result.errors)


def test_validate_llm_output_rejects_invalid_cve_and_score() -> None:
    payload = _valid_payload()
    payload["cves"] = ["INVALID"]
    payload["impact_score"] = 101

    result = validate_llm_output(payload, {"plat_windows", "type_vuln"})

    assert not result.ok
    assert any("invalid CVEs" in e for e in result.errors)
    assert any("impact_score" in e for e in result.errors)
