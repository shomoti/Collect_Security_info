from cti_collector.ioc import merge_iocs


def test_merge_iocs_extracts_and_dedupes() -> None:
    llm_iocs = {
        "ips": ["1.1.1.1"],
        "domains": ["example.com"],
        "urls": [],
        "hashes": [],
        "emails": [],
        "files": [],
        "registry": [],
        "mutexes": [],
    }
    text = "Observed 1.1.1.1 and hxxps://example[.]com/path and admin@example.com"
    out = merge_iocs(
        llm_iocs=llm_iocs,
        article_text=text,
        enable_regex_extraction=True,
        case_insensitive=True,
        max_items_per_type=50,
    )
    assert "1.1.1.1" in out["ips"]
    assert "example.com" in [x.lower() for x in out["domains"]]
    assert "admin@example.com" in [x.lower() for x in out["emails"]]
    assert len(out["ips"]) == 1
