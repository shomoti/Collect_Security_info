from cti_collector.sigma_validate import validate_sigma_rules


def test_validate_sigma_rules_drops_invalid_when_enabled() -> None:
    rules = [
        {"title": "ok", "logsource": {"product": "windows"}, "detection": {"selection": {"a": 1}}, "condition": "selection"},
        {"title": "bad", "logsource": {}, "condition": "selection"},
    ]
    valid, errors = validate_sigma_rules(rules, target_backends=[], drop_invalid_rules=True)
    assert len(valid) == 1
    assert errors


def test_validate_sigma_rules_backend_gate() -> None:
    rules = [{"title": "x", "logsource": {"product": "windows"}, "detection": {"foo": {"a": 1}}, "condition": "foo"}]
    valid, errors = validate_sigma_rules(rules, target_backends=["splunk"], drop_invalid_rules=True)
    assert valid == []
    assert errors
