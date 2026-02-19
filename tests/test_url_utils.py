from cti_collector.url_utils import normalize_url


def test_normalize_url_removes_tracking_and_fragment_and_sorts_query() -> None:
    url = "https://example.com/path?b=2&utm_source=x&a=1#section"
    normalized = normalize_url(url)
    assert normalized == "https://example.com/path?a=1&b=2"


def test_normalize_url_removes_common_click_ids() -> None:
    url = "https://example.com/?gclid=abc&fbclid=def&x=1"
    normalized = normalize_url(url)
    assert normalized == "https://example.com/?x=1"
