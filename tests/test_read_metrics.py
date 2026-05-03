"""Tests for read_metrics."""

from __future__ import annotations

from osi_runtime_mcp.tools.read_metrics import (
    _extract_metrics_url,
    parse_prom_exposition,
)


def test_extract_metrics_url_simple():
    assert _extract_metrics_url("0.0.0.0:8007->8000/tcp") == "http://127.0.0.1:8007/metrics"


def test_extract_metrics_url_ipv6():
    assert _extract_metrics_url("[::]:8007->8000/tcp") == "http://127.0.0.1:8007/metrics"


def test_extract_metrics_url_dual():
    url = _extract_metrics_url("0.0.0.0:8007->8000/tcp, [::]:8007->8000/tcp")
    assert url == "http://127.0.0.1:8007/metrics"


def test_extract_metrics_url_none():
    assert _extract_metrics_url("") is None
    assert _extract_metrics_url("not-a-port-mapping") is None


def test_parse_prom_basic():
    text = """
# HELP requests_total Total HTTP requests
# TYPE requests_total counter
requests_total{method="GET",status="200"} 100
requests_total{method="POST",status="500"} 5
heap_bytes 1234567
""".strip()
    out = parse_prom_exposition(text)
    assert "requests_total" in out
    assert out["requests_total"]['method=GET,status=200'] == 100.0
    assert out["requests_total"]['method=POST,status=500'] == 5.0
    assert out["heap_bytes"][""] == 1234567.0


def test_parse_prom_handles_inf_nan():
    import math

    text = "x_seconds 1.5\nx_inf +Inf\nx_nan NaN\n"
    out = parse_prom_exposition(text)
    assert out["x_seconds"][""] == 1.5
    # Python's float() accepts these — that's fine, value is just a float
    assert math.isinf(out["x_inf"][""])
    assert math.isnan(out["x_nan"][""])


def test_parse_prom_skips_comments():
    text = "# HELP foo bar\n# TYPE foo gauge\nfoo 1\n"
    out = parse_prom_exposition(text)
    assert out == {"foo": {"": 1.0}}
