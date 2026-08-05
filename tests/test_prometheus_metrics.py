import pytest
from tornado import web
from tornado.testing import AsyncHTTPTestCase

from hivemind_websocket_protocol import _prometheus
from hivemind_websocket_protocol._prometheus import (
    HiveMindMetricsHandler,
    collect_histograms,
    load_metric_collectors,
    render_prometheus,
)


def _collector():
    return {
        "hivemind_bus_write_ms": {
            "name": "hivemind_bus_write_ms",
            "count": 2,
            "sum_ms": 12.5,
            "buckets": {
                "le_1": 0,
                "le_10": 1,
                "le_25": 2,
                "inf": 2,
            },
        },
    }


def test_prometheus_renderer_converts_milliseconds_to_seconds():
    payload = render_prometheus(_collector())

    assert "# TYPE hivemind_bus_write_seconds histogram" in payload
    assert 'hivemind_bus_write_seconds_bucket{le="0.001"} 0' in payload
    assert 'hivemind_bus_write_seconds_bucket{le="0.01"} 1' in payload
    assert 'hivemind_bus_write_seconds_bucket{le="+Inf"} 2' in payload
    assert "hivemind_bus_write_seconds_sum 0.0125" in payload
    assert "hivemind_bus_write_seconds_count 2" in payload


def test_collectors_must_not_publish_duplicate_metrics():
    collectors = (("first", _collector), ("second", _collector))

    with pytest.raises(ValueError, match="duplicate performance metric"):
        collect_histograms(collectors)


def test_metric_collectors_are_discovered_through_explicit_entry_points(
    monkeypatch,
):
    class FakeEntryPoint:
        name = "core"
        value = "hivemind_core._metrics:performance_histograms"

        @staticmethod
        def load():
            return _collector

    monkeypatch.setattr(
        _prometheus.metadata,
        "entry_points",
        lambda *, group: [FakeEntryPoint()],
    )

    collectors = load_metric_collectors()

    assert [name for name, _collector_fn in collectors] == [
        "websocket",
        "core",
    ]


class TestPrometheusMetricsEndpoint(AsyncHTTPTestCase):
    def get_app(self):
        return web.Application([
            (
                r"/metrics",
                HiveMindMetricsHandler,
                {"collectors": (("test", _collector),)},
            ),
        ])

    def test_get_returns_prometheus_text_without_caching(self):
        response = self.fetch("/metrics")

        assert response.code == 200
        assert response.headers["Cache-Control"] == "no-store"
        assert response.headers["Content-Type"].startswith(
            "text/plain; version=0.0.4"
        )
        assert b"hivemind_bus_write_seconds_count 2" in response.body
