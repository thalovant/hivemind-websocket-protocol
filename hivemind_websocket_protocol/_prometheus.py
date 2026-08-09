"""Prometheus exposition for process-local HiveMind latency histograms."""

from __future__ import annotations

import math
import re
from collections.abc import Callable, Mapping, Sequence
from importlib import metadata
from typing import Any

from ovos_utils.log import LOG
from tornado import ioloop, web

from hivemind_websocket_protocol._metrics import performance_histograms

METRIC_ENTRYPOINT_GROUP = "hivemind.performance.metrics"
_PROMETHEUS_NAME = re.compile(r"[a-zA-Z_:][a-zA-Z0-9_:]*")
HistogramCollector = Callable[[], Mapping[str, Mapping[str, object]]]


def load_metric_collectors() -> tuple[tuple[str, HistogramCollector], ...]:
    """Load the local collector and every advertised package collector.

    Entry points make metrics an explicit cross-package contract. A package
    that advertises a broken collector fails listener startup when metrics are
    enabled instead of silently returning an incomplete scrape.
    """
    collectors: list[tuple[str, HistogramCollector]] = [
        ("websocket", performance_histograms),
    ]
    entry_points = sorted(
        metadata.entry_points(group=METRIC_ENTRYPOINT_GROUP),
        key=lambda entry_point: (entry_point.name, entry_point.value),
    )
    for entry_point in entry_points:
        collector = entry_point.load()
        if not callable(collector):
            raise TypeError(
                f"metrics entry point {entry_point.name!r} is not callable"
            )
        collectors.append((entry_point.name, collector))
    return tuple(collectors)


def collect_histograms(
    collectors: Sequence[tuple[str, HistogramCollector]],
) -> dict[str, Mapping[str, object]]:
    """Collect one consistent process-local snapshot from every provider."""
    histograms: dict[str, Mapping[str, object]] = {}
    for collector_name, collector in collectors:
        snapshots = collector()
        if not isinstance(snapshots, Mapping):
            raise TypeError(
                f"metrics collector {collector_name!r} returned a non-mapping"
            )
        for metric_name, snapshot in snapshots.items():
            if metric_name in histograms:
                raise ValueError(f"duplicate performance metric {metric_name!r}")
            if not isinstance(snapshot, Mapping):
                raise TypeError(
                    f"performance metric {metric_name!r} is not a mapping"
                )
            histograms[str(metric_name)] = snapshot
    return histograms


def _prometheus_metric_name(metric_name: str) -> str:
    exported = (
        f"{metric_name[:-3]}_seconds"
        if metric_name.endswith("_ms")
        else metric_name
    )
    if not _PROMETHEUS_NAME.fullmatch(exported):
        raise ValueError(f"invalid Prometheus metric name {exported!r}")
    return exported


def _number(value: Any, field: str, metric_name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(f"{metric_name}.{field} must be numeric")
    parsed = float(value)
    if not math.isfinite(parsed) or parsed < 0:
        raise ValueError(f"{metric_name}.{field} must be finite and non-negative")
    return parsed


def _count(value: Any, field: str, metric_name: str) -> int:
    parsed = _number(value, field, metric_name)
    if not parsed.is_integer():
        raise ValueError(f"{metric_name}.{field} must be an integer")
    return int(parsed)


def render_prometheus(
    histograms: Mapping[str, Mapping[str, object]],
) -> str:
    """Render cumulative millisecond snapshots as Prometheus histograms."""
    lines: list[str] = []
    for metric_name in sorted(histograms):
        snapshot = histograms[metric_name]
        exported = _prometheus_metric_name(metric_name)
        buckets = snapshot.get("buckets")
        if not isinstance(buckets, Mapping):
            raise TypeError(f"{metric_name}.buckets must be a mapping")

        count = _count(snapshot.get("count"), "count", metric_name)
        sum_seconds = _number(
            snapshot.get("sum_ms"),
            "sum_ms",
            metric_name,
        ) / 1000.0
        finite_buckets: list[tuple[float, int]] = []
        infinity_count: int | None = None
        for bucket_name, raw_count in buckets.items():
            bucket_count = _count(raw_count, str(bucket_name), metric_name)
            if bucket_name == "inf":
                infinity_count = bucket_count
                continue
            if not str(bucket_name).startswith("le_"):
                raise ValueError(
                    f"unexpected bucket {bucket_name!r} in {metric_name}"
                )
            bound_ms = float(str(bucket_name)[3:])
            if not math.isfinite(bound_ms) or bound_ms < 0:
                raise ValueError(f"invalid bucket bound in {metric_name}")
            finite_buckets.append((bound_ms, bucket_count))

        finite_buckets.sort(key=lambda item: item[0])
        cumulative = [bucket_count for _, bucket_count in finite_buckets]
        if cumulative != sorted(cumulative):
            raise ValueError(f"non-cumulative buckets in {metric_name}")
        if cumulative and cumulative[-1] > count:
            raise ValueError(f"bucket exceeds count in {metric_name}")
        if infinity_count != count:
            raise ValueError(
                f"{metric_name} infinity bucket does not equal count"
            )

        lines.append(
            f"# HELP {exported} Process-local latency observed by {metric_name}."
        )
        lines.append(f"# TYPE {exported} histogram")
        for bound_ms, bucket_count in finite_buckets:
            lines.append(
                f'{exported}_bucket{{le="{bound_ms / 1000.0:g}"}} '
                f"{bucket_count}"
            )
        lines.append(f'{exported}_bucket{{le="+Inf"}} {count}')
        lines.append(f"{exported}_sum {sum_seconds!r}")
        lines.append(f"{exported}_count {count}")
    return "\n".join(lines) + "\n"


class HiveMindMetricsHandler(web.RequestHandler):
    """Serve one process-local Prometheus scrape without blocking workers."""

    def initialize(
        self,
        collectors: Sequence[tuple[str, HistogramCollector]],
    ) -> None:
        self.collectors = tuple(collectors)

    async def get(self) -> None:
        try:
            payload = await ioloop.IOLoop.current().run_in_executor(
                None,
                lambda: render_prometheus(
                    collect_histograms(self.collectors)
                ),
            )
        except Exception as error:
            LOG.exception("HiveMind metrics scrape failed")
            raise web.HTTPError(500, reason="metrics collection failed") from error
        self.set_header(
            "Content-Type",
            "text/plain; version=0.0.4; charset=utf-8",
        )
        self.set_header("Cache-Control", "no-store")
        self.write(payload)
