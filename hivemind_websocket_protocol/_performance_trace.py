"""Opt-in request tracing for the websocket receive boundary.

Request identifiers belong in diagnostic logs, never Prometheus labels.  This
module intentionally lives with the transport so the protocol does not require
an unreleased HiveMind-core version merely to expose its own receive boundary.
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections import deque
from typing import Any

_LOG = logging.getLogger("hivemind.performance.trace")
_TRUE_VALUES = {"1", "true", "yes", "on"}
_DIRECT_ID_KEYS = ("query_id", "request_id", "qa_query_id")
_NESTED_KEYS = ("context", "data", "metadata", "payload")
_MAX_REQUEST_ID_LENGTH = 256
_MAX_SEARCH_NODES = 32


def performance_trace_enabled() -> bool:
    """Return whether diagnostic request tracing is enabled."""
    return os.environ.get(
        "HIVEMIND_PERFORMANCE_TRACE", ""
    ).strip().lower() in _TRUE_VALUES


def message_request_id(message: Any) -> str | None:
    """Find one bounded request ID across known envelope boundaries."""
    pending = deque([message])
    visited: set[int] = set()
    searched = 0
    while pending and searched < _MAX_SEARCH_NODES:
        candidate = pending.popleft()
        if candidate is None:
            continue
        identity = id(candidate)
        if identity in visited:
            continue
        visited.add(identity)
        searched += 1

        if isinstance(candidate, dict):
            for key in _DIRECT_ID_KEYS:
                value = candidate.get(key)
                if isinstance(value, str) and value:
                    return value[:_MAX_REQUEST_ID_LENGTH]
            pending.extend(
                candidate.get(key) for key in _NESTED_KEYS
                if key in candidate
            )
            continue

        for key in _DIRECT_ID_KEYS:
            value = getattr(candidate, key, None)
            if isinstance(value, str) and value:
                return value[:_MAX_REQUEST_ID_LENGTH]
        pending.extend(
            getattr(candidate, key, None) for key in _NESTED_KEYS
            if hasattr(candidate, key)
        )
    return None


def trace_performance_stage(
    stage: str,
    *,
    message: Any = None,
    request_id: str | None = None,
    at_unix_ns: int | None = None,
    at_monotonic_ns: int | None = None,
) -> None:
    """Log one timestamped stage for an explicitly correlated request."""
    if not performance_trace_enabled():
        return
    identifier = request_id or message_request_id(message)
    if not identifier:
        return
    event = {
        "at_monotonic_ns": int(
            at_monotonic_ns if at_monotonic_ns is not None
            else time.monotonic_ns()
        ),
        "at_unix_ns": int(
            at_unix_ns if at_unix_ns is not None else time.time_ns()
        ),
        "request_id": identifier[:_MAX_REQUEST_ID_LENGTH],
        "stage": str(stage),
    }
    _LOG.info(
        "performance_trace %s",
        json.dumps(event, sort_keys=True, separators=(",", ":")),
    )
