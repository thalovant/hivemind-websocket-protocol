"""Process-local health endpoint for transport liveness probes."""

from __future__ import annotations

from ipaddress import ip_address
from typing import Any

from tornado import web


LOCAL_HEALTH_PATH = "/_healthz"


def _is_loopback_address(value: Any) -> bool:
    """Return whether ``value`` is an IPv4 or IPv6 loopback address."""

    try:
        return ip_address(str(value)).is_loopback
    except ValueError:
        return False


class LocalHealthHandler(web.RequestHandler):
    """Prove that the listener IOLoop can accept and dispatch a request."""

    def prepare(self) -> None:
        # This is an internal process-health contract, not an unauthenticated
        # public API. Kubernetes runs the probe inside the listener container.
        if not _is_loopback_address(self.request.remote_ip):
            raise web.HTTPError(404)

    def get(self) -> None:
        self.set_header("Cache-Control", "no-store")
        self.set_status(204)
        self.finish()


class HiveMindWebApplication(web.Application):
    """Tornado application that keeps successful local probes out of logs."""

    def log_request(self, handler: web.RequestHandler) -> None:
        if isinstance(handler, LocalHealthHandler) and handler.get_status() == 204:
            return
        super().log_request(handler)
