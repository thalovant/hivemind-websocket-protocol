"""Tests for the process-local listener health contract."""

from unittest.mock import patch

import pytest
from tornado import web
from tornado.testing import AsyncHTTPTestCase

from hivemind_websocket_protocol._health import (
    LOCAL_HEALTH_PATH,
    HiveMindWebApplication,
    LocalHealthHandler,
    _is_loopback_address,
)


class TestLocalHealthHandler(AsyncHTTPTestCase):
    def get_app(self) -> HiveMindWebApplication:
        return HiveMindWebApplication([(LOCAL_HEALTH_PATH, LocalHealthHandler)])

    def test_local_health_is_bodyless_and_quiet(self) -> None:
        with patch.object(web.Application, "log_request") as inherited_logger:
            response = self.fetch(LOCAL_HEALTH_PATH)

        assert response.code == 204
        assert response.body == b""
        assert response.headers["Cache-Control"] == "no-store"
        inherited_logger.assert_not_called()


@pytest.mark.parametrize(
    ("address", "expected"),
    [
        ("127.0.0.1", True),
        ("127.255.255.254", True),
        ("::1", True),
        ("10.42.0.1", False),
        ("2001:db8::1", False),
        ("not-an-address", False),
        (None, False),
    ],
)
def test_loopback_address_validation(address: object, expected: bool) -> None:
    assert _is_loopback_address(address) is expected
