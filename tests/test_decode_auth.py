"""Unit tests for HiveMindTornadoWebSocket.decode_auth.

Regression coverage for the crash fixed in #12: bad base64 / malformed
payloads used to raise binascii.Error out of pybase64.b64decode and crash
the Tornado handler. decode_auth must now raise a plain ValueError (or
UnicodeDecodeError) for every malformed-input case, which the caller in
open() catches at the boundary.
"""
import pybase64
import pytest

from hivemind_websocket_protocol import HiveMindTornadoWebSocket


def _encode(s: str) -> str:
    return pybase64.b64encode(s.encode("utf-8")).decode("ascii")


class TestDecodeAuthValid:
    def test_simple_name_and_key(self):
        assert HiveMindTornadoWebSocket.decode_auth(_encode("alice:secret")) == ("alice", "secret")

    def test_key_containing_colon(self):
        # split(":", 1) — colons inside the key must be preserved
        assert HiveMindTornadoWebSocket.decode_auth(_encode("alice:a:b:c")) == ("alice", "a:b:c")

    def test_unicode_name_and_key(self):
        assert HiveMindTornadoWebSocket.decode_auth(_encode("ünïcødé:kéy")) == ("ünïcødé", "kéy")


class TestDecodeAuthRejected:
    """Every malformed input must raise ValueError or UnicodeDecodeError —
    never a bare binascii.Error escaping into Tornado (the original crash)."""

    @pytest.mark.parametrize("bad", [
        None,
        "",
        "not_base64!@#",        # invalid base64 alphabet
        "YWxpY2U",              # valid b64 but decodes to "alice" — no colon
        _encode(":secret"),     # empty name
        _encode("alice:"),      # empty key
        _encode(":"),           # both empty
        "QQ",                   # decodes to "A" — no colon
    ])
    def test_rejects_malformed(self, bad):
        with pytest.raises((ValueError, UnicodeDecodeError)):
            HiveMindTornadoWebSocket.decode_auth(bad)

    def test_rejects_padding_error_from_traceback(self):
        # This is the exact failure mode from the PR #12 traceback:
        # pybase64.b64decode raised binascii.Error "Incorrect padding".
        # It must now surface as ValueError so open() can catch it.
        with pytest.raises(ValueError):
            HiveMindTornadoWebSocket.decode_auth("YWxpY2U6c2VjcmV0X")

    def test_rejects_invalid_utf8(self):
        # valid base64, but the decoded bytes aren't valid UTF-8
        bad = pybase64.b64encode(b"\xff\xfe:\xff").decode("ascii")
        with pytest.raises((ValueError, UnicodeDecodeError)):
            HiveMindTornadoWebSocket.decode_auth(bad)
