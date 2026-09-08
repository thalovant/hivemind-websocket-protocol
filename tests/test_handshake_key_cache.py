"""Rotation safety for the listener's parsed private-key cache.

The cache exists so every connection does not reparse the RSA key. The risk it
carries is that a key rotated *while* one is being parsed gets filed under the
new file's identity, and every later connection then authenticates with the
old key until the next rotation -- long after the rotation should have taken
effect.
"""
import os
from unittest.mock import patch

import pytest

from hivemind_websocket_protocol import (
    _HANDSHAKE_TEMPLATE_CACHE,
    _new_client_handshake,
    _private_key_fingerprint,
)


@pytest.fixture(autouse=True)
def _clear_cache():
    _HANDSHAKE_TEMPLATE_CACHE.clear()
    yield
    _HANDSHAKE_TEMPLATE_CACHE.clear()


def _key_file(tmp_path, content):
    path = tmp_path / "listener.key"
    path.write_text(content)
    return str(path)


class _FakeHandShake:
    """Stands in for HandShake: records the bytes it was constructed from."""

    def __init__(self, path=None):
        self.path = path
        self.parsed = open(path).read() if path else None
        self.target_key = "leftover"
        self.secret = "leftover"


def test_a_key_rotated_during_parsing_is_not_cached(tmp_path):
    path = _key_file(tmp_path, "ORIGINAL")

    def rotate_then_parse(p=None):
        handshake = _FakeHandShake(p)
        # rotation lands while we are parsing
        with open(path, "w") as handle:
            handle.write("ROTATED")
        os.utime(path, (1, 1))
        return handshake

    with patch("hivemind_websocket_protocol.HandShake", side_effect=rotate_then_parse):
        first = _new_client_handshake(path)
    assert first.parsed == "ORIGINAL"
    assert not _HANDSHAKE_TEMPLATE_CACHE, (
        "a key parsed from the pre-rotation file must not be cached under the "
        "post-rotation fingerprint"
    )

    # the next connection must read the rotated key, not a cached stale one
    with patch("hivemind_websocket_protocol.HandShake", side_effect=_FakeHandShake):
        second = _new_client_handshake(path)
    assert second.parsed == "ROTATED"


def test_a_stable_key_is_cached_and_reused(tmp_path):
    path = _key_file(tmp_path, "STABLE")
    with patch("hivemind_websocket_protocol.HandShake", side_effect=_FakeHandShake) as ctor:
        _new_client_handshake(path)
        _new_client_handshake(path)
    assert ctor.call_count == 1, "an unchanged key must be parsed once"
    assert len(_HANDSHAKE_TEMPLATE_CACHE) == 1


def test_every_path_clears_connection_local_fields(tmp_path):
    path = _key_file(tmp_path, "STABLE")
    with patch("hivemind_websocket_protocol.HandShake", side_effect=_FakeHandShake):
        cached_miss = _new_client_handshake(path)
        cached_hit = _new_client_handshake(path)
    for handshake in (cached_miss, cached_hit):
        assert handshake.target_key is None
        assert handshake.secret is None

    # and the path that declines to cache
    def rotate_then_parse(p=None):
        handshake = _FakeHandShake(p)
        os.utime(path, (2, 2))
        return handshake

    _HANDSHAKE_TEMPLATE_CACHE.clear()
    with patch("hivemind_websocket_protocol.HandShake", side_effect=rotate_then_parse):
        uncached = _new_client_handshake(path)
    assert uncached.target_key is None
    assert uncached.secret is None


def test_fingerprint_survives_a_vanishing_file(tmp_path):
    """isfile() then stat() is a race; a missing key must not raise."""
    path = _key_file(tmp_path, "GONE")
    real_stat = os.stat

    def stat_that_vanishes(target, *args, **kwargs):
        if str(target) == os.path.realpath(path):
            raise FileNotFoundError(path)
        return real_stat(target, *args, **kwargs)

    with patch("hivemind_websocket_protocol.os.stat", side_effect=stat_that_vanishes):
        assert _private_key_fingerprint(path) is None
