import logging

import hivemind_websocket_protocol


def test_package_logger_is_controlled_by_host_runtime(caplog):
    """The library logger must inherit handlers and levels from its host."""
    logger = hivemind_websocket_protocol._log

    assert logger.level == logging.NOTSET
    assert logger.handlers == []
    assert logger.propagate is True

    with caplog.at_level(logging.DEBUG):
        logger.debug("host-controlled websocket debug record")

    assert any(
        record.name == logger.name
        and record.message == "host-controlled websocket debug record"
        for record in caplog.records
    )
