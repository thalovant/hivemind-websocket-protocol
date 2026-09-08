from types import SimpleNamespace

from ovos_bus_client import Message
from ovos_bus_client.session import Session

from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_websocket_protocol import HiveMindTornadoWebSocket


def _montreal_location() -> dict:
    # OVOS-SESSION-1 §3.5 shape; ovos-bus-client >= 2.11 normalizes the legacy
    # nested mycroft.conf city/coordinate/timezone shape into this and no
    # longer emits "city" on serialize.
    return {"lat": 45.5, "lon": -73.6, "tz": "America/Toronto"}


def _handler_with_session(session: Session) -> HiveMindTornadoWebSocket:
    handler = object.__new__(HiveMindTornadoWebSocket)
    handler.client = SimpleNamespace(sess=session)
    return handler


def test_hello_session_is_cached_on_connection() -> None:
    handler = _handler_with_session(Session(session_id="default"))
    hello = HiveMessage(
        HiveMessageType.HELLO,
        {
            "session": Session(
                session_id="sat-session",
                lang="fr-FR",
                location_prefs=_montreal_location(),
                time_format="full",
                site_id="office",
            ).serialize()
        },
    )

    handler._remember_hello_session(hello)

    session = handler.client.sess.serialize()
    assert session["session_id"] == "sat-session"
    assert session["site_id"] == "office"
    assert session["lang"] == "fr-FR"
    assert session["location"]["lat"] == 45.5
    assert session["location"]["lon"] == -73.6
    assert session["location"]["tz"] == "America/Toronto"


def test_bus_session_hydrates_missing_fields_from_cached_connection_session() -> None:
    handler = _handler_with_session(
        Session(
            session_id="sat-session",
            lang="fr-FR",
            location_prefs=_montreal_location(),
            time_format="full",
            site_id="office",
        )
    )
    message = HiveMessage(
        HiveMessageType.BUS,
        Message(
            "recognizer_loop:utterance",
            {"utterances": ["Quelle heure est-il?"]},
            {"session": {"session_id": "sat-session", "site_id": "office"}},
        ),
    )

    hydrated = handler._hydrate_bus_session(message)

    session = hydrated.as_dict["payload"]["context"]["session"]
    assert session["session_id"] == "sat-session"
    assert session["site_id"] == "office"
    assert session["lang"] == "fr-FR"
    assert session["location"]["lat"] == 45.5
    assert session["location"]["lon"] == -73.6
    assert session["location"]["tz"] == "America/Toronto"
    assert session["time_format"] == "full"
