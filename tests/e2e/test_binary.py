"""Binary frame round-trip across the websocket-protocol envelope."""
from hivemind_bus_client.message import HiveMessage, HiveMessageType
from hivemind_bus_client.serialization import HiveMindBinaryPayloadType


FAKE_AUDIO = b"\x00\x01" * 2048
FAKE_FILE = b"hello binary world"
FAKE_TTS = b"\xab\xcd" * 1024
LARGE_PAYLOAD = b"x" * 65_536  # 64 KiB


def _binary(payload: bytes, bin_type: HiveMindBinaryPayloadType, **meta) -> HiveMessage:
    return HiveMessage(
        HiveMessageType.BINARY,
        payload=payload,
        bin_type=bin_type,
        metadata=meta,
    )


def test_raw_audio_round_trip(hive):
    master, satellite = hive
    satellite.send(_binary(FAKE_AUDIO, HiveMindBinaryPayloadType.RAW_AUDIO,
                           sample_rate=16000, sample_width=2))

    master.binary_protocol.assert_called("microphone_input")
    call = master.binary_protocol.last_call("microphone_input")
    assert call.data == FAKE_AUDIO
    assert call.meta["sample_rate"] == 16000


def test_file_payload_round_trip(hive):
    master, satellite = hive
    satellite.send(_binary(FAKE_FILE, HiveMindBinaryPayloadType.FILE,
                           file_name="greeting.txt"))

    master.binary_protocol.assert_called("receive_file")
    call = master.binary_protocol.last_call("receive_file")
    assert call.data == FAKE_FILE
    assert call.meta["file_name"] == "greeting.txt"


def test_stt_transcribe_round_trip(hive):
    master, satellite = hive
    satellite.send(_binary(FAKE_AUDIO, HiveMindBinaryPayloadType.STT_AUDIO_TRANSCRIBE,
                           sample_rate=16000, sample_width=2, lang="en-US"))

    master.binary_protocol.assert_called("stt_transcribe")
    call = master.binary_protocol.last_call("stt_transcribe")
    assert call.data == FAKE_AUDIO
    assert call.meta["lang"] == "en-US"


def test_tts_audio_round_trip(hive):
    master, satellite = hive
    satellite.send(_binary(FAKE_TTS, HiveMindBinaryPayloadType.TTS_AUDIO,
                           utterance="hello world", lang="en-US", file_name="out.wav"))

    master.binary_protocol.assert_called("receive_tts")
    call = master.binary_protocol.last_call("receive_tts")
    assert call.data == FAKE_TTS
    assert call.meta["utterance"] == "hello world"


def test_large_payload_survives_round_trip(hive):
    master, satellite = hive
    satellite.send(_binary(LARGE_PAYLOAD, HiveMindBinaryPayloadType.FILE,
                           file_name="big.bin"))

    call = master.binary_protocol.last_call("receive_file")
    assert len(call.data) == len(LARGE_PAYLOAD)
    assert call.data == LARGE_PAYLOAD


def test_multiple_sequential_payloads_recorded(hive):
    master, satellite = hive
    for i in range(5):
        satellite.send(_binary(f"chunk-{i}".encode(),
                               HiveMindBinaryPayloadType.FILE,
                               file_name=f"chunk-{i}.bin"))

    master.binary_protocol.assert_called("receive_file", count=5)
    names = [c.meta["file_name"] for c in master.binary_protocol.calls
             if c.handler == "receive_file"]
    assert names == [f"chunk-{i}.bin" for i in range(5)]
