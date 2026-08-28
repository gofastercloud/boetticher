from datetime import datetime, timezone
from io import BytesIO

import httpx
from PIL import Image

from boetticher_pi_streamdeck.app import Application
from boetticher_pi_streamdeck.hardware import FakeDeck, _open_matching_deck, blank_deck, render_key, render_screensaver
from boetticher_pi_streamdeck.models import Resource
from boetticher_pi_streamdeck.pulse import PulseClient
from boetticher_pi_streamdeck.render import pages, screensaver_tile, tile


def test_pinned_first_is_deterministic():
    values = (Resource("z", "lxc", "up"), Resource("a", "lxc", "down"))
    assert [item.name for item in pages(values, ["z"])] == ["z", "a"]


def test_tile_matches_requested_geometry():
    rendered = tile(72, 72, "long title", "OK", "ok", "PNG")
    assert Image.open(BytesIO(rendered)).size == (72, 72)


def test_screensaver_uses_requested_geometry_and_changes_frame():
    first = screensaver_tile(72, 72, 0, 0, "PNG")
    second = screensaver_tile(72, 72, 0, 8, "PNG")
    assert Image.open(BytesIO(first)).size == (72, 72)
    assert first != second


def test_fake_deck_writes_rendered_keys(tmp_path):
    deck = FakeDeck(str(tmp_path))
    render_key(deck, 0, "PULSE", "OK", "ok")
    render_screensaver(deck, 1)
    assert len(list(tmp_path.glob("key-*.png"))) == 15
    assert (tmp_path / "key-00.png").read_bytes().startswith(b"\x89PNG")


def test_blank_deck_writes_black_keys(tmp_path):
    deck = FakeDeck(str(tmp_path))
    render_screensaver(deck, 1)
    blank_deck(deck)
    assert Image.open(tmp_path / "key-00.png").getpixel((36, 36)) == (0, 0, 0)


def test_serial_matching_reads_serial_after_opening():
    class ProbeDeck:
        def __init__(self, serial):
            self.serial = serial
            self.opened = False
            self.closed = False

        def open(self):
            self.opened = True

        def get_serial_number(self):
            assert self.opened
            return self.serial

        def close(self):
            self.closed = True

    deck = ProbeDeck("AL33J2C14717")
    assert _open_matching_deck([deck], "AL33J2C14717") is deck
    assert not deck.closed


def test_screensaver_application_needs_no_pulse_credentials(tmp_path):
    deck = FakeDeck(str(tmp_path))
    app = Application(
        {"screensaver_only": True, "default_page": "overview", "brightness": 40},
        None,
    )
    app.render(deck)
    assert (tmp_path / "key-14.png").exists()


def test_next_from_overview_enters_first_guest_page():
    class Deck:
        def key_count(self):
            return 15

    app = Application({"default_page": "overview"}, None)
    app.actions.put(14)
    app.navigate(Deck())
    assert app.page == "guests"
    assert app.offset == 0


def test_next_on_guest_page_advances_by_guest_page_size():
    class Deck:
        def key_count(self):
            return 15

    app = Application({"default_page": "guests"}, None)
    app.page = "guests"
    app.actions.put(14)
    app.navigate(Deck())
    assert app.offset == 12


def test_pulse_rejects_oversized_response():
    client = PulseClient.__new__(PulseClient)
    client.base_url = "https://monitor.example"
    client.total_timeout = 3
    client.client = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"{" + b"x" * (4 * 1024 * 1024) + b"}"))
    )
    try:
        try:
            client._json("/api/state/summary")
        except ValueError as error:
            assert "4 MiB" in str(error)
        else:
            raise AssertionError("oversized Pulse response was accepted")
    finally:
        client.client.close()


def test_pulse_accepts_optional_metrics():
    def handler(request):
        assert request.headers["X-API-Token"] == "read-token"
        if request.url.path.endswith("health"):
            return httpx.Response(200, json={"status": "healthy"})
        if request.url.path.endswith("summary"):
            return httpx.Response(200, json={"activeAlerts": 2})
        if request.url.path.endswith("resources"):
            return httpx.Response(200, json={"resources": [{"name": "guest-01", "type": "lxc", "status": "up"}]})
        return httpx.Response(404)

    client = PulseClient.__new__(PulseClient)
    client.base_url = "https://monitor.example"
    client.total_timeout = 3
    client.client = httpx.Client(transport=httpx.MockTransport(handler))
    client.client.headers["X-API-Token"] = "read-token"
    try:
        state = client.fetch()
        assert state.resources[0].cpu is None
        assert state.status == "healthy"
        assert state.alerts == 2
        assert state.received_at.tzinfo == timezone.utc
    finally:
        client.client.close()
