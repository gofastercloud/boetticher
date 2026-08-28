from datetime import datetime, timezone
import json
import httpx
import pytest

from boetticher_streamdeck.hardware import FakeDeck, render_key
from boetticher_streamdeck.models import PulseState, Resource
from boetticher_streamdeck.pulse import PulseClient
from boetticher_streamdeck.render import pages, tile

def test_pinned_first_is_deterministic():
    values = (Resource("z", "lxc", "up"), Resource("a", "lxc", "down"))
    assert [item.name for item in pages(values, ["z"])] == ["z", "a"]

def test_tile_matches_requested_geometry():
    from PIL import Image
    from io import BytesIO
    rendered = tile(72, 72, "long title", "OK", "ok", "PNG")
    assert Image.open(BytesIO(rendered)).size == (72, 72)

def test_fake_deck_writes_rendered_key(tmp_path):
    deck = FakeDeck(str(tmp_path))
    render_key(deck, 0, "PULSE", "OK", "ok")
    assert (tmp_path / "key-00.png").read_bytes().startswith(b"\x89PNG")

def test_pulse_rejects_oversized_response():
    client = PulseClient.__new__(PulseClient)
    client.base_url = "https://monitor.example"
    client.total_timeout = 3
    client.client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"{" + b"x" * (4*1024*1024) + b"}")))
    with pytest.raises(ValueError, match="4 MiB"):
        client._json("/api/state/summary")

def test_pulse_paginates_and_accepts_optional_metrics():
    def handler(request):
        if request.url.path.endswith("summary"): return httpx.Response(200, json={"status":"ok","alerts":0})
        return httpx.Response(200, json={"resources":[{"name":"guest-01","type":"lxc","status":"up"}]})
    client=PulseClient.__new__(PulseClient); client.base_url="https://monitor.example"; client.total_timeout=3; client.client=httpx.Client(transport=httpx.MockTransport(handler))
    state=client.fetch(); assert state.resources[0].cpu is None and state.status=="ok"
