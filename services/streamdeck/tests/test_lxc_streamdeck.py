from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
import tomllib

import httpx
from PIL import Image

from boetticher_streamdeck.app import Application
from boetticher_streamdeck.hardware import FakeDeck, render_key
from boetticher_streamdeck.models import PulseState, Resource
from boetticher_streamdeck.pulse import PulseClient
from boetticher_streamdeck.render import GREEN, RED, host_value, is_proxmox_host, proxmox_hosts, status_color, tile


def test_package_metadata_allows_only_the_pinned_direct_streamdeck_reference():
    service_dir = Path(__file__).parents[1]
    package = tomllib.loads((service_dir / "pyproject.toml").read_text())
    dependencies = package["project"]["dependencies"]
    direct_dependencies = [dependency for dependency in dependencies if " @ " in dependency]
    lockfile = (service_dir.parents[1] / "images/streamdeck/runtime/requirements.lock").read_text()

    assert package["tool"]["hatch"]["metadata"]["allow-direct-references"] is True
    assert direct_dependencies == [
        "streamdeck @ https://github.com/abcminiuser/python-elgato-streamdeck/archive/5537d6991e651d0d293000fa61ee330d6209c8e5.tar.gz"
    ]
    assert direct_dependencies[0] in lockfile


def test_hardened_service_allows_libusb_udev_and_usb_device():
    unit = (Path(__file__).parents[3] / "images/streamdeck/runtime/streamdeck-status.service").read_text()
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_NETLINK" in unit
    assert "DevicePolicy=closed" in unit
    assert "DeviceAllow=char-usb_device rw" in unit


def test_proxmox_hosts_ignore_guests_and_sort_by_name():
    values = (Resource("node-b", "node", "up"), Resource("guest", "lxc", "up"), Resource("node-a", "node", "up"))
    assert [item.name for item in proxmox_hosts(values)] == ["node-a", "node-b"]
    assert is_proxmox_host(Resource("pve", "pve", "online"))
    assert not is_proxmox_host(Resource("guest", "lxc", "up"))


def test_host_display_includes_cpu_and_ram():
    assert host_value(Resource("node-a", "node", "up", 12.4, 33.6)) == "C 12% R 34%"


def test_status_is_only_green_when_current_and_healthy():
    assert status_color("online") == GREEN
    assert status_color("unknown") == RED
    assert status_color("online", stale=True) == RED


def test_tile_matches_requested_geometry():
    rendered = tile(72, 72, "node-a", "C 12% R 34%", GREEN, "PNG")
    assert Image.open(BytesIO(rendered)).size == (72, 72)


def test_fake_deck_renders_hosts_and_blank_keys_without_callbacks(tmp_path):
    deck = FakeDeck(str(tmp_path))
    app = Application({}, None)
    app.state = PulseState(
        "healthy",
        (Resource("node-b", "node", "up", 10, 20), Resource("node-a", "node", "down", 30, 40)),
        datetime.now(timezone.utc),
    )
    app.render(deck)
    assert len(list(tmp_path.glob("key-*.png"))) == 15
    assert (tmp_path / "key-00.png").read_bytes().startswith(b"\x89PNG")
    assert not hasattr(deck, "callback")


def test_render_marks_all_hosts_red_when_pulse_is_stale(tmp_path):
    deck = FakeDeck(str(tmp_path))
    app = Application({}, None)
    app.state = PulseState(
        "healthy",
        (Resource("node-a", "node", "up", 10, 20),),
        datetime.now(timezone.utc),
        stale_reason="ConnectError",
    )
    app.render(deck)
    image = Image.open(tmp_path / "key-00.png")
    assert image.getpixel((36, 36)) == (155, 28, 28)


def test_pulse_client_uses_bounded_mtls_read_contract_and_paginates():
    requests = []

    def handler(request):
        requests.append(request)
        if request.url.path.endswith("health"):
            return httpx.Response(200, json={"status": "healthy"})
        if request.url.path.endswith("summary"):
            return httpx.Response(200, json={})
        if request.url.path.endswith("resources"):
            offset = request.url.params.get("offset")
            if offset == "0":
                resources = [{"name": "node-a", "type": "node", "status": "up", "metrics": {"cpu": 10, "memory": 20}}] * 100
            else:
                resources = [{"name": "node-b", "type": "node", "status": "down", "metrics": {"cpu": 101, "memory": 30}}]
            return httpx.Response(200, json={"resources": resources})
        return httpx.Response(404)

    client = PulseClient.__new__(PulseClient)
    client.base_url = "https://monitor.example"
    client.total_timeout = 3
    client.client = httpx.Client(transport=httpx.MockTransport(handler), headers={"X-API-Token": "read-token"})
    try:
        state = client.fetch()
        assert requests[0].headers["X-API-Token"] == "read-token"
        assert [request.url.params["offset"] for request in requests if request.url.path.endswith("resources")] == ["0", "100"]
        assert state.resources[0].cpu == 10
        assert state.resources[-1].cpu is None
    finally:
        client.close()


def test_pulse_client_loads_mtls_certificate_into_httpx_tls_context(monkeypatch):
    calls = {}

    class FakeContext:
        def load_cert_chain(self, certfile, keyfile):
            calls["cert"] = certfile
            calls["key"] = keyfile

    context = FakeContext()

    def fake_context(cafile):
        calls["ca"] = cafile
        return context

    class FakeClient:
        def __init__(self, **kwargs):
            calls["client"] = kwargs

        def close(self):
            pass

    monkeypatch.setattr("boetticher_streamdeck.pulse.ssl.create_default_context", fake_context)
    monkeypatch.setattr("boetticher_streamdeck.pulse.httpx.Client", FakeClient)

    client = PulseClient("https://monitor.example", "read-token", ("client.pem", "client.key"), "ca.pem")
    try:
        assert calls["ca"] == "ca.pem"
        assert calls["cert"] == "client.pem"
        assert calls["key"] == "client.key"
        assert calls["client"]["verify"] is context
        assert "cert" not in calls["client"]
    finally:
        client.close()


def test_pulse_rejects_oversized_response():
    client = PulseClient.__new__(PulseClient)
    client.base_url = "https://monitor.example"
    client.total_timeout = 3
    client.client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200, content=b"{" + b"x" * (4 * 1024 * 1024) + b"}")))
    try:
        try:
            client._json("/api/health")
        except ValueError as error:
            assert "4 MiB" in str(error)
        else:
            raise AssertionError("oversized Pulse response was accepted")
    finally:
        client.close()
