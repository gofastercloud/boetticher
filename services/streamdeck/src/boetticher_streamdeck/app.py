import json
import logging
import os
import signal
import threading
from dataclasses import replace
from pathlib import Path

from .hardware import blank_deck, open_deck, render_key
from .pulse import PulseClient
from .render import host_value, proxmox_hosts, status_color

LOG = logging.getLogger("boetticher.streamdeck")
CONFIG_PATH = Path("/etc/boetticher/streamdeck.json")
BRIGHTNESS = 40
POLL_SECONDS = 5
RENDER_SECONDS = 1
RECONNECT_SECONDS = 3
REQUEST_TIMEOUT_SECONDS = 3.0


def load_config() -> dict:
    return json.loads(CONFIG_PATH.read_text())


class Application:
    def __init__(self, config: dict, client, deck_factory=open_deck):
        self.config = config
        self.client = client
        self.deck_factory = deck_factory
        self.stop = threading.Event()
        self.state = None

    def poll(self) -> None:
        last_error = None
        while not self.stop.is_set():
            try:
                self.state = self.client.fetch()
                last_error = None
            except Exception as error:  # the display remains useful during an outage
                message = type(error).__name__
                if self.state is not None:
                    self.state = replace(self.state, stale_reason=message)
                if message != last_error:
                    LOG.warning("Pulse polling stale: %s", message)
                    last_error = message
            self.stop.wait(POLL_SECONDS)

    def render(self, deck) -> None:
        if self.state is None:
            for index in range(deck.key_count()):
                render_key(deck, index, "PULSE", "WAIT", status_color("unknown"))
            return

        hosts = proxmox_hosts(self.state.resources)
        blank_deck(deck)
        for index in range(deck.key_count()):
            if index >= len(hosts):
                continue
            host = hosts[index]
            render_key(deck, index, host.name, host_value(host), status_color(host.status, bool(self.state.stale_reason)))

        if not hosts:
            render_key(deck, 0, "PULSE", "NO HOSTS", status_color("unknown"))

    def run(self) -> None:
        worker = threading.Thread(target=self.poll, daemon=True)
        worker.start()
        deck = None
        last_connected = None
        try:
            while not self.stop.is_set():
                if deck is None:
                    try:
                        deck = self.deck_factory(self.config.get("serial", ""))
                        deck.set_brightness(BRIGHTNESS)
                    except Exception as error:
                        if last_connected is not False:
                            LOG.warning("StreamDeck disconnected: %s", type(error).__name__)
                            last_connected = False
                        self.stop.wait(RECONNECT_SECONDS)
                        continue
                    LOG.info("StreamDeck connected")
                    last_connected = True
                try:
                    self.render(deck)
                    self.stop.wait(RENDER_SECONDS)
                except Exception as error:
                    LOG.warning("StreamDeck disconnected: %s", type(error).__name__)
                    deck.close()
                    deck = None
        finally:
            if deck is not None:
                try:
                    blank_deck(deck)
                except Exception as error:
                    LOG.warning("Could not blank StreamDeck on stop: %s", type(error).__name__)
                deck.close()
            self.stop.set()
            worker.join(timeout=2)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    config = load_config()
    credential_directory = Path(os.environ["CREDENTIALS_DIRECTORY"])
    token = (credential_directory / "pulse-token").read_text().strip()
    client = PulseClient(
        config["pulse_url"],
        token,
        (config["client_certificate"], config["client_key"]),
        config["ca_certificate"],
        REQUEST_TIMEOUT_SECONDS,
    )
    app = Application(config, client)
    signal.signal(signal.SIGTERM, lambda *_: app.stop.set())
    signal.signal(signal.SIGINT, lambda *_: app.stop.set())
    try:
        app.run()
    finally:
        client.close()


if __name__ == "__main__":
    main()
