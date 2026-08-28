import json
import logging
import os
import queue
import signal
import threading
from dataclasses import replace
from pathlib import Path

from .hardware import blank_deck, open_deck, render_key, render_screensaver
from .pulse import PulseClient
from .render import pages

LOG = logging.getLogger("boetticher.pi.streamdeck")
DEFAULT_CONFIG = Path("/etc/boetticher/pi-streamdeck.json")


def load_config() -> dict:
    path = Path(os.environ.get("BOETTICHER_STREAMDECK_CONFIG", DEFAULT_CONFIG))
    return json.loads(path.read_text())


class Application:
    def __init__(self, config: dict, client, deck_factory=open_deck):
        self.config = config
        self.client = client
        self.deck_factory = deck_factory
        self.actions: queue.SimpleQueue[int] = queue.SimpleQueue()
        self.stop = threading.Event()
        self.state = None
        self.page = config.get("default_page", "overview")
        self.offset = 0
        self.frame = 0

    def poll(self) -> None:
        if self.client is None:
            return
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
            self.stop.wait(float(self.config.get("refresh_seconds", 5)))

    def callback(self, _deck, key: int, pressed: bool) -> None:
        if pressed:
            self.actions.put(key)

    def navigate(self, deck) -> None:
        count = deck.key_count()
        while not self.actions.empty():
            key = self.actions.get()
            if key == count - 3:
                self.offset = max(0, self.offset - max(1, count - 3))
            elif key == count - 2:
                self.page, self.offset = "overview", 0
            elif key == count - 1:
                self.page, self.offset = "guests", self.offset + max(1, count - 3)

    def render(self, deck) -> None:
        if self.state is None:
            if self.config.get("screensaver_only", False):
                render_screensaver(deck, self.frame)
            else:
                for key in range(deck.key_count()):
                    render_key(deck, key, "PULSE", "?", "?")
            return

        resources = pages(self.state.resources, self.config.get("pinned_guests", []))
        cells = [
            ("PULSE", self.state.status, "warn" if self.state.stale_reason else self.state.status),
            ("ALERTS", str(self.state.alerts), "ok" if self.state.alerts == 0 else "warn"),
            ("AGE", f"{self.state.age_seconds}s", "warn" if self.state.stale_reason else "ok"),
        ]
        if self.page == "guests":
            cells = [
                (
                    resource.name,
                    resource.status.upper() if resource.status else "?",
                    "down" if resource.status.lower() in ("down", "offline") else "ok" if resource.status.lower() in ("up", "online", "ok") else "?",
                )
                for resource in resources
            ]
        else:
            cells += [
                (
                    resource.name,
                    resource.status.upper() if resource.status else "?",
                    "down" if resource.status.lower() in ("down", "offline") else "ok" if resource.status.lower() in ("up", "online", "ok") else "?",
                )
                for resource in resources[: max(0, deck.key_count() - 6)]
            ]
        nav = [("PREV", "", "?"), ("HOME", "", "?"), ("NEXT", "", "?")]
        for key in range(deck.key_count() - 3):
            title, value, status = cells[key + self.offset] if key + self.offset < len(cells) else ("", "", "?")
            render_key(deck, key, title, value, status)
        for index, cell in enumerate(nav, deck.key_count() - 3):
            render_key(deck, index, *cell)

    def run(self) -> None:
        worker = None
        if self.client is not None:
            worker = threading.Thread(target=self.poll, daemon=True)
            worker.start()

        deck = None
        last_connected = None
        screensaver = bool(self.config.get("screensaver_only", False))
        interval = float(self.config.get("screensaver_frame_seconds", 0.25)) if screensaver else 1.0
        try:
            while not self.stop.is_set():
                if deck is None:
                    try:
                        deck = self.deck_factory(self.config.get("serial", ""))
                        deck.set_brightness(int(self.config.get("brightness", 40)))
                        deck.set_key_callback(self.callback)
                    except Exception as error:
                        if last_connected is not False:
                            LOG.warning("StreamDeck disconnected: %s", type(error).__name__)
                            last_connected = False
                        self.stop.wait(3)
                        continue
                    LOG.info("StreamDeck connected")
                    last_connected = True
                try:
                    self.navigate(deck)
                    self.render(deck)
                    self.frame += 1
                    self.stop.wait(interval)
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
            if worker is not None:
                self.stop.set()
                worker.join(timeout=2)


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    config = load_config()
    client = None
    if not config.get("screensaver_only", False):
        credentials = Path(os.environ["CREDENTIALS_DIRECTORY"])
        token = (credentials / "pulse-token").read_text().strip()
        client = PulseClient(
            config["pulse_url"],
            token,
            (config["client_certificate"], config["client_key"]),
            config["ca_certificate"],
            float(config.get("request_timeout_seconds", 3)),
        )
    app = Application(config, client)
    signal.signal(signal.SIGTERM, lambda *_: app.stop.set())
    signal.signal(signal.SIGINT, lambda *_: app.stop.set())
    app.run()


if __name__ == "__main__":
    main()
