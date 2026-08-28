import json, logging, os, queue, signal, threading, time
from dataclasses import replace
from pathlib import Path
from .hardware import open_deck, render_key
from .models import PulseState
from .pulse import PulseClient
from .render import pages

LOG = logging.getLogger("boetticher.streamdeck")

def load_config(): return json.loads(Path("/etc/boetticher/streamdeck.json").read_text())

class Application:
    def __init__(self, config, client, deck_factory=open_deck):
        self.config, self.client, self.deck_factory = config, client, deck_factory
        self.actions, self.stop = queue.SimpleQueue(), threading.Event(); self.state = None; self.page = config["default_page"]; self.offset = 0
    def poll(self):
        last_error = None
        while not self.stop.is_set():
            try: self.state = self.client.fetch(); last_error = None
            except Exception as error:
                message = type(error).__name__
                if self.state is not None: self.state = replace(self.state, stale_reason=message)
                if message != last_error: LOG.warning("Pulse polling stale: %s", message); last_error = message
            self.stop.wait(self.config["refresh_seconds"])
    def callback(self, deck, key, pressed):
        if pressed: self.actions.put(key)
    def navigate(self, deck):
        count = deck.key_count()
        while not self.actions.empty():
            key = self.actions.get()
            if key == count - 3: self.offset = max(0, self.offset - max(1, count - 3))
            elif key == count - 2: self.page, self.offset = "overview", 0
            elif key == count - 1: self.page, self.offset = "guests", self.offset + max(1, count - 3)
    def render(self, deck):
        state = self.state
        if state is None:
            for key in range(deck.key_count()): render_key(deck, key, "PULSE", "?", "?")
            return
        resources = pages(state.resources, self.config["pinned_guests"])
        cells = [("PULSE", state.status, "warn" if state.stale_reason else state.status), ("ALERTS", str(state.alerts), "ok" if state.alerts == 0 else "warn"), ("AGE", f"{state.age_seconds}s", "warn" if state.stale_reason else "ok")]
        if self.page == "guests": cells = [(r.name, r.status.upper() if r.status else "?", "down" if r.status.lower() in ("down", "offline") else "ok" if r.status.lower() in ("up", "online", "ok") else "?") for r in resources]
        else: cells += [(r.name, r.status.upper() if r.status else "?", "down" if r.status.lower() in ("down", "offline") else "ok" if r.status.lower() in ("up", "online", "ok") else "?") for r in resources[:max(0, deck.key_count()-6)]]
        nav = [("PREV", "", "?"), ("HOME", "", "?"), ("NEXT", "", "?")]
        for key in range(deck.key_count() - 3):
            title, value, status = cells[key+self.offset] if key+self.offset < len(cells) else ("", "", "?")
            render_key(deck, key, title, value, status)
        for index, cell in enumerate(nav, deck.key_count()-3): render_key(deck, index, *cell)
    def run(self):
        worker = threading.Thread(target=self.poll, daemon=True); worker.start(); deck = None; last_connected = None
        while not self.stop.is_set():
            if deck is None:
                try: deck = self.deck_factory(self.config.get("serial", "")); deck.set_brightness(self.config["brightness"]); deck.set_key_callback(self.callback)
                except Exception as error:
                    if last_connected is not False: LOG.warning("StreamDeck disconnected: %s", type(error).__name__); last_connected = False
                    self.stop.wait(3); continue
                LOG.info("StreamDeck connected"); last_connected = True
            try: self.navigate(deck); self.render(deck); self.stop.wait(1)
            except Exception as error: LOG.warning("StreamDeck disconnected: %s", type(error).__name__); deck.close(); deck = None
        if deck: deck.close()

def main():
    logging.basicConfig(level=logging.INFO); config = load_config(); token = Path(os.environ["CREDENTIALS_DIRECTORY"], "pulse-token").read_text().strip()
    client = PulseClient(config["pulse_url"], token, (config["client_certificate"], config["client_key"]), config["ca_certificate"], config["request_timeout_seconds"])
    app = Application(config, client)
    signal.signal(signal.SIGTERM, lambda *_: app.stop.set()); signal.signal(signal.SIGINT, lambda *_: app.stop.set()); app.run()
