from pathlib import Path
from io import BytesIO
from PIL import Image
from .render import tile

class FakeDeck:
    def __init__(self, directory: str, rows=3, columns=5, key_size=(72, 72), image_format="PNG"):
        self.directory, self.rows, self.columns, self.key_size, self.image_format = Path(directory), rows, columns, key_size, image_format
        self.directory.mkdir(parents=True, exist_ok=True); self.callback = None
    def key_count(self): return self.rows * self.columns
    def key_image_format(self): return {"size": self.key_size, "format": self.image_format}
    def set_brightness(self, brightness): self.brightness = brightness
    def set_key_image(self, index, image): (self.directory / f"key-{index:02d}.png").write_bytes(image)
    def set_key_callback(self, callback): self.callback = callback
    def close(self): pass

def open_deck(serial=""):
    from StreamDeck.DeviceManager import DeviceManager
    decks = [deck for deck in DeviceManager(transport="libusb").enumerate() if deck.is_visual()]
    if serial: decks = [deck for deck in decks if deck.get_serial_number() == serial]
    if len(decks) != 1: raise RuntimeError(f"expected one matching visual StreamDeck, found {len(decks)}")
    deck = decks[0]; deck.open(); return deck

def render_key(deck, index, title, value, status):
    from StreamDeck.ImageHelpers import PILHelper
    width, height = deck.key_image_format()["size"]
    image_format = deck.key_image_format().get("format", "JPEG")
    data = tile(width, height, title, value, status, image_format)
    deck.set_key_image(index, data if isinstance(deck, FakeDeck) else PILHelper.to_native_format(deck, Image.open(BytesIO(data))))
