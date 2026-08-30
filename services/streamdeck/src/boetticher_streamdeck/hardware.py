from io import BytesIO
from pathlib import Path

from PIL import Image

from .render import blank_tile, tile


class FakeDeck:
    """Filesystem-backed deck used by source tests without touching USB."""

    def __init__(self, directory: str, rows: int = 3, columns: int = 5, key_size: tuple[int, int] = (72, 72), image_format: str = "PNG"):
        self.directory = Path(directory)
        self.rows = rows
        self.columns = columns
        self.key_size = key_size
        self.image_format = image_format
        self.directory.mkdir(parents=True, exist_ok=True)

    def key_count(self) -> int:
        return self.rows * self.columns

    def key_image_format(self) -> dict[str, object]:
        return {"size": self.key_size, "format": self.image_format}

    def set_brightness(self, brightness: int) -> None:
        self.brightness = brightness

    def set_key_image(self, index: int, image: bytes) -> None:
        (self.directory / f"key-{index:02d}.png").write_bytes(image)

    def close(self) -> None:
        return None


def open_deck(serial: str = ""):
    from StreamDeck.DeviceManager import DeviceManager

    decks = [deck for deck in DeviceManager(transport="libusb").enumerate() if deck.is_visual()]
    return _open_matching_deck(decks, serial)


def _open_matching_deck(decks, serial: str = ""):
    if not serial and len(decks) != 1:
        raise RuntimeError(f"expected one matching visual StreamDeck, found {len(decks)}")

    if not serial:
        deck = decks[0]
        deck.open()
        return deck

    match = None
    for deck in decks:
        try:
            deck.open()
            if deck.get_serial_number() == serial:
                if match is not None:
                    deck.close()
                    match.close()
                    raise RuntimeError("configured StreamDeck serial is not unique")
                match = deck
            else:
                deck.close()
        except Exception:
            deck.close()
            raise
    if match is None:
        raise RuntimeError("configured StreamDeck serial was not found")
    return match


def _set_key_image(deck, index: int, data: bytes) -> None:
    if isinstance(deck, FakeDeck):
        deck.set_key_image(index, data)
        return
    from StreamDeck.ImageHelpers import PILHelper

    deck.set_key_image(index, PILHelper.to_native_format(deck, Image.open(BytesIO(data))))


def render_key(deck, index: int, title: str, value: str, status: str) -> None:
    width, height = deck.key_image_format()["size"]
    image_format = deck.key_image_format().get("format", "JPEG")
    _set_key_image(deck, index, tile(width, height, title, value, status, image_format))


def blank_deck(deck) -> None:
    width, height = deck.key_image_format()["size"]
    image_format = deck.key_image_format().get("format", "JPEG")
    for index in range(deck.key_count()):
        if isinstance(deck, FakeDeck):
            _set_key_image(deck, index, blank_tile(width, height, image_format))
        else:
            deck.set_key_image(index, None)
