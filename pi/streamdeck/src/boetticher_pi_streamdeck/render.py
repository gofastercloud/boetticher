from functools import lru_cache
from io import BytesIO
import math
import random

from PIL import Image, ImageDraw, ImageFont

COLORS = {"ok": "#176b3a", "warn": "#9a6700", "down": "#9b1c1c", "?": "#374151"}
NAVY = (2, 7, 18)
CYAN = (39, 224, 255)
GREEN = (75, 255, 164)
DIM_CYAN = (8, 62, 80)
DIM_GREEN = (10, 75, 52)

SCREEN_LABELS = tuple("BOETTICHER") + ("PI", "HOLD", "mTLS", "0x0E", "READY")
FONT_PATHS = (
    "/usr/share/fonts/truetype/ocr-a/OCRA.ttf",
    "/usr/share/fonts/truetype/ocr-a/OCRA.TTF",
    "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
)


@lru_cache(maxsize=32)
def _font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in FONT_PATHS:
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    return ImageFont.load_default()


@lru_cache(maxsize=512)
def tile(width: int, height: int, title: str, value: str, status: str, image_format: str) -> bytes:
    image = Image.new("RGB", (width, height), COLORS.get(status.lower(), COLORS["?"]))
    draw = ImageDraw.Draw(image)
    font = _font(max(9, min(width, height) // 7))
    draw.multiline_text(
        (width // 2, height // 2),
        f"{title[:14]}\n{value[:16]}",
        font=font,
        fill="white",
        anchor="mm",
        align="center",
        spacing=3,
    )
    output = BytesIO()
    image.save(output, format=image_format)
    return output.getvalue()


@lru_cache(maxsize=8)
def blank_tile(width: int, height: int, image_format: str) -> bytes:
    output = BytesIO()
    Image.new("RGB", (width, height), (0, 0, 0)).save(output, format=image_format)
    return output.getvalue()


def _centered(draw: ImageDraw.ImageDraw, text: str, font: ImageFont.ImageFont, width: int, y: int, fill: tuple[int, int, int]) -> None:
    bounds = draw.textbbox((0, 0), text, font=font)
    draw.text(((width - (bounds[2] - bounds[0])) // 2, y), text, font=font, fill=fill)


@lru_cache(maxsize=360)
def screensaver_tile(width: int, height: int, index: int, frame: int, image_format: str) -> bytes:
    """Render one lightweight animated 72px StreamDeck key."""

    phase = frame % 24
    image = Image.new("RGB", (width, height), NAVY)
    draw = ImageDraw.Draw(image)

    for y in range(height):
        shade = int(4 + 8 * y / max(1, height - 1))
        draw.line((0, y, width, y), fill=(2, shade, shade + 12))

    rng = random.Random(index * 1009 + phase // 2)
    for line in range(2):
        y = 12 + line * 27 + rng.randrange(-3, 4)
        bend = 15 + rng.randrange(0, max(1, width - 25))
        draw.line((0, y, bend, y, bend + 8, y + 7, width, y + 7), fill=DIM_CYAN, width=1)
        draw.ellipse((bend - 2, y - 2, bend + 2, y + 2), outline=CYAN, width=1)

    glyph_font = _font(max(7, width // 10))
    for glyph in range(4):
        x = 5 + ((glyph * 19 + index * 7 + phase * 3) % max(1, width - 12))
        y = 5 + ((glyph * 13 + index * 11) % max(1, height - 18))
        draw.text((x, y), rng.choice("01ABCDEF<>/\\"), font=glyph_font, fill=DIM_GREEN)

    selected = index == (phase // 2) % 15
    border = GREEN if selected else DIM_CYAN
    draw.rectangle((1, 1, width - 2, height - 2), outline=border, width=2 if selected else 1)

    label = SCREEN_LABELS[index % len(SCREEN_LABELS)]
    if len(label) == 1:
        _centered(draw, label, _font(max(24, width // 2)), width, 16, CYAN)
    else:
        _centered(draw, label, _font(max(11, width // 4)), width, 24, GREEN if selected else CYAN)

    pulse = 0.5 + 0.5 * math.sin((phase + index) / 3.0)
    meter = int((width - 10) * pulse)
    draw.line((5, height - 7, 5 + meter, height - 7), fill=GREEN, width=2)
    draw.text((5, height - 18), f"{index + 1:02d} // NODE", font=_font(7), fill=(114, 156, 166))

    output = BytesIO()
    image.save(output, format=image_format)
    return output.getvalue()


def pages(resources, pinned):
    order = {name: index for index, name in enumerate(pinned)}
    return sorted(resources, key=lambda resource: (0, order[resource.name]) if resource.name in order else (1, resource.name.lower()))
