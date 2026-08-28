from io import BytesIO
from functools import lru_cache
from PIL import Image, ImageDraw, ImageFont

COLORS = {"ok": "#176b3a", "warn": "#9a6700", "down": "#9b1c1c", "?": "#374151"}

@lru_cache(maxsize=512)
def tile(width: int, height: int, title: str, value: str, status: str, image_format: str) -> bytes:
    image = Image.new("RGB", (width, height), COLORS.get(status.lower(), COLORS["?"]))
    draw = ImageDraw.Draw(image); font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", max(9, min(width, height)//7))
    draw.multiline_text((width//2, height//2), f"{title[:14]}\n{value[:16]}", font=font, fill="white", anchor="mm", align="center", spacing=3)
    output = BytesIO(); image.save(output, format=image_format); return output.getvalue()

def pages(resources, pinned):
    order = {name: index for index, name in enumerate(pinned)}
    return sorted(resources, key=lambda r: (0, order[r.name]) if r.name in order else (1, r.name.lower()))
