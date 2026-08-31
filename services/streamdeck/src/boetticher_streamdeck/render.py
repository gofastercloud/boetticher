from functools import lru_cache
from io import BytesIO

from PIL import Image, ImageDraw, ImageFont

GREEN = "#176b3a"
RED = "#9b1c1c"


@lru_cache(maxsize=16)
def _font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in (
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
    ):
        try:
            return ImageFont.truetype(path, size)
        except OSError:
            continue
    return ImageFont.load_default()


def is_proxmox_host(resource) -> bool:
    return resource.kind.casefold() in {"node", "host", "proxmox-host", "pve"}


def proxmox_hosts(resources):
    return tuple(sorted((resource for resource in resources if is_proxmox_host(resource)), key=lambda item: (item.name.casefold(), item.name)))


def status_color(status: str, stale: bool = False) -> str:
    if not stale and status.casefold() in {"up", "online", "ok", "healthy", "running"}:
        return GREEN
    return RED


def metric_value(value: float | None) -> str:
    return "--" if value is None else f"{value:.0f}%"


def host_value(resource) -> str:
    return f"C {metric_value(resource.cpu)} R {metric_value(resource.memory)}"


@lru_cache(maxsize=512)
def tile(width: int, height: int, title: str, value: str, status: str, image_format: str) -> bytes:
    image = Image.new("RGB", (width, height), status)
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
