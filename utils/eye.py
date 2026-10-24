"""
The Red Eye logo: an original line-art eye drawn procedurally in braille
dots (2x4 per terminal cell), so it scales to any size and owes nothing to
third-party artwork. Lids, an aperture-style iris and a target crosshair.
"""
import math
from typing import List, Set, Tuple

from rich.style import Style
from rich.text import Text

RGB = Tuple[int, int, int]

DARK = (165, 8, 8)
BRIGHT = (255, 48, 48)

# Braille dot bit for (dx, dy) inside a 2x4 cell.
_BRAILLE_BITS = {(0, 0): 0x01, (0, 1): 0x02, (0, 2): 0x04, (1, 0): 0x08,
                 (1, 1): 0x10, (1, 2): 0x20, (0, 3): 0x40, (1, 3): 0x80}

WORDMARK = (
    "██████╗ ███████╗██████╗     ███████╗██╗   ██╗███████╗",
    "██╔══██╗██╔════╝██╔══██╗    ██╔════╝╚██╗ ██╔╝██╔════╝",
    "██████╔╝█████╗  ██║  ██║    █████╗   ╚████╔╝ █████╗  ",
    "██╔══██╗██╔══╝  ██║  ██║    ██╔══╝    ╚██╔╝  ██╔══╝  ",
    "██║  ██║███████╗██████╔╝    ███████╗   ██║   ███████╗",
    "╚═╝  ╚═╝╚══════╝╚═════╝     ╚══════╝   ╚═╝   ╚══════╝",
)


def _mix(a: RGB, b: RGB, t: float) -> RGB:
    t = max(0.0, min(1.0, t))
    return tuple(round(x + (y - x) * t) for x, y in zip(a, b))


def eye_dots(width: int, height: int) -> Set[Tuple[int, int]]:
    """Lit dots on a width x height dot canvas."""
    dots: Set[Tuple[int, int]] = set()
    cx, cy = (width - 1) / 2, (height - 1) / 2
    half_w = width / 2 * 0.80          # the outer fifth holds the crosshair arms
    lid_h = height / 2 - 1.0
    iris_r = lid_h * 0.92

    def put(x: float, y: float) -> None:
        xi, yi = round(x), round(y)
        if 0 <= xi < width and 0 <= yi < height:
            dots.add((xi, yi))

    def lids(x: float) -> Tuple[float, float]:
        u = (x - cx) / half_w
        k = max(0.0, 1 - u * u)
        return cy - lid_h * k, cy + lid_h * 0.86 * k ** 1.1

    # Lids, the upper one drawn heavier.
    steps = int(half_w * 8)
    for i in range(-steps, steps + 1):
        x = cx + half_w * i / steps
        top, bottom = lids(x)
        put(x, top)
        put(x, bottom)
        if abs(i) < steps * 0.92:
            put(x, top - 1)
            put(x, bottom + 1)
        if abs(i) < steps * 0.70 and height >= 32:
            put(x, top - 2)

    # Iris: outer ring, inner ring and aperture spokes, clipped to the opening.
    def put_inside(x: float, y: float) -> None:
        top, bottom = lids(x)
        if top + 0.8 < y < bottom - 0.8:
            put(x, y)

    small = height < 32
    for ring in (iris_r,) if small else (iris_r, iris_r * 0.66):
        n = int(ring * 14)
        for i in range(n):
            a = 2 * math.pi * i / n
            put_inside(cx + ring * math.cos(a), cy + ring * math.sin(a))
    blades = 0 if small else 12
    for b in range(blades):
        a0 = 2 * math.pi * b / blades
        for s in range(12):
            t = s / 11
            r = iris_r * (0.40 + 0.52 * t)
            a = a0 + 0.55 * t               # curved blades, like a camera aperture
            put_inside(cx + r * math.cos(a), cy + r * math.sin(a))

    # Pupil: solid, with a glint cut out.
    pupil_r = iris_r * (0.48 if small else 0.36)
    glint_x, glint_y, glint_r = cx - pupil_r * 0.35, cy - pupil_r * 0.35, max(0.9, pupil_r * 0.28)
    for y in range(height):
        for x in range(width):
            if math.hypot(x - cx, y - cy) <= pupil_r and math.hypot(x - glint_x, y - glint_y) > glint_r:
                dots.add((x, y))

    # Crosshair: dashed arms beyond the corners, short ticks above and below.
    gap = 2
    for x in range(0, round(cx - half_w) - gap):
        if x % 3 != 2:
            put(x, cy)
            put(width - 1 - x, cy)
    tick = max(1, round(height * 0.12))
    for y in range(tick):
        put(cx, y)
        put(cx, height - 1 - y)
    return dots


def render_eye(columns: int = 30, rows: int = 7) -> Text:
    """The eye as Rich Text, `columns` wide and `rows` tall."""
    width, height = columns * 2, rows * 4
    dots = eye_dots(width, height)
    text = Text(no_wrap=True, overflow="crop")
    for r in range(rows):
        for c in range(columns):
            code = 0
            for (dx, dy), bit in _BRAILLE_BITS.items():
                if (c * 2 + dx, r * 4 + dy) in dots:
                    code |= bit
            if not code:
                text.append(" ")
                continue
            # Brighter towards the centre, darker at the edges.
            dist = math.hypot((c - columns / 2) / (columns / 2), (r - rows / 2) / (rows / 2))
            text.append(chr(0x2800 + code), Style(color="rgb%s" % (_mix(BRIGHT, DARK, dist ** 1.2),)))
        if r < rows - 1:
            text.append("\n")
    return text


def render_wordmark() -> Text:
    """'RED EYE' in block letters, shaded top to bottom."""
    text = Text(no_wrap=True, overflow="crop")
    for i, line in enumerate(WORDMARK):
        text.append(line, Style(color="rgb%s" % (_mix(BRIGHT, DARK, i / (len(WORDMARK) - 1)),), bold=True))
        if i < len(WORDMARK) - 1:
            text.append("\n")
    return text
