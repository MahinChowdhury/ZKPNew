"""
make_ui_figure.py — paper figure from the browser run's screenshots

bench_browser.py already clips each card to its title and status banner (no
file names; face previews blurred). This tiles four of them 2x2.
Usage: python api-server/benchmark/make_ui_figure.py
Output: IEEE_Transaction_Mahin/figures/fig_ui.png
"""
from pathlib import Path

from PIL import Image

HERE = Path(__file__).resolve().parent
SHOTS = HERE.parent / "results" / "browser_screens"
OUT = HERE.parent.parent / "IEEE_Transaction_Mahin" / "figures" / "fig_ui.png"
PANELS = ["2_register.png", "3_vote.png", "4_impostor.png", "5_tally.png"]
GAP = 24

tiles = [Image.open(SHOTS / n).convert("RGB") for n in PANELS]
rows = [tiles[0:2], tiles[2:4]]
col_w = [max(r[i].width for r in rows) for i in range(2)]   # the receipt card is wider
row_h = [max(t.height for t in r) for r in rows]
canvas = Image.new("RGB", (sum(col_w) + GAP, sum(row_h) + GAP), "white")
y = 0
for r, h in zip(rows, row_h):
    x = 0
    for i, t in enumerate(r):
        canvas.paste(t, (x, y))
        x += col_w[i] + GAP
    y += h + GAP
canvas.save(OUT, dpi=(300, 300))
print(f"wrote {OUT} ({canvas.width}x{canvas.height})")
