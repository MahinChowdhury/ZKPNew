"""
plot_det.py — Fig. det: DET curves (FNMR vs FMR, log axes) on LFW.

Curves from det_curves.py (api-server/benchmark/det_curves.json); the circuit's
operating point (integer coordinates, tau = 0.35, test pairs) from
select_operating_point_targeted.py (operating_point_targeted.json).

Usage (from model/):  venv312/bin/python plot_det.py
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter, LogLocator, NullFormatter

from ieee_style import COL_W, C, save, setup

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent / "api-server" / "benchmark"
OUT = HERE.parent / "IEEE_Transaction_Mahin" / "figures" / "fig_det.pdf"

curves = json.loads((BENCH / "det_curves.json").read_text())["curves"]
op = json.loads((BENCH / "operating_point_targeted.json").read_text())["selected"]

SERIES = (("insightface_raw512", "ArcFace, raw 512-D", C["black"], "-", 0.9),
          ("insightface_pca128", "ArcFace, PCA-128 (deployed)", C["blue"], "-", 1.5),
          ("insightface_pca64", "ArcFace, PCA-64", C["sky"], (0, (4, 1.5)), 1.0),
          ("facenet_pca64", "FaceNet, PCA-64", C["vermillion"], (0, (4, 1.2, 1, 1.2)), 1.0))

setup()
fig, ax = plt.subplots(figsize=(COL_W, 2.45))
ax.plot([1e-3, 100], [1e-3, 100], color=C["gray"], lw=0.5, ls=":", zorder=1)
ax.text(30, 22, "EER", fontsize=6.5, color=C["gray"], rotation=38, ha="center", va="center")
for key, label, color, ls, lw in SERIES:
    pts = [(100 * fmr, 100 * fnmr) for fmr, fnmr in curves[key] if fmr > 0 and fnmr > 0]
    ax.plot(*zip(*pts), color=color, ls=ls, lw=lw, label=label, zorder=3)
ax.plot([100 * op["test_far"]], [100 * op["test_frr"]], marker="*", color=C["black"], ms=8, ls="none",
        zorder=5, label=rf"Circuit operating point, $\tau{{=}}{op['tau']:g}$")

ax.set_xscale("log")
ax.set_yscale("log")
ax.set_xlim(1e-3, 100)
ax.set_ylim(1e-2, 100)
fmt = FuncFormatter(lambda v, _: f"{v:g}")
for axis in (ax.xaxis, ax.yaxis):
    axis.set_major_locator(LogLocator(base=10, numticks=10))
    axis.set_major_formatter(fmt)
    axis.set_minor_formatter(NullFormatter())
ax.set_xlabel(r"False match rate, FMR (\%)")
ax.set_ylabel(r"False non-match rate, FNMR (\%)")
ax.legend(loc="lower center", bbox_to_anchor=(0.5, 1.01), ncol=2, columnspacing=1.0,
          handlelength=2.2, borderaxespad=0.0)
save(fig, OUT)
