"""
ieee_style.py — one figure style for every plot in the paper and supplement.

Text is typeset by LaTeX with the paper's own fonts (newtxtext/newtxmath), at
IEEEtran sizes for a 3.5-in column: 8 pt labels, 7 pt ticks and legends.
Colors are the Okabe–Ito colorblind-safe palette, and every series also has
its own marker and line style, so figures stay readable in grayscale.

    from ieee_style import setup, COL_W, C, save
    setup(); fig, ax = plt.subplots(figsize=(COL_W, 2.3)); ...; save(fig, path)
"""

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

COL_W = 3.5     # IEEEtran column width, inches
PAGE_W = 7.16   # IEEEtran text width, inches

# Okabe–Ito
C = {"black": "#000000", "blue": "#0072B2", "orange": "#E69F00", "vermillion": "#D55E00",
     "green": "#009E73", "sky": "#56B4E9", "purple": "#CC79A7", "yellow": "#F0E442",
     "gray": "#7F7F7F"}


def setup():
    plt.rcParams.update({
        "text.usetex": True,
        "text.latex.preamble": r"\usepackage{newtxtext}\usepackage{newtxmath}",
        "font.family": "serif",
        "font.size": 8,
        "axes.labelsize": 8,
        "axes.titlesize": 8,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "legend.fontsize": 7,
        "axes.linewidth": 0.6,
        "lines.linewidth": 1.0,
        "lines.markersize": 3.5,
        "xtick.direction": "in",
        "ytick.direction": "in",
        "xtick.top": True,
        "ytick.right": True,
        "xtick.major.width": 0.6,
        "ytick.major.width": 0.6,
        "xtick.minor.width": 0.4,
        "ytick.minor.width": 0.4,
        "xtick.major.size": 3,
        "ytick.major.size": 3,
        "xtick.minor.size": 1.5,
        "ytick.minor.size": 1.5,
        "axes.grid": True,
        "axes.grid.which": "major",
        "grid.color": "#D9D9D9",
        "grid.linewidth": 0.4,
        "grid.linestyle": "-",
        "legend.frameon": True,
        "legend.framealpha": 1.0,
        "legend.edgecolor": "#BFBFBF",
        "legend.fancybox": False,
        "legend.borderpad": 0.35,
        "legend.handlelength": 2.0,
        "legend.labelspacing": 0.3,
        "savefig.dpi": 600,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.015,
        "pdf.fonttype": 42,
    })


def save(fig, path):
    """Write the PDF; with FIG_PREVIEW=<dir> set, also a PNG there for viewing."""
    import os
    fig.savefig(path)
    preview = os.environ.get("FIG_PREVIEW")
    if preview:
        fig.savefig(os.path.join(preview, os.path.splitext(os.path.basename(path))[0] + ".png"), dpi=300)
    plt.close(fig)
    print(f"wrote {path}")
