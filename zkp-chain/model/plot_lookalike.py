"""
plot_lookalike.py — Fig. lookalike: K-screening lookalike attack vs the bound.

Measured success (best of K screened candidates, one presentation, circuit
decisions) with 95% Wilson intervals, from targeted_impostor.py for the
deployed point (PCA-128, tau = 0.35) and the zero-effort rule's point (PCA-96,
tau = 0.33); the bound 1 - (1 - FAR)^K of Proposition prop:lookalike with the
deployed point's test FAR (operating_point_targeted.json), as in make_numbers.py.

Usage (from model/):  venv312/bin/python plot_lookalike.py
"""

import json
import math
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.lines import Line2D
from matplotlib.ticker import FuncFormatter, NullFormatter

from ieee_style import COL_W, C, save, setup

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent / "api-server" / "benchmark"
OUT = HERE.parent / "IEEE_Transaction_Mahin" / "figures" / "fig_lookalike.pdf"
KS = ("1", "10", "100", "1000")

deployed = json.loads((BENCH / "targeted_impostor_d128_t35.json").read_text())
zero_effort = json.loads((BENCH / "targeted_impostor_d96_t33.json").read_text())
far = json.loads((BENCH / "operating_point_targeted.json").read_text())["selected"]["test_far"]


def wilson(k, n, z=1.96):
    p = k / n
    centre = (p + z * z / (2 * n)) / (1 + z * z / n)
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / (1 + z * z / n)
    return centre - half, centre + half


def series(by_pool):
    ks, ys, lo, hi = [], [], [], []
    for k in KS:
        r = by_pool[k]
        a, b = wilson(r["accepted"], r["trials"])
        ks.append(int(k)); ys.append(100 * r["success_rate"])
        lo.append(100 * (r["success_rate"] - a)); hi.append(100 * (b - r["success_rate"]))
    return np.array(ks), np.array(ys), np.array([lo, hi])


DATASETS = (("LFW", lambda t: t["lfw"]["by_pool_size"], "o", "-"),
            ("CelebA", lambda t: t["celeba"]["by_pool_size"], "s", "--"),
            ("CelebA, same gender", lambda t: t["celeba"]["same_gender_by_pool_size"], "^", ":"))
POINTS = ((deployed, C["blue"], "white", 1.0),     # hollow markers: deployed
          (zero_effort, C["vermillion"], None, 0.97))   # filled: zero-effort rule; tiny x offset

setup()
fig, ax = plt.subplots(figsize=(COL_W, 2.45))
K = np.logspace(0, 3, 200)
ax.plot(K, 100 * (1 - (1 - far) ** K), color=C["black"], lw=0.8, zorder=2)
ax.axhline(1.0, color=C["gray"], lw=0.6, ls=(0, (4, 2)), zorder=1)
ax.text(1.05, 1.15, r"1\% design target", fontsize=6.5, color=C["gray"], va="bottom")
ax.axvline(100, color=C["gray"], lw=0.5, ls=":", zorder=1)

for data, color, mfc, shift in POINTS:
    for _, get, marker, ls in DATASETS:
        ks, ys, err = series(get(data))
        ax.errorbar(ks * shift, ys, yerr=err, color=color, marker=marker, ls=ls, mfc=mfc or color,
                    mew=0.9, ms=3.8, elinewidth=0.6, capsize=1.5, zorder=3)

ax.set_xscale("log")
ax.set_yscale("log")
ax.set_xlim(0.8, 1300)
ax.set_ylim(1e-3, 100)
fmt = FuncFormatter(lambda v, _: f"{v:g}")
ax.xaxis.set_major_formatter(fmt)
ax.yaxis.set_major_formatter(fmt)
ax.yaxis.set_minor_formatter(NullFormatter())
ax.set_xlabel(r"Candidates screened by the attacker, $K$")
ax.set_ylabel(r"Targets impersonated (\%)")

handles = [Line2D([], [], color=C["blue"], marker="o", mfc="white", mew=0.9, ls="-",
                  label=r"Deployed: PCA-128, $\tau{=}0.35$"),
           Line2D([], [], color=C["vermillion"], marker="o", ls="-",
                  label=r"Zero-effort rule: PCA-96, $\tau{=}0.33$"),
           Line2D([], [], color=C["black"], lw=0.8, label=r"Bound $1-(1-\mathrm{FAR})^K$, LFW FAR")]
handles += [Line2D([], [], color=C["gray"], marker=m, mfc="white", mew=0.9, ls=ls, label=name)
            for name, _, m, ls in DATASETS]
ax.legend(handles=handles, loc="lower center", bbox_to_anchor=(0.5, 1.01), ncol=2, columnspacing=0.9,
          handlelength=2.2, borderaxespad=0.0)
save(fig, OUT)
