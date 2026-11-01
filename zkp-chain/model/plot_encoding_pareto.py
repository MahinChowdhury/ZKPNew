"""
plot_encoding_pareto.py — Fig. encoding_pareto (EER vs full-circuit constraints).

EER per PCA output dimension from face_model_sweep.py for the deployed model
(InsightFace buffalo_l) and the FaceNet baseline (face_sweep_<label>.json).
Constraint costs come from api-server/circuits/measure_subcircuits.sh. The
full face circuit at dimension d is the compiled circuit (dimension d0) with
its d-dependent parts substituted:
    full(d) = full(d0) + 2 (H(d) - H(d0)) + (C(d) - C(d0))
(the template is hashed twice — enrolled and live).

Usage (from model/):  venv312/bin/python plot_encoding_pareto.py
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.ticker import FuncFormatter, NullFormatter

from ieee_style import COL_W, C, save, setup

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent / "api-server" / "benchmark"
COST = HERE.parent / "api-server" / "results" / "subcircuit_constraints.json"
VKEY = HERE.parent / "api-server" / "circuits" / "verification_key.json"
OUT = HERE.parent / "IEEE_Transaction_Mahin" / "figures" / "fig_encoding_pareto.pdf"
DEPLOYED = ("insightface", 128)
LABELLED_DIMS = (16, 32, 64, 128, 256)

cost = json.loads(COST.read_text())
d0 = cost.get("face_auth (dim)", 64)
H = lambda d: cost[f"PackedCoordHash({d})"]
Cmp = lambda d: cost[f"SquaredCosineSimilarity({d})"]
full = lambda d: cost["face_auth (full)"] + 2 * (H(d) - H(d0)) + (Cmp(d) - Cmp(d0))
# Groth16 needs constraints + public signals + 1 <= domain size
domain15 = 2 ** 15 - json.loads(VKEY.read_text())["nPublic"] - 1


def curve(label):
    sweep = json.loads((BENCH / f"face_sweep_{label}.json").read_text())
    eer, raw_dim = sweep["eer"], sweep["raw_dim"]
    dims = sorted(int(k[3:]) for k in eer if k.startswith("pca") and f"PackedCoordHash({k[3:]})" in cost)
    raw_x = full(raw_dim) if f"PackedCoordHash({raw_dim})" in cost else None
    return dims, [full(d) / 1e3 for d in dims], [100 * eer[f"pca{d}"]["eer"] for d in dims], \
        100 * eer["raw"]["eer"], (raw_x / 1e3 if raw_x else None), raw_dim


setup()
fig, ax = plt.subplots(figsize=(COL_W, 2.45))

ax.axvline(domain15 / 1e3, color=C["gray"], ls=(0, (4, 2)), lw=0.7, zorder=1)
ax.text(domain15 / 1e3 - 0.4, 0.6, r"$2^{15}$ FFT domain limit", rotation=90, ha="right", va="center",
        fontsize=6.5, color=C["gray"])

series = (("insightface", "ArcFace + PCA (deployed model)", C["blue"], "o", "-"),
          ("facenet", "FaceNet + PCA (baseline)", C["vermillion"], "s", "--"))
for label, name, color, marker, ls in series:
    dims, xs, ys, raw, raw_x, raw_dim = curve(label)
    ax.plot(xs, ys, ls=ls, marker=marker, color=color, mfc="white", mew=0.9, zorder=3)
    if raw_x is not None:
        ax.plot([raw_x], [raw], marker="D", color=color, ls="none", ms=4.2, zorder=4)
    if label == "insightface":
        for d, x, y in zip(dims, xs, ys):
            if d in LABELLED_DIMS and d != DEPLOYED[1]:
                ax.annotate(rf"$d{{=}}{d}$", (x, y), xytext=(3, 3), textcoords="offset points",
                            fontsize=6.5, color=color)
        ax.annotate(rf"raw {raw_dim}-D", (raw_x, raw), xytext=(-4, 4), textcoords="offset points",
                    fontsize=6.5, color=color, ha="right")
        k = dims.index(DEPLOYED[1])
        ax.plot([xs[k]], [ys[k]], marker="*", color=C["black"], ms=8, ls="none", zorder=5)
        ax.annotate(r"deployed, $d{=}128$", (xs[k], ys[k]), xytext=(6, 4), textcoords="offset points",
                    fontsize=6.5)
    else:
        ax.annotate(rf"raw {raw_dim}-D", (raw_x, raw), xytext=(4, 3), textcoords="offset points",
                    fontsize=6.5, color=color)

ax.set_yscale("log")
ax.set_ylim(0.1, 10)
ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:g}"))
ax.yaxis.set_minor_formatter(NullFormatter())
ax.set_xlim(12, 42)
ax.set_xlabel(r"Full face-circuit constraints ($\times 10^3$)")
ax.set_ylabel(r"LFW EER (\%)")

handles = [Line2D([], [], color=C["blue"], marker="o", mfc="white", mew=0.9, ls="-", label=series[0][1]),
           Line2D([], [], color=C["vermillion"], marker="s", mfc="white", mew=0.9, ls="--", label=series[1][1]),
           Line2D([], [], color=C["gray"], marker="D", ls="none", label="Raw embedding, no projection"),
           Line2D([], [], color=C["black"], marker="*", ms=7, ls="none", label="Deployed operating point")]
ax.legend(handles=handles, loc="lower center", bbox_to_anchor=(0.5, 1.01), ncol=2,
          columnspacing=1.0, handlelength=1.8, borderaxespad=0.0)
save(fig, OUT)
