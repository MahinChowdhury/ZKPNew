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

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = Path(__file__).resolve().parent
BENCH = HERE.parent / "api-server" / "benchmark"
COST = HERE.parent / "api-server" / "results" / "subcircuit_constraints.json"
OUT = HERE.parent / "IEEE_Transaction_Mahin" / "figures" / "fig_encoding_pareto.pdf"
DEPLOYED = ("insightface", 128)

cost = json.loads(COST.read_text())
d0 = cost.get("face_auth (dim)", 64)
H = lambda d: cost[f"PoseidonHashChunked({d},8)"]
C = lambda d: cost[f"SquaredCosineSimilarity({d})"]
full = lambda d: cost["face_auth (full)"] + 2 * (H(d) - H(d0)) + (C(d) - C(d0))


def curve(label):
    eer = json.loads((BENCH / f"face_sweep_{label}.json").read_text())["eer"]
    dims = sorted(int(k[3:]) for k in eer if k.startswith("pca") and f"PoseidonHashChunked({k[3:]},8)" in cost)
    return dims, [full(d) for d in dims], [100 * eer[f"pca{d}"]["eer"] for d in dims], 100 * eer["raw"]["eer"]


plt.rcParams.update({"font.size": 8, "font.family": "serif"})
fig, ax = plt.subplots(figsize=(3.4, 2.3))
for label, name, style, color in (("insightface", "InsightFace + PCA (deployed)", "o-", "#08519c"),
                                  ("facenet", "FaceNet + PCA", "s--", "#e6550d")):
    dims, xs, ys, raw = curve(label)
    ax.plot(xs, ys, style, color=color, ms=3, lw=1, label=name)
    ax.axhline(raw, color=color, ls=":", lw=0.7)
    for d, x, y in zip(dims, xs, ys):
        if label == "insightface" or d == 64:
            ax.annotate(f"{d}", (x, y), textcoords="offset points",
                        xytext=(0, 4) if label == "facenet" else (5, 2), ha="left" if label == "insightface" else "center",
                        fontsize=5.5)
    if label == "insightface":
        ax.text(xs[0], raw * 1.06, "raw 512-D", ha="left", va="bottom", fontsize=5.5, color=color)
    else:
        ax.text(xs[-1], raw * 1.06, "raw 128-D", ha="right", va="bottom", fontsize=5.5, color=color)
    if label == DEPLOYED[0]:
        k = dims.index(DEPLOYED[1])
        ax.plot([xs[k]], [ys[k]], "o", ms=8, mfc="none", mec="#d4a017", mew=1.5)
ax.set_yscale("log")
ax.set_yticks([0.2, 0.5, 1, 2, 5])
ax.yaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v:g}"))
ax.yaxis.set_minor_formatter(matplotlib.ticker.NullFormatter())
ax.xaxis.set_major_formatter(matplotlib.ticker.FuncFormatter(lambda v, _: f"{v / 1000:g}k"))
ax.set_xlabel("Full face circuit R1CS constraints (--O2)")
ax.set_ylabel("LFW EER (%), log scale")
ax.legend(frameon=False, fontsize=6, loc="center right")
fig.tight_layout()
fig.savefig(OUT, bbox_inches="tight")
print(f"wrote {OUT}")
